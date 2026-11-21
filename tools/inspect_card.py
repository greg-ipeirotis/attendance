#!/usr/bin/env python3
"""
inspect_card.py - read contactless cards with an HID OMNIKEY 5022 CL reader.

The OMNIKEY 5022 is a standard PC/SC (USB CCID) reader, so it needs no HID
driver or SDK. This program talks to it through the operating system's
smart-card service (WinSCard on Windows, PC/SC on macOS, pcsc-lite on Linux).

For every card that is tapped it prints:
  * the card's identifier (UID / CSN / PUPI / IDm) in hex and decimal
  * the card type, decoded from the ATR the reader builds for the card
  * the ATR itself
  * optionally, the contents of one MIFARE Classic block (--block)

Supported by the 5022: ISO 14443 A/B, ISO 15693, iCLASS (CSN), MIFARE Classic,
Plus, Ultralight/C and DESFire, Topaz/Jewel, FeliCa (IDm), NFC phones.

Requirements
  pip install pyscard
  Linux only: sudo apt install pcscd   (the pcscd service must be running)

Usage
  python inspect_card.py                  wait for cards, print each one
  python inspect_card.py --once           read one card, then exit
  python inspect_card.py --list           list the PC/SC readers found
  python inspect_card.py --format uid     print only the UID (for scripts)
  python inspect_card.py --format json    one JSON object per card
  python inspect_card.py --block 4        also read MIFARE Classic block 4
  python inspect_card.py --block 4 --key A0A1A2A3A4A5 --key-type B

Status messages go to stderr, card data to stdout, so the output can be piped.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from attendance.cards import (  # noqa: E402  (after the sys.path tweak above)
    MIFARE_CLASSIC_NAMES,
    describe_atr,
    hexs,
    uid_notes,
)

try:
    from smartcard import scard as sc
except ImportError:  # pragma: no cover - only hit when pyscard is missing
    sys.exit("pyscard is not installed. Install it with:  pip install pyscard")


# --------------------------------------------------------------------------
# PC/SC "pseudo-APDUs" understood by the reader itself (class byte 0xFF).
# --------------------------------------------------------------------------
APDU_GET_UID = [0xFF, 0xCA, 0x00, 0x00, 0x00]      # GET DATA: card identifier
MIFARE_DEFAULT_KEY = "FFFFFFFFFFFF"                 # factory default key
MIFARE_KEY_TYPE = {"A": 0x60, "B": 0x61}
DEFAULT_KEY_SLOT = 0x01                             # volatile key slot in reader

# Status words worth explaining to a human.
SW_TEXT = {
    0x9000: "success",
    0x6300: "operation failed (authentication error or no card response)",
    0x6581: "memory failure",
    0x6700: "wrong length",
    0x6982: "security status not satisfied (authenticate first)",
    0x6A81: "function not supported by this card",
    0x6A82: "block/address not found",
    0x6B00: "wrong parameter P1/P2",
    0x6F00: "operation failed",
}

# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------
class PCSCError(Exception):
    """A PC/SC call returned something other than SCARD_S_SUCCESS."""

    def __init__(self, what: str, hresult: int):
        self.hresult = hresult
        code = hresult & 0xFFFFFFFF
        super().__init__(f"{what} failed: {sc.SCardGetErrorMessage(hresult)} (0x{code:08X})")


class ReaderGone(Exception):
    """The reader was unplugged while we were using it."""


class CardError(Exception):
    """The card answered, but not with what we needed."""


def check(hresult: int, what: str) -> None:
    if hresult != sc.SCARD_S_SUCCESS:
        raise PCSCError(what, hresult)


# Errors after which it makes sense to re-open the PC/SC context and carry on.
RECOVERABLE = {
    sc.SCARD_E_NO_SERVICE,
    sc.SCARD_E_SERVICE_STOPPED,
    sc.SCARD_E_INVALID_HANDLE,
    sc.SCARD_E_NO_READERS_AVAILABLE,
    sc.SCARD_E_READER_UNAVAILABLE,
    sc.SCARD_E_UNKNOWN_READER,
}


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def sw_text(sw: int) -> str:
    if sw >> 8 == 0x6C:
        return f"wrong Le, card wants {sw & 0xFF} bytes"
    return SW_TEXT.get(sw, "unknown status")


def parse_hex(text: str, length: int, name: str) -> bytes:
    cleaned = text.replace(" ", "").replace(":", "").replace("-", "")
    try:
        data = bytes.fromhex(cleaned)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{name} must be hex, e.g. {MIFARE_DEFAULT_KEY}")
    if len(data) != length:
        raise argparse.ArgumentTypeError(f"{name} must be exactly {length} bytes ({length * 2} hex digits)")
    return data


_last_status = None


def status(msg: str, once: bool = False) -> None:
    """Print a status line to stderr; with once=True, don't repeat the same line."""
    global _last_status
    if once and msg == _last_status:
        return
    _last_status = msg
    print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# Talking to the card
# --------------------------------------------------------------------------
def transmit(hcard, protocol, apdu: list[int]) -> tuple[bytes, int]:
    hresult, response = sc.SCardTransmit(hcard, protocol, apdu)
    check(hresult, "SCardTransmit")
    if len(response) < 2:
        raise CardError(
            f"short response to {hexs(bytes(apdu))}: {hexs(bytes(response))}"
        )
    return bytes(response[:-2]), (response[-2] << 8) | response[-1]


def get_uid(hcard, protocol) -> bytes:
    data, sw = transmit(hcard, protocol, APDU_GET_UID)
    if sw >> 8 == 0x6C:  # card told us the exact length to ask for
        data, sw = transmit(hcard, protocol, APDU_GET_UID[:4] + [sw & 0xFF])
    if sw != 0x9000:
        raise CardError(f"GET DATA (UID) returned SW={sw:04X}: {sw_text(sw)}")
    return data


def read_mifare_block(hcard, protocol, block: int, key: bytes, key_type: int, key_slot: int) -> bytes:
    """Load a key into the reader, authenticate to the block, read 16 bytes."""
    _, sw = transmit(hcard, protocol, [0xFF, 0x82, 0x00, key_slot, 0x06] + list(key))
    if sw != 0x9000:
        raise CardError(f"Load Key returned SW={sw:04X}: {sw_text(sw)}")

    auth = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, key_type, key_slot]
    _, sw = transmit(hcard, protocol, auth)
    if sw != 0x9000:
        raise CardError(f"authentication to block {block} failed, SW={sw:04X} (wrong key or key type?)")

    data, sw = transmit(hcard, protocol, [0xFF, 0xB0, 0x00, block, 0x10])
    if sw != 0x9000:
        raise CardError(f"Read Binary of block {block} returned SW={sw:04X}: {sw_text(sw)}")
    return data


def read_card(ctx, reader: str, args) -> dict:
    """Connect to the card on `reader`, gather everything we want, disconnect."""
    result = {
        "time": _dt.datetime.now().isoformat(timespec="seconds"),
        "reader": reader,
    }
    hresult, hcard, protocol = sc.SCardConnect(
        ctx, reader, sc.SCARD_SHARE_SHARED, sc.SCARD_PROTOCOL_T0 | sc.SCARD_PROTOCOL_T1
    )
    if hresult in (sc.SCARD_W_UNRESPONSIVE_CARD, sc.SCARD_W_REMOVED_CARD, sc.SCARD_E_NO_SMARTCARD):
        result["error"] = "card was removed or did not respond; hold it still on the reader"
        return result
    if hresult == sc.SCARD_E_SHARING_VIOLATION:
        result["error"] = "another program is using the card exclusively"
        return result
    check(hresult, "SCardConnect")

    try:
        hresult, _name, _state, _proto, atr = sc.SCardStatus(hcard)
        check(hresult, "SCardStatus")
        atr = bytes(atr)
        info = describe_atr(atr)
        result["atr"] = hexs(atr)
        result["card_type"] = info["card_type"]
        if info["standard"]:
            result["standard"] = info["standard"]

        uid = get_uid(hcard, protocol)
        result.update(
            uid=hexs(uid, ""),
            uid_reversed=hexs(uid[::-1], ""),
            uid_decimal=int.from_bytes(uid, "big") if uid else None,
            uid_decimal_reversed=int.from_bytes(uid, "little") if uid else None,
            uid_length=len(uid),
        )
        notes = uid_notes(uid)
        if notes:
            result["notes"] = notes

        if args.block is not None:
            if info["card_name_code"] in MIFARE_CLASSIC_NAMES:
                try:
                    data = read_mifare_block(hcard, protocol, args.block, args.key,
                                             MIFARE_KEY_TYPE[args.key_type], args.key_slot)
                    result["block"] = {"number": args.block, "data": hexs(data)}
                except CardError as exc:
                    result["block"] = {"number": args.block, "error": str(exc)}
            else:
                result["block"] = {"number": args.block,
                                   "error": "skipped: --block only works on MIFARE Classic cards"}
    except CardError as exc:
        result["error"] = str(exc)
    except PCSCError as exc:
        if exc.hresult in (sc.SCARD_W_REMOVED_CARD, sc.SCARD_E_NO_SMARTCARD, sc.SCARD_W_RESET_CARD):
            result["error"] = "card was removed before it could be read"
        else:
            raise
    finally:
        sc.SCardDisconnect(hcard, sc.SCARD_LEAVE_CARD)
    return result


# --------------------------------------------------------------------------
# Readers and card presence
# --------------------------------------------------------------------------
def establish_context():
    hresult, ctx = sc.SCardEstablishContext(sc.SCARD_SCOPE_USER)
    check(hresult, "SCardEstablishContext")
    return ctx


def list_readers(ctx) -> list[str]:
    hresult, readers = sc.SCardListReaders(ctx, [])
    if hresult == sc.SCARD_E_NO_READERS_AVAILABLE:
        return []
    check(hresult, "SCardListReaders")
    return list(readers)


def pick_reader(readers: list[str], wanted: str | None) -> str | None:
    if wanted:
        matches = [r for r in readers if wanted.lower() in r.lower()]
        return matches[0] if matches else None
    for test in (lambda r: "5022" in r, lambda r: "omnikey" in r.lower()):
        matches = [r for r in readers if test(r)]
        if matches:
            return matches[0]
    return None


def wait_for_reader(ctx, wanted: str | None) -> str:
    while True:
        readers = list_readers(ctx)
        reader = pick_reader(readers, wanted)
        if reader:
            return reader
        if readers and not wanted:
            # No OMNIKEY 5022 visible: fall back to the first reader, but say so.
            status(f"No OMNIKEY 5022 found; using '{readers[0]}'. Use --reader to choose another.")
            return readers[0]
        target = f"a reader matching '{wanted}'" if wanted else "the OMNIKEY 5022"
        status(f"Waiting for {target} to be plugged in...", once=True)
        time.sleep(1)


def wait_for_card(ctx, reader: str, present: bool, poll_ms: int = 500) -> None:
    """Block until a card is present (present=True) or removed (present=False)."""
    state = sc.SCARD_STATE_UNAWARE
    while True:
        hresult, states = sc.SCardGetStatusChange(ctx, poll_ms, [(reader, state)])
        if hresult == sc.SCARD_E_TIMEOUT:
            continue  # short timeouts keep Ctrl+C responsive on every OS
        if hresult in (sc.SCARD_E_UNKNOWN_READER, sc.SCARD_E_READER_UNAVAILABLE,
                       sc.SCARD_E_NO_READERS_AVAILABLE):
            raise ReaderGone(reader)
        check(hresult, "SCardGetStatusChange")
        _name, event, _atr = states[0]
        if event & (sc.SCARD_STATE_UNKNOWN | sc.SCARD_STATE_UNAVAILABLE):
            raise ReaderGone(reader)
        if bool(event & sc.SCARD_STATE_PRESENT) == present:
            return
        # Feed the new state back in (minus the CHANGED flag) so the next call waits.
        state = event & ~sc.SCARD_STATE_CHANGED & 0xFFFFFFFF


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
def emit(result: dict, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(result), flush=True)
        return
    if fmt == "uid":
        if "uid" in result:
            print(result["uid"], flush=True)
        else:
            status(f"Read failed: {result.get('error', 'unknown error')}")
        return

    lines = [f"[{result['time'].replace('T', ' ')}] Card on {result['reader']}"]
    if "card_type" in result:
        std = f"  ({result['standard']})" if result.get("standard") else ""
        lines.append(f"  Type        : {result['card_type']}{std}")
    if "uid" in result:
        lines += [
            f"  UID         : {result['uid']}  ({result['uid_length']} bytes)",
            f"  UID reversed: {result['uid_reversed']}",
            f"  UID decimal : {result['uid_decimal']}  (reversed: {result['uid_decimal_reversed']})",
        ]
    for note in result.get("notes", []):
        lines.append(f"  Note        : {note}")
    if "atr" in result:
        lines.append(f"  ATR         : {result['atr']}")
    if "block" in result:
        blk = result["block"]
        lines.append(f"  Block {blk['number']:<6}: {blk.get('data') or blk.get('error')}")
    if "error" in result:
        lines.append(f"  Error       : {result['error']}")
    print("\n".join(lines) + "\n", flush=True)


# --------------------------------------------------------------------------
# Main loop
# --------------------------------------------------------------------------
def serve_reader(ctx, reader: str, args) -> None:
    status(f"Using reader: {reader}")
    status("Tap a card on the reader (Ctrl+C to quit).")
    while True:
        wait_for_card(ctx, reader, present=True)
        result = read_card(ctx, reader, args)
        emit(result, args.format)
        if args.once:
            return
        wait_for_card(ctx, reader, present=False)


def run(args) -> int:
    while True:
        try:
            ctx = establish_context()
        except PCSCError as exc:
            if exc.hresult in (sc.SCARD_E_NO_SERVICE, sc.SCARD_E_SERVICE_STOPPED):
                if sys.platform == "win32":
                    # Windows only starts its Smart Card service once a reader is attached.
                    status("Waiting for a smart-card reader to be plugged in...", once=True)
                    time.sleep(1)
                    continue
                hint = ("start it with:  sudo systemctl start pcscd"
                        if sys.platform.startswith("linux") else "check that the reader is connected")
                status(f"The PC/SC smart-card service is not running; {hint}")
                return 1
            raise

        try:
            if args.list:
                readers = list_readers(ctx)
                print("\n".join(readers) if readers else "No PC/SC readers found.")
                return 0
            reader = wait_for_reader(ctx, args.reader)
            serve_reader(ctx, reader, args)
            return 0
        except ReaderGone:
            status("Reader disconnected.")
        except PCSCError as exc:
            if exc.hresult not in RECOVERABLE:
                raise
            status(f"{exc}; retrying...")
            time.sleep(1)
        finally:
            sc.SCardReleaseContext(ctx)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Read contactless cards with an HID OMNIKEY 5022 CL reader (PC/SC).",
        epilog="Example: %(prog)s --block 4 --key FFFFFFFFFFFF --key-type A",
    )
    p.add_argument("--list", action="store_true", help="list PC/SC readers and exit")
    p.add_argument("--reader", metavar="TEXT",
                   help="use the first reader whose name contains TEXT (default: the OMNIKEY 5022)")
    p.add_argument("--once", action="store_true", help="exit after the first card")
    p.add_argument("--format", choices=["text", "json", "uid"], default="text",
                   help="output format (default: text)")

    m = p.add_argument_group("MIFARE Classic block read (optional)")
    m.add_argument("--block", type=int, metavar="N", help="also read block N (0-255)")
    m.add_argument("--key", default=MIFARE_DEFAULT_KEY, metavar="HEX",
                   help=f"6-byte key for --block (default: {MIFARE_DEFAULT_KEY})")
    m.add_argument("--key-type", choices=["A", "B"], default="A", type=str.upper,
                   help="authenticate with key A or key B (default: A)")
    m.add_argument("--key-slot", type=int, default=DEFAULT_KEY_SLOT, metavar="N",
                   help=f"reader key slot to load the key into (default: {DEFAULT_KEY_SLOT})")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.block is not None and not 0 <= args.block <= 255:
        parser.error("--block must be between 0 and 255")
    if not 0 <= args.key_slot <= 255:
        parser.error("--key-slot must be between 0 and 255")
    try:
        args.key = parse_hex(args.key, 6, "--key")
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))

    try:
        return run(args)
    except KeyboardInterrupt:
        status("\nStopped.")
        return 0
    except PCSCError as exc:
        status(f"Error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
