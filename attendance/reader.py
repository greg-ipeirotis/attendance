"""Wait for a card on an HID OMNIKEY 5022 (or any PC/SC reader) and read its ID.

The OMNIKEY 5022 is a standard USB CCID reader, so it needs no HID driver or
SDK -- just the operating system's smart-card service and pyscard.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, asdict

from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.Exceptions import (
    CardConnectionException,
    CardRequestTimeoutException,
    NoCardException,
    NoReadersException,
)
from smartcard.scard import SCARD_E_CANCELLED
from smartcard.System import readers as _pcsc_readers

from .cards import describe_atr, hexs, is_random_uid, uid_notes

# PC/SC "GET DATA": ask the reader for the card's identifier. The reader answers
# this itself, so one command covers MIFARE, iCLASS, DESFire, FeliCa and NFC
# phones without knowing in advance what was tapped.
GET_UID = [0xFF, 0xCA, 0x00, 0x00, 0x00]

# Status words worth explaining to a human.
SW_TEXT = {
    0x6300: "operation failed (no card response)",
    0x6700: "wrong length",
    0x6A81: "function not supported by this card",
    0x6B00: "wrong parameter P1/P2",
    0x6F00: "operation failed",
}


class ReaderError(Exception):
    """No usable reader, or the smart-card service is unavailable."""


class CardReadError(Exception):
    """A card was present but its ID could not be read."""


@dataclass(frozen=True)
class Card:
    """One card, as read from the reader."""

    uid: str                 # e.g. "04A23B1C"
    uid_reversed: str        # e.g. "1C3BA204" -- some systems store it this way
    uid_bytes: int           # length of the identifier
    atr: str                 # e.g. "3B 8F 80 01 80 4F 0C A0 ..."
    card_type: str           # e.g. "MIFARE Classic 1K"
    standard: str | None     # e.g. "ISO 14443 A part 3"
    random_uid: bool         # True if the ID changes on every tap
    notes: tuple[str, ...]   # human-readable warnings, if any
    read_at: _dt.datetime

    def as_dict(self) -> dict:
        d = asdict(self)
        d["read_at"] = self.read_at.isoformat(timespec="seconds")
        d["notes"] = list(self.notes)
        return d


def list_readers() -> list[str]:
    """Names of every PC/SC reader the operating system can see."""
    try:
        return [str(r) for r in _pcsc_readers()]
    except NoReadersException:
        return []
    except CardConnectionException as exc:  # service not running
        raise ReaderError(f"the PC/SC smart-card service is unavailable: {exc}") from exc


def find_reader(match: str = "5022") -> str | None:
    """First reader whose name contains `match` (case-insensitive)."""
    for name in list_readers():
        if match.lower() in name.lower():
            return name
    return None


def wait_for_card(timeout: float | None = None) -> Card:
    """Block until a card is tapped, then return it.

    `newcardonly=True` is what makes this behave correctly in a loop: it waits
    for a card to *arrive* rather than returning one already sitting on the
    reader. Without it, a card left on the reader would be read over and over.

    Raises CardRequestTimeoutException if `timeout` seconds pass with no tap,
    KeyboardInterrupt on Ctrl+C, CardReadError if a card was tapped but did
    not give up an ID.
    """
    request = CardRequest(cardType=AnyCardType(), timeout=timeout, newcardonly=True)
    try:
        service = request.waitforcard()
    except CardRequestTimeoutException as exc:
        # pyscard catches KeyboardInterrupt itself, cancels the pending wait and
        # reports it as a timeout. Translate that back, or a caller that retries
        # on timeout (as an attendance loop must) would swallow Ctrl+C and spin
        # forever.
        if getattr(exc, "hresult", None) == SCARD_E_CANCELLED:
            raise KeyboardInterrupt from None
        raise

    try:
        service.connection.connect()
    except (NoCardException, CardConnectionException) as exc:
        raise CardReadError(
            "card was removed before it could be read; hold it flat on the reader"
        ) from exc

    try:
        atr = bytes(service.connection.getATR())
        response, sw1, sw2 = service.connection.transmit(GET_UID)
        sw = (sw1 << 8) | sw2

        if sw >> 8 == 0x6C:  # card wants a specific length; ask again for it
            response, sw1, sw2 = service.connection.transmit(GET_UID[:4] + [sw & 0xFF])
            sw = (sw1 << 8) | sw2
        if sw != 0x9000:
            raise CardReadError(
                f"reader returned SW={sw:04X} "
                f"({SW_TEXT.get(sw, 'unknown status')}) when asked for the card ID"
            )

        uid = bytes(response)
        info = describe_atr(atr)
        return Card(
            uid=hexs(uid, ""),
            uid_reversed=hexs(uid[::-1], ""),
            uid_bytes=len(uid),
            atr=hexs(atr),
            card_type=info["card_type"],
            standard=info["standard"],
            random_uid=is_random_uid(uid),
            notes=tuple(uid_notes(uid)),
            read_at=_dt.datetime.now(),
        )
    except CardConnectionException as exc:
        raise CardReadError(f"lost contact with the card: {exc}") from exc
    finally:
        try:
            service.connection.disconnect()
        except CardConnectionException:
            pass


def read_cards(timeout: float | None = None):
    """Yield one Card per tap, forever.

    Read errors are raised to the caller, which decides whether to carry on --
    a dropped tap shouldn't end an attendance session.
    """
    while True:
        try:
            yield wait_for_card(timeout=timeout)
        except CardRequestTimeoutException:
            continue


__all__ = [
    "Card", "CardReadError", "ReaderError",
    "list_readers", "find_reader", "wait_for_card", "read_cards",
]
