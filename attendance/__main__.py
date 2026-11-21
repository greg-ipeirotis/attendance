"""Run an attendance session: python -m attendance

Waits for card taps and appends each one to a CSV file. Ctrl+C to stop.
"""

from __future__ import annotations

import argparse
import sys

from smartcard.Exceptions import CardRequestTimeoutException

from .log import AttendanceLog
from .reader import CardReadError, ReaderError, list_readers, wait_for_card


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m attendance",
        description="Take attendance by tapping cards on an HID OMNIKEY 5022.",
    )
    p.add_argument("-o", "--out", default="data/attendance.csv", metavar="FILE",
                   help="CSV file to append to (default: data/attendance.csv)")
    p.add_argument("--debounce", type=float, default=10.0, metavar="SECONDS",
                   help="ignore the same card re-tapped within this window "
                        "(default: 10; use 0 to log every tap)")
    p.add_argument("--list-readers", action="store_true",
                   help="list the PC/SC readers found, then exit")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        readers = list_readers()
    except ReaderError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        if sys.platform.startswith("linux"):
            print("On Linux, start the service with:  sudo systemctl start pcscd",
                  file=sys.stderr)
        return 1

    if args.list_readers:
        print("\n".join(readers) if readers else "No PC/SC readers found.")
        return 0

    if not readers:
        print("No card reader found. Plug in the OMNIKEY 5022 and try again.",
              file=sys.stderr)
        return 1

    log = AttendanceLog(args.out, debounce_seconds=args.debounce)
    print(f"Reader : {readers[0]}")
    print(f"Logging to: {log.path}  ({log.count()} taps already recorded)")
    print("Tap a card to record attendance. Ctrl+C to finish.\n")

    recorded = 0
    try:
        while True:
            try:
                card = wait_for_card()
            except CardRequestTimeoutException:
                continue
            except CardReadError as exc:
                # One bad tap shouldn't end the session.
                print(f"  !  {exc}", file=sys.stderr)
                continue

            note = "random UID - cannot identify cardholder" if card.random_uid else ""
            if log.record(card.uid, card.card_type, note):
                recorded += 1
                stamp = card.read_at.strftime("%H:%M:%S")
                print(f"  {stamp}  {card.uid:<20} {card.card_type}")
                if note:
                    print(f"            warning: {note}", file=sys.stderr)
            else:
                print(f"  {card.read_at:%H:%M:%S}  {card.uid:<20} "
                      f"(already recorded, ignored)")
    except KeyboardInterrupt:
        print(f"\nDone. {recorded} tap(s) recorded this session, "
              f"{len(log.unique_cards())} unique card(s) in {log.path}.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
