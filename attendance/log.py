"""Record taps to a CSV file.

CSV on purpose: it opens in Excel, it is easy to eyeball, and it survives the
program being killed mid-session. Swap this module out for SQLite or a database
later -- the rest of the code only uses `record()`.
"""

from __future__ import annotations

import csv
import datetime as _dt
from pathlib import Path

FIELDNAMES = ["timestamp", "card_id", "card_type", "note"]


class AttendanceLog:
    """Append-only CSV log of card taps, with repeat-tap suppression.

    `debounce_seconds` ignores the same card tapped again within that window,
    so a double tap or a card resting on the reader doesn't create duplicate
    rows. Set it to 0 to record every single tap.
    """

    def __init__(self, path: str | Path, debounce_seconds: float = 10.0):
        self.path = Path(path)
        self.debounce_seconds = debounce_seconds
        self._last_seen: dict[str, _dt.datetime] = {}
        self._ensure_header()

    def _ensure_header(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists() or self.path.stat().st_size == 0:
            with self.path.open("w", newline="", encoding="utf-8") as fh:
                csv.DictWriter(fh, fieldnames=FIELDNAMES).writeheader()

    def is_repeat(self, card_id: str, when: _dt.datetime) -> bool:
        """True if this card was already recorded inside the debounce window."""
        last = self._last_seen.get(card_id)
        if last is None:
            return False
        return (when - last).total_seconds() < self.debounce_seconds

    def record(self, card_id: str, card_type: str = "", note: str = "",
               when: _dt.datetime | None = None) -> bool:
        """Append one tap. Returns False if it was suppressed as a repeat."""
        when = when or _dt.datetime.now()
        if self.is_repeat(card_id, when):
            return False
        self._last_seen[card_id] = when
        with self.path.open("a", newline="", encoding="utf-8") as fh:
            csv.DictWriter(fh, fieldnames=FIELDNAMES).writerow({
                "timestamp": when.isoformat(timespec="seconds"),
                "card_id": card_id,
                "card_type": card_type,
                "note": note,
            })
        return True

    def count(self) -> int:
        """How many taps are recorded in the file."""
        if not self.path.exists():
            return 0
        with self.path.open(newline="", encoding="utf-8") as fh:
            return sum(1 for _ in csv.DictReader(fh))

    def unique_cards(self) -> set[str]:
        """Every distinct card ID in the file."""
        if not self.path.exists():
            return set()
        with self.path.open(newline="", encoding="utf-8") as fh:
            return {row["card_id"] for row in csv.DictReader(fh) if row.get("card_id")}
