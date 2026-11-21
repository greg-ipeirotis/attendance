"""Take attendance by tapping cards on an HID OMNIKEY 5022 reader."""

from .cards import describe_atr, is_random_uid
from .log import AttendanceLog
from .reader import (
    Card,
    CardReadError,
    ReaderError,
    find_reader,
    list_readers,
    read_cards,
    wait_for_card,
)

__version__ = "0.1.0"

__all__ = [
    "Card", "CardReadError", "ReaderError", "AttendanceLog",
    "wait_for_card", "read_cards", "list_readers", "find_reader",
    "describe_atr", "is_random_uid",
]
