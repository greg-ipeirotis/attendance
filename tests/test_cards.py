"""Unit tests for card decoding and the CSV log. No reader needed."""

import datetime as _dt
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from attendance.cards import describe_atr, hexs, is_random_uid, uid_notes
from attendance.log import AttendanceLog


def atr(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr.replace(" ", ""))


# --- ATR decoding ---------------------------------------------------------

@pytest.mark.parametrize("atr_hex, expected_type, expected_std", [
    # PC/SC Part 3 storage-card ATRs: card name is the 14th-15th byte.
    ("3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 01 00 00 00 00 6A",
     "MIFARE Classic 1K", "ISO 14443 A part 3"),
    ("3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 02 00 00 00 00 69",
     "MIFARE Classic 4K", "ISO 14443 A part 3"),
    ("3B 8F 80 01 80 4F 0C A0 00 00 03 06 0A 00 1A 00 00 00 00 00",
     "iCLASS 16KS", "ISO 15693 part 2"),
    ("3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 3A 00 00 00 00 00",
     "MIFARE Ultralight C", "ISO 14443 A part 3"),
])
def test_storage_cards_are_named(atr_hex, expected_type, expected_std):
    info = describe_atr(atr(atr_hex))
    assert info["family"] == "storage"
    assert info["card_type"] == expected_type
    assert info["standard"] == expected_std


def test_unknown_storage_card_reports_its_code():
    # Name code 0xFFEE is not in the table; the code should still surface.
    info = describe_atr(atr("3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 FF EE 00 00 00 00 00"))
    assert info["card_name_code"] == 0xFFEE
    assert "0xFFEE" in info["card_type"]


def test_desfire_is_recognised_as_iso14443_4():
    info = describe_atr(atr("3B 81 80 01 80 80"))
    assert info["family"] == "iso14443-4"
    assert "DESFire" in info["card_type"]
    assert info["card_name_code"] is None


def test_other_iso14443_4_card_gets_the_generic_description():
    # Historical bytes other than a bare 0x80 should not be called out as
    # DESFire specifically -- only the generic ISO 14443-4 description applies.
    info = describe_atr(atr("3B 86 80 01 06 75 77 81 02 80 00"))
    assert info["family"] == "iso14443-4"
    assert "historical bytes 80" not in info["card_type"]
    assert "payment card" in info["card_type"]


@pytest.mark.parametrize("bad", ["", "3B", "00 11 22 33", "3B 00"])
def test_malformed_atrs_do_not_raise(bad):
    info = describe_atr(atr(bad))
    assert info["family"] == "unknown"
    assert info["card_name_code"] is None


# --- identifiers ----------------------------------------------------------

def test_random_uid_detected():
    # ISO 14443-3 reserves a leading 0x08 in a 4-byte UID for random IDs.
    assert is_random_uid(bytes.fromhex("08112233"))
    assert "random UID" in uid_notes(bytes.fromhex("08112233"))[0]


@pytest.mark.parametrize("uid_hex", [
    "04A23B1C",          # ordinary 4-byte UID
    "0812233445566778",  # 8-byte: leading 08 is not the random marker here
    "04",
])
def test_non_random_uids(uid_hex):
    assert not is_random_uid(bytes.fromhex(uid_hex))


def test_all_zero_identifier_is_noted():
    assert any("all-zero" in n for n in uid_notes(bytes(7)))


def test_clean_uid_has_no_notes():
    assert uid_notes(bytes.fromhex("A1B2C3D4E5F60012")) == []


def test_hexs_formatting():
    assert hexs(bytes.fromhex("04a23b1c")) == "04 A2 3B 1C"
    assert hexs(bytes.fromhex("04a23b1c"), "") == "04A23B1C"
    assert hexs(b"") == ""


# --- attendance log -------------------------------------------------------

def test_log_writes_header_and_rows(tmp_path):
    log = AttendanceLog(tmp_path / "a.csv")
    assert log.count() == 0
    assert log.record("04A23B1C", "MIFARE Classic 1K") is True
    assert log.count() == 1
    assert log.unique_cards() == {"04A23B1C"}
    assert "card_id" in (tmp_path / "a.csv").read_text().splitlines()[0]


def test_log_suppresses_repeat_tap_inside_window(tmp_path):
    log = AttendanceLog(tmp_path / "a.csv", debounce_seconds=10)
    t0 = _dt.datetime(2026, 11, 20, 9, 0, 0)
    assert log.record("04A23B1C", when=t0) is True
    assert log.record("04A23B1C", when=t0 + _dt.timedelta(seconds=3)) is False
    assert log.record("04A23B1C", when=t0 + _dt.timedelta(seconds=11)) is True
    assert log.count() == 2


def test_log_does_not_suppress_a_different_card(tmp_path):
    log = AttendanceLog(tmp_path / "a.csv", debounce_seconds=60)
    t0 = _dt.datetime(2026, 11, 20, 9, 0, 0)
    log.record("AAAA", when=t0)
    assert log.record("BBBB", when=t0 + _dt.timedelta(seconds=1)) is True
    assert log.unique_cards() == {"AAAA", "BBBB"}


def test_zero_debounce_records_every_tap(tmp_path):
    log = AttendanceLog(tmp_path / "a.csv", debounce_seconds=0)
    t0 = _dt.datetime(2026, 11, 20, 9, 0, 0)
    for _ in range(3):
        assert log.record("04A23B1C", when=t0) is True
    assert log.count() == 3


def test_log_appends_across_sessions(tmp_path):
    path = tmp_path / "a.csv"
    AttendanceLog(path).record("AAAA")
    log2 = AttendanceLog(path)          # fresh object, same file
    assert log2.count() == 1
    log2.record("BBBB")
    assert log2.count() == 2
    assert log2.unique_cards() == {"AAAA", "BBBB"}


def test_log_creates_missing_directory(tmp_path):
    log = AttendanceLog(tmp_path / "nested" / "deeper" / "a.csv")
    assert log.record("AAAA") is True
    assert (tmp_path / "nested" / "deeper" / "a.csv").exists()
