"""Tests for the card-reading layer, using a fake PC/SC request. No hardware."""

import sys
from pathlib import Path

import pytest
from smartcard.Exceptions import CardRequestTimeoutException
from smartcard.scard import SCARD_E_CANCELLED, SCARD_E_TIMEOUT

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from attendance import reader as rdr

MIFARE_ATR = bytes.fromhex("3B8F8001804F0CA0000003060300010000000061")


class FakeConnection:
    """Stands in for a pyscard CardConnection."""

    def __init__(self, atr=MIFARE_ATR, replies=((b"\x04\xA2\x3B\x1C", 0x90, 0x00),)):
        self.atr = atr
        self.replies = list(replies)
        self.sent = []
        self.disconnected = False

    def connect(self):
        pass

    def getATR(self):
        return list(self.atr)

    def transmit(self, apdu):
        self.sent.append(bytes(apdu))
        data, sw1, sw2 = self.replies.pop(0)
        return list(data), sw1, sw2

    def disconnect(self):
        self.disconnected = True


def install(monkeypatch, *, connection=None, raises=None):
    """Point attendance.reader at a fake CardRequest."""
    class FakeRequest:
        def __init__(self, *a, **kw):
            pass

        def waitforcard(self):
            if raises is not None:
                raise raises
            return type("Service", (), {"connection": connection})()

    monkeypatch.setattr(rdr, "CardRequest", FakeRequest)


# --- Ctrl+C handling (regression) ----------------------------------------

def test_cancelled_wait_becomes_keyboard_interrupt(monkeypatch):
    """pyscard reports a Ctrl+C-cancelled wait as a *timeout*.

    An attendance loop retries on timeout, so if that is not translated back
    the program spins forever and Ctrl+C never stops it.
    """
    install(monkeypatch, raises=CardRequestTimeoutException(hresult=SCARD_E_CANCELLED))
    with pytest.raises(KeyboardInterrupt):
        rdr.wait_for_card()


def test_real_timeout_still_raises_timeout(monkeypatch):
    install(monkeypatch, raises=CardRequestTimeoutException(hresult=SCARD_E_TIMEOUT))
    with pytest.raises(CardRequestTimeoutException):
        rdr.wait_for_card(timeout=0.01)


# --- reading a card -------------------------------------------------------

def test_successful_read_populates_card(monkeypatch):
    conn = FakeConnection()
    install(monkeypatch, connection=conn)
    card = rdr.wait_for_card()

    assert card.uid == "04A23B1C"
    assert card.uid_reversed == "1C3BA204"
    assert card.uid_bytes == 4
    assert card.card_type == "MIFARE Classic 1K"
    assert card.random_uid is False
    assert card.notes == ()
    assert conn.sent[0] == bytes(rdr.GET_UID)
    assert conn.disconnected, "the connection must be released after reading"


def test_random_uid_is_flagged(monkeypatch):
    conn = FakeConnection(atr=bytes.fromhex("3B8180018080"),
                          replies=((b"\x08\x11\x22\x33", 0x90, 0x00),))
    install(monkeypatch, connection=conn)
    card = rdr.wait_for_card()

    assert card.uid == "08112233"
    assert card.random_uid is True
    assert any("random UID" in n for n in card.notes)


def test_error_status_word_raises(monkeypatch):
    conn = FakeConnection(replies=((b"", 0x6A, 0x81),))
    install(monkeypatch, connection=conn)
    with pytest.raises(rdr.CardReadError, match="6A81"):
        rdr.wait_for_card()
    assert conn.disconnected, "the connection must be released even on failure"


def test_wrong_length_is_retried_with_the_length_the_card_asks_for(monkeypatch):
    # 6C08 means "ask again with Le=8".
    conn = FakeConnection(
        atr=bytes.fromhex("3B8F8001804F0CA000000306" "0A001A" "0000000000"),
        replies=((b"", 0x6C, 0x08),
                 (bytes.fromhex("A1B2C3D4E5F60012"), 0x90, 0x00)),
    )
    install(monkeypatch, connection=conn)
    card = rdr.wait_for_card()

    assert card.uid == "A1B2C3D4E5F60012"
    assert len(conn.sent) == 2
    assert conn.sent[1][-1] == 0x08, "retry must use the length the card asked for"


def test_card_as_dict_is_json_friendly(monkeypatch):
    import json
    install(monkeypatch, connection=FakeConnection())
    d = rdr.wait_for_card().as_dict()
    assert json.loads(json.dumps(d))["uid"] == "04A23B1C"
