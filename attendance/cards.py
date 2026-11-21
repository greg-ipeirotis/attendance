"""Decode what kind of card was tapped, from the ATR the reader reports.

Pure functions only: no hardware needed, so this module is unit-testable.
"""

from __future__ import annotations

# ATR layout PC/SC Part 3 defines for contactless *storage* cards:
#   3B 8F 80 01 80 4F 0C A0 00 00 03 06 SS NN NN 00 00 00 00 TCK
# where SS is the standard and NN NN the card name.
PCSC_RID_PREFIX = bytes([0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x06])

STANDARDS = {
    0x01: "ISO 14443 A part 1",
    0x02: "ISO 14443 A part 2",
    0x03: "ISO 14443 A part 3",
    0x05: "ISO 14443 B part 1",
    0x06: "ISO 14443 B part 2",
    0x07: "ISO 14443 B part 3",
    0x09: "ISO 15693 part 1",
    0x0A: "ISO 15693 part 2",
    0x0B: "ISO 15693 part 3",
    0x0C: "ISO 15693 part 4",
    0x11: "FeliCa",
}

CARD_NAMES = {
    0x0001: "MIFARE Classic 1K",
    0x0002: "MIFARE Classic 4K",
    0x0003: "MIFARE Ultralight",
    0x0014: "ICODE SLI",
    0x0017: "iCLASS 2K",
    0x0018: "iCLASS 2KS",
    0x0019: "iCLASS 16K",
    0x001A: "iCLASS 16KS",
    0x001B: "iCLASS 16K (8x2)",
    0x001C: "iCLASS 16KS (8x2)",
    0x001D: "iCLASS 32KS (16+16)",
    0x001E: "iCLASS 32KS (16+8x2)",
    0x001F: "iCLASS 32KS (8x2+16)",
    0x0020: "iCLASS 32KS (8x2+8x2)",
    0x0026: "MIFARE Mini",
    0x002F: "Jewel",
    0x0030: "Topaz",
    0x0035: "ICODE SL2",
    0x0036: "MIFARE Plus SL1 2K",
    0x0037: "MIFARE Plus SL1 4K",
    0x0038: "MIFARE Plus SL2 2K",
    0x0039: "MIFARE Plus SL2 4K",
    0x003A: "MIFARE Ultralight C",
    0x003B: "FeliCa",
}

# Card name codes that accept MIFARE Classic Load Key / Authenticate / Read Binary.
MIFARE_CLASSIC_NAMES = {0x0001, 0x0002, 0x0026, 0x0036, 0x0037}


def hexs(data: bytes, sep: str = " ") -> str:
    """Format bytes as uppercase hex."""
    return sep.join(f"{b:02X}" for b in data)


def describe_atr(atr: bytes) -> dict:
    """Identify the card from its ATR.

    Returns a dict with: family, card_type, standard, card_name_code.
    """
    info = {"family": "unknown", "card_type": "Unknown card",
            "standard": None, "card_name_code": None}
    if len(atr) < 4 or atr[0] != 0x3B:
        return info

    # Contactless storage card: MIFARE Classic, Ultralight, iCLASS, ICODE, ...
    if len(atr) >= 15 and atr[4:12] == PCSC_RID_PREFIX:
        ss, name = atr[12], (atr[13] << 8) | atr[14]
        info.update(
            family="storage",
            standard=STANDARDS.get(ss, f"standard 0x{ss:02X}"),
            card_name_code=name,
            card_type=CARD_NAMES.get(name, f"Storage card (name code 0x{name:04X})"),
        )
        return info

    # ISO 14443-4 (T=CL) card: ATR is 3B 8n 80 01 followed by n-2 historical bytes.
    if (atr[1] & 0xF0) == 0x80 and atr[2] == 0x80 and atr[3] == 0x01:
        hist = atr[4 : 4 + (atr[1] & 0x0F)]
        card_type = ("ISO 14443-4 smart card "
                     "(e.g. DESFire, Seos, payment card, NFC phone)")
        if hist == b"\x80":
            card_type = ("ISO 14443-4 smart card "
                         "(historical bytes 80, typical of MIFARE DESFire)")
        info.update(family="iso14443-4", card_type=card_type)
        return info

    info["card_type"] = "Unrecognised ATR"
    return info


def is_random_uid(uid: bytes) -> bool:
    """True if this identifier changes on every tap, so it can't identify a person.

    ISO 14443-3 reserves a leading 0x08 in a 4-byte UID for randomly generated
    IDs. Phones and privacy-mode DESFire/Seos credentials use these.
    """
    return len(uid) == 4 and uid[0] == 0x08


def uid_notes(uid: bytes) -> list[str]:
    """Human-readable warnings about an identifier, if any apply."""
    notes = []
    if is_random_uid(uid):
        notes.append("random UID: it changes on every tap, so it cannot identify this card")
    if uid and all(b == 0 for b in uid):
        notes.append("all-zero identifier (Jewel/Topaz cards report this)")
    return notes
