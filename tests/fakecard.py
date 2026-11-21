"""Minimal virtual contactless card for vsmartcard's vpcd driver (test only).

Usage: python fakecard.py <mifare1k|iclass|desfire> [seconds_on_reader]
"""
import socket, struct, sys, time

KIND = sys.argv[1] if len(sys.argv) > 1 else "mifare1k"
HOLD = float(sys.argv[2]) if len(sys.argv) > 2 else 3600


def part3_atr(ss, name):
    body = [0x8F, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x06, ss, name >> 8, name & 0xFF, 0, 0, 0, 0]
    tck = 0
    for b in body:
        tck ^= b
    return bytes([0x3B] + body + [tck])


CARDS = {
    "mifare1k": (part3_atr(0x03, 0x0001), bytes.fromhex("04A23B1C")),
    "iclass": (part3_atr(0x0A, 0x001A), bytes.fromhex("A1B2C3D4E5F60012")),
    # 3B 81 80 01 80 80 is the ATR a MIFARE DESFire gets; 08.. = random UID
    "desfire": (bytes.fromhex("3B8180018080"), bytes.fromhex("08112233")),
}
ATR, UID = CARDS[KIND]
BLOCKS = {4: bytes(range(0x10, 0x20))}
state = {"key": None, "authed": None}


def handle(apdu):
    if apdu[:2] == b"\xFF\xCA" and apdu[2] == 0:
        return UID + b"\x90\x00"
    if apdu[:2] == b"\xFF\x82":
        state["key"] = apdu[5:11]
        return b"\x90\x00"
    if apdu[:2] == b"\xFF\x86":
        block, ktype = apdu[7], apdu[8]
        if KIND == "mifare1k" and state["key"] == b"\xFF" * 6 and ktype == 0x60:
            state["authed"] = block // 4
            return b"\x90\x00"
        return b"\x63\x00"
    if apdu[:2] == b"\xFF\xB0":
        block = apdu[3]
        if state["authed"] == block // 4:
            return BLOCKS.get(block, bytes(16)) + b"\x90\x00"
        return b"\x69\x82"
    return b"\x6A\x81"


s = socket.create_connection(("127.0.0.1", 35963))
s.settimeout(0.2)
deadline = time.time() + HOLD
buf = b""
while time.time() < deadline:
    try:
        chunk = s.recv(4096)
    except socket.timeout:
        continue
    if not chunk:
        break
    buf += chunk
    while len(buf) >= 2:
        (n,) = struct.unpack(">H", buf[:2])
        if len(buf) < 2 + n:
            break
        msg, buf = buf[2 : 2 + n], buf[2 + n :]
        if n == 1:
            if msg[0] == 0x04:  # get ATR
                s.sendall(struct.pack(">H", len(ATR)) + ATR)
            continue  # power on/off/reset need no reply
        resp = handle(msg)
        s.sendall(struct.pack(">H", len(resp)) + resp)
s.close()
