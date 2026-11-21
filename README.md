# attendance

Takes attendance by tapping ID cards on an [HID OMNIKEY 5022](https://www.hidglobal.com/products/omnikey-5022-reader)
contactless reader. Each tap is appended to a CSV file with a timestamp.

The 5022 is a standard USB CCID reader, so there is **no HID driver or SDK to
install** — it works through the operating system's built-in smart-card service
(Windows, macOS and Linux all ship one).

## Requirements

- An HID OMNIKEY 5022 CL reader (13.56 MHz contactless)
- Python 3.10 or newer
- 13.56 MHz credentials: iCLASS, MIFARE Classic / DESFire, NFC phones.
  **125 kHz cards (older HID Prox) will not work** — the 5022 cannot see them.

## Setup

```sh
py -m pip install -r requirements.txt     # Windows
pip install -r requirements.txt           # macOS / Linux
```

On Windows, call pip through the launcher (`py -m pip`) rather than `pip`
directly. A bare `pip` is a stub with a hard-coded path to `python.exe`, and it
fails with *"Fatal error in launcher"* whenever Python has been moved or
upgraded.

On Linux you also need the PC/SC daemon:

```sh
sudo apt install pcscd && sudo systemctl enable --now pcscd
```

## Usage

Check the reader is visible before anything else:

```sh
py -m attendance --list-readers
```

You should see a line like `HID Global OMNIKEY 5022 Smart Card Reader 00 00`.
If the list is empty, the problem is the driver layer, not this code.

Then run a session:

```sh
py -m attendance
```

```
Reader : HID Global OMNIKEY 5022 Smart Card Reader 00 00
Logging to: data/attendance.csv  (0 taps already recorded)
Tap a card to record attendance. Ctrl+C to finish.

  09:58:02  04A23B1C             MIFARE Classic 1K
  09:58:09  A1B2C3D4E5F60012     iCLASS 16KS
```

Options:

| Option | Meaning |
|---|---|
| `-o FILE` | CSV to append to (default `data/attendance.csv`) |
| `--debounce N` | ignore the same card re-tapped within N seconds (default 10) |
| `--list-readers` | list readers and exit |

`--debounce` matters in practice: without it, a card left resting on the reader
produces a new row every time it is polled.

### Identifying an unfamiliar card

`tools/inspect_card.py` is a diagnostic that prints everything a card will tell
you — ID in four formats, card type, ATR, and optionally one MIFARE Classic
data block:

```sh
py tools/inspect_card.py --once
py tools/inspect_card.py --block 4 --key FFFFFFFFFFFF
```

Use it when a badge isn't recognised, or to work out which ID format matches a
roster you already have.

## Using it from your own code

```python
from attendance import wait_for_card

card = wait_for_card()          # blocks until someone taps
print(card.uid, card.card_type)
```

`wait_for_card()` waits for a card to *arrive*, so each physical tap yields
exactly one read.

## Layout

```
attendance/
  cards.py        decode card type from the ATR (pure functions, no hardware)
  reader.py       wait for a tap, read the card ID
  log.py          append taps to CSV, suppress repeats
  __main__.py     the `py -m attendance` command
tools/
  inspect_card.py standalone diagnostic for unfamiliar cards
tests/
  test_cards.py   unit tests for card decoding (no hardware needed)
  fakecard.py     virtual card, for testing without a reader
```

## Testing without a reader

The unit tests cover card decoding and the CSV log, and need no hardware:

```sh
py -m pytest tests/
```

For an end-to-end test without a reader, Linux can present a virtual one:

```sh
sudo apt install pcscd vsmartcard-vpcd && sudo systemctl restart pcscd
python tests/fakecard.py mifare1k &          # presents a card
python -m attendance -o /tmp/test.csv
```

`fakecard.py` accepts `mifare1k`, `iclass` or `desfire`. It is a test double,
not a simulator — it verifies the code paths, not that your reader and your
real badges work together.

## Known limitations

**iCLASS badges give you the chip serial (CSN), not the printed badge number.**
The facility code and card number that door systems use live in HID's protected
area, which requires a secure session that the 5022's documented command set
does not expose. If the roster you need to match is keyed on printed badge
numbers, confirm with one real badge early.

**Some credentials report a random ID that changes on every tap.** Phones and
privacy-mode cards do this; they cannot identify a person. The code flags these
(`card.random_uid`) and notes them in the CSV rather than logging them as a
real attendee.

**Byte order varies between systems.** The same card may appear as `04A23B1C`
here and `1C3BA204` in another system's export. `card.uid_reversed` gives the
other direction; check which one your roster uses.

## Not done yet

- Matching card IDs to students (roster lookup)
- Anything beyond a flat CSV (database, export, reporting)
- Enrollment flow for registering a new card against a name
