# Contributing

Thanks for helping people who are targeted by spyware. Please read SECURITY.md first, especially
the rules on real device data.

## Setup

```
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check src tests && ruff format --check src tests
```

To run the real-feed tests, clone `mvt-project/mvt-indicators` and `AmnestyTech/investigations`
into one folder and run `ORCHARD_SAMPLES=<folder> pytest`.

## Ground rules

1. **Detection only.** Do not add exploit code, exploit generators, or working malicious samples.
   Test fixtures contain the minimum structural marker a detector needs and no payload.
2. **Cite sources.** Every detection and kit card must link to primary public research. Add the
   link to the card's `sources` and to the finding's `source`.
3. **No overclaiming.** A finding states what was seen, its confidence, and a caveat when a benign
   explanation exists. Never write copy that says a device is "clean" or "safe".
4. **Report what was not examined.** New checks that cannot cover a case must say so through
   `unsupported_checks` or module status, so coverage grades stay honest.
5. **Test the negative case.** Every detector needs a test that a benign input is not flagged, and
   a mutation check is welcome (break the logic, confirm a test fails).
6. **Parsers are an attack surface.** Bound sizes, depth and entry counts, handle truncated and
   malformed input without raising, and never extract archives to disk.
7. **Clean room.** Do not copy code from projects whose license does not allow it. Describe the
   public vulnerability or artifact and implement from that description.

## Adding a kit card

Copy an existing file in `src/orchardwarden/kits/cards/`, fill in the fields from primary sources, and
keep `needs_primary_source_review: true` until a second person has checked the version ranges
against Apple's security notes. Add a test.

## Pull requests

Keep changes focused, include tests, and update the CHANGELOG.
