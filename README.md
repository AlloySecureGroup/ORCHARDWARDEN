<p align="center">
  <img src="docs/assets/logo.png" alt="Orchard Warden logo" width="220">
</p>

<h1 align="center">Orchard Warden</h1>

<p align="center"><strong>Integrity checks for iPhones and iPads, built for journalists and others targeted by mercenary spyware.</strong><br>
Pegasus, Predator, Triangulation, Coruna, DarkSword and similar.</p>

<p align="center">
  <a href="#quick-start">Quick start</a> |
  <a href="#what-it-checks">What it checks</a> |
  <a href="#what-this-does-not-do">Limits</a> |
  <a href="docs/plan/ORCHARD_WARDEN_PLAN.md">Design plan</a> |
  <a href="SECURITY.md">Security</a>
</p>

---

**Status: alpha (0.1.0a1).** It runs end to end and has 36 passing tests, but it has been validated
only on synthetic data and public indicator feeds, not on real device backups. Read
["What this does not do"](#what-this-does-not-do) before relying on it.

Orchard Warden complements the [Mobile Verification Toolkit (MVT)](https://github.com/mvt-project/mvt).
It does not replace it and does not import MVT code. Use MVT to create and decrypt a backup,
then point Orchard Warden at the folder for extra checks that MVT does not focus on: structural file
exploit detection, hidden-message forensics, profile analysis, version exposure and cross-layer
correlation.

## Why

Mobile spyware is often invisible from the phone itself, and professional forensics is expensive.
Orchard Warden aims to give people and the helplines that support them a free, local, explainable first
check that is honest about what it can and cannot see.

## Quick start

```
git clone <this repository>
cd orchard-warden
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest

orchardwarden demo --dir ./demo_out      # builds synthetic backups, scans them, writes reports
```

Scan a real backup (decrypted first, for example with `mvt-ios decrypt-backup`):

```
# 1. get public indicators (MIT and CC BY licensed, see "Data sources")
git clone --depth 1 https://github.com/mvt-project/mvt-indicators.git
git clone --depth 1 https://github.com/AmnestyTech/investigations.git

# 2. scan
orchardwarden scan-backup /path/to/decrypted_backup \
  --ioc mvt-indicators/2026-03-30_darksword/darksword.stix2 \
  --ioc mvt-indicators/2026-03-03_coruna_cryptowaters/coruna.stix2 \
  --ioc mvt-indicators/2023-06_01_operation_triangulation/operation_triangulation.stix2 \
  --ioc investigations/2021-07-18_nso/pegasus.stix2 \
  --out report/
```

The exit code is 2 when the verdict is "Indicators found", otherwise 0. The report is written as
`report.md` and `report.json`. URLs and filenames are redacted by default.

## Standalone binaries

See [docs/RELEASING.md](docs/RELEASING.md) for building single-file binaries and for signed and
notarized macOS builds through GitHub Actions secrets.

## Commands

| Command | Purpose |
|---|---|
| `orchardwarden scan-backup BACKUP` | Run every module on a decrypted backup |
| `orchardwarden scan-files PATH... [-r] [--context messaging]` | Structural scan of files or folders (attachments, fonts, images, PDFs, passes) |
| `orchardwarden check-profile FILE... [--allow approved.json]` | Analyze configuration profiles |
| `orchardwarden exposure --versions v.json [--events e.json]` | Which kits could have worked on which iOS versions, and when |
| `orchardwarden replay LOG` or `--jsonl EVENTS` | Run cross-layer correlation rules over a recorded log or events |
| `orchardwarden schema-report BACKUP --out schema.json` | Privacy-safe structure report for reporting parser bugs |
| `orchardwarden ioc keygen / sign / verify` | Ed25519 signed IOC feeds with pinned keys |
| `orchardwarden kits` | List kit cards |
| `orchardwarden demo` | Synthetic end to end demonstration |

## What it checks

| Module | Checks | Maturity |
|---|---|---|
| `filescan` | TrueType fonts with undocumented opcodes 0x8F and 0x90 (Triangulation font stage), PDFs disguised as images and JBIG2 use (FORCEDENTRY delivery pattern), DNG/TIFF SamplesPerPixel versus lossless JPEG components (CVE-2025-43300 heuristic), WebP container, PassKit archives scanned recursively | Font check solid. Others partial |
| `messaging` | Deleted-message gaps from SQLite sequence analysis, orphan attachments, blank inbound messages, first-contact attachments, links and sender accounts against IOCs | Prototype |
| `artifacts` | Safari history against IOCs, DataUsage process names (including `BackupAgent`) | Prototype |
| `profiles` | Root certificates, proxies, VPN, DNS, APN, MDM payloads, name mimicry, non-removable profiles, profile ID IOCs, allowlists | Prototype |
| `path_iocs` | File path indicators against the backup manifest | Prototype |
| `exposure` | iOS version against kit card ranges | Prototype, ranges need verification |
| `correlate` | Sequence rules across message, crash and network events | Prototype, log patterns unvalidated |
| `ioc` | STIX2 and plain lists, signed feeds | Solid |

### Kit coverage

| Kit | Delivery | What Orchard Warden can see |
|---|---|---|
| Operation Triangulation | iMessage attachment, zero click | Font structure, `BackupAgent` process, IOC domains and accounts, version exposure |
| Pegasus (FORCEDENTRY, BLASTPASS) | iMessage and PassKit attachments | Disguised PDFs and JBIG2, pass archive contents, IOC domains, processes and accounts. WebP lossless validation is **not** implemented |
| CVE-2025-43300 | Image file | DNG heuristic only |
| Coruna | Web, hidden iframe | IOC domains in history and messages, version exposure. The exploit content is not in a backup |
| DarkSword | Web, hit and run | IOC domains and paths, version exposure |
| Predator, Candiru, others | Mostly links | IOC matching from public feeds |

Kit cards live in `src/orchardwarden/kits/cards/`. Their version ranges came from secondary summaries and
every card is flagged `needs_primary_source_review: true`.

## Verdicts

Orchard Warden never says a device is clean or safe. The verdict is one of:

- **Indicators found**: a known indicator or a structural signature legitimate files do not show.
- **Suspicious artifacts**: anomalies without a known indicator.
- **No known indicators found**: nothing known was seen. This is absence of evidence.

Every report also carries a **coverage grade** (A to D) describing how much was examined, a list of
modules that were skipped or partial and why, and a limits statement.

## What this does not do

- It does not decrypt encrypted backups. Use MVT.
- It cannot inspect memory, the kernel, the baseband, Wi-Fi, Bluetooth or cellular radio traffic.
  Those layers are on the roadmap as research tracks (see docs/plan).
- It does not detect memory-only implants after traces are gone, or web exploit content that never
  reaches a backup. Exposure analysis and IOC matching on history reduce but do not remove that gap.
- It does not validate WebP lossless tables, parse JBIG2 segments, or cover CVE-2023-41064.
- Its false positive rate is unmeasured on real data. The DNG and extension checks can fire on
  benign files, which is why they are reported as review items with caveats.
- Many paths and schemas (third party messaging apps, profile storage, log formats) are
  best-effort and need validation per iOS version. Use `docs/LAB_VALIDATION_RUNBOOK.md`.
- An attacker who deletes traces can defeat artifact-based checks.

## Data sources and licenses

- Indicator feeds are not bundled. They are fetched from
  [mvt-project/mvt-indicators](https://github.com/mvt-project/mvt-indicators) (MIT) and
  [AmnestyTech/investigations](https://github.com/AmnestyTech/investigations) (CC BY per its
  README). Follow their attribution terms.
- The file scanner is a clean-room implementation written from public vulnerability descriptions.
  [msuiche/elegant-bouncer](https://github.com/msuiche/elegant-bouncer) covers similar ground; only
  its public README was read, and its source was not used. See `docs/COVERAGE_ELEGANTBOUNCER.md`.
- Test fixtures are synthetic and contain no exploit payloads.

## Repository layout

```
src/orchardwarden/
  filescan/    structural file checks (ttf, pdf, tiff/dng, webp, pkpass)
  messaging/   sms.db forensics
  backup/      Manifest.db reader
  profiles/    configuration profile analysis
  exposure/    version exposure engine
  correlate/   event model, rules.yaml, logmap.yaml
  ioc/         STIX2 and list loading, signed feeds
  kits/        kit cards (YAML)
  report/      markdown and json reports
  live/        replay source and untested USB source
  testing/     synthetic fixture builders
docs/
  assets/                      logo and GitHub social preview image
  plan/                        full design and extension plans
  COVERAGE_ELEGANTBOUNCER.md   file exploit coverage review
  PUBLIC_SAMPLES.md            public data sources, verified and unverified
  LAB_VALIDATION_RUNBOOK.md    how to validate on real iOS versions safely
tests/
```

## Roadmap

1. Validate on real backups across iOS versions and fix schema assumptions.
2. WebP lossless table validation, JBIG2 segment parsing, an optional second engine adapter.
3. Live mode over USB (log and packet streaming) validated on hardware.
4. Desktop app with a guided flow for non-technical users.
5. Network layer (DNS and flow monitoring) and radio sensors, behind explicit validation gates.
6. Signed kit card and IOC distribution with a transparency log.

## Responsible use and security

Use Orchard Warden only on devices you own or are authorized to examine. Never put real device data in
issues or pull requests. See [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
