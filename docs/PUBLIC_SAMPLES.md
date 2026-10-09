# Public samples and test data

Date: 2026-10-09. Verified means I downloaded it and ran Orchard Warden against it. Everything else is a lead.

## Verified: indicator feeds (used)

| Source | Contents | License | Verified |
|---|---|---|---|
| github.com/mvt-project/mvt-indicators (commit b22ddf0, 2026-08-27) | STIX2 plus plain text indicators: Operation Triangulation, Coruna/CryptoWaters, DarkSword, Intellexa Predator, Candiru, QuaDream (KingsPawn), RCS Lab, Cellebrite, WyrmSpy and DragonEgg, EagleMsgSpy, SIO Spyrtacus, IPS Morpheus, BTMOB, ResidentBat | MIT | Yes, 14 bundles |
| github.com/AmnestyTech/investigations (commit 3d8f248, 2024-12-16) | STIX2 for Pegasus (2021), Cytrox/Predator, Android campaign, Wintego Helios, Serbia NoviSpy, others | CC BY (per its README) | Yes, 5 bundles |

Results with Orchard Warden against all 19 bundles (5,889 indicators):

- 99.95% parsed. The only 3 unparsed are Android `android-property` patterns, irrelevant to iOS.
- Indicator kinds present: domains (5,317), IPs (73), processes (83), emails (65), app IDs (32), file names (15), plus file paths, SHA-256 hashes, configuration profile IDs and app certificate hashes.
- The first pass handled only 62% of them. Real data showed I was missing `file:path`,
  lowercase `file:hashes.sha256`, `configuration-profile:id`, and `app:cert.sha256`, and that Pegasus
  and Triangulation list iMessage account emails that should be matched against message handles.
  All are now handled and tested.
- False-positive check: all 5,889 real indicators loaded against a clean synthetic backup produced
  zero non-informational findings.
- Cross-check: the public Triangulation bundle lists process `BackupAgent`, matching Orchard Warden's
  built-in heuristic.

Reproduce: clone both repos into one folder and run `ORCHARD_SAMPLES=<folder> pytest`.

## Leads not verified (could not fetch or confirm in this session)

| Lead | Why it matters | Status |
|---|---|---|
| Digital Corpora mobile image collection (Josh Hickman iOS images for several iOS versions) | Real, benign, full filesystem iOS images for false-positive testing across versions | Search surfaced the site but the page fetch was blocked by robots.txt. Confirm the iOS versions, format and license manually. These are filesystem extractions, not iTunes style backups, so a converter or adapter would be needed |
| github.com/EC-DIGIT-CSIRC/sysdiagnose (EUPL-1.2) | Parsers for iOS sysdiagnose, lists iOS 15 to 18 and 26 as tested. References a test-data folder | Project confirmed. Whether it ships sample archives is not stated. Inspect its `tests` folder |
| Magnet Forensics CTF challenges (2022 to 2026) | Public mobile forensics images with known planted artifacts | Search results only. Check each year's challenge page for iOS images and terms |
| Academic paper: Forensic Examination of iOS Platform Artifacts, multi-tool study using publicly available data | Points to the public datasets it used | Search result only. Read the paper's data section |

## What does not exist (as far as I could find)

- **No public iOS backup from a device genuinely infected with Pegasus, Predator, Triangulation,
  Coruna or DarkSword.** Those would contain victims' private data. Detection of real infections
  therefore cannot be validated here beyond synthetic fixtures and published indicators.
- No public corpus of malicious file samples I would recommend pulling into a lab. The structural
  scanner tests use harmless synthetic stand-ins on purpose.

## Ways to get closer to real positives, safely

1. Ask Amnesty Tech Security Lab, Citizen Lab and Kaspersky whether they share sanitized or
   synthetic test artifacts for their published detections. Kaspersky's public triangle_check tool
   shows the artifact checks it expects.
2. Build lab positives yourself by planting only the published benign-equivalent markers (for
   example a process name row in DataUsage, a profile with a listed identifier) into a lab backup.
3. Partner with a helpline that can run Orchard Warden in-house on consented cases and report only
   aggregate results and false positive notes.
