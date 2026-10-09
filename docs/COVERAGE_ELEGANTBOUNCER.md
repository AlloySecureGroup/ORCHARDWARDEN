# Coverage review: msuiche/elegant-bouncer

Date: 2026-10-09
Reviewed: the public README at github.com/msuiche/elegant-bouncer (v0.2 help output, per the page).

## How this was done

Only the public README was read. No source code from that repository was read or copied.
Orchard Warden's file scanner is a clean-room implementation written from public vulnerability
descriptions, so any behavioural difference from ELEGANTBOUNCER is expected. The README does not
state the license type, and it does not describe the detection method in detail, so neither is
assumed here. Check the license before any redistribution or bundling.

## What ELEGANTBOUNCER covers (per its README)

| Threat | CVEs | Input |
|---|---|---|
| FORCEDENTRY | CVE-2021-30860 | PDF and image-named files |
| BLASTPASS | CVE-2023-4863, CVE-2023-41064 | WebP, images, PassKit related |
| TRIANGULATION (font stage) | CVE-2023-41990 | TTF and OTF fonts |
| CVE-2025-43300 | CVE-2025-43300 | DNG and TIFF |

Input handling: single files, folders (recursive), extensions pdf, gif, webp, jpg, jpeg, png,
tif, tiff, dng, ttf, otf, iOS backup reconstruction, and messaging attachment scanning for
iMessage and SMS, WhatsApp, Viber, Signal (attachments folder only, its database is encrypted)
and Telegram. Its README presents a structural approach that does not depend on in-the-wild
samples.

## Gap analysis: what Orchard Warden did and did not match

| Capability | ELEGANTBOUNCER | Orchard Warden prototype | Status |
|---|---|---|---|
| Triangulation font stage (CVE-2023-41990) | Yes | Walks fpgm, prep and glyph programs, flags opcodes 0x8F and 0x90, skips push data correctly | **Implemented**, mutation tested |
| FORCEDENTRY (CVE-2021-30860) | Yes | Detects image-named PDFs and JBIG2 filter use (including inside Flate streams). Does **not** parse JBIG2 segments | **Partial** (delivery pattern only) |
| BLASTPASS WebP (CVE-2023-4863) | Yes | RIFF container checks only. VP8L Huffman table validation is **not implemented** and is reported as an unsupported check in every report | **Not implemented** |
| BLASTPASS PassKit vector | Yes | Opens .pkpass archives with zip bomb limits and scans inner files recursively | **Partial** |
| CVE-2025-43300 (DNG) | Yes | TIFF/DNG IFD walk, SamplesPerPixel vs lossless JPEG component count | **Heuristic**, review item, false positives possible on legitimate multi component raw files |
| CVE-2023-41064 ImageIO | Yes | No specific check | **Not implemented** |
| Messaging attachment scan: iMessage, WhatsApp, Viber, Signal, Telegram | Yes | Manifest.db driven extraction for all five. Third party app domains are best effort and **unvalidated** | **Partial** |
| iOS backup reconstruction | Yes | Reads a decrypted backup via Manifest.db in place. Encrypted backups are refused with a clear message (decrypt first) | **Different approach** |
| Real time scanning TUI | Yes | Not implemented | Gap |
| Exploit sample generator (WIP in its README) | Yes | **Deliberately not built.** Orchard Warden is detection only | Out of scope |

## What Orchard Warden adds beyond ELEGANTBOUNCER

IOC matching from signed feeds, messaging forensics (deleted-message gap inference, orphans,
invisible messages), Safari and DataUsage artifact checks, configuration profile analysis,
exposure analysis by iOS version, kit cards, and cross-layer correlation rules.

## Recommended integration

1. Keep the native scanner as the default engine so the product has no hard dependency on a
   third party binary.
2. Add an optional **external engine adapter**: when `elegantbouncer` is installed, run it over
   the extracted attachment tree, and record its detections as findings with source set to that
   tool. A second independent implementation is valuable for the same reason two antivirus
   engines are: they disagree in useful ways. The output format is not documented in the README,
   so the adapter needs to be written against real output and tested with the binary.
3. Close the native gaps in this order: VP8L Huffman validation (highest value, most widely
   deployed library), JBIG2 segment parsing, ImageIO specific checks.
4. Run both engines against the same corpus of benign files to measure false positive rate
   before trusting either result in a report.
5. Contact the maintainer about license terms, shared test corpora, and avoiding duplicate work.

## Honest limits

Structural detection finds file-borne exploits that reached the device as files. It does not see
web-delivered chains (Coruna, DarkSword), memory-only implants, or anything whose carrier file was
deleted. Those are handled by the other layers (exposure analysis, IOC and history matching,
network and log correlation) and still have blind spots.
