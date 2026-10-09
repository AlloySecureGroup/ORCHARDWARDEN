# Lab validation runbook

Goal: find out what breaks first when the prototype meets real iOS backups, without exposing any
private data. Use lab devices with test accounts only. Never use a journalist's real device or data.

## Device matrix (minimum)

One lab device per row, each on a clean, freshly restored install with a test Apple ID:

| Row | Purpose |
|---|---|
| Oldest supported iOS you can obtain | Older database layouts and date units |
| iOS 16.x | Triangulation era, kit card ranges |
| iOS 17.x | Coruna range edge |
| iOS 18.4 to 18.7 | DarkSword range |
| Current release | Baseline for false positives |

Use the same model where possible, plus one different model, to separate version effects from model effects.

## Steps per device

1. Create content: send and receive iMessages with attachments (photo, PDF, font file, Wallet pass),
   WhatsApp and Signal test messages, delete a few messages, browse a few sites in Safari, install
   one benign configuration profile.
2. Make an **encrypted** Finder or iTunes backup, then decrypt it with `mvt-ios decrypt-backup`.
3. Run `orchardwarden schema-report BACKUP --out schema_<ios>.json`. This contains structure only.
4. Run `orchardwarden scan-backup BACKUP --out report_<ios>/` with no IOC file, then with a test IOC file.
5. Record per module: status, items examined, findings, and any exceptions.

## What to check in the output

| Assumption in the prototype | Where it lives | How to confirm |
|---|---|---|
| sms.db path and `message` ROWID uses AUTOINCREMENT | messaging | `sequence_tables` contains `message` |
| Message dates are nanoseconds on modern iOS, seconds on old | messaging | `message_date_unit` |
| Safari History.db domain and path | artifacts | database shows as present, not absent |
| DataUsage.sqlite path and ZPROCESS columns | artifacts | database present, columns listed |
| Third party messaging attachment domains and prefixes | backup | `interesting_prefixes` |
| Configuration profile storage layout and file names | scan | `profile_dir_files` |
| Benign deletions do not produce alarming findings | messaging | the clean scan reports only `info` gaps |
| Verdict on a fresh clean device | all | expect "No known indicators found" with only info findings |

## Share back

Send the `schema_*.json` files and, for each device, the list of module statuses and any error
text. Do not send backups, reports with `--no-redact`, or anything from real user devices.

## Expected first failures

Based on the design, expect these first: third party app attachment prefixes not matching,
profile files in a different location or format, differing Safari history locations on newer
iOS, and `attachment.filename` path forms that do not match backup relative paths (which would
produce false "missing file" notes).
