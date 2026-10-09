# Security and responsible use

## Intended use

Orchard Warden is a defensive tool for checking devices **you own or are explicitly authorized to
examine**, for example a journalist checking their own phone or a helpline working with consent.
Do not use it to inspect another person's device or backup without their informed consent.

## Handling data

iOS backups contain messages, contacts, photos and locations. Treat every backup, report and
schema file from a real device as highly sensitive.

- Develop and test only with synthetic data or lab devices with test accounts.
- Never attach real backups, unredacted reports or private keys to issues or pull requests.
- Reports redact URLs and filenames by default. `--no-redact` exists for analysts, use it carefully.
- `orchardwarden schema-report` records structure only and is the safe thing to share when reporting
  parser bugs against a real iOS version.

## Reporting a vulnerability in Orchard Warden

Orchard Warden parses untrusted files (databases, archives, fonts, images, plists). A malformed input
that crashes the scanner, hangs it, exhausts memory, or makes it read or write outside the
intended paths is a security bug.

Please report privately through GitHub's "Report a vulnerability" feature on this repository
(Security tab). Do not open a public issue for security bugs. Include a minimal synthetic file
that reproduces the problem. Do not send real device data.

## Reporting detection gaps or false positives

Open a normal issue. Include the iOS version, the module and finding ID, and a `schema-report`
output. For a missed detection, point to the public research it should have matched.

## Newly discovered exploit artifacts

If you find evidence of an in-the-wild exploit while using this tool, consider notifying Apple
Product Security and a research partner such as Amnesty International Security Lab, Citizen Lab
or the Access Now Digital Security Helpline. The tool's findings are leads, not proof.

## Honest limits

A clean result is never proof of safety. See the "What this does not do" section of the README.
