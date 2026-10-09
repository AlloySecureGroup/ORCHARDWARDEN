# Changelog

## 0.1.0a1 (unreleased)

Initial alpha.

- Backup scanner for decrypted iOS backups (Manifest.db based).
- Structural file scanner: TrueType undocumented opcodes, PDF/JBIG2 and extension mismatch, DNG
  component heuristic, WebP container checks, PassKit archives. WebP lossless table validation is
  not implemented and is reported as an unsupported check.
- Messaging forensics: deleted-message gap inference, orphan attachments, invisible messages,
  first-contact attachments, link and account IOC matching.
- Safari history and DataUsage artifact checks.
- Configuration profile analysis with payload risk scoring, allowlists, and profile ID IOCs.
- Exposure analysis against kit cards (Triangulation, Coruna, DarkSword, FORCEDENTRY and BLASTPASS
  file exploits, CVE-2025-43300).
- Cross-layer correlation rules over normalized events and raw log replay.
- IOC loading for STIX2 and plain lists, including file paths, hashes, profile IDs and emails.
  Parses 99.95% of 5,889 indicators in the public mvt-indicators and Amnesty feeds.
- Ed25519 signed feed envelopes with pinned keys.
- `schema-report` privacy-safe structure report for validating parsers on real iOS versions.
- Standalone binary packaging (PyInstaller) and a release workflow with optional macOS signing (untested in CI).
- Logo and 1280x640 social preview image under docs/assets.
- Reports with verdict, coverage grade, redaction by default and limits statement.
