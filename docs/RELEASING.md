# Building and releasing binaries

## Local, for testing (no Apple account needed)

```
pip install -e ".[dev]" pyinstaller
pyinstaller --onefile --name orchardwarden --collect-data orchardwarden --paths src packaging/entry.py
./dist/orchardwarden demo
```

On macOS an unsigned binary is blocked by Gatekeeper after download. For local testing only:
`xattr -d com.apple.quarantine dist/orchardwarden` or ad-hoc sign it with
`codesign --force --sign - dist/orchardwarden`. Do not distribute unsigned macOS binaries to
non-technical users, and do not tell users to disable Gatekeeper.

## Signed and notarized macOS builds (GitHub Actions)

The workflow in `.github/workflows/release.yml` signs with a Developer ID Application certificate
and notarizes with an App Store Connect API key. **Never paste these into chat, issues or
commits.** Store them as repository secrets (Settings, Secrets and variables, Actions):

| Secret | What it is |
|---|---|
| `MACOS_CERT_P12_BASE64` | Developer ID Application certificate exported as .p12, then `base64 -i cert.p12` |
| `MACOS_CERT_PASSWORD` | Password you set when exporting the .p12 |
| `MACOS_SIGN_IDENTITY` | Certificate name, for example `Developer ID Application: Your Name (TEAMID)` |
| `APPLE_API_KEY_P8_BASE64` | App Store Connect API key (.p8), base64 encoded |
| `APPLE_API_KEY_ID` | Key ID of that API key |
| `APPLE_API_ISSUER_ID` | Issuer ID shown in App Store Connect |

Then push a tag (`git tag v0.1.0a1 && git push --tags`) or run the workflow manually. Without the
secrets the macOS jobs still build, unsigned.

Notes:
- A bare command line binary cannot be stapled. Notarization still lets Gatekeeper verify it online.
  Shipping a signed `.pkg` or `.dmg` would allow stapling and is a reasonable next step.
- Use an environment with required reviewers for the secrets so only approved runs can sign.
- The signing steps have not been run yet. Expect to fix small issues on the first run.
- Give users the SHA-256 file and publish it somewhere separate from the download.

## Not covered

This project is a command line tool, not an iOS app. An iOS app (for example the guidance helper
in the plan) would need an Apple Developer Program membership, provisioning profiles and Xcode,
and has to be built and signed on macOS.
