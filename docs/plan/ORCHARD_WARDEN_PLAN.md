# Project Orchard Warden: iOS Integrity Verification Kit for Journalists

Working title: Orchard Warden
Status: Planning document v0.1
Date: 2026-10-09
Foundation: Mobile Verification Toolkit (MVT), open source, by Amnesty International Security Lab

---

## 1. Mission

Give journalists, and the people who support them, a free and trustworthy way to check whether an iPhone or iPad shows signs of compromise by mercenary spyware such as Pegasus, Predator, and similar frameworks, without needing a paid forensic vendor or a specialist on call.

### Success criteria

1. A non-technical journalist can run a full check in under 30 minutes with no command line.
2. Results are explained in plain language with clear next steps.
3. No device data ever leaves the user's machine unless the user explicitly exports it.
4. Indicator-of-compromise (IOC) data stays current without the user doing anything.
5. Results are defensible: every finding links to its source indicator and evidence.
6. Digital security trainers and NGOs (Access Now, Amnesty, Citizen Lab, CPJ, RSF) can use it to triage at scale.

---

## 2. Reality Check: What Is and Is Not Possible

This section shapes the whole architecture. It must be communicated honestly to users.

### 2.1 Hard platform limits

| Desired capability | Reality on iOS |
|---|---|
| Live memory forensics on the phone | Not possible. iOS app sandboxing blocks reading other process memory. No public API exists. Full memory acquisition needs a jailbreak or exploit, which is unavailable or unsafe on current iOS. |
| Real-time on-device scanning app | Not possible in the App Store model. An iOS app cannot enumerate processes, read system logs, or read other apps' data. |
| Full filesystem dump | Only on jailbreakable devices. Not viable for current hardware or OS versions. |
| Reading backups | Possible. Encrypted local backups via USB expose a large amount of useful data. |
| Sysdiagnose analysis | Possible. User triggers it, device produces an archive, the desktop tool parses it. |
| Network traffic analysis | Possible from outside the device (DNS or proxy or router level). |

### 2.2 Consequence for the product

"Real time" must be redefined as **near real time, on demand, from a trusted companion machine**:

- Desktop companion app does the heavy forensics (backup, sysdiagnose, IOC matching).
- Optional iOS helper app provides guidance, hardening checks, and sysdiagnose walkthroughs only. It makes no claim of being able to detect spyware by itself.
- Optional continuous network monitor (home or newsroom gateway) provides ongoing DNS and traffic IOC matching, which is the closest honest equivalent to real time.

### 2.3 Honest result semantics

The tool must never say "your device is clean." Allowed verdicts:

- **Indicators found**: one or more IOCs matched. High priority escalation.
- **Suspicious artifacts**: heuristic anomalies, no IOC match.
- **No known indicators found**: absence of evidence, not proof of safety. Explain which data sources were available and which were missing (for example, a recent OS update or reboot can erase artifacts).

---

## 3. Threat Model

### 3.1 Adversary
Well-resourced state or state-aligned operators using zero-click and one-click exploit chains, with anti-forensic behavior (log wiping, process name masquerading, artifact cleanup).

### 3.2 User
Journalist, activist, lawyer, or NGO staff. May be under surveillance, may be in a hostile jurisdiction, may have limited technical skill, may fear retaliation if the tool is found on their machine.

### 3.3 Assets to protect
- The journalist's sources and communications.
- Backup contents (contain messages, contacts, photos, locations).
- Scan results (proof of targeting could itself be sensitive).
- The IOC feed integrity (poisoned IOCs could cause false alarms or hide real hits).

### 3.4 Threats to the tool itself
- Compromised desktop host (spyware also on the laptop).
- Malicious or tampered IOC feed.
- Tampered releases (supply chain).
- Leaked backups or reports.
- Hostile border or police inspection of the machine.
- False positives causing panic or legal exposure.
- False negatives giving false comfort.

---

## 4. Architecture Overview

```
                +---------------------------------------------+
                |              Orchard Warden Desktop               |
                |  (macOS first, then Windows and Linux)      |
                |                                             |
  iPhone  <-USB->  Device Acquisition Layer                   |
                |   - libimobiledevice / pymobiledevice3      |
                |   - encrypted backup                        |
                |   - sysdiagnose retrieval                   |
                |            |                                |
                |            v                                |
                |   Analysis Engine (MVT core, Python)        |
                |   - backup modules                          |
                |   - sysdiagnose modules                     |
                |   - IOC matcher (STIX2)                     |
                |   - heuristics and timeline builder         |
                |            |                                |
                |            v                                |
                |   Evidence Vault (encrypted, local)         |
                |            |                                |
                |            v                                |
                |   UI (guided wizard) + Report Generator     |
                +---------------------------------------------+
                      ^                         |
                      |                         v
          Signed IOC Feed Sync        Optional export to a
          (Amnesty, Citizen Lab,      trusted analyst (encrypted)
           Access Now, others)

   Optional: Orchard Warden Gateway (Raspberry Pi or container)
   - DNS and flow logging, IOC matching on domains and IPs
   - Alerts the desktop app, never stores payloads

   Optional: Orchard Warden Helper (iOS app)
   - Guided sysdiagnose trigger instructions
   - Lockdown Mode, update status, profile and VPN checklist
   - No spyware detection claims
```

### 4.1 Component summary

| Component | Language | Purpose |
|---|---|---|
| orchardwarden-core | Python 3.11+ | Wraps and extends MVT, orchestrates scans |
| orchardwarden-acquire | Python | Device pairing, backup, sysdiagnose, file pull |
| orchardwarden-ioc | Python | Feed sync, signature verification, STIX2 indexing |
| orchardwarden-timeline | Python | Unified event timeline across artifacts |
| orchardwarden-heuristics | Python | Anomaly rules beyond IOC matching |
| orchardwarden-ui | Tauri (Rust + web frontend) or Electron | Guided wizard |
| orchardwarden-report | Python + templates | PDF, HTML, JSON reports |
| orchardwarden-gateway | Python or Go | Network monitor |
| orchardwarden-helper-ios | Swift | Guidance app |

Recommendation: Tauri for smaller attack surface and footprint. Python core bundled as a sidecar with a pinned, hash-verified dependency set.

---

## 5. Data Sources and Analysis Modules

### 5.1 Acquisition methods (ordered by practicality)

1. **Encrypted iTunes or Finder style backup** (primary). Encryption matters because it includes more artifacts (for example, health and keychain-adjacent metadata is excluded, but many databases are only present in encrypted backups).
2. **Sysdiagnose archive** (secondary). Contains crash logs, process lists, shutdown logs, and system state.
3. **Selected file pulls via AFC** where permitted.
4. **Network telemetry** from the gateway or a user supplied PCAP or DNS log.
5. **Full filesystem image** (only for supported jailbroken or research devices, advanced analysts, out of scope for the default flow).

### 5.2 Artifact families to parse

| Family | Examples | Why it matters |
|---|---|---|
| Messaging | SMS and iMessage database, attachments metadata, WhatsApp and other app databases | Malicious links and attachments, zero-click delivery traces |
| Browser | Safari history, WebKit storage, resource load statistics, session data | Exploit landing pages, redirect chains |
| Process and network usage | Data usage database, process names with network counters | Unknown or masqueraded processes with traffic |
| Crash and analytics | Crash logs, analytics aggregates, OS analytics, shutdown log | Exploit crashes, process anomalies |
| Configuration | Installed profiles, MDM, certificates, VPN configs | Persistence via profiles, traffic interception |
| Apps | Installed apps list, entitlements, sideloaded and enterprise signed apps | Rogue apps |
| Calls and contacts | Call history, contacts, FaceTime | Social engineering, invitation exploits |
| Location and services | Locationd clients, cache files | Unexpected access |
| Calendar and notes | Invite based vectors | Attachment or link delivery |
| Backup manifest | File inventory, timestamps, missing expected files | Tampering and cleanup signs |
| System state | iOS version, patch level, last boot, uptime anomalies | Vulnerable version windows |

### 5.3 Detection strategy layers

1. **IOC matching**: domains, URLs, emails, process names, file names and paths, app bundle IDs, profile identifiers, hashes where available.
2. **Behavioral heuristics**: rules independent of known IOCs, for example:
   - Process names that mimic system daemons but never appear in a clean baseline.
   - Network usage records for processes with no matching installed binary.
   - Repeated crashes of messaging parsing components around the same time.
   - Unexpected configuration profiles or root certificates.
   - Missing or truncated logs within an otherwise populated timeline (possible cleanup).
   - Messages with suspicious attachment patterns arriving before a crash or anomaly.
3. **Timeline correlation**: merge all artifacts into one chronological view so analysts see sequences (message received, crash logged, unusual process, outbound traffic).
4. **Baseline comparison**: compare against a library of known-clean artifact profiles per iOS version, built from lab devices.
5. **Cross-device correlation** (newsroom mode, opt in): same IOC or same sender across several staff devices increases confidence of a campaign.

---

## 6. IOC Intelligence Pipeline

### 6.1 Sources
- Amnesty International Security Lab published indicators.
- Citizen Lab published indicators.
- Access Now Digital Security Helpline contributions.
- Other vetted research organizations.
- User supplied private IOC files (STIX2 or plain lists).

### 6.2 Integrity controls
- All feeds ship as signed bundles. Orchard Warden verifies signatures before use.
- Pinned public keys in the app, with a key rotation procedure.
- Transparency log of every feed update (hash chain) so tampering is detectable.
- Feed provenance shown in findings ("matched indicator from source X, published date Y").
- Each IOC carries confidence and expiry metadata.
- Offline bundle import for air-gapped use.

### 6.3 Update behavior
- Background sync over Tor or a privacy preserving transport as an option.
- Feed download never reveals the user's device or findings.
- Fetch must look like ordinary HTTPS to a CDN to reduce profiling risk.

---

## 7. Security and Privacy Design

### 7.1 Principles
1. Local first. No telemetry by default. No cloud analysis.
2. Minimize what is stored. Extract the needed fields, avoid duplicating full message content where possible.
3. Encrypt everything at rest, with a key derived from a user passphrase.
4. Make secure deletion and "panic wipe" first class.
5. Reproducible, signed builds.

### 7.2 Controls

| Area | Control |
|---|---|
| Evidence vault | Per-case encrypted container (for example age or libsodium based, Argon2id key derivation) |
| Backups | Encrypted backup password stored only in OS keychain or never stored (user choice) |
| Reports | Redaction mode: hide message bodies, contact names, and phone numbers by default |
| Updates | Signed updates, reproducible builds, SBOM published |
| Dependencies | Pinned with hashes, automated vulnerability scanning |
| Host integrity | Pre-scan host check warning if the laptop shows signs of compromise, and a recommendation to use a clean machine or a live USB image |
| Deniability | Optional "low profile" install name and no persistent logs |
| Duress | Optional duress passphrase opens an empty vault |
| Wipe | One action secure wipe of cases, caches, and logs |
| Analytics | None. Crash reports are opt in and scrubbed |

### 7.3 Clean room option
Provide a bootable, read-only live image (Linux based) with Orchard Warden preinstalled, so a journalist can scan from a machine state that is unlikely to be compromised and that leaves no trace on the host.

---

## 8. User Experience

### 8.1 Guided wizard (desktop)

1. **Safety check**: warn about the threat model, advise on whether it is safe to proceed (for example, avoid running at a location under watch).
2. **Connect**: plug in device, trust prompt, explain each step.
3. **Choose depth**: Quick (backup and IOC match), Standard (adds sysdiagnose and heuristics), Deep (adds timeline and baseline comparison).
4. **Acquire**: progress with plain language status.
5. **Analyze**: show which modules ran and which could not run, and why.
6. **Results**: verdict card, evidence list, severity, recommended actions.
7. **Report**: export for self, a trusted helper, or a digital security organization.

### 8.2 Result screen principles
- Lead with what the person should do next.
- Show evidence in layers: summary, then detail, then raw artifact.
- Provide "Why does this matter?" and "How confident are we?" for every finding.
- Never use alarmist language without evidence. Never use reassuring language without caveats.

### 8.3 Recommended actions library
- If indicators are found: stop sensitive communication on that device, use another device, contact a helpline, preserve evidence, do not factory reset before analyst review unless advised, assess exposure of sources.
- If suspicious only: update iOS, enable Lockdown Mode, reboot regularly, re-scan, seek review.
- If nothing found: keep OS updated, Lockdown Mode, disable risky features, re-scan periodically, note data limits.

### 8.4 Accessibility and localization
- Screen reader support, high contrast, keyboard navigation.
- Localization priority: English, Spanish, French, Arabic, Farsi, Russian, Turkish, Hindi, Portuguese, Ukrainian, Chinese, Amharic.
- Right to left layout support.
- Plain language review with real journalists in each major region.

---

## 9. Optional Components

### 9.1 Orchard Warden Gateway (continuous network monitoring)
- Runs on a Raspberry Pi, mini PC, or container on the newsroom network.
- Acts as DNS resolver with IOC domain matching and logs only matches by default.
- Optional flow metadata analysis (destination IPs, SNI) without payload capture.
- Alerts delivered to the desktop app or a secure channel.
- Caveat: only sees traffic on that network, and encrypted DNS on the device may bypass it, so document configuration clearly.

### 9.2 Orchard Warden Helper (iOS)
- Walkthrough for triggering a sysdiagnose and moving it to the desktop.
- Hardening checklist: iOS version, Lockdown Mode, automatic updates, unknown profiles, VPN and proxy settings, Safari and Messages exposure settings, disappearing messages, app permissions.
- Clear statement: this app cannot detect spyware by itself.
- App Store review friendly, no private API use.

### 9.3 Newsroom mode
- Multi-device case management for IT or security leads.
- Role separation: scanner, analyst, reviewer.
- Aggregated, anonymized IOC hit statistics to help spot campaigns.
- Consent flow so individual journalists control what is shared.

### 9.4 Analyst workbench
- Timeline explorer with filters and pivots.
- Artifact viewer with hex and database views.
- Notes and annotation, chain of custody log, hash manifests.
- Export to formats used by other forensic tools.

---

## 10. Repository and Engineering Plan

### 10.1 Layout

```
orchardwarden/
  core/              analysis engine, MVT integration layer
  acquire/           device pairing, backup, sysdiagnose
  ioc/               feed sync, signature verification, index
  heuristics/        rule engine and rule packs
  timeline/          unified event model
  baseline/          known-clean profiles per iOS version
  vault/             encrypted case storage
  report/            templates and renderers
  ui/                Tauri app and frontend
  gateway/           network monitor
  helper-ios/        Swift guidance app
  liveimage/         bootable image build scripts
  docs/              user guides, threat model, methodology
  tests/             unit, integration, fixtures
  tools/             dev scripts, release signing
```

### 10.2 MVT integration approach
- Use MVT as a library, not a fork, wherever possible, to inherit upstream module improvements.
- Wrap each MVT module with a stable internal interface so modules can be swapped, versioned, and tested.
- Contribute generic fixes and new modules upstream rather than diverging.
- Review the MVT license terms carefully before distribution and before any commercial or hosted use. Resolve this in Phase 0 with legal review and a conversation with the maintainers.

### 10.3 Standards and practices
- Typed Python with strict linting and static analysis.
- Memory safe languages for new native code (Rust, Swift).
- Threat-model-driven code review for acquisition and parsing code (parsers of untrusted data are an attack surface).
- Fuzz all database, plist, and archive parsers.
- Sandboxed parsing process with minimal privileges.
- CI with reproducible builds, SBOM, dependency pinning, and signed releases.

### 10.4 Testing strategy

| Layer | Approach |
|---|---|
| Unit | Per-module parsing with synthetic fixtures |
| Integration | End to end scans against sanitized sample backups |
| Detection | Test corpus of benign backups across iOS versions plus synthetic IOC injection |
| False positive | Large benign corpus run, track alert rate per rule |
| Regression | Golden outputs per module and per version |
| Fuzzing | Continuous fuzzing of parsers |
| Usability | Moderated tests with journalists and trainers |
| Security | Independent audit before 1.0, then yearly |
| Performance | Large backup targets (100 GB plus) within time and memory budgets |

Note on test data: never use real journalist data. Build fixtures from lab devices, synthetic generators, and publicly shared sample data from research organizations.

---

## 11. Phased Roadmap

### Phase 0: Foundations (4 to 6 weeks)
- Legal review of MVT license and IOC licensing terms.
- Contact Amnesty Tech, Citizen Lab, Access Now for partnership and feed access.
- Finalize threat model with input from journalists and trainers.
- Establish governance, security policy, and responsible disclosure process.
- Set up repo, CI, signing, reproducible build pipeline.
- Deliverable: signed-off design document and partnerships.

### Phase 1: Core Engine MVP (8 to 10 weeks)
- Wrap MVT backup analysis with stable internal interfaces.
- Encrypted backup acquisition via USB on macOS.
- Signed IOC feed sync and matching.
- Basic CLI plus JSON reports.
- Evidence vault.
- Deliverable: CLI that produces a reliable IOC match report from an encrypted backup.

### Phase 2: Guided Desktop App (8 to 10 weeks)
- Tauri UI with the guided wizard.
- Plain language results and recommended actions.
- Sysdiagnose acquisition and parsing.
- Redacted report export (PDF and HTML).
- Usability testing round 1 with journalists.
- Deliverable: private beta for trusted trainers and helplines.

### Phase 3: Heuristics and Timeline (10 to 12 weeks)
- Unified timeline engine.
- Heuristic rule pack with false positive tracking.
- Baseline library for supported iOS versions.
- Host integrity pre-check.
- Deliverable: richer detection that does not rely only on published IOCs.

### Phase 4: Cross Platform and Hardening (8 to 10 weeks)
- Windows and Linux support.
- Live USB clean room image.
- Panic wipe, duress vault, low profile mode.
- Localization first wave.
- Independent security audit.
- Deliverable: public beta.

### Phase 5: Gateway and Helper App (8 to 12 weeks)
- Network gateway with DNS IOC matching.
- iOS helper guidance app.
- Newsroom mode with consent based sharing.
- Deliverable: continuous monitoring option.

### Phase 6: Analyst Workbench and 1.0 (8 to 10 weeks)
- Timeline explorer, chain of custody tooling.
- Documentation, training materials, workshops.
- Public 1.0 release with signed, reproducible builds.

### Ongoing
- IOC feed maintenance, new iOS version support (every major release changes artifact formats), module updates, audits, community support, incident response for the tool itself.

---

## 12. Team and Partnerships

### Roles
- Security engineer lead (forensics and mobile).
- Python engineer (core and modules).
- Rust or TypeScript engineer (desktop app).
- Swift engineer (helper app).
- Applied cryptography reviewer.
- UX researcher and designer with experience in high-risk users.
- Technical writer and translator coordinator.
- Community and trainer liaison.
- Part time legal counsel.

### Partners
- Amnesty International Security Lab (MVT maintainers, IOC publishers).
- Citizen Lab.
- Access Now Digital Security Helpline.
- Committee to Protect Journalists, Reporters Without Borders, Freedom of the Press Foundation.
- Digital security training networks.
- Academic labs for baseline research and audits.

### Funding approaches (to keep it free for users)
- Grants (press freedom, internet freedom, and digital rights funders).
- Foundation and NGO sponsorship.
- Optional paid support and training for institutions, with the tool itself always free.

---

## 13. Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| False negatives (spyware not detected) | Dangerous false comfort | Careful verdict wording, document limits, show data coverage, encourage expert review |
| False positives | Panic, wrongful accusations | Confidence levels, evidence links, analyst review path |
| Compromised host laptop | Scan results or vault exposed | Host check, live image, minimal retention |
| Poisoned IOC feed | Hidden or fake detections | Signed feeds, transparency log, multi-source corroboration |
| iOS changes break parsers | Silent loss of coverage | Per-version test suite, explicit "module unsupported" reporting |
| Legal exposure of users | Tool present on device used as evidence | Low profile mode, wipe, guidance on local legal risks |
| Misuse against third parties | Privacy harm | Scope tool to user owned devices, consent requirements, review MVT license restrictions |
| Anti-forensics by spyware | Missing artifacts | Detect cleanup signs, timeline gaps, combine with network evidence |
| Maintainer burnout | Stale IOCs, abandoned tool | Partnerships, funding, clear governance |
| Over-claiming "real time" | Loss of trust | Precise marketing language: on-demand and continuous network monitoring, not on-device live memory scanning |

---

## 14. Ethics and Responsible Operation

- The tool defends users and must not be repurposed for surveillance of others. Require the user to confirm they own or are authorized to inspect the device.
- Publish methodology, limitations, and detection coverage openly.
- Responsible disclosure of any newly found exploit artifacts to Apple and to research partners.
- Do not store or transmit victim data to build detections without informed, revocable consent.
- Provide a human path: every scary result links to a real helpline, because software alone is not enough support.

---

## 15. Success Metrics

- Time to first completed scan for a new user.
- Percentage of scans completed without needing support.
- IOC feed freshness (median age of newest indicator).
- Number of supported iOS versions and artifact modules.
- False positive rate per rule.
- Number of trainers and helplines using the tool.
- Audit findings closed.
- Languages supported.

---

## 16. Immediate Next Steps

1. Confirm MVT license compatibility and identify any redistribution constraints.
2. Reach out to Amnesty Tech and Citizen Lab about collaboration and feed licensing.
3. Run MVT end to end on a lab device and document where it is slow, confusing, or fragile.
4. Prototype device acquisition with pymobiledevice3 or libimobiledevice on macOS.
5. Draft the vault format and signing scheme.
6. Run five interviews with journalists and digital security trainers to validate the wizard flow.
7. Decide: Tauri versus Electron, based on a spike.
8. Stand up the repo, CI, and reproducible build skeleton.

---

## 17. Open Questions

- Which iOS versions and device generations will be officially supported at launch?
- How will baseline clean profiles be built and verified at scale without real user data?
- What is the process for a journalist to get expert human review safely and quickly?
- Can the gateway reliably cover users on mobile data and public Wi-Fi, or should a trusted DNS profile be offered?
- How should the project handle the possibility that a user is already being monitored and the scan itself is observed?
- What governance structure keeps the IOC pipeline trusted over the long term?

---

## Appendix A: Glossary

- **IOC**: Indicator of Compromise, a data point linked to known malicious activity.
- **STIX2**: Structured format for sharing threat intelligence.
- **Sysdiagnose**: iOS diagnostic archive containing logs and state.
- **Zero-click**: Exploit requiring no user interaction.
- **Lockdown Mode**: Apple's extreme protection mode reducing attack surface.
- **BlastDoor**: Apple's sandboxed service for parsing untrusted message content.
- **AFC**: Apple File Conduit, a limited file access service over USB.

## Appendix B: Reference Projects and Resources

- Mobile Verification Toolkit (MVT) and its documentation.
- libimobiledevice and pymobiledevice3.
- Amnesty International Security Lab research and indicator repositories.
- Citizen Lab research reports on mercenary spyware.
- Access Now Digital Security Helpline.
- Apple Platform Security guide and Lockdown Mode documentation.
