# Project Orchard Warden: Plan Extension v0.2

Date: 2026-10-09
Extends: ORCHARD_WARDEN_PLAN.md (v0.1). Where this document conflicts with v0.1, this document wins. Specifically it amends v0.1 sections 2.1, 2.2, 4, 5, 9 and 11.

Scope of this extension:

1. Exploit chain and kit coverage (Triangulation, Coruna, DarkSword, Pegasus family, Predator, Paragon, Reign and others)
2. Hidden and exploit-bearing iMessage and app message detection
3. DNS and proxy monitoring
4. MDM and configuration profile analysis
5. Custom lockdown (hardening policy engine)
6. Radio layer monitoring: cellular, Wi-Fi, Bluetooth, baseband
7. Live USB sensor mode (real time telemetry)
8. Correlation engine, rule languages, and exposure analysis
9. Revised architecture, roadmap, risks, and test plan

---

## 0. What Changes From v0.1 (Important)

### 0.1 "Real time" is partly possible after all

v0.1 said on-device real-time scanning is impossible. That remains true for an app running on the phone. However, a **USB-attached companion** can get live telemetry from an unjailbroken device through Apple's own service protocols:

| Live source | Mechanism (to validate per iOS version) | Value |
|---|---|---|
| Live unified log stream (os_log) | syslog relay and OSLog services over USB (libimobiledevice, pymobiledevice3) | Crashes, daemon activity, CommCenter and bluetoothd and wifid events, BlastDoor and imagent errors |
| Live packet capture with process attribution | pcapd style service or Remote Virtual Interface on macOS | Every packet the device sends, tagged with originating process |
| On-demand sysdiagnose | Trigger and pull over USB | Full system state snapshot |
| Diagnostics and device info | lockdownd and diagnostics services | OS version, build, uptime, baseband version, profiles list |
| Wireless sync backups | Finder or iTunes Wi-Fi sync, when enabled by the user | Scheduled nightly encrypted backups with no cable |

This enables **Orchard Warden Sentry mode**: the phone charges on a desk, and Orchard Warden continuously records logs and traffic, runs rules in near real time, and runs a full backup scan nightly.

### 0.2 Things that remain impossible

- Reading another process's memory, or kernel memory, on a stock device.
- Observing baseband internals, SIM applet traffic, or SS7 and Diameter signaling from the device.
- Guaranteed detection of non-persistent, memory-only implants after a reboot has erased traces.

Every radio and baseband feature below is therefore labeled with a **feasibility rating** and a **validation requirement**. Nothing is promised until proven in the lab with real devices.

### 0.3 Design stance

Detect through **multiple independent layers** so that anti-forensics at one layer is caught at another:

```
Layer A  Device artifacts   (backup, sysdiagnose, filesystem where available)
Layer B  Device live logs   (USB os_log stream)
Layer C  Network            (device pcap, gateway DNS, proxy, flow metadata)
Layer D  Configuration      (profiles, MDM, certs, VPN, DNS settings, supervision)
Layer E  Radio environment  (Wi-Fi, Bluetooth, cellular passive sensors)
Layer F  Intelligence       (IOC feeds, exploit kit cards, patch and exposure data)
```

A finding is strongest when two or more layers agree (for example: iMessage from unknown sender, then BlastDoor crash, then new outbound connection to a feed IOC).

---

## 1. Exploit Chain and Kit Coverage

### 1.1 Why kit awareness changes the design

Recent research shows two shifts that the detection design must respect:

1. **Exploit kits are proliferating.** Chains first seen in commercial surveillance operations have been observed in the hands of other state-linked actors and financially motivated criminals. Google Threat Intelligence Group (GTIG) documented Coruna and DarkSword reaching multiple actors across several countries within months. A journalist can be hit by a tool whose operator is not a classic spyware vendor.
2. **Many modern chains are web-delivered and hit-and-run.** They arrive via a hidden iframe or watering hole, steal data fast, and leave little persistent footprint. Detection therefore relies less on finding an implant on disk and more on **browser history, WebKit data, DNS and network records, crash logs, and version exposure analysis**.

### 1.2 Kit intelligence cards

Every kit gets a machine-readable card (YAML), versioned in the repo and signed in the feed. This makes new kits fast to add and every finding explainable.

```yaml
kit: coruna
aliases: [CryptoWaters]
first_public: 2026-03
reporting: [GTIG, iVerify, Kaspersky]
delivery: [web_hidden_iframe, watering_hole, scam_sites]
user_interaction: visit_only
affected_ios: "13.0 to 17.2.1 (chains), later patched"
lockdown_mode_effective: true
private_browsing_effective: true
persistence: low_or_none_observed
payload_family: [PlasmaLoader, PLASMAGRID]
primary_goal: [data_theft, crypto_wallet_theft, espionage]
cves: [CVE-2024-23222, CVE-2022-48503, CVE-2023-43000]
detection:
  ioc_types: [domain, url, ip, hash]
  yara: [published_by_gtig]
  artifacts: [safari_history, webkit_rls, dns_logs, crash_logs, netusage]
  heuristics: [fingerprint_then_redirect_pattern, hidden_iframe_domains_in_cache_where_present]
  exposure_check: ios_version_window_vs_cves
limits: [no_persistent_artifact_expected, depends_on_dns_or_history_survival]
sources: [urls]
```

Cards are written from published research only, and every IOC remains traceable to its source.

### 1.3 Coverage matrix (initial)

Confidence key: H = strong published artifacts exist, M = partial, L = mostly exposure and network based.

| Kit or family | Vector | What Orchard Warden checks | Layers | Confidence |
|---|---|---|---|---|
| **Operation Triangulation** | Zero-click iMessage attachment, multi-CVE chain including a kernel and hardware register bypass, implant reported not to survive reboot | MVT timeline patterns, unexpected process names with data usage entries (the deprecated BackupAgent binary name, distinct from BackupAgent2), clusters of lower-reliability indicators within minutes of each other, iMessage attachment trail then deletion, failure of iOS updates, C2 domains in DNS or network logs | A, B, C, D | H |
| **Coruna (CryptoWaters)** | Web: hidden iframe on watering holes and fake finance sites, fingerprinting then chain selection, 23 exploits across 5 chains, iOS 13.0 to 17.2.1, payloads include PlasmaLoader | GTIG IOCs and YARA, domains in Safari and WebKit records and DNS, version window exposure, Lockdown Mode status (reported effective against it), browsing mode context | A, C, F | M |
| **DarkSword** | Web: watering holes, six vulnerabilities including three zero-days, iOS 18.4 to 18.7, GHOSTBLADE data stealer, fast hit-and-run theft, seen with several actors | GTIG and partner IOCs, version window exposure (patched in iOS 26.3), history and DNS matches, crash logs around browsing, mitigation status (update or Lockdown Mode) | A, C, F | M |
| **Pegasus (NSO) family** | Zero-click iMessage (FORCEDENTRY era), BLASTPASS style attachment and Wallet vectors, earlier one-click | Existing MVT and Amnesty IOCs, process names, DataUsage, crash logs, message attachment anomalies, shutdown log, WebKit and Safari artifacts | A, B, C | H |
| **Predator (Intellexa)** | Mostly one-click links, network injection | URL and domain IOCs, Safari history, link in message then browser launch, DNS | A, C | M |
| **Paragon Graphite** | Zero-click iMessage vector reported by researchers in 2025 | Message and iCloud link artifacts, crash logs, published IOCs, version exposure | A, B, C | M |
| **Reign (QuaDream)** | Calendar invite based zero-click | Calendar and Mail invite artifacts, unknown organizers, crash logs | A, B | M |
| **Hermit style / sideloaded apps** | Enterprise-signed or sideloaded apps | App inventory, provisioning profiles, enterprise certs, MDM and profile checks | A, D | M |
| **Generic one-click and phishing** | Links via SMS, WhatsApp, Signal, Telegram, email | URL extraction across all message stores matched to IOC feeds and reputation | A, C | M |
| **Unknown or novel chains** | Any | Behavioral heuristics, timeline anomalies, cross-layer correlation, exposure alerts for exploited-in-the-wild CVEs | A, B, C, D | L |

Notes:

- Specific indicator strings are **never hard-coded** in this plan or in source. They are ingested from the original publishers (Kaspersky, GTIG, Lookout, iVerify, Citizen Lab, Amnesty, Apple security notes) through the signed feed, which keeps them current and attributable.
- The Triangulation vulnerabilities and internals should be reviewed against Kaspersky's own write-ups when implementing the module. Coverage claims must be re-validated against each publisher's updates.

### 1.4 Exposure analysis engine (new, high value)

For kits with limited persistent traces, the strongest evidence is often **"was this device exposed, and when?"**

Inputs:

- Device iOS version history reconstructed from backups, sysdiagnose, update logs, and prior Orchard Warden scans.
- CVE and patch data: Apple security release notes, known-exploited vulnerability catalogs, kit cards.
- Browsing and DNS history, message links.

Outputs:

- A timeline of **vulnerable windows** per kit (for example, "device ran an iOS version in the DarkSword range from date X to Y").
- Overlap of those windows with **IOC hits or suspicious web visits**.
- A prioritized recommendation: update, enable Lockdown Mode, reboot, investigate specific visits.

Example finding: "Between June and August the device was on a version vulnerable to Chain 3 of kit K. During that time it resolved domain D, which appears in the published IOC list. Confidence: high exposure, medium compromise."

### 1.5 Intelligence ingestion and new-kit response

- Watch feeds and advisories: GTIG, Lookout, iVerify, Kaspersky, Citizen Lab, Amnesty Tech, Apple security releases, and CISA known-exploited catalog.
- Target SLA: new published IOCs signed and shipped within days, kit card within a couple of weeks.
- A "kit onboarding checklist" in the repo: read report, extract IOCs, define artifacts, write rules, build test fixtures, add card, validate false positives, publish.
- Community contribution path with maintainer review and signing, so trusted researchers can add cards.

### 1.6 YARA and content scanning

- Where content is available (gateway-captured responses in lab mode, files from a filesystem image, pulled attachments, sysdiagnose files), run published YARA rules.
- Be explicit that standard Safari TLS traffic is not inspectable without interception, and most web exploit content will not be visible from a normal backup. The tool should say so rather than imply coverage.

---

## 2. Hidden Messages and Exploit-Bearing iMessage Detection

The user concern is correct: zero-click message exploits often leave the message hidden, deleted, or never rendered. MVT's standard SMS module covers visible records. Orchard Warden adds a dedicated **Messaging Forensics Module**.

### 2.1 Data sources

- SMS and iMessage database (messages, attachments, chats, join tables, deleted and recoverable message tables, sync tables) including **WAL and journal files and SQLite freelist pages**.
- Attachment directory metadata (file names, MIME types, UTI, sizes, timestamps, presence or absence on disk).
- Other messaging apps: WhatsApp, Signal (limited), Telegram, others via modules.
- Mail, Calendar invites, FaceTime and invitation records, shared album and sharing invitations, Wallet pass and PassKit delivery artifacts, HomeKit and other invitation channels.
- Push notification and daemon state where present.

### 2.2 Detection techniques

| Technique | What it finds |
|---|---|
| **Deleted record carving** | Parse freelist pages and WAL for removed message and attachment rows |
| **Row ID gap analysis** | Compare autoincrement counters to existing row IDs to infer deleted messages and their time ranges |
| **Orphan analysis** | Attachment rows with no message, messages with no chat, files on disk with no row, rows pointing to missing files |
| **Empty or invisible body messages** | Messages with no text or attachment shown to the user, zero-width or unusual Unicode, unusual balloon or app plugin identifiers |
| **Unknown sender plus attachment** | First-contact iMessage from a never-seen identifier carrying an attachment, followed by deletion or crash |
| **Attachment type risk scoring** | Image, PDF, font, audio, Wallet pass, animated formats, unusual UTI or extension mismatches, malformed size metadata |
| **Message to crash correlation** | Receipt of a message followed within seconds by crashes or restarts of message-processing services (for example the sandboxed message parsing service, imagent, transcoder agents, preview generators) |
| **Message to process to network correlation** | Message, then unfamiliar process data usage, then DNS or connection to IOC |
| **Link extraction** | Every URL from all stores, normalized and matched to IOC and reputation lists, with redirect chain resolution done only in a safe lab mode |
| **Calendar and Mail invite analysis** | Unknown organizers, attachments, auto-accepted invitations |
| **Service and account anomalies** | Unexpected iMessage identity or registration changes, new Apple ID associations, device list changes |
| **Timestamp tampering** | Messages with impossible times, clock jumps, insertions out of sequence |

### 2.3 Live message monitoring (Sentry mode)

- Watch live logs for message arrival and processing errors, parser crashes, attachment transcoding failures, and rapid repeated delivery attempts.
- Alert on bursts of messages from unknown identities, repeated crash-then-retry patterns, or processing of attachments with unusual types.
- Because the content cannot be read live, the alert uses **metadata and process behavior only**, preserving privacy.

### 2.4 Hardening linked to messaging

- Recommend and verify: unknown-sender filtering, Lockdown Mode, disabling iMessage and FaceTime for high-risk periods, restricting who can send invitations, disabling automatic attachment handling features that are optional, and regular reboots.
- Provide a **message quarantine workflow**: preserve a suspicious message set encrypted, with hash manifest, for expert review.

### 2.5 Limits stated to the user

- Messages cleaned by the attacker may leave only gaps. Gap detection raises suspicion but cannot prove the cause.
- Encrypted backups include much but not everything. A sysdiagnose and live logs add independent evidence.

---

## 3. DNS and Proxy Monitoring

### 3.1 Goals

1. Catch connections to known malicious infrastructure in near real time.
2. Provide historical evidence for exposure analysis (what resolved, when).
3. Protect users proactively by blocking known IOC domains.
4. Detect network-level interference (MITM, DNS tampering, rogue resolvers).

### 3.2 Components

**Orchard Warden Shield (network service, self-hostable)**

- DNS resolver supporting encrypted DNS (DoH and DoT), with IOC matching, blocklists, and per-device query logs (local, encrypted, short retention by default).
- WireGuard endpoint so the phone can tunnel to the home or newsroom resolver from anywhere.
- Optional on-device DNS settings profile and VPN configuration, generated and signed by Orchard Warden.
- Flow metadata capture: destination IP, port, SNI where visible, JA3 or JA4 style TLS fingerprints, byte counts, timing. No payload storage by default.
- Suricata and Zeek style rule engines for known C2 patterns.
- Integration option with an existing open-source mobile traffic analysis suite (for example the PiRogue tool suite) rather than rebuilding everything. Evaluate in Phase 0.

**Orchard Warden Proxy (lab mode only)**

- Optional TLS-intercepting proxy for **triage of an already-suspect device** on an isolated network, to inspect cleartext of non-pinned traffic.
- Clear warnings: this requires a trusted root certificate on the device, reduces security, should never be left on for daily use, and will not see traffic from certificate-pinned apps and many Apple services.
- Default off. Used by analysts, not the standard journalist workflow.

**Device capture (USB)**

- Live packet capture from the attached device with process attribution, for Sentry mode and forensic sessions.

### 3.3 Detections

| Detection | Description |
|---|---|
| IOC domain, URL, IP match | From signed feed, including new kits |
| DGA and newly registered domains | Entropy, age, and registrar heuristics |
| Beaconing | Regular interval small connections from a device or process |
| Unusual process network use | Process names that do not normally use network or do not exist on clean baselines |
| Exfiltration shape | Sudden large uploads after a suspicious event, "hit-and-run" bursts |
| DNS tampering | Resolver answers differ between trusted resolvers and the local path |
| TLS interception signals | Certificate chain differs from known-good pins for stable endpoints |
| Captive portal and injection | Unexpected redirects or modified responses on first contact |
| Proxy and DNS settings drift | Unexpected proxy, PAC, or DNS payloads on the device |
| Cross-device correlation (newsroom mode) | Same suspicious domain contacted by multiple colleagues |

### 3.4 Privacy and safety rules

- DNS logs are sensitive (they reveal sources and reporting activity). Default: store only matches and aggregate counters, with full logs opt-in, encrypted, and auto-expiring.
- Never forward logs to third parties. Optional anonymous IOC "hit" sharing is opt-in and carries no identifiers.
- The Shield itself is high value to attackers: harden it, minimize its attack surface, auto-update, sign configs, and document secure deployment.

---

## 4. MDM and Configuration Profile Analysis

Malicious or abusive profiles are a real vector: they can install root certificates, route traffic through a VPN or proxy, change DNS, alter cellular APN settings, enroll the device in remote management, or weaken restrictions.

### 4.1 Data sources

- Profile and management artifacts in backups (installed profile lists and metadata, profile event history, cloud configuration and enrollment data, restrictions and settings stores).
- Live diagnostics over USB (installed profiles list where the service exposes it).
- Sysdiagnose configuration and MDM logs.
- Network observations (MDM check-in traffic to unfamiliar servers).

### 4.2 Payload risk analysis

| Payload type | Risk | Check |
|---|---|---|
| Certificate (root or intermediate) | TLS interception | Who issued it, name, validity, whether user-trusted, not in known organizational set |
| VPN and per-app VPN | Traffic rerouting | Server, protocol, on-demand rules, always-on |
| Global HTTP proxy and PAC | Traffic rerouting | Presence, destination |
| DNS settings | Resolution hijack | Resolver address, supervised vs user installed |
| Web content filter | Traffic logging | Provider |
| APN and cellular settings | Carrier-level interception or reroute | Unexpected APN, proxy fields |
| Wi-Fi payloads | Auto-join to rogue networks | SSIDs, enterprise EAP settings, trust anchors |
| MDM enrollment | Remote control, app install, data collection | Server URL, topic, enrollment type, supervised flag, organization name |
| Restrictions | Weakened security or locked user options | Differences from user's expected policy |
| Managed apps and enterprise provisioning | Sideloaded implants | Bundle IDs, signing teams, expiration |
| Email and calendar accounts | Mail interception | Unexpected accounts |

### 4.3 Outputs

- A **profile inventory** with plain-language explanation of each payload.
- A **risk score** per profile and overall device policy posture.
- "Expected versus found" comparison when the user or newsroom provides an approved baseline.
- Clear removal guidance, with a warning to preserve evidence first if compromise is suspected.
- Detection of profile **persistence tricks** such as hidden or renamed profiles, mismatched identifiers, and profile events that show install and removal in short windows.

### 4.4 Supervised devices

For organizational or advanced users, Orchard Warden supports reading supervision state and offers policy templates (see section 5).

---

## 5. Custom Lockdown: Orchard Warden Hardening Policy Engine

Apple's Lockdown Mode is a fixed, strong baseline and cannot be customized by third parties. Orchard Warden does not replace or modify it. Instead it provides a **layered hardening policy** around it.

### 5.1 Hardening tiers

| Tier | Audience | Contents |
|---|---|---|
| **Baseline** | Everyone | Up-to-date OS, automatic updates, strong passcode, regular reboot, no unknown profiles, review of app permissions |
| **Journalist** | Reporters at elevated risk | Baseline plus Lockdown Mode, unknown-sender message filtering, limited AirDrop discoverability, private Wi-Fi addresses, disable auto-join on open networks, encrypted DNS through Shield, fewer iCloud sharing features, notification privacy on lock screen |
| **Critical** | Active targets, conflict zones | Journalist plus disable iMessage and FaceTime where feasible, dedicated clean device, scheduled reboots, supervised configuration with restrictions, USB accessory limits, no Wi-Fi on untrusted networks, travel protocol |
| **Custom** | Newsroom security leads | Organization-defined checks and restrictions, authored in YAML |

### 5.2 How it works

1. **Audit**: Orchard Warden checks the device against the chosen tier using backup, sysdiagnose, live diagnostics, and user attestation for settings that cannot be read automatically (the report clearly distinguishes "verified" from "self-reported").
2. **Explain**: each failing item shows the risk and a one-step fix.
3. **Enforce (optional, supervised devices)**: generate a signed configuration profile or Apple Configurator workflow that applies restrictions (for example limiting AirDrop, USB accessories, profile installation, auto-join behavior, specific app features).
4. **Monitor drift**: re-audit on every scan and alert on a policy regression.
5. **Operational playbooks**: scheduled reboot reminders, travel checklists, "suspected compromise" decision tree, and "safe to charge or connect" guidance.

Orchard Warden-generated profiles are themselves a risk surface, so they are: minimal, human-readable, signed, reproducible, and listed in the profile inventory as trusted-by-hash.

### 5.3 Policy as code

```yaml
policy: journalist_high
requires:
  lockdown_mode: enabled
  ios_min: latest_minus_0
  unknown_sender_filter: enabled
  airdrop: contacts_only_or_off
  profiles: [orchardwarden_dns]
  forbid_profiles: [any_unlisted_root_ca, any_unlisted_mdm]
  reboot_max_age_hours: 48
attest_by_user: [app_lock_enabled, backup_encryption_enabled]
actions_on_fail: [explain, offer_fix, record_in_report]
```

### 5.4 Lockdown Mode awareness in detection

Published research notes that some recent kits do not run when Lockdown Mode is on. Orchard Warden records Lockdown Mode status over time when determinable, and uses it as a **mitigating factor** in exposure analysis (never as proof of safety).

---

## 6. Radio Layer Monitoring: Cellular, Wi-Fi, Bluetooth, Baseband

This is the highest-risk area for over-promising. The approach is **two-pronged**:

1. **Device-side evidence** from logs and diagnostics that Apple exposes.
2. **External passive sensors** that observe the radio environment around the user.

All radio features are in a **Research Track** with explicit feasibility ratings and lab validation gates before any user-facing claim.

### 6.1 Feasibility summary

| Area | Device-side | External sensor | Feasibility | Notes |
|---|---|---|---|---|
| Wi-Fi rogue AP, evil twin, deauth, injection | Good | Good | **High** | Mature tooling, monitor mode adapters |
| Wi-Fi AWDL and AirDrop abuse | Partial | Partial | **Medium** | Frame-level visibility depends on hardware and channels |
| Bluetooth LE unsolicited advertising, pairing, proximity abuse | Good | Good | **High** | BLE sniffing dongles are inexpensive |
| Bluetooth Classic attacks | Partial | Limited | **Medium to Low** | Less common now, harder to sniff |
| Cellular rogue base station, downgrade | Partial (logs) | Partial (SDR) | **Medium** | Passive observation of broadcast info is possible, 5G standalone harder |
| Silent and binary SMS, OTA SIM messages | Partial | None | **Low to Medium** | Depends on what the device logs |
| SS7 and Diameter attacks | None | None | **Not detectable here** | Carrier-side. Provide mitigations only |
| Baseband exploitation | Very limited | None | **Low** | Version checks, crash and reset artifacts, no internal visibility |
| SIM swap, eSIM abuse | Partial | None | **Medium** | Detect identity and carrier state changes |

### 6.2 Wi-Fi

**Device-side**

- Known networks list and join history, auto-join flags, unusual SSIDs, open networks, networks that mimic corporate or hotel names.
- Private Wi-Fi address status and rotation.
- Live log events: association, disassociation, deauth reason codes, repeated join failures, captive portal probes, DNS and DHCP changes.
- Sysdiagnose Wi-Fi diagnostics.

**External sensor (Orchard Warden Radio Sensor, Wi-Fi mode)**

- Monitor mode on a compatible adapter, passive only.
- Detections: evil twin (same SSID, new BSSID or changed security), KARMA-like behavior (AP answers any probe), deauth and disassoc floods, rogue DHCP and DNS, ARP and NDP spoofing, channel anomalies, beacon anomalies, unexpected AWDL frames to the device's MAC from unknown sources.
- Baseline learning for a home or office, then alerts for deviation.

**Network integrity probes (Shield)**

- Compare TLS certificates and DNS answers on the user's current path with known-good values to catch interception.

### 6.3 Bluetooth

**Device-side**

- Paired device inventory, unknown or recently added peripherals, connection history, accessory trust.
- Live log events: unexpected pairing requests, repeated connection attempts, pairing from unknown addresses.
- AirDrop and Continuity discoverability settings.

**External sensor (BLE mode)**

- Passive BLE scanning for advertising floods (proximity-spam style), repeated pairing prompt triggers, rogue accessories impersonating known devices, unknown devices following the user over time (stalking pattern), and anomalous AirDrop initiation advertisements.
- Time and location correlation (when the user opts in) to differentiate coincidence from following behavior.

### 6.4 Cellular

**Device-side (feasibility: medium, must be validated)**

- Live and archived logs from the telephony stack: serving cell changes, radio access technology changes and downgrades, rejects, authentication and security-mode events, location and tracking area updates, unexpected network registration changes, null or weak cipher indicators if logged.
- SIM and eSIM state: ICCID changes, carrier bundle changes, profile download events, unexpected provisioning or OTA activity.
- Messaging-layer oddities: class 0, type 0 or binary SMS indicators where visible in logs.
- Carrier-supplied settings and APN profile changes (also covered in section 4).

**External sensor (SDR, feasibility: medium)**

- Passive scan of local LTE and where possible 5G broadcast information, compared against a public cell database and a learned local baseline.
- Alert on: unknown cell appearing on a known site list, anomalous identity parameters, missing neighbor relationships, unusually strong signal from a new cell, advertised parameters that induce downgrade, and sudden changes during a user's presence at sensitive events.
- Strictly **receive-only**. No transmission, no active interrogation. Legal review per jurisdiction before release.
- Honest limitation: a passive sensor sees the environment, not whether the user's phone was actually attached to a rogue cell. Correlate with device logs.

**Network-side threats (out of reach)**

- SS7 and Diameter location tracking, interception, and SMS redirection occur inside carrier networks. Orchard Warden documents the risk, advises removal of SMS-based authentication and sensitive reliance on carrier voice and SMS, recommends end-to-end encrypted channels, and offers a carrier-notification playbook. It does not claim detection.

### 6.5 Baseband

- Record baseband firmware version and compare against vendor and Apple security bulletins to flag known-vulnerable versions.
- Parse any baseband-related crash, reset, and trace artifacts found in sysdiagnose and logs (mapping to be established empirically in the lab, per device model).
- Detect repeated modem resets or unexplained cellular outages that correlate with other events.
- Investigate whether Apple-provided diagnostic profiles or logging options can be used by an analyst for deeper capture (availability, lifetime, and privacy impact to be verified). Any such profile is treated as a high-risk configuration and handled under section 4 rules.
- Explicit statement in UI: **baseband compromise cannot be reliably ruled out by software on the phone.**

### 6.6 Orchard Warden Radio Sensor hardware (optional)

| Item | Purpose |
|---|---|
| Single board computer (for example Raspberry Pi class) | Host and local analysis |
| Wi-Fi adapter supporting monitor mode | Wi-Fi detections |
| BLE sniffer dongle | Bluetooth detections |
| SDR receiver | Cellular broadcast observation |
| GPS (optional, opt-in) | Location tagging for sweep and follow detection |
| Tamper-aware, encrypted storage | Protect captured metadata |

Delivered as **open hardware reference designs and a prebuilt image**, not a commercial device. Also a portable "sweep mode" for events, hotels, and border crossings.

### 6.7 Radio data handling

- Metadata only. Store hashed or truncated device identifiers where possible.
- Never capture payloads of other people's communications. Passive sensors will inevitably see third-party broadcast metadata, so the design minimizes retention and documents legal considerations.
- Region-specific legal guidance shipped with the sensor docs.

---

## 7. Sentry Mode (Live USB Sensor)

### 7.1 Behavior

When the phone is connected to the Orchard Warden desktop (or a Orchard Warden Hub mini-computer used as a "charging station"):

1. Establish a trusted pairing (user confirms on device).
2. Record live logs and packet metadata into an encrypted ring buffer.
3. Run streaming rules continuously (see section 8).
4. Trigger an on-demand sysdiagnose if a high-severity rule fires, to preserve evidence close to the event.
5. Run scheduled deep scans (nightly backup analysis).
6. Present a simple status: green (no rule hits and data coverage good), amber (anomaly or coverage problem), red (indicator found).

### 7.2 Coverage honesty

The status display always includes **coverage**: which layers were active, how long the device was observed, whether Lockdown Mode was on, last reboot time, and iOS version. "Green" never appears without coverage context.

### 7.3 Safety

- Pairing with an untrusted or compromised computer risks exposing the phone. Use a dedicated or live-image host where possible, and make the trust prompts clear.
- Charging station mode is **data-capable by design**. Warn users not to connect to public USB ports, and advise using data-blocking adapters elsewhere.

---

## 8. Correlation Engine, Rules, and Normalized Data Model

### 8.1 Unified event schema

All layers emit normalized events:

```
event: {
  time, source_layer, device_id (case-local),
  type (message, process, net_flow, dns, crash, profile, radio, config, log),
  actor (process, app, remote peer),
  object (file, domain, ip, profile id, cell id, ble addr),
  attributes{...}, evidence_ref, confidence
}
```

### 8.2 Rule languages

| Domain | Language |
|---|---|
| IOC matching | STIX 2 bundles and indexed lookups |
| Network | Suricata and Zeek style signatures |
| Content | YARA |
| Log and event patterns | Sigma-like YAML rules adapted to iOS and radio events |
| Sequence and correlation | Orchard Warden sequence rules: ordered events within time windows across layers |
| Hardening | Policy YAML (section 5) |

Example sequence rule:

```yaml
rule: message_crash_netburst
severity: high
sequence:
  - type: message, attrs: {direction: inbound, sender_known: false, has_attachment: true}
  - type: crash,   attrs: {process_in: [message_parser_services]}, within: 30s
  - type: net_flow, attrs: {first_seen_dest: true, process_not_in: baseline_net_processes}, within: 120s
explain: "Unknown sender attachment followed by message service crash and new outbound connection."
```

### 8.3 Scoring and verdicts

- Per finding: evidence strength, source reliability, corroboration across layers, and mitigating factors (Lockdown Mode, patched version).
- Overall verdict maps to the three honest states from v0.1 (Indicators found, Suspicious artifacts, No known indicators found), plus a **Coverage Grade** (A to D) shown beside every verdict.

### 8.4 Baselines and drift

- Per-device behavioral baseline (typical processes, destinations, reboot cadence) built during an initial calibration period when the device is believed clean, with warnings that a compromised start state would poison the baseline.
- Global clean profiles per iOS version and model from lab devices.

---

## 9. Revised Architecture (Delta From v0.1)

```
Layer F  Intelligence Service (signed feeds, kit cards, patch and CVE data)
              |
   +----------+--------------------------------------------------+
   |                      Orchard Warden Core (desktop / hub)            |
   |   Acquisition   Live Streams   Config Audit   Exposure Eng.   |
   |   (backup,      (os_log,       (profiles,     (version        |
   |    sysdiag)      pcap)          MDM, certs)    windows)       |
   |            \         |            |            /              |
   |             +---- Normalized Event Bus ---------+              |
   |                         |                                     |
   |        Correlation + Rule Engine (STIX, Suricata, YARA,       |
   |        Sigma-like, sequence rules)                            |
   |                         |                                     |
   |        Evidence Vault  ->  Reports / Alerts / UI              |
   +--------------+-----------------------------+------------------+
                  |                             |
          Orchard Warden Shield                Orchard Warden Radio Sensor
          (DNS, VPN, flow, proxy lab)    (Wi-Fi, BLE, SDR cellular)
```

New modules in the repo:

```
orchardwarden/
  kits/            kit intelligence cards and tests
  exposure/        version window and CVE exposure engine
  messaging/       deep messaging forensics (carving, gaps, correlation)
  profiles/        MDM and configuration profile analysis
  hardening/       policy engine, tiers, profile generator
  live/            USB log and packet streaming
  shield/          DNS, VPN, flow, proxy lab
  radio/           Wi-Fi, BLE, SDR, baseband analysis and sensor image
  correlate/       event bus, rule engines, scoring
  research/        radio and baseband lab notes, device logs maps
```

---

## 10. Revised Roadmap

Phases from v0.1 are retained and extended. New work is slotted as follows.

| Phase | Added scope |
|---|---|
| **0 Foundations** | Evaluate PiRogue and similar suites for reuse. Legal review for radio sensing and TLS interception features. Build the lab: range of iPhone models and iOS versions, Faraday enclosure, test carrier SIMs, Wi-Fi AP, BLE test devices, SDR gear. Recruit research partners. |
| **1 Core MVP** | Kit card format, first cards (Triangulation, Pegasus family, Coruna, DarkSword) with IOC ingestion. Profile inventory v1. |
| **2 Guided Desktop App** | Messaging Forensics Module v1 (gap analysis, orphan analysis, link extraction, crash correlation). Exposure analysis engine v1. Hardening audit (Baseline and Journalist tiers). |
| **3 Heuristics and Timeline** | Correlation engine and sequence rules. Profile risk scoring. Behavioral baselines. Deleted record carving. |
| **3.5 Sentry Mode (new)** | USB live log and packet capture, streaming rules, auto sysdiagnose on alert, nightly deep scan, coverage grading. |
| **4 Cross Platform and Hardening** | Shield v1 (DNS, WireGuard, IOC blocking, flow metadata). Hardening policy generator for supervised devices. |
| **5 Gateway, Helper, Radio** | Radio Sensor: Wi-Fi and BLE first (high feasibility), then cellular SDR research prototype. Baseband version and artifact checks. Newsroom correlation across devices. |
| **6 Workbench and 1.0** | Analyst tooling for radio and network evidence, proxy lab mode, community kit card contributions, documentation, workshops. |
| **Research Track (continuous)** | Cellular log mapping per device model, baseband artifact mapping, AWDL visibility, validation of every live service per iOS release. |

Release gates for radio claims: reproducible lab test, documented false positive rate, independent review, and plain-language limits in the UI.

---

## 11. Test and Validation Plan (Additions)

| Area | Approach |
|---|---|
| Kit coverage | Fixture sets per kit built from public IOC lists and synthetic artifacts. Regression tests whenever a publisher updates indicators. Never run live exploits against real people. Use isolated lab devices and published samples only under legal and ethical review. |
| Messaging | Synthetic databases with injected deletions, gaps, orphans, and crash sequences. Validate against known benign churn (normal deletions) to tune false positives. |
| Profiles | Library of benign MDM and VPN profiles plus synthetic malicious payload sets. |
| Live streams | Per iOS version matrix for service availability and log format changes. Automated nightly compatibility run against beta releases. |
| DNS and proxy | Replay of DNS and flow datasets, simulated DNS tampering and TLS interception, load and latency tests, leak tests (no DNS outside the tunnel). |
| Wi-Fi | Controlled rogue AP and deauth tests in shielded lab. |
| Bluetooth | Controlled advertising flood and pairing tests. |
| Cellular | Lab with a licensed, shielded test network to simulate cell parameter changes and downgrades on lab devices. No over-the-air transmission outside a shielded enclosure and appropriate license. |
| Exposure engine | Ground truth from Apple release notes and exploited-vulnerability catalogs with automated consistency checks. |
| Usability | Journalist and trainer sessions focused on interpreting amber and red states and coverage grades. |
| Security | Threat-model review of Shield, Sensor, and profile generator. Independent audit includes Sentry mode and live pairing. |

---

## 12. Risks (Additions)

| Risk | Mitigation |
|---|---|
| Live service availability changes with each iOS release | Compatibility test matrix, graceful degradation, coverage grade shows what was unavailable |
| Over-claiming radio or baseband detection | Feasibility ratings, release gates, explicit "cannot detect" statements |
| Hit-and-run kits leave no trace | Exposure analysis, DNS history, network layer, prevention-first recommendations |
| Attackers learn detection logic from open source | Accept this tradeoff, keep multi-layer correlation, keep some heuristics parameters in the signed feed and update often |
| Profile generator abused as attack vector | Minimal, signed, reproducible profiles. Hash allowlist. Clear user explanation |
| Shield compromise exposes DNS history | Minimal retention, encryption, hardening, separation, audit |
| Radio sensing legal exposure | Receive-only, jurisdiction guidance, no payload capture, legal counsel |
| TLS interception misuse | Lab mode only, strong warnings, off by default, logging |
| Sentry host compromise exposes phone | Clean-room host options, pairing warnings, live image |
| False positives from normal churn (deleted messages, profile changes) | Calibration baselines, severity tuning, analyst review path |
| Intelligence feed lag after new disclosure | Monitoring watchlist, rapid card process, community contributors |

---

## 13. Immediate Next Steps (Added)

1. Build the lab device matrix and verify which live services (log stream, packet capture, diagnostics) work on each supported iOS version with Developer Mode on and off.
2. Prototype Sentry mode: ten minute capture of logs and traffic from a clean lab device, then normalize into the event schema.
3. Write the first four kit cards from primary sources and ingest their IOCs.
4. Prototype the Messaging Forensics Module on synthetic data: gap analysis and orphan detection.
5. Prototype the profile inventory against sample benign and synthetic malicious profiles.
6. Evaluate PiRogue for the Shield and decide build versus integrate.
7. Order Wi-Fi, BLE, and SDR hardware and run first rogue AP and BLE flood experiments.
8. Open conversations with GTIG, Lookout, iVerify, Kaspersky, Citizen Lab, and Amnesty about indicator formats and responsible ingestion.
9. Commission legal review for radio sensing, TLS lab mode, and data handling.
10. Draft the Coverage Grade definition and test comprehension with journalists.

---

## 14. Sources Consulted for This Extension

- Google Threat Intelligence Group reporting on Coruna and on the proliferation of DarkSword (March 2026), as summarized by The Hacker News, SecurityAffairs, Privacy Guides, eSecurity Planet, and heise.
- Lookout, iVerify, and Google joint findings on DarkSword, as summarized by SecurityAffairs.
- Kaspersky: "Operation Triangulation" and the triangle_check utility on securelist.com.
- Group-IB notes on Operation Triangulation.
- Wikipedia entry on Coruna (secondary source, used for orientation only).

Primary publisher reports must be re-read in full when writing each kit card. Details in this document that are not directly traceable to a primary source are design proposals or items flagged for lab validation, not established facts.
