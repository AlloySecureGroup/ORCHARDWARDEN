"""Configuration profile and MDM analysis with payload risk scoring."""

from __future__ import annotations

import hashlib
import json
import plistlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import INDICATOR, INFO, SUSPICIOUS, Finding, ModuleResult, Severity

MODULE = "profiles"

# Display names that imitate system functions are a social-engineering signal.
MIMIC_NAMES = re.compile(
    r"\b(ios (update|security)|apple (update|security|support)|system (update|settings|service)|carrier (settings|update))\b", re.I
)

PAYLOAD_RULES: dict[str, tuple[Severity, str]] = {
    "com.apple.security.root": (Severity.HIGH, "Installs a root certificate that can enable TLS interception once trusted."),
    "com.apple.security.pkcs1": (Severity.MEDIUM, "Installs a certificate."),
    "com.apple.security.pem": (Severity.MEDIUM, "Installs a certificate."),
    "com.apple.security.pkcs12": (Severity.MEDIUM, "Installs an identity (certificate and key)."),
    "com.apple.proxy.http.global": (Severity.HIGH, "Routes web traffic through a global HTTP proxy."),
    "com.apple.vpn.managed": (Severity.MEDIUM, "Configures a VPN that can reroute traffic."),
    "com.apple.vpn.managed.applayer": (Severity.MEDIUM, "Configures a per-app VPN."),
    "com.apple.dnsSettings.managed": (Severity.MEDIUM, "Changes the DNS resolver."),
    "com.apple.apn.managed": (Severity.HIGH, "Changes cellular APN settings, which can route data through another network."),
    "com.apple.cellular": (Severity.HIGH, "Changes cellular settings, which can route data through another network."),
    "com.apple.mdm": (Severity.HIGH, "Enrolls the device in remote management."),
    "com.apple.webClip.managed": (Severity.LOW, "Adds a web clip (home screen link)."),
    "com.apple.wifi.managed": (Severity.LOW, "Adds a Wi-Fi network configuration."),
    "com.apple.applicationaccess": (Severity.LOW, "Sets restrictions."),
    "com.apple.webcontent-filter": (Severity.MEDIUM, "Installs a web content filter that can observe traffic."),
    "com.apple.eas.account": (Severity.MEDIUM, "Adds an Exchange account."),
    "com.apple.mail.managed": (Severity.MEDIUM, "Adds a mail account."),
}


@dataclass
class ProfileInfo:
    path: str
    identifier: str
    display_name: str
    organization: str
    removal_disallowed: bool
    payloads: list[dict[str, Any]] = field(default_factory=list)


def load_profile_bytes(raw: bytes) -> dict:
    try:
        return plistlib.loads(raw)
    except Exception:
        pass
    start = raw.find(b"<?xml")
    end = raw.rfind(b"</plist>")
    if start >= 0 and end > start:
        return plistlib.loads(raw[start : end + len(b"</plist>")])
    raise ValueError("not a readable profile")


def _payload_summary(p: dict) -> dict[str, Any]:
    ptype = p.get("PayloadType", "")
    out: dict[str, Any] = {"type": ptype, "name": p.get("PayloadDisplayName", ""), "identifier": p.get("PayloadIdentifier", "")}
    content = p.get("PayloadContent")
    if isinstance(content, (bytes, bytearray)):
        out["sha256"] = hashlib.sha256(bytes(content)).hexdigest()
    if ptype == "com.apple.mdm":
        out["server_url"] = p.get("ServerURL")
        out["topic"] = p.get("Topic")
    if ptype in ("com.apple.vpn.managed", "com.apple.vpn.managed.applayer"):
        out["vpn_type"] = p.get("VPNType")
    if ptype == "com.apple.proxy.http.global":
        out["proxy"] = str(p.get("ProxyServer", "")) + ":" + str(p.get("ProxyServerPort", ""))
    if ptype == "com.apple.dnsSettings.managed":
        ds = p.get("DNSSettings", {})
        out["dns_server_url"] = ds.get("ServerURL")
        out["dns_addresses"] = ds.get("ServerAddresses")
    if ptype in ("com.apple.apn.managed", "com.apple.cellular"):
        out["apns"] = p.get("AttachAPN") or p.get("APNs")
    return out


def analyze_profile(raw: bytes, path: str, allow: dict | None = None, iocs=None) -> tuple[ProfileInfo, list[Finding]]:
    allow = allow or {}
    allow_ids = set(allow.get("identifiers", []))
    allow_hashes = set(allow.get("sha256", []))
    d = load_profile_bytes(raw)
    info = ProfileInfo(
        path=path,
        identifier=str(d.get("PayloadIdentifier", "")),
        display_name=str(d.get("PayloadDisplayName", "")),
        organization=str(d.get("PayloadOrganization", "")),
        removal_disallowed=bool(d.get("PayloadRemovalDisallowed", False)),
    )
    findings: list[Finding] = []
    if iocs is not None:
        for candidate in (info.identifier, str(d.get("PayloadUUID", ""))):
            hit = iocs.match_profile_id(candidate) if candidate else None
            if hit:
                findings.append(
                    Finding(
                        "PROF-ID-IOC",
                        "Installed profile matches a known malicious profile",
                        Severity.CRITICAL,
                        INDICATOR,
                        "high",
                        "D",
                        MODULE,
                        "The profile identifier or UUID is listed in the IOC set.",
                        {"profile": info.identifier, "ioc_source": hit.source},
                        kit=hit.kit,
                        source=hit.source,
                    )
                )
                break
    approved = info.identifier in allow_ids
    payloads = d.get("PayloadContent")
    if isinstance(payloads, list):
        info.payloads = [_payload_summary(p) for p in payloads if isinstance(p, dict)]
    elif d.get("PayloadType"):
        info.payloads = [_payload_summary(d)]

    for pl in info.payloads:
        sev_why = PAYLOAD_RULES.get(pl["type"])
        if not sev_why:
            continue
        sev, why = sev_why
        if approved or (pl.get("sha256") in allow_hashes):
            findings.append(
                Finding(
                    "PROF-APPROVED",
                    "Approved profile payload: " + pl["type"],
                    Severity.INFO,
                    INFO,
                    "high",
                    "D",
                    MODULE,
                    "Matches the approved list.",
                    {"profile": info.identifier, **pl},
                )
            )
            continue
        cat = SUSPICIOUS if sev >= Severity.MEDIUM else INFO
        findings.append(
            Finding(
                "PROF-PAYLOAD-" + pl["type"].replace("com.apple.", "").replace(".", "-").upper(),
                "Profile payload: " + pl["type"],
                sev,
                cat,
                "medium",
                "D",
                MODULE,
                why,
                {"profile": info.identifier, "display_name": info.display_name, "organization": info.organization, **pl},
                caveat="Legitimate for managed work devices. Confirm you expect this profile.",
            )
        )

    if MIMIC_NAMES.search(info.display_name) and not approved:
        findings.append(
            Finding(
                "PROF-MIMIC-NAME",
                "Profile name imitates a system function",
                Severity.MEDIUM,
                SUSPICIOUS,
                "medium",
                "D",
                MODULE,
                "Display name resembles a system update or settings item.",
                {"profile": info.identifier, "display_name": info.display_name},
            )
        )
    if not info.organization.strip() and not approved:
        findings.append(
            Finding(
                "PROF-NO-ORG",
                "Profile has no organization name",
                Severity.LOW,
                SUSPICIOUS,
                "low",
                "D",
                MODULE,
                "Profiles from real organizations normally name them.",
                {"profile": info.identifier},
            )
        )
    if info.removal_disallowed and not approved:
        findings.append(
            Finding(
                "PROF-NO-REMOVE",
                "Profile cannot be removed by the user",
                Severity.HIGH,
                SUSPICIOUS,
                "medium",
                "D",
                MODULE,
                "Removal is disallowed, which is only expected on managed or supervised devices.",
                {"profile": info.identifier},
            )
        )
    return info, findings


def analyze_files(paths: list[Path], allow_file: Path | None = None, iocs=None) -> tuple[ModuleResult, list[ProfileInfo]]:
    allow = json.loads(Path(allow_file).read_text(encoding="utf-8")) if allow_file else {}
    res = ModuleResult(MODULE, "ran")
    infos: list[ProfileInfo] = []
    for p in paths:
        try:
            raw = Path(p).read_bytes()
            info, f = analyze_profile(raw, str(p), allow, iocs)
        except Exception as exc:
            res.findings.append(
                Finding(
                    "PROF-UNREADABLE", "Profile could not be parsed", Severity.LOW, INFO, "low", "D", MODULE, str(exc), {"file": str(p)}
                )
            )
            continue
        res.items_examined += 1
        infos.append(info)
        res.findings.extend(f)
    return res, infos
