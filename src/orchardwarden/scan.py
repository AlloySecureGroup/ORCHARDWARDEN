"""Orchestration: run the module set against a decrypted backup and assemble a ScanResult."""

from __future__ import annotations

import json
from pathlib import Path

from . import artifacts, exposure, filescan, messaging, profiles
from .backup import MESSAGING_SOURCES, Backup, BackupError
from .ioc import IocIndex
from .models import INDICATOR, SUSPICIOUS, Finding, ModuleResult, ScanResult, Severity

PROFILE_DOMAIN = "SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles"


def scan_backup(
    backup_dir: Path,
    iocs: IocIndex | None = None,
    allow_file: Path | None = None,
    scan_attachments: bool = True,
) -> ScanResult:
    result = ScanResult(target=str(backup_dir))
    bk = Backup(backup_dir)
    try:
        bk.validate()
    except BackupError as exc:
        result.modules.append(ModuleResult("backup", "error", reason=str(exc)))
        result.notes.append("Nothing could be examined. " + str(exc))
        return result
    result.modules.append(ModuleResult("backup", "ran", items_examined=1))
    info = bk.info()
    if info:
        result.notes.append("Backup device info: " + json.dumps({k: str(v) for k, v in info.items() if k != "Serial Number"}))
    if iocs is None or len(iocs) == 0:
        result.notes.append("No IOC set loaded: only structural and heuristic checks ran.")

    # Messaging database
    sms = bk.find("HomeDomain", "Library/SMS/sms.db")
    if sms is None:
        result.modules.append(ModuleResult("messaging", "skipped", reason="sms.db not present in backup"))
    else:
        result.modules.append(messaging.analyze_sms_db(sms.path, bk, iocs))

    # Attachments from message stores, scanned structurally
    if scan_attachments:
        att = ModuleResult(
            "attachments",
            "partial",
            unsupported_checks=[filescan.webp.UNSUPPORTED],
            reason="WebP lossless table validation not implemented",
        )
        found_any = False
        for label, domain, prefix in MESSAGING_SOURCES:
            for f in bk.files(domain=domain, path_prefix=prefix):
                found_any = True
                att.items_examined += 1
                data = f.path.read_bytes()
                name = label + ":" + f.relative_path
                for fd in filescan.scan_bytes(data, name, context="messaging", iocs=iocs):
                    fd.evidence.setdefault("source_app", label)
                    att.findings.append(fd)
        if not found_any:
            att.status = "skipped"
            att.reason = "no messaging attachments found in backup"
        result.modules.append(att)

    result.modules.append(artifacts.check_safari(bk, iocs))
    result.modules.append(artifacts.check_datausage(bk, iocs))

    # Profiles from the backup
    prof = ModuleResult("profiles", "ran")
    allow = json.loads(Path(allow_file).read_text(encoding="utf-8")) if allow_file else {}
    seen_files = 0
    for f in bk.files(domain=PROFILE_DOMAIN, path_prefix="Library/ConfigurationProfiles/"):
        seen_files += 1
        name = f.relative_path.rsplit("/", 1)[-1]
        if name == "CloudConfigurationDetails.plist":
            prof.findings.append(
                Finding(
                    "PROF-CLOUDCONFIG",
                    "Device has cloud (automated) management configuration",
                    Severity.MEDIUM,
                    SUSPICIOUS,
                    "medium",
                    "D",
                    "profiles",
                    "A cloud configuration record exists, which ties the device to an organization's management.",
                    {"file": f.relative_path},
                    caveat="Expected on employer or school devices.",
                )
            )
            continue
        try:
            raw = f.path.read_bytes()
            d = profiles.load_profile_bytes(raw)
        except Exception:
            continue
        if "PayloadIdentifier" not in d and "PayloadContent" not in d:
            continue
        _, fs = profiles.analyze_profile(raw, f.relative_path, allow, iocs)
        prof.items_examined += 1
        prof.findings.extend(fs)
    if seen_files == 0:
        prof.status = "skipped"
        prof.reason = "no configuration profile files found in backup"
    result.modules.append(prof)

    # File path indicators (for example dropped files) against the backup manifest
    pm = ModuleResult("path_iocs", "ran")
    if iocs is None or not iocs._paths_by_base:
        pm.status = "skipped"
        pm.reason = "no file path indicators loaded"
    else:
        for rel in sorted(bk.all_relative_paths()):
            pm.items_examined += 1
            hit = iocs.match_file_path(rel)
            if hit:
                pm.findings.append(
                    Finding(
                        "PATH-IOC",
                        "A file path matches a known indicator",
                        Severity.CRITICAL,
                        INDICATOR,
                        "medium",
                        "A",
                        "path_iocs",
                        "A path in the backup manifest matches a path listed in the IOC set.",
                        {"path": rel, "ioc": hit.value, "ioc_source": hit.source},
                        kit=hit.kit,
                        source=hit.source,
                        caveat="Backups are domain-relative, so a suffix match can rarely collide with an unrelated file.",
                    )
                )
    result.modules.append(pm)

    # Exposure from the single version recorded in Info.plist (history unavailable from one backup)
    ver = info.get("Product Version")
    if ver:
        w = exposure.Window(str(ver), None, None)
        exp = exposure.analyze([w])
        exp.status = "partial"
        exp.reason = "only the current iOS version is known from one backup, not the version history"
        result.modules.append(exp)
    else:
        result.modules.append(ModuleResult("exposure", "skipped", reason="iOS version not found in Info.plist"))
    return result
