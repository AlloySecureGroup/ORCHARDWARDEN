"""Backup artifact checks: Safari history IOC matching and process names in DataUsage."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .backup import Backup
from .ioc import IocIndex, extract_host
from .models import INDICATOR, Finding, ModuleResult, Severity

APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)

# Names that appear in clean iOS data usage tables and must not be flagged.
# BackupAgent2 is explicitly benign per public Triangulation guidance. BackupAgent is not.
SUSPECT_PROCESS_NAMES = {
    "BackupAgent": ("triangulation", "Process BackupAgent (not BackupAgent2) is reported as a Triangulation indicator."),
}


def _open(path: Path) -> sqlite3.Connection:
    return sqlite3.connect("file:" + str(path) + "?mode=ro", uri=True)


def _table_exists(con: sqlite3.Connection, name: str) -> bool:
    return con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def check_safari(backup: Backup, iocs: IocIndex | None) -> ModuleResult:
    res = ModuleResult("safari_history", "ran")
    f = backup.find("AppDomain-com.apple.mobilesafari", "Library/Safari/History.db") or backup.find(
        "HomeDomain", "Library/Safari/History.db"
    )
    if f is None:
        res.status = "skipped"
        res.reason = "Safari History.db not present in backup"
        return res
    if iocs is None:
        res.status = "partial"
        res.reason = "no IOC set loaded"
    con = _open(f.path)
    try:
        if not _table_exists(con, "history_items"):
            res.status = "error"
            res.reason = "history_items table missing"
            return res
        q = (
            "SELECT i.url, v.visit_time FROM history_items i LEFT JOIN history_visits v ON v.history_item=i.id"
            if _table_exists(con, "history_visits")
            else "SELECT url, 0 FROM history_items"
        )
        for url, vt in con.execute(q):
            res.items_examined += 1
            if iocs is None or not url:
                continue
            hit = iocs.match_url(url)
            if hit:
                t = (APPLE_EPOCH + timedelta(seconds=vt)).isoformat() if vt else None
                res.findings.append(
                    Finding(
                        "SAF-URL-IOC",
                        "Safari visited a known malicious address",
                        Severity.CRITICAL,
                        INDICATOR,
                        "high",
                        "A",
                        "safari_history",
                        "A browsing history entry matches the loaded IOC set.",
                        {"url": url, "host": extract_host(url), "visit_time": t, "ioc": hit.value, "ioc_source": hit.source},
                        kit=hit.kit,
                        source=hit.source,
                    )
                )
    finally:
        con.close()
    return res


def check_datausage(backup: Backup, iocs: IocIndex | None) -> ModuleResult:
    res = ModuleResult("datausage", "ran")
    f = backup.find("WirelessDomain", "Library/Databases/DataUsage.sqlite")
    if f is None:
        res.status = "skipped"
        res.reason = "DataUsage.sqlite not present in backup"
        return res
    con = _open(f.path)
    try:
        if not _table_exists(con, "ZPROCESS"):
            res.status = "error"
            res.reason = "ZPROCESS table missing"
            return res
        cols = {r[1] for r in con.execute("PRAGMA table_info(ZPROCESS)")}
        name_cols = [c for c in ("ZPROCNAME", "ZBUNDLENAME") if c in cols]
        for c in name_cols:
            for (name,) in con.execute("SELECT DISTINCT " + c + " FROM ZPROCESS WHERE " + c + " IS NOT NULL"):
                res.items_examined += 1
                if name in SUSPECT_PROCESS_NAMES:
                    kit, why = SUSPECT_PROCESS_NAMES[name]
                    res.findings.append(
                        Finding(
                            "DU-PROC-SUSPECT",
                            "Process name associated with a known spyware campaign",
                            Severity.HIGH,
                            INDICATOR,
                            "medium",
                            "A",
                            "datausage",
                            why,
                            {"process": name, "column": c},
                            kit=kit,
                            source="https://securelist.com/operation-triangulation/",
                            caveat="Corroborate with other artifacts before concluding.",
                        )
                    )
                if iocs is not None:
                    hit = iocs.match_process(name)
                    if hit:
                        res.findings.append(
                            Finding(
                                "DU-PROC-IOC",
                                "Process name matches a known indicator",
                                Severity.HIGH,
                                INDICATOR,
                                "high",
                                "A",
                                "datausage",
                                "Data usage table lists a process in the IOC set.",
                                {"process": name, "ioc_source": hit.source},
                                kit=hit.kit,
                                source=hit.source,
                            )
                        )
    finally:
        con.close()
    return res
