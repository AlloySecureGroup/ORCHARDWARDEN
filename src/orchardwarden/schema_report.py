"""Privacy-safe structure report for a decrypted backup.

Records only: iOS version and model, domains and path prefixes with file counts, table and column
names with row counts for the databases Orchard Warden parses, and date-unit classification. It never
records message text, URLs, phone numbers, account names, serial numbers or file contents, so the
output can be shared to validate parser assumptions against real iOS versions.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from pathlib import Path

from .backup import Backup, BackupError

TARGET_DBS = [
    ("HomeDomain", "Library/SMS/sms.db"),
    ("HomeDomain", "Library/Safari/History.db"),
    ("AppDomain-com.apple.mobilesafari", "Library/Safari/History.db"),
    ("WirelessDomain", "Library/Databases/DataUsage.sqlite"),
]
KEYWORDS = ("whatsapp", "signal", "telegra", "viber", "configurationprofiles", "mobilesafari", "wireless")


def _db_structure(path: Path) -> dict:
    con = sqlite3.connect("file:" + str(path) + "?mode=ro", uri=True)
    out: dict = {"tables": {}}
    try:
        for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
            cols = [r[1] for r in con.execute("PRAGMA table_info(" + name + ")")]
            try:
                n = con.execute("SELECT COUNT(*) FROM " + name).fetchone()[0]
            except sqlite3.Error:
                n = None
            out["tables"][name] = {"columns": cols, "rows": n}
        if "message" in out["tables"] and "date" in out["tables"]["message"]["columns"]:
            row = con.execute("SELECT MAX(date) FROM message").fetchone()
            v = row[0] if row else None
            out["message_date_unit"] = None if v is None else ("nanoseconds" if abs(v) > 1e12 else "seconds")
        if "sqlite_sequence" in out["tables"]:
            out["sequence_tables"] = [r[0] for r in con.execute("SELECT name FROM sqlite_sequence")]
    finally:
        con.close()
    return out


def build(backup_dir: Path) -> dict:
    bk = Backup(backup_dir)
    try:
        bk.validate()
    except BackupError as exc:
        return {"error": str(exc)}
    info = bk.info()
    report: dict = {
        "ios_version": str(info.get("Product Version")),
        "product_type": str(info.get("Product Type")),
        "build": str(info.get("Build Version")),
        "domains": {},
        "interesting_prefixes": {},
        "databases": {},
        "profile_dir_files": [],
    }
    dom_counts: Counter = Counter()
    prefix_counts: Counter = Counter()
    con = sqlite3.connect("file:" + str(bk.manifest_db) + "?mode=ro", uri=True)
    try:
        for dom, rel in con.execute("SELECT domain, relativePath FROM Files"):
            dom_counts[dom] += 1
            if any(k in dom.lower() for k in KEYWORDS):
                prefix = "/".join(rel.split("/")[:3])
                prefix_counts[dom + " :: " + prefix] += 1
            if "configurationprofiles" in dom.lower():
                report["profile_dir_files"].append(rel.rsplit("/", 1)[-1])
    finally:
        con.close()
    report["domains"] = dict(dom_counts.most_common(80))
    report["interesting_prefixes"] = dict(prefix_counts.most_common(80))
    for dom, rel in TARGET_DBS:
        f = bk.find(dom, rel)
        key = dom + " :: " + rel
        report["databases"][key] = _db_structure(f.path) if f else "absent"
    report["profile_dir_files"] = sorted(set(report["profile_dir_files"]))
    return report


def dump(backup_dir: Path, out: Path) -> dict:
    rep = build(backup_dir)
    Path(out).write_text(json.dumps(rep, indent=2, sort_keys=True), encoding="utf-8")
    return rep
