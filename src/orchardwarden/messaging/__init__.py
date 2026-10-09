"""Messaging forensics: deleted-record inference, orphans, invisible messages, link extraction.

Works on a copy of sms.db opened read-only. Column sets differ across iOS versions, so every
query checks the schema first and degrades instead of failing.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..backup import Backup
from ..ioc import IocIndex
from ..models import (
    INDICATOR,
    INFO,
    SUSPICIOUS,
    Finding,
    ModuleResult,
    Severity,
)

MODULE = "messaging"
APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)
ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿ ⠀"), None)
MIN_GAP = 3  # ignore tiny gaps, normal deletions are common


def apple_time(v: int | float | None) -> datetime | None:
    if v is None or v == 0:
        return None
    try:
        secs = v / 1e9 if abs(v) > 1e12 else float(v)
        return APPLE_EPOCH + timedelta(seconds=secs)
    except (OverflowError, ValueError):
        return None


def _cols(con: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in con.execute("PRAGMA table_info(" + table + ")")}


def _has_table(con: sqlite3.Connection, table: str) -> bool:
    return con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


def _gaps(rowids: list[int], seq: int | None) -> list[tuple[int, int]]:
    gaps: list[tuple[int, int]] = []
    prev = 0
    for r in rowids:
        if r - prev > 1:
            gaps.append((prev + 1, r - 1))
        prev = r
    if seq is not None and seq > prev:
        gaps.append((prev + 1, seq))
    return gaps


def analyze_sms_db(db_path: Path, backup: Backup | None, iocs: IocIndex | None) -> ModuleResult:
    res = ModuleResult(MODULE, "ran")
    con = sqlite3.connect("file:" + str(db_path) + "?mode=ro", uri=True)
    try:
        if not _has_table(con, "message"):
            res.status = "error"
            res.reason = "sms.db has no message table"
            return res
        mcols = _cols(con, "message")
        rows = con.execute("SELECT ROWID FROM message ORDER BY ROWID").fetchall()
        rowids = [r[0] for r in rows]
        res.items_examined = len(rowids)
        seq_row = (
            con.execute("SELECT seq FROM sqlite_sequence WHERE name='message'").fetchone() if _has_table(con, "sqlite_sequence") else None
        )
        seq = seq_row[0] if seq_row else None
        date_col = "date" if "date" in mcols else None

        def time_of(rowid: int) -> datetime | None:
            if not date_col:
                return None
            r = con.execute("SELECT date FROM message WHERE ROWID=?", (rowid,)).fetchone()
            return apple_time(r[0]) if r else None

        gap_list = [g for g in _gaps(rowids, seq) if (g[1] - g[0] + 1) >= MIN_GAP]
        gap_windows: list[tuple[datetime | None, datetime | None, int, int]] = []
        for lo, hi in gap_list:
            before = max((r for r in rowids if r < lo), default=None)
            after = min((r for r in rowids if r > hi), default=None)
            t0 = time_of(before) if before else None
            t1 = time_of(after) if after else None
            gap_windows.append((t0, t1, lo, hi))

        # Messages from handles never seen before, carrying attachments
        first_contact: list[dict] = []
        if {"handle_id", "is_from_me"} <= mcols and _has_table(con, "message_attachment_join"):
            q = (
                "SELECT m.ROWID, m.handle_id, " + ("m.date" if date_col else "0") + " "
                "FROM message m WHERE m.is_from_me=0 AND m.handle_id>0 "
                "AND m.ROWID = (SELECT MIN(m2.ROWID) FROM message m2 WHERE m2.handle_id=m.handle_id) "
                "AND EXISTS (SELECT 1 FROM message_attachment_join j WHERE j.message_id=m.ROWID)"
            )
            for rid, hid, d in con.execute(q):
                first_contact.append({"rowid": rid, "handle_id": hid, "time": apple_time(d)})

        for t0, t1, lo, hi in gap_windows:
            near = [fc for fc in first_contact if _within(fc["time"], t0, t1, slack=timedelta(minutes=10))]
            if near:
                res.findings.append(
                    Finding(
                        "MSG-GAP-FIRSTCONTACT",
                        "Deleted-message gap next to an unknown sender's attachment",
                        Severity.MEDIUM,
                        SUSPICIOUS,
                        "low",
                        "A",
                        MODULE,
                        "Message IDs " + str(lo) + " to " + str(hi) + " are missing, adjacent in time to a first "
                        "message with an attachment from a sender seen only once at that point.",
                        {
                            "gap": [lo, hi],
                            "gap_size": hi - lo + 1,
                            "window": [_iso(t0), _iso(t1)],
                            "first_contact_rowids": [n["rowid"] for n in near],
                        },
                        caveat="Users also delete messages. Correlate with crash logs and network data.",
                    )
                )
            else:
                res.findings.append(
                    Finding(
                        "MSG-GAP",
                        "Messages are missing from the database sequence",
                        Severity.INFO,
                        INFO,
                        "low",
                        "A",
                        MODULE,
                        "IDs " + str(lo) + " to " + str(hi) + " are absent. Normal deletions produce this.",
                        {"gap": [lo, hi], "gap_size": hi - lo + 1, "window": [_iso(t0), _iso(t1)]},
                    )
                )

        # Invisible bodies
        if {"text"} <= mcols:
            extra = " AND cache_has_attachments=0" if "cache_has_attachments" in mcols else ""
            extra += " AND (balloon_bundle_id IS NULL OR balloon_bundle_id='')" if "balloon_bundle_id" in mcols else ""
            inbound = " AND is_from_me=0" if "is_from_me" in mcols else ""
            q = "SELECT ROWID, text FROM message WHERE 1=1" + inbound + extra
            invisible = []
            for rid, txt in con.execute(q):
                if txt is not None and txt != "" and not str(txt).translate(ZERO_WIDTH).strip():
                    invisible.append(rid)
            if invisible:
                res.findings.append(
                    Finding(
                        "MSG-INVISIBLE",
                        "Inbound messages that display as blank",
                        Severity.MEDIUM,
                        SUSPICIOUS,
                        "low",
                        "A",
                        MODULE,
                        str(len(invisible)) + " inbound message(s) contain only invisible characters.",
                        {"rowids": invisible[:50], "count": len(invisible)},
                        caveat="Can also be emoji or sticker artifacts. Review in context.",
                    )
                )

        # Attachment orphans and missing files
        if _has_table(con, "attachment"):
            acols = _cols(con, "attachment")
            if _has_table(con, "message_attachment_join"):
                orphans = [
                    r[0]
                    for r in con.execute(
                        "SELECT a.ROWID FROM attachment a WHERE NOT EXISTS "
                        "(SELECT 1 FROM message_attachment_join j WHERE j.attachment_id=a.ROWID)"
                    )
                ]
                if orphans:
                    res.findings.append(
                        Finding(
                            "MSG-ATT-ORPHAN",
                            "Attachment records with no message",
                            Severity.MEDIUM,
                            SUSPICIOUS,
                            "low",
                            "A",
                            MODULE,
                            str(len(orphans)) + " attachment row(s) are not linked to any message, which can result "
                            "from deleting the message but not the attachment record.",
                            {"attachment_rowids": orphans[:50], "count": len(orphans)},
                            caveat="Also produced by some iOS cleanup behaviour.",
                        )
                    )
            if backup is not None and "filename" in acols:
                known = backup.all_relative_paths()
                missing = []
                for rid, fn in con.execute("SELECT ROWID, filename FROM attachment WHERE filename IS NOT NULL"):
                    rel = fn.replace("~/", "", 1) if fn.startswith("~/") else fn
                    if rel not in known:
                        missing.append({"rowid": rid, "filename": fn})
                if missing:
                    res.findings.append(
                        Finding(
                            "MSG-ATT-MISSING-FILE",
                            "Attachment records whose file is absent from the backup",
                            Severity.LOW,
                            INFO,
                            "low",
                            "A",
                            MODULE,
                            str(len(missing)) + " attachment record(s) point to files not present in the backup.",
                            {"examples": missing[:20], "count": len(missing)},
                            caveat="Large or cloud-offloaded attachments are often absent from backups.",
                        )
                    )

        # iMessage account identifiers that match known malicious accounts
        if iocs is not None and _has_table(con, "handle") and "id" in _cols(con, "handle"):
            for rid, hid in con.execute("SELECT ROWID, id FROM handle WHERE id IS NOT NULL"):
                hit = iocs.match_email(str(hid))
                if hit:
                    res.findings.append(
                        Finding(
                            "MSG-HANDLE-IOC",
                            "A message sender matches a known malicious account",
                            Severity.CRITICAL,
                            INDICATOR,
                            "high",
                            "A",
                            MODULE,
                            "A handle in the messaging database matches an account listed in the IOC set.",
                            {"handle_rowid": rid, "ioc_source": hit.source},
                            kit=hit.kit,
                            source=hit.source,
                        )
                    )

        # URL extraction and IOC matching
        if iocs is not None and "text" in mcols:
            for rid, txt in con.execute("SELECT ROWID, text FROM message WHERE text LIKE '%http%'"):
                for url in URL_RE.findall(txt or ""):
                    hit = iocs.match_url(url)
                    if hit:
                        res.findings.append(
                            Finding(
                                "MSG-URL-IOC",
                                "Message contains a link matching a known indicator",
                                Severity.CRITICAL,
                                INDICATOR,
                                "high",
                                "A",
                                MODULE,
                                "A link in a message matches the loaded IOC set.",
                                {"message_rowid": rid, "url": url, "ioc": hit.value, "ioc_source": hit.source},
                                kit=hit.kit,
                                source=hit.source,
                            )
                        )
    finally:
        con.close()
    return res


def _iso(t: datetime | None) -> str | None:
    return t.isoformat() if t else None


def _within(t: datetime | None, lo: datetime | None, hi: datetime | None, slack: timedelta) -> bool:
    if t is None or lo is None or hi is None:
        return False
    return (lo - slack) <= t <= (hi + slack)
