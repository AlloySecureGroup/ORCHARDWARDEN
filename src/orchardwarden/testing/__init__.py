"""Synthetic fixture builders for tests and the demo command.

Nothing here is a working exploit. Files carry only the minimal structural marker a detector
looks for (an opcode byte, a PDF filter name, a header mismatch) and no payload of any kind.
"""

from __future__ import annotations

import hashlib
import io
import json
import plistlib
import sqlite3
import struct
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def apple_ns(dt: datetime) -> int:
    return int((dt - APPLE_EPOCH).total_seconds() * 1e9)


def make_ttf(instructions: bytes, in_glyph: bool = False) -> bytes:
    """Minimal TrueType font with `instructions` in fpgm (or in the single glyph)."""
    fpgm = b"" if in_glyph else instructions
    glyph_instr = instructions if in_glyph else b""
    glyph = struct.pack(">hhhhh", 1, 0, 0, 10, 10) + struct.pack(">H", 0) + struct.pack(">H", len(glyph_instr)) + glyph_instr
    if len(glyph) % 2:
        glyph += b"\x00"
    head = bytearray(54)
    struct.pack_into(">h", head, 50, 0)  # short loca
    maxp = struct.pack(">IH", 0x00005000, 1)
    loca = struct.pack(">HH", 0, len(glyph) // 2)
    tables = {"fpgm": fpgm or b"\x00\x00", "glyf": glyph, "head": bytes(head), "loca": loca, "maxp": maxp, "prep": b"\x00\x00"}
    tags = sorted(tables)
    header = struct.pack(">IHHHH", 0x00010000, len(tags), 0, 0, 0)
    offset = 12 + 16 * len(tags)
    recs = b""
    body = b""
    for t in tags:
        d = tables[t]
        pad = (-len(d)) % 4
        recs += struct.pack(">4sIII", t.encode(), 0, offset + len(body), len(d))
        body += d + b"\x00" * pad
    return header + recs + body


def make_pdf(jbig2: bool) -> bytes:
    filt = b"/Filter /JBIG2Decode " if jbig2 else b""
    return (
        b"%PDF-1.4\n1 0 obj\n<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /BitsPerComponent 1 "
        + filt
        + b"/Length 4 >>\nstream\n\x00\x00\x00\x00\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"
    )


def make_tiff(samples_per_pixel: int, jpeg_components: int) -> bytes:
    """Little-endian TIFF with one JPEG compressed strip whose SOF3 declares `jpeg_components`."""
    sof3 = (
        b"\xff\xc3"
        + struct.pack(">H", 8 + 3 * jpeg_components)
        + bytes([8])
        + struct.pack(">HH", 1, 1)
        + bytes([jpeg_components])
        + b"".join(bytes([i + 1, 0x11, 0]) for i in range(jpeg_components))
    )
    jpeg = b"\xff\xd8" + sof3 + b"\xff\xda\x00\x02"
    n_entries = 4
    ifd_off = 8
    data_off = ifd_off + 2 + 12 * n_entries + 4
    entries = [
        (259, 3, 1, 7),  # Compression JPEG
        (273, 4, 1, data_off),  # StripOffsets
        (277, 3, 1, samples_per_pixel),  # SamplesPerPixel
        (279, 4, 1, len(jpeg)),  # StripByteCounts
    ]
    out = b"II*\x00" + struct.pack("<I", ifd_off) + struct.pack("<H", n_entries)
    for tag, typ, cnt, val in entries:
        out += struct.pack("<HHI", tag, typ, cnt) + struct.pack("<I", val)
    out += struct.pack("<I", 0)
    return out + jpeg


def make_webp(vp8l: bool = True) -> bytes:
    chunk = b"VP8L" + struct.pack("<I", 5) + b"\x2f\x00\x00\x00\x00" + b"\x00"
    if not vp8l:
        chunk = b"VP8 " + struct.pack("<I", 4) + b"\x00\x00\x00\x00"
    body = b"WEBP" + chunk
    return b"RIFF" + struct.pack("<I", len(body)) + body


def make_pkpass(inner: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("pass.json", json.dumps({"formatVersion": 1}))
        for k, v in inner.items():
            z.writestr(k, v)
    return buf.getvalue()


def make_mobileconfig(identifier: str, display: str, org: str, payloads: list[dict], removal_disallowed: bool = False) -> bytes:
    d = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": identifier,
        "PayloadUUID": "00000000-0000-0000-0000-000000000001",
        "PayloadDisplayName": display,
        "PayloadOrganization": org,
        "PayloadRemovalDisallowed": removal_disallowed,
        "PayloadContent": payloads,
    }
    return plistlib.dumps(d)


def _fid(domain: str, rel: str) -> str:
    return hashlib.sha1((domain + "-" + rel).encode()).hexdigest()


class _BackupWriter:
    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        self.entries: list[tuple[str, str, str]] = []

    def add(self, domain: str, rel: str, data: bytes) -> None:
        fid = _fid(domain, rel)
        p = self.root / fid[:2] / fid
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        self.entries.append((fid, domain, rel))

    def finish(self, version: str) -> None:
        con = sqlite3.connect(self.root / "Manifest.db")
        con.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
        con.executemany("INSERT INTO Files VALUES (?,?,?,1,NULL)", self.entries)
        con.commit()
        con.close()
        (self.root / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False, "Version": "10.0"}))
        (self.root / "Info.plist").write_bytes(
            plistlib.dumps(
                {
                    "Product Version": version,
                    "Product Type": "iPhone14,5",
                    "Device Name": "Test iPhone",
                    "Last Backup Date": datetime(2026, 10, 1, tzinfo=timezone.utc),
                }
            )
        )


def _sms_db(path: Path, suspicious: bool) -> None:
    con = sqlite3.connect(path)
    con.executescript(
        """
        CREATE TABLE handle (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT);
        CREATE TABLE message (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT, handle_id INTEGER,
            date INTEGER, is_from_me INTEGER, cache_has_attachments INTEGER DEFAULT 0, balloon_bundle_id TEXT);
        CREATE TABLE attachment (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, mime_type TEXT);
        CREATE TABLE message_attachment_join (message_id INTEGER, attachment_id INTEGER);
        """
    )
    t0 = datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc)
    con.execute("INSERT INTO handle (id) VALUES ('+15550100001'), ('+15550100002')")
    for i in range(1, 11):
        con.execute(
            "INSERT INTO message (ROWID, text, handle_id, date, is_from_me) VALUES (?,?,1,?,?)",
            (i, "hello " + str(i), apple_ns(t0 + timedelta(minutes=i)), i % 2),
        )
    if suspicious:
        # rows 11..14 deleted, then an unknown sender's attachment, a blank message, an IOC link
        con.execute(
            "INSERT INTO message (ROWID, text, handle_id, date, is_from_me, cache_has_attachments) VALUES (15,'ok',1,?,0,0)",
            (apple_ns(t0 + timedelta(minutes=15)),),
        )
        con.execute(
            "INSERT INTO message (ROWID, text, handle_id, date, is_from_me, cache_has_attachments) VALUES (16,'',2,?,0,1)",
            (apple_ns(t0 + timedelta(minutes=16)),),
        )
        con.execute(
            "INSERT INTO message (ROWID, text, handle_id, date, is_from_me) VALUES (17,?,1,?,0)", ("​​", apple_ns(t0 + timedelta(minutes=17)))
        )
        con.execute(
            "INSERT INTO message (ROWID, text, handle_id, date, is_from_me) VALUES (18,?,1,?,0)",
            ("look http://login.evil-example.test/x", apple_ns(t0 + timedelta(minutes=18))),
        )
        con.execute(
            "INSERT INTO attachment (ROWID, filename, mime_type) VALUES (1,'~/Library/SMS/Attachments/aa/01/IMG_0001.gif','image/gif')"
        )
        con.execute("INSERT INTO attachment (ROWID, filename, mime_type) VALUES (2,'~/Library/SMS/Attachments/aa/01/note.ttf','font/ttf')")
        con.execute(
            "INSERT INTO attachment (ROWID, filename, mime_type) VALUES (3,'~/Library/SMS/Attachments/aa/01/orphan.png','image/png')"
        )
        con.execute("INSERT INTO message_attachment_join VALUES (16,1)")
        con.execute("INSERT INTO message_attachment_join VALUES (16,2)")
    con.commit()
    con.close()


def make_backup(root: Path, suspicious: bool = True, version: str = "16.1") -> Path:
    root = Path(root)
    w = _BackupWriter(root)
    tmp = root.parent / (root.name + "_tmp")
    tmp.mkdir(parents=True, exist_ok=True)
    sms = tmp / "sms.db"
    if sms.exists():
        sms.unlink()
    _sms_db(sms, suspicious)
    w.add("HomeDomain", "Library/SMS/sms.db", sms.read_bytes())
    w.add("MediaDomain", "Library/SMS/Attachments/aa/01/benign.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
    if suspicious:
        w.add("MediaDomain", "Library/SMS/Attachments/aa/01/IMG_0001.gif", make_pdf(jbig2=True))
        w.add("MediaDomain", "Library/SMS/Attachments/aa/01/note.ttf", make_ttf(b"\xb0\x01\x8f\x2f"))
        w.add("MediaDomain", "Library/SMS/Attachments/aa/01/photo.dng", make_tiff(2, 1))

    # Safari history
    saf = tmp / "History.db"
    if saf.exists():
        saf.unlink()
    con = sqlite3.connect(saf)
    con.executescript(
        "CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT);"
        "CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL);"
    )
    con.execute("INSERT INTO history_items VALUES (1,'https://example.org/')")
    con.execute("INSERT INTO history_visits VALUES (1,1,780000000.0)")
    if suspicious:
        con.execute("INSERT INTO history_items VALUES (2,'https://cdn.evil-example.test/landing')")
        con.execute("INSERT INTO history_visits VALUES (2,2,781000000.0)")
    con.commit()
    con.close()
    w.add("HomeDomain", "Library/Safari/History.db", saf.read_bytes())

    # DataUsage
    du = tmp / "DataUsage.sqlite"
    if du.exists():
        du.unlink()
    con = sqlite3.connect(du)
    con.execute("CREATE TABLE ZPROCESS (Z_PK INTEGER PRIMARY KEY, ZPROCNAME TEXT, ZBUNDLENAME TEXT)")
    con.execute("INSERT INTO ZPROCESS (ZPROCNAME) VALUES ('MobileSafari'), ('BackupAgent2')")
    if suspicious:
        con.execute("INSERT INTO ZPROCESS (ZPROCNAME) VALUES ('BackupAgent')")
    con.commit()
    con.close()
    w.add("WirelessDomain", "Library/Databases/DataUsage.sqlite", du.read_bytes())

    # Profile
    if suspicious:
        prof = make_mobileconfig(
            "com.example.fake.update",
            "iOS Update",
            "",
            [
                {
                    "PayloadType": "com.apple.security.root",
                    "PayloadIdentifier": "root1",
                    "PayloadContent": b"FAKECERTBYTES",
                    "PayloadDisplayName": "Root",
                },
                {
                    "PayloadType": "com.apple.dnsSettings.managed",
                    "PayloadIdentifier": "dns1",
                    "DNSSettings": {"ServerURL": "https://dns.evil-example.test/q"},
                },
            ],
            removal_disallowed=True,
        )
        w.add(
            "SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles", "Library/ConfigurationProfiles/fake.mobileconfig", prof
        )
    w.finish(version)
    for p in tmp.iterdir():
        p.unlink()
    tmp.rmdir()
    return root


def make_ioc_bundle() -> dict:
    return {
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000000",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--1",
                "name": "test domain",
                "labels": ["kit:coruna"],
                "pattern": "[domain-name:value='evil-example.test']",
                "pattern_type": "stix",
            },
            {
                "type": "indicator",
                "id": "indicator--2",
                "name": "test process",
                "pattern": "[process:name='fakeimplantd']",
                "pattern_type": "stix",
            },
        ],
    }
