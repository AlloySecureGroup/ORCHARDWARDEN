"""Read an iOS backup folder (decrypted). Encrypted backups must be decrypted first."""

from __future__ import annotations

import plistlib
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


class BackupError(Exception):
    pass


@dataclass(frozen=True)
class BackupFile:
    file_id: str
    domain: str
    relative_path: str
    path: Path


# Messaging attachment locations. Domains for third party apps are best effort and must be
# verified per app version (listed in docs as unvalidated).
MESSAGING_SOURCES = [
    ("imessage_sms", "MediaDomain", "Library/SMS/Attachments/"),
    ("whatsapp", "AppDomainGroup-group.net.whatsapp.WhatsApp.shared", "Message/Media/"),
    ("signal", "AppDomainGroup-group.org.whispersystems.signal.group", "Attachments/"),
    ("telegram", "AppDomainGroup-group.ph.telegra.Telegraph", ""),
    ("viber", "AppDomainGroup-group.viber.share.container", "Content/"),
]


class Backup:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.manifest_plist = self.root / "Manifest.plist"
        self.manifest_db = self.root / "Manifest.db"
        self.info_plist = self.root / "Info.plist"
        self.status_plist = self.root / "Status.plist"

    def is_encrypted(self) -> bool:
        if not self.manifest_plist.exists():
            return False
        try:
            with open(self.manifest_plist, "rb") as fh:
                return bool(plistlib.load(fh).get("IsEncrypted", False))
        except Exception:
            return False

    def validate(self) -> None:
        if not self.root.is_dir():
            raise BackupError("backup path is not a directory")
        if not self.manifest_db.exists():
            raise BackupError("Manifest.db not found")
        if self.is_encrypted():
            raise BackupError("backup is encrypted: decrypt it first (for example with mvt-ios decrypt-backup)")

    def info(self) -> dict:
        out: dict = {}
        if self.info_plist.exists():
            with open(self.info_plist, "rb") as fh:
                d = plistlib.load(fh)
            for k in ("Product Version", "Product Type", "Build Version", "Device Name", "Last Backup Date", "Serial Number"):
                if k in d:
                    out[k] = d[k]
        return out

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect("file:" + str(self.manifest_db) + "?mode=ro", uri=True)
        return con

    def files(self, domain: str | None = None, path_prefix: str | None = None, path_like: str | None = None) -> Iterator[BackupFile]:
        sql = "SELECT fileID, domain, relativePath FROM Files WHERE 1=1"
        args: list[str] = []
        if domain:
            sql += " AND domain = ?"
            args.append(domain)
        if path_prefix:
            sql += " AND relativePath LIKE ? ESCAPE '\\'"
            args.append(path_prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
        if path_like:
            sql += " AND relativePath LIKE ?"
            args.append(path_like)
        con = self._connect()
        try:
            for fid, dom, rel in con.execute(sql, args):
                p = self.root / fid[:2] / fid
                if p.is_file():
                    yield BackupFile(fid, dom, rel, p)
        finally:
            con.close()

    def find(self, domain: str, relative_path: str) -> BackupFile | None:
        for f in self.files(domain=domain, path_prefix=relative_path):
            if f.relative_path == relative_path:
                return f
        return None

    def all_relative_paths(self) -> set[str]:
        con = self._connect()
        try:
            return {r[0] for r in con.execute("SELECT relativePath FROM Files")}
        finally:
            con.close()
