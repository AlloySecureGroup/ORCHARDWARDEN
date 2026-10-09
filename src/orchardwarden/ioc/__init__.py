"""IOC loading, indexing and matching (STIX2 and plain lists)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

# STIX pattern object paths we understand, mapped to Orchard Warden indicator types.
_PATTERN = re.compile(r"\[\s*([a-z0-9-]+):([A-Za-z0-9_.'-]+)\s*=\s*'([^']*)'\s*\]")

_TYPE_MAP = {
    ("domain-name", "value"): "domain",
    ("url", "value"): "url",
    ("ipv4-addr", "value"): "ip",
    ("ipv6-addr", "value"): "ip",
    ("email-addr", "value"): "email",
    ("file", "name"): "file_name",
    ("process", "name"): "process",
    ("app", "id"): "app_id",
    ("file", "hashes.'SHA-256'"): "sha256",
    ("file", "hashes.SHA-256"): "sha256",
    ("file", "hashes.sha256"): "sha256",
    ("file", "hashes.'sha256'"): "sha256",
    ("file", "path"): "file_path",
    ("configuration-profile", "id"): "profile_id",
    ("app", "cert.sha256"): "app_cert_sha256",
}


@dataclass(frozen=True)
class Indicator:
    kind: str
    value: str
    source: str = "unknown"
    name: str = ""
    kit: str | None = None


def _norm_domain(d: str) -> str:
    return d.strip().lower().rstrip(".")


def _norm_path(p: str) -> str:
    p = p.strip().replace("\\", "/").lower().strip("/")
    for prefix in ("private/", "var/mobile/"):
        if p.startswith(prefix):
            p = p[len(prefix) :]
    return p


def extract_host(url: str) -> str:
    try:
        host = urlsplit(url if "://" in url else "http://" + url).hostname or ""
    except ValueError:
        host = ""
    return _norm_domain(host)


class IocIndex:
    def __init__(self) -> None:
        self._by_kind: dict[str, dict[str, Indicator]] = {}
        self._paths_by_base: dict[str, list[str]] = {}

    def add(self, ind: Indicator) -> None:
        v = ind.value.strip()
        if ind.kind in ("domain", "email", "app_id", "file_name", "sha256", "ip", "profile_id", "app_cert_sha256"):
            v = v.lower()
        if ind.kind == "file_path":
            v = _norm_path(v)
            self._paths_by_base.setdefault(v.rsplit("/", 1)[-1], []).append(v)
        if ind.kind == "domain":
            v = _norm_domain(v)
        self._by_kind.setdefault(ind.kind, {})[v] = ind

    def __len__(self) -> int:
        return sum(len(v) for v in self._by_kind.values())

    def kinds(self) -> dict[str, int]:
        return {k: len(v) for k, v in self._by_kind.items()}

    def match_domain(self, host: str) -> Indicator | None:
        host = _norm_domain(host)
        table = self._by_kind.get("domain", {})
        labels = host.split(".")
        for i in range(len(labels) - 1):  # exact then parent domains (never bare TLD)
            cand = ".".join(labels[i:])
            if cand in table:
                return table[cand]
        return None

    def match_url(self, url: str) -> Indicator | None:
        table = self._by_kind.get("url", {})
        u = url.strip()
        if u in table:
            return table[u]
        if u.lower() in table:
            return table[u.lower()]
        host = extract_host(u)
        if host:
            return self.match_domain(host)
        return None

    def match_ip(self, ip: str) -> Indicator | None:
        return self._by_kind.get("ip", {}).get(ip.strip().lower())

    def match_process(self, name: str) -> Indicator | None:
        return self._by_kind.get("process", {}).get(name.strip())

    def match_file_name(self, name: str) -> Indicator | None:
        return self._by_kind.get("file_name", {}).get(name.strip().lower())

    def match_sha256(self, digest: str) -> Indicator | None:
        return self._by_kind.get("sha256", {}).get(digest.strip().lower())

    def match_email(self, email: str) -> Indicator | None:
        return self._by_kind.get("email", {}).get(email.strip().lower())

    def match_profile_id(self, pid: str) -> Indicator | None:
        return self._by_kind.get("profile_id", {}).get(pid.strip().lower())

    def match_file_path(self, rel_path: str) -> Indicator | None:
        """Match a backup-relative or absolute path against path indicators.

        Indicators are absolute device paths (for example /private/var/db/x/y). Backup paths are
        domain-relative, so we accept a match when either path is a suffix of the other on a path
        boundary and the base names agree.
        """
        r = _norm_path(rel_path)
        base = r.rsplit("/", 1)[-1]
        for cand in self._paths_by_base.get(base, []):
            if cand == r or cand.endswith("/" + r) or r.endswith("/" + cand):
                return self._by_kind["file_path"][cand]
        return None

    def match_app(self, app_id: str) -> Indicator | None:
        return self._by_kind.get("app_id", {}).get(app_id.strip().lower())


def load_stix_bundle(data: dict, source: str = "stix") -> list[Indicator]:
    out: list[Indicator] = []
    for obj in data.get("objects", []):
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        name = obj.get("name", "")
        kit = None
        for lbl in obj.get("labels", []) or []:
            if isinstance(lbl, str) and lbl.startswith("kit:"):
                kit = lbl.split(":", 1)[1]
        for m in _PATTERN.finditer(pattern):
            kind = _TYPE_MAP.get((m.group(1), m.group(2)))
            if kind:
                out.append(Indicator(kind, m.group(3), source, name, kit))
    return out


def load_plain_list(text: str, source: str = "list") -> list[Indicator]:
    out: list[Indicator] = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "://" in s:
            out.append(Indicator("url", s, source))
        elif re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", s):
            out.append(Indicator("ip", s, source))
        elif re.fullmatch(r"[0-9a-fA-F]{64}", s):
            out.append(Indicator("sha256", s, source))
        elif "@" in s:
            out.append(Indicator("email", s, source))
        else:
            out.append(Indicator("domain", s, source))
    return out


def load_iocs(paths: list[Path]) -> IocIndex:
    idx = IocIndex()
    for p in paths:
        p = Path(p)
        text = p.read_text(encoding="utf-8")
        if p.suffix in (".json", ".stix2"):
            for ind in load_stix_bundle(json.loads(text), source=p.name):
                idx.add(ind)
        else:
            for ind in load_plain_list(text, source=p.name):
                idx.add(ind)
    return idx
