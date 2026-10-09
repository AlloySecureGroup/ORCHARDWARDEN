"""Structural file scanner (message attachment and image/font/PDF exploit patterns)."""

from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import Path

from ..ioc import IocIndex
from ..models import (
    INDICATOR,
    INFO,
    SUSPICIOUS,
    Finding,
    ModuleResult,
    Severity,
)
from . import pdfscan, tiffdng, ttf, webp
from .magic import IMAGE_EXTS, expected_types_for_ext, sniff

MODULE = "filescan"
DEFAULT_EXTS = {"pdf", "gif", "webp", "jpg", "jpeg", "png", "tif", "tiff", "dng", "ttf", "otf", "ttc", "pkpass"}
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_ZIP_ENTRIES = 200
MAX_ZIP_TOTAL = 64 * 1024 * 1024


def _sev_bump(sev: Severity, context: str) -> Severity:
    if context == "messaging" and sev < Severity.CRITICAL:
        return Severity(int(sev) + 1)
    return sev


def scan_bytes(
    data: bytes,
    name: str,
    context: str = "files",
    iocs: IocIndex | None = None,
    depth: int = 0,
) -> list[Finding]:
    """Scan one file's bytes. `context` is "messaging" for attachments from message stores."""
    findings: list[Finding] = []
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    kind = sniff(data[:16])
    ev_base = {"file": name, "detected_type": kind, "size": len(data)}

    if iocs is not None:
        digest = hashlib.sha256(data).hexdigest()
        hit = iocs.match_sha256(digest)
        if hit:
            findings.append(
                Finding(
                    "FS-IOC-HASH",
                    "File hash matches a known indicator",
                    Severity.CRITICAL,
                    INDICATOR,
                    "high",
                    "A",
                    MODULE,
                    "SHA-256 of the file is in the loaded IOC set.",
                    {**ev_base, "sha256": digest, "ioc_source": hit.source},
                    kit=hit.kit,
                    source=hit.source,
                )
            )

    expected = expected_types_for_ext(ext)
    if expected and kind != "unknown" and kind not in expected:
        disguised_pdf = kind == "pdf" and ext in IMAGE_EXTS
        sev = Severity.HIGH if disguised_pdf else Severity.MEDIUM
        findings.append(
            Finding(
                "FS-EXT-MISMATCH",
                "File content does not match its extension",
                _sev_bump(sev, context) if not disguised_pdf else sev,
                SUSPICIOUS if not disguised_pdf else INDICATOR,
                "medium",
                "A",
                MODULE,
                "Image-named file is actually a PDF. This delivery trick has been reported for message-delivered decoder exploits."
                if disguised_pdf
                else "Extension says " + ext + " but content is " + kind + ".",
                ev_base,
                kit="pegasus_file_exploits" if disguised_pdf else None,
                cves=["CVE-2021-30860"] if disguised_pdf else [],
                caveat="A mismatched extension alone is not proof of an exploit.",
            )
        )

    if kind == "pdf":
        info = pdfscan.inspect_pdf(data)
        if info.has_jbig2:
            sev = Severity.MEDIUM if context == "messaging" else Severity.LOW
            findings.append(
                Finding(
                    "FS-PDF-JBIG2",
                    "PDF uses the JBIG2 image filter",
                    sev,
                    SUSPICIOUS if context == "messaging" else INFO,
                    "low",
                    "A",
                    MODULE,
                    "JBIG2 is legitimate in scanned documents but is the decoder reached by a known "
                    "message-delivered exploit class. Review the sender and context.",
                    {**ev_base, "jbig2_raw": info.jbig2_raw, "jbig2_in_streams": info.jbig2_in_compressed},
                    kit="pegasus_file_exploits",
                    cves=["CVE-2021-30860"],
                    caveat="Common in scanned documents. Not an indicator by itself.",
                )
            )

    elif kind in ("ttf", "otf", "ttc"):
        hits, notes = ttf.scan_font(data)
        if hits:
            findings.append(
                Finding(
                    "FS-TTF-ADJUST",
                    "Font program contains undocumented instruction opcodes",
                    Severity.CRITICAL,
                    INDICATOR,
                    "high",
                    "A",
                    MODULE,
                    "Opcodes 0x8F or 0x90 are not defined in the OpenType specification. A font "
                    "containing them as executable instructions matches the structural pattern of the "
                    "Triangulation font stage.",
                    {
                        **ev_base,
                        "hits": [{"where": h.where, "offset": h.offset, "opcode": hex(h.opcode)} for h in hits[:20]],
                        "total_hits": len(hits),
                    },
                    kit="triangulation",
                    cves=["CVE-2023-41990"],
                    source="https://securelist.com/operation-triangulation/",
                )
            )
        if notes:
            findings.append(
                Finding("FS-TTF-PARSE", "Font could not be fully parsed", Severity.LOW, INFO, "low", "A", MODULE, "; ".join(notes), ev_base)
            )

    elif kind == "tiff":
        info_t = tiffdng.inspect_tiff(data)
        for mm in info_t.mismatches:
            sev = Severity.MEDIUM if context != "messaging" else Severity.HIGH
            findings.append(
                Finding(
                    "FS-DNG-SPP",
                    "TIFF/DNG SamplesPerPixel disagrees with lossless JPEG components",
                    sev,
                    SUSPICIOUS,
                    "low",
                    "A",
                    MODULE,
                    "Header says " + str(mm.samples_per_pixel) + " sample(s) per pixel but the lossless JPEG "
                    "frame declares " + str(mm.jpeg_components) + " component(s).",
                    {
                        **ev_base,
                        "is_dng": info_t.is_dng,
                        "ifd_offset": mm.ifd_offset,
                        "samples_per_pixel": mm.samples_per_pixel,
                        "jpeg_components": mm.jpeg_components,
                    },
                    kit="imageio_dng_cve_2025_43300",
                    cves=["CVE-2025-43300"],
                    caveat="Some legitimate raw files use multi component lossless JPEG. Analyst review item.",
                )
            )

    elif kind == "webp":
        info_w = webp.inspect_webp(data)
        if not info_w.riff_size_consistent:
            findings.append(
                Finding(
                    "FS-WEBP-SIZE",
                    "WebP RIFF size does not match file length",
                    Severity.LOW,
                    SUSPICIOUS if context == "messaging" else INFO,
                    "low",
                    "A",
                    MODULE,
                    "Container size fields are inconsistent. Often benign, noted for correlation.",
                    {**ev_base, "chunks": info_w.chunks},
                )
            )

    elif kind == "zip" and ext == "pkpass" and depth == 0:
        findings.extend(_scan_pkpass(data, name, context, iocs))

    return findings


def _scan_pkpass(data: bytes, name: str, context: str, iocs: IocIndex | None) -> list[Finding]:
    out: list[Finding] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return [
            Finding(
                "FS-PKPASS-BAD",
                "PassKit archive is not a valid zip",
                Severity.MEDIUM,
                SUSPICIOUS,
                "low",
                "A",
                MODULE,
                "Wallet pass attachment could not be opened.",
                {"file": name},
            )
        ]
    total = 0
    for i, info in enumerate(zf.infolist()):
        if i >= MAX_ZIP_ENTRIES:
            out.append(
                Finding(
                    "FS-PKPASS-LIMIT",
                    "PassKit archive has too many entries",
                    Severity.LOW,
                    INFO,
                    "low",
                    "A",
                    MODULE,
                    "Scan truncated.",
                    {"file": name},
                )
            )
            break
        total += info.file_size
        if total > MAX_ZIP_TOTAL:
            out.append(
                Finding(
                    "FS-PKPASS-LIMIT",
                    "PassKit archive expands very large",
                    Severity.MEDIUM,
                    SUSPICIOUS,
                    "low",
                    "A",
                    MODULE,
                    "Scan truncated to avoid decompression bombs.",
                    {"file": name},
                )
            )
            break
        if info.is_dir():
            continue
        with zf.open(info) as fh:
            content = fh.read(MAX_ZIP_TOTAL)
        for f in scan_bytes(content, name + "!" + info.filename, context, iocs, depth=1):
            out.append(f)
        if sniff(content[:16]) == "webp":
            w = webp.inspect_webp(content)
            if w.has_vp8l:
                out.append(
                    Finding(
                        "FS-PKPASS-VP8L",
                        "Wallet pass contains a lossless WebP image",
                        Severity.LOW,
                        INFO,
                        "low",
                        "A",
                        MODULE,
                        "Lossless WebP inside a pass is unusual. Deep validation is not implemented in this prototype.",
                        {"file": name + "!" + info.filename},
                        kit="pegasus_file_exploits",
                        cves=["CVE-2023-4863"],
                    )
                )
    return out


def scan_paths(
    paths: list[Path],
    recursive: bool = False,
    exts: set[str] | None = None,
    context: str = "files",
    iocs: IocIndex | None = None,
) -> ModuleResult:
    exts = exts or DEFAULT_EXTS
    res = ModuleResult(MODULE, "partial", unsupported_checks=[webp.UNSUPPORTED])
    res.reason = "WebP lossless table validation not implemented"
    files: list[Path] = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            it = p.rglob("*") if recursive else p.glob("*")
            files.extend(x for x in it if x.is_file())
        elif p.is_file():
            files.append(p)
    for f in sorted(files):
        ext = f.suffix.lstrip(".").lower()
        if ext not in exts and sniff(f.read_bytes()[:16] if f.stat().st_size else b"") == "unknown":
            continue
        if f.stat().st_size > MAX_FILE_BYTES:
            continue
        res.items_examined += 1
        res.findings.extend(scan_bytes(f.read_bytes(), str(f), context, iocs))
    return res
