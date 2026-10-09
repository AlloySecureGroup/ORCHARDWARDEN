"""File type detection from content (never trust the extension)."""

from __future__ import annotations

IMAGE_EXTS = {"gif", "jpg", "jpeg", "png", "webp", "tif", "tiff", "dng", "heic"}
FONT_EXTS = {"ttf", "otf", "ttc"}


def sniff(head: bytes) -> str:
    if head.startswith(b"%PDF-"):
        return "pdf"
    if head[:4] in (b"GIF8",) or head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    if head[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if head[:4] in (b"\x00\x01\x00\x00", b"true"):
        return "ttf"
    if head[:4] == b"OTTO":
        return "otf"
    if head[:4] == b"ttcf":
        return "ttc"
    if head[:4] == b"PK\x03\x04":
        return "zip"
    return "unknown"


def expected_types_for_ext(ext: str) -> set[str]:
    ext = ext.lower().lstrip(".")
    table = {
        "pdf": {"pdf"},
        "gif": {"gif"},
        "webp": {"webp"},
        "jpg": {"jpeg"},
        "jpeg": {"jpeg"},
        "png": {"png"},
        "tif": {"tiff"},
        "tiff": {"tiff"},
        "dng": {"tiff"},
        "ttf": {"ttf"},
        "otf": {"otf", "ttf"},
        "ttc": {"ttc"},
        "pkpass": {"zip"},
    }
    return table.get(ext, set())
