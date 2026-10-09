"""TIFF/DNG structural check: SamplesPerPixel vs lossless JPEG component count.

Heuristic derived from the public description of the CVE-2025-43300 file pattern.
It is deliberately reported as a review item, because some legitimate raw files encode
interleaved sensor data as multi component lossless JPEG.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

TAG_COMPRESSION = 259
TAG_STRIP_OFFSETS = 273
TAG_SAMPLES_PER_PIXEL = 277
TAG_STRIP_BYTES = 279
TAG_SUBIFD = 330
TAG_TILE_OFFSETS = 324
TAG_TILE_BYTES = 325
TAG_DNG_VERSION = 50706

_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8, 13: 4, 16: 8}
MAX_IFDS = 16


@dataclass
class IfdFinding:
    ifd_offset: int
    samples_per_pixel: int
    jpeg_components: int


@dataclass
class TiffInfo:
    is_dng: bool
    ifds_examined: int
    mismatches: list[IfdFinding]
    notes: list[str]


def _read_values(data: bytes, end: str, typ: int, count: int, value_field_off: int) -> list[int]:
    size = _SIZES.get(typ, 0) * count
    if size == 0 or count > 4096:
        return []
    if size <= 4:
        off = value_field_off
    else:
        off = struct.unpack_from(end + "I", data, value_field_off)[0]
    if off + size > len(data):
        return []
    fmt = {1: "B", 3: "H", 4: "I", 8: "h", 9: "i", 7: "B", 6: "b"}.get(typ)
    if not fmt:
        return []
    return list(struct.unpack_from(end + fmt * count, data, off))


def _parse_ifd(data: bytes, end: str, off: int) -> dict[int, list[int]]:
    if off + 2 > len(data):
        return {}
    n = struct.unpack_from(end + "H", data, off)[0]
    tags: dict[int, list[int]] = {}
    for i in range(min(n, 512)):
        e = off + 2 + 12 * i
        if e + 12 > len(data):
            break
        tag, typ, count = struct.unpack_from(end + "HHI", data, e)
        tags[tag] = _read_values(data, end, typ, count, e + 8)
    return tags


def _sof3_components(jpeg: bytes) -> int | None:
    if jpeg[:2] != b"\xff\xd8":
        return None
    i = 2
    n = len(jpeg)
    while i + 4 <= n:
        if jpeg[i] != 0xFF:
            i += 1
            continue
        marker = jpeg[i + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        if marker == 0xFF:
            i += 1
            continue
        seglen = struct.unpack_from(">H", jpeg, i + 2)[0]
        if marker == 0xC3 and i + 10 <= n:  # SOF3: lossless
            return jpeg[i + 9]
        if marker == 0xDA:
            return None
        i += 2 + seglen
    return None


def inspect_tiff(data: bytes) -> TiffInfo:
    notes: list[str] = []
    if data[:2] == b"II":
        end = "<"
    elif data[:2] == b"MM":
        end = ">"
    else:
        return TiffInfo(False, 0, [], ["not a TIFF"])
    first = struct.unpack_from(end + "I", data, 4)[0]
    queue = [first]
    seen: set[int] = set()
    mism: list[IfdFinding] = []
    is_dng = False
    examined = 0
    while queue and examined < MAX_IFDS:
        off = queue.pop(0)
        if off in seen or off == 0:
            continue
        seen.add(off)
        tags = _parse_ifd(data, end, off)
        if not tags:
            continue
        examined += 1
        if TAG_DNG_VERSION in tags:
            is_dng = True
        for sub in tags.get(TAG_SUBIFD, []):
            queue.append(sub)
        comp = (tags.get(TAG_COMPRESSION) or [0])[0]
        spp = (tags.get(TAG_SAMPLES_PER_PIXEL) or [1])[0]
        if comp in (7, 34892):  # JPEG family
            offs = tags.get(TAG_STRIP_OFFSETS) or tags.get(TAG_TILE_OFFSETS) or []
            lens = tags.get(TAG_STRIP_BYTES) or tags.get(TAG_TILE_BYTES) or []
            if offs and lens and offs[0] + lens[0] <= len(data):
                comps = _sof3_components(data[offs[0] : offs[0] + lens[0]])
                if comps is not None and comps != spp:
                    mism.append(IfdFinding(off, spp, comps))
        # chain to next IFD
        e = off + 2 + 12 * min(struct.unpack_from(end + "H", data, off)[0], 512)
        if e + 4 <= len(data):
            queue.append(struct.unpack_from(end + "I", data, e)[0])
    return TiffInfo(is_dng, examined, mism, notes)
