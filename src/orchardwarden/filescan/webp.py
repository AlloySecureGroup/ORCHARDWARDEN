"""WebP container checks.

Only the RIFF container is validated here. The lossless (VP8L) Huffman table validation
needed to recognise the CVE-2023-4863 pattern is NOT implemented in this prototype and is
reported as an unsupported check so coverage is never overstated.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

UNSUPPORTED = "webp_vp8l_huffman_table_validation"


@dataclass
class WebpInfo:
    has_vp8l: bool
    riff_size_consistent: bool
    chunks: list[str]


def inspect_webp(data: bytes) -> WebpInfo:
    if len(data) < 12:
        return WebpInfo(False, False, [])
    riff_size = struct.unpack_from("<I", data, 4)[0]
    consistent = (riff_size + 8) == len(data)
    chunks: list[str] = []
    pos = 12
    has_vp8l = False
    while pos + 8 <= len(data) and len(chunks) < 64:
        tag = data[pos : pos + 4]
        size = struct.unpack_from("<I", data, pos + 4)[0]
        chunks.append(tag.decode("latin-1"))
        if tag == b"VP8L":
            has_vp8l = True
        pos += 8 + size + (size & 1)
        if pos > len(data) + 8:
            consistent = False
            break
    return WebpInfo(has_vp8l, consistent, chunks)
