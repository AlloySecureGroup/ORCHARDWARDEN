"""PDF structural checks relevant to message-delivered image decoder exploits."""

from __future__ import annotations

import re
import zlib
from dataclasses import dataclass

_STREAM = re.compile(rb"stream\r?\n")
MAX_STREAMS = 400
MAX_INFLATE = 8 * 1024 * 1024


@dataclass
class PdfInfo:
    jbig2_raw: int = 0
    jbig2_in_compressed: int = 0
    streams_examined: int = 0
    truncated: bool = False

    @property
    def has_jbig2(self) -> bool:
        return (self.jbig2_raw + self.jbig2_in_compressed) > 0


def inspect_pdf(data: bytes) -> PdfInfo:
    info = PdfInfo()
    info.jbig2_raw = len(re.findall(rb"/JBIG2Decode", data))
    for m in _STREAM.finditer(data):
        if info.streams_examined >= MAX_STREAMS:
            info.truncated = True
            break
        start = m.end()
        end = data.find(b"endstream", start)
        if end < 0:
            continue
        info.streams_examined += 1
        chunk = data[start:end]
        try:
            d = zlib.decompressobj()
            out = d.decompress(chunk, MAX_INFLATE)
        except zlib.error:
            continue
        if b"/JBIG2Decode" in out:
            info.jbig2_in_compressed += 1
    return info
