"""TrueType structural check: undocumented bytecode opcodes in font programs.

Clean-room implementation from the public vulnerability description of the Triangulation
font stage (an Apple-only, undocumented instruction handled by the font interpreter).
Opcodes 0x8F and 0x90 are not defined in the OpenType specification, so legitimate fonts
do not contain them as executable instructions. We walk instruction streams correctly,
skipping inline push data, so data bytes are not mistaken for opcodes.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

SUSPECT_OPCODES = {0x8F, 0x90}
MAX_TABLES = 64
MAX_GLYPHS = 70000


@dataclass
class OpcodeHit:
    where: str
    offset: int
    opcode: int


def scan_instructions(code: bytes, where: str) -> list[OpcodeHit]:
    hits: list[OpcodeHit] = []
    i = 0
    n = len(code)
    while i < n:
        op = code[i]
        if op == 0x40:  # NPUSHB
            if i + 1 >= n:
                break
            i += 2 + code[i + 1]
            continue
        if op == 0x41:  # NPUSHW
            if i + 1 >= n:
                break
            i += 2 + 2 * code[i + 1]
            continue
        if 0xB0 <= op <= 0xB7:  # PUSHB[n]
            i += 1 + (op - 0xB0 + 1)
            continue
        if 0xB8 <= op <= 0xBF:  # PUSHW[n]
            i += 1 + 2 * (op - 0xB8 + 1)
            continue
        if op in SUSPECT_OPCODES:
            hits.append(OpcodeHit(where, i, op))
        i += 1
    return hits


def _tables(data: bytes, base: int = 0) -> dict[str, tuple[int, int]]:
    if len(data) < base + 12:
        return {}
    num = struct.unpack_from(">H", data, base + 4)[0]
    if num > MAX_TABLES:
        return {}
    out: dict[str, tuple[int, int]] = {}
    for k in range(num):
        rec = base + 12 + 16 * k
        if rec + 16 > len(data):
            break
        tag, _cs, off, ln = struct.unpack_from(">4sIII", data, rec)
        if off <= len(data) and off + ln <= len(data):
            out[tag.decode("latin-1")] = (off, ln)
    return out


def _glyph_programs(data: bytes, tabs: dict[str, tuple[int, int]]):
    if not all(t in tabs for t in ("glyf", "loca", "head", "maxp")):
        return
    head_off, head_len = tabs["head"]
    maxp_off, _ = tabs["maxp"]
    loca_off, loca_len = tabs["loca"]
    glyf_off, glyf_len = tabs["glyf"]
    if head_len < 54:
        return
    long_fmt = struct.unpack_from(">h", data, head_off + 50)[0]
    num_glyphs = struct.unpack_from(">H", data, maxp_off + 4)[0]
    if num_glyphs > MAX_GLYPHS:
        return
    entry = 4 if long_fmt else 2
    if (num_glyphs + 1) * entry > loca_len:
        return
    offs = []
    for g in range(num_glyphs + 1):
        if long_fmt:
            offs.append(struct.unpack_from(">I", data, loca_off + 4 * g)[0])
        else:
            offs.append(2 * struct.unpack_from(">H", data, loca_off + 2 * g)[0])
    for g in range(num_glyphs):
        start, end = offs[g], offs[g + 1]
        if end <= start or end > glyf_len or end - start < 10:
            continue
        p = glyf_off + start
        ncont = struct.unpack_from(">h", data, p)[0]
        q = p + 10
        if ncont >= 0:
            q += 2 * ncont
            if q + 2 > glyf_off + end:
                continue
            ilen = struct.unpack_from(">H", data, q)[0]
            q += 2
            if q + ilen <= glyf_off + end:
                yield g, data[q : q + ilen]
        else:  # composite glyph
            have_instr = False
            while q + 4 <= glyf_off + end:
                flags, _gi = struct.unpack_from(">HH", data, q)
                q += 4
                q += 4 if flags & 0x0001 else 2  # ARG_1_AND_2_ARE_WORDS
                if flags & 0x0008:
                    q += 2
                elif flags & 0x0040:
                    q += 4
                elif flags & 0x0080:
                    q += 8
                have_instr = bool(flags & 0x0100)
                if not flags & 0x0020:  # MORE_COMPONENTS
                    break
            if have_instr and q + 2 <= glyf_off + end:
                ilen = struct.unpack_from(">H", data, q)[0]
                q += 2
                if q + ilen <= glyf_off + end:
                    yield g, data[q : q + ilen]


def scan_font(data: bytes) -> tuple[list[OpcodeHit], list[str]]:
    """Return (hits, notes). notes lists parsing limitations hit during the scan."""
    notes: list[str] = []
    hits: list[OpcodeHit] = []
    bases = [0]
    if data[:4] == b"ttcf" and len(data) >= 16:
        count = struct.unpack_from(">I", data, 8)[0]
        bases = [struct.unpack_from(">I", data, 12 + 4 * i)[0] for i in range(min(count, 16))]
    for base in bases:
        tabs = _tables(data, base)
        if not tabs:
            notes.append("font table directory unreadable")
            continue
        for tag in ("fpgm", "prep"):
            if tag in tabs:
                off, ln = tabs[tag]
                hits.extend(scan_instructions(data[off : off + ln], tag))
        try:
            for gid, code in _glyph_programs(data, tabs) or []:
                hits.extend(scan_instructions(code, "glyf[" + str(gid) + "]"))
        except struct.error:
            notes.append("glyf parsing stopped early on malformed data")
    return hits, notes
