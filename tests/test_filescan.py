from orchardwarden.filescan import scan_bytes
from orchardwarden.filescan.ttf import scan_instructions
from orchardwarden.testing import make_pdf, make_pkpass, make_tiff, make_ttf, make_webp


def ids(findings):
    return {f.id for f in findings}


def test_push_data_byte_is_not_flagged_but_opcode_is():
    # PUSHB[0] 0x8F pushes a data byte equal to 0x8F: must NOT be flagged.
    assert scan_instructions(b"\xb0\x8f\x2f", "t") == []
    # NPUSHB with 2 data bytes then a real 0x90 opcode: flagged exactly once.
    hits = scan_instructions(b"\x40\x02\x8f\x90\x90", "t")
    assert len(hits) == 1 and hits[0].opcode == 0x90 and hits[0].offset == 4
    # PUSHW[0] consumes two data bytes.
    assert scan_instructions(b"\xb8\x8f\x8f\x2f", "t") == []


def test_font_with_undocumented_opcode_in_fpgm_is_indicator():
    f = scan_bytes(make_ttf(b"\xb0\x01\x8f\x2f"), "x.ttf")
    assert "FS-TTF-ADJUST" in ids(f)
    hit = next(x for x in f if x.id == "FS-TTF-ADJUST")
    assert hit.category == "indicator" and "CVE-2023-41990" in hit.cves


def test_font_with_undocumented_opcode_in_glyph_is_found():
    f = scan_bytes(make_ttf(b"\xb0\x01\x90", in_glyph=True), "x.ttf")
    hit = next(x for x in f if x.id == "FS-TTF-ADJUST")
    assert hit.evidence["hits"][0]["where"].startswith("glyf[")


def test_benign_font_is_clean():
    assert scan_bytes(make_ttf(b"\xb0\x01\x2f\x2f"), "x.ttf") == []
    assert scan_bytes(make_ttf(b"\xb0\x8f\x2f"), "x.ttf") == []  # data byte only


def test_pdf_disguised_as_gif_is_flagged():
    f = scan_bytes(make_pdf(jbig2=True), "IMG_0001.gif", context="messaging")
    assert "FS-EXT-MISMATCH" in ids(f) and "FS-PDF-JBIG2" in ids(f)
    mm = next(x for x in f if x.id == "FS-EXT-MISMATCH")
    assert mm.category == "indicator"


def test_jbig2_pdf_in_normal_files_is_info_only():
    f = scan_bytes(make_pdf(jbig2=True), "scan.pdf", context="files")
    j = next(x for x in f if x.id == "FS-PDF-JBIG2")
    assert j.category == "info"
    assert scan_bytes(make_pdf(jbig2=False), "doc.pdf") == []


def test_dng_component_mismatch_is_review_item_with_context_bump():
    plain = scan_bytes(make_tiff(2, 1), "a.dng", context="files")
    msg = scan_bytes(make_tiff(2, 1), "a.dng", context="messaging")
    assert "FS-DNG-SPP" in ids(plain)
    p = next(x for x in plain if x.id == "FS-DNG-SPP")
    m = next(x for x in msg if x.id == "FS-DNG-SPP")
    assert p.category == "suspicious" and int(m.severity) > int(p.severity)
    assert scan_bytes(make_tiff(1, 1), "ok.dng") == []


def test_webp_container_and_pkpass_nesting():
    assert scan_bytes(make_webp(), "a.webp") == []
    bad = make_webp() + b"\x00\x00\x00"  # RIFF size now inconsistent
    assert "FS-WEBP-SIZE" in ids(scan_bytes(bad, "a.webp", context="messaging"))
    pk = make_pkpass({"icon.ttf": make_ttf(b"\xb0\x01\x8f"), "logo.webp": make_webp()})
    f = scan_bytes(pk, "ticket.pkpass", context="messaging")
    assert "FS-TTF-ADJUST" in ids(f) and "FS-PKPASS-VP8L" in ids(f)


def test_truncated_and_garbage_inputs_do_not_crash():
    for blob in (b"", b"\x00\x01\x00\x00", b"II*\x00\xff\xff\xff\xff", b"RIFF\x00\x00\x00\x00WEBP", b"%PDF-", b"PK\x03\x04junk"):
        scan_bytes(blob, "x.ttf")
        scan_bytes(blob, "x.dng")
        scan_bytes(blob, "x.pkpass")
