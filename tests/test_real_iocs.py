"""IOC kinds seen in real public bundles, plus an optional run against the real feeds.

Set ORCHARD_SAMPLES to a folder containing clones of mvt-project/mvt-indicators and
AmnestyTech/investigations to enable the real-data tests. They are skipped otherwise.
"""

import hashlib
import os
from pathlib import Path

import pytest

from orchardwarden import scan
from orchardwarden.filescan import scan_bytes
from orchardwarden.ioc import IocIndex, load_stix_bundle
from orchardwarden.profiles import analyze_profile
from orchardwarden.testing import make_backup, make_mobileconfig, make_ttf


def bundle(*patterns):
    return {"objects": [{"type": "indicator", "pattern": p} for p in patterns]}


def idx_from(*patterns):
    i = IocIndex()
    for ind in load_stix_bundle(bundle(*patterns)):
        i.add(ind)
    return i


def test_path_indicator_matches_backup_relative_paths_on_boundaries():
    i = idx_from("[file:path='/private/var/db/com.apple.xpc.roleaccountd.staging/evil.dat']")
    assert i.match_file_path("db/com.apple.xpc.roleaccountd.staging/evil.dat")
    assert i.match_file_path("/private/var/db/com.apple.xpc.roleaccountd.staging/evil.dat")
    assert i.match_file_path("db/com.apple.xpc.roleaccountd.staging/other.dat") is None
    assert i.match_file_path("xevil.dat") is None  # suffix must fall on a path boundary


def test_sha256_lowercase_variant_and_file_hash_match():
    data = make_ttf(b"\xb0\x01\x2f")
    digest = hashlib.sha256(data).hexdigest()
    i = idx_from("[file:hashes.sha256='" + digest + "']")
    assert "FS-IOC-HASH" in {f.id for f in scan_bytes(data, "x.ttf", iocs=i)}


def test_profile_id_and_email_indicators(tmp_path):
    uuid = "76DAB334-7E17-475D-A5D6-0794EB5818A5"
    i = idx_from("[configuration-profile:id='" + uuid + "']", "[email-addr:value='Bad.Actor@Example.test']")
    raw = make_mobileconfig("com.x.y", "Profile", "Org", []).replace(b"00000000-0000-0000-0000-000000000001", uuid.encode())
    _, f = analyze_profile(raw, "p", None, i)
    assert "PROF-ID-IOC" in {x.id for x in f}
    assert i.match_email("bad.actor@example.test")


def test_message_handle_email_ioc_in_backup(tmp_path):
    i = idx_from("[email-addr:value='+15550100002']")  # synthetic handle id stored as text
    res = scan.scan_backup(make_backup(tmp_path / "bk", suspicious=True), i)
    assert "MSG-HANDLE-IOC" in {f.id for f in res.findings}


def test_path_ioc_module_in_backup(tmp_path):
    i = idx_from("[file:path='/Library/SMS/Attachments/aa/01/note.ttf']")
    res = scan.scan_backup(make_backup(tmp_path / "bk", suspicious=True), i)
    assert "PATH-IOC" in {f.id for f in res.findings}


SAMPLES = os.environ.get("ORCHARD_SAMPLES")
real = pytest.mark.skipif(not SAMPLES or not Path(SAMPLES).exists(), reason="set ORCHARD_SAMPLES to run")


@real
def test_all_real_bundles_load_and_parse_most_indicators():
    files = list(Path(SAMPLES).rglob("*.stix2"))
    assert files
    import json

    total = parsed = 0
    for f in files:
        d = json.loads(f.read_text())
        n = sum(1 for o in d["objects"] if o.get("type") == "indicator")
        total += n
        parsed += len(load_stix_bundle(d))
    assert parsed / total > 0.97, (parsed, total)


@real
def test_false_positive_check_real_feeds_vs_clean_synthetic_backup(tmp_path):
    from orchardwarden.ioc import load_iocs

    idx = load_iocs(list(Path(SAMPLES).rglob("*.stix2")))
    assert len(idx) > 5000
    res = scan.scan_backup(make_backup(tmp_path / "bk", suspicious=False, version="26.3"), idx)
    bad = [f.id for f in res.findings if f.category != "info"]
    assert bad == [], bad
