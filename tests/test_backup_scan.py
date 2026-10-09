import json
import plistlib

from orchardwarden import scan
from orchardwarden.ioc import IocIndex, load_stix_bundle
from orchardwarden.models import VERDICT_INDICATORS, VERDICT_NONE
from orchardwarden.testing import make_backup, make_ioc_bundle


def _idx():
    idx = IocIndex()
    for i in load_stix_bundle(make_ioc_bundle()):
        idx.add(i)
    return idx


def test_suspicious_backup_finds_expected_artifacts(tmp_path):
    root = make_backup(tmp_path / "bk", suspicious=True)
    res = scan.scan_backup(root, _idx())
    ids = {f.id for f in res.findings}
    expected = {
        "FS-TTF-ADJUST",
        "FS-EXT-MISMATCH",
        "FS-PDF-JBIG2",
        "FS-DNG-SPP",
        "MSG-URL-IOC",
        "MSG-GAP-FIRSTCONTACT",
        "MSG-INVISIBLE",
        "MSG-ATT-ORPHAN",
        "SAF-URL-IOC",
        "DU-PROC-SUSPECT",
        "PROF-PAYLOAD-SECURITY-ROOT",
        "PROF-NO-REMOVE",
        "PROF-MIMIC-NAME",
        "EXP-TRIANGULATION",
    }
    assert expected <= ids, expected - ids
    assert res.verdict() == VERDICT_INDICATORS


def test_clean_backup_is_not_called_safe(tmp_path):
    root = make_backup(tmp_path / "bk", suspicious=False, version="26.3")
    res = scan.scan_backup(root, _idx())
    assert res.verdict() == VERDICT_NONE
    assert not [f for f in res.findings if f.category != "info"]
    # verdict wording never claims safety, and coverage is reported separately
    assert "safe" not in res.verdict().lower() and "clean" not in res.verdict().lower()
    assert res.coverage_grade() in "ABCD"


def test_benign_backupagent2_not_flagged(tmp_path):
    root = make_backup(tmp_path / "bk", suspicious=False)
    res = scan.scan_backup(root, None)
    assert not any(f.id == "DU-PROC-SUSPECT" for f in res.findings)


def test_encrypted_backup_is_refused_not_misread(tmp_path):
    root = make_backup(tmp_path / "bk", suspicious=True)
    (root / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": True}))
    res = scan.scan_backup(root, _idx())
    assert res.modules[0].status == "error" and "encrypted" in res.modules[0].reason
    assert res.findings == []
    assert res.coverage_grade() == "D"


def test_missing_manifest(tmp_path):
    (tmp_path / "empty").mkdir()
    res = scan.scan_backup(tmp_path / "empty")
    assert res.modules[0].status == "error"


def test_no_iocs_still_runs_structural_checks_and_says_so(tmp_path):
    root = make_backup(tmp_path / "bk", suspicious=True)
    res = scan.scan_backup(root, None)
    assert any("No IOC set loaded" in n for n in res.notes)
    assert "FS-TTF-ADJUST" in {f.id for f in res.findings}
    assert "MSG-URL-IOC" not in {f.id for f in res.findings}


def test_report_redacts_urls_by_default(tmp_path):
    from orchardwarden import report

    root = make_backup(tmp_path / "bk", suspicious=True)
    res = scan.scan_backup(root, _idx())
    md = report.to_markdown(res, redact=True)
    assert "login.evil-example.test" not in md and "[redacted]" in md
    assert "cannot prove a device is safe" in md
    assert json.loads(json.dumps(report.to_dict(res), default=str))["verdict"] == VERDICT_INDICATORS
