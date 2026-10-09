import json

from orchardwarden import cli
from orchardwarden.testing import make_backup


def test_schema_report_has_structure_but_no_content(tmp_path):
    bk = make_backup(tmp_path / "bk", suspicious=True)
    out = tmp_path / "schema.json"
    assert cli.main(["schema-report", str(bk), "--out", str(out)]) == 0
    text = out.read_text()
    rep = json.loads(text)
    sms = rep["databases"]["HomeDomain :: Library/SMS/sms.db"]
    assert "message" in sms["tables"] and "ROWID" in sms["tables"]["message"]["columns"]
    assert sms["message_date_unit"] == "nanoseconds" and "message" in sms["sequence_tables"]
    assert rep["ios_version"] == "16.1"
    # no content leaks: message text, URLs, phone numbers, device name
    for secret in ("hello 1", "evil-example", "+1555", "Test iPhone", "login."):
        assert secret not in text


def test_schema_report_refuses_encrypted(tmp_path):
    import plistlib

    bk = make_backup(tmp_path / "bk")
    (bk / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": True}))
    assert cli.main(["schema-report", str(bk), "--out", str(tmp_path / "s.json")]) == 1
