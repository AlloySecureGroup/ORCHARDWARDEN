import json
import sqlite3
from datetime import datetime, timedelta, timezone

from orchardwarden import correlate, exposure, messaging, profiles
from orchardwarden.kits import load_cards, parse_version
from orchardwarden.testing import apple_ns, make_mobileconfig


def test_version_parsing_and_kit_ranges():
    assert parse_version("17.2.1") < parse_version("17.3") < parse_version("18.4")
    cards = load_cards()
    assert cards["coruna"].affects("16.0") and not cards["coruna"].affects("17.3")
    assert cards["darksword"].affects("18.5") and not cards["darksword"].affects("26.3")
    assert not cards["darksword"].affects("18.3.2")


def test_gap_detection_ignores_small_gaps_and_finds_tail(tmp_path):
    db = tmp_path / "sms.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE message (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT, handle_id INT, date INT, is_from_me INT)")
    t = datetime(2026, 9, 1, tzinfo=timezone.utc)
    for i in (1, 2, 3, 5, 6, 7):  # gap of 1 at row 4: below MIN_GAP
        con.execute("INSERT INTO message VALUES (?,?,1,?,0)", (i, "x", apple_ns(t + timedelta(minutes=i))))
    con.execute("UPDATE sqlite_sequence SET seq=20 WHERE name='message'")  # 8..20 deleted at the tail
    con.commit()
    con.close()
    res = messaging.analyze_sms_db(db, None, None)
    gaps = [f for f in res.findings if f.id.startswith("MSG-GAP")]
    assert len(gaps) == 1 and gaps[0].evidence["gap"] == [8, 20]
    assert gaps[0].category == "info"  # a lone gap is information, not an accusation


def test_sms_db_without_expected_columns_degrades(tmp_path):
    db = tmp_path / "sms.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE message (ROWID INTEGER PRIMARY KEY, text TEXT)")
    con.execute("INSERT INTO message VALUES (1,'a')")
    con.commit()
    con.close()
    assert messaging.analyze_sms_db(db, None, None).status == "ran"
    con = sqlite3.connect(tmp_path / "other.db")
    con.execute("CREATE TABLE unrelated (a)")
    con.commit()
    con.close()
    assert messaging.analyze_sms_db(tmp_path / "other.db", None, None).status == "error"


def test_profile_rules_allowlist_and_signed_wrapper():
    raw = make_mobileconfig(
        "com.corp.vpn",
        "Corp VPN",
        "Corp",
        [
            {"PayloadType": "com.apple.vpn.managed", "PayloadIdentifier": "v", "VPNType": "IKEv2"},
            {"PayloadType": "com.apple.proxy.http.global", "PayloadIdentifier": "p", "ProxyServer": "10.0.0.1", "ProxyServerPort": 8080},
        ],
    )
    _, f = profiles.analyze_profile(raw, "p")
    kinds = {x.id for x in f}
    assert "PROF-PAYLOAD-PROXY-HTTP-GLOBAL" in kinds and "PROF-PAYLOAD-VPN-MANAGED" in kinds
    _, f2 = profiles.analyze_profile(raw, "p", {"identifiers": ["com.corp.vpn"]})
    assert {x.id for x in f2} == {"PROF-APPROVED"}
    wrapped = b"\x30\x82binaryCMS" + raw + b"\x00sig"  # signed profile: XML embedded in a CMS blob
    info, _ = profiles.analyze_profile(wrapped, "p")
    assert info.identifier == "com.corp.vpn"


def test_exposure_links_events_inside_window_only():
    wins = [exposure.Window("18.5", datetime(2026, 1, 1, tzinfo=timezone.utc), datetime(2026, 3, 1, tzinfo=timezone.utc))]
    evs = [{"time": "2026-02-01T00:00:00+00:00", "kit": "darksword"}, {"time": "2026-06-01T00:00:00+00:00", "kit": "darksword"}]
    res = exposure.analyze(wins, evs)
    ds = next(f for f in res.findings if f.kit == "darksword")
    assert len(ds.evidence["linked_events"]) == 1 and ds.category == "suspicious"
    assert exposure.analyze([]).status == "skipped"


LOG = """\
2026-10-01 10:00:00.100 MessagesBlastDoorService[311] received attachment from unknown sender
2026-10-01 10:00:05.200 MessagesBlastDoorService[311] terminated: signal 11 SIGSEGV
2026-10-01 10:00:40.000 netmon[12] NEW_DEST 203.0.113.9
2026-10-01 11:00:00.000 imagent[44] heartbeat ok
"""


def test_log_replay_finds_sequence_and_respects_time_windows():
    ev = list(correlate.events_from_log(LOG.splitlines()))
    assert [e.type for e in ev] == ["message", "crash", "net_flow"]
    res = correlate.run_rules(ev, correlate.load_rules())
    assert "COR-MESSAGE_CRASH_NETBURST" in {f.id for f in res.findings}
    # same events but the connection happens too late: no match
    late = LOG.replace("10:00:40.000", "10:05:00.000")
    res2 = correlate.run_rules(list(correlate.events_from_log(late.splitlines())), correlate.load_rules())
    assert not res2.findings


def test_repeated_crash_rule_and_jsonl():
    lines = [
        json.dumps({"time": "2026-10-01T10:00:00+00:00", "type": "crash", "actor": "imagent"}),
        json.dumps({"time": "2026-10-01T10:00:30+00:00", "type": "crash", "actor": "imagent", "attrs": {"process": "imagent"}}),
    ]
    ev = list(correlate.events_from_jsonl(lines))
    ev[0].attrs["process"] = "imagent"
    res = correlate.run_rules(ev, correlate.load_rules())
    assert "COR-REPEATED_PARSER_CRASHES" in {f.id for f in res.findings}


def test_cli_end_to_end(tmp_path, capsys):
    from orchardwarden import cli
    from orchardwarden.testing import make_backup, make_ioc_bundle

    bk = make_backup(tmp_path / "bk", suspicious=True)
    iocs = tmp_path / "iocs.json"
    iocs.write_text(json.dumps(make_ioc_bundle()))
    rc = cli.main(["scan-backup", str(bk), "--ioc", str(iocs), "--out", str(tmp_path / "out")])
    assert rc == 2 and (tmp_path / "out" / "report.md").exists()

    # signed feed through the CLI, and a tampered one is rejected
    cli.main(["ioc", "keygen", "--out", str(tmp_path / "keys")])
    cli.main(
        [
            "ioc",
            "sign",
            "--bundle",
            str(iocs),
            "--private-key",
            str(tmp_path / "keys" / "feed_private.key"),
            "--key-id",
            "orchardwarden-test",
            "--out",
            str(tmp_path / "feed.signed"),
        ]
    )
    assert (
        cli.main(["ioc", "verify", "--bundle", str(tmp_path / "feed.signed"), "--pinned-keys", str(tmp_path / "keys" / "pinned_keys.json")])
        == 0
    )
    env = json.loads((tmp_path / "feed.signed").read_text())
    env["payload"] = env["payload"].replace("evil-example", "other-example")
    (tmp_path / "bad.signed").write_text(json.dumps(env))
    assert (
        cli.main(["ioc", "verify", "--bundle", str(tmp_path / "bad.signed"), "--pinned-keys", str(tmp_path / "keys" / "pinned_keys.json")])
        == 1
    )
