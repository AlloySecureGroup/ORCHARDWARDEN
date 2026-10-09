"""Command line interface."""

from __future__ import annotations

import argparse
import base64
import json
import sys
import tempfile
from pathlib import Path

from . import correlate, exposure, filescan, profiles, report, scan
from .ioc import IocIndex, load_iocs, load_stix_bundle
from .ioc import feed as ioc_feed
from .kits import load_cards
from .models import ScanResult


def _load_ioc_args(paths: list[str] | None, pinned: str | None) -> IocIndex | None:
    if not paths:
        return None
    idx = IocIndex()
    plain: list[Path] = []
    for p in paths:
        pp = Path(p)
        if pp.suffix == ".signed":
            if not pinned:
                raise SystemExit("signed feeds need --pinned-keys")
            keys = ioc_feed.load_pinned_keys(Path(pinned))
            bundle = ioc_feed.verify_envelope(json.loads(pp.read_text(encoding="utf-8")), keys)
            for ind in load_stix_bundle(bundle, source=pp.name):
                idx.add(ind)
        else:
            plain.append(pp)
    if plain:
        for kind_map in load_iocs(plain)._by_kind.values():
            for ind in kind_map.values():
                idx.add(ind)
    return idx


def _emit(res: ScanResult, out: str | None, fmt: str, redact: bool) -> None:
    md = report.to_markdown(res, redact=redact)
    js = json.dumps(report.to_dict(res), indent=2, default=str)
    if out:
        o = Path(out)
        o.mkdir(parents=True, exist_ok=True)
        (o / "report.md").write_text(md, encoding="utf-8")
        (o / "report.json").write_text(js, encoding="utf-8")
        print("Verdict: " + res.verdict() + " | Coverage grade: " + res.coverage_grade())
        print("Wrote " + str(o / "report.md") + " and " + str(o / "report.json"))
    else:
        print(js if fmt == "json" else md)


def cmd_scan_files(a: argparse.Namespace) -> int:
    iocs = _load_ioc_args(a.ioc, a.pinned_keys)
    exts = set(a.ext.split(",")) if a.ext else None
    mod = filescan.scan_paths([Path(p) for p in a.paths], a.recursive, exts, a.context, iocs)
    res = ScanResult(target=", ".join(a.paths), modules=[mod])
    _emit(res, a.out, a.format, not a.no_redact)
    return 2 if res.verdict() == "Indicators found" else 0


def cmd_scan_backup(a: argparse.Namespace) -> int:
    iocs = _load_ioc_args(a.ioc, a.pinned_keys)
    res = scan.scan_backup(Path(a.backup), iocs, Path(a.allow) if a.allow else None, not a.no_attachments)
    _emit(res, a.out, a.format, not a.no_redact)
    return 2 if res.verdict() == "Indicators found" else 0


def cmd_check_profile(a: argparse.Namespace) -> int:
    mod, infos = profiles.analyze_files([Path(p) for p in a.files], Path(a.allow) if a.allow else None)
    res = ScanResult(target=", ".join(a.files), modules=[mod])
    _emit(res, a.out, a.format, not a.no_redact)
    return 0


def cmd_exposure(a: argparse.Namespace) -> int:
    wins = exposure.load_versions(Path(a.versions))
    evs = exposure.load_events(Path(a.events)) if a.events else None
    mod = exposure.analyze(wins, evs)
    res = ScanResult(target=a.versions, modules=[mod])
    _emit(res, a.out, a.format, not a.no_redact)
    return 0


def cmd_replay(a: argparse.Namespace) -> int:
    p = Path(a.source)
    lines = p.read_text(encoding="utf-8").splitlines()
    if a.jsonl:
        events = list(correlate.events_from_jsonl(lines))
    else:
        events = list(correlate.events_from_log(lines, correlate.load_logmap(Path(a.logmap)) if a.logmap else None))
    rules = correlate.load_rules(Path(a.rules) if a.rules else None)
    mod = correlate.run_rules(events, rules)
    res = ScanResult(target=a.source, modules=[mod])
    _emit(res, a.out, a.format, not a.no_redact)
    return 0


def cmd_ioc(a: argparse.Namespace) -> int:
    if a.action == "keygen":
        priv, pub = ioc_feed.generate_keypair()
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "feed_private.key").write_text(base64.b64encode(priv).decode(), encoding="utf-8")
        (out / "pinned_keys.json").write_text(json.dumps({a.key_id: base64.b64encode(pub).decode()}, indent=2), encoding="utf-8")
        print("Wrote private key and pinned_keys.json to " + str(out))
        return 0
    if a.action == "sign":
        priv = base64.b64decode(Path(a.private_key).read_text(encoding="utf-8"))
        env = ioc_feed.sign_bundle(json.loads(Path(a.bundle).read_text(encoding="utf-8")), priv, a.key_id)
        Path(a.out).write_text(json.dumps(env, indent=2), encoding="utf-8")
        print("Signed feed written to " + a.out)
        return 0
    if a.action == "verify":
        keys = ioc_feed.load_pinned_keys(Path(a.pinned_keys))
        try:
            b = ioc_feed.verify_envelope(json.loads(Path(a.bundle).read_text(encoding="utf-8")), keys)
        except ioc_feed.FeedError as exc:
            print("INVALID: " + str(exc))
            return 1
        print("VALID: " + str(len(load_stix_bundle(b))) + " indicators")
        return 0
    return 1


def cmd_schema_report(a: argparse.Namespace) -> int:
    from . import schema_report

    rep = schema_report.dump(Path(a.backup), Path(a.out))
    if "error" in rep:
        print("ERROR: " + rep["error"])
        return 1
    print("Wrote " + a.out + " (structure only: no message text, URLs, numbers or serials)")
    return 0


def cmd_kits(a: argparse.Namespace) -> int:
    for name, c in sorted(load_cards().items()):
        d = c.data
        print(
            name
            + ": CVEs "
            + ", ".join(c.cves)
            + " | affected "
            + json.dumps(d.get("affected_ios"))
            + " | review needed: "
            + str(d.get("needs_primary_source_review", False))
        )
    return 0


def cmd_demo(a: argparse.Namespace) -> int:
    from .testing import make_backup, make_ioc_bundle

    work = Path(a.dir) if a.dir else Path(tempfile.mkdtemp(prefix="orchardwarden_demo_"))
    work.mkdir(parents=True, exist_ok=True)
    make_backup(work / "backup_suspicious", suspicious=True)
    make_backup(work / "backup_clean", suspicious=False, version="26.3")
    ioc_path = work / "iocs.json"
    ioc_path.write_text(json.dumps(make_ioc_bundle()), encoding="utf-8")
    print("Synthetic data in " + str(work))
    for name in ("backup_suspicious", "backup_clean"):
        res = scan.scan_backup(work / name, _load_ioc_args([str(ioc_path)], None))
        out = work / ("report_" + name)
        _emit(res, str(out), "md", True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="orchardwarden", description="Prototype multi-layer iOS integrity checks.")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--out", help="directory to write report.md and report.json")
        sp.add_argument("--format", choices=["md", "json"], default="md")
        sp.add_argument("--no-redact", action="store_true", help="show URLs and filenames in the report")

    sp = sub.add_parser("scan-files", help="structural scan of files or folders")
    sp.add_argument("paths", nargs="+")
    sp.add_argument("-r", "--recursive", action="store_true")
    sp.add_argument("-e", "--ext", help="comma separated extensions")
    sp.add_argument("--context", choices=["files", "messaging"], default="files")
    sp.add_argument("--ioc", action="append")
    sp.add_argument("--pinned-keys")
    common(sp)
    sp.set_defaults(fn=cmd_scan_files)

    sp = sub.add_parser("scan-backup", help="scan a decrypted iOS backup folder")
    sp.add_argument("backup")
    sp.add_argument("--ioc", action="append", help="STIX2 .json, plain list, or .signed feed")
    sp.add_argument("--pinned-keys")
    sp.add_argument("--allow", help="JSON allowlist of approved profile identifiers and hashes")
    sp.add_argument("--no-attachments", action="store_true")
    common(sp)
    sp.set_defaults(fn=cmd_scan_backup)

    sp = sub.add_parser("check-profile", help="analyze configuration profiles")
    sp.add_argument("files", nargs="+")
    sp.add_argument("--allow")
    common(sp)
    sp.set_defaults(fn=cmd_check_profile)

    sp = sub.add_parser("exposure", help="version exposure analysis")
    sp.add_argument("--versions", required=True, help="JSON list of {version, from, to}")
    sp.add_argument("--events", help="JSON list of {time, kit, ioc_match}")
    common(sp)
    sp.set_defaults(fn=cmd_exposure)

    sp = sub.add_parser("replay", help="run correlation rules over a recorded log or events file")
    sp.add_argument("source")
    sp.add_argument("--jsonl", action="store_true", help="source is normalized JSONL events")
    sp.add_argument("--rules")
    sp.add_argument("--logmap")
    common(sp)
    sp.set_defaults(fn=cmd_replay)

    sp = sub.add_parser("ioc", help="feed key generation, signing and verification")
    sp.add_argument("action", choices=["keygen", "sign", "verify"])
    sp.add_argument("--out")
    sp.add_argument("--key-id", default="orchardwarden-test")
    sp.add_argument("--private-key")
    sp.add_argument("--bundle")
    sp.add_argument("--pinned-keys")
    sp.set_defaults(fn=cmd_ioc)

    sp = sub.add_parser("schema-report", help="privacy-safe structure report of a decrypted backup")
    sp.add_argument("backup")
    sp.add_argument("--out", required=True, help="output JSON file")
    sp.set_defaults(fn=cmd_schema_report)

    sp = sub.add_parser("kits", help="list kit cards")
    sp.set_defaults(fn=cmd_kits)

    sp = sub.add_parser("demo", help="generate synthetic backups and scan them")
    sp.add_argument("--dir")
    sp.set_defaults(fn=cmd_demo)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
