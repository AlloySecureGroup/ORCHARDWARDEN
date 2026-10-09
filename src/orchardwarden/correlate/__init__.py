"""Normalized events and the cross-layer sequence rule engine."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from importlib import resources
from pathlib import Path
from typing import Any, Iterable, Iterator

import yaml

from ..models import SUSPICIOUS, Finding, ModuleResult, Severity

MODULE = "correlation"


@dataclass
class Event:
    time: datetime
    layer: str
    type: str  # message, crash, net_flow, dns, process, profile, log
    actor: str = ""
    obj: str = ""
    attrs: dict[str, Any] = field(default_factory=dict)
    raw: str = ""

    def get(self, key: str) -> Any:
        if key == "actor":
            return self.actor
        if key == "obj":
            return self.obj
        return self.attrs.get(key)


def parse_time(s: str) -> datetime:
    s = s.strip().replace("Z", "+00:00")
    if " " in s and "T" not in s:
        s = s.replace(" ", "T", 1)
    return datetime.fromisoformat(s)


def events_from_jsonl(lines: Iterable[str]) -> Iterator[Event]:
    for line in lines:
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        yield Event(parse_time(d["time"]), d.get("layer", "B"), d["type"], d.get("actor", ""), d.get("obj", ""), d.get("attrs", {}))


def load_logmap(path: Path | None = None) -> list[dict]:
    if path:
        return yaml.safe_load(Path(path).read_text(encoding="utf-8"))["mappings"]
    txt = (resources.files("orchardwarden.correlate") / "logmap.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(txt)["mappings"]


_LOG_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<proc>[^\s\[]+)(?:\[(?P<pid>\d+)\])?\s*(?P<msg>.*)$"
)


def events_from_log(lines: Iterable[str], logmap: list[dict] | None = None) -> Iterator[Event]:
    """Map raw log lines to events. The line format and mappings are a prototype and must be
    validated against real device log output per iOS version."""
    logmap = logmap or load_logmap()
    compiled = [(re.compile(m["regex"], re.I), m) for m in logmap]
    for line in lines:
        m = _LOG_LINE.match(line.strip())
        if not m:
            continue
        ts = parse_time(m.group("ts"))
        proc, msg = m.group("proc"), m.group("msg")
        for rx, mapping in compiled:
            hay = proc + " " + msg
            mm = rx.search(hay)
            if mm:
                attrs = dict(mapping.get("attrs", {}))
                attrs.update({k: v for k, v in mm.groupdict().items() if v})
                yield Event(ts, mapping.get("layer", "B"), mapping["type"], proc, attrs.get("obj", ""), attrs, line.strip())
                break


def _match(ev: Event, step: dict) -> bool:
    if ev.type != step["type"]:
        return False
    for key, want in (step.get("attrs") or {}).items():
        if key.endswith("_in"):
            if ev.get(key[:-3]) not in want:
                return False
        elif key.endswith("_not_in"):
            if ev.get(key[:-7]) in want:
                return False
        elif ev.get(key) != want:
            return False
    return True


def load_rules(path: Path | None = None) -> list[dict]:
    if path:
        return yaml.safe_load(Path(path).read_text(encoding="utf-8"))["rules"]
    txt = (resources.files("orchardwarden.correlate") / "rules.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(txt)["rules"]


def run_rules(events: list[Event], rules: list[dict]) -> ModuleResult:
    events = sorted(events, key=lambda e: e.time)
    res = ModuleResult(MODULE, "ran", items_examined=len(events))
    for rule in rules:
        steps = rule["sequence"]
        for i, ev in enumerate(events):
            if not _match(ev, steps[0]):
                continue
            chain = [ev]
            cursor = i
            ok = True
            for step in steps[1:]:
                within = float(step.get("within", 60))
                found = None
                for j in range(cursor + 1, len(events)):
                    e2 = events[j]
                    if (e2.time - chain[-1].time).total_seconds() > within:
                        break
                    if _match(e2, step):
                        found = (j, e2)
                        break
                if not found:
                    ok = False
                    break
                cursor, e2 = found
                chain.append(e2)
            if ok:
                res.findings.append(
                    Finding(
                        "COR-" + rule["rule"].upper(),
                        rule.get("title", rule["rule"]),
                        Severity[rule.get("severity", "MEDIUM").upper()],
                        SUSPICIOUS,
                        rule.get("confidence", "medium"),
                        "B",
                        MODULE,
                        rule.get("explain", ""),
                        {"events": [{"time": c.time.isoformat(), "type": c.type, "actor": c.actor, "obj": c.obj} for c in chain]},
                        kit=rule.get("kit"),
                        caveat="Behavioural correlation. Corroborate with artifacts and network evidence.",
                    )
                )
    return res
