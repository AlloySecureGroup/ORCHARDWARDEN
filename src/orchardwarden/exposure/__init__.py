"""Exposure analysis: which kits could have worked on this device, and when."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from ..kits import KitCard, load_cards
from ..models import INFO, SUSPICIOUS, Finding, ModuleResult, Severity

MODULE = "exposure"


def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


@dataclass
class Window:
    version: str
    start: datetime | None
    end: datetime | None


def load_versions(path: Path) -> list[Window]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return [Window(r["version"], _dt(r.get("from")), _dt(r.get("to"))) for r in raw]


def load_events(path: Path) -> list[dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def analyze(windows: list[Window], events: list[dict] | None = None, cards: dict[str, KitCard] | None = None) -> ModuleResult:
    cards = cards or load_cards()
    events = events or []
    res = ModuleResult(MODULE, "ran" if windows else "skipped")
    if not windows:
        res.reason = "no iOS version history supplied"
        return res
    res.items_examined = len(windows)
    for w in windows:
        for card in cards.values():
            if not card.affects(w.version):
                continue
            overlapping = [e for e in events if _in_window(_dt(e.get("time")), w) and (e.get("kit") == card.kit or e.get("ioc_match"))]
            sev = Severity.MEDIUM if overlapping else Severity.LOW
            res.findings.append(
                Finding(
                    "EXP-" + card.kit.upper(),
                    "Device ran an iOS version in the affected range for " + card.kit,
                    sev,
                    SUSPICIOUS if overlapping else INFO,
                    "medium" if overlapping else "low",
                    "F",
                    MODULE,
                    "iOS "
                    + w.version
                    + " ("
                    + _fmt(w)
                    + ") falls inside the range recorded on the kit card. "
                    + (
                        "Activity linked to this kit occurred in the same window."
                        if overlapping
                        else "Exposure alone is not evidence of compromise."
                    ),
                    {
                        "version": w.version,
                        "from": _fmt_t(w.start),
                        "to": _fmt_t(w.end),
                        "cves": card.cves,
                        "linked_events": overlapping[:10],
                    },
                    kit=card.kit,
                    cves=card.cves,
                    caveat="Affected ranges on kit cards are coarse and need verification against Apple security notes."
                    if card.data.get("needs_primary_source_review")
                    else None,
                )
            )
    return res


def _in_window(t: datetime | None, w: Window) -> bool:
    if t is None:
        return False
    if w.start and t < w.start:
        return False
    if w.end and t > w.end:
        return False
    return True


def _fmt_t(t: datetime | None) -> str | None:
    return t.isoformat() if t else None


def _fmt(w: Window) -> str:
    return (_fmt_t(w.start) or "unknown start") + " to " + (_fmt_t(w.end) or "unknown end")
