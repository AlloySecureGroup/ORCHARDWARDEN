"""Kit intelligence cards."""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml


def parse_version(v: str) -> tuple[int, ...]:
    parts = []
    for p in str(v).strip().split("."):
        digits = "".join(ch for ch in p if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


@dataclass
class KitCard:
    kit: str
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def cves(self) -> list[str]:
        return list(self.data.get("cves", []))

    @property
    def sources(self) -> list[str]:
        return list(self.data.get("sources", []))

    def affects(self, version: str) -> bool:
        ver = parse_version(version)
        for rng in self.data.get("affected_ios", []):
            lo = parse_version(rng["min"])
            hi = parse_version(rng["max"])
            if lo <= ver <= hi:
                return True
        return False


def load_cards(extra_dir: Path | None = None) -> dict[str, KitCard]:
    cards: dict[str, KitCard] = {}
    base = resources.files("orchardwarden.kits") / "cards"
    for entry in base.iterdir():
        if entry.name.endswith(".yaml"):
            data = yaml.safe_load(entry.read_text(encoding="utf-8"))
            cards[data["kit"]] = KitCard(data["kit"], data)
    if extra_dir:
        for p in Path(extra_dir).glob("*.yaml"):
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
            cards[data["kit"]] = KitCard(data["kit"], data)
    return cards


def card_for_cve(cards: dict[str, KitCard], cve: str) -> KitCard | None:
    for c in cards.values():
        if cve in c.cves:
            return c
    return None
