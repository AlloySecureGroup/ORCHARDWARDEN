"""Core data model: findings, module results, verdicts, coverage grade."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# Category drives the verdict. "indicator" means a known-bad match or a structural
# signature that legitimate files do not exhibit. "suspicious" means anomaly only.
INDICATOR = "indicator"
SUSPICIOUS = "suspicious"
INFO = "info"

VERDICT_INDICATORS = "Indicators found"
VERDICT_SUSPICIOUS = "Suspicious artifacts"
VERDICT_NONE = "No known indicators found"


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    category: str  # indicator | suspicious | info
    confidence: str  # high | medium | low
    layer: str  # A device artifacts, B live logs, C network, D config, E radio, F intel
    module: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    kit: str | None = None
    cves: list[str] = field(default_factory=list)
    source: str | None = None
    caveat: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.name,
            "category": self.category,
            "confidence": self.confidence,
            "layer": self.layer,
            "module": self.module,
            "description": self.description,
            "evidence": self.evidence,
            "kit": self.kit,
            "cves": self.cves,
            "source": self.source,
            "caveat": self.caveat,
        }


@dataclass
class ModuleResult:
    name: str
    status: str  # ran | partial | skipped | error
    reason: str = ""
    items_examined: int = 0
    findings: list[Finding] = field(default_factory=list)
    unsupported_checks: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "reason": self.reason,
            "items_examined": self.items_examined,
            "findings": len(self.findings),
            "unsupported_checks": self.unsupported_checks,
        }


@dataclass
class ScanResult:
    target: str
    modules: list[ModuleResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        out: list[Finding] = []
        for m in self.modules:
            out.extend(m.findings)
        return sorted(out, key=lambda f: (-int(f.severity), f.module, f.id))

    def verdict(self) -> str:
        cats = {f.category for f in self.findings}
        if INDICATOR in cats:
            return VERDICT_INDICATORS
        if SUSPICIOUS in cats:
            return VERDICT_SUSPICIOUS
        return VERDICT_NONE

    def coverage_grade(self) -> str:
        """A to D. Never a statement of safety, only of how much was examined."""
        if not self.modules:
            return "D"
        score = 0.0
        for m in self.modules:
            if m.status == "ran":
                score += 1.0
            elif m.status == "partial":
                score += 0.5
        ratio = score / len(self.modules)
        if ratio >= 0.9:
            grade = "A"
        elif ratio >= 0.7:
            grade = "B"
        elif ratio >= 0.4:
            grade = "C"
        else:
            grade = "D"
        return grade
