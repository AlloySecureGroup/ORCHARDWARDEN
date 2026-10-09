"""JSON and Markdown report rendering with honest verdict wording."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from ..models import VERDICT_NONE, ScanResult

LIMITS = (
    "This tool reports known indicators and anomalies. It cannot prove a device is safe. "
    "Absence of findings can result from missing data, a recent update or reboot, or an attacker "
    "removing traces. Baseband, kernel memory and carrier-side attacks are not observable here."
)

NEXT_STEPS = {
    "Indicators found": [
        "Stop using this device for sensitive communication. Use another device.",
        "Do not factory reset yet. Preserve this report and the backup for expert review.",
        "Contact a digital security helpline (for example Access Now Digital Security Helpline).",
        "Assess which sources and contacts may be exposed and warn them through a different device.",
    ],
    "Suspicious artifacts": [
        "Update iOS, enable Lockdown Mode, and restart the device.",
        "Re-scan after a few days and compare findings.",
        "Ask a trusted analyst to review the evidence listed below.",
    ],
    "No known indicators found": [
        "Keep iOS updated, use Lockdown Mode if you are at elevated risk, and restart regularly.",
        "Re-scan periodically. Read the coverage section to see what was not examined.",
    ],
}


def to_dict(res: ScanResult) -> dict:
    return {
        "generated": datetime.now(timezone.utc).isoformat(),
        "target": res.target,
        "verdict": res.verdict(),
        "coverage_grade": res.coverage_grade(),
        "limits": LIMITS,
        "notes": res.notes,
        "modules": [m.to_dict() for m in res.modules],
        "findings": [f.to_dict() for f in res.findings],
        "next_steps": NEXT_STEPS[res.verdict()],
    }


def to_markdown(res: ScanResult, redact: bool = True) -> str:
    d = to_dict(res)
    lines: list[str] = []
    lines.append("# Orchard Warden scan report")
    lines.append("")
    lines.append("**Verdict:** " + d["verdict"] + "  ")
    lines.append("**Coverage grade:** " + d["coverage_grade"] + " (how much was examined, not how safe the device is)")
    lines.append("")
    lines.append("> " + d["limits"])
    lines.append("")
    lines.append("## What to do next")
    for s in d["next_steps"]:
        lines.append("- " + s)
    lines.append("")
    lines.append("## Coverage")
    lines.append("")
    lines.append("| Module | Status | Items | Findings | Notes |")
    lines.append("|---|---|---|---|---|")
    for m in d["modules"]:
        note = m["reason"] or ""
        if m["unsupported_checks"]:
            note = (note + " Unsupported: " + ", ".join(m["unsupported_checks"])).strip()
        lines.append(
            "| " + m["name"] + " | " + m["status"] + " | " + str(m["items_examined"]) + " | " + str(m["findings"]) + " | " + note + " |"
        )
    if d["notes"]:
        lines.append("")
        for n in d["notes"]:
            lines.append("- " + n)
    lines.append("")
    lines.append("## Findings")
    if not d["findings"]:
        lines.append("")
        lines.append(VERDICT_NONE + ". See the limits statement above.")
    for f in d["findings"]:
        lines.append("")
        lines.append("### [" + f["severity"] + "] " + f["title"])
        lines.append("")
        lines.append("- Category: " + f["category"] + ", confidence: " + f["confidence"] + ", module: " + f["module"])
        if f["kit"]:
            lines.append("- Related kit: " + f["kit"])
        if f["cves"]:
            lines.append("- CVEs: " + ", ".join(f["cves"]))
        lines.append("- " + f["description"])
        if f["caveat"]:
            lines.append("- Caveat: " + f["caveat"])
        ev = dict(f["evidence"])
        if redact:
            for k in ("url", "filename", "text"):
                if k in ev:
                    ev[k] = "[redacted]"
        lines.append("- Evidence: `" + json.dumps(ev, default=str)[:600] + "`")
        if f["source"]:
            lines.append("- Source: " + f["source"])
    lines.append("")
    return "\n".join(lines)
