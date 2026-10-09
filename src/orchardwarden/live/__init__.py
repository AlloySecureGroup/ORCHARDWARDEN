"""Sentry mode adapters (live telemetry from a USB attached device).

UNTESTED against real hardware in this prototype. The replay source is what the tests use.
The USB source shells out to pymobiledevice3 if it is installed and the device is paired.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Iterator


def replay_lines(path: Path) -> Iterator[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            yield line.rstrip("\n")


def usb_syslog_lines() -> Iterator[str]:
    exe = shutil.which("pymobiledevice3")
    if not exe:
        raise RuntimeError("pymobiledevice3 is not installed. Install it and pair the device first.")
    proc = subprocess.Popen([exe, "syslog", "live"], stdout=subprocess.PIPE, text=True, errors="replace")
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            yield line.rstrip("\n")
    finally:
        proc.terminate()
