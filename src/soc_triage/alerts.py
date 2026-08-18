"""Loads the labelled alert dataset ``data/build_alerts.py`` writes out."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Alert:
    id: str
    rule: str
    summary: str
    hostname: str
    indicator: str
    threat_intel_reputation: str
    recent_alert_count: int
    malicious: bool
    severity: str


def load_alerts(path: str | Path) -> list[Alert]:
    alerts: list[Alert] = []
    with Path(path).open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            alerts.append(Alert(**row))
    return alerts
