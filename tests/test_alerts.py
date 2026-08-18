from __future__ import annotations

import json
from pathlib import Path

from soc_triage.alerts import load_alerts


def test_round_trips_every_field(tmp_path: Path) -> None:
    row = {
        "id": "a0001",
        "rule": "ssh_auth_failures",
        "summary": "5 failed logins",
        "hostname": "prod-db-01",
        "indicator": "203.0.113.4",
        "threat_intel_reputation": "known_malicious",
        "recent_alert_count": 5,
        "malicious": True,
        "severity": "high",
    }
    path = tmp_path / "alerts.jsonl"
    path.write_text(json.dumps(row) + "\n")

    alerts = load_alerts(path)
    assert len(alerts) == 1
    assert alerts[0].id == "a0001"
    assert alerts[0].malicious is True
    assert alerts[0].recent_alert_count == 5


def test_blank_lines_are_skipped(tmp_path: Path) -> None:
    row = {
        "id": "a0001",
        "rule": "ssh_auth_failures",
        "summary": "x",
        "hostname": "prod-db-01",
        "indicator": "1.2.3.4",
        "threat_intel_reputation": "clean",
        "recent_alert_count": 1,
        "malicious": False,
        "severity": "none",
    }
    path = tmp_path / "alerts.jsonl"
    path.write_text(json.dumps(row) + "\n\n\n")
    assert len(load_alerts(path)) == 1
