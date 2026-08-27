"""CLI argument handling and output. ``agent`` uses ``--fake`` so no network
or GPU is touched.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soc_triage import cli
from soc_triage.escalation import EscalationPolicy

_ALERT_ROWS = [
    {
        "id": "a1",
        "rule": "ssh_auth_failures",
        "summary": "20 failed logins",
        "hostname": "prod-db-01",
        "indicator": "203.0.113.4",
        "threat_intel_reputation": "known_malicious",
        "recent_alert_count": 20,
        "malicious": True,
        "severity": "critical",
    },
    {
        "id": "a2",
        "rule": "ssh_auth_failures",
        "summary": "2 failed logins",
        "hostname": "dev-vm-03",
        "indicator": "10.0.0.5",
        "threat_intel_reputation": "clean",
        "recent_alert_count": 2,
        "malicious": False,
        "severity": "none",
    },
]


def _write_alerts(path: Path) -> None:
    with path.open("w") as f:
        for row in _ALERT_ROWS:
            f.write(json.dumps(row) + "\n")


def test_baseline_writes_metrics_and_verdicts(tmp_path: Path) -> None:
    data = tmp_path / "alerts.jsonl"
    out = tmp_path / "baseline.json"
    _write_alerts(data)

    cli.main(["baseline", "--data", str(data), "--out", str(out)])

    result = json.loads(out.read_text())
    assert result["source"] == "baseline"
    assert set(result["verdicts"]) == {"a1", "a2"}
    assert "accuracy" in result["metrics"]


def test_agent_fake_mode_writes_metrics_and_verdicts(tmp_path: Path) -> None:
    data = tmp_path / "alerts.jsonl"
    out = tmp_path / "agent.json"
    _write_alerts(data)

    cli.main(["agent", "--data", str(data), "--fake", "--out", str(out)])

    result = json.loads(out.read_text())
    assert result["source"] == "agent"
    assert set(result["verdicts"]) == {"a1", "a2"}
    assert result["failures"] == 0


def test_agent_no_tools_ablation_runs(tmp_path: Path) -> None:
    data = tmp_path / "alerts.jsonl"
    out = tmp_path / "agent-no-tools.json"
    _write_alerts(data)

    cli.main(["agent", "--data", str(data), "--fake", "--no-tools", "--out", str(out)])

    result = json.loads(out.read_text())
    assert result["use_tools"] is False


def test_sweep_reads_a_saved_verdicts_file(tmp_path: Path) -> None:
    data = tmp_path / "alerts.jsonl"
    verdicts_path = tmp_path / "baseline.json"
    out = tmp_path / "sweep.json"
    _write_alerts(data)
    cli.main(["baseline", "--data", str(data), "--out", str(verdicts_path)])

    cli.main(
        [
            "sweep",
            "--verdicts",
            str(verdicts_path),
            "--data",
            str(data),
            "--thresholds",
            "0.3,0.7",
            "--out",
            str(out),
        ]
    )

    result = json.loads(out.read_text())
    assert set(result["sweep"]) == {"0.30", "0.70"}


def test_escalation_policy_flags_override_defaults() -> None:
    args = cli._parse_args(
        [
            "baseline",
            "--confidence-threshold",
            "0.3",
            "--always-escalate-criticality",
            "high",
            "--always-escalate-criticality",
            "medium,low",
        ]
    )

    policy = cli._build_escalation_policy(args)

    assert policy.confidence_threshold == 0.3
    assert policy.always_escalate_criticalities == frozenset({"high", "medium", "low"})


def test_escalation_policy_flags_default_to_the_policy_defaults() -> None:
    args = cli._parse_args(["baseline"])
    default_policy = EscalationPolicy()

    policy = cli._build_escalation_policy(args)

    assert policy.confidence_threshold == default_policy.confidence_threshold
    assert policy.always_escalate_criticalities == default_policy.always_escalate_criticalities


def test_missing_subcommand_exits() -> None:
    with pytest.raises(SystemExit):
        cli.main([])


def test_unknown_subcommand_exits() -> None:
    with pytest.raises(SystemExit):
        cli.main(["nonsense"])
