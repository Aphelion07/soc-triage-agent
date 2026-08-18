from __future__ import annotations

import pytest

from soc_triage.alerts import Alert
from soc_triage.baseline import _severity_from_score, score_alert, triage_baseline


def _alert(**overrides: object) -> Alert:
    base: dict[str, object] = {
        "id": "a1",
        "rule": "ssh_auth_failures",
        "summary": "s",
        "hostname": "dev-vm-03",  # low criticality
        "indicator": "1.2.3.4",
        "threat_intel_reputation": "clean",
        "recent_alert_count": 1,
        "malicious": False,
        "severity": "none",
    }
    base.update(overrides)
    return Alert(**base)  # type: ignore[arg-type]


def test_score_is_always_in_zero_one() -> None:
    for reputation in ["known_malicious", "suspicious", "unknown", "clean"]:
        for host in ["prod-db-01", "dev-vm-03"]:
            alert = _alert(
                threat_intel_reputation=reputation, hostname=host, recent_alert_count=500
            )
            assert 0.0 <= score_alert(alert) <= 1.0


def test_known_malicious_on_a_critical_host_scores_high() -> None:
    alert = _alert(
        rule="outbound_beacon",
        hostname="prod-db-01",
        threat_intel_reputation="known_malicious",
        recent_alert_count=40,
    )
    verdict = triage_baseline(alert)
    assert verdict.malicious is True
    assert verdict.severity in {"high", "critical"}


def test_clean_low_volume_on_a_low_criticality_host_scores_low() -> None:
    alert = _alert(
        rule="port_scan_detected",
        hostname="dev-vm-03",
        threat_intel_reputation="clean",
        recent_alert_count=1,
    )
    verdict = triage_baseline(alert)
    assert verdict.malicious is False
    assert verdict.severity == "none"


def test_confidence_reflects_distance_from_the_boundary_not_just_the_verdict() -> None:
    clearly_benign = _alert(threat_intel_reputation="clean", recent_alert_count=0)
    clearly_malicious = _alert(
        rule="outbound_beacon",
        hostname="prod-db-01",
        threat_intel_reputation="known_malicious",
        recent_alert_count=48,
    )
    assert triage_baseline(clearly_benign).confidence > 0.5
    assert triage_baseline(clearly_malicious).confidence > 0.5


def test_more_recent_events_never_decreases_the_score() -> None:
    low_volume = score_alert(_alert(recent_alert_count=1))
    high_volume = score_alert(_alert(recent_alert_count=50))
    assert high_volume >= low_volume


@pytest.mark.parametrize(
    ("score", "expected"),
    [(0.95, "critical"), (0.85, "high"), (0.70, "medium"), (0.50, "low")],
)
def test_severity_bands(score: float, expected: str) -> None:
    assert _severity_from_score(score) == expected
