from __future__ import annotations

from soc_triage.alerts import Alert
from soc_triage.escalation import EscalationPolicy
from soc_triage.evaluate import (
    TriageOutcome,
    compute_metrics,
    outcomes_for_policy,
    sweep_thresholds,
)
from soc_triage.verdict import TriageVerdict


def _alert(alert_id: str, malicious: bool) -> Alert:
    return Alert(
        id=alert_id,
        rule="ssh_auth_failures",
        summary="s",
        hostname="dev-vm-03",  # low criticality, never force-escalates
        indicator="1.2.3.4",
        threat_intel_reputation="clean",
        recent_alert_count=1,
        malicious=malicious,
        severity="low" if malicious else "none",
    )


class TestWorkedExample:
    """4 alerts, threshold=0.7.

    a1: malicious, verdict correct (malicious, conf .9) -> automated, correct.
    a2: malicious, verdict wrong (benign, conf .9)       -> automated, WRONG + MISSED INCIDENT.
    a3: benign,    verdict correct (benign, conf .9)     -> automated, correct.
    a4: benign,    verdict wrong (malicious, conf .5)    -> conf<.7, escalated -> FALSE ESCALATION.

    accuracy = 2/4 = 0.5
    automation_rate = 3/4 = 0.75   (a1, a2, a3 not escalated)
    missed_incident_rate = 1/2 = 0.5   (of {a1, a2}, only a2 was missed)
    false_escalation_rate = 1/2 = 0.5  (of {a3, a4}, only a4 was escalated)
    """

    def _outcomes(self) -> list[TriageOutcome]:
        alerts = [_alert("a1", True), _alert("a2", True), _alert("a3", False), _alert("a4", False)]
        verdicts = {
            "a1": TriageVerdict(malicious=True, severity="low", confidence=0.9),
            "a2": TriageVerdict(malicious=False, severity="none", confidence=0.9),
            "a3": TriageVerdict(malicious=False, severity="none", confidence=0.9),
            "a4": TriageVerdict(malicious=True, severity="low", confidence=0.5),
        }
        policy = EscalationPolicy(confidence_threshold=0.7)
        return outcomes_for_policy(alerts, verdicts, policy)

    def test_metrics_match_the_worked_example(self) -> None:
        metrics = compute_metrics(self._outcomes())
        assert metrics.n == 4
        assert metrics.accuracy == 0.5
        assert metrics.automation_rate == 0.75
        assert metrics.missed_incident_rate == 0.5
        assert metrics.false_escalation_rate == 0.5


def test_compute_metrics_of_empty_outcomes_is_all_zero() -> None:
    metrics = compute_metrics([])
    assert metrics.n == 0
    assert metrics.accuracy == 0.0
    assert metrics.automation_rate == 0.0
    assert metrics.missed_incident_rate == 0.0
    assert metrics.false_escalation_rate == 0.0


def test_sweep_only_changes_which_alerts_escalate_not_the_verdicts() -> None:
    alerts = [_alert("a1", True), _alert("a2", True), _alert("a3", False), _alert("a4", False)]
    verdicts = {
        "a1": TriageVerdict(malicious=True, severity="low", confidence=0.9),
        "a2": TriageVerdict(malicious=False, severity="none", confidence=0.9),
        "a3": TriageVerdict(malicious=False, severity="none", confidence=0.9),
        "a4": TriageVerdict(malicious=True, severity="low", confidence=0.5),
    }
    results = sweep_thresholds(alerts, verdicts, [0.7, 0.4])

    # At 0.7, a4 (confidence .5) escalates - the worked example above.
    assert results[0.7].false_escalation_rate == 0.5

    # At 0.4, a4's confidence now clears the bar, so it no longer escalates
    # - accuracy is untouched (the verdict itself never changed), but the
    # false-escalation rate drops because fewer benign alerts get flagged.
    assert results[0.4].false_escalation_rate == 0.0
    assert results[0.7].accuracy == results[0.4].accuracy
