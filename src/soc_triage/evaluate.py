"""Turns per-alert verdicts and escalation decisions into the numbers this
repo reports: raw classification accuracy, how much gets handled without a
human, and - the metric that actually matters for a triage system - how
often a real incident gets auto-closed as noise.
"""

from __future__ import annotations

from dataclasses import dataclass

from .alerts import Alert
from .escalation import EscalationPolicy, should_escalate
from .verdict import TriageVerdict


@dataclass(frozen=True)
class TriageOutcome:
    alert_id: str
    hostname: str
    ground_truth_malicious: bool
    verdict: TriageVerdict
    escalated: bool


@dataclass(frozen=True)
class TriageMetrics:
    n: int
    accuracy: float
    automation_rate: float
    missed_incident_rate: float
    false_escalation_rate: float


def outcomes_for_policy(
    alerts: list[Alert], verdicts: dict[str, TriageVerdict], policy: EscalationPolicy
) -> list[TriageOutcome]:
    return [
        TriageOutcome(
            alert_id=alert.id,
            hostname=alert.hostname,
            ground_truth_malicious=alert.malicious,
            verdict=verdicts[alert.id],
            escalated=should_escalate(policy, verdicts[alert.id], alert.hostname),
        )
        for alert in alerts
    ]


def compute_metrics(outcomes: list[TriageOutcome]) -> TriageMetrics:
    n = len(outcomes)
    if n == 0:
        return TriageMetrics(
            n=0,
            accuracy=0.0,
            automation_rate=0.0,
            missed_incident_rate=0.0,
            false_escalation_rate=0.0,
        )

    correct = sum(1 for o in outcomes if o.verdict.malicious == o.ground_truth_malicious)
    not_escalated = sum(1 for o in outcomes if not o.escalated)

    malicious = [o for o in outcomes if o.ground_truth_malicious]
    # The dangerous failure: a real incident that both got called benign
    # AND wasn't escalated, so no human ever saw it either.
    missed = [o for o in malicious if not o.escalated and not o.verdict.malicious]

    benign = [o for o in outcomes if not o.ground_truth_malicious]
    false_escalations = [o for o in benign if o.escalated]

    return TriageMetrics(
        n=n,
        accuracy=correct / n,
        automation_rate=not_escalated / n,
        missed_incident_rate=(len(missed) / len(malicious)) if malicious else 0.0,
        false_escalation_rate=(len(false_escalations) / len(benign)) if benign else 0.0,
    )


def sweep_thresholds(
    alerts: list[Alert], verdicts: dict[str, TriageVerdict], thresholds: list[float]
) -> dict[float, TriageMetrics]:
    """Verdicts are produced once; the threshold only changes which of them
    get escalated, so this is pure post-processing - no need to re-run the
    triage source for every point on the curve.
    """
    results: dict[float, TriageMetrics] = {}
    for threshold in thresholds:
        policy = EscalationPolicy(confidence_threshold=threshold)
        outcomes = outcomes_for_policy(alerts, verdicts, policy)
        results[threshold] = compute_metrics(outcomes)
    return results
