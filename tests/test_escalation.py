from __future__ import annotations

from soc_triage.escalation import EscalationPolicy, should_escalate
from soc_triage.verdict import TriageVerdict


def test_low_confidence_always_escalates() -> None:
    policy = EscalationPolicy(confidence_threshold=0.7)
    verdict = TriageVerdict(malicious=False, severity="none", confidence=0.5)
    assert should_escalate(policy, verdict, hostname="dev-vm-03") is True


def test_high_confidence_benign_on_a_low_criticality_host_does_not_escalate() -> None:
    policy = EscalationPolicy(confidence_threshold=0.7)
    verdict = TriageVerdict(malicious=False, severity="none", confidence=0.95)
    assert should_escalate(policy, verdict, hostname="dev-vm-03") is False


def test_critical_severity_always_escalates_even_with_high_confidence() -> None:
    policy = EscalationPolicy(confidence_threshold=0.5)
    verdict = TriageVerdict(malicious=True, severity="critical", confidence=0.99)
    assert should_escalate(policy, verdict, hostname="dev-vm-03") is True


def test_high_severity_below_the_always_escalate_set_does_not_force_escalation() -> None:
    policy = EscalationPolicy(confidence_threshold=0.5)
    verdict = TriageVerdict(malicious=True, severity="high", confidence=0.99)
    assert should_escalate(policy, verdict, hostname="dev-vm-03") is False


def test_critical_asset_always_escalates_regardless_of_verdict() -> None:
    policy = EscalationPolicy(confidence_threshold=0.5)
    verdict = TriageVerdict(malicious=False, severity="none", confidence=0.99)
    assert should_escalate(policy, verdict, hostname="prod-db-01") is True


def test_lower_threshold_escalates_less() -> None:
    verdict = TriageVerdict(malicious=False, severity="none", confidence=0.6)
    strict = EscalationPolicy(confidence_threshold=0.8)
    lenient = EscalationPolicy(confidence_threshold=0.3)
    assert should_escalate(strict, verdict, hostname="dev-vm-03") is True
    assert should_escalate(lenient, verdict, hostname="dev-vm-03") is False
