"""A fixed-rule triage score: the baseline that asks whether an LLM is even
necessary here, using exactly the same facts the LLM agent has to call
tools to get - a base risk per detection rule, threat-intel reputation,
asset criticality, and recent event volume - combined with fixed weights
instead of judgement.
"""

from __future__ import annotations

from .alerts import Alert
from .verdict import TriageVerdict
from .world import ASSET_CRITICALITY

_RULE_BASE_RISK: dict[str, float] = {
    "ssh_auth_failures": 0.30,
    "sql_injection_pattern": 0.40,
    "xss_pattern_waf": 0.35,
    "port_scan_detected": 0.25,
    "outbound_beacon": 0.45,
}

_REPUTATION_WEIGHT: dict[str, float] = {
    "known_malicious": 0.45,
    "suspicious": 0.20,
    "unknown": 0.0,
    "clean": -0.35,
}

_CRITICALITY_WEIGHT: dict[str, float] = {
    "critical": 0.15,
    "high": 0.08,
    "medium": 0.0,
    "low": -0.05,
}


def score_alert(alert: Alert) -> float:
    """A risk score in [0, 1]. 0.5 is the malicious/benign decision
    boundary - see ``triage_baseline`` for how that becomes a verdict.
    """
    score = _RULE_BASE_RISK[alert.rule]
    score += _REPUTATION_WEIGHT.get(alert.threat_intel_reputation, 0.0)
    criticality = ASSET_CRITICALITY.get(alert.hostname, "medium")
    score += _CRITICALITY_WEIGHT.get(criticality, 0.0)
    # Event volume as a saturating signal - a burst matters, but the 200th
    # event in it doesn't matter 200x more than the first.
    score += min(0.25, alert.recent_alert_count / 100)
    return max(0.0, min(1.0, score))


def _severity_from_score(score: float) -> str:
    if score >= 0.90:
        return "critical"
    if score >= 0.80:
        return "high"
    if score >= 0.65:
        return "medium"
    return "low"


def triage_baseline(alert: Alert) -> TriageVerdict:
    score = score_alert(alert)
    malicious = score >= 0.5
    confidence = score if malicious else (1.0 - score)
    severity = _severity_from_score(score) if malicious else "none"
    return TriageVerdict(malicious=malicious, severity=severity, confidence=confidence)
