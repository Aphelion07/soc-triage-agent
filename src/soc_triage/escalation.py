"""The human-in-the-loop policy: a fixed, auditable rule applied to a
verdict, never a judgement call the model gets to make about itself.

Deliberately not "ask the LLM whether it's confident enough to act alone" -
a model asked to grade its own certainty is exactly the failure mode a
human-in-the-loop gate exists to catch. The threshold and the escalation
rules live here as plain arithmetic on the verdict's own reported
confidence and the alert's independently-known facts, so the actual
escalation decision is reviewable without re-running anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .verdict import TriageVerdict
from .world import ASSET_CRITICALITY


@dataclass(frozen=True)
class EscalationPolicy:
    confidence_threshold: float = 0.7
    always_escalate_severities: frozenset[str] = field(
        default_factory=lambda: frozenset({"critical"})
    )
    always_escalate_criticalities: frozenset[str] = field(
        default_factory=lambda: frozenset({"critical"})
    )


def should_escalate(policy: EscalationPolicy, verdict: TriageVerdict, hostname: str) -> bool:
    if verdict.confidence < policy.confidence_threshold:
        return True
    if verdict.malicious and verdict.severity in policy.always_escalate_severities:
        return True
    return ASSET_CRITICALITY.get(hostname) in policy.always_escalate_criticalities
