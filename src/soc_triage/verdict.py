"""The shape every triage approach in this repo produces, whether it comes
from fixed rules or from an LLM: a call on whether the alert is real, how
bad it is if so, and how sure the source is of that call. The escalation
policy only ever looks at this - it has no idea whether a verdict came from
``baseline.py`` or ``triage_agent.py``.
"""

from __future__ import annotations

from dataclasses import dataclass

Severity = str  # "none" | "low" | "medium" | "high" | "critical"


@dataclass(frozen=True)
class TriageVerdict:
    malicious: bool
    severity: Severity
    confidence: float  # in [0, 1] - confidence in `malicious`, whichever way it leans
