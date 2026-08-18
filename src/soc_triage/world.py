"""The fixed facts a triage agent can look up but never sees directly.

An alert's own text tells an analyst (or an agent) what fired, not whether
it matters - that depends on what else is true: how critical the host is,
whether the source has a reputation, whether this is an isolated blip or a
sustained pattern. Keeping the asset inventory as a fixed, named pool
(rather than generating it per-alert) makes it a genuine lookup an agent has
to bother calling, not something inferable from the alert text alone.
"""

from __future__ import annotations

ASSET_CRITICALITY: dict[str, str] = {
    "prod-db-01": "critical",
    "prod-db-02": "critical",
    "payment-gateway": "critical",
    "domain-controller": "critical",
    "prod-api-01": "high",
    "prod-api-02": "high",
    "auth-svc": "high",
    "prod-web-01": "high",
    "staging-web-01": "medium",
    "internal-wiki": "medium",
    "build-server": "medium",
    "monitoring-01": "medium",
    "dev-vm-03": "low",
    "test-vm-12": "low",
    "sandbox-01": "low",
    "laptop-jdoe": "low",
}

CRITICALITY_LEVELS = ["critical", "high", "medium", "low"]
