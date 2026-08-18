from __future__ import annotations

import collections

from build_alerts import RULES, build_alerts

from soc_triage.world import ASSET_CRITICALITY


def test_same_seed_is_deterministic() -> None:
    a = build_alerts(seed=0, per_category=5)
    b = build_alerts(seed=0, per_category=5)
    assert [x.summary for x in a] == [x.summary for x in b]


def test_different_seeds_differ() -> None:
    a = build_alerts(seed=0, per_category=5)
    b = build_alerts(seed=1, per_category=5)
    assert [x.summary for x in a] != [x.summary for x in b]


def test_balanced_across_rules_and_malicious_split() -> None:
    alerts = build_alerts(seed=0, per_category=10)
    counts = collections.Counter((a.rule, a.malicious) for a in alerts)
    assert set(r for r, _m in counts) == set(RULES)
    assert all(c == 10 for c in counts.values())


def test_every_hostname_is_a_known_asset() -> None:
    alerts = build_alerts(seed=0, per_category=10)
    assert all(a.hostname in ASSET_CRITICALITY for a in alerts)


def test_malicious_alerts_have_a_real_severity() -> None:
    alerts = build_alerts(seed=0, per_category=10)
    for alert in alerts:
        if alert.malicious:
            assert alert.severity in {"low", "medium", "high", "critical"}
        else:
            assert alert.severity == "none"


def test_benign_alerts_are_always_threat_intel_clean() -> None:
    # A benign look-alike should never itself be flagged malicious by threat
    # intel - that would make the tool actively misleading rather than just
    # incomplete, which is a different (and unrealistic) failure mode.
    alerts = build_alerts(seed=0, per_category=20)
    assert all(a.threat_intel_reputation == "clean" for a in alerts if not a.malicious)


def test_ids_are_unique() -> None:
    alerts = build_alerts(seed=0, per_category=10)
    ids = [a.id for a in alerts]
    assert len(ids) == len(set(ids))
