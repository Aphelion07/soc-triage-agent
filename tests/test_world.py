from __future__ import annotations

from soc_triage.world import ASSET_CRITICALITY, CRITICALITY_LEVELS


def test_every_asset_criticality_is_a_known_level() -> None:
    assert all(level in CRITICALITY_LEVELS for level in ASSET_CRITICALITY.values())


def test_criticality_levels_are_unique_and_ordered_most_severe_first() -> None:
    assert len(CRITICALITY_LEVELS) == len(set(CRITICALITY_LEVELS))
    assert CRITICALITY_LEVELS[0] == "critical"
    assert CRITICALITY_LEVELS[-1] == "low"


def test_hostnames_are_unique() -> None:
    hostnames = list(ASSET_CRITICALITY.keys())
    assert len(hostnames) == len(set(hostnames))


def test_at_least_one_asset_per_criticality_level() -> None:
    levels_present = {criticality for criticality in ASSET_CRITICALITY.values()}
    assert levels_present == set(CRITICALITY_LEVELS)
