from __future__ import annotations

import dataclasses

import pytest

from soc_triage.verdict import TriageVerdict


def test_fields_are_stored_as_given() -> None:
    verdict = TriageVerdict(malicious=True, severity="high", confidence=0.8)
    assert verdict.malicious is True
    assert verdict.severity == "high"
    assert verdict.confidence == 0.8


def test_is_frozen() -> None:
    verdict = TriageVerdict(malicious=False, severity="none", confidence=0.9)
    with pytest.raises(dataclasses.FrozenInstanceError):
        verdict.malicious = True  # type: ignore[misc]


def test_equality_is_by_value() -> None:
    a = TriageVerdict(malicious=True, severity="critical", confidence=0.5)
    b = TriageVerdict(malicious=True, severity="critical", confidence=0.5)
    c = TriageVerdict(malicious=True, severity="critical", confidence=0.6)
    assert a == b
    assert a != c
