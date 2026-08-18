from __future__ import annotations

from soc_triage.alerts import Alert
from soc_triage.tools import build_tools

_ALERTS = [
    Alert(
        id="a1",
        rule="ssh_auth_failures",
        summary="s",
        hostname="prod-db-01",
        indicator="203.0.113.4",
        threat_intel_reputation="known_malicious",
        recent_alert_count=12,
        malicious=True,
        severity="high",
    ),
    Alert(
        id="a2",
        rule="sql_injection_pattern",
        summary="s",
        hostname="dev-vm-03",
        indicator="10.0.0.5",
        threat_intel_reputation="clean",
        recent_alert_count=1,
        malicious=False,
        severity="none",
    ),
]


async def test_asset_criticality_lookup_known_host() -> None:
    tools = build_tools(_ALERTS)
    result = await tools.call("asset_criticality_lookup", {"hostname": "prod-db-01"})
    assert result.error is False
    assert "critical" in result.output


async def test_asset_criticality_lookup_unknown_host() -> None:
    tools = build_tools(_ALERTS)
    result = await tools.call("asset_criticality_lookup", {"hostname": "nonexistent-host"})
    assert "unknown host" in result.output


async def test_threat_intel_lookup_known_indicator() -> None:
    tools = build_tools(_ALERTS)
    result = await tools.call("threat_intel_lookup", {"indicator": "203.0.113.4"})
    assert "known_malicious" in result.output


async def test_threat_intel_lookup_unlisted_indicator_is_unknown_not_clean() -> None:
    tools = build_tools(_ALERTS)
    result = await tools.call("threat_intel_lookup", {"indicator": "198.51.100.9"})
    assert "unknown" in result.output


async def test_alert_history_lookup_known_indicator() -> None:
    tools = build_tools(_ALERTS)
    result = await tools.call("alert_history_lookup", {"indicator": "203.0.113.4"})
    assert "12" in result.output


async def test_alert_history_lookup_unlisted_indicator() -> None:
    tools = build_tools(_ALERTS)
    result = await tools.call("alert_history_lookup", {"indicator": "198.51.100.9"})
    assert "no recent history" in result.output


def test_registry_exposes_all_three_tools() -> None:
    tools = build_tools(_ALERTS)
    assert set(tools.names()) == {
        "asset_criticality_lookup",
        "threat_intel_lookup",
        "alert_history_lookup",
    }
