"""The three tools a triage agent can call - and the reason it has to call
them: none of this is in an alert's own summary text.

Built from the alert set being evaluated rather than hardcoded, since
``threat_intel_lookup`` and ``alert_history_lookup`` need to answer for
whatever indicator a given alert actually carries. ``asset_criticality_lookup``
is the exception - it reads the fixed inventory in ``world.py`` directly,
because a real asset inventory doesn't depend on which alerts happen to be
in front of the agent today.
"""

from __future__ import annotations

from agent_core import Tool, ToolRegistry
from pydantic import BaseModel

from .alerts import Alert
from .world import ASSET_CRITICALITY


class HostnameArgs(BaseModel):
    hostname: str


class IndicatorArgs(BaseModel):
    indicator: str


def _asset_criticality_tool() -> Tool[HostnameArgs]:
    def lookup(args: HostnameArgs) -> str:
        tier = ASSET_CRITICALITY.get(args.hostname)
        if tier is None:
            return f"unknown host '{args.hostname}': not in the asset inventory"
        return f"{args.hostname}: criticality={tier}"

    return Tool(
        name="asset_criticality_lookup",
        description="Look up how critical a hostname is: critical, high, medium, or low.",
        parameters=HostnameArgs,
        func=lookup,
    )


def _threat_intel_tool(reputation_by_indicator: dict[str, str]) -> Tool[IndicatorArgs]:
    def lookup(args: IndicatorArgs) -> str:
        reputation = reputation_by_indicator.get(args.indicator, "unknown")
        return f"{args.indicator}: reputation={reputation}"

    return Tool(
        name="threat_intel_lookup",
        description=(
            "Check an IP or domain against threat intelligence. Returns one of "
            "known_malicious, suspicious, clean, or unknown - unknown means no "
            "data, not that it's safe."
        ),
        parameters=IndicatorArgs,
        func=lookup,
    )


def _alert_history_tool(count_by_indicator: dict[str, int]) -> Tool[IndicatorArgs]:
    def lookup(args: IndicatorArgs) -> str:
        count = count_by_indicator.get(args.indicator)
        if count is None:
            return f"{args.indicator}: no recent history"
        return f"{args.indicator}: {count} related events in the last 24h"

    return Tool(
        name="alert_history_lookup",
        description="Look up how many related events this indicator has triggered recently.",
        parameters=IndicatorArgs,
        func=lookup,
    )


def build_tools(alerts: list[Alert]) -> ToolRegistry:
    reputation_by_indicator = {a.indicator: a.threat_intel_reputation for a in alerts}
    count_by_indicator = {a.indicator: a.recent_alert_count for a in alerts}
    return ToolRegistry(
        [
            _asset_criticality_tool(),
            _threat_intel_tool(reputation_by_indicator),
            _alert_history_tool(count_by_indicator),
        ]
    )
