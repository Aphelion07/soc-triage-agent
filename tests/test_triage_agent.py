from __future__ import annotations

from agent_core import ToolCall, ToolRegistry
from agent_core.llm.base import LLMResponse
from agent_core.llm.fake import FakeBackend
from agent_core.messages import Message

from soc_triage.alerts import Alert
from soc_triage.tools import build_tools
from soc_triage.triage_agent import triage_alert

_ALERT = Alert(
    id="a1",
    rule="ssh_auth_failures",
    summary="20 failed SSH logins for user 'root' from 203.0.113.4 against prod-db-01",
    hostname="prod-db-01",
    indicator="203.0.113.4",
    threat_intel_reputation="known_malicious",
    recent_alert_count=20,
    malicious=True,
    severity="critical",
)


def _tools() -> ToolRegistry:
    return build_tools([_ALERT])


async def test_calls_a_tool_then_submits_a_verdict() -> None:
    backend = FakeBackend(
        [
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        id="1", name="threat_intel_lookup", arguments={"indicator": "203.0.113.4"}
                    )
                ]
            ),
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        id="2",
                        name="submit_verdict",
                        arguments={"malicious": True, "severity": "critical", "confidence": 0.95},
                    )
                ]
            ),
        ]
    )
    run = await triage_alert(backend, _tools(), _ALERT)

    assert run.verdict is not None
    assert run.verdict.malicious is True
    assert run.verdict.severity == "critical"
    assert run.verdict.confidence == 0.95
    assert run.llm_calls == 2
    assert run.tool_calls == 1


async def test_submits_verdict_immediately_without_tools() -> None:
    backend = FakeBackend(
        [
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        id="1",
                        name="submit_verdict",
                        arguments={"malicious": False, "severity": "none", "confidence": 0.8},
                    )
                ]
            )
        ]
    )
    run = await triage_alert(backend, _tools(), _ALERT)
    assert run.verdict is not None
    assert run.llm_calls == 1
    assert run.tool_calls == 0


async def test_use_tools_false_gives_the_model_no_context_tools() -> None:
    seen_tool_names: list[str] = []

    def script(messages: list[Message], tool_schemas: list[dict[str, object]]) -> LLMResponse:
        seen_tool_names.extend(t["function"]["name"] for t in tool_schemas)  # type: ignore[index]
        return LLMResponse(
            tool_calls=[
                ToolCall(
                    id="1",
                    name="submit_verdict",
                    arguments={"malicious": False, "severity": "none", "confidence": 0.6},
                )
            ]
        )

    backend = FakeBackend(script)
    await triage_alert(backend, _tools(), _ALERT, use_tools=False)
    assert seen_tool_names == ["submit_verdict"]


async def test_plain_text_response_is_nudged_back_to_submit_verdict() -> None:
    backend = FakeBackend(
        [
            LLMResponse(content="I think this is probably fine, no need to check further."),
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        id="1",
                        name="submit_verdict",
                        arguments={"malicious": False, "severity": "none", "confidence": 0.7},
                    )
                ]
            ),
        ]
    )
    run = await triage_alert(backend, _tools(), _ALERT)
    assert run.verdict is not None
    assert run.llm_calls == 2


async def test_malformed_verdict_arguments_return_none() -> None:
    backend = FakeBackend(
        [
            LLMResponse(
                tool_calls=[
                    ToolCall(id="1", name="submit_verdict", arguments={"malicious": "not-a-bool"})
                ]
            )
        ]
    )
    run = await triage_alert(backend, _tools(), _ALERT)
    assert run.verdict is None


async def test_exhausting_the_step_budget_returns_none_not_a_default_verdict() -> None:
    def always_call_a_tool(
        messages: list[Message], tool_schemas: list[dict[str, object]]
    ) -> LLMResponse:
        return LLMResponse(
            tool_calls=[ToolCall(id="1", name="threat_intel_lookup", arguments={"indicator": "x"})]
        )

    backend = FakeBackend(always_call_a_tool)
    run = await triage_alert(backend, _tools(), _ALERT, max_steps=3)
    assert run.verdict is None
    assert run.llm_calls == 3
