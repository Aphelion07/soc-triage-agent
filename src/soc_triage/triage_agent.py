"""A purpose-built tool-calling loop for triage - not ``agent-core``'s
``ReActStrategy``.

ReAct's loop is designed to end in free text; a triage system needs to end
in a structured, machine-checkable verdict a policy can act on. This reuses
``agent-core``'s ``LLMBackend``, ``Message``, ``Tool`` and ``ToolRegistry`` -
the reusable plumbing for talking to a model and calling tools, including
its retry-hardened Ollama backend - and writes a small loop around them
that ends by forcing a ``submit_verdict`` tool call instead of parsing
free text out of a final answer.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_core import Message, Tool, ToolRegistry
from agent_core.llm.base import LLMBackend
from pydantic import BaseModel, Field, ValidationError

from .alerts import Alert
from .verdict import TriageVerdict

_WITH_TOOLS_PROMPT = (
    "You are a SOC triage assistant. You will be shown one security alert. "
    "Use the available tools - asset_criticality_lookup, threat_intel_lookup, "
    "alert_history_lookup - to gather context before deciding; do not guess "
    "without checking them first. When you have enough evidence, call "
    "submit_verdict with your decision."
)
_WITHOUT_TOOLS_PROMPT = (
    "You are a SOC triage assistant. You will be shown one security alert. "
    "No additional context tools are available - decide from the alert text "
    "alone. Call submit_verdict with your decision."
)


class VerdictArgs(BaseModel):
    malicious: bool
    severity: str = Field(description="none, low, medium, high, or critical")
    confidence: float = Field(ge=0.0, le=1.0, description="confidence in the malicious call")


def _verdict_tool() -> Tool[VerdictArgs]:
    return Tool(
        name="submit_verdict",
        description="Submit your final triage decision for this alert.",
        parameters=VerdictArgs,
        func=lambda _args: "verdict recorded",
    )


@dataclass(frozen=True)
class TriageRun:
    verdict: TriageVerdict | None  # None if the model never submitted one within budget
    llm_calls: int
    tool_calls: int


def _alert_message(alert: Alert) -> Message:
    return Message(
        role="user",
        content=f"Alert: {alert.summary}\nHostname: {alert.hostname}\nIndicator: {alert.indicator}",
    )


async def triage_alert(
    backend: LLMBackend,
    tools: ToolRegistry,
    alert: Alert,
    max_steps: int = 6,
    use_tools: bool = True,
) -> TriageRun:
    active_tools = tools if use_tools else ToolRegistry([])
    tool_schemas = [*active_tools.schemas(), _verdict_tool().schema()]
    system_prompt = _WITH_TOOLS_PROMPT if use_tools else _WITHOUT_TOOLS_PROMPT

    messages: list[Message] = [Message(role="system", content=system_prompt), _alert_message(alert)]

    llm_calls = 0
    tool_calls = 0
    for _ in range(max_steps):
        response = await backend.chat(messages, tool_schemas)
        llm_calls += 1

        verdict_call = next((c for c in response.tool_calls if c.name == "submit_verdict"), None)
        if verdict_call is not None:
            try:
                args = VerdictArgs.model_validate(verdict_call.arguments)
            except ValidationError:
                return TriageRun(verdict=None, llm_calls=llm_calls, tool_calls=tool_calls)
            severity = args.severity if args.malicious else "none"
            verdict = TriageVerdict(
                malicious=args.malicious, severity=severity, confidence=args.confidence
            )
            return TriageRun(verdict=verdict, llm_calls=llm_calls, tool_calls=tool_calls)

        if not response.tool_calls:
            # The model answered in plain text instead of calling a tool -
            # nudge it back toward submit_verdict rather than failing the
            # whole alert on one formatting slip.
            messages.append(Message(role="assistant", content=response.content))
            messages.append(
                Message(role="user", content="Please call submit_verdict with your decision.")
            )
            continue

        messages.append(
            Message(role="assistant", content=response.content, tool_calls=response.tool_calls)
        )
        for call in response.tool_calls:
            result = await active_tools.call(call.name, call.arguments)
            tool_calls += 1
            messages.append(
                Message(role="tool", content=result.output, tool_call_id=call.id, name=call.name)
            )

    return TriageRun(verdict=None, llm_calls=llm_calls, tool_calls=tool_calls)
