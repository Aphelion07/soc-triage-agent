"""Three subcommands.

    soc-triage baseline --data data/alerts.jsonl
    soc-triage agent --data data/alerts.jsonl --model qwen3:8b [--no-tools]
    soc-triage sweep --verdicts results/agent.json --data data/alerts.jsonl

``agent`` accepts ``--fake``, which swaps the real Ollama backend for a
scripted one that needs no GPU and no network - what CI's smoke job runs,
to catch a broken triage loop before it costs real GPU time. Verdicts are
saved once per run; ``sweep`` re-scores a saved verdicts file against
different escalation thresholds without touching the model again, since the
threshold only changes which verdicts get escalated, not what they say.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from agent_core.llm.base import LLMBackend, LLMResponse
from agent_core.llm.fake import FakeBackend
from agent_core.llm.ollama import OllamaBackend
from agent_core.messages import Message, ToolCall

from .alerts import load_alerts
from .baseline import triage_baseline
from .escalation import EscalationPolicy
from .evaluate import TriageMetrics, compute_metrics, outcomes_for_policy, sweep_thresholds
from .tools import build_tools
from .triage_agent import triage_alert
from .verdict import TriageVerdict


def _metrics_to_dict(metrics: TriageMetrics) -> dict[str, Any]:
    return {
        "n": metrics.n,
        "accuracy": metrics.accuracy,
        "automation_rate": metrics.automation_rate,
        "missed_incident_rate": metrics.missed_incident_rate,
        "false_escalation_rate": metrics.false_escalation_rate,
    }


def _verdict_to_dict(verdict: TriageVerdict) -> dict[str, Any]:
    return {
        "malicious": verdict.malicious,
        "severity": verdict.severity,
        "confidence": verdict.confidence,
    }


def _print_metrics(metrics: TriageMetrics) -> None:
    print(
        f"accuracy={metrics.accuracy:.3f} automation={metrics.automation_rate:.3f} "
        f"missed_incidents={metrics.missed_incident_rate:.3f} "
        f"false_escalations={metrics.false_escalation_rate:.3f}"
    )


def _write_json(out_path: str, payload: dict[str, Any]) -> None:
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))
    print(f"\nwrote {path}")


def _run_baseline(args: argparse.Namespace) -> None:
    alerts = load_alerts(args.data)
    verdicts = {a.id: triage_baseline(a) for a in alerts}
    policy = EscalationPolicy(confidence_threshold=args.threshold)
    outcomes = outcomes_for_policy(alerts, verdicts, policy)
    metrics = compute_metrics(outcomes)
    _print_metrics(metrics)
    _write_json(
        args.out,
        {
            "source": "baseline",
            "threshold": args.threshold,
            "metrics": _metrics_to_dict(metrics),
            "verdicts": {aid: _verdict_to_dict(v) for aid, v in verdicts.items()},
        },
    )


def _smoke_fake_script(messages: list[Message], tool_schemas: list[dict[str, Any]]) -> LLMResponse:
    """Scripted for ``--fake``: calls one real tool first if any are on
    offer, then submits a verdict - exercises the full loop shape (tool
    call, observation, verdict) without a real model.
    """
    names = {t["function"]["name"] for t in tool_schemas}
    already_used_a_tool = any(m.role == "tool" for m in messages)
    if already_used_a_tool or names == {"submit_verdict"}:
        return LLMResponse(
            tool_calls=[
                ToolCall(
                    id="v",
                    name="submit_verdict",
                    arguments={"malicious": False, "severity": "none", "confidence": 0.9},
                )
            ]
        )
    other = next(n for n in names if n != "submit_verdict")
    args = (
        {"hostname": "prod-web-01"}
        if other == "asset_criticality_lookup"
        else {"indicator": "1.2.3.4"}
    )
    return LLMResponse(tool_calls=[ToolCall(id="t", name=other, arguments=args)])


def _build_backend(args: argparse.Namespace) -> LLMBackend:
    if args.fake:
        return FakeBackend(_smoke_fake_script)
    return OllamaBackend(model=args.model)


async def _run_agent_async(args: argparse.Namespace) -> None:
    alerts = load_alerts(args.data)
    tools = build_tools(alerts)
    backend = _build_backend(args)
    use_tools = not args.no_tools

    verdicts: dict[str, TriageVerdict] = {}
    llm_calls_total = 0
    tool_calls_total = 0
    failures = 0
    try:
        for i, alert in enumerate(alerts):
            run = await triage_alert(
                backend, tools, alert, max_steps=args.max_steps, use_tools=use_tools
            )
            llm_calls_total += run.llm_calls
            tool_calls_total += run.tool_calls
            if run.verdict is None:
                failures += 1
                # A triage that never produced a verdict defaults to zero
                # confidence, which forces escalation at any real threshold
                # - the safe failure mode is "ask a human", not "assume
                # benign because the model ran out of steps."
                verdicts[alert.id] = TriageVerdict(malicious=True, severity="none", confidence=0.0)
            else:
                verdicts[alert.id] = run.verdict
            print(f"[{i + 1}/{len(alerts)}] {alert.id} -> {verdicts[alert.id]}")
    finally:
        await backend.aclose()

    policy = EscalationPolicy(confidence_threshold=args.threshold)
    outcomes = outcomes_for_policy(alerts, verdicts, policy)
    metrics = compute_metrics(outcomes)
    print()
    _print_metrics(metrics)
    print(f"failures={failures} llm_calls={llm_calls_total} tool_calls={tool_calls_total}")

    _write_json(
        args.out,
        {
            "source": "agent",
            "model": args.model,
            "use_tools": use_tools,
            "threshold": args.threshold,
            "failures": failures,
            "llm_calls_total": llm_calls_total,
            "tool_calls_total": tool_calls_total,
            "metrics": _metrics_to_dict(metrics),
            "verdicts": {aid: _verdict_to_dict(v) for aid, v in verdicts.items()},
        },
    )


def _run_agent(args: argparse.Namespace) -> None:
    asyncio.run(_run_agent_async(args))


def _run_sweep(args: argparse.Namespace) -> None:
    alerts = load_alerts(args.data)
    saved = json.loads(Path(args.verdicts).read_text())
    verdicts = {aid: TriageVerdict(**v) for aid, v in saved["verdicts"].items()}
    thresholds = [float(t) for t in args.thresholds.split(",")]

    results = sweep_thresholds(alerts, verdicts, thresholds)
    for threshold, metrics in results.items():
        print(f"threshold={threshold:.2f} ", end="")
        _print_metrics(metrics)

    _write_json(
        args.out,
        {
            "source": saved.get("source"),
            "sweep": {f"{t:.2f}": _metrics_to_dict(m) for t, m in results.items()},
        },
    )


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="soc-triage")
    subparsers = parser.add_subparsers(dest="command", required=True)

    baseline = subparsers.add_parser("baseline", help="Run the rule-based triage baseline.")
    baseline.add_argument("--data", default="data/alerts.jsonl")
    baseline.add_argument("--threshold", type=float, default=0.7)
    baseline.add_argument("--out", default="results/baseline.json")
    baseline.set_defaults(func=_run_baseline)

    agent = subparsers.add_parser("agent", help="Run the LLM triage agent.")
    agent.add_argument("--data", default="data/alerts.jsonl")
    agent.add_argument("--model", default="qwen3:8b")
    agent.add_argument(
        "--no-tools", action="store_true", help="Ablation: decide from alert text alone"
    )
    agent.add_argument("--max-steps", type=int, default=6)
    agent.add_argument("--threshold", type=float, default=0.7)
    agent.add_argument("--fake", action="store_true")
    agent.add_argument("--out", default="results/agent.json")
    agent.set_defaults(func=_run_agent)

    sweep = subparsers.add_parser(
        "sweep", help="Re-score a saved verdicts file at other thresholds."
    )
    sweep.add_argument("--verdicts", required=True)
    sweep.add_argument("--data", default="data/alerts.jsonl")
    sweep.add_argument("--thresholds", default="0.3,0.5,0.7,0.9")
    sweep.add_argument("--out", default="results/sweep.json")
    sweep.set_defaults(func=_run_sweep)

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
