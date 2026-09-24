"""DeepAgents live-scan panels (terminal_ui.render_deep_*).

The oracle's own plan()/decide() output is rendered as ATTACK PLAN and
VERDICT panels so a `cx deep` run shows, step by step, each agent's
hypotheses (payload · endpoint · severity) and the verdict on each probe.
These pin what must appear and that it degrades on a legacy terminal.
"""
import re

from rich.console import Console

import terminal_ui as tu
from backend.deepagents.oracle_attack import (
    AttackPlan, Decision, Hypothesis, HttpRequest,
)

_SGR = re.compile(r"\x1b\[[0-9;]*m")


def _capture(fn, *a, **k):
    old = tu.soc
    tu.soc = Console(record=True, width=100, theme=tu.HUD_THEME)
    try:
        fn(*a, **k)
        return _SGR.sub("", tu.soc.export_text())
    finally:
        tu.soc = old


def _plan():
    hyps = [
        Hypothesis("h1", "Time-Based SQLi", "CWE-89", "Critical",
                   HttpRequest("GET", "/api/orders/lookup?email=", "", {}, "' OR SLEEP(5)--"), "", ""),
        Hypothesis("h2", "Union-Based SQLi", "CWE-89", "High",
                   HttpRequest("GET", "/api/orders/lookup?email=", "", {}, "' UNION SELECT pw--"), "", ""),
    ]
    return AttackPlan("Targeting /api/orders/lookup for SQLi.", "SQLi", hyps,
                      model="qwen2.5-coder:7b", strategy="Standard")


def test_attack_plan_shows_payload_endpoint_and_severity():
    out = _capture(tu.render_attack_plan, "DeepSQLiAgent", _plan(), 75719)
    assert "DeepSQLiAgent" in out and "ATTACK PLAN" in out
    assert "Hypotheses (2 generated)" in out
    assert "Time-Based SQLi" in out                    # technique
    assert "/api/orders/lookup?email=" in out          # endpoint
    assert "' OR SLEEP(5)--" in out                     # the actual payload fired
    assert "Critical" in out and "High" in out          # severity per hypothesis
    assert "qwen2.5-coder:7b" in out                     # which model planned it


def test_verdict_confirmed_shows_decision_evidence_and_next_probe():
    d = Decision("confirmed", "response time >> baseline with SLEEP payload", 85,
                 {"evidence": "5.2s vs 0.4s baseline"},
                 HttpRequest("GET", "/api/orders/lookup?email=", "", {}, "' UNION SELECT NULL--"),
                 model="llama3.1:8b", strategy="Chain-Of-Thought")
    out = _capture(tu.render_deep_verdict, "DeepSQLiAgent", d, 47431)
    assert "VERDICT" in out and "CONFIRMED" in out and "85%" in out
    assert "5.2s vs 0.4s baseline" in out               # evidence
    assert "UNION SELECT NULL" in out                    # next probe
    assert "llama3.1:8b" in out


def test_verdict_abandoned_hides_evidence_and_next_probe():
    d = Decision("abandoned", "normal response, not vulnerable", 90)
    out = _capture(tu.render_deep_verdict, "DeepXSSAgent", d, 100)
    assert "ABANDONED" in out and "normal response" in out
    assert "Evidence" not in out and "Next probe" not in out


def test_thinking_and_attempt_lines():
    out = _capture(tu.render_deep_thinking, "DeepAuthAgent", "planner", "probe the login flow")
    assert "DeepAuthAgent" in out and "planner thinking" in out and "probe the login flow" in out
    out = _capture(tu.render_deep_attempt, "h1", 2, "confirmed", 85, "sql error surfaced")
    assert "[h1]" in out and "attempt 2" in out and "confirmed" in out and "85%" in out


def test_panels_degrade_on_a_legacy_terminal(monkeypatch):
    monkeypatch.setattr(tu, "_ascii_mode", lambda console=None: True)
    out = _capture(tu.render_attack_plan, "DeepSQLiAgent", _plan(), 1)
    assert "🗺" not in out and "→" not in out and "·" not in out   # no non-ASCII glyphs
    assert "->" in out and "ATTACK PLAN" in out                      # ASCII arrow, still readable


def _agents(*names):
    return [type(n, (object,), {})() for n in names]


def test_parallel_group_panels_list_agents_and_counts():
    groups = [_agents("DeepSQLiAgent", "DeepXSSAgent", "DeepAuthAgent"),
              _agents("DeepCMDiAgent")]
    plan = _capture(tu.render_deepagents_plan, groups, 13)
    assert "DEEPAGENTS ATTACK PLAN" in plan
    assert "13 agents active" in plan and "2 parallel groups" in plan
    assert "Group 1: DeepSQLiAgent, DeepXSSAgent, DeepAuthAgent" in plan
    grp = _capture(tu.render_deepagents_group, 1, 2, groups[0])
    assert "GROUP 1/2  (parallel)" in grp and "DeepAuthAgent" in grp
    assert "No vulnerabilities found" in _capture(tu.render_deepagents_group_result, 1, 0)
    assert "3 vuln(s) found" in _capture(tu.render_deepagents_group_result, 2, 3)


def test_oracle_per_model_lock_serialises_same_model_inference():
    """Agents in a parallel group share one oracle; its per-model lock must
    keep same-model LLM calls one-at-a-time so local VRAM never thrashes."""
    import asyncio
    import types
    from backend.deepagents.oracle_attack import AttackOracle

    oracle = AttackOracle(types.SimpleNamespace(reasoner=None))
    live = {"n": 0, "peak": 0}

    async def fake_call(model, **k):
        live["n"] += 1
        live["peak"] = max(live["peak"], live["n"])
        await asyncio.sleep(0.02)
        live["n"] -= 1
        return {"target_summary": "t", "primary_vulnerability_class": "x", "hypotheses": []}

    oracle.orchestrator._call = fake_call

    async def main():
        await asyncio.gather(*[oracle.plan("t", "s", "c") for _ in range(4)])

    asyncio.run(main())
    assert live["peak"] == 1
