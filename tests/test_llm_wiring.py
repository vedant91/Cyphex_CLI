"""Hosted-LLM wiring in the council. Two guarantees:
  1. No hosted LLM configured -> behaviour is exactly as before (local Ollama).
  2. One configured (env or /llm) -> calls route to it and never touch Ollama.
No network: the provider's chat() is replaced by a recorder."""
import asyncio
import types

from backend import llm_provider as p
from backend.council.council_orchestrator import CouncilOrchestrator, VRAMManager
from backend.council.model_selector import ModelSelector

KEY = "sk-test-1234567890"
JSON = '{"confirmed": true, "thinking": "ok"}'


def _local(monkeypatch, tmp_path):
    """No hosted LLM anywhere: the default install."""
    for k in ("CYPHEX_LLM_BASE_URL", "CYPHEX_LLM_API_KEY", "CYPHEX_LLM_MODEL", "CYPHEX_LLM_EXTRA_MODELS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("CYPHEX_LLM_FILE", str(tmp_path / "none.json"))


def _hosted(monkeypatch, tmp_path, extra=""):
    _local(monkeypatch, tmp_path)
    monkeypatch.setenv("CYPHEX_LLM_BASE_URL", "https://llm.example/v1")
    monkeypatch.setenv("CYPHEX_LLM_API_KEY", KEY)
    monkeypatch.setenv("CYPHEX_LLM_MODEL", "big")
    if extra:
        monkeypatch.setenv("CYPHEX_LLM_EXTRA_MODELS", extra)


def _recorder(monkeypatch, reply=JSON):
    calls = []

    async def fake_chat(system, prompt, temperature=0.1, json_mode=True, timeout=120, model=None):
        calls.append({"system": system, "prompt": prompt, "model": model})
        return reply

    monkeypatch.setattr(p, "chat", fake_chat)
    return calls


# ── 1. default behaviour is unchanged ────────────────────────────────────

def test_default_install_has_no_hosted_llm(monkeypatch, tmp_path):
    _local(monkeypatch, tmp_path)
    assert not p.active()


def test_vram_manager_still_loads_models_the_old_way(monkeypatch, tmp_path):
    _local(monkeypatch, tmp_path)
    warmed = []

    async def fake_raw_call(self, model, prompt, stream=False):
        warmed.append(model)
        return "ok"

    monkeypatch.setattr(VRAMManager, "_raw_call", fake_raw_call)
    vm = VRAMManager()
    assert vm.VRAM_LIMIT < 1e6  # real hardware budget, not the hosted "unlimited"
    asyncio.run(vm.ensure_loaded("qwen2.5-coder:7b"))
    assert warmed == ["qwen2.5-coder:7b"] and "qwen2.5-coder:7b" in vm.loaded


def test_model_selector_still_asks_ollama(monkeypatch, tmp_path):
    _local(monkeypatch, tmp_path)
    asked = []

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            asked.append(url)
            return types.SimpleNamespace(json=lambda: {"models": [
                {"name": "qwen2.5-coder:7b", "size": 4_500_000_000, "details": {"parameter_size": "7B"}}]})

    monkeypatch.setattr("backend.council.model_selector.httpx.AsyncClient", lambda **k: FakeClient())
    sel = ModelSelector()
    assert asyncio.run(sel.discover(quiet=True))
    assert asked == ["http://localhost:11434/api/tags"] and sel.get("patcher") == "qwen2.5-coder:7b"


def test_oracle_plan_still_uses_the_reasoner_not_the_orchestrator(monkeypatch, tmp_path):
    """No hosted LLM: AttackOracle on this branch routes through self.reasoner (CyphexReasoner,
    optionally the agent-reasoning package), NOT through CouncilOrchestrator — untouched by /llm."""
    from backend.deepagents import oracle_attack
    from backend.deepagents.oracle_attack import AttackOracle
    _local(monkeypatch, tmp_path)
    monkeypatch.setattr(oracle_attack, "_MODEL_CACHE", ["qwen2.5-coder:7b"])

    seen = {}

    def no_orchestrator_call(*a, **k):
        raise AssertionError("no hosted LLM: must not route through CouncilOrchestrator._call")

    monkeypatch.setattr(CouncilOrchestrator, "_call", no_orchestrator_call)
    oracle = AttackOracle(CouncilOrchestrator())

    class FakeReasoner:
        def generate(self, model, prompt, **kw):
            seen["model"] = model
            return types.SimpleNamespace(
                response='{"target_summary": "s", "primary_vulnerability_class": "SQLi", "hypotheses": []}',
                strategy_name="Decomposition", strategy="decomposed", duration_ms=1)

    oracle.reasoner = FakeReasoner()
    plan = asyncio.run(oracle.plan("http://x", "surface", "SQLi"))
    assert plan.target_summary == "s" and seen["model"] == "qwen2.5-coder:7b"


# ── 2. with a hosted LLM configured, everything routes to it ─────────────

def test_vram_manager_does_not_load_anything_for_a_hosted_llm(monkeypatch, tmp_path):
    _hosted(monkeypatch, tmp_path)

    async def must_not_run(self, *a, **k):
        raise AssertionError("Ollama warm-up must not run for a hosted LLM")

    monkeypatch.setattr(VRAMManager, "_raw_call", must_not_run)
    vm = VRAMManager()
    asyncio.run(vm.ensure_loaded("big"))
    asyncio.run(vm.ensure_loaded_together(["big", "reviewer"]))
    asyncio.run(vm.unload("big"))
    assert vm.loaded == {} and vm.VRAM_LIMIT == 1e6 and vm.parallel_capable


def test_council_call_goes_to_the_hosted_llm_not_ollama(monkeypatch, tmp_path):
    _hosted(monkeypatch, tmp_path)
    calls = _recorder(monkeypatch)

    def no_ollama(*a, **k):
        raise AssertionError("Ollama must not be called for a hosted LLM")

    monkeypatch.setattr("backend.council.council_orchestrator.httpx.AsyncClient", no_ollama)
    result = asyncio.run(CouncilOrchestrator()._call("qwen2.5-coder:7b", "system text", "prompt text"))
    assert result["thinking"] == "ok" and len(calls) == 1
    assert "system text" in calls[0]["system"] and calls[0]["prompt"] == "prompt text"
    assert calls[0]["model"] == "qwen2.5-coder:7b"  # the provider ignores names it was not configured with


def test_model_selector_uses_the_configured_models_and_keeps_a_second_opinion(monkeypatch, tmp_path):
    _hosted(monkeypatch, tmp_path, extra="reviewer")
    sel = ModelSelector()
    assert asyncio.run(sel.discover(quiet=True))
    assert [m.name for m in sel.models] == ["big", "reviewer"]
    assert sel.get("validator") != sel.get("detector")  # debate/review keeps two different models


def test_oracle_plan_decide_mutate_all_go_to_the_hosted_llm_not_ollama(monkeypatch, tmp_path):
    """plan/decide/mutate each resolve a different LOCAL Ollama model name (qwen/llama/deepseek),
    but with a hosted LLM configured, CouncilOrchestrator._call() must route every one of them to
    the hosted provider, not Ollama — the provider itself collapses unknown names to the primary."""
    from backend.deepagents import oracle_attack as _oracle_mod
    from backend.deepagents.oracle_attack import AttackOracle, Hypothesis, HttpRequest
    # _resolve_model_for_role() caches role -> model in module globals for the
    # process lifetime (correct for one real scan) — reset them so this
    # assertion isn't at the mercy of whatever an earlier test in the same
    # pytest run already cached for "mutator" etc.
    monkeypatch.setattr(_oracle_mod, "_ROLE_CACHE", {})
    monkeypatch.setattr(_oracle_mod, "_MODEL_CACHE", [])
    _hosted(monkeypatch, tmp_path)
    calls = _recorder(monkeypatch, reply=(
        '{"target_summary": "s", "primary_vulnerability_class": "SQLi", "hypotheses": [], '
        '"action": "confirmed", "thinking": "ok", "variants": ["v1", "v2"]}'))

    def no_ollama(*a, **k):
        raise AssertionError("Ollama must not be called for a hosted LLM")

    monkeypatch.setattr("backend.council.council_orchestrator.httpx.AsyncClient", no_ollama)
    oracle = AttackOracle(CouncilOrchestrator())

    plan = asyncio.run(oracle.plan("http://x", "surface", "SQLi"))
    hyp = Hypothesis("h1", "SQLi", "CWE-89", "High", HttpRequest("GET", "/x"), "ok", "no")
    decision = asyncio.run(oracle.decide(hyp, 200, "body", 0.5, 0))
    variants = asyncio.run(oracle.mutate("' OR 1=1", "SQLi"))

    # _call()'s pre-existing "_sanitize" step flattens a list-of-strings into one \n-joined
    # string — applies identically to a hosted reply as it always did to an Ollama one.
    assert plan.target_summary == "s" and decision.action == "confirmed" and variants == "v1\nv2"
    # planner/analyst/mutator each resolve a different local-Ollama-style name (see _ROLE_PREFERENCES);
    # the provider itself (test_llm_provider.py) proves all 3 collapse to the one configured model.
    assert {c["model"] for c in calls} == {"qwen2.5-coder:7b", "llama3.1:8b", "deepseek-coder:1.3b"}


def test_oracle_on_provider_failure_degrades_like_a_reasoner_timeout_would(monkeypatch, tmp_path):
    """_call_reasoner already catches a timeout and returns None so plan() degrades to an empty
    plan rather than crashing the DeepAgents swarm — a hosted-provider failure must get the same
    resilience, not a different (crashing) failure mode."""
    from backend.deepagents.oracle_attack import AttackOracle
    _hosted(monkeypatch, tmp_path)

    async def boom(*a, **k):
        raise p.ProviderError("HTTP 500")

    monkeypatch.setattr(p, "chat", boom)
    oracle = AttackOracle(CouncilOrchestrator())
    plan = asyncio.run(oracle.plan("http://x", "surface", "SQLi"))  # must not raise
    assert plan.hypotheses == []


def test_classic_agents_use_the_hosted_llm(monkeypatch, tmp_path):
    import pytest
    base_agent = pytest.importorskip("backend.backend.agents.base_agent")
    _hosted(monkeypatch, tmp_path)
    calls = _recorder(monkeypatch, reply="analysis text")

    async def log(*a, **k):
        pass

    agent = types.SimpleNamespace(log=log)
    assert asyncio.run(base_agent.BaseAgent.call_cerebras(agent, "sys", "user")) == "analysis text"
    assert calls[0]["prompt"] == "user"


# ── 3. the /llm slash command ────────────────────────────────────────────

def _run(cx, line):
    import contextlib
    import io
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        cx._handle(line)
    return out.getvalue()


def test_llm_command_connects_saves_and_never_prints_the_key(monkeypatch, tmp_path):
    import cx
    _local(monkeypatch, tmp_path)
    prov = cx._llm_provider()
    monkeypatch.setattr(prov, "check", lambda url, key, model="": {
        "ok": True, "base_url": url, "models": ["my-slm"], "model": model or "my-slm", "reply": "ok"})

    out = _run(cx, f"/llm https://llm.example/v1 {KEY} my-slm")
    assert "Connected" in out and KEY not in out
    assert p.load()["model"] == "my-slm" and p.active()

    status = _run(cx, "/llm")
    assert "Hosted" in status and "my-slm" in status and KEY not in status

    assert "Back to local" in _run(cx, "/llm local") and not p.active()
    assert "Local Ollama" in _run(cx, "/llm")


def test_llm_command_refuses_an_insecure_remote_url(monkeypatch, tmp_path):
    import cx
    _local(monkeypatch, tmp_path)
    out = _run(cx, f"/llm http://api.example.com/v1 {KEY} m")
    assert "https://" in out and KEY not in out and not p.active()