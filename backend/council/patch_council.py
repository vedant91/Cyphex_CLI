import json
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from backend.council.council_orchestrator import CouncilOrchestrator, is_approved_vote
from backend.council.model_selector import get_selector
from backend.council.reasoning_strategy import select_strategy

try:                      # drag legacy [green]/[red] markup onto the ramp
    from terminal_ui import themed_console as _themed_console
except Exception:         # terminal_ui not importable in this context
    def _themed_console(**kw): return Console(**kw)
console = _themed_console()

# ── Oracle Reasoning System ───────────────────────────────────────────────────
# Called BEFORE patch generation. Same model, same VRAM session — zero extra
# cost. Forces the small model to decompose the problem before generating code,
# which measurably improves patch quality on 6-8B parameter models.
ORACLE_SYSTEM = """
You are CYPHEX Oracle — a vulnerability reasoning engine.
Your ONLY job: analyse a vulnerability and produce a structured decomposition that
a code-generation agent will use to write the fix.

Return ONLY valid JSON with these exact keys:
{
  "thinking": "1-2 sentences of chain-of-thought",
  "attack_vector": "how an attacker exploits this specific code",
  "data_flow": "trace from user-controlled input to the vulnerable sink (e.g. req.query.id → db.query template literal)",
  "minimal_fix": "the exact minimal change that eliminates the vulnerability — be specific about the code pattern, not general advice",
  "avoid": ["list of naive/wrong fixes that would be rejected (e.g. 'commenting out the route')"],
  "confidence": 0.0
}

Be concrete. Reference the actual variable names, function calls, and line patterns from the code.
Never invent CVE IDs. Never use CWE numbers not in: CWE-89,79,78,22,798,306,942,287,284,918,250.
"""

PATCH_GENERATION_SYSTEM = """
You are CYPHEX Patch Agent, a secure code analysis assistant.
RULES:
1. Return ONLY valid JSON: {"unsafe_reason": string, "fixed_code": string, "patch_safety": "safe"|"review_needed"}
2. fixed_code must be a COMPLETE drop-in replacement for the vulnerable snippet provided. It will EXACTLY replace the snippet from start to end.
3. VERY IMPORTANT: You must preserve ALL opening and closing braces, parentheses, and structural blocks present in the original snippet. Do not truncate the code. If the original snippet includes a `try {` block, make sure the `catch` block is fully preserved. Failure to output syntactically valid code will cause a fatal compiler error.
4. Do not add imports unless strictly required, do not restructure, do not rename variables.
5. IMPORTANT: Provide REAL, WORKING code. Never use pseudo-code, comments-as-placeholders, or stubs like "// add auth logic here".
6. unsafe_reason: one sentence explaining why the original code is dangerous.
7. patch_safety = "safe" only if the fix is unambiguous.

ANTI-REGRESSION RULES (CRITICAL — violations will be rejected by reviewers):
8. NEVER remove existing try/catch/finally blocks or error handling.
9. NEVER add new import/require statements in the middle of a function body — only at the top of the file.
10. NEVER delete or comment out a route/handler to "fix" it — guard it behind auth/role checks instead.
11. NEVER add scanner-suppression comments (nosemgrep, eslint-disable, # noqa, @ts-ignore).
12. Preserve the function signature and surrounding control flow exactly.
13. Your fix must be MINIMAL — change only what is needed to eliminate the vulnerability.

ANTI-REGRESSION RULES (violating these gets the patch rejected):
- Never remove existing try/catch blocks or error handling.
- Never add new import/require statements in the MIDDLE of a function. If an import is
  strictly required, assume it already exists at the top of the file.
- Never "fix" a vulnerability by deleting or commenting-out a route, handler, or feature.
  A commented-out line is NOT a valid fix and will be rejected.
- Preserve the function signature, return type, and surrounding control flow.
- SNIPPET INTEGRITY: fixed_code must be a COMPLETE verbatim replacement for ALL lines in
  the "Vulnerable code" block. Never drop, restructure, or omit the first line of the
  snippet (e.g. the route declaration `app.get(...)` or function signature `def foo():`
  or class definition). Preserve unchanged context lines exactly as given — only edit
  the minimum lines required to eliminate the vulnerability.
- BRACKET BALANCE: Your fixed_code must have the same net brace depth ({/} balance) as the
  original snippet. If the snippet opens a `{` without closing it (e.g. a route handler
  opening like `app.get('/path', (req, res) => {`), your replacement must also leave that
  brace open — the handler body continues beyond the snippet boundary. Never add a
  closing `}` or `});` that wasn't in the original snippet.

VULNERABILITY-SPECIFIC FIX PATTERNS (use these):
- SQL Injection: Replace template literals with parameterized queries using ? placeholders and [value] arrays.
- XSS: Remove dangerouslySetInnerHTML entirely. Render content as text children: <h3>{a.title}</h3> instead of dangerouslySetInnerHTML={{__html: a.title}}.
- Hardcoded Secrets: Replace literal values with ${ENV_VAR} references. Example: MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}
- Sensitive Data Exposure (debug routes): Guard the route behind an admin role check (e.g., requireAdmin middleware). Do NOT comment it out.
- SSRF: Add URL validation blocking private IPs (127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16) and metadata endpoints.
- IDOR: Use parameterized queries with ownership check: WHERE id = ? AND user_id = ?
- Container as Root: Add USER node before CMD.
- Debug UI routes/nav: Guard with admin role check middleware. Do NOT remove or comment out.

CRITICAL: Your fix must ELIMINATE the vulnerability, not just add a superficial check. The fix will be reviewed by other AI models — incomplete patches will be rejected.
"""

PATCH_REVIEW_SYSTEM = """
You are a senior security code reviewer.
You will receive: the vulnerability type, the original vulnerable code, and a proposed patch.
RULES:
1. Return ONLY valid JSON: {"approved": true/false, "reason": "one sentence max 30 words"}
2. APPROVE (approved=true) if the patch meaningfully reduces or eliminates the attack surface:
   - SQL Injection: Approve if template literals are replaced with parameterized queries (? placeholders).
   - XSS: Approve if dangerouslySetInnerHTML is removed OR input is escaped/sanitized.
   - Hardcoded Secrets: Approve if literal secrets are replaced with environment variable references (${VAR}).
   - Sensitive Data Exposure: Approve if the debug route is auth-gated or removed.
   - SSRF: Approve if URL validation/allowlisting is added.
   - IDOR: Approve if ownership checks or parameterized queries are added.
   - Container as Root: Approve if USER directive is added before CMD.
3. REJECT (approved=false) if ANY of these are true:
   - The patch does NOT address the vulnerability at all (no meaningful change).
   - The patch introduces a WORSE vulnerability than the original.
   - The patch contains placeholder comments instead of real code.
   - The patch REMOVES existing error handling (try/catch/finally blocks).
   - The patch adds scanner-suppression comments (nosemgrep, eslint-disable, # noqa, @ts-ignore).
   - The patch changes MORE code than necessary (blast radius too large).
4. Do NOT reject patches for minor style issues or incomplete edge cases.
   Focus ONLY on whether the core vulnerability is fixed without introducing regressions.
"""



# CWE-specific fix directives — the sharp, deterministic instruction that tells
# the model EXACTLY what a real fix looks like ("eliminate execSync entirely",
# "use parameterized queries", ...). Rendered by _build_patch_prompt from the
# vuln's cwe, so EVERY generation path (batch + single) gets it. Previously this
# lived inline in generate_and_validate_batch and was silently discarded when the
# prompt was rebuilt via _build_patch_prompt — so the directive never reached the
# model and patches were weaker than intended.
CWE_DIRECTIVES = {
    "CWE-78": "CRITICAL: You MUST replace execSync/exec with execFileSync or spawn using an arguments array, OR remove the shell call entirely and use safe string operations. Adding input validation alone is NOT sufficient — the shell call itself must be eliminated.",
    "CWE-89": "Replace template literals/string concatenation with parameterized queries using ? placeholders and [value] arrays. Example: db.query('SELECT * FROM t WHERE id = ?', [userId])",
    "CWE-79": "Remove dangerouslySetInnerHTML entirely and render as text content, OR apply DOMPurify.sanitize() before rendering.",
    "CWE-798": "Replace ALL hardcoded secret values with process.env.VAR_NAME references.",
    "CWE-918": "Add URL validation that blocks private IPs (127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16) and cloud metadata endpoints.",
    "CWE-22": "Use path.basename() to strip directory traversal, or path.resolve() + startsWith() check against allowed base directory.",
    "CWE-942": "Replace wildcard CORS origin ('*') with a specific allowlist of origins.",
    "CWE-287": "Add authentication middleware check before the route handler.",
    "CWE-352": "Add anti-CSRF protection: require and validate a per-session CSRF token (e.g. csurf middleware or a double-submit cookie) on state-changing routes. Do NOT add, remove, or rename unrelated routes or handlers — only harden the existing one.",
}
_GENERIC_DIRECTIVE = ("Eliminate the vulnerability completely. The fix must remove the dangerous "
                      "pattern, not just add a superficial validation.")


def _build_patch_prompt(vuln_dict: dict) -> str:
    """
    Build the Stage-1 patch generation prompt from a vuln_dict.

    Required keys: vuln_name (or vuln_type), cwe, file_path, vulnerable_code.
    Optional keys: oracle_analysis, memory_hint, severity.

    Returns the full prompt string to pass to the LLM.
    """
    vuln_name = vuln_dict.get("vuln_name") or vuln_dict.get("vuln_type", "Unknown Vulnerability")
    cwe = vuln_dict.get("cwe", "")
    file_path = vuln_dict.get("file_path", "")
    vulnerable_code = vuln_dict.get("vulnerable_code", "")
    context = vuln_dict.get("context", "")
    memory_hint = vuln_dict.get("memory_hint", "")
    oracle = vuln_dict.get("oracle_analysis")
    directive = CWE_DIRECTIVES.get(cwe, _GENERIC_DIRECTIVE)

    parts = [
        f"Vulnerability: {vuln_name} ({cwe})",
        f"File: {file_path}",
        "",
    ]

    # Read-only surrounding context (imports, enclosing function, KB recipe,
    # repo secure pattern). The model must NOT reproduce or return this — it is
    # only here so the fix is written correctly for the exact window below.
    if context:
        parts.append("READ-ONLY CONTEXT (do NOT include this in your output):")
        parts.append(f"```\n{context}\n```")
        parts.append("")

    parts.append(
        "Vulnerable code — REPLACE ONLY THESE LINES. Return a drop-in replacement "
        "for exactly this block, preserving its net brace/paren balance (if it "
        "opens a brace and does not close it, your replacement must do the same):"
    )
    parts.append(f"```\n{vulnerable_code}\n```")
    parts.append("")

    parts.append(f"FIX REQUIREMENT: {directive}")
    parts.append("")

    if oracle:
        thinking = oracle.get("thinking", "")
        data_flow = oracle.get("data_flow", "")
        minimal_fix = oracle.get("minimal_fix", "")
        avoid = oracle.get("avoid", [])
        if thinking or data_flow or minimal_fix:
            parts.append("ORACLE ANALYSIS (use this reasoning to guide your fix):")
            if thinking:
                parts.append(f"  Thinking: {thinking}")
            if data_flow:
                parts.append(f"  Data flow: {data_flow}")
            if minimal_fix:
                parts.append(f"  Minimal fix required: {minimal_fix}")
            if avoid:
                parts.append(f"  Do NOT do: {'; '.join(avoid)}")
            parts.append("")

    if memory_hint:
        parts.append(memory_hint)
        parts.append("")

    parts.append(
        "Generate the fixed version of the 'Vulnerable code' block ONLY. "
        "Return a drop-in replacement for exactly those lines — do NOT include the "
        "read-only context, and preserve the snippet's net brace/paren balance. "
        "The fix must ELIMINATE the vulnerability, not just add a superficial check."
    )

    return "\n".join(parts)


class PatchCouncil(CouncilOrchestrator):

    async def _oracle_reason(self, model: str, vuln: dict) -> dict:
        """
        Oracle reasoning step: ask the already-loaded patcher model to decompose
        the vulnerability BEFORE generating the patch.

        Uses the same loaded model — no extra VRAM cost.
        Returns a dict with keys: attack_vector, data_flow, minimal_fix, avoid, confidence.
        Returns {} silently on any failure so patch generation still proceeds.
        """
        try:
            oracle_prompt = _build_oracle_prompt(vuln)
            raw = await self._call(model, ORACLE_SYSTEM, oracle_prompt, task_name="Oracle Reasoning")
            # Surface the oracle reasoning for user visibility
            av  = raw.get("attack_vector", "")
            df  = raw.get("data_flow", "")
            mf  = raw.get("minimal_fix", "")
            conf = raw.get("confidence", 0.0)
            thinking = raw.get("thinking", "")
            from rich.table import Table
            from rich.box import SIMPLE
            t = Table(box=SIMPLE, show_header=False, padding=(0, 1))
            t.add_column("k", style="dim cyan", no_wrap=True)
            t.add_column("v", style="white")
            if thinking: t.add_row("thinking",      thinking[:120])
            if av:       t.add_row("attack_vector", av[:120])
            if df:       t.add_row("data_flow",     df[:120])
            if mf:       t.add_row("minimal_fix",   mf[:160])
            avoid = raw.get("avoid") or []
            if avoid:    t.add_row("avoid",         "; ".join(avoid[:2])[:120])
            t.add_row("confidence", f"{conf:.2f}")
            console.print(Panel(t, title=f"[yellow bold]⚙ Oracle Analysis[/yellow bold]  [dim]{vuln.get('vuln_name','')}[/dim]", border_style="yellow"))
            return raw
        except Exception:
            return {}

    @staticmethod
    def _fingerprint_patch(code: str) -> str:
        """Normalise a candidate for majority voting (ignore whitespace noise)."""
        return "\n".join(line.strip() for line in (code or "").splitlines() if line.strip())

    async def _self_consistent_patch(self, model: str, vuln: dict, prompt: str, k: int = 3) -> dict:
        """
        Self-Consistency: generate K candidate patches at raised temperature and
        keep the one the majority agree on (by normalised fingerprint). Ties break
        toward the candidate flagged patch_safety='safe'. Falls back gracefully to
        the first non-empty candidate. Reuses the already-loaded model — the only
        cost is K forward passes, no extra VRAM.
        """
        candidates: list[dict] = []
        for i in range(k):
            temp = 0.15 + 0.20 * i  # 0.15, 0.35, 0.55 — diversify without going incoherent
            try:
                res = await self._call(model, PATCH_GENERATION_SYSTEM, prompt,
                                       task_name=f"Patch Candidate {i + 1}/{k}", temperature=temp)
                if res.get("fixed_code", "").strip():
                    candidates.append(res)
            except Exception:
                continue

        if not candidates:
            return {"fixed_code": "", "unsafe_reason": "All candidates failed"}

        # Majority vote by fingerprint
        buckets: dict[str, list[dict]] = {}
        for c in candidates:
            buckets.setdefault(self._fingerprint_patch(c.get("fixed_code", "")), []).append(c)

        best_fp = max(buckets, key=lambda fp: (
            len(buckets[fp]),
            any(c.get("patch_safety") == "safe" for c in buckets[fp]),
        ))
        winner = buckets[best_fp][0]
        agree = len(buckets[best_fp])

        console.print(
            f"[dim]  🗳️  Self-Consistency: {len(candidates)} candidates → "
            f"[/dim][cyan]{agree}/{len(candidates)} agreed[/cyan]"
            + ("" if len(buckets) == 1 else f" [dim]({len(buckets)} distinct)[/dim]")
        )
        winner = dict(winner)
        winner["self_consistency"] = {"candidates": len(candidates), "agreed": agree, "distinct": len(buckets)}
        return winner

    async def generate_and_validate_patch(
        self,
        vuln_name: str,
        cwe: str,
        vulnerable_code: str,
        file_path: str
    ) -> dict:
        """
        Dynamically selects models:
          - Patcher: best coding model (generates the fix)
          - Reviewers: 2 distinct models (validate the fix)

        Returns patch result dict with keys:
          fixed_code, unsafe_reason, patch_safety, approvals, dissent_reasons
        """
        console.print(f"\n[bold magenta]Patching Vulnerability:[/bold magenta] {vuln_name}")

        # Dynamically discover best models
        selector = await get_selector(quiet=True)
        self.vram.update_costs(selector.get_vram_costs())

        patch_model = selector.get("patcher")
        reviewer_models = selector.get_reviewers(count=2)

        console.print(f"[dim]  Patcher:   {patch_model}[/dim]")
        console.print(f"[dim]  Reviewers: {', '.join(reviewer_models)}[/dim]")

        # Stage 1: Unload everything, load patcher
        for model in list(self.vram.loaded.keys()):
            await self.vram.unload(model)

        try:
            await self.vram.ensure_loaded(patch_model)
        except Exception:
            # Fallback to any available model THAT ISN'T the one that just failed
            fallback_candidates = [m for m in selector.models if m.name != patch_model]
            if fallback_candidates:
                patch_model = fallback_candidates[0].name
            elif selector.models:
                patch_model = selector.models[0].name  # Only option
            else:
                return {"fixed_code": "", "patch_safety": "rejected",
                        "unsafe_reason": "No models available", "dissent_reasons": ["No Ollama models"]}
            console.print(f"[yellow]⚠ Patcher failed. Using {patch_model}.[/yellow]")
            try:
                await self.vram.ensure_loaded(patch_model)
            except Exception:
                return {"fixed_code": "", "patch_safety": "rejected",
                        "unsafe_reason": "No models available", "dissent_reasons": ["All models failed to load"]}

        vuln_dict = {
            "vuln_name": vuln_name,
            "cwe": cwe,
            "file_path": file_path,
            "vulnerable_code": vulnerable_code,
        }

        # ── Oracle: decompose before generating ──
        console.print(f"[dim]Stage 0: Oracle reasoning ({patch_model})...[/dim]")
        oracle = await self._oracle_reason(patch_model, vuln_dict)
        if oracle:
            vuln_dict["oracle_analysis"] = oracle

        patch_prompt = _build_patch_prompt(vuln_dict)

        console.print(f"[dim]Stage 1: {patch_model} Generating Patch...[/dim]")
        strat = select_strategy(cwe, vuln_dict.get("severity", ""))
        console.print(f"[dim]  Strategy: {strat.icon} {strat.name} ({strat.calls})[/dim]")
        try:
            patch_result = await self._call(patch_model, PATCH_GENERATION_SYSTEM, patch_prompt, task_name="Generating", severity="Critical", cwe=cwe)
        except Exception as e:
            console.print(f"[red]Error generating patch: {e}[/red]")
            return {"fixed_code": "", "patch_safety": "rejected", "unsafe_reason": "Error", "dissent_reasons": ["Generation failed"]}

        fixed_code = patch_result.get("fixed_code", "")

        # Display the generated code
        lang = "javascript" if file_path.endswith((".js", ".jsx")) else "python" if file_path.endswith(".py") else "php" if file_path.endswith(".php") else "python"
        console.print(Panel(Syntax(fixed_code, lang, theme="monokai", line_numbers=True), title=f"[{patch_model}] Generated Fix", border_style="green"))

        # Stage 2: Unload patcher, reload reviewers
        console.print(f"[dim]Stage 2: {' & '.join(reviewer_models)} Validating Patch...[/dim]")
        await self.vram.unload(patch_model)

        review_prompt = (
            f"Vulnerability: {vuln_name} ({cwe})\n\n"
            f"Original vulnerable code:\n```\n{vulnerable_code}\n```\n\n"
            f"Proposed patch:\n```\n{fixed_code}\n```"
        )

        approvals = []
        for model in reviewer_models:
            try:
                await self.vram.ensure_loaded(model)
                review = await self._call(model, PATCH_REVIEW_SYSTEM, review_prompt, task_name="Reviewing", severity="Critical", cwe=cwe)
                approvals.append({"model": model, **review})
            except Exception as e:
                console.print(f"[red]Error from {model}: {e}[/red]")
                approvals.append({"model": model, "approved": False, "reason": "Error during call"})

        approved_count = sum(1 for a in approvals if is_approved_vote(a.get("approved")))
        total_reviewers = len(approvals)
        # FIX: Use .get() instead of hard key access to prevent KeyError
        dissent_reasons = [a.get("reason", "No reason provided") for a in approvals if not is_approved_vote(a.get("approved"))]

        if approved_count == total_reviewers:
            final_safety = "safe"
            c = "green"
        elif approved_count >= 1:
            final_safety = "review_needed"
            c = "yellow"
        else:
            final_safety = "rejected"
            c = "red"

        console.print(f"[bold {c}]Patch Validation Result: {final_safety.upper()}[/bold {c}]")

        return {
            "fixed_code": fixed_code,
            "unsafe_reason": patch_result.get("unsafe_reason", ""),
            "patch_safety": final_safety,
            "approvals": approvals,
            "dissent_reasons": dissent_reasons,
            "vote_summary": f"{approved_count}/{total_reviewers} validators approved"
        }

    async def generate_and_validate_batch(self, vuln_list: list[dict]) -> list[dict]:
        """
        Agent-Centric Batching with Patch Cache:
        - Loads each model ONCE and processes ALL vulnerabilities before swapping.
        - Stage 1 patches are CACHED so they survive review-stage crashes.
        - If reviews crash, cached patches are returned with 'review_needed' status
          instead of being thrown away and regenerated from scratch.

        vuln_list: list of dicts with keys: vuln_name, cwe, vulnerable_code, file_path
        Returns: list of patch result dicts (same format as generate_and_validate_patch)
        """
        if not vuln_list:
            return []

        console.print(f"\n[bold magenta]═══ Batch Patch Mode: {len(vuln_list)} vulnerabilities ═══[/bold magenta]")

        from backend.council.reasoning_strategy import render_engine_banner
        render_engine_banner(console)

        # Discover models — uses intelligent resource-aware brain
        selector = await get_selector(quiet=True)
        self.vram.update_costs(selector.get_vram_costs())
        patch_model = selector.get("patcher")
        reviewer_models = selector.get_reviewers(count=2)  # Resource-aware: returns 1 or 2

        console.print(f"[dim]  Patcher:   {patch_model}[/dim]")
        console.print(f"[dim]  Reviewers: {', '.join(reviewer_models)} ({selector.strategy})[/dim]")

        # ── Stage 1: Load patcher ONCE, generate ALL patches ──
        console.print(f"\n[bold cyan]Stage 1/3: Generating {len(vuln_list)} patches ({patch_model})[/bold cyan]")
        for model in list(self.vram.loaded.keys()):
            await self.vram.unload(model)

        try:
            await self.vram.ensure_loaded(patch_model)
        except Exception:
            # Fallback to any available model THAT ISN'T the one that just failed
            fallback_candidates = [m for m in selector.models if m.name != patch_model]
            if fallback_candidates:
                patch_model = fallback_candidates[0].name
            elif selector.models:
                patch_model = selector.models[0].name  # Only option
            else:
                return [{"fixed_code": "", "patch_safety": "rejected",
                         "unsafe_reason": "No models available"} for _ in vuln_list]
            console.print(f"[yellow]⚠ Patcher failed. Using {patch_model}.[/yellow]")
            try:
                await self.vram.ensure_loaded(patch_model)
            except Exception:
                return [{"fixed_code": "", "patch_safety": "rejected",
                         "unsafe_reason": "All models failed to load"} for _ in vuln_list]

        # ── PATCH CACHE: these results survive even if reviews crash ──
        # The full prompt (CWE directive + KB/context + memory hint + oracle
        # analysis) is assembled by _build_patch_prompt below — the directive is
        # derived from the vuln's cwe there, so it always reaches the model.
        patch_results = []
        for i, v in enumerate(vuln_list, 1):
            console.print(f"[dim]  [{i}/{len(vuln_list)}] Patching: {v['vuln_name']}[/dim]")
            # ── Oracle: decompose the problem before generating the patch ──
            oracle = await self._oracle_reason(patch_model, v)
            if oracle:
                v = dict(v)  # don't mutate the caller's dict
                v["oracle_analysis"] = oracle
            prompt = _build_patch_prompt(v)
            try:
                result = await self._call(patch_model, PATCH_GENERATION_SYSTEM, prompt, task_name="Generating", severity=v.get('severity', ''), cwe=v.get('cwe', ''))
                patch_results.append(result)
            except Exception as e:
                console.print(f"[red]  Error: {e}[/red]")
                patch_results.append({"fixed_code": "", "unsafe_reason": "Generation failed"})

        # ── Stage 2 & 3: Reviews — PARALLEL if hardware allows, sequential otherwise ──
        # This is wrapped in try/except so review crashes DON'T lose Stage 1 patches
        await self.vram.unload(patch_model)

        all_approvals = [[] for _ in vuln_list]  # per-vuln approval lists
        review_completed = False

        # Use the selector's strategy decision — no redundant VRAM checks
        unique_reviewers = list(dict.fromkeys(reviewer_models))  # deduplicate, preserve order
        can_parallel = (
            len(unique_reviewers) >= 2
            and selector.parallel_review_enabled
        )

        try:
            if can_parallel:
                # ── PARALLEL REVIEW: Both reviewers loaded at once ──
                console.print(f"\n[bold cyan]Stage 2/2: Parallel review — {' & '.join(unique_reviewers[:2])} (both loaded)[/bold cyan]")
                console.print(f"[dim]  ⚡ Parallel mode: {self.vram.VRAM_LIMIT:.0f}GB VRAM budget allows dual-model execution[/dim]")

                # Load both reviewers simultaneously
                await self.vram.ensure_loaded_together(unique_reviewers[:2])

                # For each vulnerability, run BOTH reviews concurrently
                for i, (v, patch_res) in enumerate(zip(vuln_list, patch_results)):
                    fixed_code = patch_res.get("fixed_code", "")
                    if not fixed_code:
                        for reviewer in unique_reviewers[:2]:
                            all_approvals[i].append({"model": reviewer, "approved": False, "reason": "No code to review"})
                        continue

                    review_prompt = (
                        f"Vulnerability: {v['vuln_name']} ({v['cwe']})\n\n"
                        + (f"Surrounding code context (read-only — the patch integrates with this; do NOT flag symbols defined here as missing):\n```\n{v['context']}\n```\n\n" if v.get('context') else "")
                        + f"Original vulnerable code:\n```\n{v['vulnerable_code']}\n```\n\n"
                        f"Proposed patch:\n```\n{fixed_code}\n```"
                    )

                    # Fire both reviews simultaneously with asyncio.gather
                    async def _review_one(reviewer_model, prompt):
                        try:
                            review = await self._call(
                                reviewer_model, PATCH_REVIEW_SYSTEM, prompt,
                                task_name="Reviewing", severity=v.get('severity', ''), cwe=v.get('cwe', '')
                            )
                            return {"model": reviewer_model, **review}
                        except Exception as e:
                            return {"model": reviewer_model, "approved": False, "reason": f"Error: {str(e)[:40]}"}

                    import asyncio
                    results = await asyncio.gather(
                        _review_one(unique_reviewers[0], review_prompt),
                        _review_one(unique_reviewers[1], review_prompt),
                    )
                    for r in results:
                        all_approvals[i].append(r)

                # Unload both reviewers
                for reviewer in unique_reviewers[:2]:
                    await self.vram.unload(reviewer)

            else:
                # ── SEQUENTIAL REVIEW: One reviewer at a time (original flow) ──
                for r_idx, reviewer in enumerate(unique_reviewers, 2):
                    console.print(f"\n[bold cyan]Stage {r_idx}/3: Reviewing ALL patches ({reviewer})[/bold cyan]")
                    try:
                        await self.vram.ensure_loaded(reviewer)
                    except Exception:
                        console.print(f"[yellow]⚠ Could not load {reviewer}, skipping.[/yellow]")
                        for approvals in all_approvals:
                            approvals.append({"model": reviewer, "approved": False, "reason": "Model load failed"})
                        continue

                    for i, (v, patch_res) in enumerate(zip(vuln_list, patch_results)):
                        fixed_code = patch_res.get("fixed_code", "")
                        if not fixed_code:
                            all_approvals[i].append({"model": reviewer, "approved": False, "reason": "No code to review"})
                            continue

                        review_prompt = (
                            f"Vulnerability: {v['vuln_name']} ({v['cwe']})\n\n"
                            + (f"Surrounding code context (read-only — the patch integrates with this; do NOT flag symbols defined here as missing):\n```\n{v['context']}\n```\n\n" if v.get('context') else "")
                            + f"Original vulnerable code:\n```\n{v['vulnerable_code']}\n```\n\n"
                            f"Proposed patch:\n```\n{fixed_code}\n```"
                        )
                        try:
                            review = await self._call(reviewer, PATCH_REVIEW_SYSTEM, review_prompt, task_name="Reviewing", severity=v.get('severity', ''), cwe=v.get('cwe', ''))
                            all_approvals[i].append({"model": reviewer, **review})
                        except Exception as e:
                            all_approvals[i].append({"model": reviewer, "approved": False, "reason": f"Error: {str(e)[:40]}"})

                    await self.vram.unload(reviewer)

            review_completed = True

        except Exception as review_error:
            console.print(f"[yellow]⚠ Review stage error: {str(review_error)[:80]}[/yellow]")
            console.print(f"[cyan]  → Using cached patches from Stage 1 (no regeneration needed)[/cyan]")

        # ── Assemble final results ──
        final_results = []
        for i, patch_res in enumerate(patch_results):
            approvals = all_approvals[i] if i < len(all_approvals) else []

            # Safe key access — use .get() to prevent KeyError on missing 'reason'
            approved_count = sum(1 for a in approvals if is_approved_vote(a.get("approved")))
            total_reviewers = len(approvals)
            dissent_reasons = [a.get("reason", "No reason provided") for a in approvals if not is_approved_vote(a.get("approved"))]

            fixed_code = patch_res.get("fixed_code", "")

            if not fixed_code:
                final_safety = "rejected"
            elif not review_completed and total_reviewers == 0:
                final_safety = "review_needed"
            elif (approved_count == total_reviewers and total_reviewers > 0
                  and set(a.get("model") for a in approvals) != {patch_model}):
                # Unanimous approval from at least one INDEPENDENT reviewer.
                # On single-model hardware get_reviewers falls back to [patcher],
                # so the reviewer set == {patch_model}; that is self-review, not
                # validation — fall through to "review_needed" instead of "safe".
                final_safety = "safe"
            elif approved_count >= 1:
                final_safety = "review_needed"
            elif total_reviewers == 0:
                final_safety = "review_needed"
            else:
                final_safety = "rejected"

            final_results.append({
                "fixed_code": fixed_code,
                "unsafe_reason": patch_res.get("unsafe_reason", ""),
                "patch_safety": final_safety,
                "approvals": approvals,
                "dissent_reasons": dissent_reasons,
                "vote_summary": f"{approved_count}/{total_reviewers} validators approved" if total_reviewers > 0 else "Unreviewed (cached from Stage 1)"
            })

        # ══════════════════════════════════════════════════════════════
        # REFLEXION LOOP: Retry rejected patches with critique feedback
        # ══════════════════════════════════════════════════════════════
        MAX_REFLEXION_RETRIES = 2
        rejected_indices = [
            i for i, r in enumerate(final_results)
            if r["patch_safety"] == "rejected" and r.get("dissent_reasons")
        ]

        if rejected_indices and review_completed:
            console.print(Panel(
                f"[bold]🔄 {len(rejected_indices)} patch(es) rejected by council — entering Reflexion Loop[/bold]\n"
                f"[dim]Max {MAX_REFLEXION_RETRIES} retries per vuln. Reviewer critique is injected into the prompt.[/dim]",
                title="◈ REFLEXION LOOP", border_style="bright_yellow", padding=(1, 2)
            ))

            # Load patcher for retries
            for model in list(self.vram.loaded.keys()):
                await self.vram.unload(model)
            try:
                await self.vram.ensure_loaded(patch_model)
            except Exception:
                console.print("[yellow]⚠ Could not load patcher for reflexion — skipping retries[/yellow]")
                rejected_indices = []

            for retry_round in range(1, MAX_REFLEXION_RETRIES + 1):
                if not rejected_indices:
                    break

                console.print(f"\n[bold yellow]  Reflexion Round {retry_round}/{MAX_REFLEXION_RETRIES} — {len(rejected_indices)} patch(es) to retry[/bold yellow]")

                still_rejected = []
                for idx in rejected_indices:
                    v = vuln_list[idx]
                    prev_result = final_results[idx]
                    critique = "; ".join(prev_result.get("dissent_reasons", ["Patch was rejected"]))

                    console.print(f"  [dim]🔄 [{idx+1}] Retrying: {v['vuln_name']}[/dim]")
                    console.print(f"  [dim]   Critique: \"{critique[:100]}\"[/dim]")

                    directive = CWE_DIRECTIVES.get(v['cwe'], "Eliminate the vulnerability completely.")
                    retry_prompt = (
                        f"Vulnerability: {v['vuln_name']} ({v['cwe']})\n"
                        f"Severity: {v.get('severity', 'High')}\n"
                        f"File: {v['file_path']}\n\n"
                        f"Vulnerable code:\n```\n{v['vulnerable_code']}\n```\n\n"
                        f"PREVIOUS ATTEMPT WAS REJECTED by code reviewers.\n"
                        f"Reviewer critique: \"{critique}\"\n\n"
                        f"FIX REQUIREMENT: {directive}\n\n"
                        f"You MUST address the reviewer critique above and generate a DIFFERENT, BETTER fix.\n"
                        f"The fix must ELIMINATE the vulnerability — not just add superficial validation."
                    )

                    try:
                        new_result = await self._call(
                            patch_model, PATCH_GENERATION_SYSTEM, retry_prompt,
                            task_name="Reflexion", severity=v.get('severity', ''), cwe=v.get('cwe', '')
                        )
                    except Exception as e:
                        console.print(f"  [red]   Retry error: {e}[/red]")
                        still_rejected.append(idx)
                        continue

                    new_code = new_result.get("fixed_code", "")
                    if not new_code:
                        still_rejected.append(idx)
                        continue

                    # Re-review using the SAME reviewer set/quorum as the original
                    # council pass (not a single reviewer) — FAIL CLOSED: an error
                    # or a missing reviewer must never promote the patch to "safe".
                    new_approvals = []
                    if unique_reviewers:
                        await self.vram.unload(patch_model)
                        review_prompt = (
                            f"Vulnerability: {v['vuln_name']} ({v['cwe']})\n"
                            + (f"Surrounding code context (read-only — the patch integrates with this; do NOT flag symbols defined here as missing):\n```\n{v['context']}\n```\n\n" if v.get('context') else "")
                            + f"Original vulnerable code:\n```\n{v['vulnerable_code']}\n```\n\n"
                            f"Proposed patch (attempt {retry_round + 1}):\n```\n{new_code}\n```\n\n"
                            f"Previous rejection reason: \"{critique}\"\n"
                            f"Has this new patch addressed the critique?"
                        )
                        for reviewer in unique_reviewers:
                            try:
                                await self.vram.ensure_loaded(reviewer)
                                review_result = await self._call(
                                    reviewer, PATCH_REVIEW_SYSTEM, review_prompt,
                                    task_name="Re-reviewing", severity=v.get('severity', ''), cwe=v.get('cwe', '')
                                )
                                is_approved = is_approved_vote(review_result.get("approved"))
                                reason = review_result.get("reason", "No reason")
                                new_approvals.append({"model": reviewer, "approved": is_approved, "reason": reason})
                                verdict = "[green]APPROVED[/green]" if is_approved else "[red]REJECTED[/red]"
                                console.print(f"  [dim]   {reviewer} re-review: {verdict} — {str(reason)[:60]}[/dim]")
                                await self.vram.unload(reviewer)
                            except Exception as e:
                                # FAIL CLOSED: an errored re-review counts as NOT
                                # approved — never as an automatic pass.
                                console.print(f"  [red]   {reviewer} re-review error: {str(e)[:60]} — counted as NOT approved[/red]")
                                new_approvals.append({"model": reviewer, "approved": False, "reason": f"Error during re-review: {str(e)[:60]}"})
                        # Reload patcher for next retry
                        try:
                            await self.vram.ensure_loaded(patch_model)
                        except Exception:
                            pass
                    else:
                        # FAIL CLOSED: no reviewer available — do NOT auto-accept.
                        console.print("  [yellow]   No reviewer available for re-review — cannot promote to safe (fail closed)[/yellow]")

                    approved_count = sum(1 for a in new_approvals if is_approved_vote(a.get("approved")))
                    total_reviewers = len(new_approvals)

                    if total_reviewers == 0:
                        # Nobody actually reviewed this attempt — surface it for
                        # human review, never mark it "safe" on faith.
                        new_safety = "review_needed"
                    elif approved_count == total_reviewers:
                        new_safety = "safe"
                    elif approved_count >= 1:
                        new_safety = "review_needed"
                    else:
                        new_safety = "rejected"

                    new_dissent = [a.get("reason", "") for a in new_approvals if not is_approved_vote(a.get("approved"))]

                    if new_safety == "rejected":
                        # Still fully rejected — keep the previously-reviewed code
                        # on file, just refresh the critique for the next round.
                        final_results[idx]["dissent_reasons"] = new_dissent
                        final_results[idx]["approvals"] = new_approvals
                        still_rejected.append(idx)
                    else:
                        final_results[idx] = {
                            "fixed_code": new_code,
                            "unsafe_reason": new_result.get("unsafe_reason", ""),
                            "patch_safety": new_safety,
                            "approvals": new_approvals,
                            "dissent_reasons": new_dissent,
                            "vote_summary": (
                                f"Approved after reflexion (attempt {retry_round + 1})"
                                if new_safety == "safe" else
                                f"{approved_count}/{total_reviewers} validators approved after reflexion (attempt {retry_round + 1})"
                                if total_reviewers else
                                f"Unreviewed candidate after reflexion (attempt {retry_round + 1}) — no reviewer available"
                            ),
                        }
                        if new_safety == "safe":
                            console.print(f"  [green]   ✓ Patch improved and APPROVED on attempt {retry_round + 1}[/green]")
                        else:
                            console.print(f"  [yellow]   Patch improved to REVIEW_NEEDED on attempt {retry_round + 1}[/yellow]")

                rejected_indices = still_rejected

            # Summary
            improved = len([i for i, r in enumerate(final_results) if "reflexion" in r.get("vote_summary", "").lower()])
            if improved:
                console.print(f"\n[bold green]  ✓ Reflexion improved {improved} patch(es)[/bold green]")
            else:
                console.print(f"\n[dim]  Reflexion could not improve remaining patches[/dim]")

        mode_label = "parallel" if can_parallel else "sequential"
        console.print(f"\n[bold green]═══ Batch complete: {len(final_results)} patches ({mode_label} review) ═══[/bold green]")
        return final_results
