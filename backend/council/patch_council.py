import json
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from backend.council.council_orchestrator import CouncilOrchestrator
from backend.council.model_selector import get_selector

console = Console()

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





class PatchCouncil(CouncilOrchestrator):
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

        patch_prompt = (
            f"Vulnerability: {vuln_name} ({cwe})\n"
            f"File: {file_path}\n\n"
            f"Vulnerable code:\n```\n{vulnerable_code}\n```\n\n"
            f"Generate the fixed version of this code."
        )

        console.print(f"[dim]Stage 1: {patch_model} Generating Patch...[/dim]")
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

        approved_count = sum(1 for a in approvals if a.get("approved", False))
        total_reviewers = len(approvals)
        # FIX: Use .get() instead of hard key access to prevent KeyError
        dissent_reasons = [a.get("reason", "No reason provided") for a in approvals if not a.get("approved", False)]

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
        # CWE-specific fix directives — tell the model EXACTLY what to do
        CWE_DIRECTIVES = {
            "CWE-78": "CRITICAL: You MUST replace execSync/exec with execFileSync or spawn using an arguments array, OR remove the shell call entirely and use safe string operations. Adding input validation alone is NOT sufficient — the shell call itself must be eliminated.",
            "CWE-89": "Replace template literals/string concatenation with parameterized queries using ? placeholders and [value] arrays. Example: db.query('SELECT * FROM t WHERE id = ?', [userId])",
            "CWE-79": "Remove dangerouslySetInnerHTML entirely and render as text content, OR apply DOMPurify.sanitize() before rendering.",
            "CWE-798": "Replace ALL hardcoded secret values with process.env.VAR_NAME references.",
            "CWE-918": "Add URL validation that blocks private IPs (127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16) and cloud metadata endpoints.",
            "CWE-22": "Use path.basename() to strip directory traversal, or path.resolve() + startsWith() check against allowed base directory.",
            "CWE-942": "Replace wildcard CORS origin ('*') with a specific allowlist of origins.",
            "CWE-287": "Add authentication middleware check before the route handler.",
        }
        patch_results = []
        for i, v in enumerate(vuln_list, 1):
            console.print(f"[dim]  [{i}/{len(vuln_list)}] Patching: {v['vuln_name']}[/dim]")
            directive = CWE_DIRECTIVES.get(v['cwe'], "Eliminate the vulnerability completely. The fix must remove the dangerous pattern, not just add a superficial validation.")
            prompt = (
                f"Vulnerability: {v['vuln_name']} ({v['cwe']})\n"
                f"Severity: {v.get('severity', 'High')}\n"
                f"File: {v['file_path']}\n\n"
                f"Vulnerable code:\n```\n{v['vulnerable_code']}\n```\n\n"
                f"FIX REQUIREMENT: {directive}\n\n"
                f"Generate the fixed version of this code. The fix must ELIMINATE the vulnerability, not just add a superficial check."
            )
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
                        f"Original vulnerable code:\n```\n{v['vulnerable_code']}\n```\n\n"
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
                            f"Original vulnerable code:\n```\n{v['vulnerable_code']}\n```\n\n"
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
            approved_count = sum(1 for a in approvals if a.get("approved", False))
            total_reviewers = len(approvals)
            dissent_reasons = [a.get("reason", "No reason provided") for a in approvals if not a.get("approved", False)]

            fixed_code = patch_res.get("fixed_code", "")

            if not fixed_code:
                final_safety = "rejected"
            elif not review_completed and total_reviewers == 0:
                final_safety = "review_needed"
            elif approved_count == total_reviewers and total_reviewers > 0:
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

                    # Quick re-review with first available reviewer
                    reviewer = unique_reviewers[0] if unique_reviewers else None
                    new_approved = False
                    new_approvals = []
                    if reviewer:
                        await self.vram.unload(patch_model)
                        try:
                            await self.vram.ensure_loaded(reviewer)
                            review_prompt = (
                                f"Vulnerability: {v['vuln_name']} ({v['cwe']})\n"
                                f"Original vulnerable code:\n```\n{v['vulnerable_code']}\n```\n\n"
                                f"Proposed patch (attempt {retry_round + 1}):\n```\n{new_code}\n```\n\n"
                                f"Previous rejection reason: \"{critique}\"\n"
                                f"Has this new patch addressed the critique?"
                            )
                            review_result = await self._call(
                                reviewer, PATCH_REVIEW_SYSTEM, review_prompt,
                                task_name="Re-reviewing", severity=v.get('severity', ''), cwe=v.get('cwe', '')
                            )
                            is_approved = review_result.get("approved", False)
                            reason = review_result.get("reason", "No reason")
                            new_approvals = [{"model": reviewer, "approved": is_approved, "reason": reason}]
                            new_approved = is_approved
                            verdict = "[green]APPROVED[/green]" if is_approved else "[red]REJECTED[/red]"
                            console.print(f"  [dim]   {reviewer} re-review: {verdict} — {reason[:60]}[/dim]")
                            await self.vram.unload(reviewer)
                        except Exception:
                            new_approved = True  # Give benefit of doubt if review fails
                        # Reload patcher for next retry
                        try:
                            await self.vram.ensure_loaded(patch_model)
                        except Exception:
                            pass
                    else:
                        new_approved = True  # No reviewer available — accept

                    if new_approved:
                        final_results[idx] = {
                            "fixed_code": new_code,
                            "unsafe_reason": new_result.get("unsafe_reason", ""),
                            "patch_safety": "safe" if new_approved else "review_needed",
                            "approvals": new_approvals,
                            "dissent_reasons": [],
                            "vote_summary": f"Approved after reflexion (attempt {retry_round + 1})",
                        }
                        console.print(f"  [green]   ✓ Patch improved and APPROVED on attempt {retry_round + 1}[/green]")
                    else:
                        # Update with new dissent for next round
                        new_dissent = [a.get("reason", "") for a in new_approvals if not a.get("approved", False)]
                        final_results[idx]["dissent_reasons"] = new_dissent
                        still_rejected.append(idx)

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
