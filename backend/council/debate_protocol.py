import json
import time
from rich.console import Console
from backend.council.council_orchestrator import CouncilOrchestrator, is_approved_vote
from backend.council.model_selector import get_selector

try:                      # drag legacy [green]/[red] markup onto the ramp
    from terminal_ui import themed_console as _themed_console
except Exception:         # terminal_ui not importable in this context
    def _themed_console(**kw): return Console(**kw)
console = _themed_console()

VALIDATION_SYSTEM = """
You are a security vulnerability validator on a review council.
You receive: a vulnerability type, the HTTP request sent, and the HTTP response received.

STRICT RULES:
1. Respond ONLY with valid JSON: {"confirmed": true/false, "confidence": 0.0-1.0, "reason": "one sentence max 30 words"}
2. confirmed=true ONLY when the response body contains hard evidence:
   - SQLi: SQL error string present OR response time > 4.5s on SLEEP payload
   - XSS: exact injected payload string appears unescaped in response HTML
   - CMDi: OS command output present (uid=, root, www-data, Directory of)
   - LFI: /etc/passwd content present (root:x:0:0)
   - Auth: auth token/cookie set OR redirect to protected route
   - Missing header: header is absent (always confirmed=true)
3. confirmed=false if evidence is a 500 error alone, a vague change in response, or your suspicion.
4. Never reference CVE numbers. Never guess.
"""

# ── Performance tuning ──────────────────────────────────────────
MAX_DEBATE_VULNS = 5          # Only debate the first N vulns (Critical/High first)
DEBATE_TIMEOUT_TOTAL = 180    # 3 min max for entire debate phase
MIN_MODEL_PARAMS_FOR_DEBATE = 7  # Models need at least 7B params for reliable debate


class DebateProtocol(CouncilOrchestrator):

    async def should_debate(self) -> tuple[bool, str]:
        """
        Check if the installed models are large enough for reliable debate.
        Models <7B produce too many JSON errors and hallucinated rejections,
        which causes REAL vulnerabilities to be discarded.

        Returns: (should_debate: bool, reason: str)
        """
        selector = await get_selector(quiet=True)
        if not selector.models:
            return False, "No Ollama models available"

        max_param = max(m.param_size for m in selector.models)
        if max_param < MIN_MODEL_PARAMS_FOR_DEBATE:
            model_summary = ", ".join(f"{m.name} ({m.param_size}B)" for m in selector.models)
            return False, f"Models too small for reliable debate ({model_summary}). Need ≥7B."

        return True, f"Largest model: {max_param}B — sufficient for debate"

    async def debate_finding(self, vuln_name: str, evidence: str) -> tuple[bool, float, list[dict]]:
        """
        Multi-model debate for false-positive filtering.
        IMPORTANT: Errors/timeouts count as ABSTAIN (not reject).
        Only actual "confirmed: false" votes count as rejection.

        Returns: (confirmed: bool, avg_confidence: float, vote_log: list)
        """
        selector = await get_selector(quiet=True)
        VALIDATORS = selector.get_validators(count=3)
        self.vram.update_costs(selector.get_vram_costs())

        console.print(f"\n[bold cyan]⚡ Debating:[/bold cyan] {vuln_name}")
        console.print(f"[dim]  Council: {' + '.join(set(VALIDATORS))}[/dim]")

        # Load models
        for i, model in enumerate(VALIDATORS):
            try:
                await self.vram.ensure_loaded(model)
            except Exception:
                fallback = selector.models[0].name if selector.models else None
                if fallback:
                    VALIDATORS[i] = fallback
                    try:
                        await self.vram.ensure_loaded(fallback)
                    except Exception:
                        pass

        # Truncate evidence to save tokens
        evidence_trimmed = evidence[:1500] if len(evidence) > 1500 else evidence
        prompt = f"Vulnerability type: {vuln_name}\n\nEvidence (request + response):\n{evidence_trimmed}"

        # Round 1: independent votes
        console.print("[dim]Round 1: Voting...[/dim]")
        votes = []
        for model in VALIDATORS:
            try:
                vote = await self._call(model, VALIDATION_SYSTEM, prompt, task_name="Debate R1")
                votes.append({"model": model, "round": 1, "status": "voted", **vote})
            except Exception as e:
                console.print(f"[yellow]  ⚠ {model}: abstained ({str(e)[:50]})[/yellow]")
                # ABSTAIN — do NOT count as confirmed=false
                votes.append({"model": model, "round": 1, "status": "abstained",
                              "confirmed": None, "confidence": 0.0, "reason": "Error/timeout"})

        # Count only actual votes (not abstentions)
        actual_votes = [v for v in votes if v.get("status") == "voted"]
        abstained = len(votes) - len(actual_votes)
        num_actual = len(actual_votes)
        confirmed_count = sum(1 for v in actual_votes if is_approved_vote(v.get("confirmed")))
        rejected_count = num_actual - confirmed_count

        # If majority abstained → not enough data to reject, KEEP the finding
        if num_actual == 0:
            console.print(f"  [yellow]→ All models abstained — KEEPING finding (no reliable votes)[/yellow]")
            return True, 0.5, votes

        # Early exit: unanimous actual votes
        if num_actual > 0 and (confirmed_count == num_actual or rejected_count == num_actual):
            avg_conf = sum(v.get("confidence", 0.5) for v in actual_votes) / max(num_actual, 1)
            result = confirmed_count == num_actual
            c = "green" if result else "red"
            label = "CONFIRMED" if result else "REJECTED"
            extra = f", {abstained} abstained" if abstained else ""
            console.print(f"  [{c}]→ Unanimous: {label}[/{c}] (conf={avg_conf:.0%}{extra})")
            return result, avg_conf, votes

        # Split vote → for safety, KEEP the finding (conservative approach)
        # Only reject if ALL actual voters say "not confirmed"
        avg_conf = sum(v.get("confidence", 0.5) for v in actual_votes) / max(num_actual, 1)
        if confirmed_count >= 1:
            # At least one model confirmed → keep it
            console.print(f"  [green]→ Split vote ({confirmed_count}/{num_actual} confirmed) — KEEPING finding[/green]")
            return True, avg_conf, votes
        else:
            # All actual voters rejected → reject
            extra = f", {abstained} abstained" if abstained else ""
            console.print(f"  [red]→ All voters rejected ({rejected_count}/{num_actual}{extra}) — REJECTED[/red]")
            return False, avg_conf, votes

    async def debate_batch(self, vulns: list, max_vulns: int = MAX_DEBATE_VULNS) -> list:
        """
        Agent-Centric Batch Debate: loads each validator model ONCE and
        debates ALL vulnerabilities against it before swapping.
        Reduces model swaps from O(N * Validators) to O(Validators).
        """
        if not vulns:
            return []

        # Check if debate is worthwhile with current models
        should_run, reason = await self.should_debate()
        if not should_run:
            console.print(f"[yellow]  ⚡ Council Debate SKIPPED:[/yellow] [dim]{reason}[/dim]")
            console.print(f"[dim]  → Keeping all {len(vulns)} findings (install a 7B+ model for AI false-positive filtering)[/dim]")
            return vulns

        # Sort by severity (critical first)
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        sorted_vulns = sorted(vulns, key=lambda v: severity_order.get(v.severity, 5))

        # Limit the number of vulns to debate
        to_debate = sorted_vulns[:max_vulns]
        auto_keep = sorted_vulns[max_vulns:]

        if auto_keep:
            console.print(f"[dim]  Debating top {len(to_debate)} findings, auto-keeping {len(auto_keep)} lower-priority...[/dim]")

        # ── Agent-Centric Batching: load each validator once ──
        selector = await get_selector(quiet=True)
        VALIDATORS = selector.get_validators(count=3)
        self.vram.update_costs(selector.get_vram_costs())

        console.print(f"[dim]  Council validators: {' + '.join(set(VALIDATORS))}[/dim]")

        unique_validators = list(dict.fromkeys(VALIDATORS))
        validator_batches = self.vram.get_parallel_batches(unique_validators)
        
        console.print(f"[dim]  Running in {len(validator_batches)} batch(es) due to VRAM limits (Limit: {self.vram.VRAM_LIMIT:.0f}GB)[/dim]")

        # Per-vuln vote storage: votes[vuln_idx] = list of vote dicts
        all_votes = [[] for _ in to_debate]
        start = time.time()

        import asyncio

        for batch_idx, batch in enumerate(validator_batches, 1):
            elapsed = time.time() - start
            if elapsed > DEBATE_TIMEOUT_TOTAL:
                console.print(f"[yellow]⏱ Debate timeout ({DEBATE_TIMEOUT_TOTAL}s). Keeping remaining findings.[/yellow]")
                break

            console.print(f"\n[bold cyan]Batch {batch_idx}/{len(validator_batches)}: Parallel debate — {' + '.join(batch)}[/bold cyan]")
            
            # 1. Ensure whole batch is loaded
            await self.vram.ensure_loaded_together(batch)

            # 2. Iterate ALL vulns against this batch of validators
            for v_idx, v in enumerate(to_debate):
                elapsed = time.time() - start
                if elapsed > DEBATE_TIMEOUT_TOTAL:
                    for model in batch:
                        all_votes[v_idx].append({"model": model, "round": 1, "status": "abstained",
                                                 "confirmed": None, "confidence": 0.0, "reason": "Timeout"})
                    continue

                evidence = str(v.evidence) if v.evidence else str(getattr(v, 'payload', ''))
                evidence_trimmed = evidence[:1500] if len(evidence) > 1500 else evidence
                prompt = f"Vulnerability type: {v.name}\n\nEvidence (request + response):\n{evidence_trimmed}"

                # Concurrent execution for all models in this batch for the current vuln
                async def _vote_one(model_name, p):
                    try:
                        vote = await self._call(model_name, VALIDATION_SYSTEM, p, task_name=f"Batch Debate ({model_name})")
                        return {"model": model_name, "round": 1, "status": "voted", **vote}
                    except Exception as e:
                        return {"model": model_name, "round": 1, "status": "abstained",
                                "confirmed": None, "confidence": 0.0, "reason": f"Error: {str(e)[:40]}"}

                tasks = [_vote_one(model, prompt) for model in batch]
                results = await asyncio.gather(*tasks)
                
                for r in results:
                    all_votes[v_idx].append(r)

            # 3. Unload batch before loading next
            for model in batch:
                await self.vram.unload(model)

        # ── Tally votes per vulnerability ──
        validated = list(auto_keep)
        for v_idx, v in enumerate(to_debate):
            votes = all_votes[v_idx]
            actual_votes = [vote for vote in votes if vote.get("status") == "voted"]
            num_actual = len(actual_votes)

            if num_actual == 0:
                console.print(f"  [yellow]→ {v.name}: All abstained — KEEPING[/yellow]")
                validated.append(v)
                continue

            confirmed_count = sum(1 for vote in actual_votes if is_approved_vote(vote.get("confirmed")))

            if confirmed_count >= 1:
                validated.append(v)
                console.print(f"  [green]→ {v.name}: {confirmed_count}/{num_actual} confirmed — KEEPING[/green]")
            else:
                console.print(f"  [red]→ {v.name}: 0/{num_actual} confirmed — REJECTED[/red]")

        return validated

