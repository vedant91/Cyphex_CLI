import json
from rich.console import Console
from backend.council.council_orchestrator import CouncilOrchestrator
from backend.council.model_selector import get_selector

try:                      # drag legacy [green]/[red] markup onto the ramp
    from terminal_ui import themed_console as _themed_console
except Exception:         # terminal_ui not importable in this context
    def _themed_console(**kw): return Console(**kw)
console = _themed_console()

ANALYSIS_SYSTEM = """
You are a security analyst writing a technical report.
You receive a list of confirmed vulnerabilities with their evidence.
RULES:
1. Return ONLY valid JSON array. Each item: {"vuln_name": "...", "root_cause": "...", "attack_scenario": "...", "owasp": "...", "cwe": "...", "risk_level": "...", "business_impact": "..."}
2. Write ONLY about the confirmed vulnerabilities provided. Do not add new findings.
3. attack_scenario: a specific, realistic description of how an attacker would exploit this
   given the actual endpoint and payload evidence. Not generic advice.
4. business_impact: what data or functionality could be compromised. Be specific.
5. risk_level: "Critical" | "High" | "Medium" | "Low" — use CVSS scoring logic.
6. Never reference CVE numbers. CWE only.
7. Never use phrases like "might be vulnerable" or "could potentially". Every statement
   is about a confirmed finding.
"""

ANALYSIS_VALIDATION_SYSTEM = """
You are a technical fact-checker for security reports.
You receive: a list of confirmed findings with evidence, and an analysis report.
Return ONLY valid JSON: {"valid": true/false, "unsupported_claims": ["...", "..."]}

IMPORTANT RULES:
1. valid=true if the report ONLY discusses vulnerabilities that appear in the evidence list.
2. The report is ALLOWED to elaborate on confirmed findings — adding attack scenarios,
   business impact descriptions, and remediation context is expected and valid.
3. Only flag as unsupported_claims if the report INVENTS vulnerabilities not in the evidence
   (e.g., claims a finding exists when the evidence list has no such finding).
4. Do NOT flag elaborations, explanations, or risk assessments of confirmed findings.
5. An empty unsupported_claims list means valid=true.
"""

class AnalysisCouncil(CouncilOrchestrator):
    async def analyse_findings(self, confirmed_vulns: list[dict]) -> list[dict]:
        """
        Uses the patcher model (code specialist) to write security analysis,
        and a different model to cross-check claims.
        Returns the analysis only if validation finds no unsupported claims.
        """
        if not confirmed_vulns:
            return []

        console.print("\n[bold blue]Analysis Council:[/bold blue] Drafting Security Report...")

        # Use patcher model for report (code-aware = better security reports)
        # and a different model for validation (cross-model fact-checking)
        selector = await get_selector(quiet=True)
        self.vram.update_costs(selector.get_vram_costs())

        narrator_model = selector.get("patcher")  # qwen2.5-coder:7b — best for code reports
        # Validator must differ from narrator for cross-checking
        reviewer_candidates = [m.name for m in selector.models if m.name != narrator_model]
        validator_model = reviewer_candidates[0] if reviewer_candidates else narrator_model

        console.print(f"[dim]  Report Writer: {narrator_model}[/dim]")
        console.print(f"[dim]  Validator:     {validator_model}[/dim]")

        # Unload previous models to free VRAM for narrator
        for m in list(self.vram.loaded.keys()):
            await self.vram.unload(m)

        try:
            await self.vram.ensure_loaded(narrator_model)
        except Exception:
            # Fallback to any available model
            if selector.models:
                narrator_model = selector.models[0].name
                console.print(f"[yellow]⚠ Narrator failed. Using {narrator_model}.[/yellow]")
                await self.vram.ensure_loaded(narrator_model)
            else:
                console.print("[red]⚠ No models available for report generation.[/red]")
                return []

        # Create a clean version of the dicts to send to model to save tokens
        clean_vulns = []
        for v in confirmed_vulns:
            clean_vulns.append({
                "name": v.get("name"),
                "severity": v.get("severity"),
                "endpoint": v.get("endpoint"),
                "evidence": v.get("evidence", v.get("payload", ""))
            })

        analysis_prompt = (
            "Confirmed vulnerabilities with evidence:\n"
            + json.dumps(clean_vulns, indent=2)
        )

        try:
            analysis = await self._call(narrator_model, ANALYSIS_SYSTEM, analysis_prompt, task_name="Report Generation")
            if not isinstance(analysis, list):
                if "analysis" in analysis:
                    analysis = analysis["analysis"]
                elif "findings" in analysis:
                    analysis = analysis["findings"]
                else:
                    analysis = [analysis]
        except Exception as e:
            console.print(f"[red]Failed to generate analysis: {e}[/red]")
            return []

        console.print(f"[dim]Report Drafted. {validator_model} validating claims...[/dim]")

        # Validator cross-checks: are any claims unsupported by the evidence?
        cross_model = True
        try:
            await self.vram.ensure_loaded(validator_model)
        except Exception:
            validator_model = narrator_model  # fallback to same model
            cross_model = False  # narrator grading its own report — not independent

        validation_prompt = (
            f"Evidence:\n{json.dumps(clean_vulns, indent=2)}\n\n"
            f"Analysis to validate:\n{json.dumps(analysis, indent=2)}"
        )

        try:
            validation = await self._call(validator_model, ANALYSIS_VALIDATION_SYSTEM, validation_prompt, task_name="Report Validation")
        except Exception as e:
            console.print(f"[red]Validation failed: {e}[/red]")
            # Fail CLOSED: a validator error means the claims were NOT
            # independently checked, so do not stamp them "validated".
            validation = {"valid": False,
                          "unsupported_claims": ["validator model unavailable — not independently validated"]}

        if not validation.get("valid", False):
            unsupported = validation.get("unsupported_claims", [])
            if isinstance(unsupported, str):
                unsupported = [unsupported]
            console.print(f"[yellow]⚠ {validator_model} flagged {len(unsupported)} unsupported claims in the report.[/yellow]")
            for item in analysis:
                item["_validated"] = False
                item["_unsupported_claims"] = unsupported
        else:
            if cross_model:
                console.print(f"[green]✓ {validator_model} validated all claims in the report.[/green]")
            else:
                console.print(f"[yellow]⚠ Report self-validated by {validator_model} "
                              f"(no independent validator model available — not cross-checked).[/yellow]")
            for item in analysis:
                # Only a genuine, cross-model validation earns the green badge.
                item["_validated"] = cross_model
                item["_self_validated"] = not cross_model

        return analysis
