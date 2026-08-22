"""
CYPHEX — Scan Orchestrator

Coordinates the execution of all 11 agents in the correct order:
  Stage 1: Recon (sequential — others depend on it)
  Stage 2: Crawler (sequential — attack agents depend on it)
  Stage 3: Attack agents (PARALLEL via asyncio.gather)
           - InjectionAgent (combined SQLi + CMDi)
           - XSSAgent, AuthAgent, LFIAgent, LogicAgent
           - SupplyChainAgent
  Stage 4: Cerebras AI Analysis (sequential)
  Stage 5: Patch Generation (sequential)

30-minute total scan timeout.
"""

import asyncio
import json
import os
import sys
import time
from datetime import datetime
from typing import Optional, Callable

# Force UTF-8 output on Windows
if os.name == 'nt':
    os.environ.setdefault("PYTHONUTF8", "1")

from scoring import score_from_counts
from agents.terminal import Colors
from agents.agent_01_recon import ReconAgent
from agents.agent_02_crawler import CrawlerAgent
from agents.agent_injection import InjectionAgent
from agents.agent_04_xss import XSSAgent
from agents.agent_05_auth import AuthAgent
from agents.agent_07_lfi import LFIAgent
from agents.agent_08_logic import LogicAgent
from agents.agent_09_analysis import CerebrasAnalysisAgent
from agents.agent_10_patch import PatchAgent
from agents.agent_11_supply_chain import SupplyChainAgent
from models.scan import ScanContext
from models.agent_result import AgentResult
from config import config
from live_log_queue import log_queue


class ScanOrchestrator:
    """Coordinates the full 11-agent exploitation pipeline."""

    def __init__(self, event_callback: Optional[Callable] = None):
        self.scan_start = None
        self.scan_end = None
        self._event_callback = event_callback

    async def _emit(self, event: dict):
        """Emit an event to the frontend via WebSocket (if callback provided)."""
        if self._event_callback:
            try:
                await self._event_callback(event)
            except Exception:
                pass  # Never let event emission kill the scan

    async def run_scan(
        self,
        scan_id: str,
        target_url: str,
        cerebras_key: str = "",
    ) -> dict:
        """
        Execute the full multi-agent scan pipeline.
        Returns the complete scan report.
        """
        self.scan_start = time.time()
        cerebras_key = cerebras_key or config.CEREBRAS_API_KEY
        
        # Start a background task to consume live terminal logs
        self.live_log_task = asyncio.create_task(self._stream_live_logs())

        # Initialize shared context
        context = ScanContext(target_url=target_url)

        self._print_banner(scan_id, target_url)

        await self._emit({
            "type": "scan_start",
            "scan_id": scan_id,
            "target": target_url,
        })

        try:
            # ═══════════════════════════════════════
            # STAGE 1: RECONNAISSANCE (Sequential)
            # ═══════════════════════════════════════
            self._print_stage("STAGE 1/5", "RECONNAISSANCE", "🔍")
            await self._emit({
                "type": "stage_start",
                "stage": 1,
                "name": "RECONNAISSANCE",
            })

            recon = ReconAgent(scan_id, target_url, cerebras_key)
            await self._emit({
                "type": "agent_start",
                "agent_id": "recon",
                "agent_name": "Recon Agent",
                "task": f"Scanning {target_url}",
            })

            result = await asyncio.wait_for(
                recon.run(context),
                timeout=300,  # 5 min max for recon
            )
            context = result.context
            context.terminal_logs.extend(result.terminal_logs)

            await self._emit({
                "type": "agent_complete",
                "agent_id": "recon",
                "agent_name": "Recon Agent",
                "vulns_found": len(recon.vulns),
                "detail": f"framework={context.framework}, server={context.server}",
                "task": f"Found {context.framework or 'Unknown'} framework",
            })

            self._print_stage_complete(
                "RECON", len(recon.vulns),
                f"framework={context.framework}, server={context.server}"
            )

            # Emit terminal logs for recon
            await self._emit_terminal_logs(result.terminal_logs, "Recon Agent")

            # ═══════════════════════════════════════
            # STAGE 2: CRAWLING (Sequential)
            # ═══════════════════════════════════════
            self._print_stage("STAGE 2/5", "CRAWLING", "🕷")
            await self._emit({
                "type": "stage_start",
                "stage": 2,
                "name": "CRAWLING",
            })

            crawler = CrawlerAgent(scan_id, target_url, cerebras_key)
            await self._emit({
                "type": "agent_start",
                "agent_id": "crawler",
                "agent_name": "Crawler Agent",
                "task": "Mapping endpoints and forms",
            })

            result = await asyncio.wait_for(
                crawler.run(context),
                timeout=300,  # 5 min max
            )
            context = result.context
            context.terminal_logs.extend(result.terminal_logs)

            await self._emit({
                "type": "agent_complete",
                "agent_id": "crawler",
                "agent_name": "Crawler Agent",
                "vulns_found": len(crawler.vulns),
                "detail": f"forms={len(context.all_forms)}, endpoints={len(context.all_endpoints)}, params={len(context.all_params)}",
                "task": f"Mapped {len(context.all_endpoints)} endpoints, {len(context.all_forms)} forms",
            })

            self._print_stage_complete(
                "CRAWLER",
                len(crawler.vulns),
                f"forms={len(context.all_forms)}, "
                f"endpoints={len(context.all_endpoints)}, "
                f"params={len(context.all_params)}"
            )

            await self._emit_terminal_logs(result.terminal_logs, "Crawler Agent")

            # ═══════════════════════════════════════
            # STAGE 3: ATTACK AGENTS (PARALLEL)
            # ═══════════════════════════════════════
            self._print_stage("STAGE 3/5", "PARALLEL ATTACK AGENTS", "⚔")
            await self._emit({
                "type": "stage_start",
                "stage": 3,
                "name": "PARALLEL ATTACK AGENTS",
            })

            print(
                f"  {Colors.YELLOW}Launching 6 attack agents simultaneously...{Colors.RESET}\n"
            )

            attack_agents = [
                InjectionAgent(scan_id, target_url, cerebras_key),
                XSSAgent(scan_id, target_url, cerebras_key),
                AuthAgent(scan_id, target_url, cerebras_key),
                LFIAgent(scan_id, target_url, cerebras_key),
                LogicAgent(scan_id, target_url, cerebras_key),
                SupplyChainAgent(scan_id, target_url, cerebras_key),
            ]

            agent_id_map = {
                "InjectionAgent": ("injection", "Injection Agent (SQLi + CMDi)"),
                "XSSAgent": ("xss", "XSS Agent"),
                "AuthAgent": ("auth", "Auth Agent"),
                "LFIAgent": ("lfi", "LFI Agent"),
                "LogicAgent": ("logic", "Logic Agent"),
                "SupplyChainAgent": ("supply_chain", "Supply Chain Agent"),
            }

            # Emit agent_start for all attack agents
            for agent in attack_agents:
                cls_name = agent.__class__.__name__
                aid, aname = agent_id_map.get(cls_name, (cls_name.lower(), cls_name))
                await self._emit({
                    "type": "agent_start",
                    "agent_id": aid,
                    "agent_name": aname,
                    "task": f"Attacking {target_url}",
                })

            # Run all attack agents in parallel
            tasks = [agent.run(context) for agent in attack_agents]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Merge results
            total_attack_vulns = 0
            for i, result in enumerate(results):
                agent_name = attack_agents[i].__class__.__name__
                aid, aname = agent_id_map.get(agent_name, (agent_name.lower(), agent_name))

                if isinstance(result, Exception):
                    print(
                        f"  {Colors.RED}✗ {agent_name} failed: {result}{Colors.RESET}"
                    )
                    await self._emit({
                        "type": "agent_error",
                        "agent_id": aid,
                        "agent_name": aname,
                        "error": str(result),
                    })
                elif isinstance(result, AgentResult):
                    context.confirmed_vulns.extend(result.vulns)
                    context.terminal_logs.extend(result.terminal_logs)
                    total_attack_vulns += len(result.vulns)

                    # Emit vulns found by this agent
                    for v in result.vulns:
                        await self._emit({
                            "type": "vuln_found",
                            "agent_id": aid,
                            "agent_name": aname,
                            "vuln": v.to_dict(),
                        })

                    await self._emit({
                        "type": "agent_complete",
                        "agent_id": aid,
                        "agent_name": aname,
                        "vulns_found": len(result.vulns),
                        "task": f"Found {len(result.vulns)} vulnerabilities" if result.vulns else "No vulnerabilities found",
                    })

                    await self._emit_terminal_logs(result.terminal_logs, aname)

            self._print_stage_complete(
                "ATTACKS", total_attack_vulns,
                f"total_confirmed={len(context.confirmed_vulns)}"
            )

            # ═══════════════════════════════════════
            # STAGE 4: AI ANALYSIS (Sequential)
            # ═══════════════════════════════════════
            self._print_stage("STAGE 4/5", "AI ANALYSIS", "🧠")
            await self._emit({
                "type": "stage_start",
                "stage": 4,
                "name": "AI ANALYSIS",
            })

            analysis = CerebrasAnalysisAgent(
                scan_id, target_url, cerebras_key
            )
            await self._emit({
                "type": "agent_start",
                "agent_id": "analysis",
                "agent_name": "Analysis Agent",
                "task": "Sending context to Cerebras AI",
            })

            analysis_result = await asyncio.wait_for(
                analysis.run(context),
                timeout=120,
            )
            context.terminal_logs.extend(analysis_result.terminal_logs)

            await self._emit({
                "type": "agent_complete",
                "agent_id": "analysis",
                "agent_name": "Analysis Agent",
                "vulns_found": 0,
                "task": "AI threat analysis complete",
            })

            self._print_stage_complete("ANALYSIS", 0, "report generated")

            # ═══════════════════════════════════════
            # STAGE 5: PATCH GENERATION (Sequential)
            # ═══════════════════════════════════════
            self._print_stage("STAGE 5/5", "PATCH GENERATION", "🔧")
            await self._emit({
                "type": "stage_start",
                "stage": 5,
                "name": "PATCH GENERATION",
            })

            patcher = PatchAgent(scan_id, target_url, cerebras_key)
            await self._emit({
                "type": "agent_start",
                "agent_id": "patch",
                "agent_name": "Patch Agent",
                "task": "Generating cure plan",
            })

            patch_result = await asyncio.wait_for(
                patcher.run(context),
                timeout=120,
            )
            context.terminal_logs.extend(patch_result.terminal_logs)

            await self._emit({
                "type": "agent_complete",
                "agent_id": "patch",
                "agent_name": "Patch Agent",
                "vulns_found": 0,
                "task": "Cure plan ready",
            })

            self._print_stage_complete("PATCHES", 0, "cure plan ready")

            # ═══════════════════════════════════════
            # BUILD FINAL REPORT
            # ═══════════════════════════════════════
            self.scan_end = time.time()
            duration = self.scan_end - self.scan_start

            # ── Deduplicate vulnerabilities ──
            deduped_vulns = self._deduplicate_vulns(context.confirmed_vulns)
            context.confirmed_vulns = deduped_vulns

            n_critical = len([v for v in context.confirmed_vulns if v.severity == "Critical"])
            n_high = len([v for v in context.confirmed_vulns if v.severity == "High"])
            n_medium = len([v for v in context.confirmed_vulns if v.severity == "Medium"])
            n_low = len([v for v in context.confirmed_vulns if v.severity == "Low"])

            report = {
                "scan_id": scan_id,
                "target": target_url,
                "scan_time": f"{duration:.1f}s",
                "timestamp": datetime.now().isoformat(),
                "framework": context.framework,
                "database": context.database,
                "server": context.server,
                "technologies": context.technologies,
                "summary": {
                    "total_vulns": len(context.confirmed_vulns),
                    "critical": n_critical,
                    "high": n_high,
                    "medium": n_medium,
                    "low": n_low,
                    # Authoritative 0-100 posture score (higher = safer), from
                    # scoring.py — the SAME formula the CLI's before/after
                    # panel and final banner use. The web dashboard's
                    # real-time gauge computes its own local approximation
                    # while a scan is in flight (see usePipeline.ts); this
                    # value is what it reconciles against once the scan
                    # completes, so the two never permanently disagree.
                    "security_score": score_from_counts(n_critical, n_high, n_medium, n_low),
                    "pages_crawled": len(context.sitemap),
                    "forms_found": len(context.all_forms),
                    "endpoints_found": len(context.all_endpoints),
                    "commands_executed": len(context.terminal_logs),
                },
                "vulnerabilities": [v.to_dict() for v in context.confirmed_vulns],
                "analysis": analysis_result.report,
                "cure_plan": self._normalize_cure_plan(patch_result.cure_plan),
            }

            self._print_final_report(report, context.confirmed_vulns)
            
            if hasattr(self, 'live_log_task'):
                self.live_log_task.cancel()
                
            return report

        except asyncio.TimeoutError:
            if hasattr(self, 'live_log_task'):
                self.live_log_task.cancel()
            print(
                f"\n  {Colors.RED}{Colors.BOLD}"
                f"! SCAN TIMED OUT after {config.SCAN_TIMEOUT_SECONDS}s"
                f"{Colors.RESET}"
            )
            return {"error": "Scan timed out", "partial_vulns": len(context.confirmed_vulns)}

        except Exception as e:
            if hasattr(self, 'live_log_task'):
                self.live_log_task.cancel()
            print(
                f"\n  {Colors.RED}{Colors.BOLD}"
                f"x SCAN FAILED: {e}"
                f"{Colors.RESET}"
            )
            import traceback
            traceback.print_exc()
            return {"error": str(e)}
    async def _stream_live_logs(self):
        """Continuously pulls logs from the queue and emits to the UI."""
        
        # Mapping from ClassName to Frontend Display Name
        live_mapping = {
            "ReconAgent": "Recon Agent",
            "CrawlerAgent": "Crawler Agent",
            "SQLiAgent": "Injection Agent (SQLi + CMDi)",
            "CMDiAgent": "Injection Agent (SQLi + CMDi)",
            "InjectionAgent": "Injection Agent (SQLi + CMDi)",
            "XSSAgent": "XSS Agent",
            "AuthAgent": "Auth Agent",
            "LFIAgent": "LFI Agent",
            "LogicAgent": "Logic Agent",
            "SupplyChainAgent": "Supply Chain Agent",
            "PatchAgent": "Patch Agent",
            "AnalysisAgent": "Analysis Agent",
        }
        
        try:
            while True:
                item = await log_queue.get()
                event_type = item.get("type", "")
                # Skip verbose terminal/agent logs — the orchestrator already
                # emits the important lifecycle events (agent_start, agent_complete,
                # vuln_found, stage_start) directly.  Forwarding every terminal
                # command floods the WebSocket and causes ping timeouts (1011).
                if event_type in ("terminal_log", "agent_log"):
                    continue
                await self._emit(item)
        except asyncio.CancelledError:
            pass

    async def _emit_terminal_logs(self, logs: list, agent_name: str):
        """Emit terminal log entries as events (now stripped down since streaming handles it)."""
        pass

    def _deduplicate_vulns(self, vulns):
        """Remove duplicate vulnerability findings."""
        seen = {}
        for v in vulns:
            key = f"{v.name}|{v.endpoint}|{v.payload}"
            if key not in seen:
                seen[key] = v
            else:
                # Keep the one with more evidence
                existing = seen[key]
                if len(v.evidence or "") > len(existing.evidence or ""):
                    seen[key] = v
                if v.dumped_data and not existing.dumped_data:
                    seen[key] = v
        return list(seen.values())

    def _normalize_cure_plan(self, raw_plan) -> dict:
        """
        Transform the patch agent's cure_plan into the format the frontend expects:
          { patches: [{ vuln, fix_type, code, explanation }], security_checklist: [...] }
        Also deduplicates patches with identical explanations.
        """
        if not raw_plan or not isinstance(raw_plan, dict):
            return {"patches": [], "security_checklist": []}

        raw_patches = raw_plan.get("patches", [])
        seen_explanations = set()
        normalized = []

        for p in raw_patches:
            if not isinstance(p, dict):
                continue

            # Build the vuln name
            vuln = (
                p.get("vuln_name")
                or p.get("vuln")
                or p.get("vulnerability")
                or "Unknown Vulnerability"
            )

            explanation = p.get("explanation", "")

            # Deduplicate: skip patches with an identical explanation
            dedup_key = explanation.strip().lower()
            if dedup_key in seen_explanations:
                continue
            seen_explanations.add(dedup_key)

            # Build the fix_type label
            fix_type = p.get("fix_type", "")
            if not fix_type:
                file_path = p.get("file_path", "")
                install = p.get("install", "")
                parts = []
                if file_path:
                    parts.append(file_path)
                if install:
                    parts.append(install)
                fix_type = " · ".join(parts) if parts else "Code Patch"

            # Build the code block: combine before/after into a diff-like view
            code = p.get("code", "")
            if not code:
                before = p.get("before", "")
                after = p.get("after", "")
                install = p.get("install", "")
                code_parts = []
                if before:
                    code_parts.append(f"// ❌ BEFORE (vulnerable)\n{before}")
                if after:
                    code_parts.append(f"// ✅ AFTER (fixed)\n{after}")
                if install:
                    code_parts.append(f"// 📦 Install\n$ {install}")
                code = "\n\n".join(code_parts)

            normalized.append({
                "vuln": vuln,
                "fix_type": fix_type,
                "code": code,
                "explanation": explanation,
            })

        return {
            "patches": normalized,
            "security_checklist": raw_plan.get("security_checklist", []),
        }

    def _print_banner(self, scan_id: str, target: str):
        """Print the CYPHEX banner."""
        print(f"""
{Colors.CYAN}{Colors.BOLD}
   ██████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██╗  ██╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝╚██╗██╔╝
  ██║      ╚████╔╝ ██████╔╝███████║█████╗   ╚███╔╝ 
  ██║       ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝   ██╔██╗ 
  ╚██████╗   ██║   ██║     ██║  ██║███████╗██╔╝ ██╗
   ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
{Colors.RESET}
  {Colors.DIM}Multi-Agent Exploitation Pipeline v2.0{Colors.RESET}
  {Colors.DIM}{'=' * 50}{Colors.RESET}
  {Colors.WHITE}Scan ID:  {Colors.CYAN}{scan_id}{Colors.RESET}
  {Colors.WHITE}Target:   {Colors.RED}{target}{Colors.RESET}
  {Colors.WHITE}Time:     {Colors.DIM}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}
  {Colors.DIM}{'=' * 50}{Colors.RESET}
""")

    def _print_stage(self, stage: str, name: str, icon: str):
        """Print stage header."""
        print(
            f"\n  {Colors.CYAN}{Colors.BOLD}"
            f"{'─' * 50}\n"
            f"  {icon}  {stage}: {name}\n"
            f"  {'─' * 50}"
            f"{Colors.RESET}\n"
        )

    def _print_stage_complete(self, name: str, vulns: int, detail: str):
        """Print stage completion."""
        elapsed = time.time() - self.scan_start
        vuln_text = f"{Colors.RED}{vulns} vulns{Colors.RESET}" if vulns > 0 else f"{Colors.GREEN}0 vulns{Colors.RESET}"
        print(
            f"\n  {Colors.GREEN}+ {name} COMPLETE{Colors.RESET} "
            f"[{vuln_text}] "
            f"{Colors.DIM}({detail}) [{elapsed:.1f}s elapsed]{Colors.RESET}\n"
        )

    def _print_final_report(self, report: dict, vulns: list):
        """Print the final scan report with justified proof."""
        summary = report.get("summary", {})
        total = summary.get("total_vulns", 0)
        crits = summary.get("critical", 0)
        highs = summary.get("high", 0)
        meds = summary.get("medium", 0)
        lows = summary.get("low", 0)
        cmds = summary.get("commands_executed", 0)

        print(f"""
{Colors.CYAN}{Colors.BOLD}
  +{'=' * 50}+
  |              CYPHEX SCAN COMPLETE                |
  +{'=' * 50}+
{Colors.RESET}
  {Colors.WHITE}Target:     {Colors.CYAN}{report.get('target', 'N/A')}{Colors.RESET}
  {Colors.WHITE}Duration:   {Colors.DIM}{report.get('scan_time', 'N/A')}{Colors.RESET}
  {Colors.WHITE}Commands:   {Colors.DIM}{cmds} terminal commands executed{Colors.RESET}
  {Colors.WHITE}Framework:  {Colors.DIM}{report.get('framework', 'Unknown')}{Colors.RESET}

  {Colors.BOLD}VULNERABILITIES FOUND: {total}{Colors.RESET}
  {Colors.RED}  Critical: {crits}{Colors.RESET}
  {Colors.YELLOW}  High:     {highs}{Colors.RESET}
  {Colors.CYAN}  Medium:   {meds}{Colors.RESET}
  {Colors.DIM}  Low:      {lows}{Colors.RESET}
""")

        # Print each vulnerability with JUSTIFIED proof
        print(f"  {Colors.DIM}{'─' * 50}{Colors.RESET}")
        print(f"  {Colors.BOLD}EXPLOITATION DETAILS & PROOF{Colors.RESET}")
        print(f"  {Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        for i, vuln in enumerate(vulns, 1):
            sev = vuln.severity
            sev_color = {
                "Critical": Colors.RED,
                "High": Colors.YELLOW,
                "Medium": Colors.CYAN,
                "Low": Colors.DIM,
            }.get(sev, Colors.DIM)

            print(
                f"  {Colors.BOLD}{i}. {sev_color}[{sev.upper()}]{Colors.RESET} "
                f"{Colors.WHITE}{Colors.BOLD}{vuln.name}{Colors.RESET}"
            )
            print(f"  {Colors.DIM}   CVSS: {vuln.cvss_score}/10{Colors.RESET}")

            if vuln.endpoint:
                print(f"  {Colors.CYAN}   Endpoint: {vuln.endpoint}{Colors.RESET}")

            if vuln.payload:
                print(f"  {Colors.RED}   Payload:  {vuln.payload[:100]}{Colors.RESET}")

            if vuln.description:
                print(f"  {Colors.DIM}   Details:  {vuln.description[:150]}{Colors.RESET}")

            # ── PROOF / JUSTIFICATION ──
            if vuln.dumped_data:
                print(f"  {Colors.RED}{Colors.BOLD}   >> PROOF: Data Extracted: {vuln.dumped_data[:100]}{Colors.RESET}")

            if vuln.rce_output:
                print(f"  {Colors.RED}{Colors.BOLD}   >> PROOF: Command Output: {vuln.rce_output[:100]}{Colors.RESET}")

            # Show clickable exploit URL for XSS
            if "xss" in vuln.name.lower() and vuln.payload and vuln.endpoint:
                from urllib.parse import quote as url_quote
                if "reflected" in vuln.name.lower() or "dom" in vuln.name.lower():
                    exploit_url = f"{vuln.endpoint}?q={url_quote(vuln.payload)}"
                    print(f"  {Colors.YELLOW}   >> EXPLOIT URL: {exploit_url}{Colors.RESET}")

            # Show login proof for auth bypass
            if "credential" in vuln.name.lower() or "auth bypass" in vuln.name.lower():
                print(f"  {Colors.GREEN}   >> LOGIN: Use these credentials at {vuln.endpoint}{Colors.RESET}")

            if vuln.fix:
                print(f"  {Colors.GREEN}   Fix: {vuln.fix}{Colors.RESET}")

            print()  # spacing between vulns

        print(f"  {Colors.DIM}{'=' * 50}{Colors.RESET}")

        # Print cure plan summary
        cure = report.get("cure_plan")
        if cure and isinstance(cure, dict):
            patches = cure.get("patches", [])
            checklist = cure.get("security_checklist", [])
            print(
                f"\n  {Colors.GREEN}{Colors.BOLD}CURE PLAN:{Colors.RESET} "
                f"{len(patches)} patches, {len(checklist)} checklist items"
            )

        print(f"\n  {Colors.DIM}Full report saved to scan results.{Colors.RESET}\n")
