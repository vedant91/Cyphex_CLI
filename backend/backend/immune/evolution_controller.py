"""
CYPHEX — Evolution Controller (The Core Loop)

Orchestrates the Adversarial Co-Evolution:
  1. Red team generates payloads
  2. Blue genome scores each payload
  3. Blocked payloads → feedback to red team
  4. Bypassed payloads → training data for blue team
  5. Both evolve → repeat

Each iteration = one "generation"
"""

import time
import asyncio
from datetime import datetime
from typing import Optional, Callable

from config import config
from models.genome import EvolutionResult, GenomeState
from models.scan import ScanContext
from immune.behavioral_genome import BehavioralGenome
from immune.mutation_engine import MutationEngine


class EvolutionController:
    """
    Orchestrates the Adversarial Co-Evolution loop.
    The core innovation: red team and blue team fighting each other
    in a closed loop, each making the other stronger.
    """

    def __init__(self):
        self.genome = BehavioralGenome()
        self.mutation = MutationEngine()
        self.history: list[EvolutionResult] = []
        self.current_generation = 0
        self._last_generation_results: list[dict] = []  # Actual payloads + verdicts

    async def run_evolution(
        self,
        context: ScanContext,
        generations: int = None,
        payloads_per_gen: int = None,
        on_generation_complete: Optional[Callable] = None,
    ) -> list[EvolutionResult]:
        """
        Run the full co-evolution loop.

        GENERATION 0:
        - Red: Generate initial payloads (no LLM needed)
        - Blue: Build genome from scan context
        - Score all payloads → establish baseline block rate

        GENERATION 1..N:
        - Red: Take BLOCKED payloads → mutate to evade genome
        - Blue: Take BYPASSED payloads → retrain genome
        - Score new payloads → record new block rate
        - Emit progress event for dashboard

        CONVERGENCE CHECK:
        - If block_rate >= 0.99 for 3 consecutive gens → stop early
        """
        generations = generations or config.EVOLUTION_GENERATIONS
        payloads_per_gen = payloads_per_gen or config.EVOLUTION_PAYLOADS_PER_GEN

        print(f"\n  🧬 Starting Adversarial Co-Evolution ({generations} generations)...")
        print(f"  🧬 Payloads per generation: {payloads_per_gen}")

        # ─── Build initial genome from scan results ───
        # Skip if already profiled (the caller may have built or loaded it) so we
        # don't retrain on normal-only samples and clobber restored/accumulated
        # adversarial state.
        print("  🔵 BLUE TEAM: Building behavioral genome from scan data...")
        if not self.genome.endpoint_profiles:
            self.genome.build_from_scan(context)
        print(f"  🔵 Genome profiled {len(self.genome.endpoint_profiles)} endpoints")

        # ─── Generate initial attack payloads ───
        print("  🔴 RED TEAM: Generating initial attack payloads...")
        current_payloads = []
        for attack_type in ["sqli", "xss", "cmdi"]:
            payloads = self.mutation.generate_initial_payloads(
                attack_type=attack_type,
                count=payloads_per_gen // 3,
            )
            current_payloads.extend(payloads)
        print(f"  🔴 Generated {len(current_payloads)} initial payloads")

        # Assign endpoints to payloads
        endpoints = list(self.genome.endpoint_profiles.keys())
        if not endpoints:
            endpoints = [context.target_url]

        for p in current_payloads:
            if "endpoint" not in p:
                p["endpoint"] = endpoints[hash(p["payload"]) % len(endpoints)]

        # ─── Evolution Loop ───
        convergence_count = 0

        for gen in range(generations):
            self.current_generation = gen
            start_time = time.time()

            result = await self._run_single_generation(
                gen, current_payloads, context
            )

            self.history.append(result)

            # Print generation result
            status = "🟢" if result.block_rate > 0.8 else "🟡" if result.block_rate > 0.5 else "🔴"
            print(
                f"  {status} Generation {gen}: "
                f"blocked {result.payloads_blocked}/{result.payloads_generated} "
                f"({result.block_rate:.1%}) | "
                f"⏱ {result.duration_seconds:.1f}s"
            )

            # Callback for real-time dashboard updates
            if on_generation_complete:
                try:
                    await on_generation_complete(result)
                except Exception:
                    pass

            # Check convergence
            if result.block_rate >= config.EVOLUTION_CONVERGENCE_THRESHOLD:
                convergence_count += 1
                if convergence_count >= 3:
                    print(f"  ✅ Genome converged at {result.block_rate:.1%} — stopping evolution")
                    break
            else:
                convergence_count = 0

            # Prepare next generation payloads
            if gen < generations - 1:
                current_payloads = await self._prepare_next_generation(result)

        # ─── Summary ───
        final = self.history[-1] if self.history else None
        initial = self.history[0] if self.history else None

        print(f"\n  🧬 ══════ EVOLUTION COMPLETE ══════")
        if initial and final:
            print(f"  📈 Block rate: {initial.block_rate:.1%} → {final.block_rate:.1%}")
            print(f"  🔬 Generations: {len(self.history)}")
            print(f"  🛡️  Genome is now hardened against {final.payloads_blocked} attack patterns")
        print()

        return self.history

    async def _run_single_generation(
        self, gen_num: int, payloads: list[dict], context: ScanContext
    ) -> EvolutionResult:
        """
        Execute one generation:
        1. Score all payloads against genome
        2. Partition into blocked/bypassed
        3. Record metrics
        """
        start = time.time()
        blocked = []
        bypassed = []

        threshold = config.GENOME_BLOCK_THRESHOLD

        for payload_data in payloads:
            payload_text = payload_data.get("payload", "")
            endpoint = payload_data.get("endpoint", "")

            score = self.genome.score_request(endpoint, payload_text)

            if score >= threshold:
                blocked.append({
                    **payload_data,
                    "anomaly_score": score,
                    "verdict": "BLOCKED",
                })
            else:
                bypassed.append({
                    **payload_data,
                    "anomaly_score": score,
                    "verdict": "BYPASSED",
                })

        # Blue team learns from bypassed attacks
        features_learned = []
        if bypassed:
            # Group bypassed by endpoint
            by_endpoint = {}
            for bp in bypassed:
                ep = bp.get("endpoint", "default")
                if ep not in by_endpoint:
                    by_endpoint[ep] = []
                by_endpoint[ep].append(bp["payload"])

            for ep, attack_texts in by_endpoint.items():
                self.genome.retrain(ep, attack_texts)
                features_learned.append(f"retrained_{ep}_with_{len(attack_texts)}_attacks")

        total = max(len(payloads), 1)
        block_rate = len(blocked) / total

        # Update genome state
        if self.genome.state:
            self.genome.state.generation = gen_num
            self.genome.state.block_rate = block_rate
            self.genome.state.total_attacks_seen += len(payloads)
            self.genome.state.total_attacks_blocked += len(blocked)

        # Store actual results for next-gen mutation (the evolution fix)
        self._last_generation_results = blocked + bypassed

        return EvolutionResult(
            generation=gen_num,
            payloads_generated=len(payloads),
            payloads_blocked=len(blocked),
            payloads_bypassed=len(bypassed),
            block_rate=block_rate,
            new_features_learned=features_learned,
            red_mutations_applied=[p.get("technique", "") for p in payloads[:5]],
            duration_seconds=time.time() - start,
        )

    async def _prepare_next_generation(self, result: EvolutionResult) -> list[dict]:
        """
        Prepare payloads for the next generation.
        Red team mutates blocked payloads AND builds on bypassed payloads
        (successful evasions breed new evasions).
        """
        blocked_payloads = self._get_last_blocked()
        bypassed_payloads = self._get_last_bypassed()

        if not blocked_payloads and not bypassed_payloads:
            return self.mutation.generate_initial_payloads(count=config.EVOLUTION_PAYLOADS_PER_GEN)

        # Determine what features triggered detection
        avg_score = sum(p.get("anomaly_score", 0.5) for p in blocked_payloads) / max(len(blocked_payloads), 1)
        genome_feedback = {
            "avg_anomaly_score": avg_score,
            "features_triggered": self._analyze_triggered_features(blocked_payloads),
            "generation": result.generation,
        }

        # Red team mutates BLOCKED payloads (try to evade detection)
        new_payloads = await self.mutation.mutate_blocked_payloads(
            blocked_payloads[:10], genome_feedback
        )

        # ALSO mutate BYPASSED payloads (breed from successful evasions)
        for bp in bypassed_payloads[:5]:
            variants = self.mutation.generate_variants(
                bp.get("payload", ""), count=2,
                attack_type=bp.get("type", "sqli")
            )
            new_payloads.extend(variants)

        # Add some fresh payloads to keep diversity
        fresh = self.mutation.generate_initial_payloads(
            count=max(5, config.EVOLUTION_PAYLOADS_PER_GEN // 4)
        )
        new_payloads.extend(fresh)

        # Assign endpoints
        endpoints = list(self.genome.endpoint_profiles.keys())
        if endpoints:
            for p in new_payloads:
                if "endpoint" not in p:
                    p["endpoint"] = endpoints[hash(p.get("payload", "")) % len(endpoints)]

        return new_payloads[:config.EVOLUTION_PAYLOADS_PER_GEN]

    def _get_last_blocked(self) -> list[dict]:
        """Get blocked payloads from last generation (real results, not re-scored)."""
        return [p for p in self._last_generation_results if p.get("verdict") == "BLOCKED"]

    def _get_last_bypassed(self) -> list[dict]:
        """Get bypassed payloads from last generation (used as mutation seeds)."""
        return [p for p in self._last_generation_results if p.get("verdict") == "BYPASSED"]

    def _analyze_triggered_features(self, blocked: list[dict]) -> list[str]:
        """Analyze which detection features triggered blocking."""
        features = []
        for p in blocked[:5]:
            payload = p.get("payload", "")
            vec = self.genome.extract_features(payload)

            if vec[1] > 4.0:  # High entropy
                features.append("entropy")
            if vec[2] > 0.3:  # Special chars
                features.append("special_char")
            if vec[3] > 0.1:  # URL encoding
                features.append("url_encoding")
            if vec[7] > 0.3:  # Keywords
                features.append("keyword")
            if vec[0] > 100:  # Long input
                features.append("length")

        return list(set(features))

    def get_evolution_summary(self) -> dict:
        """Return the full evolution history for the dashboard."""
        return {
            "generations_completed": len(self.history),
            "initial_block_rate": self.history[0].block_rate if self.history else 0,
            "final_block_rate": self.history[-1].block_rate if self.history else 0,
            "genome_endpoints": len(self.genome.endpoint_profiles),
            "total_attacks_tested": sum(r.payloads_generated for r in self.history),
            "total_attacks_blocked": sum(r.payloads_blocked for r in self.history),
            "history": [r.to_dict() for r in self.history],
        }
