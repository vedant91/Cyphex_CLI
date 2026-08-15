"""
CYPHEX DeepAgent — Race Condition (CWE-362)

Tests for Time-of-Check to Time-of-Use (TOCTOU) vulnerabilities by sending
concurrent requests to state-changing endpoints (orders, coupons, discounts,
wallet/credits). A successful race condition allows an attacker to apply a
discount multiple times, over-draw a balance, or place multiple orders for
the price of one.
"""
import asyncio
import json as _json
from backend.deepagents.base_deep_agent import BaseDeepAgent
from backend.backend.models.scan import ScanContext, Vuln
from backend.backend.models.agent_result import AgentResult
from backend.deepagents.oracle_attack import HttpRequest

# Endpoints that are prime race condition targets
RACE_TARGET_KEYWORDS = [
    "coupon", "discount", "order", "checkout", "cart", "redeem",
    "voucher", "wallet", "credit", "purchase", "buy", "payment",
    "apply", "use", "claim", "transfer",
]

# How many concurrent requests to fire in a race window
RACE_CONCURRENCY = 8


class DeepRaceConditionAgent(BaseDeepAgent):
    """
    Race Condition / TOCTOU DeepAgent.

    Sends N concurrent POST requests to the same state-changing endpoint
    within a tight time window. If the server doesn't use proper locking
    (DB transactions, Redis locks, SELECT FOR UPDATE), multiple requests
    may succeed simultaneously — e.g., applying a discount N times.
    """
    PRIMARY_VULN_CLASS = "Race Condition / TOCTOU Business Logic Flaw"
    # Use a smaller parallel batch — race attacks are inherently parallel
    PARALLEL_BATCH = 1

    async def run(self, context: ScanContext) -> AgentResult:
        race_targets = self._find_race_targets()

        if race_targets:
            self.console.print(
                f"[cyan]DeepRaceConditionAgent[/cyan] found "
                f"[yellow]{len(race_targets)}[/yellow] race target(s): "
                f"{', '.join(race_targets[:3])}"
            )
            for endpoint in race_targets[:2]:
                await self._race_attack(endpoint, context)
        else:
            self.console.print(
                "[cyan]DeepRaceConditionAgent[/cyan] No obvious race targets — "
                "probing generic POST endpoints..."
            )
            # Probe any POST endpoints. asi.endpoints maps path -> EndpointProfile
            # whose `.methods` is a set of observed verbs (not a dict).
            def _has_post(ep: str) -> bool:
                profile = self.asi.endpoints.get(ep)
                return "POST" in (getattr(profile, "methods", None) or set())

            post_endpoints = [
                ep for ep in list(self.asi.endpoints)
                if _has_post(ep) or "create" in ep.lower() or "register" in ep.lower()
            ]
            for ep in post_endpoints[:2]:
                await self._race_attack(ep, context)

        return await super().run(context)

    def _find_race_targets(self) -> list[str]:
        candidates = []
        for path in list(self.asi.endpoints):
            path_lower = path.lower()
            if any(kw in path_lower for kw in RACE_TARGET_KEYWORDS):
                candidates.append(path)
        return candidates

    async def _race_attack(self, endpoint: str, context: ScanContext) -> None:
        """Fire RACE_CONCURRENCY identical requests simultaneously."""
        body = _json.dumps({
            "product_id": 1,
            "quantity": 1,
            "coupon": "DISCOUNT50",
            "user_id": 1,
        })
        requests = [
            HttpRequest(
                method="POST",
                path=endpoint,
                body=body,
                headers={"Content-Type": "application/json"},
                payload="race_condition_concurrent",
            )
            for _ in range(RACE_CONCURRENCY)
        ]

        self.console.print(
            f"[cyan]  Firing {RACE_CONCURRENCY} concurrent requests to {endpoint}[/cyan]"
        )

        # All fire at the same instant
        results = await asyncio.gather(
            *[self._http_probe(req) for req in requests],
            return_exceptions=True
        )

        successes = []
        for r in results:
            if isinstance(r, Exception):
                continue
            status, body_resp, elapsed, headers = r
            if status in (200, 201):
                successes.append((status, body_resp[:100]))

        self.console.print(
            f"  Race result: {len(successes)}/{RACE_CONCURRENCY} requests returned 200/201"
        )

        # If more than 1 request succeeded on a state-changing endpoint → race condition
        if len(successes) > 1:
            self.console.print(
                f"[red]  [DeepRace] RACE CONDITION CONFIRMED at {endpoint}![/red]\n"
                f"  {len(successes)} simultaneous requests both succeeded."
            )
            self.vulns.append(Vuln(
                name="[DYNAMIC] Race Condition / TOCTOU",
                cwe="CWE-362",
                severity="High",
                endpoint=endpoint,
                payload=f"{RACE_CONCURRENCY} concurrent POST requests",
                confirmed=True,
                evidence=(
                    f"{len(successes)}/{RACE_CONCURRENCY} simultaneous requests "
                    f"returned HTTP 200/201 on a state-changing endpoint. "
                    f"First two responses: {successes[0][1][:80]} | {successes[1][1][:80]}"
                ),
                fix=(
                    "Use database-level locking (SELECT FOR UPDATE / transaction) or "
                    "a distributed lock (Redis SETNX) around the critical section. "
                    "Implement idempotency keys on order/payment endpoints."
                ),
            ))
