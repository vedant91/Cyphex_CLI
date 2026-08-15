"""DeepBusinessLogicAgent — Race conditions, price tampering, workflow bypass."""
import asyncio
import json
import re
from backend.deepagents.base_deep_agent import BaseDeepAgent
from backend.backend.models.scan import ScanContext, Vuln
from backend.backend.models.agent_result import AgentResult
from backend.deepagents.oracle_attack import HttpRequest

class DeepBusinessLogicAgent(BaseDeepAgent):
    """
    Business logic vulnerability testing agent.
    Covers:
    - Race conditions (concurrent coupon use, wallet operations)
    - Negative quantity / integer overflow price tampering
    - Workflow skip (jump to checkout without cart)
    - Forced browsing on multi-step processes
    - Coupon stacking / reuse
    """
    PRIMARY_VULN_CLASS = "Business Logic Flaw"

    # Cart/wallet endpoint patterns
    CART_PATHS    = ["/api/cart", "/api/basket", "/cart", "/basket", "/api/checkout"]
    COUPON_PATHS  = ["/api/coupon", "/api/promo", "/api/discount", "/api/voucher"]
    WALLET_PATHS  = ["/api/wallet", "/api/balance", "/api/credits", "/api/points"]
    CHECKOUT_PATHS= ["/api/checkout", "/api/order", "/api/payment", "/api/purchase"]

    async def run(self, context: ScanContext) -> AgentResult:
        if not self.asi.endpoints:
            return AgentResult(agent=self.__class__.__name__, vulns=[], context=context)

        await self._test_race_condition(context)
        await self._test_price_tampering(context)
        await self._test_workflow_bypass(context)

        return await super().run(context)

    async def _test_race_condition(self, context: ScanContext) -> None:
        """Send 10 concurrent identical requests to detect TOCTOU race conditions."""
        race_targets = []
        for path in self.asi.endpoints:
            if any(p in path.lower() for p in ("coupon", "promo", "discount", "voucher", "redeem")):
                race_targets.append(path)
        race_targets.extend(self.COUPON_PATHS)
        race_targets = list(set(race_targets))[:3]

        for path in race_targets:
            req = HttpRequest(
                method="POST",
                path=path,
                body=json.dumps({"code": "TESTCOUPON", "coupon": "TESTCOUPON"}),
                headers={"Content-Type": "application/json"},
                payload="race_condition",
            )
            # Fire 10 requests simultaneously
            tasks = [self._http_probe(req) for _ in range(10)]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            successes = [
                r for r in results
                if not isinstance(r, Exception) and r[0] == 200
                and any(k in r[1].lower() for k in ("success", "applied", "discount", "credit"))
            ]
            if len(successes) > 1:
                self.console.print(
                    f"[red][BizLogic] Race condition at {path}! "
                    f"{len(successes)}/10 concurrent requests succeeded.[/red]"
                )
                self.vulns.append(Vuln(
                    name="[DYNAMIC] Race Condition — Concurrent Request Abuse",
                    cwe="CWE-362",
                    severity="High",
                    endpoint=path,
                    payload="10 concurrent identical POST requests",
                    confirmed=True,
                    evidence=f"{len(successes)} of 10 concurrent requests received success response",
                    fix="Implement atomic DB operations with transactions/locks; use idempotency keys.",
                ))
                return

    async def _test_price_tampering(self, context: ScanContext) -> None:
        """Try negative quantities, zero price, and float overflow in cart/order."""
        tamper_bodies = [
            {"quantity": -1, "price": 0.01},
            {"quantity": 0, "amount": -100},
            {"price": -99.99},
            {"total": 0.001},
            {"quantity": 99999999, "price": 0},
        ]
        cart_paths = [
            p for p in self.asi.endpoints
            if any(kw in p.lower() for kw in ("cart", "basket", "order", "buy"))
        ] + self.CART_PATHS

        for path in list(set(cart_paths))[:3]:
            for body in tamper_bodies:
                req = HttpRequest(
                    method="POST",
                    path=path,
                    body=json.dumps(body),
                    headers={"Content-Type": "application/json"},
                    payload=json.dumps(body),
                )
                status, resp_body, elapsed, headers = await self._http_probe(req)
                self.asi.ingest_response(path, "POST", req.body, status, resp_body, headers)
                if status in (200, 201) and any(
                    k in resp_body.lower() for k in ("success", "added", "total", "created")
                ):
                    self.console.print(
                        f"[red][BizLogic] Price tampering accepted at {path}! body={body}[/red]"
                    )
                    self.vulns.append(Vuln(
                        name="[DYNAMIC] Business Logic — Price Tampering",
                        cwe="CWE-20",
                        severity="High",
                        endpoint=path,
                        payload=json.dumps(body),
                        confirmed=True,
                        evidence=f"Server accepted malformed price/quantity — HTTP {status}",
                        fix="Validate all numeric inputs server-side; fetch price from DB, never trust client.",
                    ))
                    return

    async def _test_workflow_bypass(self, context: ScanContext) -> None:
        """Try accessing later workflow steps without completing earlier ones."""
        checkout_paths = [
            p for p in self.asi.endpoints
            if any(kw in p.lower() for kw in ("checkout", "payment", "confirm", "complete"))
        ] + self.CHECKOUT_PATHS

        for path in list(set(checkout_paths))[:3]:
            req = HttpRequest(
                method="GET",
                path=path,
                payload="workflow_bypass",
            )
            status, body, elapsed, headers = await self._http_probe(req)
            self.asi.ingest_response(path, "GET", "", status, body, headers)
            # If checkout page is accessible directly (no cart/session required)
            if status == 200 and len(body) > 100:
                self.console.print(f"[yellow][BizLogic] Checkout accessible directly at {path}[/yellow]")
                self.vulns.append(Vuln(
                    name="[DYNAMIC] Business Logic — Workflow Step Bypass",
                    cwe="CWE-840",
                    severity="Medium",
                    endpoint=path,
                    payload="Direct GET without preceding steps",
                    confirmed=True,
                    evidence=f"Checkout endpoint accessible without authentication or cart state — HTTP 200",
                    fix="Enforce server-side workflow state machine; verify prerequisites before each step.",
                ))
                return
