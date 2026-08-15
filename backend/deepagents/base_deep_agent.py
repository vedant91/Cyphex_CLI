"""
CYPHEX DeepAgents — BaseDeepAgent

Upgraded with:
- Parallel hypothesis testing (asyncio.gather, 3 concurrent probes)
- Baseline latency measurement for time-based blind detection
- Payload mutation on failure (Oracle mutate() call)
- Full Evidence recording into ScanContext.raw_evidence
- Confidence scoring per finding
"""
import time
import asyncio
import httpx
from rich.console import Console

from backend.backend.models.scan import ScanContext, Vuln, Evidence
from backend.backend.models.agent_result import AgentResult
from backend.deepagents.attack_graph import AttackGraph
from backend.deepagents.attack_surface_index import AttackSurfaceIndex
from backend.deepagents.oracle_attack import AttackOracle, Hypothesis, HttpRequest

console = Console()


# How many hypotheses to test in parallel (keep at 3 to avoid hammering target)
_PARALLEL_BATCH = 3
# Minimum confidence threshold to emit a confirmed finding
_CONFIDENCE_THRESHOLD = 60


class HypothesisResult:
    def __init__(self, confirmed: bool, vuln: Vuln = None, confidence: int = 0):
        self.confirmed = confirmed
        self.vuln = vuln
        self.confidence = confidence


class BaseDeepAgent:
    """
    Standalone DeepAgent base — full Observe→Think→Act adaptive loop.
    Uses only local Ollama models — zero external API dependency.
    """

    MAX_HYPOTHESES = 10
    MAX_ATTEMPTS_PER_HYPOTHESIS = 5
    PRIMARY_VULN_CLASS = "Unknown"
    # Parallel batch size (subclasses can lower for expensive tests like time-based)
    PARALLEL_BATCH = _PARALLEL_BATCH

    def __init__(self, scan_id: str, target_url: str, attack_graph: AttackGraph,
                 asi: AttackSurfaceIndex, oracle: AttackOracle, **kwargs):
        self.scan_id = scan_id
        self.target = target_url.rstrip("/")
        self.console = console
        self.graph = attack_graph
        self.asi = asi
        self.oracle = oracle
        self.vulns: list[Vuln] = []
        # Cached baseline latency (measured once per agent run)
        self._baseline_ms: float = 0.0

    # ── Public entry point ────────────────────────────────────────────────────

    async def run(self, context: ScanContext) -> AgentResult:
        console.print(
            f"[cyan]DeepAgent[/cyan] [yellow]{self.__class__.__name__}[/yellow] "
            f"initialising against {self.target}..."
        )

        # Measure baseline response time once
        self._baseline_ms = await self._measure_baseline()

        # Oracle generates attack plan
        surface_summary = self.asi.summarise_for_prompt()
        console.print(f"[dim]DeepAgent {self.__class__.__name__} consulting Oracle...[/dim]")
        try:
            plan = await self.oracle.plan(
                target=self.target,
                surface_summary=surface_summary,
                vuln_class=self.PRIMARY_VULN_CLASS,
            )
            console.print(
                f"[cyan]Oracle[/cyan] generated {len(plan.hypotheses)} hypotheses "
                f"for {self.__class__.__name__}."
            )
        except Exception as e:
            console.print(f"[red]Oracle plan failed for {self.__class__.__name__}: {e}[/red]")
            return AgentResult(agent=self.__class__.__name__, vulns=self.vulns, context=context)

        # Execute hypotheses in parallel batches
        hypotheses = plan.hypotheses[:self.MAX_HYPOTHESES]
        for i in range(0, len(hypotheses), self.PARALLEL_BATCH):
            batch = hypotheses[i:i + self.PARALLEL_BATCH]
            results = await asyncio.gather(
                *[self._test_hypothesis(hyp, context) for hyp in batch],
                return_exceptions=True
            )
            for hyp, result in zip(batch, results):
                if isinstance(result, Exception):
                    console.print(f"[yellow]Hypothesis {hyp.id} errored: {result}[/yellow]")
                    continue
                if result.confirmed and result.vuln:
                    self.vulns.append(result.vuln)
                    new_edges = self.graph.update_from_finding(result.vuln)
                    for edge in new_edges:
                        console.print(
                            f"[green]Attack chain discovered:[/green] "
                            f"{edge.action} {edge.source} → {edge.target}"
                        )

        return AgentResult(
            agent=self.__class__.__name__,
            vulns=self.vulns,
            context=context,
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _measure_baseline(self) -> float:
        """GET the root URL once to establish a response-time baseline."""
        try:
            url = self.target.rstrip("/") + "/"
            if not url.startswith("http"):
                url = "http://" + url
            t0 = time.time()
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                await client.get(url)
            return time.time() - t0
        except Exception:
            return 0.5  # safe fallback

    async def _http_probe(self, request: HttpRequest) -> tuple[int, str, float, dict]:
        """Send the HTTP request and return (status, body, elapsed_s, headers)."""
        # Resolve absolute URL
        path = request.path
        if not path.startswith("http"):
            url = self.target.rstrip("/") + "/" + path.lstrip("/")
        else:
            url = path

        # Inject the payload into the path if it uses the {PAYLOAD} placeholder
        if "{PAYLOAD}" in url and request.payload:
            url = url.replace("{PAYLOAD}", request.payload)

        t0 = time.time()
        try:
            async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=True) as client:
                headers = dict(request.headers or {})
                method = request.method.upper()
                if method == "GET":
                    res = await client.get(url, headers=headers)
                elif method == "POST":
                    content_type = headers.get("Content-Type", "application/x-www-form-urlencoded")
                    if "json" in content_type:
                        res = await client.post(url, headers=headers, content=request.body)
                    else:
                        res = await client.post(url, headers=headers, data=request.body)
                elif method == "PUT":
                    res = await client.put(url, headers=headers, content=request.body)
                elif method == "DELETE":
                    res = await client.delete(url, headers=headers)
                elif method == "PATCH":
                    res = await client.patch(url, headers=headers, content=request.body)
                else:
                    res = await client.request(method, url, headers=headers, content=request.body)

                elapsed = time.time() - t0
                return res.status_code, res.text, elapsed, dict(res.headers)
        except Exception as e:
            elapsed = time.time() - t0
            return 0, str(e), elapsed, {}

    async def _record_evidence(self, context: ScanContext, request: HttpRequest,
                                status: int, body: str) -> None:
        """Append a raw Evidence record to the shared ScanContext."""
        url = self.target.rstrip("/") + "/" + request.path.lstrip("/")
        context.raw_evidence.append(Evidence(
            request_method=request.method,
            request_url=url,
            request_body=request.body or request.payload,
            response_status=status,
            response_body=body,
        ))

    async def _test_hypothesis(self, hyp: Hypothesis,
                                context: ScanContext) -> HypothesisResult:
        """
        Test one hypothesis through up to MAX_ATTEMPTS_PER_HYPOTHESIS probes.
        On failure, asks Oracle to mutate the payload and tries variants.
        """
        current_request = hyp.test_request

        for attempt in range(self.MAX_ATTEMPTS_PER_HYPOTHESIS):
            status, body, elapsed, headers = await self._http_probe(current_request)

            # Dead-route guard: a 404 means the route does not exist; a 0 means the
            # request failed to connect. No amount of payload mutation makes a
            # non-existent endpoint vulnerable, so abandon immediately instead of
            # burning MAX_ATTEMPTS × (Oracle decide + mutate) slow local-LLM calls
            # on it. This is what turned a handful of dead routes into ~39 minutes.
            if status in (404, 0):
                console.print(
                    f"[dim]  [{hyp.id}] {current_request.path} → HTTP {status}: "
                    f"dead route, abandoning (no Oracle call)[/dim]"
                )
                return HypothesisResult(False)

            # Update ASI with observation
            self.asi.ingest_response(
                url=current_request.path,
                method=current_request.method,
                body=current_request.body,
                status=status,
                response_body=body,
                headers=headers,
            )

            # Record evidence
            await self._record_evidence(context, current_request, status, body)

            # Oracle evaluates
            try:
                decision = await self.oracle.decide(
                    hypothesis=hyp,
                    response_status=status,
                    response_body=body,
                    response_time=elapsed,
                    attempt=attempt,
                    baseline_time=self._baseline_ms,
                )
            except Exception as e:
                console.print(f"[red]Oracle decide failed: {e}[/red]")
                break

            console.print(
                f"[dim]  [{hyp.id}] attempt {attempt+1} → {decision.action} "
                f"(conf={decision.confidence}%) {decision.thinking}[/dim]"
            )

            if decision.action == "confirmed" and decision.vuln:
                if decision.confidence >= _CONFIDENCE_THRESHOLD:
                    v = decision.vuln
                    vuln = Vuln(
                        name=v.get("name", hyp.vuln_type),
                        cwe=v.get("cwe", hyp.cwe),
                        severity=v.get("severity", hyp.severity),
                        endpoint=current_request.path,
                        payload=current_request.payload or current_request.body,
                        confirmed=True,
                        evidence=v.get("evidence", body[:300]),
                        fix=v.get("fix", ""),
                        description=(
                            f"Confirmed {hyp.vuln_type} on {current_request.path}. "
                            f"Confidence: {decision.confidence}%"
                        ),
                    )
                    return HypothesisResult(True, vuln, decision.confidence)

            if decision.action == "abandoned":
                return HypothesisResult(False)

            if decision.action == "adapt":
                if decision.next_probe:
                    # Oracle gave us a better probe
                    current_request = decision.next_probe
                    hyp.test_request = current_request
                else:
                    # Ask Oracle to mutate the current payload
                    variants = await self.oracle.mutate(
                        payload=current_request.payload or current_request.body,
                        vuln_class=self.PRIMARY_VULN_CLASS,
                        reason=f"HTTP {status}, decision=adapt",
                    )
                    if variants:
                        # Try the first variant immediately
                        new_payload = variants[0]
                        # Build a new request with the mutated payload
                        new_path = current_request.path
                        if current_request.payload and current_request.payload in new_path:
                            new_path = new_path.replace(current_request.payload, new_payload)
                        current_request = HttpRequest(
                            method=current_request.method,
                            path=new_path,
                            body=current_request.body.replace(
                                current_request.payload, new_payload
                            ) if current_request.payload in current_request.body else current_request.body,
                            headers=current_request.headers,
                            payload=new_payload,
                        )
                        hyp.test_request = current_request

        return HypothesisResult(False)
