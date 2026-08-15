"""
CYPHEX — Agent 02: Web Crawler Agent

Builds the full attack surface:
  - Crawls all pages from discovered paths
  - Extracts forms, inputs, parameters
  - Finds JavaScript endpoints
  - Discovers API patterns
  - Identifies file upload points
  - Checks for GraphQL
"""

import re
import shlex
from urllib.parse import urlparse, urljoin, parse_qs

from agents.base_agent import BaseAgent
from models.scan import ScanContext, Vuln, FormData, ParamData
from models.agent_result import AgentResult


class CrawlerAgent(BaseAgent):

    async def run(self, context: ScanContext) -> AgentResult:
        await self.log("═══ CRAWLING PHASE ═══", "info")

        target = context.target_url
        visited = set()
        to_visit = [target]

        # Add discovered paths from recon
        for path in context.discovered_paths:
            full_url = f"{target.rstrip('/')}{path}"
            if full_url not in to_visit:
                to_visit.append(full_url)

        # Common additional paths to check
        extra_paths = [
            # Auth
            "/login", "/register", "/signup", "/logout",
            "/api/login", "/api/auth/login",
            # Common pages
            "/search", "/contact", "/profile", "/about",
            "/dashboard", "/settings", "/admin", "/products",
            "/users", "/comments", "/messages",
            # API
            "/api", "/api/users", "/api/search", "/api/products",
            "/api/comments", "/api/ping", "/api/file",
            "/api/user/1", "/api/user/update",
            # Utilities
            "/redirect", "/check-status", "/status",
            "/upload", "/download", "/export",
        ]
        for path in extra_paths:
            full_url = f"{target.rstrip('/')}{path}"
            if full_url not in to_visit:
                to_visit.append(full_url)

        # ─── Crawl all pages ───
        await self.log(f"Crawling {len(to_visit)} initial URLs...", "info")

        while to_visit and len(visited) < 50:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)

            out = await self.terminal.run(
                f'curl -sL -w "\\n__STATUS__%{{http_code}}" '
                f'--max-time 10 {shlex.quote(url)}'
            )

            if not out.stdout:
                continue

            # Parse status code
            status = "000"
            body = out.stdout
            if "__STATUS__" in out.stdout:
                parts = out.stdout.rsplit("__STATUS__", 1)
                body = parts[0]
                status = parts[1].strip()

            if status in ["404", "000"]:
                continue

            await self.log(f"  Crawled: {url} → HTTP {status}", "info")
            context.sitemap[url] = {"status": status, "size": len(body)}

            # Check for cookies
            cookie_match = re.findall(
                r'Set-Cookie:\s*([^=]+)=([^;\n]+)', body, re.IGNORECASE
            )
            for name, value in cookie_match:
                context.all_cookies[name.strip()] = value.strip()

            # Extract links
            links = self._extract_links(body, url, target)
            for link in links:
                if link not in visited and link not in to_visit:
                    to_visit.append(link)
                if link not in context.all_links:
                    context.all_links.append(link)

            # Extract forms
            forms = self._extract_forms(body, url)
            for form in forms:
                context.all_forms.append(form)
                await self.log(
                    f"  Form: {form.method} {form.action} "
                    f"[{', '.join(form.inputs)}]",
                    "info",
                )

            # Extract URL parameters
            params = self._extract_params(url)
            context.all_params.extend(params)

            # Extract endpoint from linked URLs
            endpoints = self._extract_endpoints(body, url, target)
            for ep in endpoints:
                if ep not in context.all_endpoints:
                    context.all_endpoints.append(ep)

            # Check for XML content type indicators
            if "application/xml" in body.lower() or "<xml" in body.lower():
                context.xml_endpoints.append(url)

        # ─── Check for GraphQL ───
        await self.log("Checking for GraphQL endpoints...", "info")
        gql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/gql"]
        for gql_path in gql_paths:
            gql_url = f"{target.rstrip('/')}{gql_path}"
            out = await self.terminal.run(
                f'curl -s -X POST {shlex.quote(gql_url)} '
                f'-H "Content-Type: application/json" '
                f"""-d "{{\\"query\\":\\"{{__schema{{types{{name}}}}}}\\"}}\" """
                f"--max-time 5"
            )
            if "__schema" in out.stdout or "types" in out.stdout:
                await self.log(f"GraphQL found at {gql_path}!", "danger")
                context.graphql_endpoint = gql_path

        # ─── Check JS files for API endpoints ───
        js_links = [l for l in context.all_links if l.endswith('.js')]
        if js_links:
            await self.log(f"Analyzing {len(js_links)} JavaScript files...", "info")
            for js_url in js_links[:10]:  # Limit to 10 JS files
                out = await self.terminal.run(
                    f'curl -sL --max-time 10 {shlex.quote(js_url)}'
                )
                if out.success:
                    js_endpoints = self._extract_js_endpoints(out.stdout, target)
                    for ep in js_endpoints:
                        if ep not in context.all_endpoints:
                            context.all_endpoints.append(ep)
                            await self.log(f"  JS endpoint: {ep}", "info")

        # ─── Summary ───
        await self.log(
            f"Crawl complete: {len(visited)} pages, "
            f"{len(context.all_forms)} forms, "
            f"{len(context.all_endpoints)} endpoints, "
            f"{len(context.all_params)} params",
            "success",
        )

        return AgentResult(
            agent="CrawlerAgent",
            vulns=self.vulns,
            context=context,
            terminal_logs=self.terminal.command_history,
        )

    def _extract_links(self, html: str, current_url: str, base: str) -> list[str]:
        """Extract all links from HTML."""
        links = []
        parsed_base = urlparse(base)

        # href links
        for match in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
            href = match.group(1)
            full = self._resolve_url(href, current_url, base)
            if full and urlparse(full).hostname == parsed_base.hostname:
                links.append(full)

        # src links (scripts, images) — restrict to same host to prevent SSRF
        for match in re.finditer(r'src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            src = match.group(1)
            full = self._resolve_url(src, current_url, base)
            if full and urlparse(full).hostname == parsed_base.hostname:
                links.append(full)

        # action attributes — restrict to same host to prevent SSRF
        for match in re.finditer(r'action=["\']([^"\']+)["\']', html, re.IGNORECASE):
            action = match.group(1)
            full = self._resolve_url(action, current_url, base)
            if full and urlparse(full).hostname == parsed_base.hostname:
                links.append(full)

        return list(set(links))

    def _resolve_url(self, href: str, current: str, base: str) -> str:
        """Resolve a relative URL to absolute."""
        if href.startswith("http"):
            return href
        if href.startswith("//"):
            return f"https:{href}"
        if href.startswith("/"):
            parsed = urlparse(base)
            return f"{parsed.scheme}://{parsed.netloc}{href}"
        if href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
            return ""
        return urljoin(current, href)

    def _extract_forms(self, html: str, page_url: str) -> list[FormData]:
        """Extract all forms from HTML."""
        forms = []
        # Match form tags
        form_pattern = re.compile(
            r'<form[^>]*>([\s\S]*?)</form>', re.IGNORECASE
        )
        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            inner = form_match.group(1)

            # Get action
            action_match = re.search(
                r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE
            )
            action = action_match.group(1) if action_match else page_url
            if not action.startswith("http"):
                parsed = urlparse(page_url)
                if action.startswith("/"):
                    action = f"{parsed.scheme}://{parsed.netloc}{action}"
                else:
                    action = urljoin(page_url, action)

            # Get method
            method_match = re.search(
                r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE
            )
            method = (method_match.group(1) if method_match else "GET").upper()

            # Get inputs
            inputs = []
            has_file = False
            for inp_match in re.finditer(
                r'<(?:input|textarea|select)[^>]*name=["\']([^"\']+)["\']',
                inner, re.IGNORECASE
            ):
                inputs.append(inp_match.group(1))

            # Check for file upload
            if re.search(r'type=["\']file["\']', inner, re.IGNORECASE):
                has_file = True

            if inputs:
                forms.append(FormData(
                    action=action,
                    method=method,
                    inputs=inputs,
                    page=page_url,
                    has_file_upload=has_file,
                ))

        return forms

    def _extract_params(self, url: str) -> list[ParamData]:
        """Extract URL query parameters."""
        params = []
        parsed = urlparse(url)
        if parsed.query:
            for key, values in parse_qs(parsed.query).items():
                params.append(ParamData(
                    url=url.split("?")[0],
                    name=key,
                    value=values[0] if values else "",
                ))
        return params

    def _extract_endpoints(
        self, html: str, current_url: str, base: str
    ) -> list[str]:
        """Extract API-like endpoints from HTML."""
        endpoints = []
        # Look for API paths
        api_pattern = re.compile(
            r'["\'](/api/[^"\'?\s]+(?:\?[^"\']*)?)["\']', re.IGNORECASE
        )
        for match in api_pattern.finditer(html):
            path = match.group(1)
            parsed = urlparse(base)
            full = f"{parsed.scheme}://{parsed.netloc}{path}"
            endpoints.append(full)

        return endpoints

    def _extract_js_endpoints(self, js_content: str, base: str) -> list[str]:
        """Extract API endpoints from JavaScript source."""
        endpoints = []
        patterns = [
            r'["\'](/api/[^"\'?\s]+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.\w+\(["\']([^"\']+)["\']',
            r'\.get\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']',
        ]
        parsed = urlparse(base)

        for pattern in patterns:
            for match in re.finditer(pattern, js_content):
                path = match.group(1)
                if path.startswith("/"):
                    full = f"{parsed.scheme}://{parsed.netloc}{path}"
                    endpoints.append(full)
                elif path.startswith("http"):
                    endpoints.append(path)

        return list(set(endpoints))
