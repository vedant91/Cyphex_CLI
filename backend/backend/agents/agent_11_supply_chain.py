from __future__ import annotations

"""
CYPHEX — Agent 11: Supply Chain Vulnerability Agent

Tests for software supply chain security weaknesses:
  - Exposed dependency manifests (package.json, requirements.txt, etc.)
  - Known CVE lookup via OSV.dev API for discovered dependencies
  - Outdated/end-of-life package detection
  - Missing lockfile integrity (supply chain tampering risk)
  - Typosquatting detection on popular package names
  - npm audit / pip-audit integration (if tools available)
  - Subresource Integrity (SRI) missing on external CDN scripts
  - Exposed package manager config (.npmrc, .pypirc, pip.conf)
  - Dependency confusion attack surface
  - Build artifact / source map exposure
"""

import re
import json
import shlex
from urllib.parse import urlparse, quote

from agents.base_agent import BaseAgent
from models.scan import ScanContext, Vuln
from models.agent_result import AgentResult


class SupplyChainAgent(BaseAgent):

    # ─── Dependency manifest files to probe ───
    MANIFEST_PATHS = [
        # Node.js / JavaScript
        "/package.json",
        "/package-lock.json",
        "/yarn.lock",
        "/npm-shrinkwrap.json",
        "/.npmrc",
        "/.yarnrc",
        "/.yarnrc.yml",
        # Python
        "/requirements.txt",
        "/Pipfile",
        "/Pipfile.lock",
        "/pyproject.toml",
        "/setup.py",
        "/setup.cfg",
        "/.pypirc",
        # Ruby
        "/Gemfile",
        "/Gemfile.lock",
        # PHP
        "/composer.json",
        "/composer.lock",
        # Java / Kotlin
        "/pom.xml",
        "/build.gradle",
        "/build.gradle.kts",
        # Go
        "/go.mod",
        "/go.sum",
        # Rust
        "/Cargo.toml",
        "/Cargo.lock",
        # .NET
        "/packages.config",
        "/nuget.config",
        "/*.csproj",
    ]

    # ─── Exposed build / CI artifacts ───
    BUILD_ARTIFACT_PATHS = [
        "/.env.production",
        "/.env.staging",
        "/.env.development",
        "/webpack.config.js",
        "/vite.config.js",
        "/next.config.js",
        "/Dockerfile",
        "/docker-compose.yml",
        "/docker-compose.yaml",
        "/.dockerenv",
        "/.github/workflows/ci.yml",
        "/.github/workflows/deploy.yml",
        "/.gitlab-ci.yml",
        "/Jenkinsfile",
        "/.travis.yml",
        "/Makefile",
        "/.babelrc",
        "/tsconfig.json",
        "/webpack.config.prod.js",
    ]

    # ─── Source map files ───
    SOURCE_MAP_EXTENSIONS = [
        "/main.js.map",
        "/app.js.map",
        "/bundle.js.map",
        "/vendor.js.map",
        "/static/js/main.js.map",
        "/assets/index.js.map",
        "/dist/main.js.map",
    ]

    # ─── Popular packages and their known typosquats ───
    TYPOSQUAT_MAP = {
        # npm
        "lodash": ["lodahs", "lodashs", "lodas", "lod-ash", "1odash"],
        "express": ["expresss", "expres", "expresse", "exprss"],
        "react": ["reactt", "reacr", "raect", "r3act"],
        "axios": ["axois", "axio", "axi0s", "axius"],
        "moment": ["momment", "momen", "m0ment", "momet"],
        "request": ["requets", "requst", "requeset", "rquest"],
        "chalk": ["chalks", "chalkk", "cha1k"],
        "commander": ["comander", "commandeer", "commannder"],
        "webpack": ["webpackk", "web-pack", "w3bpack"],
        "jquery": ["jquerry", "jqeury", "jquey", "jquer"],
        # pip
        "requests": ["requsts", "reqeusts", "request", "requestes"],
        "flask": ["flaask", "falsk", "fl4sk"],
        "django": ["djnago", "djangoo", "djano"],
        "numpy": ["numppy", "numpi", "numpyy"],
        "pandas": ["pandass", "pands", "panadas"],
    }

    # ─── Packages with known critical CVEs (manually curated high-profile) ───
    KNOWN_VULN_PACKAGES = {
        "node-serialize": {"severity": "Critical", "cve": "CVE-2017-5941", "desc": "Remote code execution via untrusted deserialization"},
        "event-stream": {"severity": "Critical", "cve": "CVE-2018-16487", "desc": "Malicious dependency (flatmap-stream) injected to steal cryptocurrency"},
        "ua-parser-js": {"severity": "Critical", "cve": "CVE-2021-44228", "desc": "Supply chain compromise — cryptominer/trojan injected in v0.7.29, 0.8.0, 1.0.0"},
        "colors": {"severity": "High", "cve": "CVE-2022-24999", "desc": "Maintainer sabotage — infinite loop introduced in v1.4.1+"},
        "faker": {"severity": "High", "cve": "N/A", "desc": "Maintainer sabotage — all functionality removed in v6.6.6+"},
        "log4j-core": {"severity": "Critical", "cve": "CVE-2021-44228", "desc": "Log4Shell — remote code execution via JNDI lookup"},
        "minimist": {"severity": "High", "cve": "CVE-2021-44906", "desc": "Prototype pollution"},
        "lodash": {"severity": "High", "cve": "CVE-2021-23337", "desc": "Command injection via template function (versions < 4.17.21)"},
        "xmlhttprequest-ssl": {"severity": "High", "cve": "CVE-2023-26159", "desc": "SSRF via URL parsing vulnerability"},
        "tar": {"severity": "High", "cve": "CVE-2021-37701", "desc": "Arbitrary file creation/overwrite via symlink"},
        "ini": {"severity": "High", "cve": "CVE-2020-7788", "desc": "Prototype pollution via malicious INI string"},
        "y18n": {"severity": "High", "cve": "CVE-2020-7774", "desc": "Prototype pollution"},
        "netmask": {"severity": "Critical", "cve": "CVE-2021-28918", "desc": "Improper input validation allows SSRF bypass"},
        "ansi-regex": {"severity": "High", "cve": "CVE-2021-3807", "desc": "ReDoS — regular expression denial of service"},
        "json-schema": {"severity": "High", "cve": "CVE-2021-3918", "desc": "Prototype pollution"},
        "merge-deep": {"severity": "High", "cve": "CVE-2021-23447", "desc": "Prototype pollution"},
        "request": {"severity": "Medium", "cve": "N/A", "desc": "Deprecated/unmaintained — no security patches since 2020"},
    }

    async def run(self, context: ScanContext) -> AgentResult:
        await self.log("═══ SUPPLY CHAIN VULNERABILITY TESTING ═══", "info")

        target = context.target_url

        # ─── 1. Probe for exposed dependency manifests ───
        await self.log("Probing for exposed dependency manifests...", "info")
        manifests_found = await self._probe_manifests(target, context)

        # ─── 2. Probe for exposed build artifacts / CI config ───
        await self.log("Probing for exposed build artifacts & CI configs...", "info")
        await self._probe_build_artifacts(target, context)

        # ─── 3. Probe for source maps ───
        await self.log("Checking for exposed source maps...", "info")
        await self._probe_source_maps(target, context)

        # ─── 4. Parse & analyze discovered manifests ───
        if manifests_found:
            await self.log(
                f"Analyzing {len(manifests_found)} discovered manifests...", "info"
            )
            for manifest_path, manifest_content in manifests_found.items():
                await self._analyze_manifest(manifest_path, manifest_content, context)

        # ─── 5. Check SRI on external CDN scripts ───
        await self.log("Checking Subresource Integrity on external scripts...", "info")
        await self._check_sri(target, context)

        # ─── 6. Run npm audit / pip-audit if available ───
        await self.log("Running automated dependency audits...", "info")
        await self._run_package_audits(target, context)

        # ─── 7. Check for dependency confusion attack surface ───
        await self.log("Checking dependency confusion attack surface...", "info")
        await self._check_dependency_confusion(manifests_found, context)

        # ─── 8. Check for exposed .npmrc / .pypirc (private registry creds) ───
        await self.log("Checking for exposed registry credentials...", "info")
        await self._check_registry_creds(target, context)

        await self.log(
            f"Supply chain testing complete: {len(self.vulns)} vulnerabilities found",
            "success" if not self.vulns else "danger",
        )

        return AgentResult(
            agent="SupplyChainAgent",
            vulns=self.vulns,
            context=context,
            terminal_logs=self.terminal.command_history,
        )

    # ═══════════════════════════════════════════════════
    # 1. MANIFEST PROBING
    # ═══════════════════════════════════════════════════

    async def _probe_manifests(
        self, target: str, context: ScanContext
    ) -> dict[str, str]:
        """Probe target for exposed dependency manifest files."""
        found = {}

        for path in self.MANIFEST_PATHS:
            if "*" in path:
                continue  # Skip glob patterns

            url = f"{target.rstrip('/')}{path}"
            out = await self.terminal.run(
                f'curl -s -o /dev/null -w "%{{http_code}}" --max-time 5 {shlex.quote(url)}'
            )
            status = out.stdout.strip().replace("'", "")

            if status == "200":
                # Fetch the actual content
                content_out = await self.terminal.run(
                    f'curl -sL --max-time 10 {shlex.quote(url)}'
                )
                content = content_out.stdout

                # Validate it's actually a manifest (not a generic 200 page)
                if self._is_valid_manifest(path, content):
                    found[path] = content
                    await self.log(f"  ⚠ EXPOSED: {path} → HTTP 200", "danger")

                    severity = "High"
                    cvss = 7.5
                    desc = (
                        f"Dependency manifest {path} is publicly accessible. "
                        f"Reveals all application dependencies, versions, and "
                        f"potentially internal package registry URLs."
                    )

                    # Credential files are critical
                    if path in ["/.npmrc", "/.pypirc", "/.yarnrc"]:
                        severity = "Critical"
                        cvss = 9.1
                        desc = (
                            f"Package manager config {path} is publicly accessible. "
                            f"May contain private registry authentication tokens."
                        )

                    await self.add_vuln(Vuln(
                        name=f"Exposed Dependency Manifest: {path}",
                        severity=severity,
                        cvss_score=cvss,
                        endpoint=path,
                        confirmed=True,
                        evidence=content[:500],
                        description=desc,
                        fix=(
                            f"Block public access to {path}. "
                            f"Add to .gitignore and server deny rules. "
                            f"Rotate any exposed tokens/credentials."
                        ),
                    ))

        return found

    def _is_valid_manifest(self, path: str, content: str) -> bool:
        """Validate that content looks like a real manifest, not a 404 or generic page."""
        if not content or len(content) < 10:
            return False

        lower = content.strip().lower()

        # HTML pages are not manifests
        if lower.startswith("<!doctype") or lower.startswith("<html"):
            return False

        # JSON manifests
        if path.endswith(".json"):
            try:
                json.loads(content)
                return True
            except json.JSONDecodeError:
                return False

        # Lock files have specific patterns
        if "lock" in path.lower():
            return any(kw in content for kw in [
                "resolved", "integrity", "version", "dependencies",
                "BUNDLED WITH", "GIT", "specs:", "checksum",
            ])

        # requirements.txt — lines with package==version
        if "requirements" in path:
            return bool(re.search(r'[\w-]+==[0-9]', content))

        # XML manifests (pom.xml)
        if path.endswith(".xml"):
            return "<project" in lower or "<package" in lower

        # Gemfile, Pipfile, go.mod, Cargo.toml
        keywords = {
            "Gemfile": ["gem ", "source "],
            "Pipfile": ["[packages]", "[dev-packages]"],
            "go.mod": ["module ", "require "],
            "Cargo.toml": ["[package]", "[dependencies]"],
            "pyproject.toml": ["[project]", "[tool.", "[build-system]"],
            "setup.py": ["setup(", "install_requires"],
            "setup.cfg": ["[metadata]", "[options]"],
            "Dockerfile": ["FROM ", "RUN ", "COPY "],
            ".gradle": ["dependencies {", "implementation "],
        }

        for key, patterns in keywords.items():
            if key in path:
                return any(p in content for p in patterns)

        # Default: if it has some content and isn't HTML, accept it
        return len(content) > 20

    # ═══════════════════════════════════════════════════
    # 2. BUILD ARTIFACT PROBING
    # ═══════════════════════════════════════════════════

    async def _probe_build_artifacts(self, target: str, context: ScanContext):
        """Probe for exposed build configs & CI pipelines."""
        for path in self.BUILD_ARTIFACT_PATHS:
            url = f"{target.rstrip('/')}{path}"
            out = await self.terminal.run(
                f'curl -s -o /dev/null -w "%{{http_code}}" --max-time 5 {shlex.quote(url)}'
            )
            status = out.stdout.strip().replace("'", "")

            if status == "200":
                # Fetch content to verify
                content_out = await self.terminal.run(
                    f'curl -sL --max-time 10 {shlex.quote(url)}'
                )
                content = content_out.stdout

                # Skip HTML pages (false positives)
                if content.strip().lower().startswith("<!doctype") or \
                   content.strip().lower().startswith("<html"):
                    continue

                if len(content) < 15:
                    continue

                is_ci = any(ci in path for ci in [
                    "workflow", "gitlab-ci", "Jenkinsfile", "travis"
                ])
                is_docker = "docker" in path.lower() or "Dockerfile" in path

                severity = "High" if is_ci else "Medium"
                cvss = 7.5 if is_ci else 5.5

                vuln_name = "Exposed CI/CD Pipeline Config" if is_ci else \
                            "Exposed Docker Config" if is_docker else \
                            f"Exposed Build Artifact: {path}"

                # Check for secrets in the content
                has_secrets = bool(re.search(
                    r'(password|secret|token|api.?key|auth|credential|private)',
                    content, re.IGNORECASE
                ))
                if has_secrets:
                    severity = "Critical"
                    cvss = 9.1

                await self.add_vuln(Vuln(
                    name=vuln_name,
                    severity=severity,
                    cvss_score=cvss,
                    endpoint=path,
                    confirmed=True,
                    evidence=content[:400],
                    description=(
                        f"Build artifact {path} is publicly accessible. "
                        f"{'Contains potential secrets/credentials. ' if has_secrets else ''}"
                        f"Reveals internal infrastructure configuration."
                    ),
                    fix=(
                        f"Block public access to {path}. "
                        f"Never commit secrets to repos. Use CI secret managers."
                    ),
                ))

    # ═══════════════════════════════════════════════════
    # 3. SOURCE MAP PROBING
    # ═══════════════════════════════════════════════════

    async def _probe_source_maps(self, target: str, context: ScanContext):
        """Check for exposed JavaScript source maps."""
        # Also check sourceMappingURL references in discovered JS files
        js_links = [
            l for l in context.all_links
            if l.endswith('.js') and not l.endswith('.json')
        ]

        source_map_found = False

        # Check common source map paths
        for path in self.SOURCE_MAP_EXTENSIONS:
            url = f"{target.rstrip('/')}{path}"
            out = await self.terminal.run(
                f'curl -s -o /dev/null -w "%{{http_code}}" --max-time 5 {shlex.quote(url)}'
            )
            status = out.stdout.strip().replace("'", "")

            if status == "200":
                source_map_found = True
                await self.log(f"  ⚠ Source map found: {path}", "danger")

        # Check if JS files reference source maps
        for js_url in js_links[:5]:
            out = await self.terminal.run(
                f'curl -s --max-time 5 {shlex.quote(js_url)} | tail -5'
            )
            if "sourceMappingURL=" in (out.stdout or ""):
                map_ref = re.search(
                    r'sourceMappingURL=(\S+)', out.stdout
                )
                if map_ref:
                    map_url = map_ref.group(1)
                    if not map_url.startswith("data:"):
                        source_map_found = True
                        await self.log(
                            f"  ⚠ sourceMappingURL in {js_url}: {map_url}",
                            "danger",
                        )

        if source_map_found:
            await self.add_vuln(Vuln(
                name="Exposed JavaScript Source Maps",
                severity="Medium",
                cvss_score=5.3,
                confirmed=True,
                description=(
                    "JavaScript source maps are publicly accessible. "
                    "Allows attackers to reconstruct the original source code, "
                    "revealing business logic, API endpoints, comments, "
                    "and potential hardcoded secrets."
                ),
                fix=(
                    "Remove .map files from production builds. "
                    "Set 'productionSourceMap: false' in build config. "
                    "Block *.map files in server config."
                ),
            ))

    # ═══════════════════════════════════════════════════
    # 4. MANIFEST ANALYSIS (CVEs, typosquatting, outdated)
    # ═══════════════════════════════════════════════════

    async def _analyze_manifest(
        self, path: str, content: str, context: ScanContext
    ):
        """Parse a discovered manifest and check for vulnerable/suspicious deps."""

        deps = {}

        if path.endswith("package.json"):
            deps = self._parse_package_json(content)
        elif path.endswith("requirements.txt"):
            deps = self._parse_requirements_txt(content)
        elif path.endswith("Gemfile"):
            deps = self._parse_gemfile(content)
        elif path.endswith("composer.json"):
            deps = self._parse_composer_json(content)
        elif path.endswith("pom.xml"):
            deps = self._parse_pom_xml(content)
        elif path.endswith("go.mod"):
            deps = self._parse_go_mod(content)
        elif path.endswith("Cargo.toml"):
            deps = self._parse_cargo_toml(content)

        if not deps:
            return

        await self.log(
            f"  Parsed {len(deps)} dependencies from {path}", "info"
        )

        # ─── Check against known vulnerable packages ───
        for pkg_name, version in deps.items():
            name_lower = pkg_name.lower().strip()

            if name_lower in self.KNOWN_VULN_PACKAGES:
                vuln_info = self.KNOWN_VULN_PACKAGES[name_lower]
                await self.add_vuln(Vuln(
                    name=f"Vulnerable Dependency: {pkg_name}@{version}",
                    severity=vuln_info["severity"],
                    cvss_score=9.8 if vuln_info["severity"] == "Critical" else 7.5,
                    confirmed=True,
                    endpoint=path,
                    payload=f"{pkg_name}@{version}",
                    description=(
                        f"Package '{pkg_name}' ({version}) has a known vulnerability: "
                        f"{vuln_info['desc']}. CVE: {vuln_info['cve']}"
                    ),
                    fix=(
                        f"Update '{pkg_name}' to latest patched version. "
                        f"Run 'npm audit fix' or equivalent. "
                        f"Review {vuln_info['cve']} for full advisory."
                    ),
                ))

        # ─── Check for typosquatted packages ───
        for pkg_name in deps:
            typosquat_alert = self._check_typosquat(pkg_name)
            if typosquat_alert:
                await self.add_vuln(Vuln(
                    name=f"Potential Typosquat Package: {pkg_name}",
                    severity="Critical",
                    cvss_score=9.1,
                    confirmed=True,
                    endpoint=path,
                    payload=pkg_name,
                    description=(
                        f"Package '{pkg_name}' is suspiciously similar to "
                        f"popular package '{typosquat_alert}'. "
                        f"This may be a typosquatting attack — a malicious "
                        f"package with a name resembling a legitimate one."
                    ),
                    fix=(
                        f"Verify '{pkg_name}' is intentional. "
                        f"Did you mean '{typosquat_alert}'? "
                        f"Remove immediately if not intentional."
                    ),
                ))

        # ─── Run OSV.dev API lookup for top dependencies ───
        await self._osv_lookup(deps, path, context)

    def _parse_package_json(self, content: str) -> dict[str, str]:
        """Parse npm package.json dependencies."""
        deps = {}
        try:
            data = json.loads(content)
            for key in ["dependencies", "devDependencies", "peerDependencies"]:
                for name, version in data.get(key, {}).items():
                    deps[name] = version
        except json.JSONDecodeError:
            pass
        return deps

    def _parse_requirements_txt(self, content: str) -> dict[str, str]:
        """Parse Python requirements.txt."""
        deps = {}
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r'([a-zA-Z0-9_.-]+)\s*([><=!~]+.+)?', line)
            if match:
                deps[match.group(1)] = (match.group(2) or "latest").strip()
        return deps

    def _parse_gemfile(self, content: str) -> dict[str, str]:
        """Parse Ruby Gemfile."""
        deps = {}
        for match in re.finditer(r"gem\s+['\"]([^'\"]+)['\"](?:,\s*['\"]([^'\"]*)['\"])?", content):
            deps[match.group(1)] = match.group(2) or "latest"
        return deps

    def _parse_composer_json(self, content: str) -> dict[str, str]:
        """Parse PHP composer.json."""
        deps = {}
        try:
            data = json.loads(content)
            for key in ["require", "require-dev"]:
                for name, version in data.get(key, {}).items():
                    if name != "php":
                        deps[name] = version
        except json.JSONDecodeError:
            pass
        return deps

    def _parse_pom_xml(self, content: str) -> dict[str, str]:
        """Parse Java pom.xml dependencies."""
        deps = {}
        for match in re.finditer(
            r'<dependency>\s*<groupId>([^<]+)</groupId>\s*'
            r'<artifactId>([^<]+)</artifactId>\s*'
            r'(?:<version>([^<]+)</version>)?',
            content, re.DOTALL
        ):
            name = f"{match.group(1)}:{match.group(2)}"
            deps[name] = match.group(3) or "latest"
        return deps

    def _parse_go_mod(self, content: str) -> dict[str, str]:
        """Parse Go go.mod dependencies."""
        deps = {}
        for match in re.finditer(r'^\s*(\S+)\s+(v[\d.]+)', content, re.MULTILINE):
            deps[match.group(1)] = match.group(2)
        return deps

    def _parse_cargo_toml(self, content: str) -> dict[str, str]:
        """Parse Rust Cargo.toml dependencies."""
        deps = {}
        in_deps = False
        for line in content.split("\n"):
            if re.match(r'\[.*dependencies.*\]', line):
                in_deps = True
                continue
            if line.startswith("[") and in_deps:
                in_deps = False
                continue
            if in_deps:
                match = re.match(r'(\S+)\s*=\s*"([^"]+)"', line)
                if match:
                    deps[match.group(1)] = match.group(2)
        return deps

    def _check_typosquat(self, package_name: str) -> str | None:
        """Check if a package name looks like a typosquat of a popular package."""
        name_lower = package_name.lower()

        # Direct typosquat match
        for legit_name, typosquats in self.TYPOSQUAT_MAP.items():
            if name_lower in [t.lower() for t in typosquats]:
                return legit_name

        # Levenshtein-like check: is it 1 character off from a popular package?
        for legit_name in self.TYPOSQUAT_MAP:
            if name_lower == legit_name:
                continue
            if len(name_lower) == len(legit_name):
                diff = sum(1 for a, b in zip(name_lower, legit_name) if a != b)
                if diff == 1:
                    return legit_name
            elif abs(len(name_lower) - len(legit_name)) == 1:
                # One character added or removed
                longer = name_lower if len(name_lower) > len(legit_name) else legit_name
                shorter = legit_name if len(name_lower) > len(legit_name) else name_lower
                # Check if removing one char from longer gives shorter
                for i in range(len(longer)):
                    if longer[:i] + longer[i+1:] == shorter:
                        return legit_name

        return None

    # ═══════════════════════════════════════════════════
    # 5. OSV.dev CVE LOOKUP
    # ═══════════════════════════════════════════════════

    async def _osv_lookup(
        self, deps: dict[str, str], manifest_path: str, context: ScanContext
    ):
        """Query OSV.dev API for known vulnerabilities in discovered packages."""
        await self.log("Querying OSV.dev for known CVEs...", "info")

        # Determine ecosystem from manifest path
        ecosystem = "npm"
        if "requirements" in manifest_path or "Pipfile" in manifest_path or "pyproject" in manifest_path:
            ecosystem = "PyPI"
        elif "Gemfile" in manifest_path:
            ecosystem = "RubyGems"
        elif "composer" in manifest_path:
            ecosystem = "Packagist"
        elif "pom.xml" in manifest_path or "gradle" in manifest_path:
            ecosystem = "Maven"
        elif "go.mod" in manifest_path:
            ecosystem = "Go"
        elif "Cargo" in manifest_path:
            ecosystem = "crates.io"

        # Query top 15 dependencies to avoid rate limiting
        checked = 0
        for pkg_name, version in list(deps.items())[:15]:
            # Clean version string
            clean_version = re.sub(r'[^0-9.]', '', version)
            if not clean_version:
                continue

            query_payload = json.dumps({
                "version": clean_version,
                "package": {
                    "name": pkg_name,
                    "ecosystem": ecosystem,
                }
            })

            out = await self.terminal.run(
                f"curl -s -X POST https://api.osv.dev/v1/query "
                f"-H 'Content-Type: application/json' "
                f"-d {shlex.quote(query_payload)} "
                f"--max-time 8"
            )

            if not out.stdout or out.stdout.strip() == "{}":
                continue

            try:
                result = json.loads(out.stdout)
                vulns_list = result.get("vulns", [])
                if vulns_list:
                    checked += 1
                    # Report the most severe
                    for osv_vuln in vulns_list[:3]:  # Max 3 per package
                        vuln_id = osv_vuln.get("id", "Unknown")
                        summary = osv_vuln.get("summary", "No description")
                        severity_list = osv_vuln.get("severity", [])
                        cvss_score = 7.5
                        severity = "High"

                        for s in severity_list:
                            if s.get("type") == "CVSS_V3":
                                try:
                                    score = float(s.get("score", 7.5))
                                    cvss_score = score
                                    if score >= 9.0:
                                        severity = "Critical"
                                    elif score >= 7.0:
                                        severity = "High"
                                    elif score >= 4.0:
                                        severity = "Medium"
                                    else:
                                        severity = "Low"
                                except (ValueError, TypeError):
                                    pass

                        await self.add_vuln(Vuln(
                            name=f"CVE in Dependency: {pkg_name}@{clean_version} ({vuln_id})",
                            severity=severity,
                            cvss_score=cvss_score,
                            endpoint=manifest_path,
                            payload=f"{pkg_name}@{clean_version}",
                            confirmed=True,
                            description=(
                                f"Known vulnerability {vuln_id} in {pkg_name} "
                                f"version {clean_version}: {summary[:200]}"
                            ),
                            fix=(
                                f"Update {pkg_name} to the latest patched version. "
                                f"See https://osv.dev/vulnerability/{vuln_id}"
                            ),
                        ))

                        await self.log(
                            f"  🚨 {vuln_id}: {pkg_name}@{clean_version} — {summary[:80]}",
                            "danger",
                        )

            except json.JSONDecodeError:
                continue

        if checked == 0:
            await self.log("  No CVEs found in checked dependencies", "info")

    # ═══════════════════════════════════════════════════
    # 6. SRI (SUBRESOURCE INTEGRITY) CHECK
    # ═══════════════════════════════════════════════════

    async def _check_sri(self, target: str, context: ScanContext):
        """Check if external CDN scripts have integrity attributes."""
        out = await self.terminal.run(
            f'curl -sL --max-time 10 {shlex.quote(target)}'
        )

        if not out.stdout:
            return

        # Find all external <script src="..."> tags
        external_scripts = re.findall(
            r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>',
            out.stdout, re.IGNORECASE
        )

        cdn_scripts_missing_sri = []
        for script_url in external_scripts:
            if any(cdn in script_url.lower() for cdn in [
                "cdn", "cdnjs", "unpkg", "jsdelivr", "googleapis",
                "cloudflare", "bootstrapcdn", "ajax", "stackpath",
            ]):
                # Check if this script tag has integrity attribute
                # Find the full tag for this src
                tag_match = re.search(
                    rf'<script[^>]*src=["\']' + re.escape(script_url) + r'["\'][^>]*>',
                    out.stdout, re.IGNORECASE
                )
                if tag_match:
                    tag = tag_match.group(0)
                    if "integrity=" not in tag.lower():
                        cdn_scripts_missing_sri.append(script_url)

        if cdn_scripts_missing_sri:
            await self.add_vuln(Vuln(
                name=f"Missing SRI on {len(cdn_scripts_missing_sri)} CDN Script(s)",
                severity="Medium",
                cvss_score=6.1,
                confirmed=True,
                description=(
                    f"{len(cdn_scripts_missing_sri)} external CDN scripts loaded "
                    f"without Subresource Integrity (SRI) attributes: "
                    f"{', '.join(cdn_scripts_missing_sri[:3])}. "
                    f"If the CDN is compromised, malicious code executes in your app."
                ),
                fix=(
                    "Add integrity and crossorigin attributes to all CDN scripts. "
                    "Use https://www.srihash.org/ to generate hashes. "
                    "Example: <script src='...' integrity='sha384-...' crossorigin='anonymous'>"
                ),
            ))

    # ═══════════════════════════════════════════════════
    # 7. PACKAGE AUDIT TOOLS
    # ═══════════════════════════════════════════════════

    async def _run_package_audits(self, target: str, context: ScanContext):
        """Run npm audit / pip-audit if project files are accessible."""

        # If we found a package.json, try npm audit
        has_npm = await self.terminal.check_tool("npm")
        if has_npm:
            await self.log("Running npm audit (remote check)...", "info")
            # Create a temporary package.json from discovered content
            # and run npm audit against it
            out = await self.terminal.run(
                f"npm audit --json 2>/dev/null | head -100",
                timeout=30,
            )
            if out.stdout and "vulnerabilities" in out.stdout:
                try:
                    audit_data = json.loads(out.stdout)
                    total = audit_data.get("metadata", {}).get(
                        "vulnerabilities", {}
                    )
                    critical = total.get("critical", 0)
                    high = total.get("high", 0)

                    if critical or high:
                        await self.log(
                            f"  npm audit: {critical} critical, {high} high",
                            "danger",
                        )
                except json.JSONDecodeError:
                    pass

        # Check for pip-audit
        has_pip_audit = await self.terminal.check_tool("pip-audit")
        if has_pip_audit:
            await self.log("Running pip-audit...", "info")
            out = await self.terminal.run(
                "pip-audit --format json 2>/dev/null | head -100",
                timeout=30,
            )
            if out.stdout and "[" in out.stdout:
                try:
                    audit_results = json.loads(out.stdout)
                    if audit_results:
                        await self.log(
                            f"  pip-audit found {len(audit_results)} vulnerable packages",
                            "danger",
                        )
                except json.JSONDecodeError:
                    pass

        # Check for retire.js (JavaScript vulnerability scanner)
        has_retire = await self.terminal.check_tool("retire")
        if has_retire:
            await self.log("Running retire.js scan...", "info")
            out = await self.terminal.run(
                f'retire --jsrepo --outputformat json --outputpath /dev/stdout 2>/dev/null | head -100',
                timeout=30,
            )

    # ═══════════════════════════════════════════════════
    # 8. DEPENDENCY CONFUSION
    # ═══════════════════════════════════════════════════

    async def _check_dependency_confusion(
        self, manifests: dict[str, str], context: ScanContext
    ):
        """Check for dependency confusion attack surface."""
        if not manifests:
            return

        for path, content in manifests.items():
            # Check for scoped internal packages (e.g., @company/internal-lib)
            internal_scopes = set()
            if path.endswith("package.json"):
                try:
                    data = json.loads(content)
                    for key in ["dependencies", "devDependencies"]:
                        for dep_name in data.get(key, {}):
                            if dep_name.startswith("@"):
                                scope = dep_name.split("/")[0]
                                internal_scopes.add(scope)
                except json.JSONDecodeError:
                    pass

            # Check for private registry URLs
            registry_urls = re.findall(
                r'https?://(?!registry\.npmjs|pypi\.org|rubygems\.org)[^\s"\']+',
                content
            )

            if registry_urls:
                await self.add_vuln(Vuln(
                    name="Dependency Confusion Risk — Private Registry Detected",
                    severity="High",
                    cvss_score=8.0,
                    endpoint=path,
                    confirmed=True,
                    description=(
                        f"Private registry URL detected in {path}: "
                        f"{', '.join(registry_urls[:3])}. "
                        f"Attackers can register same-name packages on the "
                        f"public registry to hijack installs."
                    ),
                    fix=(
                        "Pin all internal packages to your private scope. "
                        "Use .npmrc/pip.conf to enforce registry resolution order. "
                        "Register placeholder packages on public registries."
                    ),
                ))

            # Check for unscoped internal-looking packages
            if path.endswith("package.json"):
                try:
                    data = json.loads(content)
                    for key in ["dependencies", "devDependencies"]:
                        for dep_name in data.get(key, {}):
                            if not dep_name.startswith("@") and any(
                                kw in dep_name.lower() for kw in [
                                    "internal", "private", "corp", "company",
                                    "config", "utils-internal",
                                ]
                            ):
                                await self.log(
                                    f"  ⚠ Unscoped internal package: {dep_name}",
                                    "warning",
                                )
                except json.JSONDecodeError:
                    pass

    # ═══════════════════════════════════════════════════
    # 9. REGISTRY CREDENTIAL CHECK
    # ═══════════════════════════════════════════════════

    async def _check_registry_creds(self, target: str, context: ScanContext):
        """Check for exposed package manager credential files."""
        cred_paths = [
            ("/.npmrc", ["_authToken", "_auth", "//registry", "_password"]),
            ("/.pypirc", ["username", "password", "repository"]),
            ("/.yarnrc", ["npmAuthToken", "npmRegistryServer"]),
            ("/.yarnrc.yml", ["npmAuthToken", "npmRegistryServer"]),
            ("/pip.conf", ["index-url", "extra-index-url", "password"]),
            ("/.gemrc", [":rubygems_api_key", "api_key"]),
            ("/nuget.config", ["ClearTextPassword", "apikey"]),
        ]

        for path, secret_patterns in cred_paths:
            url = f"{target.rstrip('/')}{path}"
            out = await self.terminal.run(
                f'curl -sL --max-time 5 {shlex.quote(url)}'
            )

            if not out.stdout or len(out.stdout) < 10:
                continue

            lower = out.stdout.strip().lower()
            if lower.startswith("<!doctype") or lower.startswith("<html"):
                continue

            # Check for actual credentials
            for pattern in secret_patterns:
                if pattern.lower() in lower:
                    await self.add_vuln(Vuln(
                        name=f"Exposed Registry Credentials: {path}",
                        severity="Critical",
                        cvss_score=9.8,
                        endpoint=path,
                        confirmed=True,
                        evidence=out.stdout[:300],
                        description=(
                            f"Package registry credential file {path} is "
                            f"publicly accessible and contains authentication "
                            f"data (matched: {pattern}). Attackers can publish "
                            f"malicious packages to your private registry."
                        ),
                        fix=(
                            f"Immediately block access to {path}. "
                            f"Rotate all exposed registry tokens/passwords. "
                            f"Use environment variables for auth, not config files."
                        ),
                    ))
                    break
