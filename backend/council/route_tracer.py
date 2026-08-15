import os
import re
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional

# backend/backend has no __init__.py and is added directly to sys.path by the
# CLI entrypoint (cli_engine.py inserts "backend/backend" before importing the
# council package), so the rest of the codebase imports this module as a
# top-level "models" package (e.g. `from models.scan import Vuln`) rather than
# via the repo-root-qualified "backend.backend.models.scan". Try that
# canonical form first so we bind the SAME Vuln class the rest of the app
# uses; fall back to the fully-qualified path for contexts where only the
# repo root is on sys.path; only give up to Any if neither resolves.
try:
    from models.scan import Vuln
except ImportError:
    try:
        from backend.backend.models.scan import Vuln
    except ImportError:
        Vuln = Any

class RouteTracer:
    """
    Maps dynamic (DAST) HTTP vulnerabilities back to static source code files and line numbers.
    Uses SAST correlation, regex codebase scanning, and optional AI fallback.
    """
    def __init__(self, source_dir: str):
        self.source_dir = source_dir

    def resolve_dast_vulns(self, vulns: List[Vuln], patch_council=None) -> None:
        """
        Takes a mixed list of static and dynamic Vulns.
        Attempts to resolve the endpoint of dynamic findings to a 'filepath:line_number' format.
        """
        import re as _re

        def _is_file_line(ep: str) -> bool:
            # A static SAST finding endpoint is a 'file:line' locator that ends with
            # ':<digits>' — e.g. 'src/routes/orders.js:34' OR an absolute path like
            # '/Users/.../index.js:16' (Semgrep emits absolute paths, so we must NOT
            # exclude leading-'/' here — only the trailing ':<line>' distinguishes it).
            ep = (ep or "").strip()
            return (not ep.startswith(("http://", "https://"))) and bool(_re.search(r":\d+$", ep))

        static_vulns = [v for v in vulns if _is_file_line(v.endpoint)]
        # DAST/DeepAgent findings store a RELATIVE path (parsed.path, e.g.
        # '/api/products?id=1') OR a full URL in .endpoint — both are dynamic
        # findings that must be mapped back to source. Previously only http(s)://
        # endpoints qualified, so every relative-path DeepAgent finding (the common
        # case) was dropped as "unpatchable dynamic-only".
        dynamic_vulns = [
            v for v in vulns
            if (not _is_file_line(v.endpoint))
            and (v.endpoint or "").startswith(("http://", "https://", "/"))
        ]

        for dv in dynamic_vulns:
            # Clean the path
            try:
                # Remove query params and split into base URL and path
                parts = dv.endpoint.split(" (")
                raw_url = parts[0].strip()
                parsed = urlparse(raw_url)
                path = parsed.path
            except Exception:
                continue
            
            if not path or path == "/":
                # Hard to trace root path statically without more context
                continue

            # Strategy 1: Heuristic SAST Correlation
            resolved = self._find_sast_correlation(dv, path, static_vulns)
            
            # Strategy 2: Regex Route Matcher
            if not resolved and self.source_dir:
                resolved = self._regex_route_match(path)

            # (Optional) Strategy 3: AI Codebase Resolver could be added here
            
            if resolved:
                # Update the endpoint so the patcher can find it
                # Preserve the original URL as evidence
                if not dv.evidence:
                    dv.evidence = f"Original Endpoint: {dv.endpoint}\n"
                dv.endpoint = resolved
                print(f"  [dim]Mapped DAST finding -> {resolved}[/dim]")

    def _find_sast_correlation(self, dynamic_vuln: Vuln, path: str, static_vulns: List[Vuln]) -> Optional[str]:
        """Matches a DAST finding to a SAST finding based on vulnerability type and path segments."""
        path_segments = [s for s in path.strip('/').split('/') if s]
        if not path_segments:
            return None

        # Normalize vulnerability name for fuzzy matching
        d_name = dynamic_vuln.name.lower().replace("[dynamic]", "").strip()
        
        for sv in static_vulns:
            s_name = sv.name.lower().replace("[static]", "").strip()
            
            # Check if they belong to the same family
            is_same_family = False
            if "sql injection" in d_name and "sql injection" in s_name: is_same_family = True
            elif "xss" in d_name and "xss" in s_name: is_same_family = True
            elif "sensitive data" in d_name and "sensitive data" in s_name: is_same_family = True
            elif "idor" in d_name and "idor" in s_name: is_same_family = True
            elif "ssrf" in d_name and "ssrf" in s_name: is_same_family = True

            if is_same_family:
                # Check if the static file path contains any of the important path segments
                # e.g. path `/api/auth/login` -> check if `auth` or `login` is in the filepath
                filepath = sv.endpoint.split(':')[0]
                filepath_lower = filepath.lower()
                
                # Match against the last two meaningful segments of the URL
                targets = path_segments[-2:]
                for target in targets:
                    if len(target) > 2 and target in filepath_lower:
                        return sv.endpoint  # Found a strong correlation!
        return None

    def _regex_route_match(self, path: str) -> Optional[str]:
        """Scans the codebase for files registering this route."""
        path_segments = [s for s in path.strip('/').split('/') if s]
        if not path_segments:
            return None
        
        last_segment = path_segments[-1]
        
        # Regex patterns for Express/NodeJS, Python, etc.
        patterns = [
            # Express: router.post('/login', ...) or app.get('/login', ...)
            re.compile(r'\.(get|post|put|delete|use|all)\s*\(\s*[\'"`]/?(?:api/)?(?:v1/)?(?:' + re.escape(last_segment) + r')/?[\'"`]', re.IGNORECASE),
            # NestJS / Spring: @Post('login')
            re.compile(r'@(Get|Post|Put|Delete|RequestMapping)\s*\(\s*[\'"`]/?' + re.escape(last_segment) + r'/?[\'"`]\)', re.IGNORECASE),
            # Flask/FastAPI: @app.route('/login')
            re.compile(r'@(app|router)\.(route|get|post|put|delete)\s*\(\s*[\'"`]/?(?:api/)?(?:' + re.escape(last_segment) + r')/?[\'"`]', re.IGNORECASE)
        ]

        # Scan files
        for root, dirs, files in os.walk(self.source_dir):
            # Skip noise
            if 'node_modules' in root or '.git' in root or 'dist' in root or 'build' in root:
                continue
            
            for file in files:
                if file.endswith(('.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.go')):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                            
                        for i, line in enumerate(lines):
                            for pattern in patterns:
                                if pattern.search(line):
                                    rel_path = os.path.relpath(filepath, self.source_dir)
                                    return f"{rel_path}:{i + 1}"
                    except Exception:
                        pass
        return None
