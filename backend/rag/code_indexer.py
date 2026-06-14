"""
CYPHEX — Vectorless Code Indexer

Walks the source directory and builds a keyword-based index.
No embeddings, no vector DB, no VRAM overhead — just regex + file walking.

Used to:
  - Find the actual source files related to a vulnerability
  - Find the repo's own secure coding patterns for the model to follow
  - Provide real code context instead of blind 5-line snippets
"""

import os
import re
from pathlib import Path
from typing import Optional


SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", "__pycache__",
    ".venv", "venv", ".next", ".nuxt", "coverage", ".cache",
    "vendor", "bower_components", ".svn",
}

SKIP_EXTENSIONS = {
    ".map", ".min.js", ".min.css", ".lock", ".png", ".jpg",
    ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".mp3", ".mp4", ".zip", ".tar", ".gz",
    ".pyc", ".pyo", ".class", ".o", ".so", ".dll", ".exe",
}

SOURCE_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".py", ".php", ".rb", ".go", ".java", ".rs",
    ".html", ".ejs", ".hbs", ".pug",
    ".json", ".yaml", ".yml", ".toml",
    ".env", ".env.example",
    ".sql",
}

MAX_FILE_SIZE = 512 * 1024  # 512 KB


class CodeIndexer:
    """Vectorless keyword index of a source tree."""

    def __init__(self, source_dir: str):
        self.root = os.path.normpath(source_dir)
        self.files: dict = {}  # rel_path → FileInfo dict

    def build_index(self) -> int:
        """Walk the source tree and build keyword index. Returns file count."""
        self.files.clear()

        for dirpath, dirnames, filenames in os.walk(self.root):
            # Skip excluded directories (in-place modification)
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

            for fname in filenames:
                ext = Path(fname).suffix.lower()
                if ext in SKIP_EXTENSIONS:
                    continue
                if ext not in SOURCE_EXTENSIONS and not fname.startswith("."):
                    continue

                fpath = os.path.join(dirpath, fname)

                # Skip oversized files
                try:
                    if os.path.getsize(fpath) > MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue

                # Read content
                try:
                    content = open(fpath, encoding="utf-8", errors="ignore").read()
                except Exception:
                    continue

                rel = os.path.relpath(fpath, self.root).replace("\\", "/")

                self.files[rel] = {
                    "abs_path": fpath,
                    "content": content,
                    "size": len(content),
                    "routes": re.findall(r'["\']/([\w/:.-]+)["\']', content),
                    "has_db": bool(re.search(
                        r'db\.|\.query|SELECT\s|INSERT\s|UPDATE\s|DELETE\s|sequelize|mongoose|prisma|typeorm',
                        content, re.I
                    )),
                    "has_auth": bool(re.search(
                        r'session|login|password|jwt|token|bcrypt|passport|auth|cookie',
                        content, re.I
                    )),
                    "has_input": bool(re.search(
                        r'req\.(body|query|params|headers)|request\.(form|args|json)',
                        content, re.I
                    )),
                    "imports": re.findall(
                        r'require\(["\'](.+?)["\']\)|from\s+["\'](.+?)["\']|import\s+.+?\s+from\s+["\'](.+?)["\']',
                        content
                    ),
                    "functions": re.findall(
                        r'(?:function|const|let|var|async)\s+(\w+)\s*[=(]',
                        content
                    ),
                }

        return len(self.files)

    def extract_api_routes(self) -> list:
        """
        Extract API routes from source code by parsing framework-specific patterns.
        
        Two-pass approach:
          Pass 1: Scan main entry file for app.use('/prefix', require('./routes/xxx'))
          Pass 2: Scan route files for router.get/post/etc, using real mount prefixes
        
        Returns list of {method, path, source, params} dicts.
        """
        routes = []
        seen = set()

        # ══════════════════════════════════════════════════════════════
        # PASS 1: Discover mount prefixes from app.use() in entry files
        # ══════════════════════════════════════════════════════════════
        # Maps: route module basename → mount prefix
        # e.g. "orders" → "/api/orders" from app.use('/api/orders', require('./routes/orders'))
        mount_map = {}
        
        entry_files = [
            rel for rel in self.files
            if os.path.basename(rel).replace(".js", "").replace(".ts", "")
            in ("index", "app", "server", "main")
        ]
        
        for entry_rel in entry_files:
            content = self.files[entry_rel]["content"]
            # Pattern: app.use('/prefix', require('./routes/xxx'))
            # Also handles: app.use('/prefix', xxxRoutes) where xxxRoutes = require(...)
            mount_pattern = r"app\.use\s*\(\s*['\"](/[^'\"]*)['\"].*?(?:require\s*\(\s*['\"]\.?/(?:routes?/)?(\w+)['\"]|(\w+)Routes)"
            for m in re.finditer(mount_pattern, content):
                prefix = m.group(1)
                module_name = m.group(2) or m.group(3)
                if module_name:
                    mount_map[module_name.lower()] = prefix

        # ══════════════════════════════════════════════════════════════
        # PASS 2: Extract routes from all files using discovered mounts
        # ══════════════════════════════════════════════════════════════
        for rel_path, meta in self.files.items():
            content = meta["content"]

            # Determine the mount prefix for this file
            basename = os.path.basename(rel_path).replace(".js", "").replace(".ts", "")
            
            # Priority: use mount_map from Pass 1, fallback to filename
            if basename.lower() in mount_map:
                mount_prefix = mount_map[basename.lower()]
            elif basename in ("index", "app", "server", "main"):
                mount_prefix = ""  # Entry files have no prefix
            else:
                mount_prefix = f"/{basename}"  # Fallback: use filename

            # ── Express patterns ──
            # router.get('/path', handler) or app.post('/path', handler)
            express_pattern = r'(?:router|app)\.(get|post|put|delete|patch)\s*\(\s*[\'"](/[^\'"]*)[\'"]'
            for match in re.finditer(express_pattern, content, re.I):
                method = match.group(1).upper()
                path = match.group(2)
                full_path = f"{mount_prefix}{path}" if path != "/" else mount_prefix or "/"
                # Normalize: /api/orders/ → /api/orders, but keep / as /
                full_path = full_path.rstrip("/") or "/"

                # Extract potential query/body params from nearby code
                params = []
                nearby = content[max(0, match.start()-50):match.end()+300]
                params.extend(re.findall(r'req\.query\.(\w+)', nearby))
                params.extend(re.findall(r'req\.body\.(\w+)', nearby))
                params.extend(re.findall(r'req\.params\.(\w+)', nearby))

                key = (method, full_path)
                if key not in seen:
                    seen.add(key)
                    routes.append({
                        "method": method,
                        "path": full_path,
                        "source": rel_path,
                        "params": list(set(params)),
                    })

            # ── Flask patterns ──
            flask_pattern = r'@\w+\.route\s*\(\s*[\'"](/[^\'"]*)[\'"](?:.*?methods\s*=\s*\[([^\]]*)\])?'
            for match in re.finditer(flask_pattern, content, re.I):
                path = match.group(1)
                methods_str = match.group(2) or "'GET'"
                methods = re.findall(r"'(\w+)'", methods_str)
                for method in methods:
                    key = (method.upper(), path)
                    if key not in seen:
                        seen.add(key)
                        routes.append({
                            "method": method.upper(),
                            "path": path,
                            "source": rel_path,
                            "params": [],
                        })

        return routes

    def find_for_vuln(self, vuln, location=None) -> list:
        """
        Find files most relevant to a vulnerability.
        Returns list of {path, score, content, abs_path} sorted by score (top 3).
        """
        endpoint = getattr(vuln, "endpoint", "") or ""
        vuln_name = (getattr(vuln, "name", "") or "").lower()
        payload = getattr(vuln, "payload", "") or ""
        cwe = getattr(vuln, "cwe", "") or ""

        # Extract route from endpoint
        route = ""
        if ":" in endpoint and not endpoint.startswith("http"):
            route = endpoint.split(":")[0].strip("/")
        elif endpoint.startswith("http"):
            # Extract path from URL
            from urllib.parse import urlparse
            parsed = urlparse(endpoint)
            route = parsed.path.strip("/")

        results = []

        for rel_path, meta in self.files.items():
            score = 0

            # Route match (strongest signal)
            if route:
                for r in meta["routes"]:
                    if route in r or r in route:
                        score += 10
                        break

            # Direct file match from location
            if location and location.rel:
                if rel_path == location.rel:
                    score += 20  # Exact file match

            # CWE-type relevance
            if "sql" in vuln_name or cwe == "CWE-89":
                if meta["has_db"]:
                    score += 5
            if "auth" in vuln_name or "idor" in vuln_name or cwe in ("CWE-287", "CWE-306"):
                if meta["has_auth"]:
                    score += 5
            if meta["has_input"]:
                score += 2

            # Payload term match
            if payload:
                for term in payload.split()[:3]:
                    if len(term) > 3 and term in meta["content"]:
                        score += 3
                        break

            if score > 0:
                results.append({
                    "path": rel_path,
                    "abs_path": meta["abs_path"],
                    "score": score,
                    "content": meta["content"],
                })

        return sorted(results, key=lambda x: -x["score"])[:3]

    def find_secure_pattern(self, cwe: str) -> Optional[str]:
        """
        Find an existing secure pattern in the repo for a given CWE.
        "Fix it the way this repo already does it."
        """
        patterns = {
            "CWE-89": [
                r'\.query\s*\(\s*["\'][^"\']*\?\s*["\']',    # Parameterized queries
                r'\.findOne\s*\(\s*\{',                        # ORM methods
                r'\.create\s*\(\s*\{',
            ],
            "CWE-79": [
                r'escapeHtml|DOMPurify|sanitize|encode',
            ],
            "CWE-78": [
                r'execFile\s*\(|spawn\s*\(',                   # Safe subprocess
            ],
        }

        search_patterns = patterns.get(cwe, [])
        if not search_patterns:
            return None

        for rel_path, meta in self.files.items():
            for pattern in search_patterns:
                match = re.search(pattern, meta["content"], re.I)
                if match:
                    # Extract the surrounding lines as an example
                    lines = meta["content"].split("\n")
                    match_line = meta["content"][:match.start()].count("\n")
                    start = max(0, match_line - 2)
                    end = min(len(lines), match_line + 3)
                    snippet = "\n".join(lines[start:end])
                    return f"// From {rel_path}:\n{snippet}"

        return None

    def get_file_content(self, rel_path: str) -> Optional[str]:
        """Get content of a specific file by relative path."""
        meta = self.files.get(rel_path)
        return meta["content"] if meta else None

    def get_dependency_info(self) -> dict:
        """Extract dependency information from package.json or requirements.txt."""
        deps = {}

        # Node.js
        pkg = self.files.get("package.json")
        if pkg:
            try:
                import json
                data = json.loads(pkg["content"])
                deps["node_deps"] = list(data.get("dependencies", {}).keys())
                deps["node_dev_deps"] = list(data.get("devDependencies", {}).keys())
            except Exception:
                pass

        # Python
        req = self.files.get("requirements.txt")
        if req:
            deps["python_deps"] = [
                line.split("==")[0].strip()
                for line in req["content"].split("\n")
                if line.strip() and not line.startswith("#")
            ]

        return deps
