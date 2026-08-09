"""
CYPHEX — PageIndex-Style Knowledge Tree Builder

Builds a hierarchical JSON tree from:
  1. Source code (regex/AST — no LLM, instant)
  2. Security documents (local Ollama summarization)
  3. Security KB (static JSON)

The tree is traversed at patch-time to assemble perfect context.
No APIs, no embeddings, no vector DB — 100% local.

Architecture:
  Root
  ├── code_tree (built by Python regex, 0 VRAM)
  │   ├── route: /api/users
  │   │   ├── summary, file, line_range, params, sinks
  │   │   └── full_function_code (leaf content)
  │   └── route: /api/orders/:id
  │       └── ...
  ├── knowledge_tree (built by local Ollama summarization)
  │   ├── section: SQL Injection
  │   │   ├── summary (LLM-generated)
  │   │   └── children: [fix patterns, examples]
  │   └── section: XSS
  │       └── ...
  └── cwe_index (deterministic lookup, no LLM needed)
      ├── CWE-89 → [code nodes, knowledge nodes, fix strategies]
      └── CWE-79 → [...]
"""

import os
import re
import json
import time
import hashlib
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("cyphex.knowledge_tree")

OLLAMA_BASE = "http://localhost:11434"

# ═══════════════════════════════════════════════════════════════
# Tree Node Structure
# ═══════════════════════════════════════════════════════════════

def _node(ntype: str, title: str, summary: str = "", **kwargs) -> dict:
    """Create a tree node."""
    node = {"type": ntype, "title": title, "summary": summary, "children": []}
    node.update(kwargs)
    return node


# ═══════════════════════════════════════════════════════════════
# PHASE 1: Code Tree (Pure Python — 0 VRAM, <2 seconds)
# ═══════════════════════════════════════════════════════════════

SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", "__pycache__",
    ".venv", "venv", ".next", ".nuxt", "coverage", ".cache",
}

SOURCE_EXTS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py", ".php", ".go", ".java"}

# Route patterns for Express, Flask, FastAPI
ROUTE_PATTERNS = [
    # Express: router.get('/path', ...) or app.post('/path', ...)
    re.compile(r'(?:router|app)\.(get|post|put|delete|patch)\s*\(\s*[\'"](/[^\'"]*)[\'"]', re.I),
    # Flask: @app.route('/path', methods=[...])
    re.compile(r'@\w+\.route\s*\(\s*[\'"](/[^\'"]*)[\'"]', re.I),
]

SINK_PATTERNS = {
    "CWE-89": re.compile(r'(?:db\.query|\.execute|SELECT\s|INSERT\s|UPDATE\s|DELETE\s).*(?:\$\{|` ?\+|%s|\.format)', re.I),
    "CWE-79": re.compile(r'dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write', re.I),
    "CWE-78": re.compile(r'(?:exec|execSync|spawn)\s*\(.*(?:\$\{|` ?\+)', re.I),
    "CWE-22": re.compile(r'(?:readFile|readFileSync|open)\s*\(.*(?:req\.|request\.)', re.I),
    "CWE-798": re.compile(r'(?:password|secret|api_key|token)\s*[:=]\s*["\'][^"\']{4,}["\']', re.I),
    "CWE-918": re.compile(r'(?:fetch|axios|request|http\.get)\s*\(.*(?:req\.|request\.)', re.I),
}


def build_code_tree(source_dir: str) -> dict:
    """
    Walk source code and build a hierarchical tree of routes → functions → sinks.
    Pure Python, no LLM. Returns a tree node.
    """
    root = _node("code_tree", "Source Code", f"Code structure of {os.path.basename(source_dir)}")
    root["source_dir"] = source_dir
    root["framework"] = ""
    root["files_indexed"] = 0

    # Detect framework from package.json
    pkg_path = os.path.join(source_dir, "package.json")
    if os.path.isfile(pkg_path):
        try:
            with open(pkg_path, "r", encoding="utf-8") as f:
                pkg = json.loads(f.read())
            deps = list(pkg.get("dependencies", {}).keys())
            for fw in ["express", "fastify", "koa", "next", "flask", "django", "fastapi"]:
                if any(fw in d.lower() for d in deps):
                    root["framework"] = fw
                    break
            root["dependencies"] = deps
        except Exception:
            pass

    # Discover mount prefixes from entry files
    mount_map = {}
    files_data = {}  # rel_path → {content, lines, abs_path}

    for dirpath, dirnames, filenames in os.walk(source_dir):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            ext = Path(fname).suffix.lower()
            if ext not in SOURCE_EXTS:
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                if os.path.getsize(fpath) > 512 * 1024:
                    continue
                content = open(fpath, encoding="utf-8", errors="ignore").read()
            except Exception:
                continue

            rel = os.path.relpath(fpath, source_dir).replace("\\", "/")
            files_data[rel] = {"content": content, "lines": content.split("\n"), "abs_path": fpath}
            root["files_indexed"] += 1

            # Detect mount prefixes from entry files
            basename = Path(fname).stem
            if basename in ("index", "app", "server", "main"):
                for m in re.finditer(
                    r"app\.use\s*\(\s*['\"](/[^'\"]*)['\"].*?(?:require\s*\(\s*['\"]\.?/(?:routes?/)?(\w+)['\"]|(\w+)Routes)",
                    content
                ):
                    prefix = m.group(1)
                    module = m.group(2) or m.group(3)
                    if module:
                        mount_map[module.lower()] = prefix

    # Extract routes and build tree nodes
    route_nodes = {}  # full_path → node

    for rel_path, fdata in files_data.items():
        content = fdata["content"]
        basename = Path(rel_path).stem.lower()
        mount_prefix = mount_map.get(basename, f"/{basename}" if basename not in ("index", "app", "server", "main") else "")

        for pattern in ROUTE_PATTERNS:
            for match in pattern.finditer(content):
                groups = match.groups()
                if len(groups) == 2:
                    method, path = groups[0].upper(), groups[1]
                else:
                    method, path = "GET", groups[0]

                full_path = f"{mount_prefix}{path}".rstrip("/") or "/"
                line_num = content[:match.start()].count("\n") + 1

                # Extract the handler function
                func_code, func_end = _extract_handler(fdata["lines"], line_num - 1)

                # Detect sinks in this handler
                sinks = []
                for cwe, sink_pat in SINK_PATTERNS.items():
                    if sink_pat.search(func_code):
                        sinks.append(cwe)

                # Detect params
                params = []
                params.extend(re.findall(r'req\.query\.(\w+)', func_code))
                params.extend(re.findall(r'req\.body\.(\w+)', func_code))
                params.extend(re.findall(r'req\.params\.(\w+)', func_code))
                # Also extract :param from path
                params.extend(re.findall(r':(\w+)', path))

                key = f"{method}:{full_path}"
                if key not in route_nodes:
                    node = _node(
                        "route", f"{method} {full_path}",
                        summary=f"{method} {full_path} in {rel_path}, params: {params}, sinks: {sinks}",
                        method=method, path=full_path, file=rel_path,
                        line=line_num, line_end=line_num + func_end,
                        params=list(set(params)), sinks=sinks,
                        content=func_code,
                    )
                    route_nodes[key] = node
                    root["children"].append(node)

    # Add non-route files with sinks (standalone modules)
    for rel_path, fdata in files_data.items():
        content = fdata["content"]
        for cwe, sink_pat in SINK_PATTERNS.items():
            for match in sink_pat.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                func_code, _ = _extract_handler(fdata["lines"], line_num - 1)
                # Only add if not already covered by a route
                if not any(rel_path == n.get("file") and abs(n.get("line", 0) - line_num) < 5
                           for n in root["children"]):
                    node = _node(
                        "sink", f"{cwe} sink in {rel_path}:{line_num}",
                        summary=f"Potential {cwe} at {rel_path}:{line_num}",
                        cwe=cwe, file=rel_path, line=line_num,
                        content=func_code,
                    )
                    root["children"].append(node)

    root["summary"] = (
        f"{root['files_indexed']} files, {len(route_nodes)} routes, "
        f"framework: {root.get('framework', 'unknown')}"
    )
    return root


def _extract_handler(lines: list, start_idx: int) -> tuple:
    """Extract a handler function starting near start_idx. Returns (code, line_count)."""
    # Walk backward to find function/route start
    begin = start_idx
    while begin > 0:
        line = lines[begin]
        if re.match(r'\s*(?:router|app)\.\w+\s*\(|(?:async\s+)?function\s+|(?:const|let|var)\s+\w+\s*=', line):
            break
        begin -= 1

    # Walk forward to find closing brace
    depth = 0
    end = begin
    for i in range(begin, min(len(lines), begin + 150)):
        depth += lines[i].count("{") - lines[i].count("}")
        end = i
        if depth <= 0 and i > begin:
            break

    snippet = "\n".join(lines[begin:end + 1])
    return snippet, end - begin


# ═══════════════════════════════════════════════════════════════
# PHASE 2: Knowledge Tree (Local Ollama Summarization)
# ═══════════════════════════════════════════════════════════════

def build_knowledge_tree(docs_dir: str, model: str = "llama3.1") -> dict:
    """
    Parse security documents into a hierarchical tree using local Ollama.
    Handles both TOC (markdown with headers) and non-TOC (plain text) documents.

    Args:
        docs_dir: Directory containing .md, .txt, .json files
        model: Local Ollama model for summarization

    Returns:
        A knowledge tree node with children for each document section.
    """
    root = _node("knowledge_tree", "Security Knowledge", "Security documentation and fix patterns")

    if not os.path.isdir(docs_dir):
        logger.warning(f"Docs directory not found: {docs_dir}")
        return root

    for fname in sorted(os.listdir(docs_dir)):
        fpath = os.path.join(docs_dir, fname)
        if not os.path.isfile(fpath):
            continue

        ext = Path(fname).suffix.lower()
        if ext not in (".md", ".txt", ".json", ".pdf"):
            continue

        try:
            if ext == ".pdf":
                try:
                    from pypdf import PdfReader
                    reader = PdfReader(fpath)
                    content = "\n".join([page.extract_text() for page in reader.pages if page.extract_text()])
                except Exception as e:
                    logger.warning(f"Failed to read PDF {fname}: {e}. Ensure pypdf is installed.")
                    continue
            else:
                content = open(fpath, encoding="utf-8", errors="ignore").read()
        except Exception as e:
            logger.warning(f"Failed to read {fname}: {e}")
            continue

        if ext == ".json":
            doc_node = _ingest_json_doc(fname, content)
        elif ext in (".md", ".txt") and _has_toc_structure(content):
            doc_node = _ingest_toc_document(fname, content, model)
        else:
            doc_node = _ingest_flat_document(fname, content, model)

        if doc_node:
            root["children"].append(doc_node)

    root["summary"] = f"{len(root['children'])} documents ingested"
    return root


def _has_toc_structure(content: str) -> bool:
    """Check if a document has TOC structure (markdown headers)."""
    header_count = len(re.findall(r'^#{1,4}\s+', content, re.MULTILINE))
    return header_count >= 3


def _ingest_toc_document(fname: str, content: str, model: str) -> dict:
    """Parse a markdown document with headers into tree nodes."""
    doc_node = _node("document", fname, f"Security document: {fname}")

    # Split by headers
    sections = re.split(r'^(#{1,4}\s+.+)$', content, flags=re.MULTILINE)

    current_section = None
    for part in sections:
        part = part.strip()
        if not part:
            continue

        header_match = re.match(r'^(#{1,4})\s+(.+)$', part)
        if header_match:
            level = len(header_match.group(1))
            title = header_match.group(2).strip()
            current_section = _node(
                "section", title,
                level=level,
                cwes=_extract_cwes_from_text(title),
            )
            doc_node["children"].append(current_section)
        elif current_section is not None:
            # This is the content under the current header
            if len(part) > 50:
                summary = _local_summarize(part[:2000], model)
                current_section["summary"] = summary
                current_section["content"] = part[:3000]
                current_section["cwes"] = list(set(
                    current_section.get("cwes", []) + _extract_cwes_from_text(part)
                ))

    doc_node["summary"] = f"{len(doc_node['children'])} sections from {fname}"
    return doc_node


def _ingest_flat_document(fname: str, content: str, model: str) -> dict:
    """Parse a flat document using an Agentic LLM parser to extract structured knowledge."""
    doc_node = _node("document", fname, f"Agent-Parsed document: {fname}")
    
    # Send up to 6000 chars to the Agent to extract structured JSON
    structured_data = _agentic_parse_document(content[:6000], model)
    
    if structured_data and isinstance(structured_data, list):
        for i, item in enumerate(structured_data):
            title = item.get("title", f"{fname} - Section {i+1}")
            section = _node(
                "section", title,
                summary=item.get("summary", ""),
                content=item.get("content", "")[:3000],
                cwes=item.get("cwes", []),
            )
            doc_node["children"].append(section)
    else:
        # Fallback if Agent fails to return valid JSON
        logger.warning(f"Agentic parsing failed for {fname}, falling back to basic chunking")
        paragraphs = content.split("\n\n")
        chunk = ""
        chunk_idx = 0
        for para in paragraphs:
            chunk += para + "\n\n"
            if len(chunk) > 1500:
                chunk_idx += 1
                summary = _local_summarize(chunk[:2000], model)
                section = _node("section", f"{fname} - Section {chunk_idx}", summary=summary, content=chunk[:3000], cwes=_extract_cwes_from_text(chunk))
                doc_node["children"].append(section)
                chunk = ""
        if chunk.strip():
            chunk_idx += 1
            summary = _local_summarize(chunk[:2000], model)
            doc_node["children"].append(_node("section", f"{fname} - Section {chunk_idx}", summary=summary, content=chunk[:3000], cwes=_extract_cwes_from_text(chunk)))

    doc_node["summary"] = f"{len(doc_node['children'])} cognitive sections from {fname}"
    return doc_node


def _ingest_json_doc(fname: str, content: str) -> dict:
    """Parse a JSON knowledge base into tree nodes."""
    doc_node = _node("document", fname, f"JSON knowledge base: {fname}")
    try:
        data = json.loads(content)
        entries = data.get("entries", data) if isinstance(data, dict) else data
        if isinstance(entries, dict):
            for key, val in entries.items():
                section = _node(
                    "section", key,
                    summary=val.get("description", str(val)[:200]) if isinstance(val, dict) else str(val)[:200],
                    content=json.dumps(val, indent=2)[:3000] if isinstance(val, dict) else str(val)[:3000],
                    cwes=[key] if key.startswith("CWE-") else _extract_cwes_from_text(str(val)),
                )
                doc_node["children"].append(section)
        elif isinstance(entries, list):
            for i, entry in enumerate(entries):
                text = entry.get("text", str(entry))[:200] if isinstance(entry, dict) else str(entry)[:200]
                section = _node("section", f"Entry {i+1}", summary=text,
                                content=str(entry)[:3000])
                doc_node["children"].append(section)
    except Exception as e:
        logger.warning(f"JSON parse error for {fname}: {e}")

    doc_node["summary"] = f"{len(doc_node['children'])} entries from {fname}"
    return doc_node


# ═══════════════════════════════════════════════════════════════
# PHASE 3: CWE Index (Deterministic — No LLM)
# ═══════════════════════════════════════════════════════════════

def build_cwe_index(code_tree: dict, knowledge_tree: dict, security_kb: dict = None) -> dict:
    """
    Build a fast CWE → relevant nodes lookup.
    This is the key optimization: most patch lookups are by CWE,
    so we pre-compute the mapping and skip LLM traversal entirely.
    """
    index = {}

    # Index code tree nodes by their sinks/CWEs
    for node in code_tree.get("children", []):
        for cwe in node.get("sinks", []) + ([node.get("cwe")] if node.get("cwe") else []):
            if cwe not in index:
                index[cwe] = {"code_nodes": [], "knowledge_nodes": [], "fix_strategies": []}
            index[cwe]["code_nodes"].append({
                "title": node["title"],
                "file": node.get("file", ""),
                "line": node.get("line", 0),
                "summary": node.get("summary", ""),
            })

    # Index knowledge tree nodes by their CWEs
    def _walk_knowledge(node, path=""):
        for child in node.get("children", []):
            child_path = f"{path}/{child['title']}"
            for cwe in child.get("cwes", []):
                if cwe not in index:
                    index[cwe] = {"code_nodes": [], "knowledge_nodes": [], "fix_strategies": []}
                index[cwe]["knowledge_nodes"].append({
                    "title": child["title"],
                    "path": child_path,
                    "summary": child.get("summary", ""),
                })
            _walk_knowledge(child, child_path)

    _walk_knowledge(knowledge_tree)

    # Add security KB strategies
    if security_kb:
        entries = security_kb.get("entries", security_kb)
        if isinstance(entries, dict):
            for cwe, data in entries.items():
                if cwe.startswith("CWE-") and cwe in index:
                    index[cwe]["fix_strategies"] = data.get("fix_strategies", []) if isinstance(data, dict) else []

    return index


# ═══════════════════════════════════════════════════════════════
# LOCAL OLLAMA HELPERS
# ═══════════════════════════════════════════════════════════════

def _local_summarize(text: str, model: str = "llama3.1") -> str:
    """Summarize text using local Ollama. Falls back to first 200 chars if offline."""
    try:
        import httpx
        r = httpx.post(
            f"{OLLAMA_BASE}/api/generate",
            json={
                "model": model,
                "prompt": (
                    "Summarize this security documentation in 1-2 sentences. "
                    "Focus on vulnerability types, fix patterns, and CWE numbers.\n\n"
                    f"TEXT:\n{text[:2000]}\n\nSUMMARY:"
                ),
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 100, "num_ctx": 2048},
            },
            timeout=30.0,
        )
        return r.json().get("response", "").strip()[:300]
    except Exception as e:
        logger.debug(f"Ollama summarize fallback: {e}")
        # Fallback: first sentence or 200 chars
        first_sentence = text.split(".")[0][:200] if "." in text[:200] else text[:200]
        return first_sentence.strip()


def _agentic_parse_document(text: str, model: str = "llama3.1") -> Optional[list]:
    """Uses a Reasoning Agent to extract structured JSON from unstructured text."""
    try:
        import httpx
        prompt = (
            "You are a Security Parsing Agent. Read the following unstructured document and extract distinct security rules, fix patterns, and vulnerabilities.\n"
            "Respond ONLY with a valid JSON array of objects. Do not include markdown formatting like ```json. Each object must have these exact keys:\n"
            '  "title": string (name of the rule or topic)\n'
            '  "summary": string (1-2 sentence summary)\n'
            '  "cwes": array of strings (e.g., ["CWE-79", "CWE-89"] if applicable, else [])\n'
            '  "content": string (the specific relevant text or code pattern)\n\n'
            f"DOCUMENT:\n{text}\n\nJSON OUTPUT:\n["
        )
        r = httpx.post(
            f"{OLLAMA_BASE}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.1, "num_predict": 1024, "num_ctx": 8192},
            },
            timeout=180.0,
        )
        response_text = r.json().get("response", "").strip()
        
        # Sometimes the model wraps it in markdown blocks even with format=json
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        response_text = response_text.strip()
        
        # Try to repair if it missed the starting bracket
        if not response_text.startswith("[") and not response_text.startswith("{"):
            response_text = "[" + response_text
            
        parsed = json.loads(response_text)
        
        # If the LLM returned an object instead of an array (e.g. {"rules": [...]})
        if isinstance(parsed, dict):
            for val in parsed.values():
                if isinstance(val, list):
                    return val
            return [parsed]  # Wrap single object in list
            
        return parsed
    except Exception as e:
        logger.debug(f"Agentic Parse failed: {e}")
        return None


def _extract_cwes_from_text(text: str) -> list:
    """Extract CWE-XXX references from text."""
    return list(set(re.findall(r'CWE-\d+', text)))


# ═══════════════════════════════════════════════════════════════
# MASTER BUILDER + PERSISTENCE
# ═══════════════════════════════════════════════════════════════

class KnowledgeTreeBuilder:
    """
    Builds and caches the complete knowledge tree.

    Usage:
        builder = KnowledgeTreeBuilder(source_dir="/path/to/target")
        tree = builder.build()  # First time: builds everything
        tree = builder.build()  # Second time: returns cached
    """

    def __init__(self, source_dir: str, docs_dir: str = "", model: str = "llama3.1"):
        self.source_dir = source_dir
        self.docs_dir = docs_dir or os.path.join(source_dir, "docs")
        self.model = model

        # Cache path
        cyphex_dir = os.path.join(source_dir, ".cyphex")
        os.makedirs(cyphex_dir, exist_ok=True)
        self.cache_path = os.path.join(cyphex_dir, "knowledge_tree.json")

        self._tree = None
        self._cwe_index = None

    def build(self, force: bool = False) -> dict:
        """Build or load the complete knowledge tree."""
        if self._tree and not force:
            return self._tree

        # Check cache
        if not force and os.path.isfile(self.cache_path):
            try:
                with open(self.cache_path, "r", encoding="utf-8") as f:
                    cached = json.load(f)
                # Validate cache freshness (rebuild if source changed)
                if cached.get("_source_hash") == self._source_hash():
                    self._tree = cached
                    self._cwe_index = cached.get("_cwe_index", {})
                    logger.info(f"Knowledge tree loaded from cache ({len(cached.get('children', []))} branches)")
                    return self._tree
            except Exception:
                pass

        logger.info("Building knowledge tree from scratch...")
        start = time.time()

        # Build both trees
        code_tree = build_code_tree(self.source_dir)
        knowledge_tree = build_knowledge_tree(self.docs_dir, self.model)

        # Load security KB
        kb = {}
        kb_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_kb.json")
        if os.path.isfile(kb_path):
            try:
                with open(kb_path, "r", encoding="utf-8") as f:
                    kb = json.load(f)
            except Exception:
                pass

        # Build CWE index
        cwe_index = build_cwe_index(code_tree, knowledge_tree, kb)

        # Assemble master tree
        self._tree = _node("root", "Cyphex Knowledge Tree",
                           summary=f"Code: {code_tree['summary']}, Knowledge: {knowledge_tree['summary']}")
        self._tree["children"] = [code_tree, knowledge_tree]
        self._tree["_cwe_index"] = cwe_index
        self._tree["_source_hash"] = self._source_hash()
        self._tree["_built_at"] = time.time()
        self._cwe_index = cwe_index

        elapsed = time.time() - start
        logger.info(f"Knowledge tree built in {elapsed:.1f}s")

        # Persist
        self._save()
        return self._tree

    @property
    def cwe_index(self) -> dict:
        if self._cwe_index is None:
            self.build()
        return self._cwe_index

    def _save(self):
        """Save tree to disk (strip large content fields for compact cache)."""
        try:
            # Create a compact version for caching (keep content in code_tree only)
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(self._tree, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            logger.warning(f"Cache save failed: {e}")

    def _source_hash(self) -> str:
        """Hash of source directory structure for cache invalidation."""
        parts = []
        try:
            for dirpath, _, filenames in os.walk(self.source_dir):
                # Skip non-source dirs
                if any(skip in dirpath for skip in SKIP_DIRS):
                    continue
                for f in sorted(filenames)[:50]:
                    fpath = os.path.join(dirpath, f)
                    try:
                        parts.append(f"{f}:{os.path.getsize(fpath)}")
                    except Exception:
                        pass
                if len(parts) > 200:
                    break
        except Exception:
            pass
        return hashlib.md5("|".join(parts).encode()).hexdigest()[:12]
