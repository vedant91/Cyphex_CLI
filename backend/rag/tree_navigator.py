"""
CYPHEX — Tree Navigator (PageIndex-Style Traversal)

Two retrieval modes:
  1. FAST PATH (deterministic, 0 LLM calls, <1ms):
     CWE + file path → direct index lookup → leaf content
     Used for 90%+ of patch queries.

  2. DEEP PATH (LLM-guided, 1-2 calls, ~2s):
     Complex query → LLM reads branch summaries → picks path → leaf
     Used for cross-cutting queries like "all auth-related endpoints".

The navigator never sends the full tree to the LLM.
It sends only the SUMMARIES at each level, asks the LLM to pick
the most relevant branch, then drills down. This keeps token
usage minimal even on large trees.
"""

import re
import json
import logging
from typing import Optional

logger = logging.getLogger("cyphex.tree_navigator")

OLLAMA_BASE = "http://localhost:11434"


class TreeNavigator:
    """
    Navigates the knowledge tree to retrieve context for patching.

    Usage:
        nav = TreeNavigator(tree, cwe_index)
        ctx = nav.get_patch_context("CWE-89", "routes/users.js", 22)
        # Returns: {function_code, fix_recipe, repo_example, related_findings}
    """

    def __init__(self, tree: dict, cwe_index: dict = None, model: str = "llama3.1"):
        self.tree = tree
        self.cwe_index = cwe_index or tree.get("_cwe_index", {})
        self.model = model
        self._cache = {}  # query_hash → result

    # ═══════════════════════════════════════════════════════════
    # FAST PATH: Deterministic CWE + File Lookup (0 LLM calls)
    # ═══════════════════════════════════════════════════════════

    def get_patch_context(
        self,
        cwe: str,
        file_path: str = "",
        line: int = 0,
        vuln_name: str = "",
    ) -> dict:
        """
        Assemble complete patch context from the tree.
        This is the main entry point — called for each vuln during patching.

        Returns dict with:
          - function_code: The full enclosing function (not 5 lines)
          - imports: File's import block
          - fix_recipe: CWE-specific fix strategy from KB
          - repo_example: How this repo already does it securely
          - related_knowledge: Relevant doc sections
          - related_code: Other files with same sink pattern
        """
        result = {
            "function_code": "",
            "imports": "",
            "fix_recipe": "",
            "repo_example": "",
            "related_knowledge": "",
            "related_code": [],
            "source": "tree_navigator",
        }

        code_tree = self._get_subtree("code_tree")
        knowledge_tree = self._get_subtree("knowledge_tree")

        # 1. Find the exact function from code tree
        if file_path and code_tree:
            result["function_code"] = self._find_function_in_tree(
                code_tree, file_path, line
            )

        # 2. Get fix recipe from CWE index (instant lookup)
        if cwe and cwe in self.cwe_index:
            idx = self.cwe_index[cwe]

            # Fix strategies from security KB
            strategies = idx.get("fix_strategies", [])
            if strategies:
                recipe_parts = [f"FIX STRATEGIES for {cwe}:"]
                for i, s in enumerate(strategies[:3], 1):
                    name = s.get("name", "Strategy")
                    desc = s.get("description", "")
                    pattern = s.get("pattern", "")
                    recipe_parts.append(f"  {i}. {name}: {desc}")
                    if pattern:
                        recipe_parts.append(f"     Code: {pattern}")
                result["fix_recipe"] = "\n".join(recipe_parts)

            # Related knowledge sections
            k_nodes = idx.get("knowledge_nodes", [])
            if k_nodes:
                k_parts = [f"KNOWLEDGE BASE for {cwe}:"]
                for kn in k_nodes[:3]:
                    k_parts.append(f"  • {kn['title']}: {kn['summary'][:200]}")
                result["related_knowledge"] = "\n".join(k_parts)

            # Related code (other files with same CWE)
            c_nodes = idx.get("code_nodes", [])
            related = [cn for cn in c_nodes if cn.get("file", "") != file_path]
            result["related_code"] = related[:3]

        # 3. Find repo's own secure example
        if cwe and code_tree:
            result["repo_example"] = self._find_secure_pattern(code_tree, cwe)

        # 4. Extract imports from the target file
        if file_path and code_tree:
            result["imports"] = self._find_imports(code_tree, file_path)

        return result

    def _get_subtree(self, tree_type: str) -> Optional[dict]:
        """Get a specific subtree (code_tree or knowledge_tree)."""
        for child in self.tree.get("children", []):
            if child.get("type") == tree_type:
                return child
        return None

    def _find_function_in_tree(self, code_tree: dict, file_path: str, line: int) -> str:
        """Find the handler function from the code tree by file + line."""
        file_path_normalized = file_path.replace("\\", "/")

        best_match = None
        best_distance = float("inf")

        for node in code_tree.get("children", []):
            node_file = node.get("file", "").replace("\\", "/")
            if not node_file:
                continue

            # Match by file path (exact or suffix match)
            if node_file == file_path_normalized or file_path_normalized.endswith(node_file):
                node_line = node.get("line", 0)
                distance = abs(node_line - line) if line > 0 else 0

                if distance < best_distance:
                    best_distance = distance
                    best_match = node

        if best_match and best_match.get("content"):
            return best_match["content"]
        return ""

    def _find_secure_pattern(self, code_tree: dict, cwe: str) -> str:
        """Find an existing secure pattern in the codebase for this CWE."""
        secure_patterns = {
            "CWE-89": [r'\.query\s*\(\s*["\'][^"\']*\?\s*["\']', r'\.findOne\s*\(\s*\{'],
            "CWE-79": [r'escapeHtml|DOMPurify|sanitize'],
            "CWE-78": [r'execFile\s*\(|spawn\s*\('],
            "CWE-22": [r'path\.basename|path\.resolve.*startsWith'],
        }

        patterns = secure_patterns.get(cwe, [])
        for node in code_tree.get("children", []):
            content = node.get("content", "")
            if not content:
                continue
            for pat in patterns:
                match = re.search(pat, content, re.I)
                if match:
                    return f"// Secure pattern from {node.get('file', 'unknown')}:\n{content[:500]}"
        return ""

    def _find_imports(self, code_tree: dict, file_path: str) -> str:
        """Find the import block for a given file from the tree."""
        # The code tree stores full function content, not file-level imports.
        # We need the raw file content for imports — check parent source_dir
        source_dir = code_tree.get("source_dir", "")
        if not source_dir:
            return ""

        import os
        fpath = os.path.join(source_dir, file_path)
        if not os.path.isfile(fpath):
            # Try with normalized path
            fpath = file_path
            if not os.path.isfile(fpath):
                return ""

        try:
            lines = open(fpath, encoding="utf-8", errors="ignore").readlines()
            imports = []
            for line in lines[:60]:
                stripped = line.strip()
                if re.match(r'(import |from ["\']|const \w+ = require|var \w+ = require|let \w+ = require)', stripped):
                    imports.append(line.rstrip())
            return "\n".join(imports)
        except Exception:
            return ""

    # ═══════════════════════════════════════════════════════════
    # DEEP PATH: LLM-Guided Navigation (1-2 calls)
    # ═══════════════════════════════════════════════════════════

    def search(self, query: str, max_results: int = 3) -> list:
        """
        LLM-guided tree search for complex queries.

        The LLM sees ONLY the branch summaries at each level,
        picks the most relevant branches, then we drill down
        to retrieve the leaf content. Keeps token usage minimal.

        Used for queries like:
          "Show me all endpoints that accept user input without validation"
          "What auth patterns does this codebase use?"

        Returns list of {title, content, path, score} dicts.
        """
        cache_key = hash(query)
        if cache_key in self._cache:
            return self._cache[cache_key]

        results = []

        # Step 1: Present root-level branch summaries to LLM
        branches = []
        for i, child in enumerate(self.tree.get("children", [])):
            branches.append(f"[{i}] {child['title']}: {child.get('summary', '')[:200]}")

        if not branches:
            return []

        selected = self._llm_select_branches(query, branches)

        # Step 2: For each selected branch, present its children
        for branch_idx in selected:
            if branch_idx >= len(self.tree.get("children", [])):
                continue
            branch = self.tree["children"][branch_idx]

            child_summaries = []
            for j, child in enumerate(branch.get("children", [])):
                child_summaries.append(
                    f"[{j}] {child['title']}: {child.get('summary', '')[:150]}"
                )

            if not child_summaries:
                continue

            # Ask LLM which children are relevant
            relevant = self._llm_select_branches(query, child_summaries)

            for child_idx in relevant[:max_results]:
                if child_idx >= len(branch.get("children", [])):
                    continue
                node = branch["children"][child_idx]
                results.append({
                    "title": node["title"],
                    "content": node.get("content", node.get("summary", "")),
                    "path": f"{branch['title']}/{node['title']}",
                    "cwes": node.get("cwes", []),
                })

        self._cache[cache_key] = results[:max_results]
        return results[:max_results]

    def _llm_select_branches(self, query: str, branch_summaries: list) -> list:
        """Ask local LLM which branches are relevant to the query."""
        if not branch_summaries:
            return []

        prompt = (
            "You are a knowledge retrieval agent. Given a query and a list of document sections, "
            "return ONLY a JSON array of the indices (numbers) of the most relevant sections.\n\n"
            f"QUERY: {query}\n\n"
            f"SECTIONS:\n" + "\n".join(branch_summaries) + "\n\n"
            "Return JSON array of relevant indices (max 3). Example: [0, 2]\n"
            "ANSWER:"
        )

        try:
            import httpx
            r = httpx.post(
                f"{OLLAMA_BASE}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0.1, "num_predict": 50, "num_ctx": 2048},
                },
                timeout=15.0,
            )
            text = r.json().get("response", "").strip()
            # Parse array from response
            nums = re.findall(r'\d+', text)
            return [int(n) for n in nums[:3]]
        except Exception as e:
            logger.debug(f"LLM branch selection fallback: {e}")
            # Fallback: return all indices (brute-force)
            return list(range(min(3, len(branch_summaries))))

    # ═══════════════════════════════════════════════════════════
    # PROMPT ASSEMBLY — The Final Step
    # ═══════════════════════════════════════════════════════════

    def assemble_prompt_context(
        self,
        cwe: str,
        file_path: str = "",
        line: int = 0,
        vuln_name: str = "",
        max_chars: int = 2500,
    ) -> str:
        """
        Assemble a complete, high-signal context string for the patch LLM prompt.
        This is what gets injected into the model's context window.

        Combines:
          - Full function code (from code tree)
          - CWE fix recipe (from knowledge tree)
          - Repo's own secure example
          - Import block

        Returns a ready-to-inject prompt section.
        """
        ctx = self.get_patch_context(cwe, file_path, line, vuln_name)
        parts = []
        char_count = 0

        # 1. Function context (highest priority)
        if ctx["function_code"]:
            block = f"=== FULL FUNCTION CONTEXT ===\n{ctx['function_code']}\n"
            if char_count + len(block) < max_chars:
                parts.append(block)
                char_count += len(block)

        # 2. Imports
        if ctx["imports"]:
            block = f"=== FILE IMPORTS ===\n{ctx['imports']}\n"
            if char_count + len(block) < max_chars:
                parts.append(block)
                char_count += len(block)

        # 3. Fix recipe (critical for quality)
        if ctx["fix_recipe"]:
            block = f"=== {ctx['fix_recipe']}\n"
            if char_count + len(block) < max_chars:
                parts.append(block)
                char_count += len(block)

        # 4. Repo's own pattern
        if ctx["repo_example"]:
            block = f"=== REPO SECURE PATTERN ===\n{ctx['repo_example'][:400]}\n"
            if char_count + len(block) < max_chars:
                parts.append(block)
                char_count += len(block)

        # 5. Related knowledge
        if ctx["related_knowledge"]:
            block = f"=== {ctx['related_knowledge']}\n"
            if char_count + len(block) < max_chars:
                parts.append(block)
                char_count += len(block)

        if not parts:
            return ""

        return "\n".join(parts)


# ═══════════════════════════════════════════════════════════════
# Convenience — Global navigator instance
# ═══════════════════════════════════════════════════════════════

_navigator: Optional[TreeNavigator] = None


def get_navigator(tree: dict = None, cwe_index: dict = None) -> Optional[TreeNavigator]:
    """Get or create the global navigator."""
    global _navigator
    if tree is not None:
        _navigator = TreeNavigator(tree, cwe_index)
    return _navigator
