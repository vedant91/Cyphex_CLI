"""
CYPHEX — Reasoning Tree Schema

Captures the full thought traversal for each patch decision as a JSON tree.
Each node represents one step of the model's reasoning process.

Tree types map to Oracle agent-reasoning strategies:
  - CoT       → linear chain (root → thought₁ → thought₂ → action → verify)
  - ToT       → branching tree (root → [branch₁, branch₂, branch₃] → best → verify)
  - Reflexion → loop (root → draft → critique → improve → verify → [retry if fail])
  - Standard  → single node (root → action)

Storage: .cyphex/reasoning_trees/{tree_id}.json
"""

import os
import json
import uuid
import time
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass, field, asdict


TREE_DIR = os.path.join(".cyphex", "reasoning_trees")


@dataclass
class TreeNode:
    """A single node in the reasoning tree."""
    id: str = ""
    type: str = "thought"     # "root" | "thought" | "action" | "critique" | "verification" | "branch"
    step: int = 0
    content: str = ""
    children: list = field(default_factory=list)  # list of node IDs
    metadata: dict = field(default_factory=dict)   # strategy-specific data


@dataclass
class ReasoningTree:
    """
    Full reasoning tree for a single patch decision.
    
    Captures every step the model took to arrive at a fix,
    enabling auditability and debugging of patch quality.
    """
    tree_id: str = ""
    thread_id: str = ""        # Links to session_memory
    vuln_cwe: str = ""
    vuln_type: str = ""
    file_path: str = ""
    line: int = 0
    strategy: str = "standard"
    model: str = ""
    nodes: list = field(default_factory=list)  # list of TreeNode dicts
    final_patch: str = ""
    verdict: str = "UNVERIFIED"
    duration_ms: float = 0.0
    created_at: str = ""

    def add_node(
        self,
        node_type: str,
        content: str,
        step: int = 0,
        parent_id: str = "",
        metadata: dict = None,
    ) -> str:
        """Add a node to the tree and return its ID."""
        node_id = f"node_{len(self.nodes)}"
        node = {
            "id": node_id,
            "type": node_type,
            "step": step,
            "content": content[:2000],  # Cap content length
            "children": [],
            "metadata": metadata or {},
        }
        self.nodes.append(node)

        # Link to parent
        if parent_id:
            for n in self.nodes:
                if n["id"] == parent_id:
                    n["children"].append(node_id)
                    break

        return node_id

    def build_cot_tree(
        self,
        vuln_description: str,
        thinking_steps: list,
        final_action: str,
        verify_result: dict = None,
    ):
        """Build a linear CoT tree from thinking steps."""
        root_id = self.add_node("root", vuln_description, step=0)
        parent = root_id

        for i, step_text in enumerate(thinking_steps, 1):
            parent = self.add_node("thought", step_text, step=i, parent_id=parent)

        action_id = self.add_node(
            "action", final_action,
            step=len(thinking_steps) + 1,
            parent_id=parent
        )

        if verify_result:
            self.add_node(
                "verification",
                f"Verdict: {verify_result.get('verdict', 'N/A')}",
                step=len(thinking_steps) + 2,
                parent_id=action_id,
                metadata=verify_result,
            )

    def build_reflection_tree(
        self,
        vuln_description: str,
        draft: str,
        critique: str,
        improvement: str,
        verify_result: dict = None,
    ):
        """Build a reflection tree (draft → critique → improve)."""
        root_id = self.add_node("root", vuln_description, step=0)
        draft_id = self.add_node("action", f"DRAFT:\n{draft}", step=1, parent_id=root_id)
        critique_id = self.add_node("critique", f"CRITIQUE:\n{critique}", step=2, parent_id=draft_id)
        improve_id = self.add_node("action", f"IMPROVEMENT:\n{improvement}", step=3, parent_id=critique_id)

        if verify_result:
            self.add_node(
                "verification",
                f"Verdict: {verify_result.get('verdict', 'N/A')}",
                step=4,
                parent_id=improve_id,
                metadata=verify_result,
            )

    def build_tot_tree(
        self,
        vuln_description: str,
        branches: list,
        selected_branch: int,
        verify_result: dict = None,
    ):
        """
        Build a Tree-of-Thoughts tree from branches.
        
        Args:
            branches: list of {"approach": str, "code": str, "score": float}
            selected_branch: index of chosen branch
        """
        root_id = self.add_node("root", vuln_description, step=0)
        branch_ids = []
        for i, branch in enumerate(branches):
            bid = self.add_node(
                "branch",
                f"Approach {i+1}: {branch.get('approach', '')}",
                step=1,
                parent_id=root_id,
                metadata={"score": branch.get("score", 0), "selected": i == selected_branch},
            )
            branch_ids.append(bid)

        if 0 <= selected_branch < len(branch_ids):
            action_id = self.add_node(
                "action",
                f"SELECTED: {branches[selected_branch].get('code', '')}",
                step=2,
                parent_id=branch_ids[selected_branch],
            )
            if verify_result:
                self.add_node("verification", f"Verdict: {verify_result.get('verdict', 'N/A')}",
                              step=3, parent_id=action_id, metadata=verify_result)

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dict."""
        return asdict(self)

    def get_summary(self) -> dict:
        """Get a compact summary of the reasoning tree."""
        return {
            "tree_id": self.tree_id,
            "strategy": self.strategy,
            "model": self.model,
            "nodes": len(self.nodes),
            "verdict": self.verdict,
            "duration_ms": self.duration_ms,
            "depth": self._max_depth(),
        }

    def _max_depth(self) -> int:
        """Calculate the max depth of the tree."""
        if not self.nodes:
            return 0

        # Build adjacency
        children_map = {}
        for n in self.nodes:
            children_map[n["id"]] = n.get("children", [])

        def depth(node_id, visited=None):
            if visited is None:
                visited = set()
            if node_id in visited:
                return 0
            visited.add(node_id)
            kids = children_map.get(node_id, [])
            if not kids:
                return 1
            return 1 + max(depth(c, visited) for c in kids)

        root_ids = [n["id"] for n in self.nodes if n.get("type") == "root"]
        if root_ids:
            return depth(root_ids[0])
        return depth(self.nodes[0]["id"]) if self.nodes else 0


def create_tree(
    thread_id: str,
    vuln_cwe: str,
    vuln_type: str,
    file_path: str,
    line: int,
    strategy: str,
    model: str,
) -> ReasoningTree:
    """Create a new reasoning tree for a patch decision."""
    return ReasoningTree(
        tree_id=f"tree_{uuid.uuid4().hex[:12]}",
        thread_id=thread_id,
        vuln_cwe=vuln_cwe,
        vuln_type=vuln_type,
        file_path=file_path,
        line=line,
        strategy=strategy,
        model=model,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def save_tree(tree: ReasoningTree, base_dir: str = "."):
    """Save reasoning tree to .cyphex/reasoning_trees/{tree_id}.json"""
    trees_dir = os.path.join(base_dir, TREE_DIR)
    os.makedirs(trees_dir, exist_ok=True)
    filepath = os.path.join(trees_dir, f"{tree.tree_id}.json")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(tree.to_dict(), f, indent=2, ensure_ascii=False)
    return filepath


def load_tree(tree_id: str, base_dir: str = ".") -> Optional[ReasoningTree]:
    """Load a reasoning tree by ID."""
    filepath = os.path.join(base_dir, TREE_DIR, f"{tree_id}.json")
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        tree = ReasoningTree()
        for k, v in data.items():
            if hasattr(tree, k):
                setattr(tree, k, v)
        return tree
    except Exception:
        return None


def list_trees(thread_id: str = "", base_dir: str = ".") -> list:
    """List all reasoning trees, optionally filtered by thread_id."""
    trees_dir = os.path.join(base_dir, TREE_DIR)
    if not os.path.isdir(trees_dir):
        return []
    trees = []
    for fname in os.listdir(trees_dir):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(trees_dir, fname), "r") as f:
                data = json.load(f)
            if thread_id and data.get("thread_id") != thread_id:
                continue
            trees.append({
                "tree_id": data.get("tree_id"),
                "vuln_cwe": data.get("vuln_cwe"),
                "strategy": data.get("strategy"),
                "verdict": data.get("verdict"),
                "duration_ms": data.get("duration_ms"),
                "nodes": len(data.get("nodes", [])),
            })
        except Exception:
            continue
    return trees
