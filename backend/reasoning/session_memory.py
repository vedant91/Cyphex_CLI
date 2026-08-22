"""
CYPHEX — Persistent Session Memory

UUID-based session tracking so models retain context across scans.
Each scan gets a thread_id. The session file stores:
  - Scan metadata (target repo, framework, file count)
  - Reasoning history (per-vuln decisions, strategies used, outcomes)
  - Model context (lessons learned, common patterns, prior patches)

Storage: .cyphex/sessions/{thread_id}.json

On re-scan of the same repo, the prior session is loaded and its
'lessons' are injected into the model prompt, giving the 7B model
context it wouldn't otherwise have.
"""

import os
import re
import json
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass, field, asdict


# Sessions stored in a STABLE global directory — NOT inside temporary sandboxes
# This ensures thread continuity across scans of the same repo.
# Path: backend/reasoning/session_memory.py → go up 3 levels to reach project root
_CYPHEX_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SESSION_DIR = os.path.join(_CYPHEX_ROOT, ".cyphex", "sessions")

# thread_id is attacker-influenceable on the load path (unlike the writer,
# which always generates it internally via uuid.uuid4()). Restrict to a safe
# charset before it's ever joined into a filesystem path.
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _safe_session_path(thread_id: str) -> Optional[str]:
    """
    Validate thread_id and resolve it to a path guaranteed to stay inside
    SESSION_DIR. Returns None if thread_id is missing, malformed, or would
    resolve outside the sessions directory (path traversal attempt).
    """
    if not thread_id or not _SAFE_ID_RE.match(thread_id):
        return None
    filepath = os.path.join(SESSION_DIR, f"{thread_id}.json")
    real_base = os.path.realpath(SESSION_DIR)
    real_path = os.path.realpath(filepath)
    if real_path != os.path.join(real_base, os.path.basename(real_path)):
        return None
    if os.path.dirname(real_path) != real_base:
        return None
    return real_path


@dataclass
class ReasoningEntry:
    """A single reasoning decision for one vulnerability."""
    vuln_id: str
    cwe: str
    file: str
    line: int
    strategy_used: str
    rounds: int = 1
    verdict: str = "UNVERIFIED"
    patch_hash: str = ""
    fix_source: str = "council"  # "template" | "council" | "reflexion"
    duration_ms: float = 0.0
    reasoning_tree_id: str = ""


@dataclass
class SessionMemory:
    """Persistent session for a CYPHEX scan."""
    thread_id: str = ""
    scan_id: str = ""
    created_at: str = ""
    updated_at: str = ""
    target: dict = field(default_factory=dict)
    reasoning_history: list = field(default_factory=list)
    model_context: dict = field(default_factory=lambda: {
        "patches_attempted": 0,
        "patches_applied": 0,
        "patches_verified": 0,
        "patches_failed": 0,
        "common_patterns": [],
        "lessons": [],
    })

    def add_entry(self, entry: ReasoningEntry):
        """Add a reasoning entry for a vulnerability."""
        self.reasoning_history.append(asdict(entry))
        self.updated_at = datetime.now(timezone.utc).isoformat()

        # Update aggregate stats. A FAIL entry is a patch that was rolled back,
        # so it counts as an ATTEMPT, never as an applied patch — otherwise
        # "patches applied" grew on every rejection and the panel showed more
        # applied patches than survive in the tree.
        self.model_context["patches_attempted"] = (
            self.model_context.get("patches_attempted", 0) + 1
        )
        if entry.verdict == "FAIL":
            self.model_context["patches_failed"] += 1
        else:
            self.model_context["patches_applied"] += 1
            if entry.verdict == "PASS":
                self.model_context["patches_verified"] += 1

    def add_lesson(self, lesson: str):
        """Add a learned lesson (e.g., 'SQLi in this codebase uses db.query()')."""
        if lesson and lesson not in self.model_context["lessons"]:
            self.model_context["lessons"].append(lesson)
            # Keep max 20 lessons
            self.model_context["lessons"] = self.model_context["lessons"][-20:]

    def add_pattern(self, pattern: str):
        """Record a common fix pattern (e.g., 'parameterized_query')."""
        if pattern and pattern not in self.model_context["common_patterns"]:
            self.model_context["common_patterns"].append(pattern)

    def get_prior_context(self, max_lessons: int = 5) -> str:
        """
        Build a prompt-injectable context from prior sessions.
        Returns a string suitable for prepending to model prompts.
        """
        if not self.reasoning_history and not self.model_context["lessons"]:
            return ""

        parts = ["=== PRIOR SCAN CONTEXT (from session memory) ==="]

        # Lessons
        lessons = self.model_context.get("lessons", [])[-max_lessons:]
        if lessons:
            parts.append("LESSONS FROM PREVIOUS SCANS:")
            for i, lesson in enumerate(lessons, 1):
                parts.append(f"  {i}. {lesson}")

        # Common patterns
        patterns = self.model_context.get("common_patterns", [])
        if patterns:
            parts.append(f"\nCOMMON FIX PATTERNS: {', '.join(patterns)}")

        # Stats
        ctx = self.model_context
        applied = ctx.get("patches_applied", 0)
        verified = ctx.get("patches_verified", 0)
        # Success rate is verified / ATTEMPTED. Dividing by applied-only would
        # hide every rolled-back patch and report a near-100% rate.
        attempted = ctx.get("patches_attempted", applied + ctx.get("patches_failed", 0))
        if attempted > 0:
            parts.append(f"\nPRIOR RESULTS: {attempted} patches attempted, {applied} applied, "
                         f"{verified} verified ({verified/attempted*100:.0f}% success rate)")

        # Recently fixed CWEs
        recent_cwes = set()
        for entry in self.reasoning_history[-10:]:
            if entry.get("verdict") == "PASS":
                recent_cwes.add(entry.get("cwe", ""))
        if recent_cwes:
            parts.append(f"PREVIOUSLY FIXED CWEs: {', '.join(sorted(recent_cwes))}")

        parts.append("=== END PRIOR CONTEXT ===\n")
        return "\n".join(parts)

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dict."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "SessionMemory":
        """Deserialize from dict."""
        sm = cls()
        sm.thread_id = data.get("thread_id", "")
        sm.scan_id = data.get("scan_id", "")
        sm.created_at = data.get("created_at", "")
        sm.updated_at = data.get("updated_at", "")
        sm.target = data.get("target", {})
        sm.reasoning_history = data.get("reasoning_history", [])
        sm.model_context = data.get("model_context", {
            "patches_attempted": 0,
            "patches_applied": 0,
            "patches_verified": 0,
            "patches_failed": 0,
            "common_patterns": [],
            "lessons": [],
        })
        return sm


def create_session(
    repo_url: str = "",
    source_dir: str = "",
    framework: str = "",
    file_count: int = 0,
) -> SessionMemory:
    """
    Create a new session or load an existing one for this repo.
    
    If a prior session exists for the same repo, it's loaded (continuity).
    Otherwise a fresh session with a new UUID is created.
    
    Sessions are stored in a STABLE global directory so they survive
    sandbox teardown and are discoverable on re-scan.
    """
    # Normalize the repo identifier for hashing
    # For --repo: use the URL (strips trailing .git for consistency)
    # For --path: use the absolute path
    identifier = repo_url or source_dir
    if identifier:
        identifier = identifier.rstrip("/").removesuffix(".git")
    repo_hash = _repo_hash(identifier)

    # Check for existing session in the STABLE global sessions dir
    existing = _find_session_for_repo(repo_hash)
    if existing:
        existing.updated_at = datetime.now(timezone.utc).isoformat()
        # Update metadata that may have changed
        existing.target["framework"] = framework or existing.target.get("framework", "")
        existing.target["file_count"] = file_count or existing.target.get("file_count", 0)
        return existing

    # New session
    session = SessionMemory(
        thread_id=str(uuid.uuid4()),
        scan_id=f"cyphex_{uuid.uuid4().hex[:8]}",
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
        target={
            "repo_url": repo_url,
            "source_dir": source_dir,
            "framework": framework,
            "file_count": file_count,
            "repo_hash": repo_hash,
        },
    )
    return session


def save_session(session: SessionMemory, base_dir: str = "."):
    """Save session to the STABLE global sessions directory."""
    # Always save to the global stable dir, ignoring base_dir for storage
    os.makedirs(SESSION_DIR, exist_ok=True)
    filepath = os.path.join(SESSION_DIR, f"{session.thread_id}.json")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(session.to_dict(), f, indent=2, ensure_ascii=False)
    return filepath


def load_session(thread_id: str, base_dir: str = ".") -> Optional[SessionMemory]:
    """Load a specific session by thread_id from the global sessions dir."""
    filepath = _safe_session_path(thread_id)
    if not filepath or not os.path.exists(filepath):
        return None
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return SessionMemory.from_dict(data)
    except Exception:
        return None


def list_sessions(base_dir: str = ".") -> list:
    """List all saved sessions (newest first) from the global sessions dir."""
    if not os.path.isdir(SESSION_DIR):
        return []
    sessions = []
    for fname in os.listdir(SESSION_DIR):
        if fname.endswith(".json"):
            try:
                with open(os.path.join(SESSION_DIR, fname), "r") as f:
                    data = json.load(f)
                sessions.append({
                    "thread_id": data.get("thread_id"),
                    "scan_id": data.get("scan_id"),
                    "target": data.get("target", {}).get("repo_url", ""),
                    "created_at": data.get("created_at", ""),
                    "patches": data.get("model_context", {}).get("patches_applied", 0),
                })
            except Exception:
                continue
    sessions.sort(key=lambda s: s.get("created_at", ""), reverse=True)
    return sessions


def _repo_hash(identifier: str) -> str:
    """Create a stable hash for a repo identifier."""
    return hashlib.sha256(identifier.encode()).hexdigest()[:16]


def _find_session_for_repo(repo_hash: str) -> Optional[SessionMemory]:
    """Find the most recent session for a given repo in the global sessions dir."""
    if not os.path.isdir(SESSION_DIR):
        return None
    best = None
    best_time = ""
    for fname in os.listdir(SESSION_DIR):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(SESSION_DIR, fname), "r") as f:
                data = json.load(f)
            if data.get("target", {}).get("repo_hash") == repo_hash:
                t = data.get("updated_at", "")
                if t > best_time:
                    best_time = t
                    best = SessionMemory.from_dict(data)
        except Exception:
            continue
    return best
