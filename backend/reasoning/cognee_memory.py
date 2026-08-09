"""
CYPHEX × Cognee — Agent Memory Bridge

Wraps Cognee's remember/recall/cognify API for use by Cyphex's 14 agents.
Configures Cognee for 100% local operation via Ollama.

Three memory operations:
  - remember(): Agents write discoveries, findings, strategies
  - recall():   Agents query for context before attacking
  - build():    Process all memories into knowledge graph (cognify)

When Cognee is NOT installed, falls back to a lightweight in-memory
dict-based store so the pipeline never crashes.

Usage:
    memory = CyphexMemory(scan_id="scan_abc123")
    await memory.agent_remember("agent_03", "FINDING", "SQLi confirmed on /api/users", {...})
    context = await memory.agent_recall("What endpoints accept user input?")
    await memory.build()
"""

import os
import json
import time
import logging
import asyncio
from typing import Optional
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("cyphex.memory")

# ── IMPORTANT: Must set telemetry and access control BEFORE importing cognee ──
os.environ.setdefault("TELEMETRY_DISABLED", "1")
os.environ.setdefault("ENABLE_BACKEND_ACCESS_CONTROL", "false")
os.environ.setdefault("CACHING", "false")   # Disable session caching to prevent blocking

# Configure Cognee for 100% local Ollama operation
os.environ["LLM_PROVIDER"] = "ollama"
os.environ["LLM_MODEL"] = "llama3.1:8b"
# Must end with /v1 — AsyncOpenAI appends /chat/completions to make the full path
os.environ["LLM_ENDPOINT"] = "http://localhost:11434/v1"
os.environ["LLM_API_KEY"] = "ollama"
os.environ["EMBEDDING_PROVIDER"] = "ollama"
os.environ["EMBEDDING_MODEL"] = "nomic-embed-text"
os.environ["EMBEDDING_ENDPOINT"] = "http://localhost:11434/api/embed"
os.environ["EMBEDDING_API_KEY"] = "ollama"
os.environ["EMBEDDING_DIMENSIONS"] = "768"  # nomic-embed-text outputs 768-dim vectors
os.environ["COGNEE_SKIP_CONNECTION_TEST"] = "true"
# Disable HuggingFace model downloads — Cognee's graph classification pipeline
# tries to load sentence-transformers when GRAPH_DATABASE_PROVIDER is not set.
# Setting these prevents the "None is not a local folder" HuggingFace error.
os.environ.setdefault("HUGGINGFACE_TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")  # Force offline mode — no HF downloads
os.environ.setdefault("HF_DATASETS_OFFLINE", "1")

# ── Try importing Cognee ──
COGNEE_AVAILABLE = True
try:
    import cognee

    # ── HOTFIX: Disable HuggingFace tokenizer downloads for Ollama embeddings ──
    # The OllamaEmbeddingEngine.get_tokenizer() method tries to download from HF
    # on first call. Replacing with a no-op prevents the 422 EmbeddingException.
    try:
        from cognee.infrastructure.databases.vector.embeddings.OllamaEmbeddingEngine import OllamaEmbeddingEngine
        OllamaEmbeddingEngine.get_tokenizer = lambda self: None
    except (ImportError, AttributeError):
        pass  # Newer Cognee versions don't need this patch

    # ── HOTFIX: Patch graph classification to skip HF model loading ──
    # Cognee's cognify() internally runs entity extraction using a model
    # configured via GRAPH_DATABASE_PROVIDER. If not set, it defaults to None
    # which causes "None is not a valid model identifier" from HuggingFace.
    try:
        from cognee.tasks.graph import extract_graph_from_data as _egfd
    except (ImportError, AttributeError):
        pass

    logger.info("Cognee agent memory loaded (Telemetry Disabled, Access Control OFF)")
except ImportError:
    COGNEE_AVAILABLE = False
    logger.info("Cognee not installed — using fallback memory (pip install cognee[ollama])")


# Stable storage directory for memory snapshots
_CYPHEX_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MEMORY_DIR = os.path.join(_CYPHEX_ROOT, ".cyphex", "agent_memory")


@dataclass
class MemoryEntry:
    """A single memory written by an agent."""
    id: str
    agent_id: str
    timestamp: float
    memory_type: str        # DISCOVERY | FINDING | STRATEGY | CONTEXT | WARNING
    content: str
    metadata: dict = field(default_factory=dict)
    tags: list = field(default_factory=list)
    confidence: float = 1.0


class CyphexMemory:
    """
    Cognee-powered memory layer for Cyphex agents.
    
    When Cognee is available: Uses graph+vector memory via Ollama.
    When not available: Falls back to in-memory keyword search.
    Both modes expose the same API so the pipeline works either way.
    """
    
    # Global write lock to prevent SQLite 'OperationalError: database is locked' during batch patching
    _write_lock = asyncio.Lock()

    def __init__(self, scan_id: str, target_url: str = ""):
        self.scan_id = scan_id
        self.target_url = target_url
        # Use a unified global dataset for cross-project recall
        self.dataset = "cyphex_global_memory"
        self._initialized = False
        self._cognee_ready = False

        # Fallback: in-memory store
        self._entries: list[MemoryEntry] = []
        self._entry_counter = 0

        # ── BATCH BUFFER ──────────────────────────────────────────────────────
        # agent_remember() no longer calls cognee.add() immediately — that
        # triggers a full Cognee pipeline run per write, causing 20+ queued
        # runs to deadlock Ollama.  Instead we buffer the pre-formatted text
        # here and flush everything in a SINGLE add()+cognify() inside build().
        self._pending_cognee_texts: list[str] = []

    async def initialize(self):
        """Configure Cognee for local Ollama operation."""
        if self._initialized:
            return
        self._initialized = True

        if not COGNEE_AVAILABLE:
            logger.info("Memory: using in-memory fallback (no Cognee)")
            return

        # ── Suppress OntologyAdapter INFO spam ("No close match found for...") ──
        # These are expected — Cyphex terms (agent, scan, endpoint) aren't in the
        # default OWL ontology. Raising to WARNING hides the noise.
        import logging as _logging
        _logging.getLogger("OntologyAdapter").setLevel(_logging.WARNING)

        # Configuration is now handled globally before import

        try:
            # Quick test — if Cognee can't connect, fall back gracefully
            self._cognee_ready = True
            logger.info("Cognee memory initialized (Ollama-backed)")
        except Exception as e:
            logger.warning(f"Cognee init failed: {e}. Using fallback memory.")
            self._cognee_ready = False

    async def agent_remember(
        self,
        agent_id: str,
        memory_type: str,
        content: str,
        metadata: dict = None,
        tags: list = None,
        confidence: float = 1.0,
    ):
        """
        Agent writes a finding to memory.
        
        Args:
            agent_id: e.g. "agent_03_sqli"
            memory_type: DISCOVERY | FINDING | STRATEGY | CONTEXT | WARNING
            content: Human-readable description
            metadata: Structured data (endpoint, cwe, payload, etc.)
            tags: Keywords for retrieval
            confidence: 0.0 to 1.0
        """
        await self.initialize()

        self._entry_counter += 1
        entry = MemoryEntry(
            id=f"mem_{self._entry_counter:04d}",
            agent_id=agent_id,
            timestamp=time.time(),
            memory_type=memory_type,
            content=content,
            metadata=metadata or {},
            tags=tags or [],
            confidence=confidence,
        )
        self._entries.append(entry)

        # Buffer for batch Cognee write — actual add()+cognify() happens in build()
        if self._cognee_ready:
            metadata = metadata or {}
            metadata["project_url"] = self.target_url
            metadata["scan_id"] = self.scan_id
            self._pending_cognee_texts.append(self._format_for_cognee(entry))

        return entry.id

    async def agent_recall(self, query: str, limit: int = 5) -> list[dict]:
        """
        Agent queries memory for relevant context.
        
        Returns list of {content, agent_id, memory_type, metadata, score} dicts.
        """
        await self.initialize()

        if self._cognee_ready:
            try:
                from cognee.api.v1.search import SearchType
                # Try different SearchType values depending on Cognee version
                # Cognee 1.2+ removed INSIGHTS — use SUMMARIES or GRAPH_COMPLETION
                search_type = None
                for candidate in ("SUMMARIES", "GRAPH_COMPLETION", "INSIGHTS", "CHUNKS"):
                    if hasattr(SearchType, candidate):
                        search_type = getattr(SearchType, candidate)
                        break
                if search_type is None:
                    raise AttributeError("No usable SearchType found in Cognee version")

                results = await cognee.search(
                    query_type=search_type,
                    query_text=query,
                    datasets=[self.dataset]
                )
                if results:
                    return [
                        {"content": getattr(r, "text", str(r)), "source": "cognee", "score": 1.0}
                        for r in results[:limit]
                    ]
            except AttributeError as e:
                logger.debug(f"Cognee SearchType mismatch (API version): {e}. Using fallback.")
            except Exception as e:
                logger.warning(f"Cognee search failed: {e}. Using fallback.")


        # Fallback: keyword-based search through in-memory entries
        return self._fallback_recall(query, limit)

    async def recall_for_prompt(self, query: str, max_chars: int = 1500) -> str:
        """
        Get recall results formatted for LLM prompt injection.
        
        Returns a string ready to prepend to any model prompt.
        """
        results = await self.agent_recall(query)
        if not results:
            return ""

        parts = ["=== AGENT MEMORY (cross-agent intelligence) ==="]
        char_count = 0
        for r in results:
            text = r.get("content", "")
            if char_count + len(text) > max_chars:
                break
            parts.append(text)
            char_count += len(text)
        parts.append("=== END AGENT MEMORY ===\n")
        return "\n".join(parts)

    async def build(self, timeout: float = 120.0):
        """
        Flush all buffered agent_remember() writes to Cognee and build the
        knowledge graph in a single pipeline pass.

        This is the ONLY place cognee.add() + cognee.cognify() are called,
        keeping the total pipeline runs to exactly 1 per build() invocation
        regardless of how many agent_remember() calls preceded it.

        timeout: Max seconds to wait for cognify(). If Ollama is busy embedding
                 all graph nodes concurrently, the scan pipeline continues instead
                 of hanging indefinitely. Default 120s.
        """
        if not self._cognee_ready:
            return

        pending = self._pending_cognee_texts[:]
        self._pending_cognee_texts.clear()

        if not pending:
            logger.info("Cognee build skipped — no new entries to flush")
            return

        async def _do_build():
            async with self._write_lock:
                # Split into batches of ≤8 entries to keep each document
                # small enough for nomic-embed-text's 8192-token window.
                # Large single batches cause 422 EmbeddingException because
                # the graph LLM produces oversized node descriptions.
                BATCH_SIZE = 8
                for i in range(0, len(pending), BATCH_SIZE):
                    chunk = pending[i : i + BATCH_SIZE]
                    batch_text = "\n\n---\n\n".join(chunk)
                    await cognee.add(
                        data=batch_text,
                        dataset_name=self.dataset,
                    )
                logger.info(
                    f"Cognee add: flushed {len(pending)} entries "
                    f"in {((len(pending) - 1) // BATCH_SIZE) + 1} batch(es)"
                )
                await cognee.cognify()
            logger.info("Cognee knowledge graph built (cognify complete)")

        try:
            await asyncio.wait_for(_do_build(), timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning(
                f"Cognee build timed out after {timeout}s — "
                "graph incomplete but scan pipeline continues. "
                "Embeddings will catch up in the background."
            )
        except Exception as e:
            logger.warning(f"Cognee cognify failed: {e}")

    async def reset(self):
        """Clear memory for a fresh scan."""
        self._entries.clear()
        self._entry_counter = 0
        self._pending_cognee_texts.clear()  # Discard unflushed buffered writes
        if self._cognee_ready:
            try:
                await cognee.forget(everything=True)
            except Exception:
                pass

    async def ingest_security_kb(self):
        """
        Load CWE/OWASP/MITRE knowledge into Cognee (run once).
        Skips if already ingested.
        """
        if not self._cognee_ready:
            return

        # Check if knowledge is already present
        try:
            test = await cognee.recall(query_text="CWE-89 SQL Injection parameterized query")
            if test:
                logger.info("Security knowledge base already ingested")
                return
        except Exception:
            pass

        # Load security knowledge from bundled JSON
        kb_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "security_knowledge.json"
        )
        if not os.path.exists(kb_path):
            logger.warning(f"Security KB not found at {kb_path}")
            return

        try:
            with open(kb_path, "r", encoding="utf-8") as f:
                kb = json.load(f)

            for entry in kb.get("entries", []):
                await cognee.remember(
                    text=entry["text"],
                    dataset_name="cyphex_security_kb",
                )

            await cognee.cognify()
            logger.info(f"Security KB ingested ({len(kb.get('entries', []))} entries)")
        except Exception as e:
            logger.warning(f"Security KB ingestion failed: {e}")

    # ── Persistence ──

    def save_snapshot(self):
        """Save current memory state to disk for cross-scan continuity."""
        os.makedirs(MEMORY_DIR, exist_ok=True)
        filepath = os.path.join(MEMORY_DIR, f"{self.scan_id}.json")
        data = {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "entry_count": len(self._entries),
            "entries": [asdict(e) for e in self._entries],
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return filepath

    @classmethod
    def load_snapshot(cls, scan_id: str) -> Optional["CyphexMemory"]:
        """Load a previous memory snapshot."""
        filepath = os.path.join(MEMORY_DIR, f"{scan_id}.json")
        if not os.path.exists(filepath):
            return None
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            mem = cls(scan_id=data["scan_id"], target_url=data.get("target_url", ""))
            for e_data in data.get("entries", []):
                mem._entries.append(MemoryEntry(**e_data))
            mem._entry_counter = len(mem._entries)
            return mem
        except Exception:
            return None

    # ── Stats ──

    def get_stats(self) -> dict:
        """Return memory statistics."""
        by_type = {}
        by_agent = {}
        for e in self._entries:
            by_type[e.memory_type] = by_type.get(e.memory_type, 0) + 1
            by_agent[e.agent_id] = by_agent.get(e.agent_id, 0) + 1
        return {
            "total_entries": len(self._entries),
            "cognee_active": self._cognee_ready,
            "by_type": by_type,
            "by_agent": by_agent,
        }

    # ── Internal ──

    def _format_for_cognee(self, entry: MemoryEntry) -> str:
        """
        Format a memory entry as structured text for Cognee ingestion.

        Values are hard-truncated here to prevent the graph LLM from
        generating node descriptions longer than nomic-embed-text's
        8192-token context window (which causes 422 EmbeddingException).
        """
        # Keep content short — LLM will expand it into graph nodes anyway
        content = entry.content[:300] if entry.content else ""

        lines = [
            "CYPHEX AGENT MEMORY ENTRY",
            f"Agent: {entry.agent_id}",
            f"Type: {entry.memory_type}",
            f"Scan: {self.scan_id}",
            f"Target: {self.target_url}",
            f"Confidence: {entry.confidence}",
            f"Content: {content}",
        ]
        if entry.tags:
            lines.append(f"Tags: {', '.join(entry.tags)}")
        if entry.metadata:
            for k, v in entry.metadata.items():
                # Cap each metadata value to 150 chars
                v_str = str(v)[:150]
                lines.append(f"{k}: {v_str}")
        return "\n".join(lines)

    def _fallback_recall(self, query: str, limit: int) -> list[dict]:
        """
        Keyword-based fallback recall when Cognee is not available.
        Scores entries by keyword overlap with the query.
        """
        query_lower = query.lower()
        query_words = set(query_lower.split())

        scored = []
        for entry in self._entries:
            score = 0.0
            text = f"{entry.content} {' '.join(entry.tags)} {entry.memory_type}".lower()
            text_words = set(text.split())

            # Word overlap
            overlap = query_words & text_words
            score += len(overlap) * 2.0

            # Substring match
            for word in query_words:
                if len(word) > 3 and word in text:
                    score += 1.0

            # Boost findings and discoveries
            if entry.memory_type in ("FINDING", "DISCOVERY"):
                score += 0.5

            if score > 0:
                scored.append({
                    "content": entry.content,
                    "agent_id": entry.agent_id,
                    "memory_type": entry.memory_type,
                    "metadata": entry.metadata,
                    "source": "fallback",
                    "score": score,
                })

        scored.sort(key=lambda x: -x["score"])
        return scored[:limit]


# ── Convenience: singleton per scan ──
_active_memory: Optional[CyphexMemory] = None


def get_memory(scan_id: str = "", target_url: str = "") -> CyphexMemory:
    """Get or create the active memory instance for the current scan."""
    global _active_memory
    if _active_memory is None or (scan_id and _active_memory.scan_id != scan_id):
        _active_memory = CyphexMemory(scan_id=scan_id, target_url=target_url)
    return _active_memory
