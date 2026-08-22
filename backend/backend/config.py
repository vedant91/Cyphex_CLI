"""
CYPHEX — Configuration
All settings centralized here. Uses environment variables with fallbacks.
"""

import os
from dataclasses import dataclass


@dataclass
class CyphexConfig:
    """Central configuration for CYPHEX."""

    # AI Backend Mode: 'local' (Ollama) | 'groq' (cloud) | 'cerebras' (legacy)
    # 'local' = primary (uses your GPU, no API key needed)
    # 'groq'  = cloud backup (free, fastest cloud API)
    AI_BACKEND_MODE: str = "local"

    # ─── Groq AI (Cloud — FREE, OpenAI-compatible) ───
    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "llama-3.3-70b-versatile"
    GROQ_MAX_TOKENS: int = 4096
    GROQ_API_URL: str = "https://api.groq.com/openai/v1/chat/completions"

    # ─── Local Ollama (Primary — runs on your GPU) ───
    OLLAMA_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen2.5-coder:7b"  # Best coding model you have installed

    # ─── Cross-project patch memory (cognee, optional — pip install ".[memory]") ───
    COGNEE_LLM_MODEL: str = ""              # Falls back to OLLAMA_MODEL if unset
    COGNEE_EMBEDDING_MODEL: str = "nomic-embed-text"
    COGNEE_RECALL_TIMEOUT_S: float = 20.0    # CHUNKS retrieval + cold vector load
    COGNEE_REMEMBER_TIMEOUT_S: float = 300.0  # cognify() runs an LLM extraction pass;
                                              # cognee's own Ollama structured-output retry
                                              # floor is 240s (stop_after_delay), so a 120s
                                              # budget ALWAYS cancelled cognify mid-pass →
                                              # empty TimeoutError, nothing persisted. Must
                                              # exceed 240s. Runs post-remediation, so a
                                              # larger budget never delays the actual fix.
                                              # Runs after the patch is applied, so a
                                              # larger budget never delays remediation.

    # ─── Cerebras AI (Cloud — LEGACY, currently broken) ───
    CEREBRAS_API_KEY: str = ""  # Set via CEREBRAS_API_KEY env var
    CEREBRAS_MODEL: str = "llama-3.3-70b"
    CEREBRAS_MAX_TOKENS: int = 4096
    CEREBRAS_API_URL: str = "https://api.cerebras.ai/v1/chat/completions"

    # ─── Scan settings ───
    SCAN_TIMEOUT_SECONDS: int = 1800  # 30 minutes max — only enforced on the
                                       # backend API path (main.py/api.py via
                                       # asyncio.wait_for); the `cx` CLI path
                                       # (cli_engine.py) has no equivalent
                                       # top-level cap, see DEEPAGENT_* below.
    COMMAND_TIMEOUT_SECONDS: int = 60  # Per-command default timeout
    MAX_PARALLEL_AGENTS: int = 6

    # ─── DeepAgents swarm (--deep) — bounds ───
    # Confirmed live: a `cx deep` run against a 1-file dummy app hard-hung
    # past 10 minutes on agent 4/13 (DeepAuthAgent) — its oracle-guided
    # adaptive loop is internally bounded (MAX_HYPOTHESES=10 ×
    # MAX_ATTEMPTS_PER_HYPOTHESIS=5), but each attempt's decide() call can
    # itself take up to ~90s on local Ollama models, and nothing in
    # cli_engine.py's `for agent in agents_to_run` loop ever timed out or
    # capped the phase — a single slow/looping agent could consume the
    # entire scan with zero backstop, unlike the cognee persist step (which
    # already uses this exact wait_for-then-skip pattern).
    DEEPAGENT_PER_AGENT_TIMEOUT_S: float = 150.0   # one agent's full run()
    DEEPAGENT_PHASE_BUDGET_S: float = 480.0        # whole 13-agent swarm

    # ─── Immune System / Co-Evolution ───
    GENOME_BLOCK_THRESHOLD: float = 0.7      # Anomaly score above this = BLOCK
    EVOLUTION_GENERATIONS: int = 10           # Default generations per run
    EVOLUTION_PAYLOADS_PER_GEN: int = 20      # Payloads per generation
    GENOME_STORAGE_DIR: str = ""              # Where to save genome state
    EVOLUTION_CONVERGENCE_THRESHOLD: float = 0.99

    # ─── Paths ───
    WORKING_DIR: str = ""  # Set at runtime
    WORDLIST_DIR: str = ""  # Auto-detected

    # ─── Platform detection ───
    IS_WINDOWS: bool = os.name == "nt"
    SHELL: str = "powershell" if os.name == "nt" else "/bin/bash"

    # ─── API Security ───
    # If empty, API is restricted to localhost clients only.
    API_AUTH_TOKEN: str = ""
    API_BIND_HOST: str = "127.0.0.1"
    API_BIND_PORT: int = 8000
    API_RELOAD: bool = False
    # Comma-separated origins, e.g. "http://localhost:5173,http://127.0.0.1:5173"
    API_CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"
    MAX_UPLOAD_MB: int = 500

    def __post_init__(self):
        # Override from env if available
        self.AI_BACKEND_MODE = os.getenv("AI_BACKEND_MODE", self.AI_BACKEND_MODE)
        self.GROQ_API_KEY = os.getenv("GROQ_API_KEY", self.GROQ_API_KEY)
        self.CEREBRAS_API_KEY = os.getenv("CEREBRAS_API_KEY", self.CEREBRAS_API_KEY)
        self.OLLAMA_URL = os.getenv("OLLAMA_URL", self.OLLAMA_URL)
        self.OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", self.OLLAMA_MODEL)
        self.COGNEE_LLM_MODEL = os.getenv("COGNEE_LLM_MODEL", self.COGNEE_LLM_MODEL)
        self.COGNEE_EMBEDDING_MODEL = os.getenv("COGNEE_EMBEDDING_MODEL", self.COGNEE_EMBEDDING_MODEL)
        self.COGNEE_RECALL_TIMEOUT_S = float(os.getenv("COGNEE_RECALL_TIMEOUT_S", self.COGNEE_RECALL_TIMEOUT_S))
        self.COGNEE_REMEMBER_TIMEOUT_S = float(os.getenv("COGNEE_REMEMBER_TIMEOUT_S", self.COGNEE_REMEMBER_TIMEOUT_S))
        self.DEEPAGENT_PER_AGENT_TIMEOUT_S = float(os.getenv("DEEPAGENT_PER_AGENT_TIMEOUT_S", self.DEEPAGENT_PER_AGENT_TIMEOUT_S))
        self.DEEPAGENT_PHASE_BUDGET_S = float(os.getenv("DEEPAGENT_PHASE_BUDGET_S", self.DEEPAGENT_PHASE_BUDGET_S))

        # Fall back to the main coding model if no cognee-specific model is set
        # — users shouldn't be forced into downloading a separate large model
        # just for this optional feature.
        if not self.COGNEE_LLM_MODEL:
            self.COGNEE_LLM_MODEL = self.OLLAMA_MODEL

        # Set working dir
        if not self.WORKING_DIR:
            self.WORKING_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "workdir")
            os.makedirs(self.WORKING_DIR, exist_ok=True)

        # Set genome storage dir
        if not self.GENOME_STORAGE_DIR:
            self.GENOME_STORAGE_DIR = os.path.join(self.WORKING_DIR, "genomes")
            os.makedirs(self.GENOME_STORAGE_DIR, exist_ok=True)


# Global config singleton
config = CyphexConfig()
