"""
CYPHEX CLI — Hardware Detection & Smart Model Selection

Detects available GPU/unified memory and selects the BEST Ollama models
that will actually fit. The philosophy: always use the largest model your
hardware can run — small models produce garbage patches.

Tiers (based on usable VRAM/unified memory):
─────────────────────────────────────────────
  Tier     VRAM       Best Code Model        Best General Model
  ──────   ────────   ────────────────────    ──────────────────
  ultra    24+ GB     qwen2.5-coder:14b      llama3.1:14b
  high     12+ GB     qwen2.5-coder:7b       llama3.1:8b
  mid       6+ GB     deepseek-coder:6.7b    phi3:medium
  low       4+ GB     deepseek-coder:1.3b    phi3:mini
  minimal   2+ GB     deepseek-coder:1.3b    (none)
  cloud     <2 GB     (cloud API)            (cloud API)
"""

import os
import shutil
import subprocess
import platform
from typing import Optional


# ═══════════════════════════════════════════════════════════════
# Model Catalog — ordered by preference (best first)
# Each entry: (model_tag, param_billions, vram_needed_gb, role)
# ═══════════════════════════════════════════════════════════════

MODEL_CATALOG = [
    # ── Ultra tier (24+ GB) ──
    {"tag": "qwen2.5-coder:14b",   "params": 14.0, "vram": 20.0, "role": "code",    "tier": "ultra"},
    {"tag": "llama3.1:14b",        "params": 14.0, "vram": 20.0, "role": "general",  "tier": "ultra"},

    # ── High tier (12+ GB) — sweet spot for M1 Pro/M2/RTX 3060+ ──
    {"tag": "qwen2.5-coder:7b",    "params": 7.0,  "vram": 8.0,  "role": "code",    "tier": "high"},
    {"tag": "llama3.1:8b",         "params": 8.0,  "vram": 8.0,  "role": "general",  "tier": "high"},
    {"tag": "deepseek-coder:6.7b", "params": 6.7,  "vram": 7.0,  "role": "code",    "tier": "high"},
    {"tag": "codellama:7b",        "params": 7.0,  "vram": 7.0,  "role": "code",    "tier": "high"},

    # ── Mid tier (6+ GB) ──
    {"tag": "phi3:medium",         "params": 14.0, "vram": 10.0, "role": "general",  "tier": "mid"},
    {"tag": "codegemma:7b",        "params": 7.0,  "vram": 7.0,  "role": "code",    "tier": "mid"},
    {"tag": "mistral:7b",          "params": 7.0,  "vram": 6.0,  "role": "general",  "tier": "mid"},

    # ── Low tier (4+ GB) ──
    {"tag": "phi3:mini",           "params": 3.8,  "vram": 3.5,  "role": "general",  "tier": "low"},
    {"tag": "deepseek-coder:1.3b", "params": 1.3,  "vram": 1.5,  "role": "code",    "tier": "low"},
    {"tag": "llama3.2:1b",         "params": 1.0,  "vram": 1.2,  "role": "general",  "tier": "low"},

    # ── Minimal tier (2+ GB) ──
    {"tag": "qwen2.5-coder:0.5b",  "params": 0.5,  "vram": 0.8,  "role": "code",    "tier": "minimal"},
]

# Minimum model params for reliable patching/debate
MIN_PARAMS_FOR_PATCHING = 7.0
MIN_PARAMS_FOR_DEBATE = 7.0


def get_gpu_info() -> dict:
    """
    Detect GPU and available VRAM across platforms.
    Returns: {"gpu_name": str, "vram_gb": float, "platform": str}
    """
    system = platform.system().lower()
    info = {"gpu_name": "None", "vram_gb": 0.0, "platform": system}

    # ── NVIDIA (Windows/Linux) ──
    if shutil.which("nvidia-smi"):
        try:
            result = subprocess.run(
                ["nvidia-smi", "--query-gpu=name,memory.total",
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                line = result.stdout.strip().split("\n")[0]
                parts = line.split(", ")
                if len(parts) == 2:
                    info["gpu_name"] = parts[0].strip()
                    info["vram_gb"] = round(int(parts[1].strip()) / 1024, 1)
                    return info
        except Exception:
            pass

    # ── Apple Silicon (macOS — unified memory) ──
    if system == "darwin":
        try:
            result = subprocess.run(
                ["sysctl", "-n", "hw.memsize"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                total_bytes = int(result.stdout.strip())
                # Apple Silicon shares RAM with GPU; report ~75% as available for ML
                total_gb = total_bytes / (1024 ** 3)
                info["gpu_name"] = _get_apple_chip()
                info["vram_gb"] = round(total_gb * 0.75, 1)
                return info
        except Exception:
            pass

    # ── AMD ROCm (Linux) ──
    if shutil.which("rocm-smi"):
        try:
            result = subprocess.run(
                ["rocm-smi", "--showmeminfo", "vram"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "Total" in line:
                        # Parse total VRAM in MB
                        parts = line.split()
                        for i, p in enumerate(parts):
                            if p.isdigit():
                                info["vram_gb"] = round(int(p) / 1024, 1)
                                info["gpu_name"] = "AMD GPU (ROCm)"
                                return info
        except Exception:
            pass

    return info


def _get_apple_chip() -> str:
    """Detect Apple Silicon chip model."""
    try:
        result = subprocess.run(
            ["sysctl", "-n", "machdep.cpu.brand_string"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "Apple Silicon"


def detect_mode(vram_gb: Optional[float] = None) -> str:
    """
    Select operating mode based on available VRAM.

    Returns: 'ultra' | 'high' | 'mid' | 'low' | 'minimal' | 'cloud'
    """
    if vram_gb is None:
        vram_gb = get_gpu_info()["vram_gb"]

    if vram_gb >= 24.0:
        return "ultra"
    elif vram_gb >= 12.0:
        return "high"
    elif vram_gb >= 6.0:
        return "mid"
    elif vram_gb >= 4.0:
        return "low"
    elif vram_gb >= 2.0:
        return "minimal"
    else:
        return "cloud"


MODE_DESCRIPTIONS = {
    "ultra":   "14B+ models — maximum accuracy for code analysis & patching",
    "high":    "7B-8B models — reliable patching, debate, and reports",
    "mid":     "6-7B models — good analysis, functional patching",
    "low":     "1-4B models — basic scanning, patching quality limited",
    "minimal": "< 2B model — scanning only, AI patching disabled",
    "cloud":   "Cloud LLM via Groq/OpenAI (set GROQ_API_KEY or OPENAI_API_KEY)",
}


def recommend_models(vram_gb: float) -> dict:
    """
    Given available VRAM, recommend the best models to install.
    
    Returns: {
        "code": {"tag": "...", "params": ..., "vram": ...},
        "general": {"tag": "...", "params": ..., "vram": ...},
        "validator": {"tag": "...", "params": ..., "vram": ...} or None,
        "total_vram": float,
        "can_patch": bool,
        "can_debate": bool,
    }
    """
    # Find best code model that fits
    code_model = None
    general_model = None

    for m in MODEL_CATALOG:
        if m["role"] == "code" and m["vram"] <= vram_gb and code_model is None:
            code_model = m
        if m["role"] == "general" and m["vram"] <= vram_gb and general_model is None:
            general_model = m

    # If we can fit both, check total doesn't exceed VRAM
    # (Ollama swaps models, so we only need space for the LARGEST one at a time)
    largest_vram = 0
    if code_model:
        largest_vram = max(largest_vram, code_model["vram"])
    if general_model:
        largest_vram = max(largest_vram, general_model["vram"])

    # Try to find a 3rd model for validator diversity (smaller than primary)
    validator_model = None
    if code_model and general_model:
        for m in MODEL_CATALOG:
            if (m["tag"] != code_model["tag"] and
                m["tag"] != general_model["tag"] and
                m["vram"] <= vram_gb):
                validator_model = m
                break

    can_patch = code_model is not None and code_model["params"] >= MIN_PARAMS_FOR_PATCHING
    can_debate = general_model is not None and general_model["params"] >= MIN_PARAMS_FOR_DEBATE

    return {
        "code": code_model,
        "general": general_model,
        "validator": validator_model,
        "total_vram": largest_vram,
        "can_patch": can_patch,
        "can_debate": can_debate,
    }


# Legacy compat — MODE_MODELS now computed dynamically
def get_mode_models(mode: str, vram_gb: float = 0) -> list[str]:
    """Get recommended model tags for a given mode."""
    rec = recommend_models(vram_gb)
    models = []
    if rec["code"]:
        models.append(rec["code"]["tag"])
    if rec["general"]:
        models.append(rec["general"]["tag"])
    if rec["validator"]:
        models.append(rec["validator"]["tag"])
    return models


# Legacy compat
MODE_MODELS = {
    "ultra":   ["qwen2.5-coder:14b", "llama3.1:14b"],
    "high":    ["qwen2.5-coder:7b", "llama3.1:8b"],
    "mid":     ["deepseek-coder:6.7b", "mistral:7b"],
    "low":     ["deepseek-coder:1.3b", "phi3:mini"],
    "minimal": ["deepseek-coder:1.3b"],
    "cloud":   [],
}
