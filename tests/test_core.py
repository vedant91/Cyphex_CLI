"""
CYPHEX — Core Test Suite

Tests the critical components without requiring Ollama, Docker, or external tools.
"""

import ast
import os
import sys
import glob

# Ensure project root is importable
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "backend", "backend"))


class TestSyntax:
    """All Python files must parse without errors."""

    def test_all_files_parse(self):
        errors = []
        SKIP_DIRS = ["node_modules", ".git", "__pycache__", "venv", "finetune", "sandboxes"]
        for f in glob.glob(os.path.join(ROOT, "**", "*.py"), recursive=True):
            if any(skip in f for skip in SKIP_DIRS):
                continue
            try:
                ast.parse(open(f, encoding="utf-8", errors="ignore").read())
            except SyntaxError as e:
                errors.append(f"{f}: {e}")
        assert not errors, f"Syntax errors:\n" + "\n".join(errors)


class TestGenome:
    """Test Behavioral Genome core functionality."""

    def test_feature_vector_dimensions(self):
        from immune.behavioral_genome import BehavioralGenome
        genome = BehavioralGenome()
        features = genome.extract_features("normal search query")
        assert len(features) == 15, f"Expected 15 features, got {len(features)}"

    def test_empty_input(self):
        from immune.behavioral_genome import BehavioralGenome
        genome = BehavioralGenome()
        features = genome.extract_features("")
        assert len(features) == 15
        assert all(f == 0.0 for f in features)

    def test_sqli_detection(self):
        from immune.behavioral_genome import BehavioralGenome
        genome = BehavioralGenome()
        features = genome.extract_features("' OR 1=1--")
        # keyword_score (index 7) and sqli_pattern_score (index 8) should be > 0
        assert features[7] > 0 or features[8] > 0, "SQLi payload should trigger keyword or pattern score"

    def test_xss_detection(self):
        from immune.behavioral_genome import BehavioralGenome
        genome = BehavioralGenome()
        features = genome.extract_features("<script>alert(1)</script>")
        assert features[7] > 0, "XSS payload should trigger keyword score"

    def test_null_byte_detection(self):
        from immune.behavioral_genome import BehavioralGenome
        genome = BehavioralGenome()
        features = genome.extract_features("file.txt%00.jpg")
        assert features[9] == 1.0, "Null byte should be detected (feature 9)"

    def test_path_traversal_detection(self):
        from immune.behavioral_genome import BehavioralGenome
        genome = BehavioralGenome()
        features = genome.extract_features("../../../etc/passwd")
        assert features[10] > 0, "Path traversal should be detected (feature 10)"

    def test_heuristic_blocks_attack(self):
        from immune.behavioral_genome import BehavioralGenome
        genome = BehavioralGenome()
        features = genome.extract_features("' UNION SELECT * FROM users--")
        score = genome._heuristic_score(features)
        assert score >= 0.7, f"SQLi payload should score >= 0.7, got {score}"

    def test_heuristic_passes_normal(self):
        from immune.behavioral_genome import BehavioralGenome
        genome = BehavioralGenome()
        features = genome.extract_features("john.doe@gmail.com")
        score = genome._heuristic_score(features)
        assert score < 0.5, f"Normal email should score < 0.5, got {score}"

    def test_realistic_sample_generation(self):
        from immune.behavioral_genome import BehavioralGenome
        from models.genome import EndpointProfile
        genome = BehavioralGenome()
        profile = EndpointProfile(
            endpoint="/api/login", method="POST",
            input_fields=["username", "password"]
        )
        samples = genome._generate_normal_samples(profile, n=20)
        assert len(samples) == 20
        # All samples should have 15 features
        assert all(len(s) == 15 for s in samples)


class TestScanner:
    """Test static scanner pattern matching."""

    def test_language_detection(self):
        from cyphex.scanner import _get_language_for_file
        assert _get_language_for_file("app.js") == "javascript"
        assert _get_language_for_file("main.py") == "python"
        assert _get_language_for_file("Server.java") == "java"
        assert _get_language_for_file("main.go") == "go"
        assert _get_language_for_file("index.php") == "php"
        assert _get_language_for_file("app.rb") == "ruby"
        assert _get_language_for_file("main.rs") == "rust"
        assert _get_language_for_file("file.txt") is None

    def test_pattern_inheritance(self):
        from cyphex.scanner import LANGUAGE_PATTERNS
        # TypeScript should inherit JavaScript rules
        ts_rules = LANGUAGE_PATTERNS["typescript"]["rules"]
        js_rules = LANGUAGE_PATTERNS["javascript"]["rules"]
        assert ts_rules == js_rules


class TestFormatters:
    """Test output formatters."""

    def test_json_output(self):
        import json
        from cyphex.formatters import to_json
        result = {"scan_id": "test", "score": 85, "vulnerabilities": []}
        output = to_json(result)
        parsed = json.loads(output)
        assert parsed["score"] == 85

    def test_sarif_output(self):
        import json
        from cyphex.formatters import to_sarif
        result = {
            "scan_id": "test",
            "version": "0.1.0",
            "vulnerabilities": [{
                "name": "SQLi",
                "severity": "Critical",
                "cwe": "CWE-89",
                "endpoint": "/api/login",
            }]
        }
        output = to_sarif(result)
        parsed = json.loads(output)
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"][0]["results"]) == 1

    def test_markdown_output(self):
        from cyphex.formatters import to_markdown
        result = {
            "scan_id": "test",
            "score": 50,
            "summary": {"critical": 1, "high": 2, "medium": 0, "low": 0, "total_vulns": 3},
            "vulnerabilities": []
        }
        output = to_markdown(result)
        assert "CYPHEX Security Assessment" in output
        assert "50/100" in output


class TestHardware:
    """Test hardware detection."""

    def test_mode_selection(self):
        from cyphex.hardware import detect_mode
        # Verify current 6-tier system thresholds (from hardware.py):
        # ultra: >=24, high: >=12, mid: >=6, low: >=4, minimal: >=2, cloud: <2
        assert detect_mode(25.0) == "ultra"
        assert detect_mode(12.0) == "high"
        assert detect_mode(8.0)  == "mid"
        assert detect_mode(5.0)  == "low"
        assert detect_mode(3.0)  == "minimal"
        assert detect_mode(1.0)  == "cloud"
        assert detect_mode(0.0)  == "cloud"


class TestConfig:
    """Test configuration safety."""

    def test_no_hardcoded_api_key(self):
        config_path = os.path.join(ROOT, "backend", "backend", "config.py")
        with open(config_path) as f:
            content = f.read()
        assert "csk-" not in content, "Hardcoded Cerebras API key found in config.py!"

    def test_vram_costs_complete(self):
        sys.path.insert(0, os.path.join(ROOT, "backend"))
        from council.council_orchestrator import VRAMManager
        assert "qwen2.5-coder:7b" in VRAMManager.VRAM_COST
        assert "qwen2.5-coder:3b" in VRAMManager.VRAM_COST
