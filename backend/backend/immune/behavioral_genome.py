"""
CYPHEX — Behavioral Genome (Blue Team Defense)

Per-endpoint anomaly detector using Isolation Forest.
Learns what "normal" looks like for each endpoint, then scores
incoming requests — anything abnormal gets flagged.

This is the "immune system" core: it doesn't need a database of attacks,
it just knows what YOUR app looks like and blocks everything else.

Dependencies: scikit-learn, numpy (both CPU-only, work on Pi 5)
"""

import hashlib
import hmac
import math
import json
import os
import re
import secrets
from collections import Counter
from datetime import datetime
from typing import Optional

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib
    HAS_SKLEARN = True
except (ImportError, Exception):
    # numpy/scipy/sklearn may not have Python 3.14 wheels yet.
    # CLI degrades gracefully: immune system is disabled.
    import types
    np = types.ModuleType("numpy_stub")
    np.ndarray = list  # type: ignore
    np.array = list    # type: ignore
    np.zeros = lambda *a, **kw: []  # type: ignore
    HAS_SKLEARN = False

from models.genome import EndpointProfile, GenomeState
from models.scan import ScanContext


# ── Genome cache integrity (HMAC) ──
#
# `BehavioralGenome.save()` persists trained scikit-learn objects
# (IsolationForest / StandardScaler instances, not plain numeric/dict data)
# via joblib, which deserializes with pickle under the hood. A `.pkl` file
# placed at a predictable path (md5(target_url)-derived, see cli_engine.py)
# could otherwise be swapped for a crafted payload that executes arbitrary
# code the moment `load()` calls `joblib.load()`. Since the object graph
# here is genuine sklearn estimators (not simple data that could be moved
# to JSON/npz without a large refactor of the ML training code), we instead
# sign the cache with a per-installation HMAC secret and refuse to
# deserialize it if the signature is missing or doesn't match.
_HMAC_KEY_FILENAME = ".genome_hmac.key"


def _get_or_create_hmac_key(storage_dir: str) -> bytes:
    """
    Load the per-installation genome-signing secret, creating it on first
    use. Stored under the same storage dir as the genome caches, with
    permissions restricted to the owner.
    """
    storage_dir = storage_dir or "."
    os.makedirs(storage_dir, exist_ok=True)
    key_path = os.path.join(storage_dir, _HMAC_KEY_FILENAME)

    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            key = f.read()
        if key:
            return key

    # First run (or an empty/corrupt key file): generate a fresh secret and
    # write it with restrictive (owner-only) permissions.
    key = secrets.token_bytes(32)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return key


def _sign_file(path: str, key: bytes) -> str:
    """Compute a hex HMAC-SHA256 digest over a file's contents."""
    digest = hmac.new(key, digestmod=hashlib.sha256)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


class BehavioralGenome:
    """
    Blue Team Defense — learns what "normal" looks like for each endpoint
    and scores incoming requests for anomaly.

    Uses scikit-learn Isolation Forest:
    - Lightweight (<1ms inference, CPU-only)
    - Unsupervised (no labeled data needed)
    - Works on Raspberry Pi 5
    """

    def __init__(self):
        self.endpoint_models: dict[str, IsolationForest] = {}
        self.endpoint_profiles: dict[str, EndpointProfile] = {}
        self.scalers: dict[str, StandardScaler] = {}
        self.state: Optional[GenomeState] = None
        # Accumulate attack samples across generations for better learning
        self._attack_history: dict[str, list[np.ndarray]] = {}

    def build_from_scan(self, context: ScanContext) -> GenomeState:
        """
        Build initial genome from a CYPHEX scan result.
        Uses data already collected by Agent 01 (Recon) and Agent 02 (Crawler).
        """
        self.state = GenomeState(target_url=context.target_url)

        # Profile each endpoint discovered by the crawler
        for endpoint in context.all_endpoints:
            profile = self._build_endpoint_profile(endpoint, context)
            key = self._endpoint_key(endpoint)
            self.endpoint_profiles[key] = profile
            self.state.endpoints[key] = profile

            # Generate synthetic "normal" samples and train Isolation Forest
            normal_samples = self._generate_normal_samples(profile, n=100)
            if len(normal_samples) > 10:
                self._train_endpoint_model(key, normal_samples)

        # Profile forms as well
        for form in context.all_forms:
            profile = EndpointProfile(
                endpoint=form.action,
                method=form.method.upper(),
                input_fields=form.inputs,
                input_length_mean=15.0,
                input_length_std=10.0,
                input_charset_expected="mixed",
                input_entropy_mean=3.2,
                input_entropy_std=0.5,
                sample_count=100,
            )
            key = self._endpoint_key(form.action)
            self.endpoint_profiles[key] = profile
            self.state.endpoints[key] = profile

            normal_samples = self._generate_normal_samples(profile, n=100)
            if len(normal_samples) > 10:
                self._train_endpoint_model(key, normal_samples)

        return self.state

    def extract_features(self, text: str) -> np.ndarray:
        """
        Extract 15-dimensional feature vector from an input string.

        Features:
         1. input_length
         2. entropy (Shannon entropy)
         3. special_char_ratio (non-alphanumeric %)
         4. url_encoding_ratio (% of %XX sequences)
         5. uppercase_ratio
         6. digit_ratio
         7. max_token_length (longest "word")
         8. sql_keyword_score (presence of SQL/JS keywords)
         9. sqli_pattern_score (regex pattern matching for injection syntax)
        10. null_byte_present (\x00 or %00)
        11. path_traversal_depth (count of ../ sequences)
        12. bracket_imbalance (unmatched {, [, (, <)
        13. unicode_ratio (non-ASCII character %)
        14. repetition_ratio (most repeated char / length)
        15. token_count (number of tokens)
        """
        if not text:
            return np.zeros(15)

        length = len(text)
        entropy = self._shannon_entropy(text)

        # Special character ratio
        special = sum(1 for c in text if not c.isalnum() and c not in " ._-")
        special_ratio = special / max(length, 1)

        # URL encoding ratio
        url_encoded = len(re.findall(r'%[0-9A-Fa-f]{2}', text))
        url_ratio = url_encoded * 3 / max(length, 1)

        # Uppercase ratio
        upper = sum(1 for c in text if c.isupper())
        upper_ratio = upper / max(length, 1)

        # Digit ratio
        digits = sum(1 for c in text if c.isdigit())
        digit_ratio = digits / max(length, 1)

        # Max token length
        tokens = re.split(r'[\s+\-=&?/]', text)
        non_empty_tokens = [t for t in tokens if t]
        max_token = max((len(t) for t in non_empty_tokens), default=0)

        # SQL/JS keyword score
        keywords = [
            'select', 'union', 'insert', 'update', 'delete', 'drop', 'exec',
            'script', 'alert', 'onerror', 'onload', 'eval', 'document',
            'window', 'cookie', '--', '/*', '*/', 'waitfor', 'sleep',
            'benchmark', 'char(', 'concat(', 'information_schema',
            'onclick', 'onfocus', 'onmouseover', 'src=', 'href=',
            'passwd', 'shadow', '/etc/', 'cmd.exe', 'powershell',
            'wget', 'curl', 'base64', 'fromcharcode', 'settimeout',
        ]
        text_lower = text.lower()
        keyword_hits = sum(1 for kw in keywords if kw in text_lower)
        keyword_score = min(keyword_hits / 2.0, 1.0)

        # Injection pattern matching. Originally SQLi/XSS only; extended to the
        # modern classes the `cx benchmark` harness surfaced as blind spots
        # (SSTI, NoSQLi, SSRF, LDAP, CRLF) so per-class detection generalises
        # past keyword-based attacks. Length stays 15-D — this only feeds the
        # existing sqli_pattern_score dimension, so trained genomes still load.
        sqli_patterns = [
            # ── SQLi ──
            r"'\s*(or|and)\s+.*[=<>]",
            r"'\s*;\s*(drop|delete|insert|update)",
            r"\d+\s*=\s*\d+",
            r"'\s*=\s*'",
            r"union\s+(all\s+)?select",
            r"order\s+by\s+\d+",
            # ── Command injection ──
            r"(;|\|\||&&)\s*(ls|cat|dir|whoami|id|ping|curl|wget)",
            r"[;|&]\s*(nc|bash|sh|python|perl|powershell)\b",
            r"\$\(|`[^`]+`",
            # ── XSS ──
            r"<\s*script[^>]*>",
            r"<\s*\w+[^>]+on\w+\s*=",
            r"<\s*(img|svg|body|iframe|input|details|marquee|object)",
            r"javascript\s*:",
            # ── SSTI (template expression / sandbox escape) ──
            r"\{\{.+?\}\}",
            r"\$\{.+?\}",
            r"<%[=\s].*?%>",
            r"#\{.+?\}",
            # ── NoSQL injection ──
            r"\$(ne|gt|lt|gte|lte|regex|where|exists|in|nin)\b",
            r"'\s*\|\|\s*'",
            # ── SSRF: dangerous schemes + internal / cloud-metadata targets ──
            r"\b(file|gopher|dict|ldap|ftp)://",
            r"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200",
            r"://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?|169\.254\.)",
            # ── LDAP injection / CRLF header injection ──
            r"\)\s*\(\s*[\w|&]*=?",
            r"%0d%0a|%0a|\r\n",
        ]
        pattern_hits = sum(1 for p in sqli_patterns if re.search(p, text_lower))
        sqli_pattern_score = min(pattern_hits / 2.0, 1.0)

        # ── New features (10-15) ──

        # 10. Null byte detection
        null_byte = 1.0 if ('\x00' in text or '%00' in text_lower) else 0.0

        # 11. Path traversal depth
        traversal_count = len(re.findall(r'\.\.\/|\.\.\.\\', text))
        traversal_depth = min(traversal_count / 3.0, 1.0)

        # 12. Bracket imbalance (unmatched delimiters = likely injection)
        openers = sum(1 for c in text if c in '{[(<')
        closers = sum(1 for c in text if c in '}])>')
        bracket_imbalance = abs(openers - closers) / max(openers + closers, 1)

        # 13. Unicode ratio (non-ASCII chars — evasion technique)
        non_ascii = sum(1 for c in text if ord(c) > 127)
        unicode_ratio = non_ascii / max(length, 1)

        # 14. Repetition ratio (most-repeated char / length — DoS padding)
        if text:
            freq = Counter(text)
            repetition_ratio = freq.most_common(1)[0][1] / length
        else:
            repetition_ratio = 0.0

        # 15. Token count
        token_count = len(non_empty_tokens) / max(length / 5.0, 1.0)

        return np.array([
            length,
            entropy,
            special_ratio,
            url_ratio,
            upper_ratio,
            digit_ratio,
            max_token,
            keyword_score,
            sqli_pattern_score,
            null_byte,
            traversal_depth,
            bracket_imbalance,
            unicode_ratio,
            repetition_ratio,
            token_count,
        ])

    def score_request(self, endpoint: str, payload: str) -> float:
        """
        Score a request for anomaly. Returns 0.0 (normal) to 1.0 (anomalous).

        COMBINED scoring:
        - ML score (Isolation Forest): catches statistical anomalies
        - Heuristic score: catches known attack patterns (keywords, encoding)
        - Final = weighted combination for maximum detection
        """
        key = self._endpoint_key(endpoint)

        # Graceful degradation when numpy/sklearn is unavailable: extract_features
        # then returns a plain Python list (stub np.array=list) with no .reshape,
        # so score heuristically on the flat vector instead of touching the ML path.
        if not HAS_SKLEARN:
            return self._heuristic_score(self.extract_features(payload))

        # Extract features
        features = self.extract_features(payload).reshape(1, -1)

        # Heuristic score (always available, catches obvious attacks)
        heuristic = self._heuristic_score(features[0])

        # ML score (if model is trained for this endpoint)
        ml_score = 0.0
        if key in self.endpoint_models and key in self.scalers:
            try:
                scaled = self.scalers[key].transform(features)
                raw_score = self.endpoint_models[key].decision_function(scaled)[0]
                # Convert: lower raw_score = more anomalous
                # Typical range is [-0.5, 0.5], map to [1.0, 0.0]
                ml_score = max(0.0, min(1.0, 0.5 - raw_score))
            except Exception:
                ml_score = 0.0

        # Combined score: take the MAX of both signals
        # This means if EITHER detector flags it, it's suspicious
        # The heuristic catches keyword-based attacks
        # The ML catches statistical anomalies (unusual patterns)
        combined = max(ml_score, heuristic)

        # Boost: if BOTH detectors agree it's suspicious, extra confidence
        if ml_score > 0.3 and heuristic > 0.3:
            combined = min(1.0, combined + 0.15)

        return combined

    def retrain(self, endpoint: str, attack_samples: list[str]):
        """
        Retrain the genome for a specific endpoint with attack data.
        Called after each evolution generation.

        ACCUMULATES attack history across generations so the genome
        gets progressively better — each generation's bypasses make
        the next generation's detection stronger.
        """
        key = self._endpoint_key(endpoint)

        # Get existing normal samples or generate them
        profile = self.endpoint_profiles.get(key)
        if not profile:
            return

        # Generate diverse normal samples (different seed each time)
        seed = hash(datetime.now().isoformat()) % (2**31)
        normal_samples = self._generate_normal_samples(profile, n=200, seed=seed)

        # Extract features from new attack samples
        new_attack_features = [self.extract_features(s) for s in attack_samples]

        # ACCUMULATE attacks across generations (key improvement)
        if key not in self._attack_history:
            self._attack_history[key] = []
        self._attack_history[key].extend(new_attack_features)

        # Use ALL accumulated attacks for training (up to 500)
        all_attacks = self._attack_history[key][-500:]

        # Combine: mostly normal + accumulated attacks
        all_features = normal_samples + all_attacks
        contamination = len(all_attacks) / max(len(all_features), 1)
        self._train_endpoint_model(key, all_features, contamination=contamination)

        if self.state:
            self.state.last_evolved = datetime.now().isoformat()

    def _train_endpoint_model(
        self, key: str, samples: list[np.ndarray], contamination: float = 0.1
    ):
        """Train an Isolation Forest for a specific endpoint."""
        if not HAS_SKLEARN or len(samples) < 10:
            return

        X = np.array(samples)

        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # Train Isolation Forest
        clf = IsolationForest(
            n_estimators=100,
            contamination=max(0.01, min(contamination, 0.4)),
            random_state=42,
            n_jobs=1,  # Single thread for Pi 5 compatibility
        )
        clf.fit(X_scaled)

        self.endpoint_models[key] = clf
        self.scalers[key] = scaler

    def _build_endpoint_profile(
        self, endpoint: str, context: ScanContext
    ) -> EndpointProfile:
        """Build a behavioral profile from scan context data."""
        # Determine method from discovered params/forms
        method = "GET"
        input_fields = []

        for param in context.all_params:
            if param.url == endpoint:
                input_fields.append(param.name)

        for form in context.all_forms:
            if form.action == endpoint:
                method = form.method.upper()
                input_fields = form.inputs

        return EndpointProfile(
            endpoint=endpoint,
            method=method,
            input_fields=input_fields,
            input_length_mean=12.0,
            input_length_std=8.0,
            input_charset_expected="alphanumeric",
            input_entropy_mean=3.0,
            input_entropy_std=0.4,
            sample_count=100,
        )

    # ── Realistic input generators for training data ──
    _REALISTIC_NAMES = [
        "john_doe", "alice.smith", "bob_jones", "María García", "O'Brien",
        "jean-claude", "user2024", "admin_test", "sarah.connor", "mike_t",
        "李明", "Hans Müller", "François", "nakamura_yuki", "dev.user",
    ]
    _REALISTIC_EMAILS = [
        "john@example.com", "alice.smith@company.co", "user+tag@gmail.com",
        "admin@localhost", "support@web-app.io", "test.user@domain.org",
        "name@sub.domain.com", "hello@company.co.uk", "user@192.168.1.1",
    ]
    _REALISTIC_SEARCHES = [
        "laptop 16gb ram", "how to reset password", "O'Brien report 2024",
        "best price < $500", "shoes size 10.5", "café near me",
        "node.js tutorial", "error: connection refused", "meeting 3pm",
        "annual report Q3", "blue dress size M", "python3 --version",
        "flight LAX → JFK", "résumé template", "2024-01-15 log",
    ]
    _REALISTIC_PASSWORDS = [
        "P@ssw0rd!2024", "MyS3cur3#Pass", "hunter2", "correct-horse-battery",
        "X9#kL2$mN", "Summer2024!", "qwerty123", "iloveyou",
    ]
    _REALISTIC_PATHS = [
        "/home/user/docs/report.pdf", "C:\\Users\\admin\\file.txt",
        "./src/index.js", "../config/settings.json", "/var/log/app.log",
        "uploads/avatar.png", "static/css/style.css",
    ]

    def _generate_normal_samples(
        self, profile: EndpointProfile, n: int = 100, seed: int = 42
    ) -> list[np.ndarray]:
        """
        Generate synthetic "normal" traffic samples for an endpoint.
        Uses REALISTIC input patterns based on field names to produce
        training data that resembles actual user traffic.
        """
        # np.random is absent on the stub (numpy/sklearn missing) — with no ML to
        # train, there is nothing to generate; build_from_scan then just registers
        # the endpoint profile and scoring falls back to the heuristic path.
        if not HAS_SKLEARN:
            return []
        samples = []
        rng = np.random.default_rng(seed)

        # Infer field type from field names in the profile
        field_types = []
        for field_name in (profile.input_fields or ["generic"]):
            fn = field_name.lower()
            if any(k in fn for k in ["email", "mail"]):
                field_types.append("email")
            elif any(k in fn for k in ["user", "name", "login", "author"]):
                field_types.append("username")
            elif any(k in fn for k in ["pass", "pwd", "secret", "token"]):
                field_types.append("password")
            elif any(k in fn for k in ["search", "q", "query", "keyword", "term"]):
                field_types.append("search")
            elif any(k in fn for k in ["id", "uid", "pid", "num", "page", "limit"]):
                field_types.append("id")
            elif any(k in fn for k in ["file", "path", "dir", "url", "href", "src"]):
                field_types.append("path")
            else:
                field_types.append("generic")

        if not field_types:
            field_types = ["generic"]

        for _ in range(n):
            field_type = rng.choice(field_types)
            text = self._generate_realistic_input(field_type, rng)
            features = self.extract_features(text)
            samples.append(features)

        return samples

    def _generate_realistic_input(self, field_type: str, rng) -> str:
        """Generate a realistic input string for a given field type."""
        if field_type == "email":
            return str(rng.choice(self._REALISTIC_EMAILS))
        elif field_type == "username":
            return str(rng.choice(self._REALISTIC_NAMES))
        elif field_type == "password":
            return str(rng.choice(self._REALISTIC_PASSWORDS))
        elif field_type == "search":
            return str(rng.choice(self._REALISTIC_SEARCHES))
        elif field_type == "id":
            return str(rng.integers(1, 10000))
        elif field_type == "path":
            return str(rng.choice(self._REALISTIC_PATHS))
        else:
            # Generic: mix of realistic patterns
            generators = [
                lambda: str(rng.choice(self._REALISTIC_NAMES)),
                lambda: str(rng.choice(self._REALISTIC_SEARCHES)),
                lambda: str(rng.integers(1, 99999)),
                lambda: str(rng.choice(self._REALISTIC_EMAILS)),
                lambda: f"page {rng.integers(1, 50)} results",
                lambda: f"{rng.integers(2020, 2026)}-{rng.integers(1,13):02d}-{rng.integers(1,29):02d}",
            ]
            return rng.choice(generators)()

    def _heuristic_score(self, features: np.ndarray) -> float:
        """
        Heuristic scoring based on feature thresholds.
        Catches attacks that Isolation Forest may miss.
        Uses all 15 features for comprehensive detection.
        """
        score = 0.0

        length = features[0]
        entropy = features[1]
        special_ratio = features[2]
        url_ratio = features[3]
        keyword_score = features[7]
        sqli_pattern = features[8]
        null_byte = features[9] if len(features) > 9 else 0.0
        traversal_depth = features[10] if len(features) > 10 else 0.0
        bracket_imbalance = features[11] if len(features) > 11 else 0.0
        unicode_ratio = features[12] if len(features) > 12 else 0.0

        # Very long inputs are suspicious
        if length > 100:
            score += 0.2
        if length > 500:
            score += 0.3

        # High entropy = random/encoded = suspicious
        if entropy > 4.0:
            score += 0.2
        if entropy > 5.0:
            score += 0.3

        # Lots of special characters = suspicious
        if special_ratio > 0.3:
            score += 0.2
        if special_ratio > 0.15:
            score += 0.1

        # URL encoding = possible evasion
        if url_ratio > 0.1:
            score += 0.15

        # SQL/JS keywords
        if keyword_score > 0.2:
            score += 0.3
        if keyword_score > 0.5:
            score += 0.2

        # SQLi/XSS PATTERN match (strongest signal!)
        if sqli_pattern > 0.0:
            score += 0.5
        if sqli_pattern > 0.5:
            score += 0.3

        # ── New feature-based heuristics ──

        # Null byte = almost always an attack
        if null_byte > 0.0:
            score += 0.7

        # Path traversal
        if traversal_depth > 0.0:
            score += 0.5

        # Bracket imbalance = injection syntax
        if bracket_imbalance > 0.5:
            score += 0.2

        # High unicode ratio with other signals = evasion
        if unicode_ratio > 0.3 and keyword_score > 0.1:
            score += 0.2

        return min(score, 1.0)

    def _shannon_entropy(self, text: str) -> float:
        """Shannon entropy — measures randomness of input."""
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    def _endpoint_key(self, endpoint: str) -> str:
        """Normalize endpoint to a consistent key."""
        return endpoint.rstrip("/").lower()

    def save(self, filepath: str):
        """Serialize genome to disk."""
        if not HAS_SKLEARN:
            return
        data = {
            "state": self.state.to_dict() if self.state else {},
            "profiles": {k: v.to_dict() for k, v in self.endpoint_profiles.items()},
        }
        # Save metadata as JSON
        with open(filepath + ".json", "w") as f:
            json.dump(data, f, indent=2)
        # Save sklearn models + the rest of the genome state so a reload actually
        # CONTINUES evolution instead of silently resetting it. Previously only
        # models/scalers were persisted, and load() dropped the profiles, state,
        # and accumulated _attack_history that retrain() builds on — so adversarial
        # adaptation was lost every run. joblib pickles the dataclasses/arrays
        # directly and the HMAC below covers the whole pkl.
        models_data = {
            "models": self.endpoint_models,
            "scalers": self.scalers,
            "profiles": self.endpoint_profiles,
            "state": self.state,
            "attack_history": self._attack_history,
        }
        pkl_path = filepath + ".pkl"
        joblib.dump(models_data, pkl_path)

        # Sign the cache so a future `load()` can detect a swapped/tampered
        # .pkl before handing it to joblib (== pickle) for deserialization.
        key = _get_or_create_hmac_key(os.path.dirname(filepath))
        digest = _sign_file(pkl_path, key)
        hmac_path = pkl_path + ".hmac"
        with open(hmac_path, "w") as f:
            f.write(digest)
        try:
            os.chmod(hmac_path, 0o600)
        except OSError:
            pass

    @classmethod
    def load(cls, filepath: str) -> "BehavioralGenome":
        """Load genome from disk."""
        genome = cls()
        pkl_path = filepath + ".pkl"
        if os.path.exists(pkl_path):
            # Refuse to deserialize (joblib.load == pickle.load) unless the
            # cache carries a valid HMAC signed with our per-installation
            # secret. An attacker who can drop/replace a .pkl at this
            # predictable path (md5(target_url)-derived) but not read our
            # local secret cannot forge a matching signature.
            hmac_path = pkl_path + ".hmac"
            if not os.path.exists(hmac_path):
                raise ValueError(
                    f"Refusing to load genome cache without a signature: {pkl_path}"
                )
            with open(hmac_path, "r") as f:
                expected_digest = f.read().strip()
            key = _get_or_create_hmac_key(os.path.dirname(filepath))
            actual_digest = _sign_file(pkl_path, key)
            if not hmac.compare_digest(expected_digest, actual_digest):
                raise ValueError(
                    f"Genome cache HMAC mismatch (possible tampering) — refusing to load: {pkl_path}"
                )
            models_data = joblib.load(pkl_path)
            genome.endpoint_models = models_data.get("models", {})
            genome.scalers = models_data.get("scalers", {})
            # Restore the rest of the genome so evolution continues (older caches
            # lacking these keys fall back to empty via .get()).
            genome.endpoint_profiles = models_data.get("profiles", {})
            genome.state = models_data.get("state", None)
            genome._attack_history = models_data.get("attack_history", {})
        return genome
