"""
CYPHEX — Network Behavioural Genome

Per-device anomaly detection using Isolation Forest — same approach as
backend/backend/immune/behavioral_genome.py but applied to network traffic
instead of HTTP payloads.

Learns what "normal" looks like for each device on the network, then
continuously scores deviations. No signatures required.

25-dimensional feature vector per observation window:
  1–5:   Traffic volume (bytes/s, packet rate, connection count)
  6–10:  Port behaviour (unique ports, entropy, scan ratio)
  11–14: Protocol mix (TCP:UDP:ICMP, DNS rate, cleartext ratio)
  15–18: Temporal (hour-of-day, burst score, idle ratio, session length)
  19–22: Destination (unique IPs, LAN/WAN ratio, new dests, /8 spread)
  23–25: Scan indicators (ARP rate, ICMP rate, SYN-without-ACK rate)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
import time
from collections import Counter
from datetime import datetime
from typing import Optional

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib
    HAS_SKLEARN = True
except ImportError:
    import types
    np = types.ModuleType("numpy_stub")
    np.ndarray = list  # type: ignore
    np.array = list    # type: ignore
    np.zeros = lambda *a, **kw: []  # type: ignore
    HAS_SKLEARN = False

from backend.network.models import DeviceBehaviourWindow, AnomalyScore

# Feature dimension names (for explainability)
FEATURE_NAMES = [
    "bytes_sent_rate", "bytes_recv_rate", "packet_rate",
    "connection_count", "new_connection_rate",
    "unique_remote_ports", "port_entropy", "scan_ratio",
    "high_risk_port_ratio", "unexpected_port_count",
    "protocol_mix_tcp_ratio", "dns_query_rate",
    "http_ratio", "cleartext_ratio",
    "hour_of_day_score", "burst_score", "idle_ratio", "session_duration_mean",
    "unique_remote_ips", "lan_wan_ratio", "new_dest_ratio", "geo_spread",
    "arp_broadcast_rate", "icmp_rate", "syn_without_ack_rate",
]

# Ports classified as high-risk for the high_risk_port_ratio feature
HIGH_RISK_PORTS = {
    21, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5432,
    5900, 6379, 9200, 11211, 27017, 2375,
}

# Ports classified as cleartext protocols
CLEARTEXT_PORTS = {21, 23, 25, 80, 110, 143, 8080}

ANOMALY_THRESHOLD = 0.65   # score above this → flagged
CACHE_DIR = os.path.expanduser("~/.cyphex/network_genome")


# ── HMAC integrity helpers (mirrors behavioral_genome.py pattern) ─────────────

def _get_or_create_hmac_key() -> bytes:
    os.makedirs(CACHE_DIR, exist_ok=True)
    key_path = os.path.join(CACHE_DIR, ".genome_hmac.key")
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            key = f.read()
        if key:
            return key
    key = secrets.token_bytes(32)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key


def _sign_file(path: str, key: bytes) -> str:
    digest = hmac.new(key, digestmod=hashlib.sha256)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ── Feature extraction ────────────────────────────────────────────────────────

def _shannon_entropy(values: list) -> float:
    """Shannon entropy of a list of discrete values."""
    if not values:
        return 0.0
    total = len(values)
    counts = Counter(values)
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


def extract_features(window: DeviceBehaviourWindow,
                     baseline_port_set: Optional[set] = None) -> list:
    """
    Convert a DeviceBehaviourWindow into a 25-element feature vector.
    baseline_port_set: set of ports seen during training (for unexpected_port_count).
    """
    w = window
    mins = max(w.window_minutes, 1)

    # 1–5: Volume
    bytes_sent_rate = w.bytes_sent_total / mins / 60.0
    bytes_recv_rate = w.bytes_recv_total / mins / 60.0
    packet_rate     = (w.packets_sent_total + w.packets_recv_total) / mins / 60.0
    connection_count = w.active_connections
    new_conn_rate   = w.new_connections / mins

    # 6–10: Port behaviour
    port_list = list(w.unique_remote_ports)
    unique_ports = len(port_list)
    port_entropy = _shannon_entropy(port_list)
    total_conns = max(w.new_connections, 1)
    scan_ratio = w.refused_connections / total_conns
    high_risk_ratio = sum(1 for p in port_list if p in HIGH_RISK_PORTS) / max(unique_ports, 1)
    unexpected = 0
    if baseline_port_set:
        unexpected = sum(1 for p in port_list if p not in baseline_port_set)

    # 11–14: Protocol mix
    total_proto = max(w.tcp_count + w.udp_count + w.icmp_count, 1)
    tcp_ratio  = w.tcp_count / total_proto
    dns_rate   = w.dns_queries / mins
    http_ratio = w.http_connections / max(w.active_connections, 1)
    cleartext_ratio = w.cleartext_connections / max(w.active_connections, 1)

    # 15–18: Temporal
    hour_now = datetime.utcnow().hour
    # Score deviation from business hours (9-18): 0=business hours, 1=midnight
    hour_score = abs(hour_now - 13.5) / 13.5  # peaks at midnight/noon edges
    burst_score = min(new_conn_rate / max(w.active_connections, 1), 1.0)
    idle_ratio = 0.0   # would need time-series data; default safe
    session_dur = 0.0  # would need per-flow timing data; default safe

    # 19–22: Destinations
    unique_ips = len(w.unique_remote_ips)
    lan_wan_total = max(w.lan_connections + w.wan_connections, 1)
    lan_wan_ratio = w.lan_connections / lan_wan_total
    new_dest_ratio = w.new_destinations / max(unique_ips, 1)
    # geo_spread: approximate by counting distinct /8 subnets
    geo_spread = len(set(ip.split(".")[0] for ip in w.unique_remote_ips if ip))

    # 23–25: Scan indicators
    arp_rate = w.arp_broadcasts / mins
    icmp_rate = w.icmp_count / mins
    syn_no_ack_rate = w.syn_no_ack / total_conns

    return [
        bytes_sent_rate, bytes_recv_rate, packet_rate,
        float(connection_count), new_conn_rate,
        float(unique_ports), port_entropy, scan_ratio,
        high_risk_ratio, float(unexpected),
        tcp_ratio, dns_rate,
        http_ratio, cleartext_ratio,
        hour_score, burst_score, idle_ratio, session_dur,
        float(unique_ips), lan_wan_ratio, new_dest_ratio, float(geo_spread),
        arp_rate, icmp_rate, syn_no_ack_rate,
    ]


# ── Main genome class ─────────────────────────────────────────────────────────

class NetworkBehavioralGenome:
    """
    Per-device behavioural anomaly detector.
    Trains an IsolationForest on historical network observations,
    then scores live observations for deviation from the learned baseline.
    """

    def __init__(self):
        self.device_models: dict[str, "IsolationForest"] = {}
        self.device_scalers: dict[str, "StandardScaler"] = {}
        self.device_port_baselines: dict[str, set] = {}
        self.device_feature_means: dict[str, list] = {}
        self.device_feature_stds: dict[str, list] = {}
        self._hmac_key: Optional[bytes] = None

    # ── Training ──────────────────────────────────────────────────────────────

    def train(self, device_ip: str,
              windows: list[DeviceBehaviourWindow],
              n_synthetic: int = 200) -> bool:
        """
        Train a baseline model for a device.
        If fewer than 20 real observations are available, generates synthetic
        normal samples so the forest has enough data to learn from.

        Returns True if training succeeded.
        """
        if not HAS_SKLEARN:
            return False

        features = [extract_features(w) for w in windows]

        if len(features) < 20:
            features += self._generate_synthetic_normal(device_ip, n_synthetic)

        try:
            X = np.array(features)
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            model = IsolationForest(
                n_estimators=150,
                contamination=0.05,     # expect 5% anomalies
                random_state=42,
                n_jobs=1,
            )
            model.fit(X_scaled)

            self.device_models[device_ip] = model
            self.device_scalers[device_ip] = scaler

            # Store per-feature mean/std for explainability
            self.device_feature_means[device_ip] = X.mean(axis=0).tolist()
            self.device_feature_stds[device_ip] = X.std(axis=0).tolist()

            # Record port baseline from training data
            port_baseline: set = set()
            for w in windows:
                port_baseline |= w.unique_remote_ports
            self.device_port_baselines[device_ip] = port_baseline

            return True
        except Exception:
            return False

    def _generate_synthetic_normal(self, device_ip: str,
                                    n: int = 200) -> list:
        """
        Generate synthetic 'normal' observations so we can train even
        on a fresh device with no history. Mimics a typical workstation.
        """
        import random
        rng = random.Random(hash(device_ip) % (2**32))
        samples = []
        for _ in range(n):
            w = DeviceBehaviourWindow(
                device_ip=device_ip,
                window_minutes=5,
                bytes_sent_total=rng.randint(10_000, 500_000),
                bytes_recv_total=rng.randint(50_000, 5_000_000),
                packets_sent_total=rng.randint(100, 5000),
                packets_recv_total=rng.randint(200, 10000),
                active_connections=rng.randint(1, 30),
                new_connections=rng.randint(0, 15),
                unique_remote_ports={80, 443, 53}.union(
                    {rng.randint(1024, 65535) for _ in range(rng.randint(0, 5))}
                ),
                unique_remote_ips={f"1.1.{rng.randint(0,255)}.{rng.randint(0,255)}"
                                   for _ in range(rng.randint(1, 8))},
                refused_connections=rng.randint(0, 2),
                tcp_count=rng.randint(10, 100),
                udp_count=rng.randint(1, 20),
                icmp_count=rng.randint(0, 5),
                dns_queries=rng.randint(5, 50),
                http_connections=rng.randint(0, 20),
                cleartext_connections=0,
                lan_connections=rng.randint(0, 5),
                wan_connections=rng.randint(1, 20),
                new_destinations=rng.randint(0, 3),
                arp_broadcasts=rng.randint(0, 2),
                syn_no_ack=0,
            )
            samples.append(extract_features(w))
        return samples

    # ── Scoring ───────────────────────────────────────────────────────────────

    def score(self, window: DeviceBehaviourWindow) -> AnomalyScore:
        """
        Score a single observation window against the device's baseline.
        Returns AnomalyScore(score 0–1, is_anomaly, reason, top_features).
        """
        device_ip = window.device_ip

        if not HAS_SKLEARN or device_ip not in self.device_models:
            return AnomalyScore(
                device_ip=device_ip,
                score=0.0,
                is_anomaly=False,
                reason="no baseline trained",
            )

        features = extract_features(
            window, self.device_port_baselines.get(device_ip)
        )
        X = np.array([features])
        X_scaled = self.device_scalers[device_ip].transform(X)

        # IsolationForest: decision_function returns negative for anomalies
        raw = self.device_models[device_ip].decision_function(X_scaled)[0]
        # Normalise: [-0.5, 0.5] → [0, 1]  (negative = anomalous)
        score = float(max(0.0, min(1.0, 0.5 - raw)))

        is_anomaly = score >= ANOMALY_THRESHOLD
        top_features = self._top_deviating(features, device_ip) if is_anomaly else []
        reason = "; ".join(top_features) if top_features else ""

        return AnomalyScore(
            device_ip=device_ip,
            score=round(score, 3),
            is_anomaly=is_anomaly,
            reason=reason,
            top_deviating_features=top_features,
        )

    def _top_deviating(self, features: list, device_ip: str, top_k: int = 3) -> list[str]:
        """Return the top-k feature names most responsible for the anomaly."""
        means = self.device_feature_means.get(device_ip, [0.0] * 25)
        stds  = self.device_feature_stds.get(device_ip, [1.0] * 25)

        z_scores = []
        for i, (v, m, s) in enumerate(zip(features, means, stds)):
            z = abs(v - m) / max(s, 0.001)
            z_scores.append((z, i))

        z_scores.sort(reverse=True)
        result = []
        for z, idx in z_scores[:top_k]:
            if z > 2.0 and idx < len(FEATURE_NAMES):
                name = FEATURE_NAMES[idx]
                result.append(f"{name} is {z:.1f}σ above baseline")
        return result

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self, path: Optional[str] = None) -> bool:
        """Save all trained models to disk with HMAC integrity."""
        if not HAS_SKLEARN:
            return False
        path = path or os.path.join(CACHE_DIR, "network_genome.pkl")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            payload = {
                "models": self.device_models,
                "scalers": self.device_scalers,
                "port_baselines": {k: list(v) for k, v in self.device_port_baselines.items()},
                "feature_means": self.device_feature_means,
                "feature_stds": self.device_feature_stds,
            }
            joblib.dump(payload, path)
            key = _get_or_create_hmac_key()
            sig = _sign_file(path, key)
            with open(path + ".sig", "w") as f:
                f.write(sig)
            return True
        except Exception:
            return False

    def load(self, path: Optional[str] = None) -> bool:
        """Load models from disk, verifying HMAC integrity."""
        if not HAS_SKLEARN:
            return False
        path = path or os.path.join(CACHE_DIR, "network_genome.pkl")
        if not os.path.exists(path):
            return False
        try:
            key = _get_or_create_hmac_key()
            sig_path = path + ".sig"
            if not os.path.exists(sig_path):
                return False
            with open(sig_path) as f:
                stored_sig = f.read().strip()
            computed = _sign_file(path, key)
            if not hmac.compare_digest(stored_sig, computed):
                return False
            payload = joblib.load(path)
            self.device_models    = payload.get("models", {})
            self.device_scalers   = payload.get("scalers", {})
            self.device_port_baselines = {
                k: set(v) for k, v in payload.get("port_baselines", {}).items()
            }
            self.device_feature_means = payload.get("feature_means", {})
            self.device_feature_stds  = payload.get("feature_stds", {})
            return True
        except Exception:
            return False

    def trained_devices(self) -> list[str]:
        return list(self.device_models.keys())
