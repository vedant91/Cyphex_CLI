"""
CYPHEX — Agent 10: Patch Generation Agent

Uses Cerebras AI to generate:
  - Framework-specific code fixes (before/after)
  - Security middleware configuration
  - Content-Security-Policy header
  - Rate limiting config
  - Input validation schemas
  - Docker security hardening
"""

import json

from agents.base_agent import BaseAgent
from models.scan import ScanContext, Vuln
from models.agent_result import AgentResult


class PatchAgent(BaseAgent):

    async def run(self, context: ScanContext) -> AgentResult:
        await self.log("=== PATCH GENERATION PHASE ===", "info")
        await self.log(
            f"Generating fixes for {len(context.confirmed_vulns)} vulns "
            f"(framework: {context.framework or 'generic'})...",
            "info",
        )

        system_prompt = """You are a senior security engineer. You have a confirmed list of 
vulnerabilities in a web application. Generate production-ready 
security patches.

For each vulnerability provide:
1. BEFORE: the vulnerable code pattern
2. AFTER: the fixed code (framework-specific)
3. INSTALL: any npm/pip package to add
4. EXPLANATION: why this fix works

Be specific to the detected framework and database.
Return ONLY valid JSON, no markdown.

Schema:
{
  "patches": [{
    "vuln_name": "",
    "file_path": "e.g. app.js or routes/login.js",
    "before": "// vulnerable code",
    "after": "// fixed code",
    "install": "npm install helmet express-rate-limit",
    "explanation": ""
  }],
  "middleware_config": "// full security middleware code",
  "csp_header": "Content-Security-Policy header value",
  "rate_limit_config": "// rate limiting code",
  "security_checklist": [
    "item 1",
    "item 2"
  ]
}"""

        user_prompt = f"""
FRAMEWORK: {context.framework or 'Express.js/Node.js'}
DATABASE: {context.database or 'MySQL'}
LANGUAGE: {context.language or 'JavaScript'}
SERVER: {context.server or 'Unknown'}

CONFIRMED VULNERABILITIES:
{json.dumps([v.to_dict() for v in context.confirmed_vulns], indent=2)}

Generate complete patches including:
1. Code fixes (before/after) for every vuln
2. Security middleware config for {context.framework or 'Express.js'}
3. Content-Security-Policy header tailored to this app
4. Rate limiting config
5. Input validation for every vulnerable endpoint
6. Security headers middleware
7. A prioritized security checklist
"""

        response = await self.call_cerebras(system_prompt, user_prompt)

        # Parse AI response
        cure_plan = self._parse_json(response)
        if not cure_plan:
            await self.log("AI patch generation failed — using fallback", "warning")
            cure_plan = self._generate_fallback_patches(context)
        else:
            await self.log("AI cure plan generated successfully", "success")

        # Print patches summary
        if isinstance(cure_plan, dict):
            patches = cure_plan.get("patches", [])
            await self.log(f"Generated {len(patches)} code patches", "success")
            for i, patch in enumerate(patches):
                if isinstance(patch, dict):
                    await self.log(
                        f"  Patch {i+1}: {patch.get('vuln_name', 'Unknown')} "
                        f"-> {patch.get('file_path', 'N/A')}",
                        "info",
                    )

            if cure_plan.get("middleware_config"):
                await self.log("  + Security middleware config", "info")
            if cure_plan.get("csp_header"):
                await self.log("  + CSP header", "info")
            if cure_plan.get("rate_limit_config"):
                await self.log("  + Rate limiting config", "info")

            checklist = cure_plan.get("security_checklist", [])
            if checklist:
                await self.log(f"Security Checklist ({len(checklist)} items):", "info")
                for item in checklist:
                    await self.log(f"  ☐ {item}", "info")

        return AgentResult(
            agent="PatchAgent",
            cure_plan=cure_plan,
            vulns=self.vulns,
            context=context,
            terminal_logs=self.terminal.command_history,
        )

    def _generate_fallback_patches(self, context: ScanContext) -> dict:
        """Generate patches without AI."""
        framework = (context.framework or "Express.js").lower()
        patches = []

        for vuln in context.confirmed_vulns:
            name_lower = vuln.name.lower()

            if "sql" in name_lower:
                patches.append({
                    "vuln_name": vuln.name,
                    "file_path": "routes/login.js" if "login" in vuln.endpoint else "app.js",
                    "before": (
                        '// VULNERABLE\n'
                        'db.query(`SELECT * FROM users WHERE username=\'${username}\'`)'
                    ),
                    "after": (
                        '// FIXED — Parameterized query\n'
                        'db.query("SELECT * FROM users WHERE username = ?", [username])'
                    ),
                    "install": "npm install mysql2",
                    "explanation": "Parameterized queries prevent SQL injection by separating SQL logic from data.",
                })

            elif "xss" in name_lower:
                patches.append({
                    "vuln_name": vuln.name,
                    "file_path": "app.js",
                    "before": (
                        '// VULNERABLE\n'
                        'res.send(`<div>Results for: ${q}</div>`)'
                    ),
                    "after": (
                        '// FIXED — HTML entity encoding\n'
                        'const escapeHtml = (s) => s.replace(/&/g,"&amp;")'
                        '.replace(/</g,"&lt;").replace(/>/g,"&gt;")'
                        '.replace(/"/g,"&quot;");\n'
                        'res.send(`<div>Results for: ${escapeHtml(q)}</div>`)'
                    ),
                    "install": "npm install helmet xss-filters",
                    "explanation": "HTML entity encoding prevents script injection.",
                })

            elif "csrf" in name_lower:
                patches.append({
                    "vuln_name": vuln.name,
                    "file_path": "app.js",
                    "before": "// No CSRF protection",
                    "after": (
                        '// FIXED — CSRF middleware\n'
                        'const csrf = require("csurf");\n'
                        'app.use(csrf({ cookie: { sameSite: "strict" } }));'
                    ),
                    "install": "npm install csurf",
                    "explanation": "CSRF tokens prevent cross-site request forgery.",
                })

            elif "command injection" in name_lower:
                patches.append({
                    "vuln_name": vuln.name,
                    "file_path": "app.js",
                    "before": (
                        '// VULNERABLE\n'
                        'exec(`ping -c 1 ${req.query.host}`)'
                    ),
                    "after": (
                        '// FIXED — Use execFile with argument array\n'
                        'const { execFile } = require("child_process");\n'
                        'const host = req.query.host.replace(/[^a-zA-Z0-9.\\-]/g, "");\n'
                        'execFile("ping", ["-c", "1", host], callback);'
                    ),
                    "install": "",
                    "explanation": "execFile with array args prevents shell injection.",
                })

            elif "file inclusion" in name_lower or "lfi" in name_lower:
                patches.append({
                    "vuln_name": vuln.name,
                    "file_path": "app.js",
                    "before": (
                        '// VULNERABLE\n'
                        'fs.readFile(`/var/www/${req.query.path}`)'
                    ),
                    "after": (
                        '// FIXED — Path validation\n'
                        'const path = require("path");\n'
                        'const safePath = path.normalize(req.query.path)\n'
                        '  .replace(/^\\.\\.([\\\\/]|$)/g, "");\n'
                        'const fullPath = path.join("/var/www/public", safePath);\n'
                        'if (!fullPath.startsWith("/var/www/public")) {\n'
                        '  return res.status(403).send("Forbidden");\n'
                        '}'
                    ),
                    "install": "",
                    "explanation": "Normalize path and verify it stays within allowed directory.",
                })

            elif "header" in name_lower:
                patches.append({
                    "vuln_name": vuln.name,
                    "file_path": "app.js",
                    "before": "// No security headers",
                    "after": (
                        '// FIXED — Security headers via helmet\n'
                        'const helmet = require("helmet");\n'
                        'app.use(helmet({\n'
                        '  contentSecurityPolicy: {\n'
                        '    directives: {\n'
                        '      defaultSrc: ["\'self\'"],\n'
                        '      scriptSrc: ["\'self\'"],\n'
                        '      styleSrc: ["\'self\'", "\'unsafe-inline\'"],\n'
                        '    }\n'
                        '  },\n'
                        '  frameguard: { action: "deny" },\n'
                        '}));'
                    ),
                    "install": "npm install helmet",
                    "explanation": "Helmet sets all security headers automatically.",
                })

        middleware_config = (
            '// Security middleware for Express.js\n'
            'const helmet = require("helmet");\n'
            'const rateLimit = require("express-rate-limit");\n'
            'const cors = require("cors");\n\n'
            '// Helmet — all security headers\n'
            'app.use(helmet());\n\n'
            '// CORS — restrict origins\n'
            'app.use(cors({ origin: "https://yourdomain.com" }));\n\n'
            '// Rate limiting\n'
            'app.use("/api/login", rateLimit({\n'
            '  windowMs: 15 * 60 * 1000,\n'
            '  max: 5,\n'
            '  message: "Too many attempts"\n'
            '}));\n'
        )

        csp = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )

        return {
            "patches": patches,
            "middleware_config": middleware_config,
            "csp_header": csp,
            "rate_limit_config": (
                'const rateLimit = require("express-rate-limit");\n'
                'const limiter = rateLimit({\n'
                '  windowMs: 15 * 60 * 1000,\n'
                '  max: 100,\n'
                '  standardHeaders: true,\n'
                '  legacyHeaders: false,\n'
                '});\n'
                'app.use(limiter);'
            ),
            "security_checklist": [
                "Rotate all exposed credentials (AWS keys, DB passwords, JWT secrets)",
                "Enable parameterized queries on ALL SQL operations",
                "Add Content-Security-Policy header",
                "Implement CSRF tokens on all POST forms",
                "Add rate limiting to login and API endpoints",
                "Remove .env and sensitive files from public access",
                "Implement proper authorization checks on all endpoints",
                "Use bcrypt/argon2 for password hashing (not MD5)",
                "Enable HTTPS with HSTS header",
                "Implement input validation on all user inputs",
                "Remove server version headers",
                "Set up WAF (Web Application Firewall)",
            ],
        }
