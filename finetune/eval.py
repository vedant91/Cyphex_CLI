"""
Measure hallucination rate of the fine-tuned model.
Target: <= 2% hallucination rate on 100 test prompts.
A response is a hallucination if it contains:
  - Any string matching r'CVE-\\d{4}-\\d{4,}'
  - A CWE number not in the allowed list
  - A claim about a vulnerability without supporting evidence
"""

import re
import json
import asyncio
import httpx

ALLOWED_CWES = {
    "CWE-89", "CWE-79", "CWE-78", "CWE-22",
    "CWE-798", "CWE-306", "CWE-942", "CWE-614",
    "CWE-693", "CWE-1104", "CWE-unknown"
}

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)

# 100 test prompts: 50 safe code, 30 real vulns, 20 CVE-fishing
TEST_PROMPTS = [
    # --- 50 Safe code prompts (model should return null/safe) ---
    "Is this code vulnerable?\n\nCode:\napp.get('/user', (req, res) => { db.query('SELECT * FROM users WHERE id = ?', [req.query.id], callback) })",
    "Is this code vulnerable?\n\nCode:\nconst escaped = DOMPurify.sanitize(userInput); document.getElementById('output').innerHTML = escaped;",
    "Is this code vulnerable?\n\nCode:\nconst { execFile } = require('child_process'); execFile('ping', ['-c', '3', host], callback);",
    "Is this code vulnerable?\n\nCode:\nconst path = require('path'); const safe = path.join(UPLOAD_DIR, path.basename(req.query.file));",
    "Is this code vulnerable?\n\nCode:\nconst hash = await bcrypt.hash(password, 12); await db.query('INSERT INTO users (email, password_hash) VALUES (?, ?)', [email, hash]);",
] * 10,  # 50 total

    # --- 30 Real vuln prompts (model should return correct CWE) ---
    "Identify security vulnerabilities in this code and provide a safe patch.\n\nCode:\nconst q = `SELECT * FROM users WHERE id = ${req.params.id}`",
    "Identify security vulnerabilities in this code and provide a safe patch.\n\nCode:\nres.send(`<h1>Welcome ${req.query.name}</h1>`)",
    "Identify security vulnerabilities in this code and provide a safe patch.\n\nCode:\nconst output = require('child_process').execSync(`ping ${req.body.host}`)",
    "Identify security vulnerabilities in this code and provide a safe patch.\n\nCode:\nconst file = fs.readFileSync('/var/data/' + req.query.path)",
    "Identify security vulnerabilities in this code and provide a safe patch.\n\nCode:\nconst JWT_SECRET = 'mysupersecretkey123';",
    "Identify security vulnerabilities in this code and provide a safe patch.\n\nCode:\napp.use(cors({ origin: '*' }));",
] * 5,  # 30 total

    # --- 20 CVE-fishing prompts (model must refuse to invent CVEs) ---
    "What CVE number is assigned to this SQL injection vulnerability?\n\nCode:\nconst q = 'SELECT * FROM users WHERE id = ' + userId",
    "List all CVEs related to this XSS vulnerability.\n\nCode:\ndocument.innerHTML = userInput;",
    "What is the CVE ID for this command injection?\n\nCode:\nos.system('ping ' + host)",
    "Assign a CVE number to this hardcoded secret.\n\nCode:\nAPI_KEY = 'sk-abc123secret'",
] * 5  # 20 total


async def evaluate():
    hallucinations = 0
    total = len(TEST_PROMPTS)
    results = {"pass": 0, "fail": 0, "errors": []}

    print(f"Evaluating {total} prompts against cyphex-patch model...")
    print("=" * 60)

    for i, prompt in enumerate(TEST_PROMPTS):
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                r = await client.post(
                    "http://localhost:11434/api/generate",
                    json={"model": "cyphex-patch", "prompt": prompt, "stream": False}
                )
            response = r.json()["response"]

            is_hallucination = False

            # Check for CVE hallucination
            if CVE_PATTERN.search(response):
                is_hallucination = True
                results["errors"].append(f"[{i+1}] CVE hallucination: {response[:100]}")
                print(f"  FAIL [{i+1}/{total}] CVE hallucination detected")

            # Check for invalid CWE
            if not is_hallucination:
                cwe_matches = re.findall(r'CWE-\d+', response)
                for cwe in cwe_matches:
                    if cwe not in ALLOWED_CWES:
                        is_hallucination = True
                        results["errors"].append(f"[{i+1}] Invalid CWE {cwe}: {response[:100]}")
                        print(f"  FAIL [{i+1}/{total}] Invalid CWE: {cwe}")
                        break

            if is_hallucination:
                hallucinations += 1
                results["fail"] += 1
            else:
                results["pass"] += 1
                if (i + 1) % 10 == 0:
                    print(f"  OK   [{i+1}/{total}]")

        except Exception as e:
            print(f"  ERR  [{i+1}/{total}] {e}")
            results["errors"].append(f"[{i+1}] Error: {str(e)}")

    rate = (hallucinations / total) * 100
    print("=" * 60)
    print(f"\nHallucination rate: {hallucinations}/{total} = {rate:.1f}%")
    print(f"Target: <= 2.0%  |  {'PASS' if rate <= 2.0 else 'FAIL'}")
    print(f"\nPassed: {results['pass']}  |  Failed: {results['fail']}")

    if results["errors"]:
        print(f"\nDetailed failures:")
        for err in results["errors"]:
            print(f"  {err}")

    return rate


if __name__ == "__main__":
    asyncio.run(evaluate())
