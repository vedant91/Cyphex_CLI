"""
CYPHEX Integration Test — VibeMart

Tests the new patching infrastructure against the demo VibeMart app.
This exercises: resolver → code_indexer → context → security_kb → templates → applier → verifier

Run: python -m backend.patch.test_vibemart
"""

import os
import sys
import json
import asyncio
import copy

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.patch.resolver import resolve, Location, is_patchable
from backend.patch.context import extract_function, extract_imports, detect_language
from backend.patch.applier import apply_patch, rollback
from backend.patch.verifier import verify_static, VerifyResult
from backend.patch.manifest import PatchManifest
from backend.patch.templates import apply_template
from backend.patch.regression import generate_regression_test
from backend.rag.code_indexer import CodeIndexer
from backend.rag.security_kb import get_fix_recipe, format_for_prompt, detect_framework
from backend.rag.patch_memory import PatchMemory

# ─────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────
VIBEMART_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "demo", "vibemart")
VIBEMART_SRC = os.path.join(VIBEMART_DIR, "src")

# Simulated Vuln dataclass (matching the real one from backend.backend.models.scan)
class MockVuln:
    def __init__(self, name, severity, endpoint, payload="", cwe="", evidence=""):
        self.name = name
        self.severity = severity
        self.endpoint = endpoint
        self.payload = payload
        self.cwe = cwe
        self.evidence = evidence
        self.confirmed = True
        self.description = ""
        self.cvss_score = 0.0
        self.dumped_data = ""
        self.rce_output = ""
        self.cvss_vector = ""
        self.attack_chain = ""
        self.business_impact = ""
        self.fix = ""


# ─────────────────────────────────────────────────────────────
# Test Findings (simulating what CYPHEX scanners would produce)
# ─────────────────────────────────────────────────────────────
TEST_VULNS = [
    MockVuln(
        name="[STATIC] SQL Injection",
        severity="Critical",
        endpoint="src/routes/orders.js:18",
        payload="1; DROP TABLE orders--",
        cwe="CWE-89",
    ),
    MockVuln(
        name="[STATIC] OS Command Injection",
        severity="Critical",
        endpoint="src/routes/admin.js:28",
        payload="; cat /etc/passwd",
        cwe="CWE-78",
    ),
    MockVuln(
        name="[STATIC] Reflected XSS",
        severity="High",
        endpoint="src/routes/orders.js:51",
        payload="<script>alert(1)</script>",
        cwe="CWE-79",
    ),
    MockVuln(
        name="[STATIC] OS Command Injection",
        severity="Critical",
        endpoint="src/routes/orders.js:34",
        payload="json; cat /etc/passwd",
        cwe="CWE-78",
    ),
    MockVuln(
        name="[STATIC] Information Disclosure",
        severity="Medium",
        endpoint="src/routes/admin.js:38",
        payload="",
        cwe="CWE-200",
    ),
    MockVuln(
        name="[DYNAMIC] SQL Injection",
        severity="Critical",
        endpoint="http://localhost:3003/api/orders/create",
        payload='{"user_id": "1 OR 1=1", "product_id": "1", "quantity": "1"}',
        cwe="CWE-89",
        evidence="curl -X POST http://localhost:3003/api/orders/create -d '{}'",
    ),
]


# ─────────────────────────────────────────────────────────────
# Test Execution
# ─────────────────────────────────────────────────────────────

def separator(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")


def test_resolver():
    """Test 1: Location Resolver"""
    separator("TEST 1: Location Resolver")
    
    results = []
    for v in TEST_VULNS:
        loc = resolve(v, VIBEMART_SRC)
        status = "✓" if loc else "✗"
        if loc:
            if loc.kind == "file":
                exists = "EXISTS" if os.path.isfile(loc.file) else "MISSING"
                patchable = "PATCHABLE" if is_patchable(loc) else "DYNAMIC-ONLY"
                print(f"  {status} {v.name[:40]:40s} → {loc.kind}: {loc.rel}:{loc.line} [{exists}] [{patchable}]")
            else:
                print(f"  {status} {v.name[:40]:40s} → {loc.kind}: {loc.url} [{loc.method}]")
            results.append(loc)
        else:
            print(f"  {status} {v.name[:40]:40s} → UNRESOLVABLE (endpoint: {v.endpoint})")
            results.append(None)
    
    resolved = sum(1 for r in results if r)
    patchable = sum(1 for r in results if r and is_patchable(r))
    print(f"\n  Summary: {resolved}/{len(TEST_VULNS)} resolved, {patchable} patchable (have file+line)")
    return results


def test_code_indexer():
    """Test 2: Vectorless Code Indexer"""
    separator("TEST 2: Vectorless Code Indexer")
    
    indexer = CodeIndexer(VIBEMART_SRC)
    count = indexer.build_index()
    print(f"  Indexed {count} files in {VIBEMART_SRC}")
    
    for path, meta in indexer.files.items():
        flags = []
        if meta["has_db"]: flags.append("DB")
        if meta["has_auth"]: flags.append("AUTH")
        if meta["has_input"]: flags.append("INPUT")
        funcs = meta["functions"][:5]
        routes = meta["routes"][:5]
        print(f"  📄 {path:35s} [{', '.join(flags):15s}] funcs={funcs} routes={routes[:3]}")
    
    print("\n  --- Finding relevant files for each vuln ---")
    for v in TEST_VULNS[:3]:
        loc = resolve(v, VIBEMART_SRC)
        relevant = indexer.find_for_vuln(v, loc)
        print(f"\n  Vuln: {v.name[:40]}")
        for r in relevant:
            print(f"    → {r['path']} (score: {r['score']})")
    
    # Test secure pattern search
    print("\n  --- Searching for repo's own secure patterns ---")
    for cwe in ["CWE-89", "CWE-79", "CWE-78"]:
        pattern = indexer.find_secure_pattern(cwe)
        if pattern:
            print(f"  {cwe}: Found! {pattern[:80]}...")
        else:
            print(f"  {cwe}: No existing secure pattern found")
    
    return indexer


def test_context_extraction():
    """Test 3: Function & Import Extraction"""
    separator("TEST 3: Context Extraction")
    
    test_cases = [
        ("src/routes/orders.js", 18, "js", "SQL Injection line"),
        ("src/routes/admin.js", 28, "js", "Command Injection line"),
        ("src/routes/orders.js", 51, "js", "XSS line"),
        ("src/routes/orders.js", 34, "js", "Export command injection"),
    ]
    
    for rel_path, line, lang, desc in test_cases:
        fpath = os.path.join(VIBEMART_SRC, rel_path)
        if not os.path.isfile(fpath):
            print(f"  ✗ {desc}: file not found: {fpath}")
            continue
        
        content = open(fpath, encoding="utf-8").read()
        
        # Extract function
        snippet, quality = extract_function(content, line, lang)
        snippet_lines = snippet.count('\n') + 1
        
        # Extract imports
        imports = extract_imports(content, lang)
        import_count = len([l for l in imports.split('\n') if l.strip()])
        
        print(f"\n  📍 {desc} ({rel_path}:{line})")
        print(f"     Extraction quality: {quality}")
        print(f"     Function snippet: {snippet_lines} lines")
        print(f"     Imports: {import_count} lines")
        print(f"     First 3 lines of snippet:")
        for i, sl in enumerate(snippet.split('\n')[:3]):
            print(f"       {sl.rstrip()}")


def test_security_kb():
    """Test 4: Security Knowledge Base"""
    separator("TEST 4: Security Knowledge Base")
    
    for cwe in ["CWE-89", "CWE-79", "CWE-78", "CWE-798", "CWE-942", "CWE-200"]:
        recipe = get_fix_recipe(cwe)
        if recipe:
            strategies = [s["name"] for s in recipe.get("fix_strategies", [])]
            print(f"  {cwe} ({recipe['name']:30s}): strategies={strategies}")
        else:
            print(f"  {cwe}: NOT IN KB")
    
    # Test prompt formatting
    print("\n  --- Formatted prompt for CWE-89 ---")
    prompt = format_for_prompt("CWE-89", "express")
    for line in prompt.split('\n')[:8]:
        print(f"  {line}")


def test_template_transforms():
    """Test 5: Deterministic Template Transforms"""
    separator("TEST 5: Deterministic Template Transforms")
    
    test_cases = [
        (
            "CWE-89",
            'const sql = `INSERT INTO orders (user_id) VALUES (${user_id})`;\ndb.query(sql);',
            "SQL Injection template literal",
        ),
        (
            "CWE-798",
            'const password = "admin123";\nconst api_key = "sk-secret-key-12345";',
            "Hardcoded secrets",
        ),
        (
            "CWE-942",
            "app.use(cors({ origin: '*' }));",
            "Wildcard CORS",
        ),
        (
            "CWE-79",
            '<div dangerouslySetInnerHTML={{__html: userInput}} />',
            "XSS dangerouslySetInnerHTML",
        ),
    ]
    
    for cwe, code, desc in test_cases:
        result = apply_template(cwe, code)
        if result:
            print(f"\n  ✓ {desc} ({cwe}):")
            print(f"    BEFORE: {code[:70]}...")
            print(f"    AFTER:  {result[:70]}...")
        else:
            print(f"\n  ✗ {desc} ({cwe}): No template matched")


def test_applier_and_verifier():
    """Test 6: Apply + Verify (on a copy of VibeMart)"""
    separator("TEST 6: Apply + Verify Pipeline")
    
    # Work on the real order.js file — we'll use apply + rollback
    orders_file = os.path.join(VIBEMART_SRC, "routes", "orders.js")
    if not os.path.isfile(orders_file):
        print("  ✗ orders.js not found, skipping")
        return
    
    original = open(orders_file, encoding="utf-8").read()
    lines = original.split('\n')
    
    # The SQL injection is on line 18:
    # const sql = `INSERT INTO orders (user_id, product_id, quantity) VALUES (${user_id}, ${product_id}, ${quantity})`;
    print(f"  Original line 18: {lines[17].strip()}")
    
    # Try template transform first
    vuln_line = lines[17]
    template_fix = apply_template("CWE-89", vuln_line)
    
    if template_fix:
        print(f"  Template fix:     {template_fix.strip()}")
        
        # Apply the patch
        result = apply_patch(orders_file, 18, 18, template_fix.strip())
        print(f"  Apply result:     success={result.success}, parse_valid={result.parse_valid}")
        
        if result.success:
            # Read patched content
            patched = open(orders_file, encoding="utf-8").read()
            patched_line = patched.split('\n')[17]
            print(f"  Patched line 18:  {patched_line.strip()}")
            
            # Verify with static scanner
            vuln = MockVuln(
                name="[STATIC] SQL Injection",
                severity="Critical", 
                endpoint="src/routes/orders.js:18",
                cwe="CWE-89",
            )
            loc = resolve(vuln, VIBEMART_SRC)
            
            verify_result = verify_static(
                loc, vuln, VIBEMART_SRC,
                parse_valid=result.parse_valid,
                original_content=original,
                patched_content=patched,
            )
            
            print(f"\n  Verification:")
            print(f"    finding_gone:   {verify_result.finding_gone}")
            print(f"    builds:         {verify_result.builds}")
            print(f"    no_suppression: {verify_result.no_suppression}")
            print(f"    blast_ok:       {verify_result.blast_ok}")
            print(f"    verdict:        {verify_result.verdict}")
            if verify_result.evidence:
                print(f"    evidence:       {verify_result.evidence}")
            
            # ALWAYS rollback after test
            rollback(orders_file, original)
            print(f"\n  ↩ Rolled back orders.js to original")
            
            # Verify rollback
            after_rollback = open(orders_file, encoding="utf-8").read()
            print(f"  Rollback OK: {after_rollback == original}")
        else:
            print(f"  Apply failed: {result.error}")
    else:
        print("  No template matched for line 18 — would need model-based patching")
        
        # Still test the applier with a manual fix
        manual_fix = "  const sql = 'INSERT INTO orders (user_id, product_id, quantity) VALUES (?, ?, ?)';"
        result = apply_patch(orders_file, 18, 18, manual_fix)
        print(f"  Manual fix applied: success={result.success}")
        
        if result.success:
            patched = open(orders_file, encoding="utf-8").read()
            
            vuln = MockVuln(
                name="[STATIC] SQL Injection",
                severity="Critical",
                endpoint="src/routes/orders.js:18",
                cwe="CWE-89",
            )
            loc = resolve(vuln, VIBEMART_SRC)
            
            verify_result = verify_static(
                loc, vuln, VIBEMART_SRC,
                parse_valid=result.parse_valid,
                original_content=original,
                patched_content=patched,
            )
            
            print(f"  Verification verdict: {verify_result.verdict}")
            print(f"  Evidence: {verify_result.evidence}")
        
        # ALWAYS rollback
        rollback(orders_file, original)
        print(f"  ↩ Rolled back orders.js to original")


def test_manifest():
    """Test 7: Patch Manifest"""
    separator("TEST 7: Patch Manifest")
    
    import tempfile
    tmp_dir = tempfile.mkdtemp()
    
    manifest = PatchManifest(tmp_dir)
    
    # Record a verified patch
    manifest.record(
        rel_path="src/routes/orders.js",
        line=18,
        cwe="CWE-89",
        vuln_type="SQL Injection",
        verdict="PASS",
        original_hash="abc123",
        patched_hash="def456",
        exploit_payload="1; DROP TABLE orders--",
    )
    
    # Record an unverified patch
    manifest.record(
        rel_path="src/routes/admin.js",
        line=28,
        cwe="CWE-78",
        vuln_type="Command Injection",
        verdict="UNVERIFIABLE",
        original_hash="ghi789",
        patched_hash="jkl012",
    )
    
    print(f"  Already patched (CWE-89, line 18)? {manifest.is_already_patched('src/routes/orders.js', 18, 'CWE-89')}")
    print(f"  Already patched (CWE-78, line 28)? {manifest.is_already_patched('src/routes/admin.js', 28, 'CWE-78')}")
    
    stats = manifest.get_durability_stats()
    print(f"  Durability stats: {stats}")
    
    # Cleanup
    import shutil
    shutil.rmtree(tmp_dir, ignore_errors=True)


def test_regression_tests():
    """Test 8: Regression Test Generation"""
    separator("TEST 8: Regression Test Generation")
    
    # Dynamic finding
    vuln_dynamic = MockVuln(
        name="[DYNAMIC] SQL Injection",
        severity="Critical",
        endpoint="http://localhost:3003/api/orders/create",
        payload='{"user_id": "1 OR 1=1"}',
        cwe="CWE-89",
    )
    loc_dynamic = resolve(vuln_dynamic, VIBEMART_SRC)
    
    test_content = generate_regression_test(vuln_dynamic, loc_dynamic, "jest")
    if test_content:
        lines = test_content.strip().split('\n')
        print(f"  Dynamic test: {len(lines)} lines generated")
        for l in lines[:10]:
            print(f"    {l}")
        print(f"    ... ({len(lines) - 10} more lines)")
    
    # Static finding
    vuln_static = MockVuln(
        name="[STATIC] Command Injection",
        severity="Critical",
        endpoint="src/routes/admin.js:28",
        cwe="CWE-78",
    )
    loc_static = resolve(vuln_static, VIBEMART_SRC)
    
    test_content = generate_regression_test(vuln_static, loc_static, "jest")
    if test_content:
        lines = test_content.strip().split('\n')
        print(f"\n  Static test: {len(lines)} lines generated")
        for l in lines[:8]:
            print(f"    {l}")


def test_patch_memory():
    """Test 9: Patch Memory"""
    separator("TEST 9: Patch Memory")
    
    import tempfile
    tmp_dir = tempfile.mkdtemp()
    
    memory = PatchMemory(tmp_dir)
    
    func_code = """
    router.post('/create', (req, res) => {
      const { user_id } = req.body;
      const sql = `INSERT INTO orders VALUES (${user_id})`;
      db.query(sql);
    });
    """
    
    # Store a verified fix
    memory.store("CWE-89", func_code, "const sql = 'INSERT INTO orders VALUES (?)'", "Parameterized Query", verified=True)
    
    # Recall it
    recalled = memory.recall("CWE-89", func_code)
    print(f"  Recalled fix: {recalled is not None}")
    if recalled:
        print(f"  Strategy: {recalled.get('strategy')}")
        print(f"  Patch: {recalled.get('patch')[:60]}")
        print(f"  Reuse count: {recalled.get('reuse_count')}")
    
    # Test semantic hashing resilience
    func_reformatted = """
    router.post('/create', (req, res) => {
        const { user_id } = req.body;
        const sql = `INSERT INTO orders VALUES (${user_id})`;
        db.query(sql);
    });
    """
    
    recalled2 = memory.recall("CWE-89", func_reformatted)
    print(f"\n  Same function (reformatted) recalled: {recalled2 is not None}")
    
    # Cleanup
    import shutil
    shutil.rmtree(tmp_dir, ignore_errors=True)


def test_full_pipeline():
    """Test 10: Full Pipeline Simulation"""
    separator("TEST 10: Full Pipeline — End-to-End")
    
    indexer = CodeIndexer(VIBEMART_SRC)
    indexer.build_index()
    
    deps = indexer.get_dependency_info()
    framework = detect_framework(deps)
    print(f"  Detected framework: {framework or 'unknown'}")
    print(f"  Dependencies: {deps.get('node_deps', [])[:5]}")
    
    print("\n  Processing each finding through the full pipeline:")
    
    for v in TEST_VULNS:
        # Step 1: Resolve
        loc = resolve(v, VIBEMART_SRC)
        if not loc or not is_patchable(loc):
            print(f"\n  ⊘ {v.name[:40]:40s} → SKIPPED (dynamic-only or unresolvable)")
            continue
        
        # Step 2: Get context
        content = open(loc.file, encoding="utf-8").read()
        snippet, quality = extract_function(content, loc.line, detect_language(loc.file))
        imports = extract_imports(content, detect_language(loc.file))
        
        # Step 3: Get KB recipe
        kb_prompt = format_for_prompt(v.cwe, framework)
        
        # Step 4: Find repo examples
        repo_example = indexer.find_secure_pattern(v.cwe)
        
        # Step 5: Try template
        vuln_lines = content.split('\n')
        vuln_line = vuln_lines[loc.line - 1] if loc.line <= len(vuln_lines) else ""
        template_fix = apply_template(v.cwe, vuln_line, framework)
        
        print(f"\n  ► {v.name[:40]:40s} @ {loc.rel}:{loc.line}")
        print(f"    Context: {quality} ({snippet.count(chr(10))+1} lines)")
        print(f"    KB recipe: {'YES' if kb_prompt else 'NO'}")
        print(f"    Repo example: {'YES' if repo_example else 'NO'}")
        print(f"    Template fix: {'YES → ' + template_fix.strip()[:50] if template_fix else 'NO → needs model'}")
        
        if not template_fix:
            # Assemble the prompt that would go to the model
            prompt_parts = []
            if kb_prompt:
                prompt_parts.append(kb_prompt)
            if imports:
                prompt_parts.append(f"\nFILE IMPORTS:\n{imports}")
            prompt_parts.append(f"\nVULNERABLE CODE ({quality} extraction):\n{snippet}")
            if repo_example:
                prompt_parts.append(f"\nREPO'S OWN SECURE PATTERN:\n{repo_example}")
            prompt_parts.append(f"\nEXPLOIT: {v.payload}")
            
            full_prompt = "\n".join(prompt_parts)
            print(f"    Model prompt: {len(full_prompt)} chars ({full_prompt.count(chr(10))+1} lines)")


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║          CYPHEX Patching Infrastructure — VibeMart Test            ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print(f"\n  VibeMart source: {os.path.abspath(VIBEMART_SRC)}")
    print(f"  Source exists:   {os.path.isdir(VIBEMART_SRC)}")
    
    if not os.path.isdir(VIBEMART_SRC):
        print("\n  ERROR: VibeMart source directory not found!")
        sys.exit(1)
    
    test_resolver()
    test_code_indexer()
    test_context_extraction()
    test_security_kb()
    test_template_transforms()
    test_applier_and_verifier()
    test_manifest()
    test_regression_tests()
    test_patch_memory()
    test_full_pipeline()
    
    separator("ALL TESTS COMPLETE")
    print("  Run CYPHEX against VibeMart to test the full patching pipeline:")
    print("  python cyphex_cli.py onboard --path ./demo/vibemart")
    print()
