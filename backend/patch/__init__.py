"""
CYPHEX Patch Infrastructure — Package Init

New modules for verified, context-aware patching:
  - resolver:   Vuln.endpoint → Location (file:line or url)
  - applier:    Range-accurate patch apply + rollback
  - verifier:   Static re-scan + dynamic replay + anti-gaming guards
  - templates:  Deterministic CWE transforms (zero model dependency)
  - manifest:   .cyphex/patches.json tracking
  - context:    Function/import extraction (regex-based)
  - regression: Proof-carrying test generation
"""
