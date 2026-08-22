"""
CYPHEX — Observability

Structured, best-effort telemetry for the scan pipeline: a JSONL event log
written during every scan (backend.observability.events) and a maintainer
health aggregator that reads it back alongside the Verify Gate's own history
(backend.observability.health). Additive only — nothing here can affect scan
outcomes; every write is guarded and every read tolerates a missing/partial
log.
"""

from backend.observability.events import emit
from backend.observability.health import get_system_health

__all__ = ["emit", "get_system_health"]
