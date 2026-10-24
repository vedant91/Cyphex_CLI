"""AttackGraph.nodes is shared, mutated/iterated state across every DeepAgent
in a parallel group (asyncio.gather, see cli_engine.py's GROUP_PLAN). A real
scan hit "dictionary changed size during iteration" in DeepSSTIAgent and
DeepCMDiAgent — both members of the same 6-agent group — while concurrently
calling update_from_finding(). This pins the fix: concurrent callers from
real threads must not corrupt the dict.
"""
import threading

from backend.deepagents.attack_graph import AttackGraph


class _Finding:
    def __init__(self, name, endpoint, evidence="", dumped_data=""):
        self.name = name
        self.endpoint = endpoint
        self.evidence = evidence
        self.dumped_data = dumped_data


def test_concurrent_update_from_finding_does_not_corrupt_nodes():
    graph = AttackGraph()
    errors = []

    def worker(i):
        try:
            for j in range(50):
                graph.update_from_finding(_Finding(
                    name="SQL Injection" if j % 2 else "Auth Default Credentials",
                    endpoint=f"/api/endpoint-{i}-{j}",
                    dumped_data="user:pass" if j % 3 == 0 else "",
                ))
        except Exception as e:  # pragma: no cover - the race this test guards
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"concurrent update_from_finding raised: {errors}"
    assert len(graph.nodes) == 8 * 50


def test_get_node_is_idempotent_under_concurrency():
    graph = AttackGraph()
    errors = []

    def worker():
        try:
            for _ in range(200):
                graph.get_node("/api/shared")
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(graph.nodes) == 1
