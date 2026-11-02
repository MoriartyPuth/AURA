import threading
import time
import unittest

from aura import run_group_with_progress
from core.engine import AuraEngine


class TestParallelRunner(unittest.TestCase):
    def _tasks(self):
        # Each task sleeps a little; if run serially this is slow, parallel is fast.
        return [(f"t{i}", (lambda i=i: (time.sleep(0.05), [f"finding-{i}"])[1])) for i in range(6)]

    def test_results_keep_task_order(self):
        state = {}
        results = run_group_with_progress("Phase 0", self._tasks(), state, None, workers=6)
        self.assertEqual(list(results.keys()), [f"t{i}" for i in range(6)])
        self.assertEqual([f.title for f in results["t3"]], ["finding-3"])

    def test_all_tasks_checkpointed(self):
        state = {}
        run_group_with_progress("Phase 0", self._tasks(), state, None, workers=4)
        self.assertEqual(sorted(state["completed"]["Phase 0"]), [f"t{i}" for i in range(6)])

    def test_failing_task_does_not_sink_others(self):
        def boom():
            raise RuntimeError("nope")

        tasks = [("ok1", lambda: ["a"]), ("bad", boom), ("ok2", lambda: ["b"])]
        results = run_group_with_progress("Phase 0", tasks, {}, None, workers=3)
        self.assertEqual([f.title for f in results["ok1"]], ["a"])
        self.assertEqual(results["bad"], [])
        self.assertEqual([f.title for f in results["ok2"]], ["b"])


class TestEngineCacheThreadSafe(unittest.TestCase):
    def test_producer_runs_once_under_concurrency(self):
        engine = AuraEngine.__new__(AuraEngine)  # skip config/network in __init__
        engine._cache = {}
        engine._cache_locks = {}
        engine._cache_guard = threading.Lock()

        calls = {"n": 0}
        lock = threading.Lock()

        def producer():
            with lock:
                calls["n"] += 1
            time.sleep(0.05)
            return ["subdomains"]

        out = []
        threads = [threading.Thread(target=lambda: out.append(engine.cached("subs", producer)))
                   for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(calls["n"], 1)                 # producer ran exactly once
        self.assertTrue(all(o == ["subdomains"] for o in out))


if __name__ == "__main__":
    unittest.main()
