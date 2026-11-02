import os
import tempfile
import unittest

from utils.state_store import get_task_result, is_task_completed, load_state, mark_task_completed, save_state


class TestStateStore(unittest.TestCase):
    def test_resume_restores_results(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "state.json")
            state = {}
            mark_task_completed(state, "Phase 0", "OSINT", ["Subdomain Found: a.example.com"])
            save_state(path, state)

            restored = load_state(path)
            self.assertTrue(is_task_completed(restored, "Phase 0", "OSINT"))
            self.assertEqual(get_task_result(restored, "Phase 0", "OSINT"), ["Subdomain Found: a.example.com"])


if __name__ == "__main__":
    unittest.main()
