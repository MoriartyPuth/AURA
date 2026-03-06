import unittest

from utils.finding_filters import apply_finding_filters


class TestFindingFilters(unittest.TestCase):
    def test_ignore_pattern(self):
        phase_map = {"Phase 1": {"Classic": ["manual review needed", "confirmed leak"]}}
        cfg = {"tuning": {"ignore_finding_patterns": ["manual review"]}}
        filtered, meta = apply_finding_filters(phase_map, cfg)
        self.assertEqual(meta["filtered"], 1)
        self.assertEqual(filtered["Phase 1"]["Classic"], ["confirmed leak"])


if __name__ == "__main__":
    unittest.main()
