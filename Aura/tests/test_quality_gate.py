import unittest

from utils.quality_gate import apply_quality_gate


class TestQualityGate(unittest.TestCase):
    def test_drops_low_confidence(self):
        phase_map = {"Phase 1": {"A": ["possible issue detected", "confirmed data leak"]}}
        filtered, meta = apply_quality_gate(phase_map, min_confidence="medium")
        self.assertEqual(meta["dropped"], 1)
        self.assertEqual(meta["kept"], 1)
        kept = filtered["Phase 1"]["A"]
        self.assertEqual(len(kept), 1)
        self.assertIn("confirmed", kept[0].title.lower())
        self.assertEqual(kept[0].confidence, "high")  # recorded on the finding, not in the title
        self.assertNotIn("[", kept[0].title)           # no confidence tag glued into the title


if __name__ == "__main__":
    unittest.main()
