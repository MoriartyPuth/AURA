import unittest

from utils.quality_gate import apply_quality_gate


class TestQualityGate(unittest.TestCase):
    def test_drops_low_confidence(self):
        phase_map = {
            "Phase 1": {
                "A": ["possible issue detected", "confirmed data leak"],
            }
        }
        filtered, meta = apply_quality_gate(phase_map, min_confidence="medium")
        self.assertEqual(meta["dropped"], 1)
        self.assertEqual(meta["kept"], 1)
        self.assertEqual(len(filtered["Phase 1"]["A"]), 1)
        self.assertIn("confirmed", filtered["Phase 1"]["A"][0].lower())


if __name__ == "__main__":
    unittest.main()
