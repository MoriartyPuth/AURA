import unittest

from utils.risk_normalizer import build_risk_table, infer_severity


class TestInferSeverity(unittest.TestCase):
    def test_confidence_tag_is_not_severity(self):
        self.assertEqual(infer_severity("[MEDIUM] Tool Ready: nuclei"), "info")
        self.assertEqual(infer_severity("[HIGH] Parameter: id"), "info")

    def test_keywords_match_whole_words_only(self):
        self.assertEqual(infer_severity("Crawled: https://x.com/resources"), "info")
        self.assertEqual(infer_severity("HTTP Surface: https://x.com [Allow list]"), "info")

    def test_real_keywords(self):
        self.assertEqual(infer_severity("[HIGH] Takeover: sub.x.com VULNERABLE"), "critical")
        self.assertEqual(infer_severity("Fuzz-XSS Reflection: q at /search"), "high")
        self.assertEqual(infer_severity("CORS: wildcard ACAO on root endpoint"), "medium")

    def test_dedup_keeps_highest_score(self):
        table = build_risk_table({
            "Phase 1": {"Classic Vuln Classes": ["[MEDIUM] CORS: wildcard ACAO on root endpoint"]},
            "Phase 2": {"Toolchain Health": ["[LOW] CORS: wildcard ACAO on root endpoint"]},
        })
        self.assertEqual(len(table), 1)
        self.assertEqual(table[0]["source"], "Classic Vuln Classes")


if __name__ == "__main__":
    unittest.main()
