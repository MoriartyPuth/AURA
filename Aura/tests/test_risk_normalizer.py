import unittest

from core.findings import Finding
from utils.risk_normalizer import build_risk_table, infer_severity, severity_of


class TestInferSeverity(unittest.TestCase):
    def test_explicit_severity_wins_over_title(self):
        # Title mentions nothing high-sev; explicit field is authoritative.
        self.assertEqual(severity_of(Finding(title="Tool Ready: nuclei", severity="info")), "info")
        # No explicit severity, benign title -> info (not "medium" from a stray word).
        self.assertEqual(severity_of(Finding(title="Tool Ready: nuclei")), "info")

    def test_keywords_match_whole_words_only(self):
        self.assertEqual(infer_severity("Crawled: https://x.com/resources"), "info")
        self.assertEqual(infer_severity("HTTP Surface: https://x.com [Allow list]"), "info")

    def test_real_keywords(self):
        self.assertEqual(infer_severity("Takeover: sub.x.com VULNERABLE"), "critical")
        self.assertEqual(infer_severity("Fuzz-XSS Reflection: q at /search"), "high")
        self.assertEqual(infer_severity("CORS: wildcard ACAO on root endpoint"), "medium")

    def test_dedup_keeps_highest_score(self):
        table = build_risk_table({
            "Phase 1": {"Classic Vuln Classes": [Finding(title="CORS: wildcard ACAO on root endpoint")]},
            "Phase 2": {"Toolchain Health": [Finding(title="CORS: wildcard ACAO on root endpoint")]},
        })
        self.assertEqual(len(table), 1)
        self.assertEqual(table[0]["source"], "Classic Vuln Classes")

    def test_verified_outranks_heuristic(self):
        table = build_risk_table({"P": {
            "Payload Mutation Fuzzing": [Finding(title="Fuzz-XSS Reflection: id at /item", severity="high")],
            "Web Vulnerability Probes": [Finding(title="SQLi confirmed by sqlmap: id (GET)", severity="high", verified=True)],
        }})
        self.assertIn("SQLi confirmed", table[0]["finding"])
        self.assertTrue(table[0]["verified"])


if __name__ == "__main__":
    unittest.main()
