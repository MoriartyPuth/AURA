import unittest

from core.findings import Finding
from utils.common import normalize_key
from utils.risk_normalizer import build_risk_table


class TestNormalizeKey(unittest.TestCase):
    def test_nuclei_and_cve_wrapping_collapse(self):
        cve = "CVE CVE-2025-55182: React Server Components - Remote Code Execution (CVSS 10)"
        nuc = "Nuclei: React Server Components - Remote Code Execution"
        self.assertEqual(normalize_key(cve, strip_ips=True), normalize_key(nuc, strip_ips=True))

    def test_confidence_tag_still_stripped(self):
        self.assertEqual(normalize_key("[HIGH] Nuclei: Foo Bar"), normalize_key("Foo Bar"))

    def test_unrelated_findings_stay_distinct(self):
        self.assertNotEqual(normalize_key("CORS misconfiguration"), normalize_key("Open redirect"))

    def test_source_prefix_not_over_stripped(self):
        # "Tech Fingerprint (...)" and "Shodan InternetDB:" are not collapsed away.
        self.assertIn("tech fingerprint", normalize_key("Tech Fingerprint (product): Next.js"))
        self.assertIn("shodan internetdb", normalize_key("Shodan InternetDB: 1.1.1.1 open port 80"))

    def test_cvss_suffix_only_at_end(self):
        self.assertEqual(normalize_key("Foo (CVSS 9.8)"), "foo")


class TestDedupKeepsRicherFinding(unittest.TestCase):
    def test_cve_finding_beats_plain_nuclei_line(self):
        pm = {"Phase 2": {
            "CVE Detection": [Finding(
                title="CVE CVE-2025-55182: React Server Components - Remote Code Execution (CVSS 10)",
                severity="critical", confidence="high", verified=True, url="http://x")],
            "Nuclei Findings": [Finding(
                title="Nuclei: React Server Components - Remote Code Execution",
                severity="info", confidence="high")],
        }}
        rt = build_risk_table(pm)
        self.assertEqual(len(rt), 1)
        self.assertEqual(rt[0]["severity"], "CRITICAL")
        self.assertIn("CVE-2025-55182", rt[0]["finding"])  # the id survives in the display


if __name__ == "__main__":
    unittest.main()
