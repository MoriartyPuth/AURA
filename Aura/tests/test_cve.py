import json
import os
import tempfile
import unittest

from modules.vuln import cve_mgr


class FakeResp:
    def __init__(self, headers):
        self.headers = headers


class FakeEngine:
    def __init__(self):
        self.config = {}
        self.target = "https://app.test"


class TestCveFingerprint(unittest.TestCase):
    def test_header_fingerprint_flags_versions(self):
        orig = cve_mgr.build_session

        class S:
            def get(self, *_a, **_k):
                return FakeResp({"Server": "nginx/1.18.0", "X-Powered-By": "PHP"})

        cve_mgr.build_session = lambda _c: S()
        try:
            findings = cve_mgr._fingerprint_headers(FakeEngine())
        finally:
            cve_mgr.build_session = orig
        self.assertIn("Tech Fingerprint (versioned): Server: nginx/1.18.0", findings)
        self.assertIn("Tech Fingerprint (product): X-Powered-By: PHP", findings)


class TestCveNucleiParsing(unittest.TestCase):
    def test_parses_cve_id_and_dedups(self):
        records = [
            {"template-id": "CVE-2021-1", "matched-at": "https://app.test/a",
             "info": {"name": "Thing RCE", "severity": "critical",
                      "classification": {"cve-id": ["CVE-2021-1"]}}},
            {"template-id": "dup", "matched-at": "https://app.test/b",
             "info": {"name": "Thing RCE again", "severity": "critical",
                      "classification": {"cve-id": ["CVE-2021-1"]}}},  # same CVE -> dropped
            {"template-id": "tech-detect", "matched-at": "https://app.test/c",
             "info": {"name": "Tech", "severity": "info"}},
        ]
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "nuclei_cve.json")

            def fake_run(*_a, **_k):
                # stand in for nuclei: write the JSONL output it would produce
                with open(out, "w") as f:
                    f.write("\n".join(json.dumps(r) for r in records) + "\n")
                return (0, "", "")

            orig_out, orig_avail, orig_run = cve_mgr.NUCLEI_CVE_OUT, cve_mgr.is_tool_available, cve_mgr.run_command
            cve_mgr.NUCLEI_CVE_OUT = out
            cve_mgr.is_tool_available = lambda _n: True
            cve_mgr.run_command = fake_run
            try:
                findings = cve_mgr._run_nuclei_cves(FakeEngine(), update_templates=False)
            finally:
                cve_mgr.NUCLEI_CVE_OUT, cve_mgr.is_tool_available, cve_mgr.run_command = orig_out, orig_avail, orig_run

        self.assertEqual(len(findings), 2)  # CVE-2021-1 once + the info template
        self.assertTrue(any(f.startswith("CVE CVE-2021-1 [CRITICAL] [VERIFIED]") for f in findings))

    def test_skips_without_nuclei(self):
        orig = cve_mgr.is_tool_available
        cve_mgr.is_tool_available = lambda _n: False
        try:
            self.assertEqual(cve_mgr._run_nuclei_cves(FakeEngine(), update_templates=True), [])
        finally:
            cve_mgr.is_tool_available = orig


if __name__ == "__main__":
    unittest.main()
