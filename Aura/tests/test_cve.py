import json
import os
import tempfile
import unittest

from core.findings import Finding
from modules.vuln import cve_mgr, nuclei_mgr


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

    def test_cve_scan_is_fingerprint_only(self):
        # run_cve_scan must not invoke nuclei any more.
        orig = cve_mgr.build_session

        class S:
            def get(self, *_a, **_k):
                return FakeResp({})

        cve_mgr.build_session = lambda _c: S()
        try:
            self.assertEqual(cve_mgr.run_cve_scan(FakeEngine()), [])
        finally:
            cve_mgr.build_session = orig


class TestNucleiUnifiedParsing(unittest.TestCase):
    """The single nuclei pass yields structured CVE findings + plain findings."""

    def _run(self, records):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "nuclei_raw.json")

            def fake_run(cmd, *_a, **_k):
                if "-update-templates" in cmd:
                    return (0, "", "")
                with open(out, "w") as f:
                    f.write("\n".join(json.dumps(r) for r in records) + "\n")
                return (0, "", "")

            orig = (nuclei_mgr.NUCLEI_OUT, nuclei_mgr.CVE_DETAILS_OUT,
                    nuclei_mgr.is_tool_available, nuclei_mgr.run_command)
            nuclei_mgr.NUCLEI_OUT = out
            nuclei_mgr.CVE_DETAILS_OUT = os.path.join(d, "cve_details.json")
            nuclei_mgr.is_tool_available = lambda _n: True
            nuclei_mgr.run_command = fake_run
            try:
                return nuclei_mgr.run_nuclei(FakeEngine(), severity="critical")
            finally:
                (nuclei_mgr.NUCLEI_OUT, nuclei_mgr.CVE_DETAILS_OUT,
                 nuclei_mgr.is_tool_available, nuclei_mgr.run_command) = orig

    def test_cve_structured_plain_split_and_dedup(self):
        records = [
            {"template-id": "CVE-2021-44228", "matched-at": "https://app.test/a",
             "info": {"name": "Thing RCE", "severity": "critical",
                      "classification": {"cve-id": ["CVE-2021-44228"], "cvss-score": 9.8}}},
            {"template-id": "dup", "matched-at": "https://app.test/b",
             "info": {"name": "Thing RCE again", "severity": "critical",
                      "classification": {"cve-id": ["CVE-2021-44228"]}}},  # same CVE -> dropped
            {"template-id": "tech-detect", "matched-at": "https://app.test/c",
             "info": {"name": "Tech Detect", "severity": "info"}},  # no CVE -> plain
        ]
        findings = self._run(records)
        cves = [f for f in findings if isinstance(f, Finding)]
        plain = [f for f in findings if isinstance(f, str)]
        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0].extra["cve"], "CVE-2021-44228")
        self.assertTrue(cves[0].verified)
        self.assertEqual(cves[0].severity, "critical")
        self.assertIn("CVSS 9.8", cves[0].title)
        self.assertEqual(plain, ["Nuclei: Tech Detect"])

    def test_skips_without_nuclei(self):
        orig = nuclei_mgr.is_tool_available
        nuclei_mgr.is_tool_available = lambda _n: False
        try:
            self.assertEqual(nuclei_mgr.run_nuclei(FakeEngine()), [])
        finally:
            nuclei_mgr.is_tool_available = orig


if __name__ == "__main__":
    unittest.main()
