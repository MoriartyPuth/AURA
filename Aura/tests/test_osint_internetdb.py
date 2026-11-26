import unittest

from core.findings import Finding
from modules.recon import osint_mgr


class FakeResp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, resp):
        self._resp = resp

    def get(self, url, **_):
        return self._resp


def _query(resp):
    # Bypass the rate-limit decorator's sleep by swapping the fetch helper.
    orig = osint_mgr._limited_get
    osint_mgr._limited_get = lambda session, url, timeout: session._resp
    try:
        return osint_mgr._query_internetdb(FakeSession(resp), "198.51.100.7")
    finally:
        osint_mgr._limited_get = orig


class TestInternetDB(unittest.TestCase):
    def test_ports_hostnames_tags_and_cves(self):
        resp = FakeResp(200, {
            "ports": [80, 443], "hostnames": ["a.example"],
            "tags": ["cdn"], "vulns": ["CVE-2021-1234"],
        })
        out = _query(resp)
        titles = [f.title if isinstance(f, Finding) else f for f in out]
        self.assertIn("Shodan InternetDB: 198.51.100.7 open port 80", titles)
        self.assertIn("Shodan InternetDB hostname: a.example", titles)
        self.assertIn("Shodan InternetDB tag: 198.51.100.7 [cdn]", titles)
        cve = next(f for f in out if isinstance(f, Finding))
        self.assertEqual(cve.severity, "medium")
        self.assertFalse(cve.verified)
        self.assertIn("CVE-2021-1234", cve.title)
        self.assertEqual(cve.extra["cve"], "CVE-2021-1234")

    def test_404_is_silent(self):
        self.assertEqual(_query(FakeResp(404, {})), [])

    def test_non_200_is_silent(self):
        self.assertEqual(_query(FakeResp(500, {})), [])

    def test_empty_dataset(self):
        self.assertEqual(_query(FakeResp(200, {"ip": "x", "ports": []})), [])


if __name__ == "__main__":
    unittest.main()
