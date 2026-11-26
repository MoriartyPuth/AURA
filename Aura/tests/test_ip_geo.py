import unittest

from modules.recon import osint_plus_mgr


class FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, payload):
        self._payload = payload

    def get(self, *_a, **_k):
        return FakeResp(self._payload)


class TestIpGeoKeyless(unittest.TestCase):
    def setUp(self):
        self._orig = osint_plus_mgr.build_session

    def tearDown(self):
        osint_plus_mgr.build_session = self._orig

    def test_ip_api_fallback_when_no_token(self):
        osint_plus_mgr.build_session = lambda _c: FakeSession({
            "status": "success", "country": "Australia",
            "org": "Cloudflare DNS", "as": "AS13335 Cloudflare, Inc.",
        })
        out = osint_plus_mgr._ip_geo({}, "1.1.1.1")
        self.assertIn("AS13335", out)
        self.assertIn("Australia", out)
        self.assertTrue(out.startswith("IP Geo (ip-api)"))

    def test_ip_api_failure_returns_none(self):
        osint_plus_mgr.build_session = lambda _c: FakeSession({"status": "fail"})
        self.assertIsNone(osint_plus_mgr._ip_geo({}, "10.0.0.1"))

    def test_placeholder_token_uses_keyless(self):
        osint_plus_mgr.build_session = lambda _c: FakeSession({
            "status": "success", "country": "US", "as": "AS1", "org": "x"})
        out = osint_plus_mgr._ip_geo({"ipinfo": {"token": "YOUR_IPINFO_TOKEN"}}, "1.2.3.4")
        self.assertIn("ip-api", out)


if __name__ == "__main__":
    unittest.main()
