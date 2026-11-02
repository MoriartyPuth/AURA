import time
import unittest

from core import http_utils
from core.http_utils import build_session, tool_footprint


class TestFootprintSettings(unittest.TestCase):
    def test_defaults_are_low_noise(self):
        session = build_session({})
        self.assertIn("Mozilla/5.0", session.headers["User-Agent"])  # not "Aura-Scanner"
        self.assertNotIn("Aura-Scanner", session.headers["User-Agent"])
        self.assertEqual(session.proxies, {})  # no proxy unless configured

    def test_proxy_and_ua_from_config(self):
        cfg = {"settings": {"proxy": "http://127.0.0.1:8080", "user_agent": "custom-ua"}}
        session = build_session(cfg)
        self.assertEqual(session.proxies, {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"})
        self.assertEqual(session.headers["User-Agent"], "custom-ua")

    def test_tool_footprint(self):
        fp = tool_footprint({"settings": {"proxy": "http://p:1", "tool_rate_limit": 25}})
        self.assertEqual(fp, {"proxy": "http://p:1", "rate_limit": 25})
        # defaults: no proxy, no cap
        self.assertEqual(tool_footprint({}), {"proxy": "", "rate_limit": 0})


class TestThrottle(unittest.TestCase):
    def test_delay_enforced_globally(self):
        http_utils._last_request[0] = 0.0
        start = time.monotonic()
        http_utils._throttle(0.15, 0.0)  # first call: no prior request, minimal wait
        http_utils._throttle(0.15, 0.0)  # second call must wait ~0.15s after the first
        elapsed = time.monotonic() - start
        self.assertGreaterEqual(elapsed, 0.15)

    def test_noop_when_disabled(self):
        start = time.monotonic()
        http_utils._throttle(0.0, 0.0)
        self.assertLess(time.monotonic() - start, 0.05)


if __name__ == "__main__":
    unittest.main()
