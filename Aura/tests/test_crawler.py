import os
import tempfile
import unittest

from modules.recon import crawler_mgr


class FakeResp:
    def __init__(self, text):
        self.text = text
        self.headers = {"Content-Type": "text/html"}


class RecordingSession:
    def __init__(self, pages):
        self.pages = pages
        self.headers = {}
        self.requested = []

    def get(self, url, **_):
        self.requested.append(url)
        return FakeResp(self.pages.get(url, "<html></html>"))


class FakeScope:
    def __init__(self, target):
        self.host = target

    def is_in_scope(self, url):
        return self.host in url


class FakeEngine:
    def __init__(self, config):
        self.config = config
        self.target = "https://app.test"
        self.scope = FakeScope("app.test")


HOME = """
<html><body>
  <a href="/dashboard">dash</a>
  <a href="/logout">logout</a>
  <a href="/account?id=1">acct</a>
</body></html>
"""


class TestAuthenticatedCrawl(unittest.TestCase):
    def _run(self, auth_enabled):
        session = RecordingSession({"https://app.test": HOME})
        cfg = {"auth": {"enabled": auth_enabled, "victim": {"headers": {"Cookie": "s=victim"}}}}

        orig_build, orig_auth = crawler_mgr.build_authed_session, crawler_mgr.auth_headers
        crawler_mgr.build_authed_session = lambda _c, _a="victim": session
        crawler_mgr.auth_headers = orig_auth
        cwd = os.getcwd()
        tmp = tempfile.mkdtemp()
        os.chdir(tmp)
        try:
            findings = crawler_mgr.run_crawler_pipeline(FakeEngine(cfg), max_pages=10)
        finally:
            os.chdir(cwd)
            crawler_mgr.build_authed_session, crawler_mgr.auth_headers = orig_build, orig_auth
        return findings, session

    def test_authenticated_mode_skips_logout(self):
        findings, session = self._run(auth_enabled=True)
        self.assertIn("authenticated", findings[0])
        # logout link must never be requested
        self.assertFalse(any("logout" in u for u in session.requested))
        # but the normal in-scope page is crawled
        self.assertTrue(any("/dashboard" in u for u in session.requested))

    def test_unauthenticated_mode_reported(self):
        findings, _ = self._run(auth_enabled=False)
        self.assertIn("unauthenticated", findings[0])


if __name__ == "__main__":
    unittest.main()
