import unittest

from core.soft404 import Soft404Detector


class FakeResp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text


SPA_SHELL = "<html><head><title>App</title></head><body><div id=root></div>{path}</body></html>"


class CatchAllSession:
    """Answers 200 with the same SPA shell (echoing the path) for every URL."""

    def get(self, url, **_):
        return FakeResp(200, SPA_SHELL.format(path=url.split("127.0.0.1", 1)[-1]))


class Real404Session:
    def get(self, url, **_):
        return FakeResp(404, "<html><title>Not Found</title></html>")


class TestSoft404(unittest.TestCase):
    def test_catch_all_spa_is_soft404(self):
        det = Soft404Detector(CatchAllSession(), "http://127.0.0.1")
        resp = FakeResp(200, SPA_SHELL.format(path="/.env"))
        self.assertTrue(det.is_soft404(resp, "/.env"))

    def test_distinct_content_is_not_soft404(self):
        det = Soft404Detector(CatchAllSession(), "http://127.0.0.1")
        resp = FakeResp(200, "DB_PASSWORD=hunter2\nSECRET_KEY=abc\n")
        self.assertFalse(det.is_soft404(resp, "/.env"))

    def test_real_404_server_never_flags_200(self):
        det = Soft404Detector(Real404Session(), "http://127.0.0.1")
        self.assertFalse(det.is_soft404(FakeResp(200, "<title>Admin</title>"), "/admin"))


if __name__ == "__main__":
    unittest.main()
