import unittest

from modules.auth import authz_mgr


class FakeResp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text


class FakeSession:
    """Maps url -> FakeResp. Missing urls return 404."""

    def __init__(self, responses):
        self.responses = responses
        self.headers = {}

    def get(self, url, **_):
        return self.responses.get(url, FakeResp(404, "not found"))


VICTIM_BODY = "Account owner: Alice\nBalance: $4200\nSSN: 111\n" + "x" * 200
OTHER_BODY = "Account owner: Bob\nBalance: $17\nSSN: 999\n" + "y" * 200
LOGIN_WALL = "<html><body>Please log in to continue</body></html>" + "z" * 100


class FakeEngine:
    def __init__(self, config):
        self.config = config
        self.target = "https://app.test"

        class _Scope:
            def is_in_scope(self, _):
                return True

        self.scope = _Scope()


class TestAuthz(unittest.TestCase):
    def setUp(self):
        self._orig_seeds = authz_mgr.load_url_seeds
        authz_mgr.load_url_seeds = lambda: []

    def tearDown(self):
        authz_mgr.load_url_seeds = self._orig_seeds

    def _run(self, victim, attacker, anon):
        sessions = {"victim": victim, "attacker": attacker, "anon": anon}
        calls = {"n": 0}

        def fake_build(_config):
            # victim first, attacker second, anon third (order matches module)
            key = ["victim", "attacker", "anon"][min(calls["n"], 2)]
            calls["n"] += 1
            return sessions[key]

        orig = authz_mgr.build_session
        authz_mgr.build_session = fake_build
        try:
            cfg = {"auth": {"enabled": True,
                            "victim": {"headers": {"Cookie": "s=victim"}},
                            "attacker": {"headers": {"Cookie": "s=attacker"}},
                            "endpoints": ["/api/account/1"]}}
            return authz_mgr.run_authz_checks(FakeEngine(cfg))
        finally:
            authz_mgr.build_session = orig

    def test_idor_detected_when_attacker_sees_victim_resource(self):
        url = "https://app.test/api/account/1"
        findings = self._run(
            victim=FakeSession({url: FakeResp(200, VICTIM_BODY)}),
            attacker=FakeSession({url: FakeResp(200, VICTIM_BODY)}),  # same body -> IDOR
            anon=FakeSession({url: FakeResp(302, "")}),
        )
        self.assertTrue(any("horizontal/IDOR" in f for f in findings))

    def test_no_finding_when_attacker_gets_own_data(self):
        url = "https://app.test/api/account/1"
        findings = self._run(
            victim=FakeSession({url: FakeResp(200, VICTIM_BODY)}),
            attacker=FakeSession({url: FakeResp(200, OTHER_BODY)}),  # different body
            anon=FakeSession({url: FakeResp(302, "")}),
        )
        self.assertEqual(findings, [])

    def test_no_finding_when_attacker_hits_login_wall(self):
        url = "https://app.test/api/account/1"
        findings = self._run(
            victim=FakeSession({url: FakeResp(200, VICTIM_BODY)}),
            attacker=FakeSession({url: FakeResp(200, LOGIN_WALL)}),  # wall, not resource
            anon=FakeSession({url: FakeResp(200, LOGIN_WALL)}),
        )
        self.assertEqual(findings, [])

    def test_missing_auth_detected_for_anonymous_access(self):
        url = "https://app.test/api/account/1"
        findings = self._run(
            victim=FakeSession({url: FakeResp(200, VICTIM_BODY)}),
            attacker=FakeSession({url: FakeResp(403, "forbidden")}),
            anon=FakeSession({url: FakeResp(200, VICTIM_BODY)}),  # anon sees it
        )
        self.assertTrue(any("MISSING AUTHENTICATION" in f for f in findings))

    def test_skips_when_disabled(self):
        self.assertEqual(authz_mgr.run_authz_checks(FakeEngine({"auth": {"enabled": False}})), [])

    def test_skips_when_one_account_missing(self):
        cfg = {"auth": {"enabled": True, "victim": {"headers": {}}}}
        self.assertEqual(authz_mgr.run_authz_checks(FakeEngine(cfg)), [])


if __name__ == "__main__":
    unittest.main()
