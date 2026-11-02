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
ADMIN_BODY = "Admin panel: user management\nDelete user / promote\n" + "q" * 250


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

    def _run(self, victim, attacker, anon, admin=None, extra_cfg=None):
        # Map sessions by account identity (cookie), not call order, so adding
        # the admin session can't shuffle which fake session each account gets.
        by_cookie = {"s=victim": victim, "s=attacker": attacker, "s=admin": admin}

        def fake_session_for(_engine, account):
            return by_cookie[account["headers"]["Cookie"]]

        orig_sf, orig_build = authz_mgr._session_for, authz_mgr.build_session
        authz_mgr._session_for = fake_session_for
        authz_mgr.build_session = lambda _c: anon  # anon (no-auth) session
        try:
            cfg = {"auth": {"enabled": True,
                            "victim": {"headers": {"Cookie": "s=victim"}},
                            "attacker": {"headers": {"Cookie": "s=attacker"}},
                            "endpoints": ["/api/account/1"]}}
            if admin is not None:
                cfg["auth"]["admin"] = {"headers": {"Cookie": "s=admin"}}
            if extra_cfg:
                cfg["auth"].update(extra_cfg)
            return authz_mgr.run_authz_checks(FakeEngine(cfg))
        finally:
            authz_mgr._session_for, authz_mgr.build_session = orig_sf, orig_build

    def test_idor_detected_when_attacker_sees_victim_resource(self):
        url = "https://app.test/api/account/1"
        findings = self._run(
            victim=FakeSession({url: FakeResp(200, VICTIM_BODY)}),
            attacker=FakeSession({url: FakeResp(200, VICTIM_BODY)}),  # same body -> IDOR
            anon=FakeSession({url: FakeResp(302, "")}),
        )
        self.assertTrue(any("horizontal/IDOR" in f.title for f in findings))
        self.assertEqual(findings[0].severity, "critical")
        self.assertTrue(findings[0].verified)

    def test_vertical_privesc_detected(self):
        admin_url = "https://app.test/admin"
        findings = self._run(
            victim=FakeSession({}),                               # no horizontal resource
            attacker=FakeSession({admin_url: FakeResp(200, ADMIN_BODY)}),  # low-priv sees admin page
            anon=FakeSession({}),
            admin=FakeSession({admin_url: FakeResp(200, ADMIN_BODY)}),
            extra_cfg={"admin_endpoints": ["/admin"]},
        )
        self.assertTrue(any("vertical privilege escalation" in f.title for f in findings))
        self.assertTrue(findings[0].verified)

    def test_no_privesc_when_attacker_blocked_from_admin(self):
        admin_url = "https://app.test/admin"
        findings = self._run(
            victim=FakeSession({}),
            attacker=FakeSession({admin_url: FakeResp(403, "forbidden")}),  # properly blocked
            anon=FakeSession({}),
            admin=FakeSession({admin_url: FakeResp(200, ADMIN_BODY)}),
            extra_cfg={"admin_endpoints": ["/admin"]},
        )
        self.assertEqual(findings, [])

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
        self.assertTrue(any("Missing authentication" in f.title for f in findings))

    def test_skips_when_disabled(self):
        self.assertEqual(authz_mgr.run_authz_checks(FakeEngine({"auth": {"enabled": False}})), [])

    def test_skips_when_one_account_missing(self):
        cfg = {"auth": {"enabled": True, "victim": {"headers": {}}}}
        self.assertEqual(authz_mgr.run_authz_checks(FakeEngine(cfg)), [])


if __name__ == "__main__":
    unittest.main()
