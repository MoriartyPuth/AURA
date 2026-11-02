import unittest

from core.scope import ScopeManager


class TestScopeManager(unittest.TestCase):
    def test_base_scope(self):
        scope = ScopeManager("example.com")
        self.assertTrue(scope.is_in_scope("https://app.example.com/a"))
        self.assertFalse(scope.is_in_scope("https://evil.com"))

    def test_exclude_domain(self):
        scope = ScopeManager("example.com", exclude_domains=["admin.example.com"])
        self.assertFalse(scope.is_in_scope("https://admin.example.com"))
        self.assertTrue(scope.is_in_scope("https://www.example.com"))

    def test_ports_and_bare_hosts(self):
        scope = ScopeManager("example.com")
        self.assertTrue(scope.is_in_scope("https://example.com:8443/a"))
        self.assertTrue(scope.is_in_scope("api.example.com"))
        self.assertFalse(scope.is_in_scope("https://example.com.evil.net/"))

    def test_host_scope_ignores_url_regex(self):
        scope = ScopeManager("example.com", exclude_domains=["dev.example.com"], scope_regex=r"/app/")
        self.assertTrue(scope.is_host_in_scope("api.example.com"))
        self.assertFalse(scope.is_host_in_scope("x.dev.example.com"))
        self.assertFalse(scope.is_in_scope("https://api.example.com/other"))


if __name__ == "__main__":
    unittest.main()
