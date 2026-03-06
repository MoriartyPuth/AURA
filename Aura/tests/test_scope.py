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


if __name__ == "__main__":
    unittest.main()
