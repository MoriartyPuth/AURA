import unittest

from modules.vuln.takeover_mgr import _is_takeover_hit


class TestTakeoverFilter(unittest.TestCase):
    def test_vulnerable_is_a_hit(self):
        self.assertTrue(_is_takeover_hit("[ VULNERABLE ]  https://sub.example.com (GitHub)"))
        self.assertTrue(_is_takeover_hit("sub.example.com is vulnerable to subdomain takeover"))
        self.assertTrue(_is_takeover_hit("[Takeover] cname -> unclaimed bucket"))

    def test_not_vulnerable_is_not_a_hit(self):
        # The core bug: "not vulnerable" contains "vulnerable".
        self.assertFalse(_is_takeover_hit("[ NOT VULNERABLE ]  https://sub.example.com"))
        self.assertFalse(_is_takeover_hit("Takeover: [Not Vulnerable]"))
        self.assertFalse(_is_takeover_hit("sub.example.com not-vulnerable"))

    def test_unrelated_line_is_not_a_hit(self):
        self.assertFalse(_is_takeover_hit("[ INFO ] scanned 42 subdomains"))


if __name__ == "__main__":
    unittest.main()
