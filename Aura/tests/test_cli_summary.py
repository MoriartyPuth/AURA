import re
import unittest

from utils.cli_summary import format_summary

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def plain(lines):
    return "\n".join(ANSI.sub("", line) for line in lines)


RISKS = [
    {"severity": "CRITICAL", "score": 105, "source": "Subdomain Takeover Checks",
     "finding": "Takeover: dev.x.com VULNERABLE", "confidence": "high", "url": "https://dev.x.com", "verified": True},
    {"severity": "MEDIUM", "score": 53, "source": "Misconfiguration Checks",
     "finding": "CORS misconfiguration", "confidence": "", "url": "", "verified": False},
    {"severity": "INFO", "score": 12, "source": "Crawler & JS Endpoints",
     "finding": "Crawled: https://x.com/about", "confidence": "", "url": "", "verified": False},
]


class TestCliSummary(unittest.TestCase):
    def test_lists_real_findings_and_hides_info(self):
        out = plain(format_summary("https://x.com", RISKS, width=120))
        self.assertIn("CRITICAL 1", out)
        self.assertIn("Takeover: dev.x.com VULNERABLE", out)
        self.assertIn("verified", out)
        self.assertIn("CORS misconfiguration", out)
        self.assertNotIn("Crawled: https://x.com/about", out)
        self.assertIn("1 INFO entries hidden", out)
        # Critical is printed before medium.
        self.assertLess(out.index("[CRITICAL]"), out.index("[MEDIUM]"))

    def test_show_info_lists_info(self):
        out = plain(format_summary("https://x.com", RISKS, show_info=True, width=120))
        self.assertIn("Crawled: https://x.com/about", out)
        self.assertNotIn("hidden", out)

    def test_no_real_findings(self):
        out = plain(format_summary("https://x.com", RISKS[2:], width=120))
        self.assertIn("No findings at LOW or above.", out)

    def test_long_titles_truncated(self):
        long = [{**RISKS[0], "finding": "A" * 500}]
        out = plain(format_summary("https://x.com", long, width=80))
        self.assertNotIn("A" * 200, out)


if __name__ == "__main__":
    unittest.main()
