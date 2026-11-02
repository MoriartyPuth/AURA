import unittest

from modules.vuln.probe_mgr import parse_dalfox_output, parse_sqlmap_log

SQLMAP_LOG = """sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 5713=5713

    Type: UNION query
    Title: Generic UNION query (NULL) - 2 columns
    Payload: id=1 UNION ALL SELECT NULL,NULL--
---
back-end DBMS: SQLite
"""


class TestProbeParsers(unittest.TestCase):
    def test_sqlmap_log(self):
        self.assertEqual(parse_sqlmap_log(SQLMAP_LOG), [("id (GET)", ["boolean-based blind", "UNION query"])])

    def test_sqlmap_empty_log_means_no_finding(self):
        self.assertEqual(parse_sqlmap_log(""), [])

    def test_dalfox_json_array(self):
        out = '[{"type":"V","param":"q","data":"http://x/?q=%3Csvg%3E"},{"type":"G","param":"","data":"http://x/"}]'
        self.assertEqual(parse_dalfox_output(out), [("V", "q", "http://x/?q=%3Csvg%3E"), ("G", "", "http://x/")])

    def test_dalfox_jsonl_and_empty_objects(self):
        out = '{"type":"R","param":"name","data":"http://x/?name=a"}\n{}\n'
        self.assertEqual(parse_dalfox_output(out), [("R", "name", "http://x/?name=a")])

    def test_dalfox_plain_poc_lines(self):
        out = "[POC][V][GET][inHTML-URL] http://x/?q=%22%3E%3Csvg%3E"
        self.assertEqual(parse_dalfox_output(out), [("V", "inHTML-URL", "http://x/?q=%22%3E%3Csvg%3E")])


if __name__ == "__main__":
    unittest.main()
