import json
import unittest

from modules.auth import authz_mgr as az


class TestIdExtraction(unittest.TestCase):
    def test_ids_from_json_keys(self):
        out = set()
        az._ids_from_json({"id": 8, "order_id": 6, "userId": 42,
                           "width": 100, "nested": {"vehicle_id": 7},
                           "items": [{"id": 9}, {"id": 10}]}, out)
        self.assertEqual(out, {8, 6, 42, 7, 9, 10})   # width (not an id key) excluded

    def test_ids_from_json_ignores_bools_and_strings(self):
        out = set()
        az._ids_from_json({"id": True, "order_id": "6", "name_id": "abc"}, out)
        self.assertEqual(out, {6})  # "6" string counted, bool and non-numeric excluded

    def test_path_ids(self):
        self.assertEqual(az._path_ids("http://x/api/v3/orders/6/items/9"), {6, 9})
        self.assertEqual(az._path_ids("http://x/api/v2/user/dashboard"), set())  # v2 not a bare int


class TestHarvestAndExpand(unittest.TestCase):
    def test_harvest_from_body_and_path(self):
        def fetch(url):
            if url.endswith("/orders"):
                return 200, json.dumps([{"id": 6}, {"id": 7}])
            return 200, "{}"
        ids = az.harvest_ids(fetch, ["http://x/orders", "http://x/orders/1"], workers=1)
        self.assertEqual(set(ids), {6, 7, 1})  # 6,7 from body; 1 from the path

    def test_expand_substitutes_harvested_ids(self):
        urls = ["http://x/orders/1", "http://x/user/dashboard"]
        out = az.expand_with_ids(urls, ids=[6, 7], neighbor=0)
        self.assertIn("http://x/orders/1", out)   # original kept
        self.assertIn("http://x/orders/6", out)   # harvested id substituted
        self.assertIn("http://x/orders/7", out)
        self.assertEqual([u for u in out if "dashboard" in u], ["http://x/user/dashboard"])  # no numeric slot

    def test_neighbor_window(self):
        out = az.expand_with_ids(["http://x/orders/5"], ids=[], neighbor=1)
        for u in ("http://x/orders/4", "http://x/orders/5", "http://x/orders/6"):
            self.assertIn(u, out)

    def test_total_cap(self):
        out = az.expand_with_ids(["http://x/o/1"], ids=list(range(1, 5000)), neighbor=0, total_cap=50)
        self.assertLessEqual(len(out), 50)


class TestEndToEndEnumeration(unittest.TestCase):
    """harvest + expand wired through _candidate_urls_enumerated."""
    def test_list_endpoint_seeds_the_bola_url(self):
        class Scope:
            def is_in_scope(self, u): return "x.test" in u

        class Eng:
            target = "http://x.test"; domain = "x.test"; config = {}
            scope = Scope()
        # base candidates: a list endpoint (owner's orders) + the param endpoint
        orig = az._candidate_urls
        az._candidate_urls = lambda e, p: ["http://x.test/orders", "http://x.test/orders/1"]
        try:
            def owner_fetch(url):
                if url.endswith("/orders"):
                    return 200, json.dumps([{"id": 6}])
                return 404, ""
            urls = az._candidate_urls_enumerated(Eng(), {"id_enumeration": True}, None, owner_fetch)
        finally:
            az._candidate_urls = orig
        self.assertIn("http://x.test/orders/6", urls)  # the real BOLA url, discovered automatically


if __name__ == "__main__":
    unittest.main()
