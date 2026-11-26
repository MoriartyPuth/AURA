import unittest

from modules.recon import api_discovery_mgr as api


class FakeScope:
    def __init__(self, host):
        self.host = host

    def is_in_scope(self, url):
        return self.host in url


class FakeEngine:
    def __init__(self, target="http://api.test:8888"):
        self.target = target
        self.domain = "api.test"
        self.config = {}
        self.scope = FakeScope("api.test")


OPENAPI3 = {
    "openapi": "3.0.1",
    "servers": [{"url": "/api/v3"}],
    "paths": {
        "/orders/{order_id}": {"get": {}, "delete": {}},
        "/users/me": {"get": {}},
        "/login": {"post": {}},  # no GET -> not a seed
    },
}
SWAGGER2 = {
    "swagger": "2.0",
    "basePath": "/v2",
    "paths": {"/pet/{petId}": {"get": {}}, "/store/inventory": {"get": {}}},
}


class TestParsing(unittest.TestCase):
    def test_parse_json(self):
        self.assertEqual(api.parse_spec('{"openapi":"3.0.0","paths":{}}')["openapi"], "3.0.0")

    def test_parse_yaml_fallback(self):
        doc = api.parse_spec("openapi: 3.0.0\npaths: {}\n", content_type="text/yaml")
        self.assertEqual(doc["openapi"], "3.0.0")

    def test_claimed_json_that_fails_is_not_yaml(self):
        self.assertIsNone(api.parse_spec("not json", content_type="application/json"))

    def test_is_openapi(self):
        self.assertTrue(api.is_openapi(OPENAPI3))
        self.assertTrue(api.is_openapi(SWAGGER2))
        self.assertFalse(api.is_openapi({"paths": {}}))      # no version marker
        self.assertFalse(api.is_openapi({"openapi": "3"}))   # no paths


class TestExpansion(unittest.TestCase):
    def test_fill_params(self):
        self.assertEqual(api.fill_path_params("/orders/{order_id}/items/{i}"), "/orders/1/items/1")
        self.assertEqual(api.fill_path_params("/users/:id/posts/:pid"), "/users/1/posts/1")

    def test_base_paths_anchor_to_target_origin(self):
        e = FakeEngine("http://api.test:8888")
        self.assertEqual(api.base_paths(e, OPENAPI3), {"http://api.test:8888/api/v3"})
        self.assertEqual(api.base_paths(e, SWAGGER2), {"http://api.test:8888/v2"})
        self.assertEqual(api.base_paths(e, {"paths": {}}), {"http://api.test:8888"})

    def test_expand_openapi3(self):
        out = api.expand_spec(FakeEngine(), OPENAPI3)
        self.assertEqual(out["http://api.test:8888/api/v3/orders/1"], {"GET", "DELETE"})
        self.assertEqual(out["http://api.test:8888/api/v3/users/me"], {"GET"})
        self.assertEqual(out["http://api.test:8888/api/v3/login"], {"POST"})

    def test_expand_respects_scope(self):
        e = FakeEngine()
        e.scope = FakeScope("other.test")  # nothing in scope
        self.assertEqual(api.expand_spec(e, OPENAPI3), {})

    def test_expand_swagger2(self):
        out = api.expand_spec(FakeEngine(), SWAGGER2)
        self.assertIn("http://api.test:8888/v2/pet/1", out)
        self.assertIn("http://api.test:8888/v2/store/inventory", out)


class TestFindSpecs(unittest.TestCase):
    def test_finds_json_spec_and_ignores_404(self):
        class Resp:
            def __init__(self, status, text, ct="application/json"):
                self.status_code, self.text, self.headers = status, text, {"Content-Type": ct}

        import json as _j
        hits = {"/openapi.json": Resp(200, _j.dumps(OPENAPI3))}

        from urllib.parse import urlparse

        class Session:
            def get(self, url, **_):
                return hits.get(urlparse(url).path, Resp(404, ""))

        orig = api.build_session
        api.build_session = lambda _c: Session()
        try:
            specs = api._find_specs(FakeEngine(), Session())
        finally:
            api.build_session = orig
        self.assertEqual(len(specs), 1)
        self.assertTrue(specs[0][0].endswith("/openapi.json"))


if __name__ == "__main__":
    unittest.main()
