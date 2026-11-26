"""OpenAPI / Swagger discovery.

Modern targets are JSON APIs with no HTML links, so the crawler finds nothing and
the authz engine, probes and fuzzer have no endpoints to work on. This module
probes the common spec locations, parses any OpenAPI 3 / Swagger 2 document it
finds, and expands its `paths` into concrete in-scope URLs. The URLs are written
to reports/urls_openapi.txt, which load_url_seeds() picks up like any other seed
file - so the authz (IDOR/BOLA) replay, sqlmap/dalfox probes and fuzzer now have
the real API surface to test.

Path parameters (`{id}`, `:id`) are filled with `1` as a placeholder. Catching a
BOLA still needs the victim to own that id (see the authz engine); this module's
job is discovery, not id enumeration.
"""
import json
import os
import re
from urllib.parse import urlparse

import yaml

from core.http_utils import build_session
from core.logger import Logger
from core.parallel import http_workers, pmap

API_SEED_FILE = "reports/urls_openapi.txt"
MAX_ENDPOINTS = 500  # guard against huge specs

# Common spec locations across frameworks (springdoc, drf-yasg, FastAPI, swagger-ui, ...).
SPEC_PATHS = [
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api-docs.json",
    "/api/openapi.json", "/api/swagger.json", "/api/v1/openapi.json",
    "/api/v2/swagger.json", "/api/v3/openapi.json", "/v2/swagger.json", "/v3/openapi.json",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/api/docs/openapi.json", "/.well-known/openapi.json",
    "/openapi/v2", "/openapi/v3", "/docs/openapi.json",
]

_PARAM_BRACE = re.compile(r"\{[^}/]+\}")   # OpenAPI/Swagger {id}
_PARAM_COLON = re.compile(r":([A-Za-z_][A-Za-z0-9_]*)")  # Express-style :id
_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


def parse_spec(text, content_type=""):
    """Parse a spec body as JSON, or YAML when it is not JSON. None if not a dict."""
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass
    if "json" in (content_type or "").lower():
        return None  # claimed JSON but did not parse -> not a YAML fallback
    try:
        doc = yaml.safe_load(text)
        return doc if isinstance(doc, dict) else None
    except yaml.YAMLError:
        return None


def is_openapi(doc):
    return isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc) \
        and isinstance(doc.get("paths"), dict)


def fill_path_params(path):
    """Replace `{id}` and `:id` style params with a `1` placeholder."""
    return _PARAM_COLON.sub("1", _PARAM_BRACE.sub("1", path))


def base_paths(engine, spec):
    """Base URLs for the spec, anchored to the TARGET's origin (ignore the spec's own
    host, which is often an example). Uses OpenAPI `servers` / Swagger `basePath`."""
    p = urlparse(engine.target)
    origin = f"{p.scheme}://{p.netloc}"
    bases = set()
    for server in spec.get("servers") or []:
        url = server.get("url") if isinstance(server, dict) else None
        if url:
            bases.add(origin + (urlparse(url).path or ""))
    if spec.get("basePath"):  # Swagger 2
        bases.add(origin + spec["basePath"])
    if not bases:
        bases.add(origin)
    return {b.rstrip("/") for b in bases}


def expand_spec(engine, spec):
    """Return {concrete_url: set(METHODS)} for every in-scope path in the spec."""
    out = {}
    for raw_path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict) or not str(raw_path).startswith("/"):
            continue
        methods = {m.upper() for m in item if str(m).lower() in _HTTP_METHODS}
        if not methods:
            continue
        concrete = fill_path_params(raw_path)
        for base in base_paths(engine, spec):
            url = base + concrete
            if engine.scope.is_in_scope(url):
                out.setdefault(url, set()).update(methods)
    return out


def _find_specs(engine, session):
    def fetch(path):
        url = engine.target.rstrip("/") + path
        if not engine.scope.is_in_scope(url):
            return None
        try:
            r = session.get(url, allow_redirects=True)
        except Exception:
            return None
        if r.status_code != 200:
            return None
        doc = parse_spec(r.text, r.headers.get("Content-Type", ""))
        return (url, doc) if is_openapi(doc) else None

    return [x for x in pmap(fetch, SPEC_PATHS, http_workers(engine.config)) if x]


def run_api_discovery(engine):
    findings = []
    session = build_session(engine.config)
    specs = _find_specs(engine, session)
    if not specs:
        Logger.info("API discovery: no OpenAPI/Swagger spec found at common locations.")
        return findings

    endpoints = {}
    for spec_url, spec in specs:
        version = spec.get("openapi") or spec.get("swagger") or "?"
        findings.append(f"API spec found: {spec_url} (OpenAPI/Swagger {version})")
        Logger.success(f"API discovery: spec at {spec_url}")
        for url, methods in expand_spec(engine, spec).items():
            endpoints.setdefault(url, set()).update(methods)

    # Persist GET endpoints as seeds for the authz engine / probes / fuzzer.
    get_seeds = sorted(u for u, m in endpoints.items() if "GET" in m)[:MAX_ENDPOINTS]
    os.makedirs("reports", exist_ok=True)
    with open(API_SEED_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(get_seeds) + ("\n" if get_seeds else ""))

    for url in sorted(endpoints)[:MAX_ENDPOINTS]:
        findings.append(f"API endpoint: [{','.join(sorted(endpoints[url]))}] {url}")
    Logger.success(f"API discovery: {len(specs)} spec(s), {len(endpoints)} endpoints "
                   f"({len(get_seeds)} GET seeds for authz/probes)")
    return findings
