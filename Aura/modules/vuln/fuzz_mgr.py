from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from core.logger import Logger
from core.http_utils import build_session
from utils.payload_loader import load_mutations


def _inject_param(url, param, value):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    q = urlencode(params, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, q, parsed.fragment))


def run_payload_mutation_fuzz(engine, seed_urls):
    findings = []
    headers = {"User-Agent": (engine.config or {}).get("settings", {}).get("user_agent", "Aura-Scanner/1.0")}
    session = build_session(engine.config)
    mutations = load_mutations(engine.config)
    fuzz_cfg = (engine.config or {}).get("tuning", {}).get("fuzz", {})
    max_urls = int(fuzz_cfg.get("max_seed_urls", 50))
    max_params = int(fuzz_cfg.get("max_params_per_url", 5))

    candidates = [u for u in (seed_urls or []) if "?" in u][:max_urls]
    for base in candidates:
        parsed = urlparse(base)
        params = parse_qs(parsed.query, keep_blank_values=True)
        for param in list(params.keys())[:max_params]:
            for bucket, payloads in mutations.items():
                for payload in payloads:
                    test_url = _inject_param(base, param, payload)
                    if not engine.scope.is_in_scope(test_url):
                        continue
                    try:
                        r = session.get(test_url, timeout=session._aura_timeout, headers=headers)
                    except Exception:
                        continue
                    body = (r.text or "").lower()
                    if bucket == "xss" and payload.lower() in body:
                        findings.append(f"Fuzz-XSS Reflection: {param} at {parsed.path}")
                    elif bucket == "sqli" and any(k in body for k in ["sql syntax", "odbc", "mysql", "postgresql"]):
                        findings.append(f"Fuzz-SQLi Error Pattern: {param} at {parsed.path}")
                    elif bucket == "ssrf" and "169.254.169.254" in body:
                        findings.append(f"Fuzz-SSRF Echo Pattern: {param} at {parsed.path}")
                    elif bucket == "path" and "root:x:" in body:
                        findings.append(f"Fuzz-Path Traversal Pattern: {param} at {parsed.path}")

    Logger.success(f"Payload mutation fuzzing findings: {len(findings)}")
    return findings
