"""Two-account authorization testing (horizontal IDOR / BOLA + missing auth).

The idea (same as Burp's Autorize): take two authenticated sessions belonging to
different users, plus an unauthenticated session, and replay the same in-scope
endpoints with each. If user B gets back the *same* resource that user A sees, B
can read A's data -> horizontal authorization break. If the unauthenticated
session gets it too, the endpoint has no auth at all.

This module is strictly opt-in: it does nothing unless two accounts are
configured, it only replays GET requests (never mutates), and every URL is
scope-checked before it is touched. Provide credentials in config.yaml:

    auth:
      enabled: true
      # "victim" owns the resources; "attacker" is a different low-priv user.
      victim:
        headers: {Cookie: "session=<victim-cookie>"}
      attacker:
        headers: {Cookie: "session=<attacker-cookie>"}
      # Optional: extra authenticated-only paths to test beyond crawled URLs.
      endpoints: ["/api/me", "/api/account/1/settings"]

Credentials are read from config/CLI only and never written to any report.
"""
from difflib import SequenceMatcher
from urllib.parse import urlparse

from core.findings import Finding
from core.http_utils import build_session
from core.logger import Logger
from utils.url_seeds import load_url_seeds

# Bodies at least this similar (0-1) are treated as "the same resource".
SAME_RESOURCE_RATIO = 0.95
# Login walls / error pages are usually short; ignore tiny bodies to cut noise.
MIN_BODY_LEN = 64
# Markers that a response is really a login/redirect wall, not the resource.
_AUTH_WALL_MARKERS = ("sign in", "log in", "login", "authenticate", "unauthorized", "forbidden")


def _session_for(engine, account):
    """A session carrying one account's auth headers (Cookie, Authorization, ...)."""
    session = build_session(engine.config)
    headers = (account or {}).get("headers", {})
    if headers:
        session.headers.update(headers)
    return session


def _fetch(session, url):
    try:
        r = session.get(url, allow_redirects=False)
        return r.status_code, (r.text or "")
    except Exception:
        return None, ""


def _looks_authenticated(status, body):
    """True if the response looks like real content rather than a login wall."""
    if status != 200 or len(body) < MIN_BODY_LEN:
        return False
    head = body[:2000].lower()
    return not any(m in head for m in _AUTH_WALL_MARKERS)


def _same_resource(body_a, body_b):
    if abs(len(body_a) - len(body_b)) > max(len(body_a), len(body_b)) * 0.5:
        return False
    return SequenceMatcher(None, body_a[:8000], body_b[:8000]).quick_ratio() >= SAME_RESOURCE_RATIO


def _candidate_urls(engine, auth_cfg):
    """In-scope endpoints to test: crawled/archived URLs plus configured extras."""
    urls, seen = [], set()
    for path in auth_cfg.get("endpoints", []):
        url = path if path.startswith("http") else f"{engine.target}{path}"
        if url not in seen:
            seen.add(url)
            urls.append(url)
    for url in load_url_seeds():
        parsed = urlparse(url)
        shape = (parsed.netloc, parsed.path, parsed.query)
        if shape not in seen and engine.scope.is_in_scope(url):
            seen.add(shape)
            urls.append(url)
    return urls


def run_authz_checks(engine):
    findings = []
    auth_cfg = engine.config.get("auth", {})
    if not auth_cfg.get("enabled"):
        Logger.warn("Authz checks skipped: auth.enabled is false (no accounts configured).")
        return findings

    victim, attacker = auth_cfg.get("victim") or {}, auth_cfg.get("attacker") or {}
    if not victim.get("headers") or not attacker.get("headers"):
        Logger.warn("Authz checks skipped: both auth.victim and auth.attacker need auth headers (e.g. Cookie).")
        return findings

    victim_s = _session_for(engine, victim)
    attacker_s = _session_for(engine, attacker)
    anon_s = build_session(engine.config)  # no auth headers

    max_urls = int(auth_cfg.get("max_urls", 150))
    tested = 0
    for url in _candidate_urls(engine, auth_cfg):
        if tested >= max_urls:
            break
        if not engine.scope.is_in_scope(url):
            continue
        v_status, v_body = _fetch(victim_s, url)
        if not _looks_authenticated(v_status, v_body):
            continue  # victim can't see a real resource here; nothing to compare
        tested += 1

        a_status, a_body = _fetch(attacker_s, url)
        if _looks_authenticated(a_status, a_body) and _same_resource(v_body, a_body):
            Logger.critical(f"IDOR/BOLA: attacker account reads victim resource at {url}")
            findings.append(Finding(
                title=f"Broken authorization (horizontal/IDOR): {url}",
                severity="critical", confidence="high", verified=True, url=url,
                evidence="Attacker account received a response matching the victim's resource.",
                extra={"class": "idor", "victim_status": v_status, "attacker_status": a_status},
            ))
            continue

        n_status, n_body = _fetch(anon_s, url)
        if _looks_authenticated(n_status, n_body) and _same_resource(v_body, n_body):
            Logger.critical(f"MISSING AUTH: unauthenticated request reads protected resource at {url}")
            findings.append(Finding(
                title=f"Missing authentication: {url}",
                severity="critical", confidence="high", verified=True, url=url,
                evidence="Unauthenticated request received the protected resource.",
                extra={"class": "missing-auth", "victim_status": v_status, "anon_status": n_status},
            ))

    Logger.success(f"Authz checks: tested {tested} authenticated endpoints, {len(findings)} findings")
    return findings
