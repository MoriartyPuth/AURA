"""Authorization testing (horizontal IDOR/BOLA, vertical priv-esc, missing auth).

The idea (same as Burp's Autorize): replay the same in-scope endpoints with
sessions of different privilege, plus unauthenticated, and compare responses.

  - horizontal (IDOR/BOLA): the attacker account receives the *same* resource the
    victim (a different same-level user) sees -> reads another user's data
  - vertical (privilege escalation): the low-priv attacker receives the *same*
    resource the admin sees -> reaches functionality above its privilege
  - missing auth: an unauthenticated request receives the protected resource

Strictly opt-in: does nothing unless accounts are configured, only replays GET
requests (never mutates), and scope-checks every URL first. config.yaml:

    auth:
      enabled: true
      victim:                       # owns resources (same level as attacker)
        headers: {Cookie: "session=<victim-cookie>"}
      attacker:                     # different low-priv user (the probe)
        headers: {Cookie: "session=<attacker-cookie>"}
      admin:                        # optional high-priv user (enables vertical)
        headers: {Cookie: "session=<admin-cookie>"}
      endpoints: ["/api/me", "/api/account/1/settings"]   # extra URLs to test
      admin_endpoints: ["/admin", "/admin/users"]         # admin-only URLs

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


def _absolutize(engine, paths):
    return [p if p.startswith("http") else f"{engine.target}{p}" for p in (paths or [])]


def _candidate_urls(engine, extra_paths):
    """In-scope endpoints to test: configured extras plus crawled/archived URLs."""
    urls, seen = [], set()
    for url in _absolutize(engine, extra_paths):
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


def _probe_sees_owner(owner_body, probe_result):
    """True if the probe session got authenticated content matching the owner's resource."""
    status, body = probe_result
    return _looks_authenticated(status, body) and _same_resource(owner_body, body)


def run_authz_checks(engine):
    findings = []
    auth_cfg = engine.config.get("auth", {})
    if not auth_cfg.get("enabled"):
        Logger.warn("Authz checks skipped: auth.enabled is false (no accounts configured).")
        return findings

    victim, attacker = auth_cfg.get("victim") or {}, auth_cfg.get("attacker") or {}
    admin = auth_cfg.get("admin") or {}
    if not victim.get("headers") or not attacker.get("headers"):
        Logger.warn("Authz checks skipped: both auth.victim and auth.attacker need auth headers (e.g. Cookie).")
        return findings

    victim_s = _session_for(engine, victim)
    attacker_s = _session_for(engine, attacker)
    anon_s = build_session(engine.config)  # no auth headers
    admin_s = _session_for(engine, admin) if admin.get("headers") else None

    max_urls = int(auth_cfg.get("max_urls", 150))
    tested = 0

    # Horizontal + missing-auth: resource owner is the victim (same level as attacker).
    for url in _candidate_urls(engine, auth_cfg.get("endpoints")):
        if tested >= max_urls:
            break
        if not engine.scope.is_in_scope(url):
            continue
        v_status, v_body = _fetch(victim_s, url)
        if not _looks_authenticated(v_status, v_body):
            continue  # victim can't see a real resource here; nothing to compare
        tested += 1

        if _probe_sees_owner(v_body, _fetch(attacker_s, url)):
            Logger.critical(f"IDOR/BOLA: attacker account reads victim resource at {url}")
            findings.append(Finding(
                title=f"Broken authorization (horizontal/IDOR): {url}",
                severity="critical", confidence="high", verified=True, url=url,
                evidence="Attacker account received a response matching the victim's resource.",
                extra={"class": "idor"},
            ))
            continue

        if _probe_sees_owner(v_body, _fetch(anon_s, url)):
            Logger.critical(f"MISSING AUTH: unauthenticated request reads protected resource at {url}")
            findings.append(Finding(
                title=f"Missing authentication: {url}",
                severity="critical", confidence="high", verified=True, url=url,
                evidence="Unauthenticated request received the protected resource.",
                extra={"class": "missing-auth"},
            ))

    # Vertical privilege escalation: resource owner is the admin; the low-priv
    # attacker must NOT be able to reach it. Needs an admin account configured.
    if admin_s is not None:
        vtested = 0
        admin_urls = _candidate_urls(engine, auth_cfg.get("admin_endpoints"))
        for url in admin_urls:
            if vtested >= max_urls:
                break
            if not engine.scope.is_in_scope(url):
                continue
            ad_status, ad_body = _fetch(admin_s, url)
            if not _looks_authenticated(ad_status, ad_body):
                continue  # admin sees no real resource here
            vtested += 1
            if _probe_sees_owner(ad_body, _fetch(attacker_s, url)):
                Logger.critical(f"PRIV-ESC: low-priv account reaches admin resource at {url}")
                findings.append(Finding(
                    title=f"Broken authorization (vertical privilege escalation): {url}",
                    severity="critical", confidence="high", verified=True, url=url,
                    evidence="Low-privilege attacker account received the admin's resource.",
                    extra={"class": "privilege-escalation"},
                ))
        tested += vtested

    Logger.success(f"Authz checks: tested {tested} endpoints, {len(findings)} findings")
    return findings
