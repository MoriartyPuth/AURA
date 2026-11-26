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
import json
import re
from difflib import SequenceMatcher
from urllib.parse import urlparse

from core.findings import Finding
from core.http_utils import build_session
from core.logger import Logger
from core.parallel import http_workers, pmap
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


# --- ID enumeration -------------------------------------------------------
# Discovery fills path params with a placeholder (/orders/1). To catch a BOLA the
# owner must actually own the tested id, so we harvest the owner's real ids from
# their own responses (and list endpoints) and substitute them into numeric path
# segments, plus a small sequential window to catch guessable-id IDOR.
_ID_KEY_RE = re.compile(r"(?:^id$|_id$|Id$)")
_MAX_ID = 10 ** 12


def _ids_from_json(obj, out, depth=0):
    if depth > 6 or len(out) > 200:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if _ID_KEY_RE.search(str(k)):
                if isinstance(v, bool):
                    continue
                if isinstance(v, int) and 0 < v < _MAX_ID:
                    out.add(v)
                elif isinstance(v, str) and v.isdigit() and 0 < int(v) < _MAX_ID:
                    out.add(int(v))
            _ids_from_json(v, out, depth + 1)
    elif isinstance(obj, list):
        for x in obj[:50]:
            _ids_from_json(x, out, depth + 1)


def _path_ids(url):
    return {int(seg) for seg in urlparse(url).path.split("/")
            if seg.isdigit() and 0 < int(seg) < _MAX_ID}


def harvest_ids(fetch_fn, urls, workers, limit=25):
    """Fetch each url as the owner and collect id-like values from JSON bodies and
    from numeric path segments. `fetch_fn(url) -> (status, body)`."""
    found = set()

    def grab(url):
        ids = set(_path_ids(url))
        status, body = fetch_fn(url)
        if status == 200 and body:
            try:
                _ids_from_json(json.loads(body), ids)
            except (ValueError, TypeError):
                pass
        return ids

    for ids in pmap(grab, urls, workers):
        found |= ids
    return sorted(found)[:limit]


def expand_with_ids(urls, ids, neighbor=1, per_url_cap=40, total_cap=600):
    """For each url with a numeric path segment, add variants substituting each
    harvested id (and ±neighbor of the segment already present). Originals kept."""
    out, seen = [], set()

    def add(u):
        if u not in seen:
            seen.add(u)
            out.append(u)

    for url in urls:
        add(url)
        pu = urlparse(url)
        parts = pu.path.split("/")
        slots = [i for i, p in enumerate(parts) if p.isdigit()]
        if not slots or len(out) >= total_cap:
            continue
        sub = set(ids)
        for i in slots:  # sequential window around the id already in the path
            n = int(parts[i])
            sub.update(n + d for d in range(-neighbor, neighbor + 1) if n + d > 0)
        made = 0
        for i in slots:
            for new_id in sorted(sub):
                if made >= per_url_cap or len(out) >= total_cap:
                    break
                variant = list(parts)
                variant[i] = str(new_id)
                add(pu._replace(path="/".join(variant)).geturl())
                made += 1
    return out[:total_cap]


def _candidate_urls_enumerated(engine, auth_cfg, extra_paths, owner_fetch):
    """Base candidate urls, plus id-substituted variants when id enumeration is on."""
    base = [u for u in _candidate_urls(engine, extra_paths) if engine.scope.is_in_scope(u)]
    if not auth_cfg.get("id_enumeration", True):
        return base
    workers = http_workers(engine.config)
    ids = harvest_ids(owner_fetch, base, workers)
    neighbor = int(auth_cfg.get("id_neighbor_window", 1))
    expanded = [u for u in expand_with_ids(base, ids, neighbor=neighbor)
                if engine.scope.is_in_scope(u)]
    if len(expanded) > len(base):
        Logger.info(f"Authz: id enumeration harvested {len(ids)} ids -> "
                    f"{len(expanded)} candidate urls (from {len(base)}).")
    return expanded


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
    workers = http_workers(engine.config)

    # Horizontal + missing-auth: resource owner is the victim (same level as attacker).
    def check_horizontal(url):
        """-> (tested, finding|None) for one URL."""
        v_status, v_body = _fetch(victim_s, url)
        if not _looks_authenticated(v_status, v_body):
            return False, None  # victim can't see a real resource here; nothing to compare
        if _probe_sees_owner(v_body, _fetch(attacker_s, url)):
            Logger.critical(f"IDOR/BOLA: attacker account reads victim resource at {url}")
            return True, Finding(
                title=f"Broken authorization (horizontal/IDOR): {url}",
                severity="critical", confidence="high", verified=True, url=url,
                evidence="Attacker account received a response matching the victim's resource.",
                extra={"class": "idor"},
            )
        if _probe_sees_owner(v_body, _fetch(anon_s, url)):
            Logger.critical(f"MISSING AUTH: unauthenticated request reads protected resource at {url}")
            return True, Finding(
                title=f"Missing authentication: {url}",
                severity="critical", confidence="high", verified=True, url=url,
                evidence="Unauthenticated request received the protected resource.",
                extra={"class": "missing-auth"},
            )
        return True, None

    urls = _candidate_urls_enumerated(engine, auth_cfg, auth_cfg.get("endpoints"),
                                      lambda u: _fetch(victim_s, u))
    tested = _run_capped(check_horizontal, urls, max_urls, workers, findings)

    # Vertical privilege escalation: resource owner is the admin; the low-priv
    # attacker must NOT be able to reach it. Needs an admin account configured.
    if admin_s is not None:
        def check_vertical(url):
            ad_status, ad_body = _fetch(admin_s, url)
            if not _looks_authenticated(ad_status, ad_body):
                return False, None  # admin sees no real resource here
            if _probe_sees_owner(ad_body, _fetch(attacker_s, url)):
                Logger.critical(f"PRIV-ESC: low-priv account reaches admin resource at {url}")
                return True, Finding(
                    title=f"Broken authorization (vertical privilege escalation): {url}",
                    severity="critical", confidence="high", verified=True, url=url,
                    evidence="Low-privilege attacker account received the admin's resource.",
                    extra={"class": "privilege-escalation"},
                )
            return True, None

        admin_urls = _candidate_urls_enumerated(engine, auth_cfg, auth_cfg.get("admin_endpoints"),
                                                lambda u: _fetch(admin_s, u))
        tested += _run_capped(check_vertical, admin_urls, max_urls, workers, findings)

    Logger.success(f"Authz checks: tested {tested} endpoints, {len(findings)} findings")
    return findings


def _run_capped(check, urls, max_tested, workers, findings):
    """Run `check(url) -> (tested, finding)` over urls in concurrent batches, stopping
    once `max_tested` URLs were actually tested. Results are consumed in URL order, so
    the cap and the findings match the serial behaviour (a batch may overshoot a few
    requests, but extra results past the cap are discarded)."""
    tested = 0
    for i in range(0, len(urls), workers):
        if tested >= max_tested:
            break
        for was_tested, finding in pmap(check, urls[i:i + workers], workers):
            if tested >= max_tested:
                break
            if not was_tested:
                continue
            tested += 1
            if finding is not None:
                findings.append(finding)
    return tested
