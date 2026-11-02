"""Soft-404 detection: many apps (SPAs, catch-all routes, WAF pages) answer 200 for
any path. We request a few random paths first and treat responses that look the
same as "not found", so path-based checks don't report every probe as a hit."""
import re
import secrets
from difflib import SequenceMatcher

from core.logger import Logger

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_SAMPLE_CHARS = 4000
SIMILARITY_THRESHOLD = 0.9


def _normalize_body(text, path):
    # Pages often echo the requested path back; remove it so random paths compare equal.
    body = (text or "")[:_SAMPLE_CHARS]
    for token in {path, path.lstrip("/")}:
        if token:
            body = body.replace(token, "")
    return body


def _fingerprint(resp, path):
    text = resp.text or ""
    title = _TITLE_RE.search(text)
    return {
        "status": resp.status_code,
        "title": title.group(1).strip() if title else "",
        "body": _normalize_body(text, path),
    }


class Soft404Detector:
    def __init__(self, session, base_url, samples=2):
        self.baselines = []
        for suffix in ("", ".php")[:samples]:
            path = f"/aura-{secrets.token_hex(6)}{suffix}"
            try:
                resp = session.get(f"{base_url}{path}", allow_redirects=True)
            except Exception:
                continue
            self.baselines.append(_fingerprint(resp, path))
        if any(b["status"] == 200 for b in self.baselines):
            Logger.warn("Soft-404 behaviour detected: target returns 200 for random paths; filtering lookalikes.")

    def is_soft404(self, resp, path):
        """True if `resp` (for request path `path`) looks like the target's not-found page."""
        fp = _fingerprint(resp, path)
        for base in self.baselines:
            if base["status"] != fp["status"]:
                continue
            if base["body"] == fp["body"]:
                return True
            ratio = SequenceMatcher(None, base["body"], fp["body"]).quick_ratio()
            if ratio >= SIMILARITY_THRESHOLD and base["title"] == fp["title"]:
                return True
        return False


def get_soft404_detector(engine, session):
    return engine.cached("soft404", lambda: Soft404Detector(session, engine.target))
