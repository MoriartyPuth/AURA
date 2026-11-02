import random
import threading
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# A plain browser UA by default: the old "Aura-Scanner/1.0 (National Security
# Audit)" string was a one-rule WAF block. Override in config settings.user_agent.
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

# Process-wide throttle shared by every AuraSession, so the parallel Phase 0
# workers are paced together rather than each spacing only its own requests.
_rate_lock = threading.Lock()
_last_request = [0.0]


def _throttle(delay, jitter):
    if delay <= 0 and jitter <= 0:
        return
    if delay > 0:
        with _rate_lock:  # held across the sleep -> global min interval between requests
            wait = (_last_request[0] + delay) - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            _last_request[0] = time.monotonic()
    if jitter > 0:
        time.sleep(random.uniform(0, jitter))


class AuraSession(requests.Session):
    """requests.Session that applies the configured timeout to every request and
    paces outbound requests by a global delay + per-request jitter (low noise)."""

    def __init__(self, timeout, delay=0.0, jitter=0.0):
        super().__init__()
        self.default_timeout = timeout
        self.delay = delay
        self.jitter = jitter

    def request(self, method, url, **kwargs):
        kwargs.setdefault("timeout", self.default_timeout)
        _throttle(self.delay, self.jitter)
        return super().request(method, url, **kwargs)


def build_session(config):
    settings = (config or {}).get("settings", {})
    retries = int(settings.get("http_retries", 2))

    session = AuraSession(
        timeout=int(settings.get("timeout", 10)),
        delay=float(settings.get("request_delay", 0.0)),
        jitter=float(settings.get("request_jitter", 0.0)),
    )
    retry = Retry(
        total=retries,
        connect=retries,
        read=retries,
        backoff_factor=float(settings.get("retry_backoff", 1.0)),
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "HEAD", "OPTIONS"],
        respect_retry_after_header=True,  # honor the server's Retry-After on 429/503
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": settings.get("user_agent") or DEFAULT_USER_AGENT})
    session.verify = bool(settings.get("verify_tls", True))

    proxy = settings.get("proxy")
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    return session


def tool_footprint(config):
    """Proxy + rate-limit settings to pass to external scanners (nuclei, ffuf, ...)."""
    s = (config or {}).get("settings", {})
    return {
        "proxy": s.get("proxy") or "",
        "rate_limit": int(s.get("tool_rate_limit", 0) or 0),  # requests/sec, 0 = tool default
    }


def auth_headers(config, account_name="victim"):
    """Headers for a configured account, or {} when auth is disabled/absent."""
    auth = (config or {}).get("auth", {})
    if not auth.get("enabled"):
        return {}
    return ((auth.get(account_name) or {}).get("headers") or {})


def build_authed_session(config, account_name="victim"):
    """A session pre-loaded with a configured account's auth headers (if any)."""
    session = build_session(config)
    headers = auth_headers(config, account_name)
    if headers:
        session.headers.update(headers)
    return session
