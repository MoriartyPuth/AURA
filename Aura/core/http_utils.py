import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_USER_AGENT = "Aura-Scanner/1.0"


class AuraSession(requests.Session):
    """requests.Session that applies the configured timeout to every request."""

    def __init__(self, timeout):
        super().__init__()
        self.default_timeout = timeout

    def request(self, method, url, **kwargs):
        kwargs.setdefault("timeout", self.default_timeout)
        return super().request(method, url, **kwargs)


def build_session(config):
    settings = (config or {}).get("settings", {})
    retries = int(settings.get("http_retries", 2))

    session = AuraSession(timeout=int(settings.get("timeout", 10)))
    retry = Retry(
        total=retries,
        connect=retries,
        read=retries,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "HEAD", "OPTIONS"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": settings.get("user_agent", DEFAULT_USER_AGENT)})
    session.verify = bool(settings.get("verify_tls", True))
    return session


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
