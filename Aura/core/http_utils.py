import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def get_http_settings(config):
    settings = (config or {}).get("settings", {})
    timeout = int(settings.get("timeout", 10))
    verify_tls = bool(settings.get("verify_tls", True))
    retries = int(settings.get("http_retries", 2))
    user_agent = settings.get("user_agent", "Aura-Scanner/1.0")
    return timeout, verify_tls, retries, user_agent


def build_session(config):
    timeout, verify_tls, retries, user_agent = get_http_settings(config)
    session = requests.Session()
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
    session.headers.update({"User-Agent": user_agent})
    session.verify = verify_tls
    session._aura_timeout = timeout
    return session
