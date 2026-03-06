import base64
from urllib.parse import urljoin

from bs4 import BeautifulSoup
import mmh3

from core.logger import Logger
from core.http_utils import build_session


def _get_user_agent(engine):
    configured = (engine.config or {}).get("settings", {}).get("user_agent")
    if configured:
        return configured
    try:
        from fake_useragent import UserAgent
        return UserAgent().random
    except Exception:
        return "Aura-Scanner/1.0"


def run_web_intel(engine):
    findings = []
    session = build_session(engine.config)
    headers = {"User-Agent": _get_user_agent(engine)}
    target = engine.target

    try:
        r = session.get(target, headers=headers, timeout=session._aura_timeout)
        findings.append(f"HTTP Status: {r.status_code}")

        soup = BeautifulSoup(r.text, "html.parser")
        title = (soup.title.string or "").strip() if soup.title else ""
        if title:
            findings.append(f"Page Title: {title}")

        favicon_href = None
        icon = soup.find("link", rel=lambda value: value and "icon" in value.lower())
        if icon and icon.get("href"):
            favicon_href = icon.get("href")
        if not favicon_href:
            favicon_href = "/favicon.ico"

        favicon_url = urljoin(target + "/", favicon_href)
        fav = session.get(favicon_url, headers=headers, timeout=session._aura_timeout)
        if fav.ok and fav.content:
            b64 = base64.b64encode(fav.content)
            hash_val = mmh3.hash(b64)
            findings.append(f"Favicon Hash (mmh3): {hash_val}")
    except Exception as ex:
        Logger.warn(f"Web intel failed: {ex}")

    return findings
