import re
from collections import deque
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from core.logger import Logger
from core.http_utils import build_session


def _extract_js_endpoints(js_text):
    patterns = [
        r"""["'](/api/[A-Za-z0-9_\-./?=&]+)["']""",
        r"""["'](/[A-Za-z0-9_\-]+/[A-Za-z0-9_\-./?=&]+)["']""",
    ]
    found = set()
    for pattern in patterns:
        for match in re.findall(pattern, js_text or ""):
            found.add(match)
    return found


def run_crawler_pipeline(engine, max_pages=25):
    findings = []
    seen_pages = set()
    queued = deque([engine.target])
    discovered_endpoints = set()

    headers = {"User-Agent": (engine.config or {}).get("settings", {}).get("user_agent", "Aura-Scanner/1.0")}
    session = build_session(engine.config)

    while queued and len(seen_pages) < max_pages:
        current = queued.popleft()
        if current in seen_pages or not engine.scope.is_in_scope(current):
            continue
        seen_pages.add(current)

        try:
            r = session.get(current, timeout=session._aura_timeout, headers=headers)
        except Exception:
            continue
        if "text/html" not in (r.headers.get("Content-Type", "") + "").lower():
            continue

        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            candidate = urljoin(current, a["href"])
            if engine.scope.is_in_scope(candidate):
                parsed = urlparse(candidate)
                clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if clean not in seen_pages:
                    queued.append(clean)

        for s in soup.find_all("script"):
            src = s.get("src")
            if src:
                js_url = urljoin(current, src)
                if engine.scope.is_in_scope(js_url):
                    try:
                        js_resp = session.get(js_url, timeout=session._aura_timeout, headers=headers)
                        for endpoint in _extract_js_endpoints(js_resp.text):
                            abs_ep = urljoin(current, endpoint)
                            if engine.scope.is_in_scope(abs_ep):
                                discovered_endpoints.add(abs_ep)
                    except Exception:
                        continue
            else:
                for endpoint in _extract_js_endpoints(s.get_text() or ""):
                    abs_ep = urljoin(current, endpoint)
                    if engine.scope.is_in_scope(abs_ep):
                        discovered_endpoints.add(abs_ep)

    for page in sorted(seen_pages):
        findings.append(f"Crawled: {page}")
    for endpoint in sorted(discovered_endpoints):
        findings.append(f"JS Endpoint: {endpoint}")

    Logger.success(f"Crawler: pages={len(seen_pages)} js_endpoints={len(discovered_endpoints)}")
    return findings
