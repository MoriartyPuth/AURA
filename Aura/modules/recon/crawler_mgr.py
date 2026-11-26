import os
import re
from collections import deque
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from core.logger import Logger
from core.http_utils import auth_headers, build_authed_session
from core.parallel import http_workers, pmap


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
    param_urls = set()  # links with query strings: seeds for probes/fuzzing

    # Crawl as the victim account when auth is configured, so the post-login
    # surface is discovered and fed to the probes/fuzzer/authz checks downstream.
    session = build_authed_session(engine.config, "victim")
    authed = bool(auth_headers(engine.config, "victim"))
    if authed:
        Logger.info("Crawler: authenticated crawl using the victim account.")

    workers = http_workers(engine.config)
    fetched_js = set()  # a bundle linked from every page is downloaded once, not per page

    def fetch(url):
        try:
            return session.get(url)
        except Exception:
            return None

    def add_endpoints(js_text, base):
        for endpoint in _extract_js_endpoints(js_text):
            abs_ep = urljoin(base, endpoint)
            if engine.scope.is_in_scope(abs_ep):
                discovered_endpoints.add(abs_ep)

    # Breadth-first, one frontier batch at a time: up to `workers` pages in flight.
    while queued and len(seen_pages) < max_pages:
        batch = []
        while queued and len(seen_pages) + len(batch) < max_pages and len(batch) < workers:
            current = queued.popleft()
            if current in seen_pages or current in batch or not engine.scope.is_in_scope(current):
                continue
            batch.append(current)
        if not batch:
            break
        seen_pages.update(batch)

        js_jobs = []
        for current, r in zip(batch, pmap(fetch, batch, workers)):
            if r is None or "text/html" not in (r.headers.get("Content-Type", "") + "").lower():
                continue

            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if authed and any(w in href.lower() for w in ("logout", "signout", "sign-out", "log-out")):
                    continue  # following a logout link would kill the authenticated session
                candidate = urljoin(current, href)
                if engine.scope.is_in_scope(candidate):
                    parsed = urlparse(candidate)
                    clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    if parsed.query:
                        param_urls.add(f"{clean}?{parsed.query}")
                    if clean not in seen_pages:
                        queued.append(clean)

            for s in soup.find_all("script"):
                src = s.get("src")
                if src:
                    js_url = urljoin(current, src)
                    if engine.scope.is_in_scope(js_url) and js_url not in fetched_js:
                        fetched_js.add(js_url)
                        js_jobs.append((current, js_url))
                else:
                    add_endpoints(s.get_text() or "", current)

        js_resps = pmap(lambda job: fetch(job[1]), js_jobs, workers)
        for (current, _), js_resp in zip(js_jobs, js_resps):
            if js_resp is not None:
                add_endpoints(js_resp.text, current)

    # Persist so the Phase 2 fuzzer can use these as seeds (also survives --resume).
    os.makedirs("reports", exist_ok=True)
    with open("reports/urls_crawled.txt", "w", encoding="utf-8") as f:
        f.writelines(f"{u}\n" for u in sorted(seen_pages | discovered_endpoints | param_urls))

    for page in sorted(seen_pages):
        findings.append(f"Crawled: {page}")
    for endpoint in sorted(discovered_endpoints):
        findings.append(f"JS Endpoint: {endpoint}")

    mode = "authenticated" if authed else "unauthenticated"
    findings.insert(0, f"Crawl mode: {mode} ({len(seen_pages)} pages, {len(discovered_endpoints)} JS endpoints)")
    Logger.success(f"Crawler: {mode} pages={len(seen_pages)} js_endpoints={len(discovered_endpoints)}")
    return findings
