import asyncio, aiohttp, yaml, os
from urllib.parse import urlparse
from core.logger import Logger
from core.scope import ScopeManager

class AuraEngine:
    def __init__(self, target, include_domains=None, exclude_domains=None, scope_regex=None):
        self.target = target
        self.domain = self.extract_domain(target)
        self.config = self.load_config()
        cfg_scope = (self.config or {}).get("scope", {})
        include_domains = include_domains or cfg_scope.get("include_domains", [])
        exclude_domains = exclude_domains or cfg_scope.get("exclude_domains", [])
        scope_regex = scope_regex or cfg_scope.get("url_regex")
        self.scope = ScopeManager(
            self.domain,
            include_domains=include_domains,
            exclude_domains=exclude_domains,
            scope_regex=scope_regex,
        )

    def load_config(self):
        if os.path.exists("config.yaml"):
            with open("config.yaml", "r") as f: return yaml.safe_load(f)
        return None

    async def fetch(self, session, url):
        if not self.scope.is_in_scope(url):
            return None
        ua = self.config['settings']['user_agent'] if self.config else "Aura-Scanner/1.0"
        verify_tls = bool((self.config or {}).get("settings", {}).get("verify_tls", True))
        timeout = int((self.config or {}).get("settings", {}).get("timeout", 10))
        headers = {'User-Agent': ua}
        try:
            async with session.get(url, timeout=timeout, ssl=verify_tls, headers=headers) as response:
                return {"url": url, "status": response.status, "text": await response.text()}
        except: return None

    async def run_scan(self, paths):
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch(session, f"{self.target}{p}") for p in paths]
            return await asyncio.gather(*tasks)

    @staticmethod
    def extract_domain(target):
        parsed = urlparse(target)
        return parsed.netloc or target.split("//")[-1].split("/")[0]
