import asyncio
import aiohttp
import yaml
import os
from core.logger import Logger

class AuraEngine:
    def __init__(self, target):
        self.target = target
        self.config = self.load_config()

    def load_config(self):
        if os.path.exists("config.yaml"):
            with open("config.yaml", "r") as f:
                return yaml.safe_load(f)
        return None

    async def fetch(self, session, url):
        headers = {'User-Agent': self.config['settings']['user_agent']} if self.config else {}
        try:
            async with session.get(url, timeout=10, ssl=False, headers=headers) as response:
                return {"url": url, "status": response.status, "text": await response.text()}
        except Exception:
            return None

    async def run_scan(self, paths):
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch(session, f"{self.target}{p}") for p in paths]
            return await asyncio.gather(*tasks)