import os
from urllib.parse import urlparse

import yaml

from core.scope import ScopeManager


class AuraEngine:
    def __init__(self, target, include_domains=None, exclude_domains=None, scope_regex=None):
        self.target = target
        self.domain = self.extract_domain(target)
        self.config = self.load_config()
        self._cache = {}
        cfg_scope = self.config.get("scope", {})
        self.scope = ScopeManager(
            self.domain,
            include_domains=include_domains or cfg_scope.get("include_domains", []),
            exclude_domains=exclude_domains or cfg_scope.get("exclude_domains", []),
            scope_regex=scope_regex or cfg_scope.get("url_regex"),
        )

    @staticmethod
    def load_config(path="config.yaml"):
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        return {}

    def cached(self, key, producer):
        """Run an expensive collector (e.g. subfinder, gau) once per scan and reuse the result."""
        if key not in self._cache:
            self._cache[key] = producer()
        return self._cache[key]

    @staticmethod
    def extract_domain(target):
        parsed = urlparse(target if "//" in target else f"//{target}")
        return (parsed.hostname or "").lower()
