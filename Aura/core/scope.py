import re
from urllib.parse import urlparse


def _matches(host, domain):
    return host == domain or host.endswith(f".{domain}")


class ScopeManager:
    def __init__(self, base_domain, include_domains=None, exclude_domains=None, scope_regex=None):
        self.base_domain = (base_domain or "").lower()
        self.include_domains = [d.lower() for d in (include_domains or []) if d]
        self.exclude_domains = [d.lower() for d in (exclude_domains or []) if d]
        self.scope_re = re.compile(scope_regex) if scope_regex else None

    @staticmethod
    def _extract_host(value):
        parsed = urlparse(value if "//" in value else f"//{value}")
        return (parsed.hostname or "").lower()

    def is_in_scope(self, value):
        host = self._extract_host(value)
        if not host:
            return False
        if any(_matches(host, d) for d in self.exclude_domains):
            return False
        allowed = self.include_domains or ([self.base_domain] if self.base_domain else [])
        if allowed and not any(_matches(host, d) for d in allowed):
            return False
        if self.scope_re and not self.scope_re.search(value):
            return False
        return True
