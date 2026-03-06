import re
from urllib.parse import urlparse


class ScopeManager:
    def __init__(self, base_domain, include_domains=None, exclude_domains=None, scope_regex=None):
        self.base_domain = (base_domain or "").lower()
        self.include_domains = [d.lower() for d in (include_domains or []) if d]
        self.exclude_domains = [d.lower() for d in (exclude_domains or []) if d]
        self.scope_re = re.compile(scope_regex) if scope_regex else None

    def _extract_domain(self, value):
        parsed = urlparse(value)
        host = (parsed.netloc or value).split("/")[0].lower()
        return host

    def is_in_scope(self, value):
        host = self._extract_domain(value)
        if not host:
            return False

        if self.exclude_domains and any(host == d or host.endswith(f".{d}") for d in self.exclude_domains):
            return False

        if self.include_domains:
            if not any(host == d or host.endswith(f".{d}") for d in self.include_domains):
                return False
        else:
            if self.base_domain and not (host == self.base_domain or host.endswith(f".{self.base_domain}")):
                return False

        if self.scope_re and not self.scope_re.search(value):
            return False

        return True
