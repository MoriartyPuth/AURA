"""Stack fingerprinting for CVE follow-up.

The actual CVE *matching* now happens in the single nuclei pass (see
modules/vuln/nuclei_mgr.py), which enriches any CVE-tagged hit with CVSS,
references and searchsploit/msfconsole lookups. This module only fingerprints
the exposed stack from response headers and `whatweb`, so the report records
what software/versions are present - the starting point for a manual CVE lookup.
"""
import json
import re

from core.http_utils import build_session
from core.logger import Logger
from core.tool_runner import is_tool_available, run_command

# Headers that commonly leak a product and sometimes a version.
_FINGERPRINT_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator", "Via", "X-Runtime"]
_VERSION_RE = re.compile(r"[\w.-]+/\d[\w.-]*")


def _fingerprint_headers(engine):
    findings = []
    session = build_session(engine.config)
    try:
        resp = session.get(engine.target, allow_redirects=True)
    except Exception as ex:
        Logger.warn(f"CVE fingerprint request failed: {ex}")
        return findings
    for header in _FINGERPRINT_HEADERS:
        value = resp.headers.get(header)
        if value:
            tag = "versioned" if _VERSION_RE.search(value) else "product"
            findings.append(f"Tech Fingerprint ({tag}): {header}: {value}")
    return findings


def _fingerprint_whatweb(engine):
    if not is_tool_available("whatweb"):
        return []
    Logger.info("CVE: fingerprinting stack with whatweb...")
    code, out, _ = run_command(["whatweb", "--no-errors", "-a", "3", "--log-json=-", engine.target], timeout=120)
    if code != 0 or not out:
        return []
    products = set()
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            plugins = json.loads(line).get("plugins", {})
        except json.JSONDecodeError:
            continue
        for name, data in plugins.items():
            versions = ", ".join(data.get("version", [])) if isinstance(data, dict) else ""
            products.add(f"{name} {versions}".strip())
    return [f"Tech Fingerprint (whatweb): {p}" for p in sorted(products)]


def run_cve_scan(engine, update_templates=False):
    """Fingerprint the stack. nuclei's CVE matching runs in the unified nuclei pass.

    `update_templates` is accepted for call-site compatibility but unused here.
    """
    findings = _fingerprint_headers(engine)
    findings.extend(_fingerprint_whatweb(engine))
    Logger.success(f"CVE fingerprint: {len(findings)} product/version findings")
    return findings
