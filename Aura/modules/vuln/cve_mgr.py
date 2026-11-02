"""CVE detection.

Two layers:

1. **Fingerprint** the stack from response headers (Server, X-Powered-By, etc.)
   and a whatweb run if available, so the report records what software/versions
   are exposed - the starting point for any CVE lookup.

2. **nuclei CVE templates** are the actual matching engine. nuclei ships a
   community template feed that is updated continuously, so running its `cve`
   (and `vulnerabilities`) tagged templates is how "the latest CVEs" get checked
   without us maintaining a CVE database. We refresh the templates first (unless
   disabled) so a scan uses current signatures, then run every severity because
   plenty of real CVEs are rated medium/low.

Version-to-CVE correlation beyond nuclei (e.g. an offline NVD feed) is a larger
feature; see SOURCES.md. For now the fingerprint output makes manual CVE lookup
easy and nuclei covers the automated matches.
"""
import json
import os
import re

from core.http_utils import build_session
from core.logger import Logger
from core.tool_runner import is_tool_available, run_command

NUCLEI_CVE_OUT = "reports/nuclei_cve.json"
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


def _run_nuclei_cves(engine, update_templates):
    if not is_tool_available("nuclei"):
        Logger.warn("nuclei not found. CVE template scan skipped.")
        return []

    if update_templates:
        Logger.info("CVE: refreshing nuclei templates (for latest CVE signatures)...")
        run_command(["nuclei", "-update-templates"], timeout=300)

    if os.path.exists(NUCLEI_CVE_OUT):
        os.remove(NUCLEI_CVE_OUT)  # never report stale results from a previous run

    Logger.info("CVE: running nuclei CVE/vulnerability templates (all severities)...")
    cmd = [
        "nuclei", "-u", engine.target,
        "-tags", "cve,vulnerabilities",
        "-jsonl", "-o", NUCLEI_CVE_OUT, "-silent",
    ]
    code, _, err = run_command(cmd, timeout=1800)
    if code != 0:
        Logger.warn(f"nuclei CVE scan returned non-zero: {err}")
    if not os.path.exists(NUCLEI_CVE_OUT):
        return []

    findings, seen = [], set()
    with open(NUCLEI_CVE_OUT, "r", encoding="utf-8") as f:
        for line in f:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = rec.get("info", {})
            template_id = rec.get("template-id", "")
            # Prefer the CVE id so scoring/dedup key on the CVE itself.
            cve_ids = (info.get("classification", {}) or {}).get("cve-id") or []
            cve = cve_ids[0] if cve_ids else template_id
            if cve in seen:
                continue
            seen.add(cve)
            severity = (info.get("severity") or "unknown").upper()
            name = info.get("name", template_id)
            matched = rec.get("matched-at", engine.target)
            Logger.critical(f"nuclei CVE [{severity}] {cve}: {name} @ {matched}")
            findings.append(f"CVE {cve} [{severity}]: {name} ({matched})")
    return findings


def run_cve_scan(engine, update_templates=True):
    findings = _fingerprint_headers(engine)
    findings.extend(_fingerprint_whatweb(engine))
    findings.extend(_run_nuclei_cves(engine, update_templates))
    Logger.success(f"CVE scan: {len(findings)} fingerprint/CVE findings")
    return findings
