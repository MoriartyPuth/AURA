import re

from core.findings import coerce_phase_map
from utils.common import normalize_key


SEVERITY_SCORES = {
    "critical": 95,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 10,
}

SOURCE_BONUS = {
    "Nuclei Findings": 8,
    "Subdomain Takeover Checks": 7,
    "Web Vulnerability Probes": 6,
    "Deep Scanner Findings": 5,
    "Identity Leak Checks": 6,
    "Misconfiguration Checks": 3,
    "Classic Vuln Classes": 7,
    "Payload Mutation Fuzzing": 7,
    "Crawler & JS Endpoints": 2,
    "Cloud & Infra Checks": 4,
    "Toolchain Health": 1,
    "Authorization (IDOR/BOLA) Checks": 8,
    "CVE Detection": 7,
}


# Keyword patterns are matched on word boundaries so e.g. "rce" does not match
# "resources" and "low" does not match "allow".
SEVERITY_KEYWORDS = [
    ("critical", ["critical", "takeover", "rce", "auth bypass", "broken authorization", "missing authentication", "idor", "bola", "data leak", "xxe", "request smuggling"]),
    ("high", ["high", "sqli", "xss", "ssrf", "vulnerable", "injection", "ssti", "lfi", "rfi"]),
    ("medium", ["medium", "misconfig", "misconfiguration", "outdated", "sensitive", "cors", "open redirect", "nosqli", "crlf"]),
    ("low", ["low", "info leak", "disclosure"]),
]
SEVERITY_PATTERNS = [
    (sev, re.compile(r"\b(" + "|".join(re.escape(k) for k in kws) + r")\b", re.IGNORECASE))
    for sev, kws in SEVERITY_KEYWORDS
]

# Tool-verified findings (e.g. sqlmap-confirmed injection) outrank heuristic ones.
CONFIRMED_RE = re.compile(r"\b(confirmed|verified)\b", re.IGNORECASE)
CONFIRMED_BONUS = 10


def infer_severity(text):
    for severity, pattern in SEVERITY_PATTERNS:
        if pattern.search(text or ""):
            return severity
    return "info"


def severity_of(finding):
    """Explicit finding.severity wins; otherwise infer from the title."""
    sev = (finding.severity or "").lower()
    if sev in SEVERITY_SCORES:
        return sev
    return infer_severity(finding.title)


def build_risk_table(phase_map):
    phase_map = coerce_phase_map(phase_map)
    dedup = {}

    for phase, modules in phase_map.items():
        if not isinstance(modules, dict):
            continue
        for source, entries in modules.items():
            for f in entries or []:
                severity = severity_of(f)
                score = SEVERITY_SCORES[severity] + SOURCE_BONUS.get(source, 0)
                if f.verified or CONFIRMED_RE.search(f.title):
                    score += CONFIRMED_BONUS
                key = normalize_key(f.title, strip_ips=True)
                item = {
                    "severity": severity.upper(),
                    "score": score,
                    "phase": phase,
                    "source": source,
                    "finding": f.title,
                    "confidence": f.confidence or "",
                    "url": f.url,
                    "verified": f.verified,
                    "references": f.references,
                }
                if key not in dedup or item["score"] > dedup[key]["score"]:
                    dedup[key] = item

    return sorted(dedup.values(), key=lambda x: x["score"], reverse=True)
