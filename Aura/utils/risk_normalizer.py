import re


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
}


def infer_severity(text):
    t = text.lower()
    if any(k in t for k in ["critical", "takeover", "rce", "auth bypass", "data leak", "xxe", "request smuggling"]):
        return "critical"
    if any(k in t for k in ["high", "sqli", "xss", "ssrf", "vulnerable", "injection", "ssti", "lfi", "rfi"]):
        return "high"
    if any(k in t for k in ["medium", "misconfig", "outdated", "sensitive", "cors", "open redirect", "nosqli", "crlf"]):
        return "medium"
    if any(k in t for k in ["low", "info leak", "disclosure"]):
        return "low"
    return "info"


def _normalize_key(text):
    t = text.lower().strip()
    t = re.sub(r"https?://", "", t)
    t = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", "", t)
    t = re.sub(r"\s+", " ", t)
    return t


def build_risk_table(phase_map):
    dedup = {}

    for phase, modules in phase_map.items():
        if not isinstance(modules, dict):
            continue
        for source, entries in modules.items():
            for entry in entries or []:
                severity = infer_severity(entry)
                score = SEVERITY_SCORES[severity] + SOURCE_BONUS.get(source, 0)
                key = _normalize_key(entry)
                item = {
                    "severity": severity.upper(),
                    "score": score,
                    "phase": phase,
                    "source": source,
                    "finding": entry,
                }
                if key not in dedup or item["score"] > dedup[key]["score"]:
                    dedup[key] = item

    table = sorted(dedup.values(), key=lambda x: x["score"], reverse=True)
    return table
