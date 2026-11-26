import re
from datetime import datetime, timezone

_IP_RE = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")
_CONFIDENCE_TAG_RE = re.compile(r"^\[(LOW|MEDIUM|HIGH)\]\s*")
# The same nuclei-template hit can surface from two modules with different wrapping,
# e.g. "Nuclei: React ... RCE" and "CVE CVE-2025-55182: React ... RCE (CVSS 10)".
# Strip the source prefix and the trailing CVSS so both collapse to the shared name
# and dedup/corroboration treat them as one finding.
_SOURCE_PREFIX_RE = re.compile(r"^(?:nuclei|cve\s+cve-\d{4}-\d{3,}):\s*", re.IGNORECASE)
_CVSS_SUFFIX_RE = re.compile(r"\s*\(cvss[^)]*\)\s*$", re.IGNORECASE)


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def strip_confidence_tag(text):
    """Remove the "[HIGH] " style prefix the quality gate adds to findings."""
    return _CONFIDENCE_TAG_RE.sub("", text or "")


def normalize_key(text, strip_ips=False):
    t = strip_confidence_tag(text).lower().strip()
    t = re.sub(r"https?://", "", t)
    t = _SOURCE_PREFIX_RE.sub("", t)
    t = _CVSS_SUFFIX_RE.sub("", t)
    if strip_ips:
        t = _IP_RE.sub("", t)
    return re.sub(r"\s+", " ", t).strip()
