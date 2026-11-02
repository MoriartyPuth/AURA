import re
from datetime import datetime, timezone

_IP_RE = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")
_CONFIDENCE_TAG_RE = re.compile(r"^\[(LOW|MEDIUM|HIGH)\]\s*")


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def strip_confidence_tag(text):
    """Remove the "[HIGH] " style prefix the quality gate adds to findings."""
    return _CONFIDENCE_TAG_RE.sub("", text or "")


def normalize_key(text, strip_ips=False):
    t = strip_confidence_tag(text).lower().strip()
    t = re.sub(r"https?://", "", t)
    if strip_ips:
        t = _IP_RE.sub("", t)
    return re.sub(r"\s+", " ", t)
