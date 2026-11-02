from core.findings import coerce_phase_map
from utils.common import normalize_key

CONF_ORDER = {"low": 1, "medium": 2, "high": 3}

_HIGH_MARKERS = ["confirmed", "verified", "critical data leak", "takeover:", "nuclei:", "vulnerable"]
_LOW_MARKERS = ["potential", "possible", "manual review", "heuristic", "may be"]


def _infer_confidence(finding):
    """Explicit finding.confidence wins; otherwise infer from the title (legacy)."""
    if finding.confidence in CONF_ORDER:
        return finding.confidence
    if finding.verified:
        return "high"
    t = (finding.title or "").lower()
    if any(k in t for k in _HIGH_MARKERS):
        return "high"
    if any(k in t for k in _LOW_MARKERS):
        return "low"
    return "medium"


def apply_quality_gate(phase_map, min_confidence="medium"):
    phase_map = coerce_phase_map(phase_map)
    min_rank = CONF_ORDER.get((min_confidence or "medium").lower(), 2)

    corroboration = {}
    for modules in phase_map.values():
        for entries in (modules or {}).values():
            for f in entries or []:
                key = normalize_key(f.title)
                corroboration[key] = corroboration.get(key, 0) + 1

    filtered = {}
    dropped = kept = 0
    for phase, modules in phase_map.items():
        filtered[phase] = {}
        for source, entries in (modules or {}).items():
            out = []
            for f in entries or []:
                conf = _infer_confidence(f)
                rank = CONF_ORDER[conf]
                # Keep low-confidence findings only if corroborated by >=2 modules.
                if conf == "low" and corroboration.get(normalize_key(f.title), 0) >= 2:
                    conf, rank = "medium", CONF_ORDER["medium"]
                if rank >= min_rank:
                    f.confidence = conf  # record on the finding, not glued into the title
                    out.append(f)
                    kept += 1
                else:
                    dropped += 1
            filtered[phase][source] = out

    return filtered, {"kept": kept, "dropped": dropped, "min_confidence": min_confidence}
