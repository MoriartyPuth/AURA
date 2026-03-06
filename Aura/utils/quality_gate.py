import re


CONF_ORDER = {"low": 1, "medium": 2, "high": 3}


def _confidence_of_finding(text):
    t = (text or "").lower()
    if any(k in t for k in ["confirmed", "critical data leak", "takeover:", "nuclei:", "vulnerable"]):
        return "high"
    if any(k in t for k in ["potential", "possible", "manual review", "heuristic", "may be"]):
        return "low"
    return "medium"


def _norm_key(text):
    t = (text or "").lower().strip()
    t = re.sub(r"https?://", "", t)
    t = re.sub(r"\s+", " ", t)
    return t


def apply_quality_gate(phase_map, min_confidence="medium"):
    min_rank = CONF_ORDER.get((min_confidence or "medium").lower(), 2)
    corroboration = {}

    for _, modules in phase_map.items():
        for _, entries in (modules or {}).items():
            for entry in entries or []:
                key = _norm_key(entry)
                corroboration[key] = corroboration.get(key, 0) + 1

    filtered = {}
    dropped = 0
    kept = 0
    for phase, modules in phase_map.items():
        filtered[phase] = {}
        for source, entries in (modules or {}).items():
            out = []
            for entry in entries or []:
                conf = _confidence_of_finding(entry)
                rank = CONF_ORDER[conf]
                key = _norm_key(entry)
                # Keep low confidence findings only if corroborated by multiple modules.
                if conf == "low" and corroboration.get(key, 0) >= 2:
                    rank = max(rank, CONF_ORDER["medium"])
                if rank >= min_rank:
                    out.append(f"[{conf.upper()}] {entry}")
                    kept += 1
                else:
                    dropped += 1
            filtered[phase][source] = out

    meta = {"kept": kept, "dropped": dropped, "min_confidence": min_confidence}
    return filtered, meta
