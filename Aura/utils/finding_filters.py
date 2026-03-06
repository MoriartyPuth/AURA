import re


def apply_finding_filters(phase_map, config):
    tuning = (config or {}).get("tuning", {})
    patterns = tuning.get("ignore_finding_patterns", [])
    if not patterns:
        return phase_map, {"filtered": 0}

    compiled = []
    for p in patterns:
        try:
            compiled.append(re.compile(p, re.IGNORECASE))
        except re.error:
            continue

    filtered = {}
    dropped = 0
    for phase, modules in phase_map.items():
        filtered[phase] = {}
        for source, entries in (modules or {}).items():
            kept = []
            for entry in entries or []:
                if any(c.search(entry or "") for c in compiled):
                    dropped += 1
                    continue
                kept.append(entry)
            filtered[phase][source] = kept
    return filtered, {"filtered": dropped}
