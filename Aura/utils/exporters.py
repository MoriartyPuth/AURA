import csv
import json
import os

from core.findings import coerce_phase_map, findings_to_dicts
from utils.common import utc_now_iso


def _flatten_results(phase_map):
    rows = []
    for phase, modules in phase_map.items():
        if not isinstance(modules, dict):
            continue
        for module, entries in modules.items():
            for f in entries or []:
                rows.append({
                    "phase": phase,
                    "module": module,
                    "severity": (f.severity or "").upper(),
                    "confidence": f.confidence or "",
                    "verified": f.verified,
                    "url": f.url,
                    "finding": f.title,
                })
    return rows


def export_json(path, target, phase_map, risks):
    payload = {
        "target": target,
        "generated_at": utc_now_iso(),
        "phases": findings_to_dicts(coerce_phase_map(phase_map)),
        "risks": risks,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def export_csv(path, phase_map, risks):
    rows = _flatten_results(coerce_phase_map(phase_map))
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["phase", "module", "severity", "confidence", "verified", "url", "finding"]
        )
        writer.writeheader()
        writer.writerows(rows)

    risk_path = f"{os.path.splitext(path)[0]}_risks.csv"
    with open(risk_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["score", "severity", "confidence", "verified", "phase", "source", "url", "finding"])
        writer.writeheader()
        for risk in risks:
            writer.writerow({k: risk.get(k, "") for k in writer.fieldnames})


def export_sarif(path, target, risks):
    results = []
    for risk in risks:
        result = {
            "ruleId": risk["source"],
            "level": "error" if risk["severity"] in {"CRITICAL", "HIGH"} else "warning",
            "message": {"text": risk["finding"]},
            "properties": {
                "score": risk["score"],
                "phase": risk["phase"],
                "severity": risk["severity"],
                "confidence": risk.get("confidence", ""),
                "verified": risk.get("verified", False),
                "target": target,
            },
        }
        # Use the finding's own URL as the location when we have one.
        location = risk.get("url") or target
        result["locations"] = [{
            "physicalLocation": {"artifactLocation": {"uri": location}}
        }]
        if risk.get("references"):
            result["properties"]["references"] = risk["references"]
        results.append(result)

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "Aura-Scanner"}},
            "results": results,
        }],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
