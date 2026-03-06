import csv
import json
import os
from datetime import datetime


def _flatten_results(phase_map):
    rows = []
    for phase, modules in phase_map.items():
        if not isinstance(modules, dict):
            continue
        for module, entries in modules.items():
            for entry in entries or []:
                rows.append({
                    "phase": phase,
                    "module": module,
                    "finding": entry,
                })
    return rows


def export_json(path, target, phase_map, risks):
    payload = {
        "target": target,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "phases": phase_map,
        "risks": risks,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def export_csv(path, phase_map, risks):
    rows = _flatten_results(phase_map)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["phase", "module", "finding"])
        writer.writeheader()
        writer.writerows(rows)

    risk_path = f"{os.path.splitext(path)[0]}_risks.csv"
    with open(risk_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["score", "severity", "phase", "source", "finding"])
        writer.writeheader()
        writer.writerows(risks)


def export_sarif(path, target, risks):
    results = []
    for risk in risks:
        results.append({
            "ruleId": risk["source"],
            "level": "error" if risk["severity"] in {"CRITICAL", "HIGH"} else "warning",
            "message": {"text": risk["finding"]},
            "properties": {
                "score": risk["score"],
                "phase": risk["phase"],
                "target": target,
            },
        })

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
