import json
from datetime import datetime


CHECKLIST = [
    {"id": "scope-controls", "title": "Scope controls configured and enforced"},
    {"id": "crawler-enabled", "title": "Crawler and JS endpoint extraction enabled"},
    {"id": "vuln-classes", "title": "Core vulnerability classes scanned"},
    {"id": "payload-fuzzing", "title": "Payload mutation fuzzing executed"},
    {"id": "toolchain-health", "title": "Toolchain health/version checks executed"},
    {"id": "stateful-scan", "title": "State/resume checkpointing enabled"},
    {"id": "exports", "title": "JSON/CSV/SARIF outputs generated"},
    {"id": "cloud-coverage", "title": "Cloud checks expanded beyond S3"},
    {"id": "quality-gate", "title": "Confidence quality gate enforced"},
    {"id": "http-hardening", "title": "HTTP TLS verify/retry policy enabled"},
    {"id": "tests", "title": "Core hardening tests passed"},
    {"id": "profiles", "title": "Quick/Normal/Deep scan profiles configured"},
    {"id": "payload-pack", "title": "Local payload and wordlist pack configured"},
    {"id": "maintenance", "title": "Toolchain maintenance workflow configured"},
]


def _status_from_evidence(item_id, evidence):
    return "DONE" if evidence.get(item_id, False) else "PENDING"


def generate_checklists(report_path, json_path, evidence):
    lines = [
        f"# Aura Checklist ({datetime.utcnow().isoformat()}Z)",
        "",
    ]
    payload = {"generated_at": datetime.utcnow().isoformat() + "Z", "items": []}

    for item in CHECKLIST:
        status = _status_from_evidence(item["id"], evidence)
        lines.append(f"- [{ 'x' if status == 'DONE' else ' ' }] {item['title']} ({status})")
        payload["items"].append({
            "id": item["id"],
            "title": item["title"],
            "status": status,
        })

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
