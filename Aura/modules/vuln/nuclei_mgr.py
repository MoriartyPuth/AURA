"""Single nuclei pass for Phase 2.

nuclei used to run twice: once here at the profile severity and again in the CVE
module with `-tags cve,vulnerabilities`. That double-scanned the target. Now one
pass runs at the profile severity and every result is parsed from the same JSONL:
a match carrying a real CVE id becomes a structured, verified CVE finding (CVSS,
references, searchsploit/msfconsole lookups -> reports/cve_details.json); any
other match becomes a plain nuclei finding. CVE detection therefore follows the
profile severity now (use a broader profile, e.g. `deep`, for medium/low CVEs).
"""
import json
import os

from core.findings import Finding
from core.http_utils import tool_footprint
from core.logger import Logger
from core.tool_runner import is_tool_available, run_command
from modules.vuln.exploit_refs import CVE_RE, build_cve_detail, format_finding

NUCLEI_OUT = "reports/nuclei_raw.json"
CVE_DETAILS_OUT = "reports/cve_details.json"


def run_nuclei(engine, severity="high,critical", update_templates=False):
    """Run nuclei once and return plain findings + structured CVE findings."""
    findings = []
    if not is_tool_available("nuclei"):
        Logger.warn("nuclei not found. Skipping.")
        return findings

    footprint = tool_footprint(engine.config)
    if update_templates:
        Logger.info("nuclei: refreshing templates for the latest signatures...")
        run_command(["nuclei", "-update-templates"], timeout=300)

    if os.path.exists(NUCLEI_OUT):
        os.remove(NUCLEI_OUT)  # never report stale results from a previous run

    Logger.info(f"Phase 2: nuclei scan (severity {severity}, CVEs enriched from same pass)...")
    cmd = ["nuclei", "-u", engine.target, "-severity", severity, "-jsonl", "-o", NUCLEI_OUT, "-silent"]
    if footprint["rate_limit"]:
        cmd += ["-rl", str(footprint["rate_limit"])]  # requests/sec cap
    if footprint["proxy"]:
        cmd += ["-proxy", footprint["proxy"]]
    code, _, err = run_command(cmd, timeout=1800)
    if code != 0:
        Logger.warn(f"nuclei returned non-zero: {err}")
    if not os.path.exists(NUCLEI_OUT):
        return findings

    details, seen_names, seen_cves = [], set(), set()
    with open(NUCLEI_OUT, "r", encoding="utf-8") as f:
        for line in f:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = rec.get("info", {}) or {}
            name = info.get("name") or rec.get("template-id")
            if not name:
                continue

            detail = build_cve_detail(rec, engine.target)
            if CVE_RE.match(detail["id"] or ""):  # a real CVE match -> structured finding
                if detail["id"] in seen_cves:
                    continue
                seen_cves.add(detail["id"])
                details.append(detail)
                Logger.critical(f"nuclei {format_finding(detail)}")
                sev = detail["severity"].lower()
                title = f"CVE {detail['id']}: {detail['name']}"
                if detail.get("cvss_score"):
                    title += f" (CVSS {detail['cvss_score']})"
                findings.append(Finding(
                    title=title,
                    severity=sev if sev in {"critical", "high", "medium", "low", "info"} else "info",
                    confidence="high", verified=True,
                    url=detail["matched_at"],
                    references=detail["references"],
                    extra={"cve": detail["id"], "cvss": detail.get("cvss_score"),
                           "cwe": detail.get("cwe"), "lookup_commands": detail["lookup_commands"]},
                ))
            elif name not in seen_names:  # non-CVE template match -> plain finding
                seen_names.add(name)
                findings.append(f"Nuclei: {name}")
                Logger.warn(f"Nuclei: {name}")

    # Structured CVE details (references, CVSS, lookup commands) for manual follow-up.
    # Exploitation stays a human, authorized step.
    if details:
        os.makedirs("reports", exist_ok=True)
        with open(CVE_DETAILS_OUT, "w", encoding="utf-8") as f:
            json.dump({"target": engine.target, "cves": details}, f, indent=2)
    Logger.success(f"nuclei: {len(findings)} findings ({len(details)} CVEs enriched)")
    return findings
