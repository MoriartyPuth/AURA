import json
import os

from core.logger import Logger
from core.tool_runner import is_tool_available, run_command

NUCLEI_OUT = "reports/nuclei_raw.json"


def run_nuclei(target, severity="high,critical", rate_limit=0, proxy=""):
    findings = []
    if not is_tool_available("nuclei"):
        Logger.warn("nuclei not found. Skipping.")
        return findings

    if os.path.exists(NUCLEI_OUT):
        os.remove(NUCLEI_OUT)  # never report stale results from a previous run
    cmd = ["nuclei", "-u", target, "-severity", severity, "-jsonl", "-o", NUCLEI_OUT, "-silent"]
    if rate_limit:
        cmd += ["-rl", str(rate_limit)]  # requests/sec cap
    if proxy:
        cmd += ["-proxy", proxy]
    code, _, err = run_command(cmd, timeout=1800)
    if code != 0:
        Logger.warn(f"nuclei returned non-zero: {err}")
    if not os.path.exists(NUCLEI_OUT):
        return findings

    seen = set()
    with open(NUCLEI_OUT, "r", encoding="utf-8") as f:
        for line in f:
            try:
                name = json.loads(line).get("info", {}).get("name")
            except json.JSONDecodeError:
                continue
            if name and name not in seen:
                seen.add(name)
                findings.append(f"Nuclei: {name}")
                Logger.warn(f"Nuclei: {name}")
    return findings
