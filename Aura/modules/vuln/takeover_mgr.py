import os
from core.logger import Logger
from core.tool_runner import is_tool_available, run_command


def _collect_subdomains(domain):
    subs = set()
    sources = [
        ("subfinder", ["subfinder", "-silent", "-d", domain]),
        ("assetfinder", ["assetfinder", "--subs-only", domain]),
    ]
    for tool_name, cmd in sources:
        if not is_tool_available(tool_name):
            continue
        code, out, _ = run_command(cmd, timeout=120)
        if code != 0:
            continue
        for line in out.splitlines():
            sub = line.strip().lower()
            if sub and domain in sub:
                subs.add(sub)
    return sorted(subs)


def run_takeover_checks(engine):
    findings = []
    domain = engine.domain
    subdomains = _collect_subdomains(domain)
    if not subdomains:
        Logger.warn("Takeover checks skipped: no subdomains available.")
        return findings

    os.makedirs("reports", exist_ok=True)
    sub_file = "reports/subdomains_takeover.txt"
    with open(sub_file, "w", encoding="utf-8") as f:
        f.write("\n".join(subdomains) + "\n")

    if is_tool_available("subzy"):
        Logger.info("Phase 1: running subzy takeover checks...")
        cmd = ["subzy", "run", "--targets", sub_file, "--hide_fails", "--verify_ssl"]
        code, out, err = run_command(cmd, timeout=240)
        if code == 0:
            for line in out.splitlines():
                msg = line.strip()
                if "vulnerable" in msg.lower():
                    findings.append(f"Takeover: {msg}")
                    Logger.critical(f"Takeover risk: {msg}")
        elif err:
            Logger.warn(f"subzy returned non-zero: {err}")
    else:
        Logger.warn("subzy not found. Skipping.")

    if is_tool_available("subjack"):
        Logger.info("Phase 1: running subjack takeover checks...")
        fingerprints = ""
        if engine.config:
            fingerprints = engine.config.get("tools", {}).get("subjack_fingerprints", "")

        cmd = ["subjack", "-w", sub_file, "-ssl", "-timeout", "30", "-v"]
        if fingerprints:
            cmd.extend(["-c", fingerprints])

        code, out, err = run_command(cmd, timeout=240)
        if code == 0:
            for line in out.splitlines():
                msg = line.strip()
                if "vulnerable" in msg.lower() or "takeover" in msg.lower():
                    findings.append(f"Takeover: {msg}")
                    Logger.critical(f"Takeover risk: {msg}")
        elif err:
            Logger.warn(f"subjack returned non-zero: {err}")
    else:
        Logger.warn("subjack not found. Skipping.")

    return findings
