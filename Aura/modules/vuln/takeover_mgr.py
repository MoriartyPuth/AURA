import os
from core.logger import Logger
from core.parallel import run_parallel
from core.tool_runner import is_tool_available, run_command
from modules.recon.subdomain_mgr import collect_subdomains


def _is_takeover_hit(line):
    """True only for a genuinely vulnerable subzy/subjack line. The tools also print
    "[ NOT VULNERABLE ]" for safe subdomains, which contains the substring
    "vulnerable" - so a bare `in` match reports every safe result as a finding."""
    low = line.lower()
    if "not vulnerable" in low or "not-vulnerable" in low:
        return False
    return "vulnerable" in low or "takeover" in low


def run_takeover_checks(engine):
    findings = []
    subdomains = collect_subdomains(engine)
    if not subdomains:
        Logger.warn("Takeover checks skipped: no subdomains available.")
        return findings

    os.makedirs("reports", exist_ok=True)
    sub_file = "reports/subdomains_takeover.txt"
    with open(sub_file, "w", encoding="utf-8") as f:
        f.write("\n".join(subdomains) + "\n")

    # subzy and subjack are independent -> run them concurrently.
    for part in run_parallel(lambda: _subzy(engine, sub_file), lambda: _subjack(engine, sub_file)):
        findings.extend(part)
    return findings


def _subzy(engine, sub_file):
    findings = []
    if is_tool_available("subzy"):
        Logger.info("Phase 1: running subzy takeover checks...")
        cmd = ["subzy", "run", "--targets", sub_file, "--hide_fails", "--verify_ssl"]
        code, out, err = run_command(cmd, timeout=240)
        if code == 0:
            for line in out.splitlines():
                msg = line.strip()
                if _is_takeover_hit(msg):
                    findings.append(f"Takeover: {msg}")
                    Logger.critical(f"Takeover risk: {msg}")
        elif err:
            Logger.warn(f"subzy returned non-zero: {err}")
    else:
        Logger.warn("subzy not found. Skipping.")

    return findings


def _subjack(engine, sub_file):
    findings = []
    if is_tool_available("subjack"):
        Logger.info("Phase 1: running subjack takeover checks...")
        fingerprints = engine.config.get("tools", {}).get("subjack_fingerprints", "")

        cmd = ["subjack", "-w", sub_file, "-ssl", "-timeout", "30", "-v"]
        if fingerprints:
            cmd.extend(["-c", fingerprints])

        code, out, err = run_command(cmd, timeout=240)
        if code == 0:
            for line in out.splitlines():
                msg = line.strip()
                if _is_takeover_hit(msg):
                    findings.append(f"Takeover: {msg}")
                    Logger.critical(f"Takeover risk: {msg}")
        elif err:
            Logger.warn(f"subjack returned non-zero: {err}")
    else:
        Logger.warn("subjack not found. Skipping.")

    return findings
