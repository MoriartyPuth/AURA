from core.logger import Logger
from core.tool_runner import is_tool_available, run_command


def run_misconfig_checks(target):
    findings = []

    checks = [
        ("whatweb", ["whatweb", target], "Tech Fingerprint"),
        ("nikto", ["nikto", "-h", target, "-ask", "no"], "Misconfiguration"),
    ]

    for tool_name, command, label in checks:
        if not is_tool_available(tool_name):
            Logger.warn(f"{tool_name} not found. Skipping.")
            continue

        Logger.info(f"Phase 1: running {label} checks with {tool_name}...")
        code, out, err = run_command(command, timeout=180)
        text = (out or "") + "\n" + (err or "")
        if code == 0:
            if any(token in text.lower() for token in ["osvdb", "misconfig", "x-powered-by", "outdated"]):
                findings.append(f"{label}: potential hardening issue from {tool_name}")
                Logger.warn(f"{label}: review suggested")
        else:
            Logger.warn(f"{tool_name} returned non-zero.")

    return findings
