from core.logger import Logger
from core.tool_runner import is_tool_available, run_command


def run_subdomain_enum(engine):
    findings = []
    domain = engine.domain
    seen = set()

    tools = [
        ("subfinder", ["subfinder", "-silent", "-d", domain]),
        ("assetfinder", ["assetfinder", "--subs-only", domain]),
    ]

    for tool_name, cmd in tools:
        if not is_tool_available(tool_name):
            Logger.warn(f"{tool_name} not found. Skipping.")
            continue

        Logger.info(f"Recon: {tool_name} subdomain enumeration...")
        code, out, err = run_command(cmd, timeout=120)
        if code != 0 and err:
            Logger.warn(f"{tool_name} returned non-zero: {err}")
            continue

        for line in out.splitlines():
            candidate = line.strip().lower()
            if not candidate or candidate in seen:
                continue
            if domain in candidate:
                seen.add(candidate)
                findings.append(f"Subdomain: {candidate}")

    Logger.success(f"Recon: discovered {len(findings)} unique subdomains.")
    return findings
