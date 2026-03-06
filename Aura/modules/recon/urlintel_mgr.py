from core.logger import Logger
from core.tool_runner import is_tool_available, run_command


def run_url_intel(engine):
    findings = []
    domain = engine.domain
    seen = set()

    tools = [
        ("gau", ["gau", "--subs", domain]),
        ("waybackurls", ["waybackurls", domain]),
    ]

    for tool_name, cmd in tools:
        if not is_tool_available(tool_name):
            Logger.warn(f"{tool_name} not found. Skipping.")
            continue

        Logger.info(f"Recon: collecting URLs via {tool_name}...")
        code, out, err = run_command(cmd, timeout=180)
        if code != 0 and err:
            Logger.warn(f"{tool_name} returned non-zero: {err}")
            continue

        for line in out.splitlines():
            url = line.strip()
            if not url or url in seen:
                continue
            seen.add(url)

    for url in sorted(seen)[:200]:
        findings.append(f"Historical URL: {url}")

    Logger.success(f"Recon: collected {len(findings)} URLs.")
    return findings
