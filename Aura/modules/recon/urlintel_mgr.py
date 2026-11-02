import os

from core.logger import Logger
from core.tool_runner import is_tool_available, run_command

URL_SEED_FILE = "reports/urls_historical.txt"


def collect_archived_urls(engine):
    """Run gau/waybackurls once per scan; shared by URL intel and parameter mining."""
    return engine.cached("archived_urls", lambda: _run_url_tools(engine.domain))


def _run_url_tools(domain):
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
        seen.update(u.strip() for u in out.splitlines() if u.strip())
    return sorted(seen)


def run_url_intel(engine):
    urls = collect_archived_urls(engine)
    in_scope = [u for u in urls if engine.scope.is_in_scope(u)]
    # Persist so the Phase 2 fuzzer can use these as seeds (also survives --resume).
    os.makedirs("reports", exist_ok=True)
    with open(URL_SEED_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(in_scope) + ("\n" if in_scope else ""))
    findings = [f"Historical URL: {u}" for u in in_scope[:200]]
    Logger.success(f"Recon: collected {len(in_scope)} URLs ({len(findings)} reported).")
    return findings
