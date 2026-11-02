from core.logger import Logger
from core.tool_runner import is_tool_available, run_command


def collect_subdomains(engine):
    """Run subfinder/assetfinder once per scan; shared by enumeration and takeover checks."""
    def collect():
        found = _run_subdomain_tools(engine.domain)
        in_scope = [s for s in found if engine.scope.is_host_in_scope(s)]
        if len(in_scope) < len(found):
            Logger.info(f"Scope: dropped {len(found) - len(in_scope)} out-of-scope subdomains.")
        return in_scope

    return engine.cached("subdomains", collect)


def _run_subdomain_tools(domain):
    subs = set()
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
            if candidate == domain or candidate.endswith(f".{domain}"):
                subs.add(candidate)
    return sorted(subs)


def run_subdomain_enum(engine):
    subdomains = collect_subdomains(engine)
    Logger.success(f"Recon: discovered {len(subdomains)} unique subdomains.")
    return [f"Subdomain: {s}" for s in subdomains]
