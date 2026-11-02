from urllib.parse import parse_qs, urlparse

from core.logger import Logger
from core.tool_runner import is_tool_available, run_command
from modules.recon.urlintel_mgr import collect_archived_urls


def run_param_mining(engine):
    params = set()
    for url in collect_archived_urls(engine):
        query = urlparse(url).query
        if query:
            params.update(k.lower() for k in parse_qs(query) if k)
    findings = [f"Parameter: {p}" for p in sorted(params)]

    if is_tool_available("arjun"):
        Logger.info("Recon: running arjun endpoint parameter discovery...")
        code, out, err = run_command(["arjun", "-u", engine.target, "--stable"], timeout=240)
        if code == 0:
            for line in ((out or "") + "\n" + (err or "")).splitlines():
                entry = line.strip()
                if entry and "param" in entry.lower():
                    findings.append(f"Arjun: {entry}")
        else:
            Logger.warn("arjun returned non-zero.")
    else:
        Logger.warn("arjun not found. Skipping active parameter discovery.")

    Logger.success(f"Recon: parameter mining produced {len(findings)} entries.")
    return findings
