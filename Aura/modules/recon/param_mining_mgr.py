from urllib.parse import parse_qs, urlparse
from core.logger import Logger
from core.tool_runner import is_tool_available, run_command


def run_param_mining(engine):
    findings = []
    domain = engine.domain
    params = set()

    if is_tool_available("gau"):
        Logger.info("Recon: mining query parameters from gau output...")
        code, out, err = run_command(["gau", "--subs", domain], timeout=180)
        if code == 0:
            for line in out.splitlines():
                url = line.strip()
                if not url:
                    continue
                parsed = urlparse(url)
                if parsed.query:
                    for key in parse_qs(parsed.query).keys():
                        if key:
                            params.add(key.lower())
        elif err:
            Logger.warn(f"gau returned non-zero during param mining: {err}")
    else:
        Logger.warn("gau not found. Parameter mining from archives skipped.")

    for param in sorted(params):
        findings.append(f"Parameter: {param}")

    if is_tool_available("arjun"):
        Logger.info("Recon: running arjun endpoint parameter discovery...")
        code, out, err = run_command(["arjun", "-u", engine.target, "--stable"], timeout=240)
        text = ((out or "") + "\n" + (err or "")).splitlines()
        if code == 0:
            for line in text:
                entry = line.strip()
                if "param" in entry.lower() and entry:
                    findings.append(f"Arjun: {entry}")
        else:
            Logger.warn("arjun returned non-zero.")
    else:
        Logger.warn("arjun not found. Skipping active parameter discovery.")

    Logger.success(f"Recon: parameter mining produced {len(findings)} entries.")
    return findings
