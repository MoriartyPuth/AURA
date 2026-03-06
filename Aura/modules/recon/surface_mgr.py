from core.logger import Logger
from core.tool_runner import is_tool_available, run_command


def run_surface_discovery(engine):
    findings = []
    domain = engine.domain

    if is_tool_available("naabu"):
        Logger.info("Recon: running naabu port discovery...")
        code, out, err = run_command(["naabu", "-silent", "-host", domain], timeout=120)
        if code == 0:
            for line in out.splitlines():
                port_line = line.strip()
                if port_line:
                    findings.append(f"Open Service: {port_line}")
        elif err:
            Logger.warn(f"naabu returned non-zero: {err}")
    else:
        Logger.warn("naabu not found. Skipping.")

    if is_tool_available("httpx"):
        Logger.info("Recon: validating web services via httpx...")
        code, out, err = run_command(["httpx", "-silent", "-u", engine.target, "-title", "-status-code"], timeout=60)
        if code == 0:
            for line in out.splitlines():
                site_line = line.strip()
                if site_line:
                    findings.append(f"HTTP Surface: {site_line}")
        elif err:
            Logger.warn(f"httpx returned non-zero: {err}")
    else:
        Logger.warn("httpx not found. Skipping.")

    Logger.success(f"Recon: surface findings {len(findings)}.")
    return findings
