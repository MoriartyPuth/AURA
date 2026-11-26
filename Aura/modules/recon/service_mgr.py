from core.logger import Logger
from core.tool_runner import is_tool_available, run_command
from modules.recon.surface_mgr import collect_open_ports


def run_service_enrichment(engine):
    findings = []
    domain = engine.domain

    # Fingerprint only the ports naabu already found open; fall back to nmap's own
    # top-100 sweep only when naabu is unavailable or failed.
    open_ports = collect_open_ports(engine)
    if open_ports == []:
        Logger.info("Recon: naabu found no open ports; skipping nmap service enrichment.")
        return findings
    port_args = ["-p", ",".join(map(str, open_ports))] if open_ports else ["--top-ports", "100"]

    # Prefer python3-nmap when available, fallback to nmap CLI.
    try:
        import nmap
        scanner = nmap.PortScanner()
        scanner.scan(domain, arguments=" ".join(["-Pn", "-sV", *port_args]))
        host_data = scanner[domain] if domain in scanner.all_hosts() else None
        if host_data and "tcp" in host_data:
            for port, meta in host_data["tcp"].items():
                if meta.get("state") == "open":
                    svc = meta.get("name", "unknown")
                    product = meta.get("product", "")
                    findings.append(f"Service: {port}/tcp open {svc} {product}".strip())
            Logger.success(f"Recon: python3-nmap identified {len(findings)} open services.")
            return findings
    except Exception as ex:
        Logger.warn(f"python3-nmap path failed, falling back to CLI: {ex}")

    if not is_tool_available("nmap"):
        Logger.warn("nmap not found. Skipping service enrichment.")
        return findings

    Logger.info("Recon: running nmap service enrichment...")
    cmd = ["nmap", "-Pn", "-sV", *port_args, domain]
    code, out, err = run_command(cmd, timeout=360)
    if code != 0:
        if err:
            Logger.warn(f"nmap returned non-zero: {err}")
        return findings

    capture = False
    for raw in out.splitlines():
        line = raw.strip()
        if line.lower().startswith("port"):
            capture = True
            continue
        if capture and "/tcp" in line and "open" in line:
            findings.append(f"Service: {line}")

    Logger.success(f"Recon: nmap identified {len(findings)} open services.")
    return findings
