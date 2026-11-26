from core.logger import Logger
from core.tool_runner import is_tool_available, run_command


def collect_open_ports(engine):
    """Run naabu once per scan and share the open ports with service enrichment, so
    nmap -sV only fingerprints ports already known to be open (RustScan-style)
    instead of re-scanning its own top-100 list.

    Returns a sorted list of ints, or None if naabu is unavailable or failed
    (callers then fall back to their own port selection)."""
    def collect():
        if not is_tool_available("naabu"):
            Logger.warn("naabu not found. Skipping.")
            return None
        Logger.info("Recon: running naabu port discovery...")
        code, out, err = run_command(["naabu", "-silent", "-host", engine.domain], timeout=120)
        if code != 0:
            if err:
                Logger.warn(f"naabu returned non-zero: {err}")
            return None
        return parse_naabu_ports(out)

    return engine.cached("open_ports", collect)


def parse_naabu_ports(text):
    """naabu -silent prints one `host:port` per line."""
    ports = set()
    for line in (text or "").splitlines():
        _, _, port = line.strip().rpartition(":")
        if port.isdigit() and 0 < int(port) < 65536:
            ports.add(int(port))
    return sorted(ports)


def run_surface_discovery(engine):
    findings = []
    domain = engine.domain

    for port in collect_open_ports(engine) or []:
        findings.append(f"Open Service: {domain}:{port}")

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
