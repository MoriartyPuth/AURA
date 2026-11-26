from urllib.parse import urlparse

from core.logger import Logger
from core.tool_runner import is_tool_available, run_command


def target_port(engine):
    """The explicit port in the target URL (e.g. :30139), or None. If the target was
    given with a port, that port is known-open and must always be fingerprinted —
    naabu's top-ports sweep would otherwise miss a high web port like 30139."""
    try:
        port = urlparse(engine.target).port
        return port if port and 0 < port < 65536 else None
    except (ValueError, AttributeError):
        return None


def _naabu_port_args(engine):
    """Port selection for naabu. Default is the top 1000 (naabu's own default is only
    the top 100); override with settings.naabu_ports, e.g. "1-65535" or "80,443,8080"."""
    spec = str((engine.config.get("settings", {}) or {}).get("naabu_ports", "") or "").strip()
    return ["-p", spec] if spec else ["-top-ports", "1000"]


def collect_open_ports(engine):
    """Discover open ports once per scan and share them with service enrichment, so
    nmap -sV only fingerprints known-open ports (RustScan-style) instead of its own
    top-100 sweep. Always includes the target's explicit URL port.

    Returns a sorted list of ints, or None if naabu is unavailable or failed AND the
    target carries no explicit port (callers then fall back to their own selection)."""
    def collect():
        known = {target_port(engine)} - {None}
        if not is_tool_available("naabu"):
            Logger.warn("naabu not found. Skipping port discovery.")
            return sorted(known) if known else None
        Logger.info("Recon: running naabu port discovery...")
        code, out, err = run_command(
            ["naabu", "-silent", "-host", engine.domain, *_naabu_port_args(engine)], timeout=180)
        if code != 0:
            if err:
                Logger.warn(f"naabu returned non-zero: {err}")
            return sorted(known) if known else None
        return sorted(set(parse_naabu_ports(out)) | known)

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
