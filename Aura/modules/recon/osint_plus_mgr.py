import socket

from core.http_utils import build_session
from core.logger import Logger


def _ip_geo(config, ip):
    """IP -> ASN/Org/Country. Uses the ipinfo token if configured (higher rate/accuracy);
    otherwise falls back to ip-api.com, which is free and needs NO API key."""
    token = config.get("ipinfo", {}).get("token")
    if token and token != "YOUR_IPINFO_TOKEN":
        try:
            import ipinfo
            details = ipinfo.getHandler(token).getDetails(ip)
            if details:
                return (f"IPInfo: {ip} | ASN/Org: {getattr(details, 'org', '')} "
                        f"| Country: {getattr(details, 'country', '')}")
        except Exception as ex:
            Logger.warn(f"IPInfo enrichment failed, falling back to ip-api: {ex}")

    # Keyless fallback. ip-api.com free tier is HTTP-only; geo data is not sensitive.
    try:
        r = build_session(config).get(
            f"http://ip-api.com/json/{ip}?fields=status,country,isp,org,as", timeout=10)
        data = r.json()
        if data.get("status") == "success":
            org = data.get("org") or data.get("isp") or ""
            return f"IP Geo (ip-api): {ip} | ASN/Org: {data.get('as', '')} {org} | Country: {data.get('country', '')}".strip()
    except Exception as ex:
        Logger.warn(f"IP geo lookup (ip-api) failed: {ex}")
    return None


def run_osint_plus(engine):
    findings = []
    domain = engine.domain
    config = engine.config

    # python-whois
    try:
        import whois
        data = whois.whois(domain)
        registrar = data.registrar if hasattr(data, "registrar") else None
        if registrar:
            findings.append(f"WHOIS Registrar: {registrar}")
    except Exception as ex:
        Logger.warn(f"WHOIS lookup skipped/failed: {ex}")

    # dnspython
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        for record_type in ["A", "MX", "NS", "TXT"]:
            try:
                answers = resolver.resolve(domain, record_type)
                for ans in list(answers)[:5]:
                    findings.append(f"DNS {record_type}: {str(ans)}")
            except Exception:
                continue
    except Exception as ex:
        Logger.warn(f"DNS enumeration skipped/failed: {ex}")

    # waybackpy
    try:
        from waybackpy import WaybackMachineCDXServerAPI
        cdx = WaybackMachineCDXServerAPI(engine.target, "Aura-Scanner/1.0")
        snapshot = cdx.newest()
        if snapshot:
            findings.append(f"Wayback Latest: {snapshot.archive_url}")
    except Exception as ex:
        Logger.warn(f"Wayback lookup skipped/failed: {ex}")

    # googlesearch-python
    dorks = config.get("recon", {}).get("google_dorks", ["site:{domain} inurl:admin"])
    try:
        from googlesearch import search
        for dork in dorks[:3]:
            query = dork.format(domain=domain)
            for result in search(query, num_results=3):
                findings.append(f"Google Dork Hit: {query} -> {result}")
    except Exception as ex:
        Logger.warn(f"Google dorking skipped/failed: {ex}")

    # IP geolocation / ASN — keyless via ip-api.com (ipinfo token optional).
    try:
        geo = _ip_geo(config, socket.gethostbyname(domain))
        if geo:
            findings.append(geo)
    except Exception as ex:
        Logger.warn(f"IP geo enrichment skipped/failed: {ex}")

    return findings
