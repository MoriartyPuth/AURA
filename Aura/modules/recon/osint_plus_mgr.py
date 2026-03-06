import socket

from core.logger import Logger


def run_osint_plus(engine):
    findings = []
    domain = engine.domain
    config = engine.config or {}

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

    # ipinfo
    token = config.get("ipinfo", {}).get("token")
    try:
        if token and token != "YOUR_IPINFO_TOKEN":
            import ipinfo
            ip = socket.gethostbyname(domain)
            handler = ipinfo.getHandler(token)
            details = handler.getDetails(ip)
            if details:
                asn = getattr(details, "org", "")
                country = getattr(details, "country", "")
                findings.append(f"IPInfo: {ip} | ASN/Org: {asn} | Country: {country}")
    except Exception as ex:
        Logger.warn(f"IPInfo enrichment skipped/failed: {ex}")

    return findings
