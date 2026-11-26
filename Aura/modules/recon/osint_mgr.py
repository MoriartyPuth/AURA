import socket

from ratelimit import limits, sleep_and_retry

from core.findings import Finding
from core.http_utils import build_session
from core.logger import Logger


@sleep_and_retry
@limits(calls=4, period=1)
def _limited_get(session, url, timeout):
    return session.get(url, timeout=timeout)


def _resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def _query_internetdb(session, ip):
    """Shodan InternetDB: free, no API key. Returns open ports, known CVEs, hostnames
    and tags for an IP (https://internetdb.shodan.io/<ip>). Data is passive/historical,
    so CVEs are reported as medium/low-confidence leads to verify, not confirmed."""
    findings = []
    try:
        r = _limited_get(session, f"https://internetdb.shodan.io/{ip}", timeout=15)
    except Exception as e:
        Logger.warn(f"InternetDB lookup failed: {e}")
        return findings
    if r.status_code == 404:
        return findings  # IP not in Shodan's dataset
    if r.status_code != 200:
        Logger.warn(f"InternetDB returned {r.status_code} for {ip}")
        return findings

    try:
        data = r.json()
    except Exception:
        return findings

    for port in data.get("ports", []):
        findings.append(f"Shodan InternetDB: {ip} open port {port}")
    for host in data.get("hostnames", []):
        findings.append(f"Shodan InternetDB hostname: {host}")
    for tag in data.get("tags", []):
        findings.append(f"Shodan InternetDB tag: {ip} [{tag}]")
    for cve in data.get("vulns", []):
        findings.append(Finding(
            title=f"Known CVE (Shodan InternetDB, passive): {cve} on {ip}",
            severity="medium", confidence="low", verified=False, url=f"https://{ip}",
            evidence="Reported by Shodan's historical dataset; confirm it still affects the live host.",
            references=[f"https://nvd.nist.gov/vuln/detail/{cve}"],
            extra={"cve": cve, "source": "shodan-internetdb"},
        ))
    Logger.success(f"InternetDB: {ip} -> {len(data.get('ports', []))} ports, "
                   f"{len(data.get('vulns', []))} CVEs (passive)")
    return findings


def run_osint_discovery(engine):
    findings = []
    domain = engine.domain
    session = build_session(engine.config)

    # CRT.SH (Passive SSL Logs - No API Key)
    Logger.info(f"Querying CRT.sh for {domain}...")
    try:
        r = _limited_get(session, f"https://crt.sh/?q={domain}&output=json", timeout=20)
        if r.status_code == 200:
            # name_value can hold several newline-separated names per certificate.
            names = {n.strip().lower() for item in r.json() for n in item["name_value"].splitlines()}
            subs = {n for n in names if n and "*" not in n}
            subs = {s for s in subs if engine.scope.is_host_in_scope(s)}
            for s in sorted(subs)[:15]:
                Logger.success(f"Subdomain: {s}")
                findings.append(f"Subdomain Found: {s}")
    except Exception as e:
        Logger.error(f"CRT.sh error: {e}")

    # Shodan InternetDB (no API key): resolve the target to an IP, then pull open
    # ports / known CVEs / hostnames from Shodan's free keyless endpoint.
    ip = _resolve_ip(domain)
    if ip:
        findings.extend(_query_internetdb(session, ip))
    else:
        Logger.warn(f"Could not resolve {domain} for InternetDB lookup.")

    # Optional: Shodan's keyed search API (requires a *paid* membership; the free
    # key cannot search). Left in for users who have one. InternetDB above needs no key.
    key = engine.config.get("shodan", {}).get("api_key")
    if key and key != "YOUR_SHODAN_API_KEY":
        try:
            import shodan
            res = shodan.Shodan(key).search(f"hostname:{domain}")
            for host in res["matches"]:
                msg = f"Shodan IP: {host['ip_str']} | Port: {host['port']}"
                Logger.success(msg)
                findings.append(msg)
        except Exception as e:
            Logger.error(f"Shodan (keyed search): {e}")
    return findings
