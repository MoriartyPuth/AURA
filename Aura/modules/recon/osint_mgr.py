import shodan
from ratelimit import limits, sleep_and_retry

from core.http_utils import build_session
from core.logger import Logger


@sleep_and_retry
@limits(calls=4, period=1)
def _limited_get(session, url, timeout):
    return session.get(url, timeout=timeout)


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

    # SHODAN
    key = engine.config.get("shodan", {}).get("api_key")
    if key and key != "YOUR_SHODAN_API_KEY":
        try:
            res = shodan.Shodan(key).search(f"hostname:{domain}")
            for host in res["matches"]:
                msg = f"Shodan IP: {host['ip_str']} | Port: {host['port']}"
                Logger.success(msg)
                findings.append(msg)
        except Exception as e:
            Logger.error(f"Shodan: {e}")
    return findings
