import requests, shodan
from core.logger import Logger

def run_osint_discovery(engine):
    findings = []
    domain = engine.target.split("//")[-1].split("/")[0]

    # CRT.SH (Passive SSL Logs - No API Key)
    Logger.info(f"Querying CRT.sh for {domain}...")
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        r = requests.get(url, timeout=20)
        if r.status_code == 200:
            subs = set(item['name_value'].lower() for item in r.json() if "*" not in item['name_value'])
            for s in sorted(list(subs))[:15]:
                Logger.success(f"Subdomain: {s}")
                findings.append(f"Subdomain Found: {s}")
    except Exception as e: Logger.error(f"CRT.sh error: {e}")

    # SHODAN
    if engine.config:
        key = engine.config.get('shodan', {}).get('api_key')
        if key and key != "YOUR_SHODAN_API_KEY":
            try:
                api = shodan.Shodan(key)
                res = api.search(f"hostname:{domain}")
                for host in res['matches']:
                    msg = f"Shodan IP: {host['ip_str']} | Port: {host['port']}"
                    Logger.success(msg); findings.append(msg)
            except Exception as e: Logger.error(f"Shodan: {e}")
    return findings