import shodan
from censys.search import CensysHosts
from core.logger import Logger

def run_osint_discovery(engine):
    findings = []
    if not engine.config: return findings
    
    target_domain = engine.target.split("//")[-1].split("/")[0]

    # Shodan Check
    s_key = engine.config.get('shodan', {}).get('api_key')
    if s_key and s_key != "YOUR_SHODAN_API_KEY":
        try:
            api = shodan.Shodan(s_key)
            res = api.search(f"hostname:{target_domain}")
            for host in res['matches']:
                msg = f"Shodan found host: {host['ip_str']} on ports {host['port']}"
                Logger.success(msg)
                findings.append(msg)
        except Exception as e: Logger.error(f"Shodan: {e}")

    return findings