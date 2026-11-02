from core.http_utils import build_session
from core.logger import Logger

SENSITIVE_PATHS = [
    "/admin/auth/translation", "/api/v1/config", "/.env", "/config/auth",
    "/api/users/1", "/v1/debug/vars", "/phpinfo.php",
]
LEAK_MARKERS = ["password", "db_pass", "secret_key"]


def check_identity_leaks(engine):
    findings = []
    session = build_session(engine.config)
    for path in SENSITIVE_PATHS:
        url = f"{engine.target}{path}"
        if not engine.scope.is_in_scope(url):
            continue
        try:
            r = session.get(url)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        content = (r.text or "").lower()
        if any(x in content for x in LEAK_MARKERS):
            Logger.critical(f"LEAK: {url}")
            findings.append(f"CRITICAL DATA LEAK: {url}")
        else:
            Logger.success(f"Accessible: {url}")
            findings.append(f"Sensitive Path Found: {url}")
    return findings
