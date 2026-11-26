from core.http_utils import build_session
from core.logger import Logger
from core.parallel import http_workers, pmap
from core.soft404 import get_soft404_detector

SENSITIVE_PATHS = [
    "/admin/auth/translation", "/api/v1/config", "/.env", "/config/auth",
    "/api/users/1", "/v1/debug/vars", "/phpinfo.php",
]
LEAK_MARKERS = ["db_pass", "secret_key", "aws_secret_access_key", "db_password=", "password="]


def check_identity_leaks(engine):
    findings = []
    session = build_session(engine.config)
    soft404 = get_soft404_detector(engine, session)
    paths = [p for p in SENSITIVE_PATHS if engine.scope.is_in_scope(f"{engine.target}{p}")]

    def probe(path):
        try:
            return path, session.get(f"{engine.target}{path}", allow_redirects=False)
        except Exception:
            return path, None

    for path, r in pmap(probe, paths, http_workers(engine.config)):
        url = f"{engine.target}{path}"
        if r is None or r.status_code != 200 or soft404.is_soft404(r, path):
            continue
        content = (r.text or "").lower()
        if any(x in content for x in LEAK_MARKERS):
            Logger.critical(f"LEAK: {url}")
            findings.append(f"CRITICAL DATA LEAK: {url}")
        else:
            Logger.success(f"Accessible: {url}")
            findings.append(f"Sensitive Path Found: {url}")
    return findings
