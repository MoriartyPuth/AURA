import re

import jwt

from core.logger import Logger
from core.http_utils import build_session


JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")


def analyze_jwt_exposure(engine):
    findings = []
    target = engine.target
    session = build_session(engine.config)

    try:
        resp = session.get(target)
    except Exception as ex:
        Logger.warn(f"JWT analysis skipped: {ex}")
        return findings

    token_candidates = set(JWT_RE.findall(resp.text or ""))
    auth_header = resp.headers.get("Authorization", "")
    token_candidates.update(JWT_RE.findall(auth_header))
    for cookie_val in resp.cookies.values():
        token_candidates.update(JWT_RE.findall(cookie_val or ""))

    for token in list(token_candidates)[:10]:
        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            alg = (header.get("alg") or "").lower()
            if alg == "none":
                findings.append("JWT Weakness: alg=none token found")
            findings.append(f"JWT Exposed Claims: {','.join(sorted(payload.keys())[:8])}")
        except Exception:
            findings.append("JWT-like token exposed but decode failed")

    return findings
