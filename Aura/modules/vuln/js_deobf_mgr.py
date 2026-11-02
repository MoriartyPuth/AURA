from bs4 import BeautifulSoup

from core.logger import Logger
from core.http_utils import build_session


def run_js_deobfuscation_checks(engine):
    findings = []
    target = engine.target
    session = build_session(engine.config)

    try:
        r = session.get(target)
        soup = BeautifulSoup(r.text, "html.parser")
        inline_scripts = [s.get_text() for s in soup.find_all("script") if s.get_text(strip=True)]
    except Exception as ex:
        Logger.warn(f"JS analysis skipped: {ex}")
        return findings

    suspicious = [s for s in inline_scripts if "eval(" in s or "atob(" in s or "fromCharCode" in s]
    for _ in suspicious:
        findings.append("Obfuscated JS Pattern: eval/atob/fromCharCode detected")

    if suspicious:
        try:
            import execjs
            sample = suspicious[0][:12000]
            wrapper = f"function aura_exec(){{ {sample}; return 'ok'; }}"
            try:
                execjs.compile(wrapper)
                findings.append("JS Deobfuscation: script compiles via ExecJS")
            except Exception:
                findings.append("JS Deobfuscation: suspicious script did not compile safely")
        except Exception as ex:
            Logger.warn(f"ExecJS unavailable/failed: {ex}")

    return findings
