from core.logger import Logger
from core.tool_runner import is_tool_available, run_command


def run_deep_scans(target, wordlist=None):
    findings = []

    if is_tool_available("ffuf") and wordlist:
        Logger.info("Phase 2: running ffuf content discovery...")
        cmd = [
            "ffuf",
            "-u", f"{target}/FUZZ",
            "-w", wordlist,
            "-mc", "200,204,301,302,307,401,403",
            "-s"
        ]
        code, out, err = run_command(cmd, timeout=240)
        if code == 0:
            for line in out.splitlines()[:100]:
                entry = line.strip()
                if entry:
                    findings.append(f"FFUF Hit: {entry}")
        elif err:
            Logger.warn(f"ffuf returned non-zero: {err}")
    elif not wordlist:
        Logger.warn("ffuf skipped. No wordlist configured.")
    else:
        Logger.warn("ffuf not found. Skipping.")

    if is_tool_available("wapiti"):
        Logger.info("Phase 2: running wapiti web vulnerability scan...")
        code, out, err = run_command(["wapiti", "-u", target, "-f", "txt"], timeout=300)
        text = (out or "") + "\n" + (err or "")
        if code == 0 and "vulnerab" in text.lower():
            findings.append("Wapiti: potential web vulnerabilities detected")
            Logger.warn("Wapiti reported possible findings.")
        elif code != 0:
            Logger.warn("wapiti returned non-zero.")
    else:
        Logger.warn("wapiti not found. Skipping.")

    return findings
