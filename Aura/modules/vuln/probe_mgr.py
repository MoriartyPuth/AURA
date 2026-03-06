from core.logger import Logger
from core.tool_runner import is_tool_available, run_command


def run_web_probes(target):
    findings = []
    probes = [
        (
            "dalfox",
            ["dalfox", "url", f"{target}?q=test", "--skip-bav", "--silence"],
            "XSS Probe",
            180
        ),
        (
            "sqlmap",
            ["sqlmap", "-u", f"{target}?id=1", "--batch", "--level", "1", "--risk", "1"],
            "SQLi Probe",
            240
        ),
    ]

    for tool_name, command, label, timeout in probes:
        if not is_tool_available(tool_name):
            Logger.warn(f"{tool_name} not found. Skipping.")
            continue

        Logger.info(f"Phase 1: running {label} with {tool_name}...")
        code, out, err = run_command(command, timeout=timeout)
        text = (out or "") + "\n" + (err or "")
        lowered = text.lower()
        if code == 0 and any(key in lowered for key in ["vulnerable", "found", "injection", "payload"]):
            findings.append(f"{label}: potential issue detected by {tool_name}")
            Logger.critical(f"{label}: potential vulnerability")
        elif code != 0:
            Logger.warn(f"{tool_name} finished with non-zero exit code.")

    return findings
