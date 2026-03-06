from core.logger import Logger
from core.tool_runner import is_tool_available, run_command


TOOLS = ["subfinder", "assetfinder", "httpx", "naabu", "nuclei", "ffuf", "sqlmap", "dalfox", "nikto", "wapiti"]
MAINTENANCE_COMMANDS = [
    ("nuclei", ["nuclei", "-update-templates"]),
    ("subfinder", ["subfinder", "-up"]),
]


def run_toolchain_health(engine, update_templates=False):
    findings = []
    for tool in TOOLS:
        if is_tool_available(tool):
            findings.append(f"Tool Ready: {tool}")
            code, out, err = run_command([tool, "-version"], timeout=20)
            text = out or err
            if code == 0 and text:
                findings.append(f"Tool Version: {tool} | {text.splitlines()[0]}")
        else:
            findings.append(f"Tool Missing: {tool}")

    if update_templates and is_tool_available("nuclei"):
        Logger.info("Toolchain: updating nuclei templates...")
        code, out, err = run_command(["nuclei", "-update-templates"], timeout=300)
        if code == 0:
            findings.append("Nuclei Templates: updated successfully")
        else:
            findings.append(f"Nuclei Templates: update failed ({err or 'unknown'})")

    return findings


def run_toolchain_maintenance(engine):
    findings = []
    for tool, command in MAINTENANCE_COMMANDS:
        if not is_tool_available(tool):
            findings.append(f"Maintenance Skip: {tool} not found")
            continue
        code, out, err = run_command(command, timeout=300)
        if code == 0:
            short = (out or "ok").splitlines()[0]
            findings.append(f"Maintenance OK: {tool} | {short}")
        else:
            findings.append(f"Maintenance Failed: {tool} | {(err or 'unknown').splitlines()[0] if err else 'unknown'}")
    return findings
