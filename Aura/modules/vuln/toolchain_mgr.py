from core.logger import Logger
from core.parallel import pmap
from core.tool_runner import is_tool_available, run_command


TOOLS = ["subfinder", "assetfinder", "httpx", "naabu", "nuclei", "ffuf", "sqlmap", "dalfox", "nikto", "wapiti"]
MAINTENANCE_COMMANDS = {
    "nuclei": ["nuclei", "-update-templates"],
    "subfinder": ["subfinder", "-up"],
}


def _first_line(text, default="unknown"):
    return text.splitlines()[0] if text else default


def _run_update(tool):
    if not is_tool_available(tool):
        return f"Maintenance Skip: {tool} not found"
    code, out, err = run_command(MAINTENANCE_COMMANDS[tool], timeout=300)
    if code == 0:
        return f"Maintenance OK: {tool} | {_first_line(out, 'ok')}"
    return f"Maintenance Failed: {tool} | {_first_line(err)}"


def run_toolchain_health(engine, update_templates=False):
    def check(tool):
        if not is_tool_available(tool):
            return [f"Tool Missing: {tool}"]
        out_lines = [f"Tool Ready: {tool}"]
        code, out, err = run_command([tool, "-version"], timeout=20)
        text = out or err
        if code == 0 and text:
            out_lines.append(f"Tool Version: {tool} | {_first_line(text)}")
        return out_lines

    findings = [line for lines in pmap(check, TOOLS, len(TOOLS)) for line in lines]

    if update_templates:
        Logger.info("Toolchain: updating nuclei templates...")
        findings.append(_run_update("nuclei"))
    return findings


def run_toolchain_maintenance(engine):
    return [_run_update(tool) for tool in MAINTENANCE_COMMANDS]
