"""dalfox (XSS) and sqlmap (SQLi) probes.

Findings come from the tools' structured result files, not from grepping their
console output (which contains words like "payload" on every run)."""
import glob
import json
import os
import re
import tempfile
from urllib.parse import urlparse

from core.logger import Logger
from core.http_utils import tool_footprint
from core.tool_runner import is_tool_available, run_command
from utils.url_seeds import load_url_seeds

_DALFOX_LINE_RE = re.compile(r"\[POC\]\[(?P<type>[VRG])\]\[(?P<method>\w+)\]\[(?P<inject>[^\]]*)\]\s+(?P<url>\S+)")
_SQLMAP_PARAM_RE = re.compile(r"^Parameter:\s*(?P<param>.+)$", re.MULTILINE)
_SQLMAP_TYPE_RE = re.compile(r"^\s+Type:\s*(?P<type>.+)$", re.MULTILINE)


def select_probe_urls(engine, fallback_query, max_urls):
    """Prefer real parameterised URLs found during recon; fall back to a synthetic one."""
    seen_shapes, picked = set(), []
    for url in load_url_seeds():
        parsed = urlparse(url)
        if not parsed.query or not engine.scope.is_in_scope(url):
            continue
        shape = (parsed.netloc, parsed.path)  # one URL per endpoint
        if shape in seen_shapes:
            continue
        seen_shapes.add(shape)
        picked.append(url)
        if len(picked) >= max_urls:
            break
    return picked or [f"{engine.target}/?{fallback_query}"]


def parse_dalfox_output(text):
    """Return [(type, param_or_inject, url)] from dalfox JSON / JSONL / plain POC output."""
    results = []
    text = (text or "").strip()
    if not text:
        return results
    records = None
    try:
        data = json.loads(text)
        records = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        try:
            records = [json.loads(line) for line in text.splitlines() if line.strip().startswith("{")]
        except json.JSONDecodeError:
            records = None
    if records:
        for r in records:
            if isinstance(r, dict) and r.get("type"):
                results.append((r["type"], r.get("param") or r.get("inject_type", ""), r.get("data", "")))
        return results
    for m in _DALFOX_LINE_RE.finditer(text):
        results.append((m.group("type"), m.group("inject"), m.group("url")))
    return results


def parse_sqlmap_log(text):
    """Return [(parameter, [technique, ...])] from a sqlmap output-dir `log` file."""
    results = []
    blocks = _SQLMAP_PARAM_RE.split(text or "")
    # split() yields [prefix, param1, body1, param2, body2, ...]
    for i in range(1, len(blocks) - 1, 2):
        techniques = [t.strip() for t in _SQLMAP_TYPE_RE.findall(blocks[i + 1])]
        results.append((blocks[i].strip(), techniques))
    return results


def _run_dalfox(url, footprint):
    findings = []
    with tempfile.TemporaryDirectory(prefix="aura-dalfox-") as tmp:
        out_file = os.path.join(tmp, "dalfox.json")
        cmd = ["dalfox", "url", url, "--skip-bav", "--silence", "--no-color", "--format", "json", "-o", out_file]
        if footprint.get("proxy"):
            cmd += ["--proxy", footprint["proxy"]]
        if footprint.get("rate_limit"):
            # dalfox paces by delay (ms) + single worker; derive from the req/s cap.
            cmd += ["--delay", str(int(1000 / footprint["rate_limit"])), "--worker", "1"]
        code, out, _ = run_command(cmd, timeout=300)
        text = open(out_file, encoding="utf-8").read() if os.path.exists(out_file) else out
    if code != 0:
        Logger.warn("dalfox finished with non-zero exit code.")
    seen = set()
    for poc_type, where, poc_url in parse_dalfox_output(text):
        if poc_type not in {"V", "R"} or (poc_type, where) in seen:
            continue  # "G" (grep) entries are pattern matches, not XSS
        seen.add((poc_type, where))
        if poc_type == "V":
            findings.append(f"XSS confirmed by dalfox (DOM-verified): {where} -> {poc_url}")
        else:
            findings.append(f"XSS reflected payload (dalfox, unverified): {where} -> {poc_url}")
    return findings


def _run_sqlmap(url, footprint):
    findings = []
    with tempfile.TemporaryDirectory(prefix="aura-sqlmap-") as tmp:
        cmd = ["sqlmap", "-u", url, "--batch", "--level", "1", "--risk", "1", "--output-dir", tmp, "--disable-coloring"]
        if footprint.get("proxy"):
            cmd += ["--proxy", footprint["proxy"]]
        if footprint.get("rate_limit"):
            cmd += ["--delay", str(round(1 / footprint["rate_limit"], 2))]  # seconds between requests
        code, _, _ = run_command(cmd, timeout=600)
        logs = glob.glob(os.path.join(tmp, "*", "log"))
        text = "\n".join(open(p, encoding="utf-8", errors="replace").read() for p in logs)
    if code != 0:
        Logger.warn("sqlmap finished with non-zero exit code.")
    for param, techniques in parse_sqlmap_log(text):
        findings.append(f"SQLi confirmed by sqlmap: {param} at {url} [{'; '.join(techniques)}]")
    return findings


def run_web_probes(engine):
    findings = []
    max_urls = int(engine.config.get("tuning", {}).get("probes", {}).get("max_urls", 3))
    footprint = tool_footprint(engine.config)
    probes = [
        ("dalfox", "XSS", "q=test", _run_dalfox),
        ("sqlmap", "SQLi", "id=1", _run_sqlmap),
    ]
    for tool_name, label, fallback_query, runner in probes:
        if not is_tool_available(tool_name):
            Logger.warn(f"{tool_name} not found. Skipping.")
            continue
        for url in select_probe_urls(engine, fallback_query, max_urls):
            Logger.info(f"Phase 1: {label} probe with {tool_name} -> {url}")
            for finding in runner(url, footprint):
                Logger.critical(finding)
                findings.append(finding)
    return findings
