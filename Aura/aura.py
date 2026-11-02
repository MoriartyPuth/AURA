import argparse
import os
import sys
import threading

from colorama import Fore, Style
from core.logger import Logger
from core.engine import AuraEngine
from modules.recon.osint_mgr import run_osint_discovery
from modules.recon.webintel_mgr import run_web_intel
from modules.recon.osint_plus_mgr import run_osint_plus
from modules.recon.crawler_mgr import run_crawler_pipeline
from modules.recon.subdomain_mgr import run_subdomain_enum
from modules.recon.urlintel_mgr import run_url_intel
from modules.recon.surface_mgr import run_surface_discovery
from modules.recon.service_mgr import run_service_enrichment
from modules.recon.param_mining_mgr import run_param_mining
from modules.auth.id_logic import check_identity_leaks
from modules.auth.jwt_mgr import analyze_jwt_exposure
from modules.auth.authz_mgr import run_authz_checks
from modules.cloud.cloud_mgr import run_cloud_checks
from modules.vuln.probe_mgr import run_web_probes
from modules.vuln.classics_mgr import run_classic_vuln_scans
from modules.vuln.fuzz_mgr import run_payload_mutation_fuzz
from modules.vuln.misconfig_mgr import run_misconfig_checks
from modules.vuln.takeover_mgr import run_takeover_checks
from modules.vuln.toolchain_mgr import run_toolchain_health, run_toolchain_maintenance
from modules.vuln.nuclei_mgr import run_nuclei
from modules.vuln.cve_mgr import run_cve_scan
from modules.vuln.deep_scan_mgr import run_deep_scans
from modules.vuln.js_deobf_mgr import run_js_deobfuscation_checks
from utils.report_gen import generate_pdf_report
from utils.risk_normalizer import build_risk_table
from utils.quality_gate import apply_quality_gate
from utils.finding_filters import apply_finding_filters
from utils.exporters import export_json, export_csv, export_sarif
from utils.state_store import load_state, save_state, mark_task_completed, is_task_completed, get_task_result
from utils.checklist_gen import generate_checklists
from utils.url_seeds import load_url_seeds
from core.findings import coerce_list
from core.http_utils import tool_footprint

def print_banner():
    """Renders the custom AURA block-style logo."""
    # Using the specific requested ASCII pattern
    banner = f"""
{Fore.CYAN}  ▄▄▄       █    ██  ██▀███   ▄▄▄      
{Fore.CYAN} ▒████▄     ██   ▓██▒▓██ ▒ ██▒▒████▄    
{Fore.BLUE} ▒██  ▀█▄  ▓██   ▒██░▓██ ░▄█ ▒▒██  ▀█▄  
{Fore.BLUE} ░██▄▄▄▄██ ▓▓█   ░██░▒██▀▀█▄  ░██▄▄▄▄██ 
{Fore.CYAN}  ▓█   ▓██▒▒▒█████▓ ░██▓ ▒██▒ ▓█   ▓██▒
{Fore.CYAN}  ▒▒   ▓▒█░░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░
{Fore.CYAN}   ▒   ▒▒ ░░░▒░ ░ ░   ░▒ ░ ▒░  ▒   ▒▒ ░
{Fore.CYAN}   ░   ▒     ░░░ ░ ░   ░░   ░   ░   ▒   
{Fore.CYAN}       ░  ░    ░        ░           ░  ░

{Fore.WHITE}{Style.BRIGHT} [ AURA-SCANNER v1.0 ] - {Fore.CYAN}National Infrastructure Auditor
{Fore.WHITE}{Style.DIM} Author: Bubble
{Fore.BLUE} ──────────────────────────────────────────────────────────
    """
    print(banner)


def run_group_with_progress(group_name, tasks, state, state_file, resume=False, workers=1):
    """Run a phase's tasks, checkpointing each. With workers>1 the tasks run
    concurrently in a thread pool (they are independent I/O-bound collectors);
    results keep the original task order regardless of completion order."""
    results = {}
    state_lock = threading.Lock()

    def _run_task(label, fn):
        if resume and is_task_completed(state, group_name, label):
            Logger.warn(f"{group_name}: reusing checkpointed result -> {label}")
            return coerce_list(get_task_result(state, group_name, label), source=label, phase=group_name)
        try:
            output = fn()
        except Exception as ex:
            Logger.error(f"{label} failed: {ex}")
            output = []
        findings = coerce_list(output, source=label, phase=group_name)
        with state_lock:  # state dict + file write are shared across worker threads
            mark_task_completed(state, group_name, label, findings)
            save_state(state_file, state)
        return findings

    try:
        from alive_progress import alive_bar
    except ImportError:
        alive_bar = None

    def _advance(bar):
        if bar:
            bar()

    def _run(bar=None):
        if workers and workers > 1 and len(tasks) > 1:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            Logger.info(f"{group_name}: running {len(tasks)} tasks with {workers} workers.")
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(_run_task, label, fn): label for label, fn in tasks}
                for future in as_completed(futures):
                    results[futures[future]] = future.result()
                    _advance(bar)
        else:
            for label, fn in tasks:
                results[label] = _run_task(label, fn)
                _advance(bar)
        # Restore original task order for stable, readable reports.
        return {label: results[label] for label, _ in tasks}

    if alive_bar is None:
        return _run()
    with alive_bar(len(tasks), title=group_name, force_tty=True) as bar:
        return _run(bar)


def main():
    # CLI flags left unset (None) fall back to config.yaml, then to built-in defaults.
    parser = argparse.ArgumentParser(description="Aura-Scanner: Professional Security Auditor")
    parser.add_argument("-t", "--target", required=True, help="Target URL (e.g. https://example.com)")
    parser.add_argument("-o", "--output", default="reports/audit_report.pdf", help="Output PDF path")
    parser.add_argument("--include-domain", action="append", default=[], help="Additional in-scope domain (repeatable)")
    parser.add_argument("--exclude-domain", action="append", default=[], help="Out-of-scope domain (repeatable)")
    parser.add_argument("--scope-regex", default=None, help="Regex that URLs must match to stay in scope")
    parser.add_argument("--state-file", default=None, help="State file path for checkpoints")
    parser.add_argument("--resume", action="store_true", default=None, help="Resume from checkpoint state file")
    parser.add_argument("--export-formats", default=None, help="Comma-separated: json,csv,sarif")
    parser.add_argument("--update-toolchain", action="store_true", default=None, help="Update nuclei templates during the toolchain health check")
    parser.add_argument("--min-confidence", default=None, choices=["low", "medium", "high"], help="Quality gate threshold")
    parser.add_argument("--profile", default=None, help="Scan profile: quick|normal|deep")
    parser.add_argument("--maintenance", action="store_true", default=None, help="Run toolchain maintenance update tasks before scanning")
    parser.add_argument("--maintenance-only", action="store_true", help="Run maintenance and exit")
    parser.add_argument("--proxy", default=None, help="Route Python + external-tool traffic through this proxy (e.g. http://127.0.0.1:8080)")
    args = parser.parse_args()

    os.makedirs("reports", exist_ok=True)
    print_banner()

    target = args.target.rstrip("/")
    engine = AuraEngine(
        target,
        include_domains=args.include_domain,
        exclude_domains=args.exclude_domain,
        scope_regex=args.scope_regex,
    )
    cfg = engine.config
    if args.proxy is not None:
        cfg.setdefault("settings", {})["proxy"] = args.proxy
    if not engine.scope.is_in_scope(target):
        Logger.error(f"Target {target} is outside the configured scope (include/exclude/regex). Aborting.")
        sys.exit(2)

    def setting(cli_value, section, key, default):
        return cli_value if cli_value is not None else cfg.get(section, {}).get(key, default)

    state_file = setting(args.state_file, "state", "file", "reports/scan_state.json")
    resume = bool(setting(args.resume, "state", "resume", False))
    export_formats = setting(args.export_formats, "exports", "formats", "json,csv,sarif")
    min_confidence = setting(args.min_confidence, "quality", "min_confidence", "medium")
    profile_name = setting(args.profile, "scan", "profile", "normal")
    update_toolchain = bool(setting(args.update_toolchain, "tools", "update_templates", False))
    maintenance = bool(setting(args.maintenance, "tools", "auto_maintenance", False))

    state = load_state(state_file) if resume else {}
    profiles = cfg.get("profiles", {})
    if profile_name not in profiles:
        Logger.warn(f"Unknown profile '{profile_name}', falling back to 'normal'.")
    profile_cfg = profiles.get(profile_name, profiles.get("normal", {}))
    crawler_max_pages = int(profile_cfg.get("crawler_max_pages", cfg.get("recon", {}).get("crawler_max_pages", 25)))
    nuclei_severity = profile_cfg.get("nuclei_severity", "high,critical")
    wordlist = profile_cfg.get("ffuf_wordlist") or cfg.get("tools", {}).get("ffuf_wordlist")

    if maintenance or args.maintenance_only:
        Logger.info("Maintenance: running toolchain updates...")
        for line in run_toolchain_maintenance(engine):
            Logger.info(line)
        if args.maintenance_only:
            return

    # Phase 0 is independent I/O-bound recon -> safe to parallelize. Phases 1 and 2
    # drive heavy external scanners (sqlmap, nuclei, ...) and stay serial by default.
    phase0_workers = int(cfg.get("settings", {}).get("phase0_workers", 3))

    def run_group(name, tasks, workers=1):
        return run_group_with_progress(name, tasks, state, state_file, resume=resume, workers=workers)

    # --- PHASE 0: RECON ---
    Logger.info("Phase 0: Reconnaissance & attack surface discovery...")
    phase0_tasks = [
        ("OSINT Discovery", lambda: run_osint_discovery(engine)),
        ("Web Interrogation", lambda: run_web_intel(engine)),
        ("OSINT Plus", lambda: run_osint_plus(engine)),
        ("Subdomain Enumeration", lambda: run_subdomain_enum(engine)),
        ("URL Intelligence", lambda: run_url_intel(engine)),
        ("Surface Discovery", lambda: run_surface_discovery(engine)),
        ("Service Enrichment", lambda: run_service_enrichment(engine)),
        ("Parameter Mining", lambda: run_param_mining(engine)),
        ("Cloud & Infra Checks", lambda: run_cloud_checks(engine)),
    ]
    if profile_cfg.get("enable_crawler", True):
        phase0_tasks.insert(5, ("Crawler & JS Endpoints", lambda: run_crawler_pipeline(engine, max_pages=crawler_max_pages)))
    if profile_cfg.get("enable_toolchain_health", True):
        phase0_tasks.append(("Toolchain Health", lambda: run_toolchain_health(engine, update_templates=update_toolchain)))
    phase0 = run_group("Phase 0", phase0_tasks, workers=phase0_workers)

    # --- PHASE 1: IDENTITY AUDIT ---
    Logger.info(f"Phase 1: Auditing Identity & Logic for {target}...")
    phase1 = run_group("Phase 1", [
        ("Identity Leak Checks", lambda: check_identity_leaks(engine)),
        ("JWT Analysis", lambda: analyze_jwt_exposure(engine)),
        ("Subdomain Takeover Checks", lambda: run_takeover_checks(engine)),
        ("Web Vulnerability Probes", lambda: run_web_probes(engine)),
        ("Misconfiguration Checks", lambda: run_misconfig_checks(target)),
        ("Classic Vuln Classes", lambda: run_classic_vuln_scans(engine)),
        ("Authorization (IDOR/BOLA) Checks", lambda: run_authz_checks(engine)),
    ])

    # --- PHASE 2: DEEP SCAN ---
    Logger.info("Phase 2: Launching deep vulnerability scans...")
    phase2_tasks = [
        ("Nuclei Findings", lambda: run_nuclei(target, severity=nuclei_severity, rate_limit=tool_footprint(cfg)["rate_limit"], proxy=tool_footprint(cfg)["proxy"])),
        ("JS Deobfuscation Checks", lambda: run_js_deobfuscation_checks(engine)),
    ]
    if profile_cfg.get("enable_cve_scan", True):
        phase2_tasks.append(("CVE Detection", lambda: run_cve_scan(engine, update_templates=update_toolchain)))
    footprint = tool_footprint(cfg)
    if profile_cfg.get("enable_deep_scan", True):
        phase2_tasks.append(("Deep Scanner Findings", lambda: run_deep_scans(target, wordlist=wordlist, rate_limit=footprint["rate_limit"], proxy=footprint["proxy"])))
    if profile_cfg.get("enable_fuzzing", True):
        phase2_tasks.append(("Payload Mutation Fuzzing", lambda: run_payload_mutation_fuzz(engine, load_url_seeds())))
    phase2 = run_group("Phase 2", phase2_tasks)

    phase_map, filter_meta = apply_finding_filters({"Phase 0": phase0, "Phase 1": phase1, "Phase 2": phase2}, cfg)
    Logger.info(f"Finding filters: removed={filter_meta['filtered']}")
    phase_map, quality_meta = apply_quality_gate(phase_map, min_confidence=min_confidence)
    Logger.info(f"Quality gate: kept={quality_meta['kept']} dropped={quality_meta['dropped']} threshold={quality_meta['min_confidence']}")
    risk_table = build_risk_table(phase_map)

    # --- PHASE 3: REPORTING ---
    Logger.info("Phase 3: Compiling Final Audit Report (PDF)...")
    try:
        generate_pdf_report(target, phase_map["Phase 0"], phase_map["Phase 1"], phase_map["Phase 2"], risk_table, args.output)
        Logger.success(f"Audit Complete. Final Report generated at: {args.output}")
    except Exception as e:
        Logger.error(f"Report Generation Failed: {e}")

    formats = {x.strip().lower() for x in export_formats.split(",") if x.strip()}
    if "json" in formats:
        export_json("reports/aura_results.json", target, phase_map, risk_table)
    if "csv" in formats:
        export_csv("reports/aura_results.csv", phase_map, risk_table)
    if "sarif" in formats:
        export_sarif("reports/aura_results.sarif", target, risk_table)

    checklist_evidence = {
        "scope-controls": True,
        "crawler-enabled": bool(phase_map["Phase 0"].get("Crawler & JS Endpoints")),
        "vuln-classes": bool(phase_map["Phase 1"].get("Classic Vuln Classes")),
        "payload-fuzzing": bool(phase_map["Phase 2"].get("Payload Mutation Fuzzing")),
        "authz-testing": cfg.get("auth", {}).get("enabled", False),
        "cve-detection": bool(phase_map["Phase 2"].get("CVE Detection")),
        "toolchain-health": True,
        "stateful-scan": bool(state_file),
        "exports": bool(formats),
        "cloud-coverage": True,
        "quality-gate": True,
        "http-hardening": bool(cfg.get("settings", {}).get("verify_tls", True)),
        "tests": True,
        "profiles": bool(profiles),
        "payload-pack": True,
        "maintenance": maintenance,
    }
    generate_checklists("reports/checklist.md", "reports/checklist.json", checklist_evidence)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Audit Interrupted by User.")
        sys.exit(0)
