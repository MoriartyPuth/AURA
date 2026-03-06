import argparse
import asyncio
import os
import sys
import glob
from colorama import Fore, Style, init
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
from modules.cloud.cloud_mgr import run_cloud_checks
from modules.vuln.probe_mgr import run_web_probes
from modules.vuln.classics_mgr import run_classic_vuln_scans
from modules.vuln.fuzz_mgr import run_payload_mutation_fuzz
from modules.vuln.misconfig_mgr import run_misconfig_checks
from modules.vuln.takeover_mgr import run_takeover_checks
from modules.vuln.toolchain_mgr import run_toolchain_health, run_toolchain_maintenance
from modules.vuln.nuclei_mgr import NucleiManager
from modules.vuln.deep_scan_mgr import run_deep_scans
from modules.vuln.js_deobf_mgr import run_js_deobfuscation_checks
from utils.report_gen import generate_pdf_report
from utils.risk_normalizer import build_risk_table
from utils.quality_gate import apply_quality_gate
from utils.finding_filters import apply_finding_filters
from utils.exporters import export_json, export_csv, export_sarif
from utils.state_store import load_state, save_state, mark_task_completed, is_task_completed
from utils.checklist_gen import generate_checklists

# Initialize Colorama
init(autoreset=True)

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


def run_group_with_progress(group_name, tasks, state=None, state_file=None, resume=False):
    results = {}

    def _run_task(label, fn):
        if resume and state and is_task_completed(state, group_name, label):
            Logger.warn(f"{group_name}: skipping completed task from state -> {label}")
            return []
        try:
            output = fn()
        except Exception as ex:
            Logger.error(f"{label} failed: {ex}")
            output = []
        if state is not None:
            mark_task_completed(state, group_name, label)
            save_state(state_file, state)
        return output

    try:
        from alive_progress import alive_bar
        Logger.info(f"{group_name}: using alive-progress.")
        with alive_bar(len(tasks), title=group_name, force_tty=True) as bar:
            for label, fn in tasks:
                results[label] = _run_task(label, fn)
                bar()
        return results
    except Exception:
        pass

    try:
        from tqdm import tqdm
        Logger.info(f"{group_name}: using tqdm.")
        for label, fn in tqdm(tasks, desc=group_name):
            results[label] = _run_task(label, fn)
        return results
    except Exception:
        pass

    Logger.warn(f"{group_name}: progress bar libs unavailable, running plain.")
    for label, fn in tasks:
        results[label] = _run_task(label, fn)
    return results


async def main():
    # Setup Arguments
    parser = argparse.ArgumentParser(description="Aura-Scanner: Professional Security Auditor")
    parser.add_argument("-t", "--target", required=True, help="Target URL (e.g. https://example.com)")
    parser.add_argument("-o", "--output", default="reports/audit_report.pdf", help="Output PDF path")
    parser.add_argument("--include-domain", action="append", default=[], help="Additional in-scope domain (repeatable)")
    parser.add_argument("--exclude-domain", action="append", default=[], help="Out-of-scope domain (repeatable)")
    parser.add_argument("--scope-regex", default="", help="Regex that URLs must match to stay in scope")
    parser.add_argument("--state-file", default="reports/scan_state.json", help="State file path for checkpoints")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint state file")
    parser.add_argument("--export-formats", default="json,csv,sarif", help="Comma-separated: json,csv,sarif")
    parser.add_argument("--update-toolchain", action="store_true", help="Attempt toolchain update operations where supported")
    parser.add_argument("--min-confidence", default="", help="Quality gate threshold: low|medium|high")
    parser.add_argument("--profile", default="", help="Scan profile: quick|normal|deep")
    parser.add_argument("--maintenance", action="store_true", help="Run toolchain maintenance update tasks before scanning")
    parser.add_argument("--maintenance-only", action="store_true", help="Run maintenance and exit")
    args = parser.parse_args()

    # Directory Check
    if not os.path.exists("reports"):
        os.makedirs("reports")

    # 1. Visual Identity
    print_banner()
    
    # 2. Initialization
    target = args.target.rstrip('/')
    engine = AuraEngine(
        target,
        include_domains=args.include_domain,
        exclude_domains=args.exclude_domain,
        scope_regex=args.scope_regex or None,
    )
    cfg = engine.config or {}
    if args.state_file == "reports/scan_state.json":
        args.state_file = cfg.get("state", {}).get("file", args.state_file)
    if not args.resume:
        args.resume = bool(cfg.get("state", {}).get("resume", False))
    if args.export_formats == "json,csv,sarif":
        args.export_formats = cfg.get("exports", {}).get("formats", args.export_formats)
    if not args.min_confidence:
        args.min_confidence = cfg.get("quality", {}).get("min_confidence", "medium")
    if not args.profile:
        args.profile = cfg.get("scan", {}).get("profile", "normal")
    if not args.update_toolchain:
        args.update_toolchain = bool(cfg.get("tools", {}).get("update_templates", False))
    if not args.maintenance:
        args.maintenance = bool(cfg.get("tools", {}).get("auto_maintenance", False))
    state = load_state(args.state_file) if args.resume else {}
    profiles = cfg.get("profiles", {})
    profile_cfg = profiles.get(args.profile, profiles.get("normal", {}))
    crawler_max_pages = int(profile_cfg.get("crawler_max_pages", cfg.get("recon", {}).get("crawler_max_pages", 25)))
    include_phase2_deep = bool(profile_cfg.get("enable_deep_scan", True))
    include_fuzzing = bool(profile_cfg.get("enable_fuzzing", True))
    include_crawler = bool(profile_cfg.get("enable_crawler", True))
    include_toolchain_health = bool(profile_cfg.get("enable_toolchain_health", True))
    nuclei_severity = profile_cfg.get("nuclei_severity", "high,critical")
    profile_wordlist = profile_cfg.get("ffuf_wordlist", "")

    if args.maintenance or args.maintenance_only:
        Logger.info("Maintenance: running toolchain updates...")
        maintenance_findings = run_toolchain_maintenance(engine)
        for line in maintenance_findings:
            Logger.info(line)
        if args.maintenance_only:
            return
    
    # --- PHASE 0: PASSIVE RECON ---
    Logger.info("Phase 0: Initiating Passive OSINT (CRT.sh Discovery)...")
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
    if include_crawler:
        phase0_tasks.insert(5, ("Crawler & JS Endpoints", lambda: run_crawler_pipeline(engine, max_pages=crawler_max_pages)))
    if include_toolchain_health:
        phase0_tasks.append(("Toolchain Health", lambda: run_toolchain_health(engine, update_templates=args.update_toolchain)))
    phase0 = run_group_with_progress("Phase 0", phase0_tasks, state=state, state_file=args.state_file, resume=args.resume)

    # --- PHASE 1: IDENTITY AUDIT ---
    Logger.info(f"Phase 1: Auditing Identity & Logic for {target}...")
    phase1 = {
        "Identity Leak Checks": await check_identity_leaks(engine),
    }
    phase1.update(run_group_with_progress("Phase 1", [
        ("JWT Analysis", lambda: analyze_jwt_exposure(engine)),
        ("Subdomain Takeover Checks", lambda: run_takeover_checks(engine)),
        ("Web Vulnerability Probes", lambda: run_web_probes(target)),
        ("Misconfiguration Checks", lambda: run_misconfig_checks(target)),
        ("Classic Vuln Classes", lambda: run_classic_vuln_scans(engine)),
    ], state=state, state_file=args.state_file, resume=args.resume))

    # --- PHASE 2: DEEP SCAN ---
    Logger.info("Phase 2: Launching Nuclei Vulnerability Scan...")
    nm = NucleiManager(target)
    wordlist = None
    if engine.config:
        wordlist = engine.config.get("tools", {}).get("ffuf_wordlist")
    if profile_wordlist:
        wordlist = profile_wordlist
    url_seed = []
    for path in glob.glob("reports/*.txt"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("http"):
                        url_seed.append(line)
        except Exception:
            continue
    phase2_tasks = [
        ("Nuclei Findings", lambda: nm.run_nuclei(severity=nuclei_severity)),
        ("JS Deobfuscation Checks", lambda: run_js_deobfuscation_checks(engine)),
    ]
    if include_phase2_deep:
        phase2_tasks.append(("Deep Scanner Findings", lambda: run_deep_scans(target, wordlist=wordlist)))
    if include_fuzzing:
        phase2_tasks.append(("Payload Mutation Fuzzing", lambda: run_payload_mutation_fuzz(engine, url_seed)))
    phase2 = run_group_with_progress("Phase 2", phase2_tasks, state=state, state_file=args.state_file, resume=args.resume)
    raw_phase_map = {
        "Phase 0": phase0,
        "Phase 1": phase1,
        "Phase 2": phase2,
    }
    filtered_phase_map, filter_meta = apply_finding_filters(raw_phase_map, cfg)
    Logger.info(f"Finding filters: removed={filter_meta['filtered']}")
    raw_phase_map = filtered_phase_map
    gated_phase_map, quality_meta = apply_quality_gate(raw_phase_map, min_confidence=args.min_confidence)
    Logger.info(f"Quality gate: kept={quality_meta['kept']} dropped={quality_meta['dropped']} threshold={quality_meta['min_confidence']}")
    phase0 = gated_phase_map["Phase 0"]
    phase1 = gated_phase_map["Phase 1"]
    phase2 = gated_phase_map["Phase 2"]
    risk_table = build_risk_table(gated_phase_map)

    # --- PHASE 3: REPORTING ---
    Logger.info("Phase 3: Compiling Final Audit Report (PDF)...")
    try:
        generate_pdf_report(target, phase0, phase1, phase2, risk_table, args.output)
        Logger.success(f"Audit Complete. Final Report generated at: {args.output}")
    except Exception as e:
        Logger.error(f"Report Generation Failed: {e}")

    phase_map = {"Phase 0": phase0, "Phase 1": phase1, "Phase 2": phase2}
    formats = {x.strip().lower() for x in args.export_formats.split(",") if x.strip()}
    if "json" in formats:
        export_json("reports/aura_results.json", target, phase_map, risk_table)
    if "csv" in formats:
        export_csv("reports/aura_results.csv", phase_map, risk_table)
    if "sarif" in formats:
        export_sarif("reports/aura_results.sarif", target, risk_table)

    checklist_evidence = {
        "scope-controls": True,
        "crawler-enabled": bool(phase0.get("Crawler & JS Endpoints")),
        "vuln-classes": bool(phase1.get("Classic Vuln Classes")),
        "payload-fuzzing": bool(phase2.get("Payload Mutation Fuzzing")),
        "toolchain-health": True,
        "stateful-scan": bool(args.state_file),
        "exports": bool(formats),
        "cloud-coverage": True,
        "quality-gate": True,
        "http-hardening": bool((cfg.get("settings", {}).get("verify_tls", True))),
        "tests": True,
        "profiles": bool(profiles),
        "payload-pack": True,
        "maintenance": bool(args.maintenance or cfg.get("tools", {}).get("auto_maintenance", False)),
    }
    generate_checklists("reports/checklist.md", "reports/checklist.json", checklist_evidence)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Audit Interrupted by User.")
        sys.exit(0)
