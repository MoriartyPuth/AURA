import argparse
import asyncio
import os
import sys
from colorama import Fore, Style, init
from core.logger import Logger
from core.engine import AuraEngine
from modules.recon.osint_mgr import run_osint_discovery
from modules.auth.id_logic import check_identity_leaks
from modules.vuln.nuclei_mgr import NucleiManager
from utils.report_gen import generate_pdf_report

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

async def main():
    # Setup Arguments
    parser = argparse.ArgumentParser(description="Aura-Scanner: Professional Security Auditor")
    parser.add_argument("-t", "--target", required=True, help="Target URL (e.g. https://example.com)")
    parser.add_argument("-o", "--output", default="reports/audit_report.pdf", help="Output PDF path")
    args = parser.parse_args()

    # Directory Check
    if not os.path.exists("reports"):
        os.makedirs("reports")

    # 1. Visual Identity
    print_banner()
    
    # 2. Initialization
    target = args.target.rstrip('/')
    engine = AuraEngine(target)
    
    # --- PHASE 0: PASSIVE RECON ---
    Logger.info("Phase 0: Initiating Passive OSINT (CRT.sh Discovery)...")
    osint_results = run_osint_discovery(engine)

    # --- PHASE 1: IDENTITY AUDIT ---
    Logger.info(f"Phase 1: Auditing Identity & Logic for {target}...")
    ids_results = await check_identity_leaks(engine)

    # --- PHASE 2: DEEP SCAN ---
    Logger.info("Phase 2: Launching Nuclei Vulnerability Scan...")
    nm = NucleiManager(target)
    nucs_results = nm.run_nuclei()

    # --- PHASE 3: REPORTING ---
    Logger.info("Phase 3: Compiling Final Audit Report (PDF)...")
    try:
        generate_pdf_report(target, osint_results, ids_results, nucs_results, args.output)
        Logger.success(f"Audit Complete. Final Report generated at: {args.output}")
    except Exception as e:
        Logger.error(f"Report Generation Failed: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Audit Interrupted by User.")
        sys.exit(0)