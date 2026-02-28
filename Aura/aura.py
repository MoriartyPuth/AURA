import argparse
import asyncio
import os
import sys
from core.logger import Logger
from core.engine import AuraEngine
from modules.auth.id_logic import check_identity_leaks
from modules.vuln.nuclei_mgr import NucleiManager
from modules.recon.osint_mgr import run_osint_discovery
from utils.report_gen import generate_pdf_report

async def main():
    parser = argparse.ArgumentParser(description="Aura-Scanner: National Infrastructure Auditor")
    parser.add_argument("-t", "--target", help="Target URL (e.g., https://target.gov.kh)", required=True)
    parser.add_argument("-o", "--output", default="reports/audit_report.pdf", help="Output PDF path")
    
    args = parser.parse_args()
    target = args.target.rstrip('/')

    # Professional Banner
    print("\033[36m" + r"""
    ░█▀█░█░█░█▀█░█▀█░░░░█▀▀░█▀▀░█▀█░█▀█░█▀█░█▀▀░█▀▄
    ░█▀█░█░█░█▀▄░█▀█░░░░▀▀█░█░░░█▀█░█░█░█░█░█▀▀░█▀▄
    ░▀░▀░▀▀▀░▀░▀░▀░▀░░░░▀▀▀░▀▀▀░▀░▀░▀░▀░▀░▀░▀▀▀░▀░▀
    V1.0 | Authorized Use Only
    """ + "\033[0m")

    if not os.path.exists("reports"): os.makedirs("reports")

    engine = AuraEngine(target)
    
    # Step 0: OSINT (Passive Recon)
    Logger.info("Step 0: Performing OSINT Discovery...")
    osint_results = run_osint_discovery(engine)

    # Step 1: Identity & Logic Audit (Active Scanning)
    Logger.info(f"Step 1: Initiating Identity Audit for {target}...")
    identity_findings = await check_identity_leaks(engine)

    # Step 2: Nuclei Vulnerability Scan (Deep Inspection)
    Logger.info("Step 2: Initiating Nuclei Deep Scan...")
    nm = NucleiManager(target)
    nuclei_findings = nm.run_nuclei(severity="medium,high,critical")

    # Step 3: Generate Professional PDF Report
    Logger.info("Step 3: Compiling final professional report...")
    generate_pdf_report(target, osint_results, identity_findings, nuclei_findings, args.output)
    
    Logger.success(f"Audit Complete. Report saved to: {args.output}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        Logger.warn("User interrupted. Exiting...")
        sys.exit(0)