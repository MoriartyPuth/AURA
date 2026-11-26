#!/usr/bin/env bash
cd "$(dirname "$0")"; source _player.sh
clear
line "\033[2m# AURA — one nuclei pass, CVEs enriched inline with CVSS + exploit refs\033[0m" 0.2
pause 0.4
type_cmd "aura -t http://154.57.164.83:34905 --profile quick"
pause 0.3
line "\033[34m[*]\033[0m Phase 0: recon (httpx, naabu, crawler)…" 0.3
line "\033[34m[*]\033[0m Phase 2: nuclei scan (severity critical, CVEs enriched from same pass)…" 0.4
pause 0.5
line "\033[1;31m[CRITICAL]\033[0m nuclei CVE-2025-55182  React Server Components — RCE  (CVSS 10.0)" 0.3
pause 0.6
while IFS= read -r l; do printf '%s\n' "$l"; sleep 0.08; done < cve_block.txt
pause 1.5
