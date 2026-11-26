<div align="center">

  # 🌌 Aura-Scanner **(Advanced Unified Risk Assessment)**

  [![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
  [![Status](https://img.shields.io/badge/Status-Stable-green?style=for-the-badge)](https://github.com/bubble/Aura-Scanner)

</div>

A phase-based web audit orchestrator. It wraps the recon/vuln toolchain (nuclei, httpx, naabu, sqlmap, dalfox, ffuf, …), turns the raw output into deduped, severity-scored findings, and prints them to your terminal — so you can skip the busywork and go straight to manual exploitation.

---

## Quick Start

```
cd Aura
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python aura.py -t https://target.com
```

Run it from anywhere — symlink the launcher once, then just type `aura`:

```
ln -s "$PWD/aura" ~/.local/bin/aura    # ~/.local/bin must be on your PATH
aura -t https://target.com
```

Findings print to the terminal when the scan ends, grouped by severity (highest risk first). The PDF is opt-in: `--pdf` or `-o report.pdf`. JSON/CSV/SARIF are always written to `reports/`.

External tools are optional — any that are missing are skipped: `subfinder assetfinder gau waybackurls naabu httpx nmap arjun subzy subjack whatweb nikto dalfox sqlmap nuclei ffuf wapiti`.

### Profiles

| Profile | Speed | What runs |
| :-- | :-- | :-- |
| `--profile quick` | 2–5 min | Recon + Phase 1 + critical-severity nuclei. No crawler/ffuf/wapiti/fuzzing. |
| `--profile normal` *(default)* | 10–20 min | All phases: crawler (25p), sqlmap/dalfox, high+critical nuclei, ffuf, fuzzing. |
| `--profile deep` | 60+ min | Normal + deeper crawl (60p), medium+ nuclei, larger ffuf wordlist. |

---

## Audit Lifecycle

**Phase 0 — Recon.** OSINT (crt.sh, Shodan, Wayback/gau, WHOIS/DNS, favicon hash) plus active discovery (naabu/nmap, httpx, arjun, subfinder, in-scope crawler with JS endpoint extraction). Runs in parallel. With an `auth:` block the crawler runs authenticated, feeding the post-login surface to later phases. Optional S3/GCS/Azure bucket probes (opt-out).

**Phase 1 — Identity, logic & misconfig.** Sensitive-path probing with soft-404 filtering; JWT discovery + `alg=none`; sqlmap/dalfox on real parameterised URLs; SSTI/LFI/XXE/CRLF/CORS/open-redirect/smuggling checks; subzy/subjack takeover. **Authz (opt-in):** replays in-scope endpoints across victim/attacker/anonymous (and admin) accounts to find IDOR/BOLA, missing-auth and privilege escalation. GET-only, never mutates, creds never written to reports.

**Phase 2 — Vuln orchestration.** nuclei at the profile's severity; CVE detection (header + whatweb fingerprint → nuclei `cve` templates, enriched with CVSS, PoC links and `searchsploit`/`msfconsole` lookups in `reports/cve_details.json`); ffuf (auto-calibrated) + wapiti; payload mutation fuzzing. AURA confirms and documents — it never launches exploits.

**Phase 3 — Quality gate & reporting.** Confidence gate (drops anything below `--min-confidence`, default `medium`), dedup + severity scoring (tool-confirmed outranks heuristic), then terminal summary + PDF/JSON/CSV/SARIF.

**Scope:** AURA refuses to start if the target is out of scope. `--include-domain` / `--exclude-domain` / `--scope-regex` (or the `scope:` block) filter every crawled link, archived URL, subdomain and probe target before any tool runs.

---

## Configuration

Tune via `config.yaml`:

```yaml
settings:
  timeout: 10              # network timeout (s)
  phase0_workers: 3        # parallel workers (1 = serial / quietest)
  user_agent: "Mozilla/5.0 ... Chrome/125.0.0.0 Safari/537.36"
  request_delay: 0.0       # seconds between requests (0 = off)
  request_jitter: 0.25     # add random 0..N s per request
  tool_rate_limit: 50      # req/s cap for nuclei/ffuf/sqlmap/dalfox (0 = tool default)
  proxy: ""                # route Python + tool traffic (e.g. Burp at http://127.0.0.1:8080)
```

**Staying quiet:** the external scanners generate the load. Lower the profile with a plain-browser UA (default), `request_delay`/`request_jitter`, `tool_rate_limit`, fewer workers, and `--proxy` to route everything through Burp. Note AURA still sends textbook payloads (`../../etc/passwd`, `169.254.169.254`, `{{…}}`), so a signature WAF can still flag the active checks.

---

## Legal

**FOR AUTHORIZED USE ONLY.** For security professionals and authorized auditing. The author is not responsible for misuse or damage. Use your power for good.
