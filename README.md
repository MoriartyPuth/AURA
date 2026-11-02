<div align="center">
  
  # 🌌 Aura-Scanner **(Advanced Unified Risk Assessment)**

  [![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
  [![Audit-Level](https://img.shields.io/badge/Audit-National--Security-red?style=for-the-badge)](https://github.com/bubble/Aura-Scanner)
  [![Status](https://img.shields.io/badge/Status-Stable-green?style=for-the-badge)](https://github.com/bubble/Aura-Scanner)
  
 <img width="656" height="277" alt="Aura Logo" src="https://github.com/user-attachments/assets/262b9981-3b2c-48f3-ab4c-d0d3ef7dd925" />
</div>

Aura-Scanner is a modular, high-velocity security auditing framework designed for structured infrastructure reconnaissance, vulnerability analysis, and automated risk reporting.

Unlike typical "shotgun" scanners, Aura follows a Phase-based Audit Lifecycle, transforming raw OSINT and reconnaissance data into actionable executive reports. Built for security professionals, it automates the tedious parts of an audit—recon, fuzzing, and misconfiguration detection—so you can focus on manual exploitation.

---

## 💎 Audit Features
| Feature | What it actually does | Status |
| :--- | :--- | :--- |
| **OSINT Suite** | crt.sh, Shodan, Wayback, WHOIS/DNS, Google dorks, IPInfo, favicon MMH3 hash | ✅ Active |
| **Recon Orchestration** | subfinder/assetfinder, gau/waybackurls, naabu, httpx, nmap, arjun, in-scope crawler with JS endpoint extraction | ✅ Active |
| **Cloud Bucket Probes** | Guesses S3 / GCS / Azure Blob names from the domain and checks existence/listability | ✅ Active (opt-out) |
| **Identity & Exposure** | Sensitive-path probing with soft-404 filtering; JWT discovery + `alg=none` detection | ✅ Active |
| **Authorization (IDOR/BOLA + priv-esc)** | Multi-account + anonymous replay of in-scope endpoints to find horizontal IDOR/BOLA, vertical privilege escalation and missing-auth bugs (opt-in, GET-only) | ✅ Active |
| **Vuln Probes** | sqlmap & dalfox on real parameterised URLs from recon (findings parsed from tool results); SSTI/LFI/CORS/CRLF/open-redirect checks; payload mutation fuzzing | ✅ Active |
| **Deep Scan** | Nuclei (severity per profile), ffuf with auto-calibration, wapiti | ✅ Active |
| **CVE Detection** | Stack fingerprint (headers + whatweb) and nuclei CVE/vulnerability templates; findings enriched with CVSS, exploit/PoC references and `searchsploit`/`msfconsole` lookup commands (`reports/cve_details.json`) | ✅ Active |
| **Takeover** | subzy / subjack on in-scope subdomains | ✅ Active |
| **Reporting** | Confidence gate, severity scoring & dedup, PDF / JSON / CSV / SARIF | ✅ Active |
| **403/401 Bypass** | Header/path fuzzing against forbidden endpoints | 🗺️ Planned |
| **JWT Weak Secrets** | Offline HMAC secret brute-force | 🗺️ Planned |
| **Live Notifications** | Slack/Discord webhooks for critical finds | 🗺️ Planned |

---
## 🛠️ The Audit Lifecycle
**Phase 0: Reconnaissance (passive OSINT + active discovery)**

Aggregates Certificate Transparency (crt.sh), Wayback/gau archives, Shodan, DNS and WHOIS into a footprint of the target. Note that this phase is **not purely passive**: it also runs naabu/nmap port scans, httpx, arjun and an in-scope crawler. Phase 0 tasks run in parallel (`settings.phase0_workers`, default 3). When the `auth:` block is configured the crawler runs **authenticated** as the victim account, so the post-login surface is discovered and fed to the probes, fuzzer and authz checks.

* **Web Intelligence:** Page title, favicon MMH3 hash (pivot in Shodan to find related hosts), and API endpoints extracted from linked and inline JavaScript.

* **Cloud Discovery:** Probes guessed S3/GCS/Azure bucket names for existence and anonymous listing. These buckets may belong to someone else — disable with `scope.allow_cloud_bucket_probes: false` if your rules forbid it.

**Phase 1: Identity, Logic & Misconfiguration**

* **Sensitive Paths:** Probes common config/debug paths (`/.env`, `/phpinfo.php`, …). A soft-404 baseline (random-path fingerprints) suppresses catch-all/SPA responses, so a 200 alone is not reported.

* **JWT Analysis:** Finds JWTs in the page body, headers and cookies, lists their claims and flags `alg=none`.

* **Injection Probes:** sqlmap and dalfox run against real parameterised URLs discovered in Phase 0. Findings are read from sqlmap's result log and dalfox's JSON output — only confirmed injection points (sqlmap) and verified/reflected PoCs (dalfox) are reported.

* **Authorization (IDOR/BOLA + privilege escalation):** Opt-in. Given a victim and a low-priv attacker account, AURA replays every in-scope endpoint as each (and anonymously) and flags where the attacker or an anonymous request receives the victim's resource (horizontal IDOR/BOLA / missing auth). Add an `admin` account and `admin_endpoints` to also catch vertical privilege escalation (a low-priv user reaching admin resources). GET-only, never mutates, credentials are never written to the report. Enable via the `auth:` block in `config.yaml`.

* **Classic Checks & Takeover:** SSTI, LFI/RFI, XXE, CRLF, CORS, open redirect, TE/CL smuggling heuristic; subzy/subjack takeover checks; whatweb/nikto.

**Phase 2: Vulnerability Orchestration & Fuzzing**

* **Nuclei Integration:** Runs the installed nuclei templates at the profile's severity level.

* **CVE Detection:** Fingerprints the stack from response headers and `whatweb`, then runs nuclei's `cve`/`vulnerabilities` templates at all severities. Run with `--update-toolchain` to refresh templates first so the latest CVE signatures are used. nuclei's template feed is the matching engine — see [`SOURCES.md`](Aura/SOURCES.md) for coverage and limits.

  Each confirmed CVE is tagged `[VERIFIED]` and enriched with its CVSS score, exploit/PoC reference links and the `searchsploit` / `msfconsole` lookup commands for retrieving the public exploit (full data in `reports/cve_details.json`). AURA confirms and documents — it does not launch exploits; running one is a manual step the operator performs against an authorized target.

* **Content Discovery:** ffuf with auto-calibration (`-ac`) to filter catch-all responses; wapiti limited to the target folder.

* **Mutation Fuzzing:** Injects XSS/SQLi/SSRF/path-traversal payloads (`wordlists/payloads/`) into parameters of crawled and archived in-scope URLs.

* **JS Heuristics:** Flags inline scripts using `eval`/`atob`/`fromCharCode` patterns (ExecJS compile check). It does not deobfuscate or extract secrets.

**Phase 3: Reporting & Quality Gate**

Before outputting, all findings pass through the Aura Quality Gate.

* **Confidence Gate:** Findings are tagged LOW/MEDIUM/HIGH confidence; anything below `--min-confidence` (default `medium`) is dropped unless corroborated by another module.

* **Risk Normalization:** Deduplicates findings and scores them (CRITICAL → INFO); tool-confirmed findings rank above heuristic ones.

* **Reports:** PDF (`fpdf2`) with a prioritized risk table, plus JSON, CSV and SARIF exports and a run checklist.

## 🎯 Scope

Aura refuses to start if the target itself is out of scope. `--include-domain`, `--exclude-domain` and `--scope-regex` (or the `scope:` block in `config.yaml`) are applied to crawled links, archived URLs, discovered subdomains (crt.sh/subfinder/assetfinder) and probe/fuzz targets before any tool touches them, so excluded hosts never reach takeover, sqlmap, dalfox or the fuzzer.

---

## ⚡ Quick Start
Run from inside the `Aura/` directory (config and wordlist paths are relative):

```
cd Aura
pip install -r requirements.txt
python3 aura.py -t https://target.com
```

External tools are optional — any that are missing are skipped: `subfinder assetfinder gau waybackurls naabu httpx nmap arjun subzy subjack whatweb nikto dalfox sqlmap nuclei ffuf wapiti`.

Aura-Scanner uses Profiles to balance speed and depth. Choose the profile that matches your current objective:

1. The 'Quick' Profile

* **Best for:** Initial triage and fast "low-hanging fruit" discovery.

* **Focus:** Recon, Phase 1 checks and critical-severity Nuclei templates. Crawler, toolchain health, ffuf/wapiti and payload fuzzing are skipped.

* **Speed:** 2–5 minutes.

* **Usage:**

```
python3 aura.py -t https://target.com --profile quick
```

2. The 'Normal' Profile (Default)

Best for: Standard security assessments and compliance checks.

* **Focus:** All phases: crawler (25 pages), cloud bucket probes, sqlmap/dalfox, high+critical Nuclei templates, ffuf (`common.txt`) and payload fuzzing.

* **Speed:** 10–20 minutes.

* **Usage:**

```
python3 aura.py -t https://target.com --profile normal
```
3. The 'Deep' Profile

Best for: Full-scale penetration testing and red-teaming.

* **Focus:** Everything in Normal with a deeper crawl (60 pages), medium+ Nuclei templates and the larger `common_deep.txt` ffuf wordlist.

* **Speed:** 60+ minutes (depends on target size).

* **Usage:**
```
python3 aura.py -t https://target.com --profile deep
```

---

## ⚙️ Configuration
Fine-tune your audit intensity via ```config.yaml```:
```
shodan:
  api_key: "YOUR_API_KEY"  # IoT Discovery Access
ipinfo:
  token: "YOUR_IPINFO_TOKEN"

settings:
  timeout: 10              # Network timeout (seconds)
  phase0_workers: 3        # parallel Phase 0 workers (1 = serial / quietest)
  user_agent: "Mozilla/5.0 ... Chrome/125.0.0.0 Safari/537.36"   # plain browser UA by default
  request_delay: 0.0       # seconds between Python requests (global, 0 = off)
  request_jitter: 0.25     # add random 0..N s per request to desynchronise
  tool_rate_limit: 50      # req/s cap for nuclei/ffuf/sqlmap/dalfox (0 = tool default)
  proxy: ""                # route Python + external-tool traffic (e.g. Burp at http://127.0.0.1:8080)
```

### Footprint / staying quiet
AURA's own Python checks are light, but the external scanners it drives (nuclei, ffuf, sqlmap, dalfox, nmap) are what generate load and are easily fingerprinted. To lower the profile:

* The default **User-Agent is a plain browser string** (not `Aura-Scanner`), so it is not a one-rule WAF block. Override via `settings.user_agent`.
* **Pace requests** with `request_delay` + `request_jitter` (global across the parallel workers) and cap the external tools with `tool_rate_limit`.
* **Lower `phase0_workers`** (or set `1`) to reduce the simultaneous request spike.
* **Route everything through a proxy** with `settings.proxy` or `--proxy http://127.0.0.1:8080` (Python requests *and* nuclei/ffuf/sqlmap/dalfox/wapiti), e.g. to send traffic via Burp or a rotating egress.

Note AURA still sends textbook payloads (`../../etc/passwd`, `169.254.169.254`, `{{...}}`, a TE/CL smuggling probe), so a signature WAF can still flag the active checks — the knobs above reduce volume and the obvious client fingerprint, not payload signatures.

---

## ⚖️ Legal Disclaimer
**FOR AUTHORIZED USE ONLY**. This tool is designed for security professionals and authorized infrastructure auditing. The author is not responsible for illegal use or damage caused by this software. Use your power for good.
