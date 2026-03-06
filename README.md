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

## 💎 Pro-Level Audit Features
| Feature | Description | Status |
| :--- | :--- | :--- |
| **OSINT + Suite** | CRT.sh, Shodan, Wayback, Google Dorking, Favicon Hashing | ✅ Active |
| **Cloud-Spy** | S3, Azure, & GCP Bucket Permutation/Leak Detection | ✅ Active |
| **Logic & Identity** | /admin Probing, 403-Bypass, & JWT Signature Analysis | ✅ Active |
| **Deep-Fuzz Engine** | Nuclei v3, FFuf, & Wapiti Orchestration | ✅ Active |
| **Quality Gate** | Professional PDF, JSON, CSV, and SARIF | ✅ Active |
| **Live Notifications** | Slack/Discord Webhooks for Critical Finds | 🛠️ In Progress |

---
## 🛠️ The Audit Lifecycle
**Phase 0: Multi-Vector Reconnaissance (OSINT+)**

Aura doesn't just scan; it listens. By aggregating data from Wayback Machine archives, Shodan IoT mapping, and Certificate Transparency (CRT.sh), it builds a global footprint.

* **Web Intelligence:** Extracts JS endpoints and performs Favicon MMH3 hashing to find hidden development/staging servers.

* **Cloud Discovery:** Automatically maps and probes S3/Azure/GCP storage infrastructure for misconfigured public access.

**Phase 1: Identity, Logic & Misconfiguration**

A surgical engine designed to hunt for "Security through Obscurity" failures and architectural flaws.

* **Bypass Logic:** Automated header-fuzzing to bypass 403 Forbidden and 401 Unauthorized restrictions.

* **Modern Auth Probing:** Deep analysis of JWT tokens (alg:none, weak secrets) and Subdomain Takeover checks.

* **Service Enrichment:** Fingerprints services using python3-nmap to identify high-risk legacy versions.

**Phase 2: Vulnerability Orchestration & Fuzzing**

The heavy-hitting phase where Aura orchestrates industry-standard engines.

* **Nuclei Integration:** Executes 5,000+ modern templates for CVEs, XSS, and SQLi.

* **Mutation Fuzzing:** Uses ffuf and arjun for high-velocity parameter mining and payload injection.

* **JS Deobfuscation:** Analyzes client-side code using ExecJS to find hardcoded credentials and hidden API routes.

**Phase 3: Executive Reporting & Quality Gate**

Before outputting, all findings pass through the Aura Quality Gate.

* **Risk Normalization:** Deduplicates findings and scores them based on a normalized risk table (CRITICAL to LOW).

* **Automated PDF Synthesis:** Uses the `fpdf2` engine to generate a professional, stakeholder-ready document with prioritized risk tables and implementation checklists.

---

## ⚡ Quick Start
Aura-Scanner uses Profiles to balance speed and depth. Choose the profile that matches your current objective:

1. The 'Quick' Profile

* **Best for:** Initial triage and fast "low-hanging fruit" discovery.

* **Focus:** Passive OSINT, high-level service discovery, and critical CVEs.

* **Speed:** 2–5 minutes.

* **Usage:**

```
python3 aura.py -u https://target.com --profile quick
```

2. The 'Normal' Profile (Default)

Best for: Standard security assessments and compliance checks.

* **Focus:** Full Phase 0 & 1, including Cloud-Spy (S3 leaks), 403-Bypass testing, and comprehensive Nuclei orchestration.

* **Speed:** 10–20 minutes.

* **Usage:**

```
python3 aura.py -u https://target.com --profile normal
```
3. The 'Deep' Profile

Best for: Full-scale penetration testing and red-teaming.

* **Focus:** Everything in Normal + heavy directory brute-forcing, JS deobfuscation, parameter mining (Arjun), and mutation fuzzing.

* **Speed:** 60+ minutes (depends on target size).

* **Usage:**
```
python3 aura.py -u https://target.com --profile deep --export pdf
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
  threads: 25              # Concurrent audit workers
  timeout: 10              # Network timeout (seconds)
  user_agent: "YOUR_NAME"
```

---

## ⚖️ Legal Disclaimer
**FOR AUTHORIZED USE ONLY**. This tool is designed for security professionals and authorized infrastructure auditing. The author is not responsible for illegal use or damage caused by this software. Use your power for good.
