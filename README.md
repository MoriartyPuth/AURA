<div align="center">
  
  # 🌌 Aura-Scanner
  **Advanced Unified Risk Assessment**

  [![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
  [![Audit-Level](https://img.shields.io/badge/Audit-National--Security-red?style=for-the-badge)](https://github.com/bubble/Aura-Scanner)
  [![Status](https://img.shields.io/badge/Status-Stable-green?style=for-the-badge)](https://github.com/bubble/Aura-Scanner)

 <img width="656" height="277" alt="Aura Logo" src="https://github.com/user-attachments/assets/262b9981-3b2c-48f3-ab4c-d0d3ef7dd925" />
</div>

---

## 💎 Pro-Level Audit Features
| Feature | Description | Status |
| :--- | :--- | :--- |
| **CRT.sh OSINT** | Passive Subdomain Enumeration | ✅ Active |
| **Shodan API** | IoT & Port Service Mapping | ✅ Active |
| **Identity Probe** | Detection of /admin, /auth, /config leaks | ✅ Active |
| **Nuclei Engine** | CVE & Misconfiguration Scanning | ✅ Active |
| **PDF Reporting** | Executive Summary Generation | ✅ Active |
| **Slack/Discord Webhooks** | Real-time Leak Alerts | 🛠️ In Progress |

---
## 🛠️ The Audit Lifecycle
**Phase 0: Passive Recon (OSINT)**

Aggregates data from CRT.sh (Certificate Transparency) and Shodan API to map a target's global footprint without sending a single packet to their server.

**Phase 1: Identity & Logic Probes**

A surgical engine that hunts for "Security through Obscurity" failures. It specifically targets exposed administrative portals, authentication endpoints, and sensitive configuration directories.

**Phase 2: Vulnerability Orchestration**

Wraps the Nuclei Vulnerability Engine, executing 5,000+ modern templates to detect CVEs, XSS, SQLi, and misconfigurations with zero-false-positive logic.

**Phase 3: Executive Reporting**

Automated PDF synthesis using the ```fpdf2``` engine. Generates a categorized, timestamped, and professional document ready for immediate stakeholder briefing.

---

## ⚡ Quick Start
Perform a full-spectrum audit in under 60 seconds.

**Clone the vault**
```
git clone https://github.com/MoriartyPuth/AURA && cd Aura
```
**Launch the Controller**
```
python3 aura.py -t (http://target.com)
```
**Increase audit speed (Threads: 50)**
```
python3 aura.py -t http://target.com) --threads 50
```

---

## ⚙️ Configuration
Fine-tune your audit intensity via ```config.yaml```:
```
shodan:
  api_key: "YOUR_API_KEY"  # IoT Discovery Access

settings:
  threads: 25              # Concurrent audit workers
  timeout: 10              # Network timeout (seconds)
  user_agent: "YOUR_NAME"
```

---

## ⚖️ Legal Disclaimer
**FOR AUTHORIZED USE ONLY**. This tool is designed for security professionals and authorized infrastructure auditing. The author is not responsible for illegal use or damage caused by this software. Use your power for good.
