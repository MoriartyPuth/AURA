import subprocess, json, os
from core.logger import Logger

class NucleiManager:
    def __init__(self, target):
        self.target = target
        self.out = "reports/nuclei_raw.json"

    def run_nuclei(self, severity="high,critical"):
        findings = []
        cmd = ["nuclei", "-u", self.target, "-severity", severity, "-jsonl", "-o", self.out, "-silent"]
        try:
            subprocess.run(cmd, check=True)
            if os.path.exists(self.out):
                with open(self.out, 'r') as f:
                    for line in f:
                        name = json.loads(line).get('info', {}).get('name')
                        findings.append(name); Logger.warn(f"Nuclei: {name}")
        except: pass
        return findings