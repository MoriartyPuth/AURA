import subprocess
import json
import os
from core.logger import Logger

class NucleiManager:
    def __init__(self, target, output_dir="reports"):
        self.target = target
        self.output_file = f"{output_dir}/nuclei_raw.json"

    def run_nuclei(self, severity="high,critical"):
        findings = []
        cmd = ["nuclei", "-u", self.target, "-severity", severity, "-jsonl", "-o", self.output_file, "-silent"]

        try:
            subprocess.run(cmd, check=True)
            if os.path.exists(self.output_file):
                with open(self.output_file, 'r') as f:
                    for line in f:
                        data = json.loads(line)
                        name = data.get('info', {}).get('name')
                        findings.append(name)
                        Logger.warn(f"Nuclei Finding: {name}")
        except Exception: pass
        return findings