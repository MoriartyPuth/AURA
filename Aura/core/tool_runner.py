import shutil
import subprocess
from core.logger import Logger


def is_tool_available(name):
    return shutil.which(name) is not None


def run_command(command, timeout=180):
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout
        )
        return completed.returncode, completed.stdout.strip(), completed.stderr.strip()
    except subprocess.TimeoutExpired:
        Logger.warn(f"Timeout running: {' '.join(command)}")
        return 124, "", "timeout"
    except Exception as ex:
        Logger.error(f"Command failed: {' '.join(command)} | {ex}")
        return 1, "", str(ex)
