import json
import os
from utils.common import utc_now_iso


def load_state(state_file):
    if not state_file or not os.path.exists(state_file):
        return {}
    try:
        with open(state_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(state_file, state):
    if not state_file:
        return
    os.makedirs(os.path.dirname(state_file) or ".", exist_ok=True)
    state["_updated_at"] = utc_now_iso()
    with open(state_file, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def mark_task_completed(state, phase_name, task_name, result=None):
    done = state.setdefault("completed", {}).setdefault(phase_name, [])
    if task_name not in done:
        done.append(task_name)
    state.setdefault("results", {}).setdefault(phase_name, {})[task_name] = result or []


def is_task_completed(state, phase_name, task_name):
    return task_name in state.get("completed", {}).get(phase_name, [])


def get_task_result(state, phase_name, task_name):
    return state.get("results", {}).get(phase_name, {}).get(task_name, [])
