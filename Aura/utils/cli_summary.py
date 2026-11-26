"""Print the final risk table to the terminal once a scan finishes.

Real findings (low and above) are listed in full, grouped by severity, highest
score first. INFO entries (crawled URLs, tool-ready notes, ...) are usually
noise, so they are collapsed to a count unless `show_info` is set.
"""
import shutil

from colorama import Fore, Style

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_COLORS = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH": Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW": Fore.CYAN,
    "INFO": Fore.WHITE + Style.DIM,
}


def _truncate(text, width):
    text = " ".join(str(text or "").split())
    return text if len(text) <= width else text[: max(width - 1, 0)] + "…"


def format_summary(target, risk_table, show_info=False, width=None):
    """Return the summary as a list of lines (kept separate from printing for tests)."""
    width = width or shutil.get_terminal_size((100, 20)).columns
    text_width = max(width - 6, 40)
    groups = {sev: [] for sev in SEVERITY_ORDER}
    for risk in risk_table:
        groups.setdefault(str(risk.get("severity", "INFO")).upper(), []).append(risk)

    rule = "=" * min(width, 100)
    lines = [rule, f"{Style.BRIGHT}AURA RESULTS{Style.RESET_ALL}  {target}", rule]

    counts = "  ".join(
        f"{SEVERITY_COLORS.get(sev, '')}{sev} {len(groups.get(sev, []))}{Style.RESET_ALL}"
        for sev in SEVERITY_ORDER
    )
    lines.append(counts)

    real = [sev for sev in SEVERITY_ORDER if sev != "INFO" and groups.get(sev)]
    if not real:
        lines.append(f"{Fore.GREEN}No findings at LOW or above.{Style.RESET_ALL}")

    shown = SEVERITY_ORDER if show_info else [s for s in SEVERITY_ORDER if s != "INFO"]
    for sev in shown:
        entries = groups.get(sev) or []
        if not entries:
            continue
        color = SEVERITY_COLORS.get(sev, "")
        lines.append("")
        lines.append(f"{color}[{sev}]{Style.RESET_ALL} ({len(entries)})")
        for risk in entries:
            tags = []
            if risk.get("verified"):
                tags.append(f"{Fore.GREEN}verified{Style.RESET_ALL}")
            if risk.get("confidence"):
                tags.append(f"conf={risk['confidence']}")
            tag_str = f"  [{', '.join(tags)}]" if tags else ""
            lines.append(f"  {color}●{Style.RESET_ALL} {_truncate(risk.get('finding'), text_width)}{tag_str}")
            meta = f"{risk.get('source', '')} · score {risk.get('score', '')}"
            lines.append(f"    {Style.DIM}{_truncate(meta, text_width)}{Style.RESET_ALL}")
            if risk.get("url"):
                lines.append(f"    {Style.DIM}{_truncate(risk['url'], text_width)}{Style.RESET_ALL}")

    hidden_info = len(groups.get("INFO", []))
    if hidden_info and not show_info:
        lines.append("")
        lines.append(f"{Style.DIM}+ {hidden_info} INFO entries hidden (use --show-info){Style.RESET_ALL}")
    lines.append(rule)
    return lines


def print_summary(target, risk_table, show_info=False):
    for line in format_summary(target, risk_table, show_info=show_info):
        print(line)
