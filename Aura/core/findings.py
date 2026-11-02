"""Structured finding model.

Modules may return either plain strings (legacy) or `Finding` objects (preferred).
Everything downstream - filters, quality gate, risk scoring, exporters, report -
operates on `Finding`s, so a string is wrapped with `Finding.from_any`, which
leaves severity/confidence blank for the pipeline to infer from the title (the
old behaviour). New modules set the fields explicitly, which removes the guessing
and lets exports carry real structure (url, param, references, cvss, ...).
"""
from dataclasses import asdict, dataclass, field

VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")
VALID_CONFIDENCE = ("high", "medium", "low")


@dataclass
class Finding:
    title: str                                  # one-line human summary
    source: str = ""                            # task/module that produced it
    phase: str = ""
    severity: str = ""                          # "" -> infer from title
    confidence: str = ""                        # "" -> infer from title
    url: str = ""                               # where it was observed
    param: str = ""                             # affected parameter, if any
    evidence: str = ""                          # supporting detail
    references: list = field(default_factory=list)
    verified: bool = False                      # tool-confirmed, not heuristic
    extra: dict = field(default_factory=dict)   # module-specific fields

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_any(cls, obj, source="", phase=""):
        """Coerce a string / dict / Finding into a Finding, filling source+phase."""
        if isinstance(obj, cls):
            finding = obj
        elif isinstance(obj, dict) and "title" in obj:
            known = {k: obj[k] for k in cls.__dataclass_fields__ if k in obj}
            finding = cls(**known)
        else:
            finding = cls(title=str(obj))
        if not finding.source:
            finding.source = source
        if not finding.phase:
            finding.phase = phase
        return finding


def coerce_list(entries, source="", phase=""):
    return [Finding.from_any(e, source=source, phase=phase) for e in (entries or [])]


def coerce_phase_map(phase_map):
    """Ensure every entry in a {phase: {source: [...]}} map is a Finding."""
    out = {}
    for phase, modules in (phase_map or {}).items():
        if not isinstance(modules, dict):
            out[phase] = modules
            continue
        out[phase] = {src: coerce_list(entries, source=src, phase=phase)
                      for src, entries in modules.items()}
    return out


def findings_to_dicts(phase_map):
    """Serialize a coerced phase map to plain dicts for JSON output."""
    return {
        phase: {src: [f.to_dict() for f in entries] for src, entries in modules.items()}
        for phase, modules in phase_map.items()
        if isinstance(modules, dict)
    }
