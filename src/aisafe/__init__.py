"""src/aisafe/__init__.py
----------------------
AnyAISafe: audit the prompts and algorithms of AI-enabled software for how they influence
the person using it (profiling, manipulation, engineered attachment, deceptive identity,
behavioural influence).

    from aisafe import run_audit, load_policy
    from aisafe import Finding, Report, Decision, EvidenceStatus

Everything is imported on first use (PEP 562): `aisafe --help` and the console script pay
for nothing they do not run. The command line is `aisafe audit|review|evaluate|fleet|skill`.
"""

from __future__ import annotations

import importlib

__version__ = "0.2.0"

_LAZY_ATTRIBUTES = {
    "run_audit": ("aisafe.audit", "run_audit"),
    "AuditOptions": ("aisafe.audit", "AuditOptions"),
    "load_policy": ("aisafe.policy", "load_policy"),
    "Policy": ("aisafe.policy", "Policy"),
    "Finding": ("aisafe.evidence.model", "Finding"),
    "Report": ("aisafe.evidence.model", "Report"),
    "Decision": ("aisafe.evidence.model", "Decision"),
    "EvidenceStatus": ("aisafe.evidence.model", "EvidenceStatus"),
    "ControlStatus": ("aisafe.evidence.model", "ControlStatus"),
    "Severity": ("aisafe.evidence.model", "Severity"),
}


def __getattr__(name: str):
    target = _LAZY_ATTRIBUTES.get(name)
    if target is None:
        raise AttributeError(f"module 'aisafe' has no attribute {name!r}")
    module = importlib.import_module(target[0])
    value = getattr(module, target[1])
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))


__all__ = [
    "__version__",
    "run_audit",
    "AuditOptions",
    "load_policy",
    "Policy",
    "Finding",
    "Report",
    "Decision",
    "EvidenceStatus",
    "ControlStatus",
    "Severity",
]
