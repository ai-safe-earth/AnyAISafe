"""src/aisafe/investigation/plan.py
---------------------------------
`aisafe investigate plan PATH`: the ranked queue of surfaces an investigation reads.

The queue is built from the scan's inventory, not only from rule hits: every person-facing
unit, prompt file, prompt literal and assembly, prompt fetched at run time, model call,
memory store, scheduler or sender, profile source and external destination the discovery
found is a surface. Each surface carries the hypotheses that apply to its type, as
(mechanism, pattern) pairs from the policy, and the signals and machine findings in its
scope. Deterministic: the same tree gives the same plan, and `plan_sha256` is the same.

Priority comes from structure, never from a model:

- `high`: a person-facing unit; a prompt whose scope holds a persona, confidant,
  romantic, attachment, engagement, monetisation, steering, inference, vulnerability or
  scoring signal; a prompt fetched at run time inside a person-facing unit; a scheduler
  and a send in one unit, or personalised outreach; any surface whose scope holds a machine
  finding that violates the policy or is critical or high;
- `low`: a surface in a test file;
- `normal`: the rest.

Order: priority, surface type, path, line, id. The budget (default 20) is how many are
queued; the rest are `left_out` and listed, and an assessment still counts a high one left
out as a gap. A surface in a code language the workbench does not read (anything but
Python, JS/TS and prompt or configuration text) is `unsupported` and listed.

The plan also lists `untrusted_text`: lines addressed to an auditor or an AI tool, and
the agent instruction files in the tree. They are evidence to record, never instructions.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Any, Iterable

from aisafe.discovery import walk
from aisafe.evidence.model import Decision, Finding, Severity, now_iso, redact
from aisafe.investigation.scan import MachineScan
from aisafe.investigation.text import normalise

__all__ = [
    "AGENT_INSTRUCTION_FILES",
    "DEFAULT_BUDGET",
    "HIGH_SIGNAL_KINDS",
    "HYPOTHESES",
    "PLAN_KIND",
    "PLAN_SCHEMA",
    "PRIORITIES",
    "SURFACE_TYPES",
    "build_plan",
    "plan_digest",
    "render_plan",
    "surface_id",
]

PLAN_SCHEMA = "aisg/investigation-plan/1"
PLAN_KIND = "investigation-plan"
DEFAULT_BUDGET = 20
PRIORITIES: tuple[str, ...] = ("high", "normal", "low")
SURFACE_TYPES: tuple[str, ...] = (
    "person_facing_unit",
    "prompt",
    "remote_prompt",
    "model_entry",
    "scheduler_sender",
    "memory_store",
    "profile_source",
    "external_destination",
)

_PROMPT_HYPOTHESES: tuple[tuple[str, str], ...] = (
    ("M6", "concealment_instruction"),
    ("M5", "attachment_instruction"),
    ("M4", "objective"),
    ("M7", "covert_steering"),
    ("M7", "affiliate"),
    ("M2", "inference_for_influence"),
    ("M1", "binding"),
)
# The hypotheses a surface of each type carries. Every pair names a pattern of the policy
# (a test pins that), and a record answers one pair on one surface.
HYPOTHESES: dict[str, tuple[tuple[str, str], ...]] = {
    "person_facing_unit": (
        ("M5", "confidant_without_crisis_path"),
        ("M6", "no_disclosure_on_path"),
    ),
    "prompt": _PROMPT_HYPOTHESES,
    "remote_prompt": _PROMPT_HYPOTHESES,
    "model_entry": (
        ("M1", "binding"),
        ("M1", "transmission"),
        ("M5", "confidant_without_crisis_path"),
        ("M6", "no_disclosure_on_path"),
    ),
    "scheduler_sender": (("M4", "outreach"), ("M5", "attachment_algorithm")),
    "memory_store": (
        ("M1", "storage"),
        ("M2", "inference_for_influence"),
        ("M3", "scoring_for_influence"),
    ),
    "profile_source": (
        ("M1", "binding"),
        ("M3", "scoring_for_influence"),
        ("M7", "profile_keyed_steering"),
    ),
    "external_destination": (("M1", "transmission"),),
}

# Which mechanisms a discovery signal speaks to; a hypothesis is `signalled` when a signal
# in the surface's scope speaks to its mechanism.
SIGNAL_MECHANISMS: dict[str, tuple[str, ...]] = {
    "persona": ("M6",),
    "disclosure": ("M6",),
    "fiction": ("M5", "M6"),
    "confidant": ("M5",),
    "attachment": ("M5",),
    "romantic_role": ("M5",),
    "supportive": ("M5",),
    "crisis_control": ("M5",),
    "ui_text": ("M5",),
    "engagement": ("M4",),
    "monetisation": ("M4",),
    "experiment": ("M4",),
    "objective_code": ("M4",),
    "outreach_schedule": ("M4",),
    "outreach_send": ("M4",),
    "outreach_personalised": ("M4",),
    "user_set_reminder": ("M4",),
    "manipulation_control": ("M4", "M5"),
    "steering": ("M7",),
    "neutral_info": ("M7",),
    "persuasion_use": ("M2", "M7"),
    "inference": ("M2",),
    "affect": ("M2",),
    "biometric_cat": ("M2",),
    "vulnerable": ("M2", "M4", "M5"),
    "profile_sdk": ("M1",),
    "profile_name": ("M1",),
    "profile_placeholder": ("M1",),
    "memory": ("M1",),
    "scoring": ("M3",),
    "review": ("M8",),
}
HIGH_SIGNAL_KINDS = frozenset(
    {
        "persona",
        "confidant",
        "romantic_role",
        "attachment",
        "engagement",
        "monetisation",
        "steering",
        "inference",
        "affect",
        "vulnerable",
        "persuasion_use",
        "scoring",
    }
)
_HIGH_SEVERITIES = frozenset({Severity.CRITICAL, Severity.HIGH})
_WINDOW = 15  # lines around a code surface that count as its scope
_REMOTE_KINDS = frozenset({"remote", "runtime"})
_PROMPT_KINDS = frozenset({"file", "literal", "assembly"})
_SCHEDULER_KINDS = frozenset(
    {"outreach_schedule", "outreach_send", "outreach_personalised", "user_set_reminder"}
)
_PROFILE_KINDS = frozenset({"profile_name", "profile_placeholder"})
_DESTINATION_KINDS = frozenset({"profile_sdk"})

# Files whose whole content is addressed to coding agents, at any depth, and agent
# configuration that can make an agent run something (hooks, MCP servers). Their text is
# evidence about what the authors asked tools to do; an investigator reads it and never
# follows it.
AGENT_INSTRUCTION_FILES: tuple[str, ...] = (
    "CLAUDE.md",
    "CLAUDE.local.md",
    "AGENTS.md",
    "GEMINI.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    "copilot-instructions.md",
    ".mcp.json",
    "mcp.json",
)
_AGENT_INSTRUCTION_DIRS: tuple[str, ...] = (
    ".cursor/rules/",
    ".claude/",
    ".github/instructions/",
    ".github/prompts/",
    ".windsurf/",
    ".clinerules/",
    ".gemini/",
    ".codex/",
)
_UNTRUSTED_RE = re.compile(
    r"ignore (?:all |any )?(?:the )?(?:previous|prior|above|earlier) (?:instructions|prompts|rules)"
    r"|\b(?:note|message|instructions?|hint)s? (?:to|for) (?:the |any )?(?:auditors?|reviewers?|"
    r"ai|assistants?|agents?|llms?|models?|claude|copilot|chatgpt|gemini|codex|cursor)\b"
    r"|\bif you are an? (?:ai|llm|language model|assistant|agent|auditor|reviewer|scanner)\b"
    r"|\b(?:ai|llm) (?:auditors?|reviewers?|scanners?)\b"
    r"|\bdo not (?:report|flag|mention|list)\b.{0,40}\b(?:this|these|finding|findings|issue)\b"
    r"|\b(?:mark|treat|consider|classify) (?:this|these|it|the code) as "
    r"(?:safe|compliant|benign|approved|reviewed)\b"
    r"|\bdisregard (?:all |any )?(?:the )?(?:previous|prior|above|earlier)\b"
    r"|\b(?:auditors?|reviewers?|scanners?|agents?|assistants?) (?:should|must|need not|may) (?:ignore|skip|not)\b"
    r"|\b(?:this|the) (?:file|code|repository|repo|project|prompt) (?:is|was|has been) (?:already )?(?:reviewed|approved|audited|certified|exempt)\b"
    r"|\b(?:ai|llm|automated) (?:assistants?|agents?|tools?) (?:reading|scanning|reviewing) this\b",
    re.I,
)
# How many untrusted lines the terminal names; the JSON keeps every one.
_UNTRUSTED_SHOWN = 20
_SNIPPET = 160


# ---------------------------------------------------------------------------
# Surfaces
# ---------------------------------------------------------------------------


def surface_id(kind: str, relpath: str, anchor: str) -> str:
    """`s-` and twelve hex digits of sha1(type|path|anchor); the anchor is the cited line's
    normalised text (or the unit root), so an id survives lines moving above it."""
    digest = hashlib.sha1(f"{kind}|{relpath}|{anchor}".encode("utf-8")).hexdigest()
    return "s-" + digest[:12]


def _is_test_path(relpath: str) -> bool:
    path = PurePosixPath(relpath)
    parts = {part.lower() for part in path.parts[:-1]}
    name = path.name.lower()
    return (
        bool(parts & {"test", "tests", "__tests__", "spec", "specs"})
        or name.startswith("test_")
        or name.endswith(("_test.py", ".test.ts", ".test.js", ".spec.ts", ".spec.js"))
    )


class _Builder:
    def __init__(self, scan: MachineScan) -> None:
        self.scan = scan
        self.inventory = scan.ctx.inventory
        self.signals: dict[str, list[dict[str, Any]]] = {}
        for sig in self.inventory.person_signals or []:
            self.signals.setdefault(str(sig.get("file")), []).append(sig)
        self.findings_by_file: dict[str, list[tuple[int, Finding]]] = {}
        for finding in scan.findings:
            for leg in finding.evidence:
                self.findings_by_file.setdefault(leg.file, []).append((leg.line, finding))
        self.literal_spans: dict[tuple[str, int], int] = {}
        facts = scan.ctx.pyfacts
        for literal in getattr(facts, "prompt_literals", None) or []:
            self.literal_spans[(literal.file, literal.line)] = literal.end_line
        self.person_units = self._person_facing_units()
        self._lines: dict[str, list[str]] = {}

    # -- text --------------------------------------------------------------
    def line_text(self, relpath: str, line: int) -> str:
        if relpath not in self._lines:
            record = self.scan.walked.get(relpath)
            text = walk.read_text(record.path) if record is not None else None
            self._lines[relpath] = (text or "").split("\n")
        lines = self._lines[relpath]
        return lines[line - 1] if 1 <= line <= len(lines) else ""

    # -- scope ---------------------------------------------------------------
    def _person_facing_units(self) -> set[str]:
        """A unit with an AI surface and a way in (person input, a prompt, a persona); or a
        unit with person input and a person signal, whose model client the discovery may
        not recognise."""
        units: set[str] = set()
        with_ingress = {str(row.get("unit")) for row in self.inventory.ingress or []}
        with_prompts = {str(row.get("unit")) for row in self.inventory.prompts or []}
        with_personas = {str(row.get("unit")) for row in self.inventory.personas or []}
        with_signals = {str(row.get("unit")) for row in self.inventory.person_signals or []}
        for unit in self.inventory.units or []:
            surface = getattr(unit, "ai_surface", False)
            way_in = unit.id in with_ingress or unit.id in with_prompts or unit.id in with_personas
            if (surface and way_in) or (unit.id in with_ingress and unit.id in with_signals):
                units.add(unit.id)
        return units

    def span(self, kind: str, relpath: str, line: int, prompt_kind: str = "") -> tuple[int, int]:
        if prompt_kind == "file":
            return (1, 10**9)
        end = self.literal_spans.get((relpath, line))
        if end is not None:
            return (line, end)
        return (max(1, line - _WINDOW), line + _WINDOW)

    def scoped_signals(self, relpath: str, lo: int, hi: int) -> list[dict[str, Any]]:
        rows = [s for s in self.signals.get(relpath, []) if lo <= int(s.get("line") or 0) <= hi]
        return sorted(rows, key=lambda s: (int(s.get("line") or 0), str(s.get("kind"))))

    def scoped_findings(self, relpath: str, lo: int, hi: int) -> list[Finding]:
        seen: dict[str, Finding] = {}
        for line, finding in self.findings_by_file.get(relpath, []):
            if lo <= line <= hi or line == 0:
                seen.setdefault(finding.fingerprint, finding)
        return sorted(seen.values(), key=lambda f: (f.display_id, f.fingerprint))

    def unit_scope(self, unit: str) -> tuple[list[dict[str, Any]], list[Finding]]:
        sigs = [s for rows in self.signals.values() for s in rows if str(s.get("unit")) == unit]
        files = {r for r, rec in self.scan.walked.items() if getattr(rec, "unit", None) == unit}
        found: dict[str, Finding] = {}
        for finding in self.scan.findings:
            if finding.scope.unit == unit or any(leg.file in files for leg in finding.evidence):
                found.setdefault(finding.fingerprint, finding)
        sigs.sort(key=lambda s: (str(s.get("file")), int(s.get("line") or 0), str(s.get("kind"))))
        return sigs, sorted(found.values(), key=lambda f: (f.display_id, f.fingerprint))

    # -- one surface ----------------------------------------------------------
    def surface(
        self,
        kind: str,
        relpath: str,
        line: int,
        unit: str,
        *,
        name: str | None = None,
        signals: list[dict[str, Any]],
        findings: list[Finding],
        reasons: list[str],
        anchor: str | None = None,
        reading: str | None = None,
        span: tuple[int, int] | None = None,
    ) -> dict[str, Any]:
        if anchor is None:
            anchor = normalise(self.line_text(relpath, line))[:200] if line else relpath
        reading = reading or self.scan.reading_of(relpath)
        priority, why = self.priority(kind, relpath, unit, signals, findings, reasons)
        mechanisms_signalled = {
            m for s in signals for m in SIGNAL_MECHANISMS.get(str(s.get("kind")), ())
        }
        return {
            "id": surface_id(kind, relpath, anchor),
            "type": kind,
            "priority": priority,
            "file": relpath,
            "line": line,
            "unit": unit,
            "name": name,
            "reading": reading,
            "supported": reading != "unsupported",
            "why": why,
            "signals": [
                {
                    "kind": str(s.get("kind")),
                    "file": str(s.get("file")),
                    "line": int(s.get("line") or 0),
                    "symbol": redact(str(s.get("symbol") or ""))[:_SNIPPET],
                }
                for s in signals
            ],
            "findings": [
                {
                    "fingerprint": f.fingerprint,
                    "id": f.display_id,
                    "severity": f.severity.value,
                    "evidence_status": f.evidence_status.value,
                    "decision": f.decision.value,
                }
                for f in findings
            ],
            "span": list(span) if span else None,
            "hypotheses": self.hypotheses(kind, findings, mechanisms_signalled),
        }

    def hypotheses(
        self, kind: str, findings: list[Finding], signalled: set[str]
    ) -> list[dict[str, Any]]:
        """The type's hypotheses, then the pattern of every machine finding in scope that
        the type does not already carry: a finding never goes without its hypothesis."""
        pairs = list(HYPOTHESES[kind])
        for finding in findings:
            pattern = self.scan.policy.pattern_of(finding.display_id)
            if pattern is not None and (pattern.mechanism, pattern.id) not in pairs:
                pairs.append((pattern.mechanism, pattern.id))
        from_findings = {
            (p.mechanism, p.id)
            for f in findings
            if (p := self.scan.policy.pattern_of(f.display_id)) is not None
        }
        return [
            {
                "mechanism": m,
                "pattern": p,
                "signalled": m in signalled or (m, p) in from_findings,
            }
            for m, p in pairs
        ]

    def priority(
        self,
        kind: str,
        relpath: str,
        unit: str,
        signals: list[dict[str, Any]],
        findings: list[Finding],
        reasons: list[str],
    ) -> tuple[str, list[str]]:
        why = list(reasons)
        high = kind == "person_facing_unit"
        if kind in ("prompt", "remote_prompt"):
            kinds = sorted({str(s.get("kind")) for s in signals} & HIGH_SIGNAL_KINDS)
            if kinds:
                high = True
                why.append("signals in scope: " + ", ".join(kinds))
        if kind == "remote_prompt" and unit in self.person_units:
            high = True
            why.append("fetched at run time in a person-facing unit")
        if kind == "scheduler_sender":
            unit_kinds = {
                str(s.get("kind"))
                for rows in self.signals.values()
                for s in rows
                if str(s.get("unit")) == unit
            }
            if {"outreach_schedule", "outreach_send"} <= unit_kinds:
                high = True
                why.append("a schedule and a send in one unit")
            scoped = {str(s.get("kind")) for s in signals}
            if "outreach_personalised" in scoped:
                high = True
                why.append("personalised outreach")
            elif "outreach_send" in scoped and not high:
                high = True
                why.append("a send that reaches the person")
        serious = [
            f for f in findings if f.decision is Decision.VIOLATES or f.severity in _HIGH_SEVERITIES
        ]
        if serious:
            high = True
            why.append(
                "machine findings in scope: " + ", ".join(sorted({f.display_id for f in serious}))
            )
        # A test file is not the running system, so a surface there ranks low; never when a
        # machine finding in its scope is serious, and never in auditor mode, where the
        # audited team names the folders.
        if (
            kind != "person_facing_unit"
            and not serious
            and self.scan.mode != "auditor"
            and _is_test_path(relpath)
        ):
            why.append("in a test file")
            return "low", why
        return ("high" if high else "normal"), why


def _surfaces(scan: MachineScan) -> list[dict[str, Any]]:
    builder = _Builder(scan)
    inventory = scan.ctx.inventory
    out: list[dict[str, Any]] = []
    units = {unit.id: unit for unit in inventory.units or []}
    for unit_id in sorted(builder.person_units):
        unit = units[unit_id]
        root = unit.root if unit.root not in ("", ".") else "."
        sigs, found = builder.unit_scope(unit_id)
        out.append(
            builder.surface(
                "person_facing_unit",
                root,
                0,
                unit_id,
                name=getattr(unit, "manifest", None),
                signals=sigs,
                findings=found,
                reasons=["an AI surface with person input, prompts or a persona"],
                anchor=root,
                reading=_unit_reading(getattr(unit, "language", None)),
            )
        )
    # A prompt fetched at run time on the same line as a literal or an assembly is the
    # runtime surface: what the model reads there is not in the tree.
    seen_prompt: set[tuple[str, int]] = set()
    rows = sorted(
        inventory.prompts or [],
        key=lambda r: (
            str(r.get("file")),
            int(r.get("line") or 0),
            0 if str(r.get("kind")) in _REMOTE_KINDS else 1,
            str(r.get("kind")),
        ),
    )
    prompt_files: set[str] = set()
    for row in rows:
        relpath, line = str(row.get("file")), int(row.get("line") or 0)
        prompt_kind = str(row.get("kind"))
        if prompt_kind not in _PROMPT_KINDS | _REMOTE_KINDS or (relpath, line) in seen_prompt:
            continue
        seen_prompt.add((relpath, line))
        prompt_files.add(relpath)
        kind = "remote_prompt" if prompt_kind in _REMOTE_KINDS else "prompt"
        lo, hi = builder.span(kind, relpath, line, prompt_kind)
        out.append(
            builder.surface(
                kind,
                relpath,
                line,
                str(row.get("unit")),
                name=row.get("name"),
                signals=builder.scoped_signals(relpath, lo, hi),
                findings=builder.scoped_findings(relpath, lo, hi),
                reasons=[f"prompt material ({prompt_kind})"],
                anchor=relpath if prompt_kind == "file" else None,
                span=(lo, hi),
            )
        )
    # Instruction-shaped text in JS/TS that the inventory lists as a person signal and no
    # prompt row: a template literal the deep analysis does not read.
    for sig in sorted(
        inventory.person_signals or [],
        key=lambda r: (str(r.get("file")), int(r.get("line") or 0), str(r.get("kind"))),
    ):
        relpath, line = str(sig.get("file")), int(sig.get("line") or 0)
        if (
            str(sig.get("kind")) not in HIGH_SIGNAL_KINDS
            or scan.reading_of(relpath) != "read"
            or relpath in prompt_files
            or (relpath, line) in seen_prompt
        ):
            continue
        seen_prompt.add((relpath, line))
        lo, hi = builder.span("prompt", relpath, line)
        out.append(
            builder.surface(
                "prompt",
                relpath,
                line,
                str(sig.get("unit")),
                name=None,
                signals=builder.scoped_signals(relpath, lo, hi),
                findings=builder.scoped_findings(relpath, lo, hi),
                reasons=[f"instruction-shaped JS/TS text ({sig.get('kind')})"],
                span=(lo, hi),
            )
        )
    for call in sorted(
        inventory.llm_calls or [], key=lambda r: (str(r.get("file")), int(r.get("line") or 0))
    ):
        api = str(call.get("api") or "")
        if api.startswith(("import ", "from ")):
            continue
        relpath, line = str(call.get("file")), int(call.get("line") or 0)
        lo, hi = builder.span("model_entry", relpath, line)
        out.append(
            builder.surface(
                "model_entry",
                relpath,
                line,
                str(call.get("unit")),
                name=f"{call.get('provider') or 'model'} {api}".strip(),
                signals=builder.scoped_signals(relpath, lo, hi),
                findings=builder.scoped_findings(relpath, lo, hi),
                reasons=["a model call"],
                span=(lo, hi),
            )
        )
    for store in sorted(
        inventory.memory_stores or [], key=lambda r: (str(r.get("file")), int(r.get("line") or 0))
    ):
        relpath, line = str(store.get("file")), int(store.get("line") or 0)
        lo, hi = builder.span("memory_store", relpath, line)
        out.append(
            builder.surface(
                "memory_store",
                relpath,
                line,
                str(store.get("unit")),
                name=str(store.get("symbol") or "") or None,
                signals=builder.scoped_signals(relpath, lo, hi),
                findings=builder.scoped_findings(relpath, lo, hi),
                reasons=["a memory or profile store"],
                span=(lo, hi),
            )
        )
    for sig in sorted(
        inventory.person_signals or [],
        key=lambda r: (str(r.get("file")), int(r.get("line") or 0), str(r.get("kind"))),
    ):
        signal_kind = str(sig.get("kind"))
        if signal_kind in _SCHEDULER_KINDS:
            kind, reason = "scheduler_sender", f"a scheduler or sender ({signal_kind})"
        elif signal_kind in _PROFILE_KINDS:
            kind, reason = "profile_source", f"a profile source ({signal_kind})"
        elif signal_kind in _DESTINATION_KINDS:
            kind, reason = "external_destination", "person data sent to a profiling service"
        else:
            continue
        relpath, line = str(sig.get("file")), int(sig.get("line") or 0)
        lo, hi = builder.span(kind, relpath, line)
        out.append(
            builder.surface(
                kind,
                relpath,
                line,
                str(sig.get("unit")),
                name=redact(str(sig.get("symbol") or ""))[:_SNIPPET] or None,
                signals=builder.scoped_signals(relpath, lo, hi),
                findings=builder.scoped_findings(relpath, lo, hi),
                reasons=[reason],
                span=(lo, hi),
            )
        )
    out.extend(_finding_surfaces(builder, out))
    return _dedupe(out)


# The surface type a machine finding outside every surface becomes, by its pattern.
_TYPE_BY_PATTERN: dict[str, str] = {
    "storage": "memory_store",
    "transmission": "external_destination",
    "outreach": "scheduler_sender",
    "attachment_algorithm": "scheduler_sender",
    "scoring_for_influence": "profile_source",
    "profile_keyed_steering": "profile_source",
}


def _finding_surfaces(builder: _Builder, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A surface for every machine finding whose evidence falls in no surface's scope, so no
    rule hit goes unqueued. Unit-level findings (`.`, line 0) belong to their unit's
    person-facing surface when there is one."""
    covered: list[tuple[str, int, int]] = []
    for surface in surfaces:
        span = surface.get("span") or (1, 10**9)
        covered.append((surface["file"], int(span[0]), int(span[1])))
    units_with_surface = {s["unit"] for s in surfaces if s["type"] == "person_facing_unit"}
    extra: list[dict[str, Any]] = []
    for finding in builder.scan.findings:
        leg = finding.evidence[0] if finding.evidence else None
        if leg is None:
            continue
        if leg.file in (".", "") or leg.line == 0:
            if finding.scope.unit in units_with_surface:
                continue
            continue  # a unit-level fact with no person-facing unit: the unit is not a surface
        if any(file == leg.file and lo <= leg.line <= hi for file, lo, hi in covered):
            continue
        pattern = builder.scan.policy.pattern_of(finding.display_id)
        kind = _TYPE_BY_PATTERN.get(pattern.id if pattern else "", "prompt")
        record = builder.scan.walked.get(leg.file)
        unit = getattr(record, "unit", None) or finding.scope.unit or ""
        lo, hi = builder.span(kind, leg.file, leg.line)
        surface = builder.surface(
            kind,
            leg.file,
            leg.line,
            str(unit),
            name=finding.display_id,
            signals=builder.scoped_signals(leg.file, lo, hi),
            findings=builder.scoped_findings(leg.file, lo, hi),
            reasons=[f"a machine finding outside every other surface ({finding.display_id})"],
            span=(lo, hi),
        )
        covered.append((leg.file, lo, hi))
        extra.append(surface)
    return extra


def _unit_reading(language: str | None) -> str:
    if language in ("python",):
        return "deep"
    if language in ("typescript", "javascript"):
        return "read"
    if language in (None, "unknown", "other", "config"):
        return "text"
    return "unsupported"


def _dedupe(surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One surface per (type, file, line); ids made unique in line order (`-2`, `-3`)."""
    seen: set[tuple[str, str, int]] = set()
    kept: list[dict[str, Any]] = []
    for surface in surfaces:
        key = (surface["type"], surface["file"], surface["line"])
        if key in seen:
            continue
        seen.add(key)
        kept.append(surface)
    counts: dict[str, int] = {}
    for surface in sorted(kept, key=lambda s: (s["file"], s["line"], s["type"])):
        base = surface["id"]
        counts[base] = counts.get(base, 0) + 1
        if counts[base] > 1:
            surface["id"] = f"{base}-{counts[base]}"
    return kept


def _order(surface: dict[str, Any]) -> tuple[Any, ...]:
    return (
        PRIORITIES.index(surface["priority"]),
        SURFACE_TYPES.index(surface["type"]),
        surface["file"],
        surface["line"],
        surface["id"],
    )


# ---------------------------------------------------------------------------
# Untrusted text
# ---------------------------------------------------------------------------


def _untrusted(scan: MachineScan) -> tuple[list[dict[str, Any]], int]:
    """Every line addressed to an auditor or an AI tool, and every agent instruction file.
    All of them are kept: the assessment's gap check reads the whole list."""
    items: list[dict[str, Any]] = []
    for relpath in sorted(scan.walked):
        record = scan.walked[relpath]
        if PurePosixPath(relpath).name in AGENT_INSTRUCTION_FILES or relpath.startswith(
            _AGENT_INSTRUCTION_DIRS
        ):
            items.append(
                {
                    "file": relpath,
                    "line": 0,
                    "snippet": "",
                    "why": "a file of instructions or configuration addressed to coding agents",
                }
            )
        text = scan.ctx.texts.get(relpath)
        if text is None:
            text = walk.read_text(record.path)
        for number, line in enumerate((text or "").split("\n"), 1):
            if _UNTRUSTED_RE.search(line):
                items.append(
                    {
                        "file": relpath,
                        "line": number,
                        "snippet": redact(normalise(line))[:_SNIPPET],
                        "why": "text addressed to an auditor or an AI tool",
                    }
                )
    return items, len(items)


# ---------------------------------------------------------------------------
# The plan document
# ---------------------------------------------------------------------------


def plan_digest(plan: dict[str, Any]) -> str:
    """sha256 of the plan's canonical JSON without `generated_at`, `tool`, `plan_sha256`
    and the tree's absolute path: equal for equal trees wherever they are checked out."""
    body = {k: v for k, v in plan.items() if k not in ("generated_at", "tool", "plan_sha256")}
    body["target"] = {k: v for k, v in (plan.get("target") or {}).items() if k != "path"}
    # The tool's own output (records, assessments) is not part of the system: writing a
    # record into the tree does not change the plan of it.
    body["not_read"] = {
        k: v for k, v in (plan.get("not_read") or {}).items() if k != "own_output_skipped"
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_plan(scan: MachineScan, *, budget: int = DEFAULT_BUDGET) -> dict[str, Any]:
    """The plan document (see the module docstring)."""
    from aisafe.reporting.report import TOOL_NAME, tool_version

    if budget < 1:
        raise ValueError("the budget is at least one surface")
    surfaces = sorted(_surfaces(scan), key=_order)
    for rank, surface in enumerate(surfaces, 1):
        surface["rank"] = rank
    queued = [s["id"] for s in surfaces[:budget]]
    left_out = [s["id"] for s in surfaces[budget:]]
    untrusted, untrusted_total = _untrusted(scan)
    inventory = scan.ctx.inventory
    target = inventory.target or {}
    plan: dict[str, Any] = {
        "schema": PLAN_SCHEMA,
        "kind": PLAN_KIND,
        "mode": scan.mode,
        "tool": {"name": TOOL_NAME, "version": tool_version()},
        "generated_at": now_iso(),
        "target": {
            "path": scan.root.as_posix(),
            **scan.state.to_dict(),
        },
        "policy": {"version": scan.policy.version},
        "budget": budget,
        "counts": {
            "surfaces": len(surfaces),
            "queued": len(queued),
            "left_out": len(left_out),
            "by_priority": {p: sum(1 for s in surfaces if s["priority"] == p) for p in PRIORITIES},
            "left_out_high": sum(1 for s in surfaces[budget:] if s["priority"] == "high"),
            "unsupported": sum(1 for s in surfaces if not s["supported"]),
            "unsupported_files": sum(
                1 for rel in scan.walked if scan.reading_of(rel) == "unsupported"
            ),
            "tracked_not_walked": len(scan.tracked_not_walked),
        },
        "surfaces": surfaces,
        "queued": queued,
        "left_out": left_out,
        "unsupported": [s["id"] for s in surfaces if not s["supported"]],
        "untrusted_text": untrusted,
        "untrusted_text_total": untrusted_total,
        "not_read": {
            "own_output_skipped": list(inventory.own_output_skipped or []),
            "marker_skipped": list(target.get("marker_skipped") or []),
            "oversize_files": target.get("oversize_files"),
            # Files of the commit the walk never read (a skipped directory, a binary or
            # UTF-16 file, the size limit, the marker, an exclude), and walked files in a
            # language this version does not read.
            "tracked_not_walked": list(scan.tracked_not_walked),
            "unsupported_files": sorted(
                rel for rel in scan.walked if scan.reading_of(rel) == "unsupported"
            ),
        },
        "scan": {
            "findings": len(scan.findings),
            "by_rule": _by_rule(scan.findings),
            "unknown": len(scan.unknown),
        },
    }
    plan["plan_sha256"] = plan_digest(plan)
    return plan


def _by_rule(findings: Iterable[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.display_id] = counts.get(finding.display_id, 0) + 1
    return dict(sorted(counts.items()))


def render_plan(plan: dict[str, Any]) -> str:
    """The plan for a terminal: the counts, then one line per surface in rank order."""
    counts = plan["counts"]
    queued = set(plan["queued"])
    lines = [
        "aisafe investigate plan",
        "=======================",
        f"investigation plan | mode: {plan['mode']}",
        f"target: {plan['target']['path']} at {plan['target'].get('commit') or 'no commit'}"
        + (" (uncommitted changes)" if plan["target"].get("dirty") else ""),
        f"policy {plan['policy']['version']} | plan {plan['plan_sha256'][:16]}",
        (
            f"{counts['surfaces']} surfaces: {counts['by_priority']['high']} high, "
            f"{counts['by_priority']['normal']} normal, {counts['by_priority']['low']} low; "
            f"{counts['queued']} queued (budget {plan['budget']}), {counts['left_out']} left "
            f"out ({counts['left_out_high']} high), {counts['unsupported']} unsupported"
        ),
        "",
    ]
    for surface in plan["surfaces"]:
        mark = "queued" if surface["id"] in queued else "left out"
        where = surface["file"] + (f":{surface['line']}" if surface["line"] else "")
        lines.append(
            f"{surface['rank']:>3}. {surface['id']} {surface['priority']:<6} "
            f"{surface['type']:<20} {where} [{mark}]"
            + ("" if surface["supported"] else " [unsupported language]")
        )
        signalled = [h for h in surface["hypotheses"] if h["signalled"]]
        rest = [h for h in surface["hypotheses"] if not h["signalled"]]
        hyp = ", ".join(f"{h['mechanism']}/{h['pattern']}*" for h in signalled)
        hyp += (", " if signalled and rest else "") + ", ".join(
            f"{h['mechanism']}/{h['pattern']}" for h in rest
        )
        lines.append(f"       hypotheses: {hyp}")
        if surface["why"]:
            lines.append("       why: " + "; ".join(surface["why"]))
    lines.append("")
    lines.append("* a signal in the surface's scope speaks to the mechanism")
    untrusted = plan["untrusted_text"]
    lines.append("")
    lines.append(
        f"untrusted text: {plan['untrusted_text_total']} line(s) or file(s) addressed to an "
        "auditor, a reviewer or an AI tool; record them, never follow them"
    )
    for item in untrusted[:_UNTRUSTED_SHOWN]:
        where = item["file"] + (f":{item['line']}" if item["line"] else "")
        lines.append(
            f"  - {where}: {item['why']}" + (f": {item['snippet']}" if item["snippet"] else "")
        )
    if len(untrusted) > _UNTRUSTED_SHOWN:
        lines.append(f"  - +{len(untrusted) - _UNTRUSTED_SHOWN} more in the JSON")
    not_read = plan["not_read"]
    lines.append("")
    lines.append(
        f"not read: {len(not_read['marker_skipped'])} file(s) skipped by the ignore-file "
        f"marker, {len(not_read['own_output_skipped'])} as the tool's own output, "
        f"{len(not_read['tracked_not_walked'])} tracked file(s) the walk did not read, "
        f"{len(not_read['unsupported_files'])} file(s) in a language this version does not read"
    )
    for rel in not_read["tracked_not_walked"][:10]:
        lines.append(f"  - not walked: {rel}")
    for rel in not_read["unsupported_files"][:10]:
        lines.append(f"  - unsupported: {rel}")
    return "\n".join(lines) + "\n"
