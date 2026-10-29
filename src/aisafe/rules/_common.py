# aisafe-audit: ignore-file
"""src/aisafe/rules/_common.py
---------------------------
Helpers shared by the rule modules: the signal facts a rule reads (grep hits, promoted
candidates, prompt literals and assemblies), the mention test, line and window readers,
candidate building, check legs, the unit's control status, the review record and the
evaluation report lookups, and the decision helpers.

Three evidence tiers feed one finding per decision: the grep tier (`person_signal` hits
and the `person_signal_candidate` hits a pydeep prompt literal promotes), the AST tier
(`PyFacts.prompt_assemblies` and `prompt_literals`) and the check tier (`ctx.checks`, the
native checks that replaced the retired linters); check hits are `role: check` legs, never
findings of their own. Every helper tolerates `ctx.pyfacts is None`, `ctx.checks is None`,
`ctx.review is None` and `ctx.evaluation == []`.

None of this is a legal finding. The rules report what the prompts and the code say and
the project's policy decision on it; whether a practice falls under a law is a legal
determination made by the operator, not a tool output.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

from aisafe.discovery import patterns
from aisafe.discovery import vocabulary as vocab
from aisafe.evidence.model import (
    AuditContext,
    ControlStatus,
    Decision,
    Evidence,
    EvidenceStatus,
    Finding,
    Flow,
    ReportRecord,
    Severity,
    Unit,
    fingerprint,
)
from aisafe.rules import Candidate, SiteRef, file_text, hits_in, unit_of

__all__ = [
    "LEGAL_CAVEAT",
    "CODE_EXTS",
    "INFLUENCE_KINDS",
    "PERSON_KINDS",
    "PROFILE_KINDS",
    "CheckHitLike",
    "Signal",
    "Facts",
    "attach_check_legs",
    "candidate",
    "check_hits",
    "checks_by_group",
    "declared_purpose_for",
    "decides_about_a_person",
    "evaluation_demonstrates",
    "facts",
    "fiction_context",
    "flow_for",
    "has_ai_surface",
    "is_code_file",
    "is_mention",
    "legs_by_group",
    "line_at",
    "literal_text",
    "owning_unit",
    "posix",
    "refingerprint",
    "request_cue_nearby",
    "review_decision_for",
    "split_checks",
    "unit_control_status",
    "unit_has",
    "unit_id_of",
    "vulnerable_nearby",
    "window_text",
]

LEGAL_CAVEAT = (
    "Whether this practice falls under a law is a legal determination made by the "
    "operator, not a tool output. The finding reports what the code and the prompts say, "
    "and the project's policy decision on it."
)

WINDOW = 40
FUNCTION_WINDOW = 60
CHECK_ROLE = "check"
SURFACE_ROLE = "surface"

PROFILE_KINDS = frozenset({"profile_sdk", "profile_name", "profile_placeholder"})
# The kinds that say the system tries to influence the person; AUD-1106 asks what control
# stands on the response path of a unit carrying one.
INFLUENCE_KINDS = frozenset(
    {"engagement", "persona", "attachment", "steering", "inference", "monetisation"}
)
# Every kind that says the system touches people; the disclosure, control, review,
# supportive, neutral-information and user-set-reminder vocabularies are answers to
# those, not signals of their own.
PERSON_KINDS = (
    PROFILE_KINDS
    | INFLUENCE_KINDS
    | {
        "affect",
        "biometric_cat",
        "scoring",
        "objective_code",
        "vulnerable",
        "confidant",
        "memory",
        "romantic_role",
        "experiment",
        "outreach_personalised",
    }
)

CODE_EXTS = frozenset(
    {
        ".py",
        ".pyi",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".go",
        ".java",
        ".kt",
        ".rb",
        ".rs",
        ".cs",
        ".php",
        ".swift",
        ".scala",
    }
)


# ---------------------------------------------------------------------------
# Signals: grep hits, promoted candidates, prompt literals
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Signal:
    file: str
    line: int
    kind: str
    key: str
    symbol: str
    unit: str | None
    promoted: bool = False  # a candidate a prompt literal or an assembly vouched for


@dataclass
class Facts:
    signals: list[Signal] = field(default_factory=list)
    literals: list[Any] = field(default_factory=list)  # pydeep.PromptLiteral
    assemblies: list[Any] = field(default_factory=list)  # pydeep.Assembly

    def by_kind(self, *kinds: str) -> list[Signal]:
        wanted = set(kinds)
        return [s for s in self.signals if s.kind in wanted]

    def in_unit(self, unit_id: str | None, *kinds: str) -> list[Signal]:
        return [s for s in self.by_kind(*kinds) if s.unit == unit_id]

    def in_file(self, file: str, *kinds: str) -> list[Signal]:
        return [s for s in self.by_kind(*kinds) if s.file == file]

    def literal_at(self, file: str, line: int) -> Any | None:
        for literal in self.literals:
            if posix(literal.file) == file and literal.line <= line <= literal.end_line:
                return literal
        return None

    def same_literal(self, a: Signal, b: Signal) -> bool:
        """Both signals sit inside one prompt literal (the strongest co-location)."""
        if a.file != b.file:
            return False
        literal = self.literal_at(a.file, a.line)
        return literal is not None and literal is self.literal_at(b.file, b.line)


def posix(path: Any) -> str:
    return str(path).replace("\\", "/")


def facts(ctx: AuditContext) -> Facts:
    """The signal facts for a run, computed once and cached on the context."""
    cache = getattr(ctx, "cache", None)
    if isinstance(cache, dict) and "rules.facts" in cache:
        return cache["rules.facts"]
    out = Facts()
    pyfacts = ctx.pyfacts
    out.literals = list(getattr(pyfacts, "prompt_literals", None) or [])
    out.assemblies = list(getattr(pyfacts, "prompt_assemblies", None) or [])
    for hit in hits_in(ctx, "person_signal"):
        out.signals.append(
            Signal(hit.file, hit.line, vocab.kind_of(hit.key), hit.key, hit.snippet, hit.unit)
        )
    for hit in hits_in(ctx, "person_signal_candidate"):
        kind = vocab.kind_of(hit.key)
        promoted = out.literal_at(hit.file, hit.line) is not None
        if not promoted and kind == "profile_name":
            promoted = _named_in_assembly(out, hit.file, hit.line, hit.snippet)
        if promoted:
            out.signals.append(
                Signal(hit.file, hit.line, kind, hit.key, hit.snippet, hit.unit, promoted=True)
            )
    out.signals.sort(key=lambda s: (s.file, s.line, s.kind, s.key))
    if isinstance(cache, dict):
        cache["rules.facts"] = out
    return out


def _named_in_assembly(out: Facts, file: str, line: int, snippet: str) -> bool:
    """A profile-named identifier on `line` that a prompt assembly within the window reads."""
    names = {
        tok
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", snippet)
        if vocab.PROFILE_NAME_RE.search(tok)
    }
    if not names:
        return False
    for assembly in out.assemblies:
        if posix(assembly.file) != file or not (line <= assembly.line <= line + WINDOW):
            continue
        if names & set(assembly.source_names):
            return True
    return False


# ---------------------------------------------------------------------------
# Text readers
# ---------------------------------------------------------------------------


def line_at(ctx: AuditContext, file: str, line: int, fallback: str = "") -> str:
    text = file_text(ctx, file)
    if not text or line < 1:
        return fallback
    lines = text.split("\n")
    if line > len(lines):
        return fallback
    return lines[line - 1].rstrip("\r").strip() or fallback


def literal_text(ctx: AuditContext, literal: Any) -> str:
    text = file_text(ctx, posix(literal.file))
    if not text:
        return ""
    lines = text.split("\n")
    return "\n".join(lines[literal.line - 1 : literal.end_line])


def window_text(ctx: AuditContext, file: str, line: int, span: int) -> str:
    """`span` lines starting at `line` (1-based)."""
    text = file_text(ctx, file)
    if not text:
        return ""
    lines = text.split("\n")
    return "\n".join(lines[max(0, line - 1) : line - 1 + span])


def around_text(ctx: AuditContext, file: str, line: int, before: int, after: int) -> str:
    """The lines from `line - before` to `line + after`, inclusive, clipped to the file."""
    text = file_text(ctx, file)
    if not text:
        return ""
    lines = text.split("\n")
    lo = max(0, line - 1 - before)
    hi = min(len(lines), line + after)
    return "\n".join(lines[lo:hi])


def is_code_file(relpath: str) -> bool:
    return "." + relpath.rsplit(".", 1)[-1].lower() in CODE_EXTS if "." in relpath else False


def _row_regex(key: str) -> re.Pattern[str] | None:
    for row_key, rx in vocab.PERSON_SIGNAL_PATTERNS:
        if row_key == key:
            return rx
    return None


_PROMPT_KEY_RE = re.compile(patterns._PROMPT_LHS, re.I)
CONFIG_PROSE_NOTE = (
    "prose in a configuration file that is not a prompt file (a description, a label, a "
    "comment) under no prompt key: recorded for review, not read as an instruction to the model"
)


def config_prose(ctx: AuditContext, signal: Signal) -> bool:
    """
    The signal sits in a configuration file that is not a prompt file, on a line that
    carries no prompt key (`system:`, `prompt:`, `instructions:` ...): a description or a
    comment that names the practice. The charter records it for review; only prompt
    material can be an instruction to the model.
    """
    if is_code_file(signal.file):
        return False
    lang = next(
        (
            getattr(record, "lang", None)
            for record in ctx.files
            if getattr(record, "relpath", None) == signal.file
        ),
        None,
    )
    if lang != "config":
        return False
    from aisafe.discovery.discover import is_prompt_file

    if is_prompt_file(signal.file):
        return False
    return _PROMPT_KEY_RE.search(line_at(ctx, signal.file, signal.line)) is None


def reviewed_if_config_prose(
    ctx: AuditContext,
    signal: Signal,
    status: EvidenceStatus,
    decision: Decision,
    notes: str,
) -> tuple[EvidenceStatus, Decision, str]:
    """The prompt-material status and decision, lowered to a detected signal for review
    when the signal is configuration prose (see `config_prose`)."""
    if config_prose(ctx, signal):
        return EvidenceStatus.DETECTED_SIGNAL, Decision.REVIEW, f"{notes}; {CONFIG_PROSE_NOTE}"
    return status, decision, notes


def is_mention(ctx: AuditContext, signal: Signal) -> bool:
    """A quoted or discussed phrase in prompt material: `Explain how we detect social
    scoring` is a mention of the practice, not an instruction to perform it."""
    rx = _row_regex(signal.key)
    line = line_at(ctx, signal.file, signal.line)
    if rx is None or not line:
        return False
    match = rx.search(line)
    if match is None:
        return False
    if is_code_file(signal.file):
        # A prompt literal in code is quoted by nature; only a discussion cue in the
        # window around the match makes it a mention there.
        before = line[max(0, match.start() - 80) : match.start()]
        after = line[match.end() : match.end() + 80]
        return bool(
            patterns.DISCUSSION_CUES.search(before) or patterns.DISCUSSION_CUES.search(after)
        )
    return patterns.is_mention(line, match.start(), match.end())


# A request for analysis of material the person submitted, within reach of an inference
# instruction: "when the user asks you to assess the tone of their email" is a task, not
# profiling. Read from the same line, up to 60 characters before the match.
REQUEST_CUES = re.compile(
    r"\b(?:the\s+user\s+(?:asks?|wants?|requests?|submits?|provides?|shares?)|when\s+asked"
    r"|on\s+request|if\s+(?:asked|requested)|analy[sz]e\s+the\s+(?:text|email|e-mail|document"
    r"|passage|message|draft|essay|transcript)\s+(?:the\s+user|they)\s+(?:provided|shared|sent"
    r"|submitted)|their\s+own\s+(?:text|writing|email|message))\b",
    re.I,
)


def request_cue_nearby(ctx: AuditContext, signal: Signal, chars: int = 60) -> bool:
    """True when the line reads as the person asking for the analysis of their material."""
    rx = _row_regex(signal.key)
    line = line_at(ctx, signal.file, signal.line)
    if rx is None or not line:
        return False
    match = rx.search(line)
    if match is None:
        return False
    before = line[max(0, match.start() - chars) : match.start()]
    after = line[match.end() : match.end() + chars]
    return bool(REQUEST_CUES.search(before) or REQUEST_CUES.search(after))


# A quoted string on a code line is UI text (a reason, a message), not the decision; the
# identifiers around it are what say whether a person is decided about.
STRING_LITERAL_RE = re.compile(r"""[rbfuRBFU]{0,2}(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')""")
DECISION_VERB_RE = re.compile(
    r"\b(?:approve|reject|deny|hire|fire|terminate|accept|grant|disqualify|eligib\w*|score|rank)\w*\b",
    re.I,
)


def decides_about_a_person(window: str) -> bool:
    """A decision function is about a PERSON only when the person noun sits in the
    signature (`def approve_tenant(applicant)`) or on a code line that also carries a
    decision verb. Comments and docstrings do not count."""
    lines = window.split("\n")
    if not lines:
        return False
    if vocab.PERSON_NOUN.search(STRING_LITERAL_RE.sub(" ", lines[0])):
        return True
    in_doc = False
    for line in lines[1:]:
        stripped = line.strip()
        if stripped.count('"""') % 2 == 1 or stripped.count("'''") % 2 == 1:
            in_doc = not in_doc
            continue
        if in_doc or stripped.startswith("#"):
            continue
        code = STRING_LITERAL_RE.sub(" ", stripped.split("#", 1)[0])
        if DECISION_VERB_RE.search(code) and vocab.PERSON_NOUN.search(code):
            return True
    return False


# ---------------------------------------------------------------------------
# Units and candidates
# ---------------------------------------------------------------------------


def owning_unit(ctx: AuditContext, relpath: str) -> Unit | None:
    unit = unit_of(ctx, relpath)
    if unit is not None:
        return unit
    key = posix(relpath)
    best: Unit | None = None
    for cand in ctx.inventory.units:
        root = cand.root or "."
        if root == "." or key == root or key.startswith(root.rstrip("/") + "/"):
            if best is None or len(root) > len(best.root or "."):
                best = cand
    return best


def unit_id_of(ctx: AuditContext, relpath: str) -> str | None:
    unit = owning_unit(ctx, relpath)
    return unit.id if unit is not None else None


def has_ai_surface(ctx: AuditContext) -> bool:
    return any(getattr(u, "ai_surface", False) for u in (ctx.inventory.units or []))


def unit_has(ctx: AuditContext, unit_id: str, section: str) -> bool:
    for entry in getattr(ctx.inventory, section, None) or []:
        if isinstance(entry, dict) and entry.get("unit") == unit_id:
            return True
    return False


def candidate(
    ctx: AuditContext,
    signal_or_file: Signal | str,
    line: int | None = None,
    *,
    notes: str,
    sub: str | None = None,
    severity: Severity | None = None,
    snippet: str | None = None,
    evidence_status: EvidenceStatus | None = None,
    decision: Decision | None = None,
    flow: Flow | None = None,
    encoded_objective: str | None = None,
    person_data_use: str | None = None,
    control_status: ControlStatus | None = None,
    affected_population: str | None = None,
    coverage_gaps: tuple[str, ...] = (),
    uncertainty: str | None = None,
) -> Candidate:
    """A grouping candidate from a signal (or a file and line). The declared purpose of the
    owning unit is filled from the review records when one covers it."""
    if isinstance(signal_or_file, Signal):
        file, line_no = signal_or_file.file, signal_or_file.line
        fallback = signal_or_file.symbol
    else:
        file, line_no = signal_or_file, int(line or 0)
        fallback = ""
    text = snippet if snippet is not None else line_at(ctx, file, line_no, fallback)
    unit = owning_unit(ctx, file)
    return Candidate(
        site=SiteRef(file, line_no, text or fallback or "(no text)"),
        unit=unit,
        notes=notes,
        sub=sub,
        severity=severity,
        evidence_status=evidence_status,
        decision=decision,
        flow=flow,
        encoded_objective=encoded_objective,
        person_data_use=person_data_use,
        control_status=control_status,
        affected_population=affected_population,
        declared_purpose=declared_purpose_for(ctx, unit.id if unit else None, file),
        coverage_gaps=coverage_gaps,
        uncertainty=uncertainty,
    )


def refingerprint(finding: Finding) -> str:
    display = f"{finding.id}/{finding.sub}" if finding.sub else finding.id
    return fingerprint(display, finding.evidence[0].file, finding.evidence[0].snippet)


# ---------------------------------------------------------------------------
# Check legs (the native checks that replaced the retired linters)
# ---------------------------------------------------------------------------


class CheckHitLike:
    """Duck type of `analysis.checks.CheckHit`: check, file, line, snippet, title, extra."""

    check: str
    file: str
    line: int
    snippet: str
    title: str
    extra: dict[str, Any]


def check_hits(ctx: AuditContext, *names: str) -> list[Any]:
    """The hits for `names` from `ctx.checks`, or none when the checks did not run."""
    checks = getattr(ctx, "checks", None)
    hits_fn = getattr(checks, "hits", None)
    if not callable(hits_fn):
        return []
    return list(hits_fn(*names))


def attach_check_legs(
    findings: list[Finding], legs: dict[tuple[str | None, str | None], list[Any]]
) -> None:
    """Append `role: check` evidence to each grouped finding, deduped by (file, line)."""
    for finding in findings:
        unit_id = finding.scope.unit
        key = (unit_id, finding.sub)
        hits = legs.get(key) or []
        seen = {(e.file, e.line) for e in finding.evidence if e.role == CHECK_ROLE}
        for hit in sorted(hits, key=lambda h: (h.file, h.line, h.check)):
            if (hit.file, hit.line) in seen:
                continue
            seen.add((hit.file, hit.line))
            finding.evidence.append(
                Evidence(
                    role=CHECK_ROLE,
                    file=hit.file,
                    line=hit.line,
                    snippet=f"{hit.check}: {hit.title}",
                )
            )


def split_checks(
    out: Facts, hits: list[Any], kinds: tuple[str, ...]
) -> tuple[list[Any], list[Any]]:
    """(anchors, legs): a check hit in a file that already carries a grep signal of one of
    `kinds` is a leg on that file's finding; one with no site of its own in the file
    anchors a candidate, so the check tier alone still produces the finding."""
    covered = {s.file for s in out.by_kind(*kinds)}
    anchors = [h for h in hits if h.file not in covered]
    legs = [h for h in hits if h.file in covered]
    return anchors, legs


def legs_by_group(ctx: AuditContext, hits: list[Any], sub: str | None) -> dict:
    out: dict[tuple[str | None, str | None], list[Any]] = {}
    for hit in hits:
        out.setdefault((unit_id_of(ctx, hit.file), sub), []).append(hit)
    return out


def checks_by_group(ctx: AuditContext, names: tuple[str, ...], sub: str | None) -> dict:
    return legs_by_group(ctx, check_hits(ctx, *names), sub)


# ---------------------------------------------------------------------------
# Context: fiction framing, vulnerable groups, chains, review records, evaluations
# ---------------------------------------------------------------------------


def fiction_context(ctx: AuditContext, out: Facts, file: str, line: int) -> bool:
    """A fiction or roleplay framing applies to this line: a `fiction` signal in the same
    prompt literal, or anywhere in the same prompt file. Recorded on the finding; never
    an exemption (policy: not_automatic_exemptions)."""
    literal = out.literal_at(file, line)
    for other in out.in_file(file, "fiction"):
        if literal is None:
            if not is_code_file(file) or out.literal_at(file, other.line) is None:
                return True
            continue
        if out.literal_at(file, other.line) is literal:
            return True
    return False


def vulnerable_nearby(ctx: AuditContext, out: Facts, signal: Signal) -> str | None:
    """The vulnerable-group word that co-occurs with the signal, in the same prompt literal
    when there is one, else anywhere in the same file's signals."""
    literal = out.literal_at(signal.file, signal.line)
    if literal is not None:
        match = vocab.VULNERABLE_GROUP.search(literal_text(ctx, literal))
        return match.group(0) if match else None
    for other in out.in_file(signal.file, "vulnerable"):
        if not is_mention(ctx, other):
            return other.symbol
    return None


def flow_for(
    ctx: AuditContext,
    file: str,
    line: int,
    window: int = WINDOW,
    out: Facts | None = None,
) -> Flow | None:
    """The reconstructed chain whose prompt link sits at `file`:`line`: inside the prompt
    literal that covers the line when `out` (the signal facts) is given, else within
    `window` lines of the link. None when no chain reaches the line."""
    key = posix(file)
    flows = getattr(ctx, "flows", None) or []
    if out is not None:
        literal = out.literal_at(key, line)
        if literal is not None:
            for flow in flows:
                for link in flow.links:
                    if link.kind == "prompt" and link.file == key and link.line == literal.line:
                        return flow
    best: Flow | None = None
    best_distance = window + 1
    for flow in flows:
        for link in flow.links:
            if link.kind != "prompt" or link.file != key:
                continue
            distance = abs(int(link.line) - int(line))
            if distance < best_distance:
                best, best_distance = flow, distance
    return best


def declared_purpose_for(ctx: AuditContext, unit_id: str | None, relpath: str | None) -> str | None:
    """The `declared_purpose` of the review record covering the unit (and file), else None."""
    review = getattr(ctx, "review", None)
    records = getattr(review, "records", None) or []
    for record in records:
        covers = getattr(record, "covers", None)
        if callable(covers) and covers(unit_id, relpath):
            purpose = getattr(record, "declared_purpose", None)
            if isinstance(purpose, str) and purpose.strip():
                return purpose.strip()
    return None


def review_decision_for(ctx: AuditContext, finding_fingerprint: str) -> Any | None:
    """A contextual decision recorded for the fingerprint in a review record, else None."""
    review = getattr(ctx, "review", None)
    records = getattr(review, "records", None) or []
    for record in records:
        decision_for = getattr(record, "decision_for", None)
        if callable(decision_for):
            decision = decision_for(finding_fingerprint)
            if decision is not None:
                return decision
    return None


def _report_date(record: ReportRecord) -> date | None:
    raw = record.generated_at
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).date()
    except ValueError:
        return None


def evaluation_demonstrates(
    ctx: AuditContext, family: str, max_age_days: int
) -> tuple[bool | None, ReportRecord | None]:
    """
    What the freshest evaluation report in the tree says about `family`:
    `(True, record)` when it sent the family within `max_age_days` and every case passed;
    `(False, record)` when it sent the family and any case failed, was missing or errored;
    `(None, record_or_None)` when no fresh report sent the family (absent, stale, skipped).
    A stale report is never a demonstration; a failing one is observed behaviour.
    """
    freshest: ReportRecord | None = None
    for record in getattr(ctx, "evaluation", None) or []:
        if family not in (record.families or []):
            by_family = (record.body or {}).get("by_family") or {}
            if family not in by_family:
                continue
        if freshest is None or (record.age_days or 0) < (freshest.age_days or 0):
            freshest = record
    if freshest is None:
        return None, None
    age = freshest.age_days
    if age is None or age > max_age_days:
        return None, freshest
    counts = ((freshest.body or {}).get("by_family") or {}).get(family) or {}
    sent = int(counts.get("sent", 0) or 0)
    if sent == 0:
        return None, freshest
    failed = int(counts.get("failed", 0) or 0) + int(counts.get("errors", 0) or 0)
    skipped = int(counts.get("skipped", 0) or 0) + int(counts.get("inconclusive", 0) or 0)
    if failed:
        return False, freshest
    if skipped:
        # A case that could not be judged is not a pass: the family was not demonstrated.
        return None, freshest
    return True, freshest


# ---------------------------------------------------------------------------
# Control status on a unit's response path
# ---------------------------------------------------------------------------

_TEST_FILE_RE = re.compile(
    r"(?:^|/)(?:tests?|__tests__|spec)/|(?:^|/)test_[^/]+\.py$|_test\.(?:py|go)$|\.(?:test|spec)\.(?:[cm]?[jt]sx?)$"
    r"|Tests?\.(?:java|kt|cs|scala)$"
)
_CALL_SHAPE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\s*\(")
_IMPORT_LINE_RE = re.compile(
    r"^\s*(?:from\s+\S+\s+import\b|import\s+\S+|const\s+\{?[^=]*\}?\s*=\s*require\(|import\s*\{)"
)


def unit_control_status(
    ctx: AuditContext,
    out: Facts,
    unit: Unit,
    *,
    control_kind: str = "manipulation_control",
    demonstrated_by: tuple[str, ...] = (),
    max_age_days: int = 30,
) -> tuple[ControlStatus, list[Signal], ReportRecord | None]:
    """
    The strongest status a control of `control_kind` reaches in `unit`, with the signals
    that earned it and the evaluation report when one demonstrated it.

    `none`: no symbol. `claimed`: the symbol appears only in docs, config, or an import
    line, or in code with no call shape. `wired`: a call-shaped use in a file that also
    holds a model call or a reply return (AST when Python: `PyFacts.llm_calls` /
    `reply_returns` name the file; grep otherwise: an `llm_call` hit in the same file).
    `exercised`: a test file in the unit references the symbol as well. `demonstrated`:
    a fresh evaluation report passed every case of one of `demonstrated_by`.
    None of these resolves the objective or inference reported on the unit.
    """
    signals = out.in_unit(unit.id, control_kind)
    status = ControlStatus.NONE
    if signals:
        status = ControlStatus.CLAIMED
    model_files = {h.file for h in hits_in(ctx, "llm_call", unit=unit.id)}
    pyfacts = ctx.pyfacts
    for site in getattr(pyfacts, "llm_calls", None) or []:
        model_files.add(posix(site.file))
    for site in getattr(pyfacts, "reply_returns", None) or []:
        model_files.add(posix(site.file))
    wired = False
    exercised = False
    for signal in signals:
        line = line_at(ctx, signal.file, signal.line, signal.symbol)
        if _TEST_FILE_RE.search(signal.file):
            exercised = True
            continue
        if not is_code_file(signal.file) or _IMPORT_LINE_RE.match(line):
            continue
        if _CALL_SHAPE_RE.search(line) and signal.file in model_files:
            wired = True
    if wired:
        status = ControlStatus.WIRED
        if exercised:
            status = ControlStatus.EXERCISED
    report: ReportRecord | None = None
    for family in demonstrated_by:
        verdict, record = evaluation_demonstrates(ctx, family, max_age_days)
        if verdict is True:
            status = ControlStatus.DEMONSTRATED
            report = record
            break
    return status, signals, report


# ---------------------------------------------------------------------------
# Surface legs
# ---------------------------------------------------------------------------


def surface_legs(ctx: AuditContext, signals: list[Signal], cap: int = 3) -> list[Evidence]:
    """`role: surface` legs for the lines that set a role or an objective, one per line."""
    legs: list[Evidence] = []
    seen: set[tuple[str, int]] = set()
    for signal in sorted(signals, key=lambda s: (s.file, s.line)):
        if (signal.file, signal.line) in seen:
            continue
        seen.add((signal.file, signal.line))
        legs.append(
            Evidence(
                role=SURFACE_ROLE,
                file=signal.file,
                line=signal.line,
                snippet=line_at(ctx, signal.file, signal.line, signal.symbol),
            )
        )
        if len(legs) >= cap:
            break
    return legs
