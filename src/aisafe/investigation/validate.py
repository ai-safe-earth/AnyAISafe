"""src/aisafe/investigation/validate.py
-------------------------------------
`aisafe investigate validate FILE|DIR`: the mechanical check of investigation records
against the audited tree. Deterministic; no model, no network.

A record is **rejected** when a required field is empty or malformed; when a cited file is
not one the scan walked, or (in a git tree) not one the commit tracks; when a quote is not
at the cited line or a content hash differs; when the record was made at another commit or
in another mode; when its surface id names another surface of the plan, or no link, and no
citation ruling out a link the pattern requires, sits in its surface's file (a person-facing
unit: no link in one of the unit's files); when its free text pronounces a verdict or a
quote carries a secret-shaped string; when a remediation step already passes (it tests
nothing) or a regression step fails; when a file it depends on has changed; when its id is
used twice; or when it supersedes an unknown record, a record of another mechanism, surface
or pattern, a violation with a weaker claim (a closing record never lowers a violation), or
a proposed violation with a record that does not propose one, whatever became of the
proposal; naming a record of another commit replaces nothing, so it needs none of that. In a
directory, every `*.json` is a record, or a rejected one, unless it carries the exact label
of another document of the workbench: a file that may be a record is never dropped. A
skeptic pass and a sign-off are skipped even when named one by one; `signoff.py` reads the
sign-offs.

An accepted record keeps its proposal only as far as the evidence carries it. Each
downgrade is written down in `notes`:

- `observed_behavior` becomes `supported_mechanism`: a record reads code, and observed
  behaviour comes only from an evaluation report;
- a link does not count on a comment, an import, a string standing as a statement or, in
  Python, a line that never runs; an edge between two files counts only with a hop that
  imports or calls the other file;
- a `violates_policy` proposal becomes `unknown` / `requires_contextual_review` when a link
  the pattern requires is missing, only runtime-only, in an unsupported language, or not
  connected to the rest of the chain by supported links; when a pattern's absent control is
  not shown absent on the path (with where it was looked for); it becomes a review when a
  benign reading was found supported, when questions stay open or evidence is missing;
- a `no_violation_identified_in_scope` proposal stays one only when the record shows the
  chain broken (every required link either traced or ruled out in `absent_links`, at least
  one ruled out) or, for a pattern with an absent control, a complete chain with the control
  on it (`_control_problem` says what that takes); a complete trace with a benign reading is
  for a person to weigh, so it becomes a review; a ruled-out link the scan lists needs a
  citation of each of those rows, in the units of the record's surface and links (for the
  prompt, the objective or the inference of a prompt surface, the rows inside that surface),
  and of each link the scan's syntax tree established for the pattern, whatever its kind; an
  objective or an inference is a signal of that kind or a finding that reports it, a store a
  memory row or an analytics row; a surface fetched at run time cannot be closed from the
  tree, a prompt, person-data, objective or inference link cannot be ruled out while the
  tree fetches a prompt at run time, and a control cannot sit in a fetched prompt: the claim
  is unknown and the link or control counts as runtime-only. A fetch is the whole statement
  the scan's row sits on and the statements fed from a name it bound; every prompt-borne link
  on a surface fetched at run time is runtime-only;
- a closing by a control stays one only when the control and every link of its chain (on a
  unit surface, every model call of the unit too) are in Python the syntax tree read: a file
  that parses, that the deep pass has a module for, with no lone carriage return. Elsewhere
  the machine cannot show a control runs, so the claim is a review, and a person can still
  close it;
- a `supported_mechanism` claim with a required link that is only runtime-only becomes
  `unknown` / `requires_contextual_review`, whatever the record proposed: a review too.

A skeptic result counts only when its file sits next to the record (a bare file name, a
regular file of at most 8 MiB, checked before anything opens it), is bound to it
(`record_sha256`), was written in another session than the investigation, and every claim in
it says what was tried, why, and is `upheld` or `refuted`; a pass with one refuted claim is a
refutation.
"""

from __future__ import annotations

import ast
import io
import json
import operator
import re
import stat
import tokenize
from bisect import bisect_right
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from aisafe.analysis.flows import INFERENCE_KINDS, OBJECTIVE_KINDS
from aisafe.evidence.model import (
    LINK_KINDS_BY_VIEW,
    MODES,
    Decision,
    EvidenceStatus,
    Flow,
    FlowLink,
    redact,
)
from aisafe.investigation.records import (
    COUNTER_RESULTS,
    HOW,
    ID_RE,
    INVESTIGATION_KIND,
    INVESTIGATION_SCHEMA,
    ON_PATH,
    SHA_RE,
    SIGNOFF_KIND,
    SIGNOFF_SCHEMA,
    SKEPTIC_KIND,
    SKEPTIC_RESULTS,
    SKEPTIC_SCHEMA,
    STEP_KINDS,
    STEP_PURPOSES,
    RecordError,
    load_json,
    record_digest,
    verdict_words_in,
)
from aisafe.investigation.scan import MachineScan
from aisafe.investigation.text import (
    content_sha256,
    file_lines,
    normalise,
    quote_at,
    quote_in_text,
)

__all__ = [
    "SIGNOFF_SKIPPED",
    "RecordResult",
    "ValidationRun",
    "find_record_files",
    "quote_copies",
    "quote_places",
    "quote_spans",
    "render_validation",
    "run_step",
    "validate_paths",
    "validate_record",
]

# How `find_record_files` lists a sign-off: `aisafe assess` reads the sign-offs from it.
SIGNOFF_SKIPPED = "a sign-off"
_FP_RE = re.compile(r"^[0-9a-f]{16}$")
_SURFACE_ID_RE = re.compile(r"^s-[0-9a-f]{12}(?:-\d+)?$")
_FUTURE_TOLERANCE = timedelta(hours=1)
_MAX_RECORD_BYTES = 8 * 1024 * 1024
_MAX_SEARCHED_BYTES = 8 * 1024 * 1024
# Documents of the workbench that are not records, by their exact label (`aisafe audit`
# reports and evaluation reports too). Anything else in a records directory is a record, or
# one that broke.
_OTHER_DOCUMENTS = frozenset(
    {
        ("aisg/1", "audit"),
        ("aisg/1", "inventory"),
        ("aisg/1", "evaluation"),
        *(
            (f"aisg/{name}/1", name)
            for name in (
                "investigation-plan",
                "investigation-validation",
                "assessment",
                "engagement",
                "bundle",
                "evidence-requests",
                "auditee-response",
                "qa-signoff",
                "signoff",
            )
        ),
    }
)
# A skeptic file is named, never reached: no separator, no drive, no stream, no `..`. The
# name is checked as text, because opening a path that names a host starts a network sign-in.
_SKEPTIC_NAME_RE = re.compile(r"(?!\.+$)[A-Za-z0-9._-]{1,128}")
_OTHER_COMMIT = "the record was made at commit"
_UNIT_SURFACES = frozenset({"person_facing_unit"})
_RUNTIME_SURFACES = frozenset({"remote_prompt"})
_CLOSE = Decision.NO_VIOLATION.value
_VIOLATES = Decision.VIOLATES.value
_REVIEW = Decision.REVIEW.value
_SUPPORTED = EvidenceStatus.SUPPORTED_MECHANISM.value
_UNKNOWN = EvidenceStatus.UNKNOWN.value
_OBSERVED = EvidenceStatus.OBSERVED_BEHAVIOR.value
_SIGNAL = EvidenceStatus.DETECTED_SIGNAL.value
# Kinds the scan can contradict when a record rules them out, by inventory section.
_SCAN_ROWS = {
    "ingress": "ingress",
    "collection": "ingress",
    "intervention": "llm_calls",
    "prompt": "prompts",
    "storage": "person_signals",
    "person_data": "person_signals",
    "transmission": "person_signals",
    "objective": "person_signals",
    "inference": "person_signals",
}
# For the kinds read from the person signals, which signal kinds count. A store is what
# AUD-1101/store reports: a memory row (`inventory.memory_stores` lists those) or an analytics
# row, whose vendor keeps what it is sent.
_SIGNAL_ROWS = {
    "person_data": frozenset({"profile_name", "profile_placeholder", "profile_sdk"}),
    "transmission": frozenset({"profile_sdk"}),
    "storage": frozenset({"memory", "profile_sdk"}),
    "objective": OBJECTIVE_KINDS,
    "inference": INFERENCE_KINDS,
}
# Kinds a rule can report with no inventory row: a prompt literal in Python gives a finding,
# and the signal under it stays a candidate. A prompt surface holds these itself.
_FINDING_ROWS = ("objective", "inference")
_CLAIM_RANK = {"establishes": 2, "review": 1, "closes": 0}
# Absent controls that are a change to the data: the send must follow the transformation.
_TRANSFORMING_CONTROLS = frozenset({"anonymisation"})
# What leaves the service with the person's data: each must follow the transformation.
_SEND_KINDS = frozenset({"transmission", "logging"})
# Kinds a prompt carries: a line that fetches the prompt shows none of them, and none can be
# ruled out while what the prompt says is not in the tree.
_PROMPT_BORNE = ("prompt", "person_data", "objective", "inference")
# Lines of code that name a control and run nothing: a comment, an import, a definition's
# header. Python's are also read from its syntax tree (`_Checker.inert_lines`).
_NAMES_ONLY_RE = re.compile(
    r"""^\s*(?:$|#|//|/\*|\*|"{3}|'{3}|from\s+\S+\s+import\b|import\b|export\s+\{"""
    r"""|(?:const|let|var)\s+\{?[^=]*\}?\s*=\s*require\("""
    r"""|(?:export\s+(?:default\s+)?)?(?:async\s+)?(?:function\*?|class)\s+\w"""
    # A function held in a name or a property: `const f = (x) => {`, `f: async x => x,`.
    r"""|(?:export\s+)?(?:(?:const|let|var)\s+[\w$]+\s*(?::[^=]+)?=|[\w$]+\s*[:=])\s*"""
    r"""(?:async\s+)?(?:function\b|(?:<[^>]*>\s*)?(?:\([^)]*\)|[\w$]+)\s*(?::[^=]+)?=>))"""
)
# What names a thing and is no code to cite as a link: a comment, an import. In a text file a
# `#` is a heading, so this is read in code only.
_COMMENT_OR_IMPORT_RE = re.compile(
    r"""^\s*(?:$|#|//|/\*|\*|from\s+\S+\s+import\b|import\b"""
    r"""|(?:const|let|var)\s+\{?[^=]*\}?\s*=\s*require\()"""
)
_CALL_TEXT_RE = re.compile(r"[A-Za-z_][\w.]*\s*\(")
# What a control guards: what reaches the person, what leaves the service.
_GUARDED_KINDS = frozenset({"intervention", "transmission"})
_REMOTE_KINDS = frozenset({"remote", "runtime"})
_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef)
_SCOPES = (*_DEFS, ast.ClassDef)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp)
_TRIES = (ast.Try, getattr(ast, "TryStar", ast.Try))  # `except*` came with Python 3.11
_COMPARISONS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
}
# `is` between two singletons is settled by syntax; between other constants it is not.
_IDENTITIES = {ast.Is: operator.is_, ast.IsNot: operator.is_not}
_SINGLETONS = (type(None), bool, type(Ellipsis))
# A method that puts its argument into the object it is called on: `msgs.append(prompt)`.
_MUTATORS = frozenset(
    {"append", "extend", "insert", "update", "add", "setdefault", "appendleft", "extendleft"}
)


def _surface_types() -> tuple[str, ...]:
    from aisafe.investigation.plan import SURFACE_TYPES

    return SURFACE_TYPES


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


@dataclass
class RecordResult:
    """One record, as validated. `status`: accepted | rejected | superseded | previous."""

    path: str
    id: str | None = None
    status: str = "rejected"
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    mechanism: str | None = None
    pattern: str | None = None
    view: str | None = None
    surface: dict[str, Any] = field(default_factory=dict)
    surface_known: bool | None = None
    proposed: dict[str, str] = field(default_factory=dict)
    effective: dict[str, str] = field(default_factory=dict)
    claim: str | None = None  # establishes | closes | review
    required: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    runtime: list[str] = field(default_factory=list)
    ruled_out: list[str] = field(default_factory=list)
    complete: bool = False
    connected: bool = False
    control_on_path: bool = False
    links: list[dict[str, Any]] = field(default_factory=list)
    skeptic: dict[str, Any] = field(default_factory=dict)
    investigator: dict[str, Any] = field(default_factory=dict)
    operator: dict[str, Any] = field(default_factory=dict)
    mode: str | None = None
    created_at: str | None = None
    commit: str | None = None
    covers: list[str] = field(default_factory=list)
    covers_valid: list[str] = field(default_factory=list)
    supersedes: list[str] = field(default_factory=list)
    steps: list[dict[str, Any]] = field(default_factory=list)
    untrusted: list[dict[str, Any]] = field(default_factory=list)
    cited_files: list[str] = field(default_factory=list)
    # Every verified citation as (file, first line, last line): a retest clears a copy of a
    # step's quote only where a closing cites the lines that hold it.
    cited_spans: list[tuple[str, int, int]] = field(default_factory=list)
    readings: list[str] = field(default_factory=list)
    digest: str | None = None
    raw: dict[str, Any] | None = None
    # Set only by `investigation.signoff.apply_signoffs`: who closed this record at review,
    # and the machine's own reading, which `effective` no longer shows.
    signoffs: list[dict[str, Any]] = field(default_factory=list)
    machine_effective: dict[str, str] = field(default_factory=dict)

    @property
    def accepted(self) -> bool:
        return self.status == "accepted"

    @property
    def deciding(self) -> bool:
        """Establishes or closes: the claims a skeptic pass must try to refute."""
        return self.claim in ("establishes", "closes")

    def flow(self) -> Flow | None:
        """The record's trace as an evidence-model chain: every counted link `investigated`
        (or `runtime-only`), naming this record."""
        if not self.view or not self.links:
            return None
        links = [
            FlowLink(
                link["kind"],
                link["file"],
                link["line"],
                link["quote"],
                link["established_by"],
                record=self.id if link["established_by"] == "investigated" else None,
            )
            for link in self.links
            if link.get("counted")
        ]
        return Flow(links=links, view=self.view) if links else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "id": self.id,
            "status": self.status,
            "errors": list(self.errors),
            "notes": list(self.notes),
            "mechanism": self.mechanism,
            "pattern": self.pattern,
            "view": self.view,
            "surface": dict(self.surface),
            "surface_known": self.surface_known,
            "proposed": dict(self.proposed),
            "effective": dict(self.effective),
            "claim": self.claim,
            "required": list(self.required),
            "missing": list(self.missing),
            "runtime": list(self.runtime),
            "ruled_out": list(self.ruled_out),
            "complete": self.complete,
            "connected": self.connected,
            "control_on_path": self.control_on_path,
            "links": [dict(link) for link in self.links],
            "skeptic": dict(self.skeptic),
            "investigator": dict(self.investigator),
            "operator": dict(self.operator),
            "mode": self.mode,
            "created_at": self.created_at,
            "commit": self.commit,
            "covers": list(self.covers),
            "covers_valid": list(self.covers_valid),
            "supersedes": list(self.supersedes),
            "steps": [dict(step) for step in self.steps],
            "untrusted": [dict(item) for item in self.untrusted],
            "cited_files": list(self.cited_files),
            "readings": list(self.readings),
            "digest": self.digest,
            "signoffs": [dict(row) for row in self.signoffs],
            "machine_effective": dict(self.machine_effective),
        }


@dataclass
class ValidationRun:
    root: Path
    state: dict[str, Any]
    mode: str
    results: list[RecordResult] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    working_tree: bool = False
    fatal: str | None = None

    @property
    def accepted(self) -> list[RecordResult]:
        return [r for r in self.results if r.accepted]

    @property
    def rejected(self) -> list[RecordResult]:
        return [r for r in self.results if r.status == "rejected"]

    @property
    def exit_code(self) -> int:
        if self.fatal is not None:
            return 2
        return 1 if self.rejected else 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "aisg/investigation-validation/1",
            "kind": "investigation-validation",
            "mode": self.mode,
            "target": {"path": self.root.as_posix(), **self.state},
            "working_tree": self.working_tree,
            "fatal": self.fatal,
            "counts": {
                "records": len(self.results),
                "accepted": len(self.accepted),
                "rejected": len(self.rejected),
                "superseded": sum(1 for r in self.results if r.status == "superseded"),
                "skipped_files": len(self.skipped),
            },
            "records": [r.to_dict() for r in self.results],
            "skipped": list(self.skipped),
            "exit_code": self.exit_code,
        }


# ---------------------------------------------------------------------------
# Small shape helpers
# ---------------------------------------------------------------------------


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _list(value: Any) -> list[Any] | None:
    return value if isinstance(value, list) else None


def _int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _norm_control(name: str) -> str:
    return re.sub(r"[\s\-]+", "_", name.strip().lower())


def _parse_time(value: str) -> datetime | None:
    """An ISO 8601 timestamp with its time zone (`Z` or an offset); a local time with no
    zone is ambiguous by hours, so it is not read."""
    try:
        when = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return when if when.tzinfo else None


# ---------------------------------------------------------------------------
# What the syntax tree of a Python file shows
# ---------------------------------------------------------------------------


def _truth(node: ast.AST | None) -> bool | None:
    """An expression as a condition, when the syntax alone decides it; None when it takes a
    run."""
    if isinstance(node, ast.Constant):
        return bool(node.value)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return False if not node.elts else None
    if isinstance(node, ast.Dict):
        return False if not node.keys else None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        inner = _truth(node.operand)
        return None if inner is None else not inner
    if isinstance(node, ast.BoolOp):
        values = [_truth(value) for value in node.values]
        decider = isinstance(node.op, ast.Or)  # True settles an `or`, False an `and`
        if decider in values:
            return decider
        return None if None in values else not decider
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        left, right = node.left, node.comparators[0]
        if not (isinstance(left, ast.Constant) and isinstance(right, ast.Constant)):
            return None
        identity = _IDENTITIES.get(type(node.ops[0]))
        if identity is not None:
            if isinstance(left.value, _SINGLETONS) and isinstance(right.value, _SINGLETONS):
                return bool(identity(left.value, right.value))
            return None
        compare = _COMPARISONS.get(type(node.ops[0]))
        if compare:
            try:
                return bool(compare(left.value, right.value))
            except TypeError:
                return None
        return None
    name = node.attr if isinstance(node, ast.Attribute) else getattr(node, "id", None)
    return False if name == "TYPE_CHECKING" else None


def _leaves(stmt: ast.stmt) -> bool:
    """`stmt` never hands over to the statement after it."""
    if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
        return True
    if isinstance(stmt, ast.If):
        truth = _truth(stmt.test)
        return (truth is False or _ends(stmt.body)) and (truth is True or _ends(stmt.orelse))
    if isinstance(stmt, ast.While):
        return _truth(stmt.test) is True and not any(
            isinstance(node, ast.Break) for node in ast.walk(stmt)
        )
    if isinstance(stmt, _TRIES):
        return _ends(stmt.finalbody) or (
            _ends(stmt.body + stmt.orelse) and all(_ends(h.body) for h in stmt.handlers)
        )
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        return any(isinstance(item, ast.Return) for item in stmt.body)
    return False


def _ends(body: list[ast.stmt]) -> bool:
    return any(_leaves(stmt) for stmt in body)


def _after(body: list[ast.stmt]) -> int:
    """The line after a block: where an `else:` that follows it can start."""
    return (body[-1].end_lineno or body[-1].lineno) + 1 if body else 0


def _breaks(loop: ast.While | ast.For | ast.AsyncFor) -> bool:
    """A `break` of this loop (not of a loop inside it) sits in its body."""
    stack: list[ast.AST] = list(loop.body)
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Break):
            return True
        if isinstance(node, (ast.While, ast.For, ast.AsyncFor)):
            stack.extend(node.orelse)  # a `break` there leaves this loop
        elif not isinstance(node, (*_SCOPES, ast.Lambda)):
            stack.extend(ast.iter_child_nodes(node))
    return False


def _surely_run(node: ast.AST, live: list[ast.AST]) -> set[int]:
    """ids of the parts of an expression that run whenever it does: not an arm of
    `a if c else b`, not a value of `and`/`or` after the first, not the inside of a
    comprehension past its first iterable."""
    if isinstance(node, ast.IfExp) and len(live) > 1:
        return {id(node.test)}
    if isinstance(node, ast.BoolOp):
        return {id(node.values[0])}
    if isinstance(node, _COMPREHENSIONS):
        return {id(node.generators[0])}
    if isinstance(node, ast.comprehension):
        return {id(node.iter)}
    return {id(child) for child in live}


def _branches(node: ast.AST) -> tuple[list[ast.AST], list[ast.AST]]:
    """The parts of an expression that run, and those a constant condition shuts off."""
    if isinstance(node, ast.IfExp):
        truth = _truth(node.test)
        if truth is not None:
            return [node.body if truth else node.orelse], [node.orelse if truth else node.body]
    elif isinstance(node, ast.BoolOp):
        decider = isinstance(node.op, ast.Or)
        for index, value in enumerate(node.values[:-1]):
            if _truth(value) is decider:
                return list(node.values[: index + 1]), list(node.values[index + 1 :])
    return list(ast.iter_child_nodes(node)), []


def _dotted(node: ast.AST) -> tuple[str, ...]:
    """`a.b.c` as its parts; empty for anything that does not hang off a plain name."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ()
    parts.append(node.id)
    return tuple(reversed(parts))


def _own_nodes(scope: ast.AST) -> Iterable[ast.AST]:
    """The nodes of a definition (or the module) that are its own: not those of a function,
    a class or a lambda defined inside it."""
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (*_SCOPES, ast.Lambda)):
            stack.extend(ast.iter_child_nodes(node))


def _parts_of(stmt: ast.stmt) -> list[ast.AST]:
    """What a statement evaluates where it stands: the whole of a simple statement, the
    header of one that holds a block; nothing of a definition (its body runs elsewhere)."""
    if isinstance(stmt, _SCOPES):
        return []
    if isinstance(stmt, (ast.If, ast.While)):
        return [stmt.test]
    if isinstance(stmt, (ast.For, ast.AsyncFor)):
        return [stmt.iter]
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        return [item.context_expr for item in stmt.items]
    if isinstance(stmt, ast.Match):
        return [stmt.subject]
    if isinstance(stmt, _TRIES):
        return []
    return [stmt]


def _filled(parts: list[ast.AST], names: set[str] | None) -> set[str]:
    """The names of objects a call puts a value into (`msgs.append(x)`): with `names`, only
    when the value reads one of them."""
    found: set[str] = set()
    for part in parts:
        for node in ast.walk(part):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in _MUTATORS
                and isinstance(node.func.value, ast.Name)
            ):
                continue
            values = [*node.args, *(k.value for k in node.keywords)]
            if names is None or any(
                isinstance(n, ast.Name) and n.id in names for v in values for n in ast.walk(v)
            ):
                found.add(node.func.value.id)
    return found


def _span(node: Any) -> range:
    """The lines of a statement or an expression, a definition's decorators included."""
    first = min((d.lineno for d in getattr(node, "decorator_list", [])), default=node.lineno)
    return range(first, (node.end_lineno or node.lineno) + 1)


def _statement_lines(stmt: ast.stmt) -> tuple[int, int]:
    """A statement's lines; for one that holds a block, its header's."""
    body = getattr(stmt, "body", None)
    if isinstance(body, list) and body:
        return stmt.lineno, max(stmt.lineno, body[0].lineno - 1)
    return stmt.lineno, stmt.end_lineno or stmt.lineno


@dataclass(eq=False)
class _Scope:
    """A function, a class or the module, and what each name is bound to in it."""

    node: Any
    parent: _Scope | None
    lo: int
    hi: int
    bindings: dict[str, list[_Binding]] = field(default_factory=dict)


@dataclass(frozen=True)
class _Binding:
    """A line that binds a name: `path` is the dotted thing an import names (`level` its
    leading dots); None for a definition in the file."""

    line: int
    path: tuple[str, ...] | None = None
    level: int = 0


@dataclass(frozen=True)
class _Use:
    """A name read or called in code that runs; `parts` as spelled: `request.json` is two."""

    line: int
    parts: tuple[str, ...]
    called: bool
    scope: _Scope
    # Inside a part of an expression that may not run: an arm of `a if c else b`, a value of
    # `and`/`or` after the first, the inside of a comprehension.
    maybe: bool = False
    # A call that is awaited, or an argument of an awaited call (`asyncio.gather(f(x))`).
    awaited: bool = False


@dataclass(frozen=True)
class _Target:
    """What a hop must reach to reach a control: `name`, bound on lines `lo` to `hi` of the
    control's file, called (a function) or only read (a constant)."""

    name: str
    must_call: bool
    lo: int = 0
    hi: int = 0
    # An `async def`: calling it only makes a coroutine, which runs when it is awaited.
    awaits: bool = False
    # A generator: calling it runs none of its body.
    yields: bool = False


class _Tree:
    """What one parsed Python file shows, by line, with no name match anywhere.

    `inert` lines run nothing: imports, a definition's header and its decorators, an
    expression with no effect, `pass`, the inside of a string that is no prompt, a header
    whose condition the syntax settles, a line whose only action is inside a lambda or a
    generator expression, a line that calls nothing and whose comment holds a call. `dead`
    lines never run: after a return, under `if False:`, in `for _ in ():`. `uses` are the
    names read or called in code that runs; a lambda's body, a generator's, a decorator, a
    default value and an annotation give none. An `assert` is inert: `python -O` drops it.
    `blocks` may not run when the code around them does: an arm of an `if` or a `match` the
    syntax does not settle, the body of a loop and its `else` when it can `break`, the body
    and the `else` of a `try` with a handler that carries on. Each comes with the header
    lines that decide it.
    """

    def __init__(self, tree: ast.Module, lines: list[str], prompts: list[tuple[int, int]]) -> None:
        self.lines = lines
        self.module = _Scope(tree, None, 1, max(len(lines), 1))
        self.scopes: list[_Scope] = []
        self.inert: set[int] = set()
        self.dead: set[int] = set()
        self.imported: set[int] = set()
        self.text_statements: set[int] = set()
        self.calling: set[int] = set()
        self.uses: list[_Use] = []
        self.imports: list[tuple[int, int, tuple[str, ...], int]] = []
        self.exits: list[tuple[int, _Scope]] = []
        # (statement, arm, first line, last line): two arms of one statement exclude each other
        self.arms: list[tuple[int, int, int, int]] = []
        self.excepts: list[tuple[int, int]] = []
        # (header first line, header last line, block first line, block last line)
        self.blocks: list[tuple[int, int, int, int]] = []
        # (parts as spelled, scope) of each attribute stored to: `safety.check = ...`, and
        # `setattr(safety, "check", ...)` with the name spelled out
        self.attr_stores: list[tuple[tuple[str, ...], _Scope]] = []
        # (first line, last line, text) of each string constant in code that runs
        self.strings: list[tuple[int, int, str]] = []
        self.comments = self._comments("\n".join(lines))
        self._statements = [node for node in ast.walk(tree) if isinstance(node, ast.stmt)]
        self._in_strings: set[int] = set()
        self._block(tree.body, self.module)
        self._bind()
        self.inert |= self.dead
        self.inert |= (
            self._in_strings - self.calling - {n for lo, hi in prompts for n in range(lo, hi + 1)}
        )
        self.inert |= {
            line
            for line, start in self.comments.items()
            if line not in self.calling and _CALL_TEXT_RE.search(lines[line - 1][start:])
        }

    @staticmethod
    def _comments(text: str) -> dict[int, int]:
        return {
            token.start[0]: token.start[1]
            for token in tokenize.generate_tokens(io.StringIO(text).readline)
            if token.type == tokenize.COMMENT
        }

    def code(self, line: int) -> str:
        """The line without its comment."""
        return self.lines[line - 1][: self.comments.get(line)]

    # -- reading ----------------------------------------------------------------------
    def _block(self, body: list[ast.stmt], scope: _Scope) -> None:
        ended = False
        for stmt in body:
            if ended:
                self._kill(stmt)
            else:
                self._statement(stmt, scope)
                ended = _leaves(stmt)

    def _kill(self, *stmts: ast.stmt) -> None:
        for stmt in stmts:
            self.dead.update(_span(stmt))

    def _header(self, stmt: Any) -> None:
        self.inert.update(range(stmt.lineno, max(stmt.body[0].lineno, stmt.lineno + 1)))

    def _arm(self, stmt: ast.stmt, arm: int, body: list[ast.stmt]) -> None:
        if body:
            last = body[-1].end_lineno or body[-1].lineno
            self.arms.append((id(stmt), arm, _span(body[0]).start, last))

    def _may_skip(self, head: tuple[int, int], body: list[ast.stmt], start: int = 0) -> None:
        """`body` may not run when the code around it does. It holds its lines from `start`
        when that comes first (an `else:`, a `case`, a `try:` line)."""
        if body:
            first = min(start or _span(body[0]).start, _span(body[0]).start)
            self.blocks.append((*head, first, body[-1].end_lineno or body[-1].lineno))

    def _branch(self, stmt: Any, scope: _Scope, truth: bool | None) -> None:
        """The two blocks of an `if` or a `while`, as a condition settled by syntax leaves
        them. A settled condition's header runs nothing."""
        if truth is None:
            self._read([stmt.test], scope)
        else:
            self._header(stmt)
        if truth is False:
            self._kill(*stmt.body)
        else:
            self._block(stmt.body, scope)
        if truth is True:
            self._kill(*stmt.orelse)
        else:
            self._block(stmt.orelse, scope)

    def _statement(self, stmt: Any, scope: _Scope) -> None:
        if isinstance(stmt, _SCOPES):
            self.inert.update(range(_span(stmt).start, max(stmt.body[0].lineno, stmt.lineno + 1)))
            inner = _Scope(stmt, scope, stmt.lineno, stmt.end_lineno or stmt.lineno)
            self.scopes.append(inner)
            self._block(stmt.body, inner)
        elif isinstance(stmt, ast.If):
            truth = _truth(stmt.test)
            if truth is None:
                head = _statement_lines(stmt)
                self._arm(stmt, 0, stmt.body)
                self._arm(stmt, 1, stmt.orelse)
                self._may_skip(head, stmt.body)
                self._may_skip(head, stmt.orelse, _after(stmt.body))
            self._branch(stmt, scope, truth)
        elif isinstance(stmt, (ast.While, ast.For, ast.AsyncFor)):
            # A loop's body may run no time; its `else` is skipped by a `break`.
            head = _statement_lines(stmt)
            self._may_skip(head, stmt.body)
            if _breaks(stmt):
                self._may_skip(head, stmt.orelse, _after(stmt.body))
            if isinstance(stmt, ast.While):
                self._branch(stmt, scope, _truth(stmt.test))
            else:
                if _truth(stmt.iter) is False:
                    self._header(stmt)
                    self._kill(*stmt.body)
                else:
                    self._read([stmt.iter], scope)
                    self._block(stmt.body, scope)
                self._block(stmt.orelse, scope)
        elif isinstance(stmt, _TRIES):
            self._arm(stmt, 0, stmt.body)
            self._arm(stmt, 0, stmt.orelse)
            if any(not _ends(handler.body) for handler in stmt.handlers):
                # A handler that carries on: what raises in the body skips the rest of it
                # and the `else`, and the code after the `try` still runs.
                self._may_skip((0, 0), stmt.body, stmt.lineno)
                self._may_skip((0, 0), stmt.orelse, _after(stmt.handlers[-1].body))
            self._block(stmt.body, scope)
            for index, handler in enumerate(stmt.handlers, 1):
                self.excepts.append((handler.lineno, handler.end_lineno or handler.lineno))
                self._arm(stmt, index, handler.body)
                self._read([handler.type], scope)
                self._block(handler.body, scope)
            self._block(stmt.orelse, scope)
            self._block(stmt.finalbody, scope)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            self._read([item.context_expr for item in stmt.items], scope)
            self._block(stmt.body, scope)
        elif isinstance(stmt, ast.Match):
            self._read([stmt.subject], scope)
            head = (stmt.lineno, stmt.subject.end_lineno or stmt.lineno)
            for index, case in enumerate(stmt.cases):
                self._arm(stmt, index, case.body)
                self._may_skip(head, case.body, case.pattern.lineno)
                self._read([case.guard], scope)
                self._block(case.body, scope)
        elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
            self.inert.update(_span(stmt))
            self.imported.update(_span(stmt))
            for path, level in self._imported_paths(stmt):
                self.imports.append((stmt.lineno, stmt.end_lineno or stmt.lineno, path, level))
        elif isinstance(stmt, ast.Pass):
            self.inert.update(_span(stmt))
        elif isinstance(stmt, ast.Expr):
            if not self._read([stmt.value], scope):
                self.inert.update(_span(stmt))
            if isinstance(stmt.value, ast.Constant):
                self.text_statements.update(_span(stmt))
        elif isinstance(stmt, ast.Assert):
            # `python -O` drops the statement: nothing in it can be shown to run.
            self.inert.update(_span(stmt))
        else:
            if isinstance(stmt, (ast.Return, ast.Raise)):
                self.exits.append((stmt.lineno, scope))
            annotated = isinstance(stmt, ast.AnnAssign)
            parts = [stmt.target, stmt.value] if annotated else list(ast.iter_child_nodes(stmt))
            self._read(parts, scope)

    def _read(self, nodes: list[Any], scope: _Scope, *, shut: Iterable[ast.AST] = ()) -> bool:
        """Take in a statement's expressions: their uses, and the lines where all that happens
        is shut away (a lambda, a generator, a branch a constant rules out). Says whether any
        of it acts: a call, an await, a yield."""
        stack = [(node, False) for node in nodes if node is not None]
        closed = list(shut)
        calls: list[ast.Call] = []
        awaited: set[int] = set()
        acts = False
        while stack:
            node, maybe = stack.pop()
            if isinstance(node, (ast.Lambda, ast.GeneratorExp)) or (
                isinstance(node, _COMPREHENSIONS) and _truth(node.generators[0].iter) is False
            ):
                closed.append(node)
                continue
            live, off = _branches(node)
            closed.extend(off)
            sure = _surely_run(node, live)
            stack.extend((child, maybe or id(child) not in sure) for child in live)
            if isinstance(node, ast.Call):
                calls.append(node)
                self.calling.add(node.lineno)
                self._use(node.func, node.lineno, True, scope, maybe, id(node) in awaited)
            elif isinstance(node, (ast.Await, ast.Yield, ast.YieldFrom)):
                acts = True
                if isinstance(node, ast.Await) and isinstance(node.value, ast.Call):
                    inner = node.value
                    awaited.add(id(inner))
                    awaited.update(
                        id(arg)
                        for arg in [*inner.args, *(k.value for k in inner.keywords)]
                        if isinstance(arg, ast.Call)
                    )
            elif isinstance(node, (ast.Name, ast.Attribute)):
                if isinstance(node.ctx, ast.Load):
                    self._use(node, node.lineno, False, scope, maybe)
            elif isinstance(node, (ast.Constant, ast.JoinedStr)):
                self._in_strings.update(range(node.lineno + 1, (node.end_lineno or 0) + 1))
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    self.strings.append((node.lineno, node.end_lineno or node.lineno, node.value))
        if closed:
            ids = {id(node) for node in closed}
            clear = {c.lineno for c in calls if not any(id(n) in ids for n in ast.walk(c))}
            for node in closed:
                self.inert.update(set(_span(node)) - clear)
        return acts or bool(calls)

    def _use(
        self,
        target: ast.AST,
        line: int,
        called: bool,
        scope: _Scope,
        maybe: bool = False,
        awaited: bool = False,
    ) -> None:
        parts = _dotted(target)
        if parts:
            self.uses.append(_Use(line, parts, called, scope, maybe, awaited))

    @staticmethod
    def _imported_paths(stmt: ast.Import | ast.ImportFrom) -> list[tuple[tuple[str, ...], int]]:
        if isinstance(stmt, ast.Import):
            return [(tuple(alias.name.split(".")), 0) for alias in stmt.names]
        base = tuple(stmt.module.split(".")) if stmt.module else ()
        return [((*base, alias.name), stmt.level) for alias in stmt.names]

    def _bind(self) -> None:
        """What each name is bound to, scope by scope; code that never runs binds nothing."""
        for scope in (self.module, *self.scopes):
            node = scope.node
            # `global x` in a function: what the function binds to `x` is the module's `x`.
            shared = (
                {name for n in _own_nodes(node) if isinstance(n, ast.Global) for name in n.names}
                if isinstance(node, _DEFS)
                else set()
            )
            stack: list[Any] = [*node.body, *([node.args] if isinstance(node, _DEFS) else [])]
            while stack:
                item = stack.pop()
                if getattr(item, "lineno", 0) in self.dead:
                    continue
                found: list[tuple[str, _Binding]] = []
                if isinstance(item, _SCOPES):
                    found.append((item.name, _Binding(item.lineno)))
                elif isinstance(item, ast.Import):
                    for alias in item.names:
                        head = alias.name.split(".")
                        path = tuple(head) if alias.asname else (head[0],)
                        found.append((alias.asname or head[0], _Binding(item.lineno, path)))
                elif isinstance(item, ast.ImportFrom):
                    base = tuple(item.module.split(".")) if item.module else ()
                    for alias in item.names:
                        binding = _Binding(item.lineno, (*base, alias.name), item.level)
                        found.append((alias.asname or alias.name, binding))
                elif not isinstance(item, (ast.Lambda, ast.GeneratorExp, *_COMPREHENSIONS)):
                    name = self._bind_plain(item)
                    if name:
                        found.append((name, _Binding(getattr(item, "lineno", 0))))
                    self._store_attr(item, scope)
                    stack.extend(ast.iter_child_nodes(item))
                for name, binding in found:
                    where = self.module if name in shared else scope
                    where.bindings.setdefault(name, []).append(binding)

    @staticmethod
    def _bind_plain(item: Any) -> str | None:
        if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store):
            return item.id
        if isinstance(item, ast.arg):
            return item.arg
        if isinstance(item, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
            return item.name
        return None

    def _store_attr(self, item: Any, scope: _Scope) -> None:
        """Note an attribute stored to: `a.b = ...`, `setattr(a, "b", ...)`."""
        parts: tuple[str, ...] = ()
        if isinstance(item, ast.Attribute) and isinstance(item.ctx, ast.Store):
            parts = _dotted(item)
        elif (
            isinstance(item, ast.Call)
            and isinstance(item.func, ast.Name)
            and item.func.id == "setattr"
            and len(item.args) >= 2
            and isinstance(item.args[1], ast.Constant)
            and isinstance(item.args[1].value, str)
        ):
            owner = _dotted(item.args[0])
            parts = (*owner, item.args[1].value) if owner else ()
        if len(parts) >= 2:
            self.attr_stores.append((parts, scope))

    # -- asking -----------------------------------------------------------------------
    def scope_at(self, line: int) -> _Scope:
        """The innermost function or class that holds `line`, else the module. Every
        definition has its own span, so a name defined twice loses no line."""
        best = self.module
        for scope in self.scopes:
            if scope.lo <= line <= scope.hi and scope.lo >= best.lo:
                best = scope
        return best

    def statement_at(self, line: int) -> ast.stmt | None:
        """The innermost statement at `line`; a line of a block is the block's own."""
        best = None
        size = 0
        for stmt in self._statements:
            lo, hi = _statement_lines(stmt)
            if lo <= line <= hi and (best is None or hi - lo <= size):
                best, size = stmt, hi - lo
        return best

    def in_except(self, line: int) -> bool:
        return any(lo <= line <= hi for lo, hi in self.excepts)

    def same_path(self, line: int, target: int, *, surely: bool = True) -> bool:
        """`line` runs on the way to `target`: the same function, no two arms of one `if`,
        `try` or `match`, and no `except` branch unless `target` is in it too. With `surely`,
        also in no block that may not run (`blocks`) unless `target` is in it too; without,
        `line` only can run on the way."""
        if self.scope_at(line) is not self.scope_at(target):
            return False
        if any(lo <= line <= hi and not lo <= target <= hi for lo, hi in self.excepts):
            return False
        if surely and any(
            lo <= line <= hi and not lo <= target <= hi for _first, _last, lo, hi in self.blocks
        ):
            return False
        arms = {group: arm for group, arm, lo, hi in self.arms if lo <= line <= hi}
        return not any(
            group in arms and arms[group] != arm
            for group, arm, lo, hi in self.arms
            if lo <= target <= hi
        )

    def heads_into(self, line: int, lo: int, hi: int) -> bool:
        """`line` is the header of a block that may not run, and lines `lo` to `hi` reach into
        that block: the header runs, what the citation shows inside the block may not."""
        return any(
            first <= line <= last and b_lo <= hi and b_hi >= lo
            for first, last, b_lo, b_hi in self.blocks
        )

    def exits_between(self, line: int, target: int) -> bool:
        """A `return` or `raise` of the same function stands from `line` up to `target`."""
        scope = self.scope_at(line)
        return any(where is scope and line <= at < target for at, where in self.exits)

    def bindings_of(self, name: str, scope: _Scope) -> list[_Binding]:
        """What `name` means where it is used: a local binding hides the module's."""
        current: _Scope | None = scope
        while current is not None:
            found = current.bindings.get(name)
            if found and (current is scope or not isinstance(current.node, ast.ClassDef)):
                return found
            current = current.parent
        return []

    def paths_in(self, lo: int, hi: int) -> Iterable[tuple[tuple[str, ...], int]]:
        """Each dotted thing lines `lo` to `hi` import, or use through an import."""
        for first, last, path, level in self.imports:
            if first <= hi and last >= lo:
                yield path, level
        for use in self.uses:
            if lo <= use.line <= hi:
                for binding in self.bindings_of(use.parts[0], use.scope):
                    if binding.path is not None:
                        yield (*binding.path, *use.parts[1:]), binding.level

    def bound_from(self, line: int, calls: set[int]) -> set[int]:
        """The lines of the statement at `line`, and of each statement that reads a name it
        bound: after it in its scope, anywhere in a function defined in that scope (which
        runs later). A statement that reads one binds in turn what it assigns, and the
        object it puts the value into (`msgs.append(prompt)`). A model call on `calls` takes
        the prompt in and hands back a reply, so the names stop there. Of a statement that
        holds a block, only its header counts."""
        stmt = self.statement_at(line)
        if stmt is None:
            return {line}
        lo, hi = _statement_lines(stmt)
        found = set(range(lo, hi + 1))
        names: set[str] = set()
        if not getattr(stmt, "body", None):
            names = {
                node.id
                for node in ast.walk(stmt)
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
            } | _filled(_parts_of(stmt), None)
        scope = self.scope_at(line)
        later = [
            node
            for node in ast.walk(scope.node)
            if isinstance(node, ast.stmt)
            and node is not scope.node
            and (node.lineno > hi or self.scope_at(node.lineno) is not scope)
        ]
        later.sort(key=lambda n: n.lineno)
        taken: set[int] = set()
        grew = bool(names)
        while grew:
            grew = False
            for node in later:
                if id(node) in taken:
                    continue
                parts = _parts_of(node)
                if not any(
                    isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in names
                    for part in parts
                    for n in ast.walk(part)
                ):
                    continue
                taken.add(id(node))
                first, last = _statement_lines(node)
                found.update(range(first, last + 1))
                if calls.intersection(range(first, last + 1)):
                    continue
                bound = _filled(parts, names)
                for part in parts:
                    for n in ast.walk(part):
                        if isinstance(n, ast.NamedExpr):
                            bound.add(n.target.id)
                targets: list[ast.AST] = []
                if isinstance(node, ast.Assign):
                    targets = list(node.targets)
                elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.For, ast.AsyncFor)):
                    targets = [node.target]
                elif isinstance(node, (ast.With, ast.AsyncWith)):
                    targets = [i.optional_vars for i in node.items if i.optional_vars]
                bound.update(n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name))
                if not bound <= names:
                    names |= bound
                    grew = True
        return found


class _Checker:
    """Validates one record against one scan; collects errors and notes."""

    def __init__(
        self, raw: dict[str, Any], path: Path, scan: MachineScan, mode: str, working_tree: bool
    ) -> None:
        self.raw = raw
        self.path = path
        self.scan = scan
        self.mode = mode
        self.working_tree = working_tree
        self.result = RecordResult(path=path.as_posix(), raw=raw)
        self._lines: dict[str, list[str]] = {}
        self._hashes: dict[str, str] = {}
        self._trees: dict[str, _Tree | None] = {}
        self._patched: dict[tuple[str, str], bool] = {}
        # (file, first line, last line, where) of every accepted citation
        self.citations: list[tuple[str, int, int, str]] = []

    def error(self, message: str) -> None:
        self.result.errors.append(message)

    def note(self, message: str) -> None:
        if message not in self.result.notes:
            self.result.notes.append(message)

    # -- citations --------------------------------------------------------------
    def lines_of(self, relpath: str) -> list[str] | None:
        if relpath not in self._lines:
            record = self.scan.walked.get(relpath)
            if record is None:
                return None
            try:
                self._lines[relpath] = file_lines(record.path)
                self._hashes[relpath] = content_sha256(record.path)
            except OSError:
                return None
        return self._lines[relpath]

    def tree_of(self, relpath: str) -> _Tree | None:
        """What the syntax tree shows of a Python file, on the very text the citations are
        checked against. None for any other file, one that does not parse, one the deep pass
        has no module for (it gave up on the file, so its facts say nothing), and text with a
        lone carriage return, which the parser counts as a line and a citation does not."""
        if relpath not in self._trees:
            self._trees[relpath] = self._read_tree(relpath)
        return self._trees[relpath]

    def _read_tree(self, relpath: str) -> _Tree | None:
        facts = self.scan.ctx.pyfacts
        if facts is None or self.scan.reading_of(relpath) != "deep":
            return None
        lines = self.lines_of(relpath)
        if lines is None or f"module:{relpath}" not in facts.functions:
            return None
        text = "\n".join(lines)
        if "\r" in text:
            return None
        prompts = [(p.line, p.end_line) for p in facts.prompt_literals if p.file == relpath]
        try:
            return _Tree(ast.parse(text), lines, prompts)
        except (SyntaxError, ValueError, RecursionError, MemoryError, tokenize.TokenError):
            return None

    def inert_lines(self, relpath: str) -> set[int]:
        """The lines of a Python file that run nothing (`_Tree`); none for any other file."""
        tree = self.tree_of(relpath)
        return tree.inert if tree is not None else set()

    def runs(self, relpath: str, number: int) -> bool:
        """The line is code that runs, as far as a line can show: not blank, not a comment, an
        import or a definition's header, not in `_Tree.inert`."""
        text = (self.lines_of(relpath) or [""] * number)[number - 1]
        code = self.scan.reading_of(relpath) in ("deep", "read")
        return not (
            number in self.inert_lines(relpath)
            or not text.strip()
            or (code and _NAMES_ONLY_RE.match(text))
        )

    def quoted_in_comment(self, cited: dict[str, Any]) -> bool:
        """Python: each line of the quote sits in that line's comment and not in its code."""
        tree = self.tree_of(cited["file"])
        quote = cited.get("quote")
        if tree is None or not quote:
            return False
        for number, part in enumerate(str(quote).split("\n"), cited["line"]):
            start = tree.comments.get(number)
            if start is None:
                return False
            text, wanted = tree.lines[number - 1], normalise(part)
            if wanted in normalise(text[:start]) or wanted not in normalise(text[start:]):
                return False
        return True

    def names_only(self, cited: dict[str, Any]) -> bool:
        """No cited line shows anything run: each is blank, or, in code, an import, a comment,
        a definition's header, or (Python) another line of `_Tree.inert`; or the quote is only
        in a comment. It names something and runs nothing."""
        last = cited["end_line"] or cited["line"]
        return self.quoted_in_comment(cited) or not any(
            self.runs(cited["file"], number) for number in range(cited["line"], last + 1)
        )

    def not_code(self, cited: dict[str, Any]) -> bool:
        """The citation is no link: only comments, imports, strings standing as statements,
        or, in Python, lines that never run. A definition's header stays one (a route is an
        ingress); so does the inside of a string (a prompt)."""
        relpath = cited["file"]
        numbers = range(cited["line"], (cited["end_line"] or cited["line"]) + 1)
        tree = self.tree_of(relpath)
        if tree is not None:
            return self.quoted_in_comment(cited) or all(
                n in tree.dead
                or n in tree.imported
                or n in tree.text_statements
                or not tree.code(n).strip()
                for n in numbers
            )
        if self.scan.reading_of(relpath) not in ("deep", "read"):
            return False
        lines = self.lines_of(relpath) or []
        return all(_COMMENT_OR_IMPORT_RE.match(lines[n - 1]) for n in numbers)

    def run_time_lines(self) -> set[tuple[str, int]]:
        """(file, line) of what holds a prompt fetched at run time: the whole statement of
        each row the scan lists, in Python, and the statements fed from a name it bound."""
        lines: set[tuple[str, int]] = set()
        inventory = self.scan.ctx.inventory
        for row in inventory.prompts or []:
            if str(row.get("kind")) in _REMOTE_KINDS:
                file, line = str(row.get("file")), int(row.get("line") or 0)
                lines.add((file, line))
                tree = self.tree_of(file)
                if tree is not None:
                    calls = {
                        int(call.get("line") or 0)
                        for call in inventory.llm_calls or []
                        if str(call.get("file")) == file
                    }
                    lines.update((file, number) for number in tree.bound_from(line, calls))
        return lines

    def module_file(self, importer: str, parts: tuple[str, ...], level: int = 0) -> str | None:
        """The walked file a dotted module names, seen from `importer`: next to it, or the
        only one with that path anywhere. Two candidates and none near: unknown."""
        if not parts and not level:
            return None
        path = "/".join(parts)
        names = (f"{path}.py", f"{path}/__init__.py") if path else ("__init__.py",)
        folder = PurePosixPath(importer).parent
        for _ in range(level - 1):
            folder = folder.parent
        near = [(folder / name).as_posix() for name in names]
        found = next((file for file in near if file in self.scan.walked), None)
        if found is not None or level:
            return found
        anywhere = [
            file
            for file in self.scan.walked
            if any(file == name or file.endswith(f"/{name}") for name in names)
        ]
        return anywhere[0] if len(anywhere) == 1 else None

    def patched(self, module: str, name: str) -> bool:
        """A parsed file stores to `name` in the file `module` as an attribute:
        `safety.crisis_check = ...`, `setattr(safety, "crisis_check", ...)`. Whatever a use
        resolves to there may not be what runs."""
        key = (module, name)
        if key not in self._patched:
            self._patched[key] = any(
                self._stores_to(relpath, module, name)
                for relpath in self.scan.walked
                if self.scan.reading_of(relpath) == "deep"
            )
        return self._patched[key]

    def _stores_to(self, relpath: str, module: str, name: str) -> bool:
        text = "\n".join(self.lines_of(relpath) or [])
        if name not in text:
            return False
        tree = self.tree_of(relpath)
        if tree is None:
            return False
        for parts, scope in tree.attr_stores:
            if parts[-1] != name:
                continue
            for binding in tree.bindings_of(parts[0], scope):
                if binding.path is None:
                    continue
                owner = (*binding.path, *parts[1:-1])
                if self.module_file(relpath, owner, binding.level) == module:
                    return True
        return False

    def resolves(
        self,
        importer: str,
        path: tuple[str, ...],
        level: int,
        target_file: str,
        name: str,
        depth: int = 0,
    ) -> bool:
        """The dotted `path`, seen from `importer`, is `name` in `target_file`: directly, or
        through a package or module that imports it under one binding and does nothing else
        with the name (a re-export: `from guard.safety import crisis_check`)."""
        module = self.module_file(importer, path[:-1], level)
        if module == target_file:
            return path[-1] == name
        if module is None or depth >= 4:
            return False
        tree = self.tree_of(module)
        if tree is None:
            return False
        found = tree.module.bindings.get(path[-1], [])
        if len(found) != 1 or found[0].path is None or self.patched(module, path[-1]):
            return False
        return self.resolves(module, found[0].path, found[0].level, target_file, name, depth + 1)

    def imports_file(self, importer: str, path: tuple[str, ...], level: int, other: str) -> bool:
        """`path` (a module, or a thing inside one) is in the file `other`."""
        return any(
            self.module_file(importer, path[:size], level) == other
            for size in range(len(path), 0, -1)
        )

    def citation(self, item: Any, where: str, role: str = "citation") -> dict[str, Any] | None:
        """Check `{file, line, end_line?, quote, sha256}`; returns the normalised citation
        or None (with an error recorded)."""
        if not isinstance(item, dict):
            self.error(f"{where}: not an object")
            return None
        relpath = _text(item.get("file")).replace("\\", "/")
        line = _int(item.get("line"))
        end_line = item.get("end_line")
        quote = item.get("quote")
        sha = _text(item.get("sha256")).lower()
        if not relpath:
            self.error(f"{where}: `file` is empty")
            return None
        if line is None or line < 1:
            self.error(f"{where}: `line` must be a line number (1 or more)")
            return None
        if end_line is not None and (_int(end_line) is None or end_line < line):
            self.error(f"{where}: `end_line` must be a line number at or after `line`")
            return None
        if not isinstance(quote, str) or not quote.strip():
            self.error(f"{where}: `quote` is empty")
            return None
        if not SHA_RE.match(sha):
            self.error(f"{where}: `sha256` must be 64 lowercase hex digits")
            return None
        lines = self.lines_of(relpath)
        if lines is None:
            self.error(
                f"{where}: {relpath} is not a file the scan walked (excluded, gitignored, "
                "skipped by a marker, the tool's own output, or not in the tree)"
            )
            return None
        if not self.scan.in_commit(relpath):
            if self.working_tree:
                self.note(f"{where}: {relpath} is not tracked by git; checked as it is on disk")
            else:
                self.error(
                    f"{where}: {relpath} is not tracked by git, so it is not part of the "
                    "audited commit"
                )
                return None
        if self._hashes[relpath] != sha:
            self.error(
                f"{where}: the content hash of {relpath} differs from the record's; the file "
                "changed since the record was written"
            )
            return None
        if redact(quote) != quote:
            self.error(
                f"{where}: the quote carries a secret-shaped string; quote the redacted form"
            )
            return None
        check = quote_at(lines, line, quote, end_line)
        if not check.ok:
            self.error(f"{where}: {relpath}:{line}: {check.reason}")
            return None
        last = line if end_line is None else end_line
        self.citations.append((relpath, line, last, role))
        return {"file": relpath, "line": line, "end_line": end_line, "quote": quote, "sha256": sha}

    # -- free text -----------------------------------------------------------------
    def free_text(self, value: Any, where: str) -> None:
        words = verdict_words_in(value if isinstance(value, str) else "")
        if words:
            self.error(
                f"{where}: the text pronounces a verdict; a record says what was read, never "
                "a verdict on the system"
            )

    def required_text(self, value: Any, where: str) -> str:
        text = _text(value)
        if not text:
            self.error(f"`{where}` is empty")
        else:
            self.free_text(text, where)
        return text


# ---------------------------------------------------------------------------
# One record
# ---------------------------------------------------------------------------


def validate_record(
    raw: Any,
    path: Path,
    scan: MachineScan,
    *,
    mode: str,
    plan_surfaces: dict[str, dict[str, Any]] | None = None,
    working_tree: bool = False,
) -> RecordResult:
    """Validate one parsed record (see the module docstring)."""
    if not isinstance(raw, dict):
        result = RecordResult(path=path.as_posix())
        result.errors.append("the record is not a JSON object")
        return result
    check = _Checker(raw, path, scan, mode, working_tree)
    result = check.result
    policy = scan.policy

    if raw.get("schema") != INVESTIGATION_SCHEMA or raw.get("kind") != INVESTIGATION_KIND:
        check.error(
            f"not an investigation record (`schema` {INVESTIGATION_SCHEMA}, `kind` investigation)"
        )
        return result
    record_id = _text(raw.get("id"))
    if not ID_RE.match(record_id):
        check.error("`id` must be 1 to 64 letters, digits, dots, dashes or underscores")
    result.id = record_id or None
    result.digest = record_digest(raw)

    created = _text(raw.get("created_at"))
    when = _parse_time(created) if created else None
    if when is None:
        check.error("`created_at` must be an ISO 8601 timestamp with its time zone (Z or +hh:mm)")
    elif when - datetime.now(timezone.utc) > _FUTURE_TOLERANCE:
        check.error("`created_at` is in the future")
    result.created_at = created or None

    target = raw.get("target") if isinstance(raw.get("target"), dict) else None
    if target is None:
        check.error("`target` must be an object with `path` and `commit`")
    else:
        commit = target.get("commit")
        result.commit = commit if isinstance(commit, str) and commit else None
        here = scan.state.commit
        if here is None and result.commit is not None:
            check.error(f"the record names commit {result.commit}; the tree is not a git checkout")
        elif here is not None and result.commit != here:
            check.error(
                f"{_OTHER_COMMIT} {result.commit or 'none'}; the tree is at {here}. "
                "Validate it on that commit, or write a new record"
            )

    record_mode = _text(raw.get("mode"))
    if record_mode not in MODES:
        check.error(f"`mode` must be one of {', '.join(MODES)}")
    elif record_mode != mode:
        check.error(f"the record was made in {record_mode} mode; this run is in {mode} mode")
    result.mode = record_mode or None

    operator = raw.get("operator") if isinstance(raw.get("operator"), dict) else {}
    if not _text(operator.get("name")):
        check.error("`operator.name` is empty: a record names the person who ran the investigation")
    result.operator = {"name": _text(operator.get("name")), "role": _text(operator.get("role"))}

    investigator = raw.get("investigator") if isinstance(raw.get("investigator"), dict) else {}
    for key in ("agent", "model", "version", "session"):
        if not _text(investigator.get(key)):
            check.error(f"`investigator.{key}` is empty")
    result.investigator = {
        k: _text(investigator.get(k)) for k in ("agent", "model", "version", "session")
    }

    # -- mechanism, pattern, view --------------------------------------------------
    mechanism_id = _text(raw.get("mechanism"))
    mechanism = policy.mechanism_by_id(mechanism_id) if mechanism_id else None
    pattern = None
    if mechanism is None:
        check.error("`mechanism` must be one of the policy's mechanisms, M1 to M7")
    elif not mechanism.patterns:
        check.error(
            f"{mechanism_id} is decided from review records and the AUD-1106/AUD-1107 facts, "
            "not by an investigation record"
        )
    else:
        pattern = mechanism.pattern(_text(raw.get("pattern")))
        if pattern is None:
            check.error(
                f"`pattern` must be one of {mechanism_id}'s: "
                + ", ".join(p.id for p in mechanism.patterns)
            )
    result.mechanism = mechanism_id or None
    result.pattern = _text(raw.get("pattern")) or None
    view = _text(raw.get("view"))
    result.view = view or None
    if pattern is not None and view != pattern.view:
        check.error(
            f"`view` is {view or 'empty'}; pattern {pattern.id} is in the {pattern.view} view"
        )
    kinds_of_view = LINK_KINDS_BY_VIEW.get(view, ())

    # -- surface ----------------------------------------------------------------------
    surface = raw.get("surface") if isinstance(raw.get("surface"), dict) else None
    s_type = s_file = ""
    if surface is None:
        check.error("`surface` must be an object with `type`, `file` and `line`")
    else:
        s_type = _text(surface.get("type"))
        s_file = _text(surface.get("file")).replace("\\", "/")
        s_line = _int(surface.get("line"))
        s_id = surface.get("id")
        if s_type not in _surface_types():
            check.error("`surface.type` must be one of " + ", ".join(_surface_types()))
        if not s_file:
            check.error("`surface.file` is empty")
        elif s_type not in _UNIT_SURFACES and s_file not in scan.walked:
            check.error(f"`surface.file` {s_file} is not a file the scan walked")
        elif s_type in _UNIT_SURFACES and s_file not in {
            (u.root if u.root not in ("", ".") else ".") for u in scan.ctx.inventory.units or []
        }:
            check.error(f"`surface.file` {s_file} is not the root of a unit the scan found")
        if s_line is None or s_line < 0:
            check.error("`surface.line` must be 0 or a line number")
        if s_id is not None and not (isinstance(s_id, str) and _SURFACE_ID_RE.match(s_id)):
            check.error("`surface.id` must be a plan id (`s-` and twelve hex digits) or null")
            s_id = None
        result.surface = {"id": s_id, "type": s_type, "file": s_file, "line": s_line}
        if s_id is None:
            result.surface_known = False
            check.note("a surface the plan did not list (`surface.id` is null)")
        elif plan_surfaces is not None:
            planned = plan_surfaces.get(s_id)
            if planned is None:
                check.error(f"surface {s_id} is not in this tree's plan")
            elif (planned["type"], planned["file"], planned["line"]) != (s_type, s_file, s_line):
                check.error(
                    f"surface {s_id} is the plan's {planned['type']} at "
                    f"{planned['file']}:{planned['line']}, not {s_type} at {s_file}:{s_line}"
                )
            else:
                result.surface_known = True
                result.surface["span"] = planned.get("span")
                pairs = {(h["mechanism"], h["pattern"]) for h in planned.get("hypotheses") or []}
                if (mechanism_id, _text(raw.get("pattern"))) not in pairs:
                    check.note(
                        f"the plan does not list {mechanism_id}/{_text(raw.get('pattern'))} "
                        f"for this {s_type}; the record answers no hypothesis of the plan"
                    )

    check.required_text(raw.get("hypothesis"), "hypothesis")

    # -- proposal -------------------------------------------------------------------------
    proposed = raw.get("proposed") if isinstance(raw.get("proposed"), dict) else {}
    p_status = _text(proposed.get("evidence_status"))
    p_decision = _text(proposed.get("decision"))
    if p_status not in policy.evidence_statuses:
        check.error(
            "`proposed.evidence_status` must be one of " + ", ".join(policy.evidence_statuses)
        )
    if p_decision == Decision.NOT_ASSESSED.value:
        check.error(
            "`proposed.decision` cannot be not_assessed: that is what having no record means"
        )
    elif p_decision not in policy.decisions:
        check.error("`proposed.decision` must be one of " + ", ".join(policy.decisions))
    result.proposed = {"evidence_status": p_status, "decision": p_decision}
    deciding = p_decision in (_VIOLATES, _CLOSE)

    # -- links ---------------------------------------------------------------------------
    raw_links = _list(raw.get("links"))
    if raw_links is None:
        check.error("`links` must be a list")
        raw_links = []
    remote_lines = check.run_time_lines()
    # Decided from the scan's rows too: a fetch line recorded as a plain prompt, or as a surface
    # the plan never listed, is still one. A model call the plan lists stays what it is.
    surface_fetched = s_type in _RUNTIME_SURFACES or (
        surface is not None
        and (s_file, s_line) in remote_lines
        and (s_type == "prompt" or s_id is None)
    )

    def fetched_at_run_time(cited: dict[str, Any]) -> bool:
        last = cited["end_line"] or cited["line"]
        return any((cited["file"], n) in remote_lines for n in range(cited["line"], last + 1))

    seen_ids: set[str] = set()
    links: list[dict[str, Any]] = []
    for index, item in enumerate(raw_links):
        where = f"links[{index}]"
        if not isinstance(item, dict):
            check.error(f"{where}: not an object")
            continue
        link_id = _text(item.get("id")) or f"l{index + 1}"
        if link_id in seen_ids:
            check.error(f"{where}: link id {link_id} is used twice")
        seen_ids.add(link_id)
        kind = _text(item.get("kind"))
        how = _text(item.get("how"))
        if kind not in kinds_of_view:
            check.error(f"{where}: kind {kind or 'empty'} is not a link of the {view or '?'} view")
        if how not in HOW:
            check.error(f"{where}: `how` must be one of {', '.join(HOW)}")
        cited = check.citation(item, where, role="link")
        if cited is None:
            continue
        via = []
        for hop_index, hop in enumerate(_list(item.get("via")) or []):
            hop_where = f"{where}.via[{hop_index}]"
            hop_cited = check.citation(hop, hop_where, role="link")
            if hop_cited is not None:
                hop_cited["step"] = _text(hop.get("step")) if isinstance(hop, dict) else ""
                via.append(hop_cited)
        reading = scan.reading_of(cited["file"])
        runtime = how == "runtime-only" or (
            kind in _PROMPT_BORNE and (surface_fetched or fetched_at_run_time(cited))
        )
        if runtime and how != "runtime-only":
            check.note(
                f"{where}: {cited['file']}:{cited['line']} is a prompt the scan lists as fetched "
                "or built at run time; the link counts as runtime-only"
            )
        no_code = check.not_code(cited)
        if no_code:
            check.note(
                f"{where}: {cited['file']}:{cited['line']} is a comment, an import or a line "
                "that never runs, so the link does not count"
            )
        if reading == "unsupported":
            lang = scan.lang_of(cited["file"]) or "unknown"
            check.note(
                f"{where}: {cited['file']} is in a language the workbench does not read ({lang}); "
                "the link does not count"
            )
        if reading == "read":
            note = (
                "JS/TS: the reading rests on the investigator; no deterministic deep analysis "
                "backs it"
            )
            if note not in result.readings:
                result.readings.append(note)
        links.append(
            {
                "id": link_id,
                "kind": kind,
                "how": how,
                "file": cited["file"],
                "line": cited["line"],
                "end_line": cited["end_line"],
                "quote": cited["quote"],
                "from": _text(item.get("from")) or None,
                "via": via,
                "established_by": "runtime-only" if runtime else "investigated",
                "counted": reading != "unsupported" and kind in kinds_of_view and not no_code,
            }
        )
    result.links = links
    links_by_id = {link["id"]: link for link in links}

    # -- counterevidence, controls, absent links ----------------------------------------
    counter = _list(raw.get("counterevidence"))
    if counter is None:
        check.error("`counterevidence` must be a list")
        counter = []
    if deciding and not counter:
        check.error(
            "`counterevidence` is empty: a deciding record weighs at least one other reading"
        )
    benign_supported = False
    for index, item in enumerate(counter):
        where = f"counterevidence[{index}]"
        if not isinstance(item, dict):
            check.error(f"{where}: not an object")
            continue
        check.required_text(item.get("reading"), f"{where}.reading")
        check.required_text(item.get("reason"), f"{where}.reason")
        outcome = _text(item.get("result"))
        if outcome not in COUNTER_RESULTS:
            check.error(f"{where}: `result` must be one of {', '.join(COUNTER_RESULTS)}")
        elif outcome == "supported":
            benign_supported = True
        for c_index, citation in enumerate(_list(item.get("citations")) or []):
            check.citation(citation, f"{where}.citations[{c_index}]", role="counter")

    controls = _list(raw.get("controls"))
    if controls is None:
        check.error("`controls` must be a list")
        controls = []
    absent_control = (
        _norm_control(pattern.absent_control) if pattern and pattern.absent_control else None
    )
    control_states: list[str] = []
    # Controls said to be on the path, each with the link it names: judged once the chain is
    # known. Each is (where, location, link, via hops).
    control_claims: list[tuple[str, dict[str, Any], dict[str, Any], list[dict[str, Any]]]] = []
    control_searched = False
    control_fetched = False
    for index, item in enumerate(controls):
        where = f"controls[{index}]"
        if not isinstance(item, dict):
            check.error(f"{where}: not an object")
            continue
        name = check.required_text(item.get("name"), f"{where}.name")
        check.required_text(item.get("reason"), f"{where}.reason")
        on_path = _text(item.get("on_path"))
        if on_path not in ON_PATH:
            check.error(f"{where}: `on_path` must be one of {', '.join(ON_PATH)}")
        location = item.get("location")
        located = None
        if location is not None:
            located = check.citation(location, f"{where}.location", role="control")
        hops = []
        for hop_index, hop in enumerate(_list(item.get("via")) or []):
            hop_cited = check.citation(hop, f"{where}.via[{hop_index}]", role="control")
            if hop_cited is not None:
                hops.append(hop_cited)
        searched = [s for s in (_list(item.get("searched")) or []) if _text(s)]
        for s in searched:
            check.free_text(s, f"{where}.searched")
        if absent_control and _norm_control(name) == absent_control:
            control_states.append(on_path)
            if on_path == "no" and searched:
                control_searched = True
            if on_path == "yes":
                on_link = links_by_id.get(_text(item.get("link")))
                if located is None:
                    check.note(f"{where}: a control on the path needs its `location`")
                elif fetched_at_run_time(located):
                    control_fetched = True
                    check.note(
                        f"{where}: {located['file']}:{located['line']} is a prompt the scan lists "
                        "as fetched or built at run time; what it says cannot be read from the "
                        "tree, so it closes nothing"
                    )
                elif on_link is None:
                    check.note(
                        f"{where}: a control on the path names the `link` of the chain it sits "
                        "on; without one it does not close anything"
                    )
                else:
                    control_claims.append((where, located, on_link, hops))

    absent = _list(raw.get("absent_links"))
    if absent is None:
        absent = []
        if raw.get("absent_links") is not None:
            check.error("`absent_links` must be a list")
    ruled_out: set[str] = set()
    ruled_citations: dict[str, list[dict[str, Any]]] = {}
    for index, item in enumerate(absent):
        where = f"absent_links[{index}]"
        if not isinstance(item, dict):
            check.error(f"{where}: not an object")
            continue
        kind = _text(item.get("kind"))
        if kind not in kinds_of_view:
            check.error(f"{where}: kind {kind or 'empty'} is not a link of the {view or '?'} view")
            continue
        searched = [s for s in (_list(item.get("searched")) or []) if _text(s)]
        if not searched:
            check.error(f"{where}: `searched` is empty: say where the link was looked for")
        for s in searched:
            check.free_text(s, f"{where}.searched")
        check.required_text(item.get("reason"), f"{where}.reason")
        # A kind the pattern does not need leaves the chain as it is: it answers no surface.
        role = "absent" if pattern is not None and kind in pattern.links else "absent-unneeded"
        for c_index, citation in enumerate(_list(item.get("citations")) or []):
            cited = check.citation(citation, f"{where}.citations[{c_index}]", role=role)
            if cited is not None:
                ruled_citations.setdefault(kind, []).append(cited)
        ruled_out.add(kind)

    for key in ("open_questions", "missing_evidence"):
        value = _list(raw.get(key))
        if value is None:
            check.error(f"`{key}` must be a list")
            continue
        for item in value:
            check.free_text(item if isinstance(item, str) else "", key)
    open_items = bool(_list(raw.get("open_questions"))) or bool(_list(raw.get("missing_evidence")))

    for index, item in enumerate(_list(raw.get("untrusted_text")) or []):
        cited = check.citation(item, f"untrusted_text[{index}]", role="untrusted")
        if cited is not None:
            cited["note"] = _text(item.get("note"))
            result.untrusted.append(cited)

    for index, item in enumerate(_list(raw.get("depends_on")) or []):
        where = f"depends_on[{index}]"
        relpath = _text(item.get("file")).replace("\\", "/") if isinstance(item, dict) else ""
        sha = _text(item.get("sha256")).lower() if isinstance(item, dict) else ""
        if not relpath or not SHA_RE.match(sha):
            check.error(f"{where}: needs `file` and a 64-hex `sha256`")
        elif check.lines_of(relpath) is None:
            check.error(f"{where}: {relpath} is not a file the scan walked")
        elif check._hashes[relpath] != sha:
            check.error(f"{where}: {relpath} changed since the record was written")

    # The record answers the surface it names: a link, or a citation ruling out a link the
    # pattern needs, is in that file, and inside the surface's span when the plan gives one.
    if surface is not None and s_type not in _UNIT_SURFACES and s_file in scan.walked:
        in_file = [
            (lo, hi)
            for file, lo, hi, role in check.citations
            if file == s_file and role in ("link", "absent")
        ]
        span = result.surface.get("span")
        if not in_file:
            check.error(f"the record cites nothing in {s_file}, the file of the surface it answers")
        elif span and not any(lo <= span[1] and hi >= span[0] for lo, hi in in_file):
            check.error(
                f"the record cites nothing in lines {span[0]}-{span[1]} of {s_file}, the "
                "surface it answers"
            )
    # A person-facing unit is answered by a link (or a `via` hop of one) in one of its files.
    if surface is not None and s_type in _UNIT_SURFACES:
        unit = _unit_of(result.surface, scan)
        if not any(
            role == "link" and getattr(scan.walked.get(file), "unit", None) == unit
            for file, _lo, _hi, role in check.citations
        ):
            check.error(f"the record cites no link in {s_file}, the person-facing unit it answers")
    result.cited_files = sorted({file for file, _lo, _hi, _role in check.citations})
    result.cited_spans = sorted({(file, lo, hi) for file, lo, hi, _role in check.citations})

    # -- skeptic ----------------------------------------------------------------------------
    skeptic = raw.get("skeptic") if isinstance(raw.get("skeptic"), dict) else None
    if skeptic is None:
        check.error("`skeptic` must be an object with `result` and `reason`")
        skeptic = {}
    claimed = _text(skeptic.get("result"))
    if claimed not in SKEPTIC_RESULTS:
        check.error(f"`skeptic.result` must be one of {', '.join(SKEPTIC_RESULTS)}")
    check.required_text(skeptic.get("reason"), "skeptic.reason")
    result.skeptic = _bind_skeptic(skeptic, claimed, path, result, check)

    # -- verification steps -------------------------------------------------------------
    steps = _list(raw.get("verification_steps"))
    if steps is None:
        check.error("`verification_steps` must be a list")
        steps = []
    if deciding and not steps:
        check.error("`verification_steps` is empty: a deciding record names how a retest checks it")
    step_ids: set[str] = set()
    for index, item in enumerate(steps):
        where = f"verification_steps[{index}]"
        if not isinstance(item, dict):
            check.error(f"{where}: not an object")
            continue
        step_id = _text(item.get("id")) or f"v{index + 1}"
        if step_id in step_ids:
            check.error(f"{where}: step id {step_id} is used twice")
        step_ids.add(step_id)
        purpose = _text(item.get("purpose"))
        kind = _text(item.get("kind"))
        if purpose not in STEP_PURPOSES:
            check.error(f"{where}: `purpose` must be one of {', '.join(STEP_PURPOSES)}")
            continue
        if kind not in STEP_KINDS:
            check.error(f"{where}: `kind` must be one of {', '.join(STEP_KINDS)}")
            continue
        problem = _step_shape(item, kind)
        if problem:
            check.error(f"{where}: {problem}")
            continue
        check.free_text(_text(item.get("note")), f"{where}.note")
        passes, detail = run_step(item, scan)
        entry = {
            "id": step_id,
            "purpose": purpose,
            "kind": kind,
            "spec": {k: item[k] for k in ("file", "quote", "rule", "family", "note") if k in item},
            "passes_at_record": passes,
            "detail": detail,
        }
        if kind in ("absent", "present", "no_finding") and passes is None:
            check.error(f"{where}: {detail}")
        if purpose == "remediation" and passes is True:
            check.error(
                f"{where}: remediation step {step_id} already passes at this commit, so it "
                "tests nothing"
            )
        if purpose == "regression" and passes is False:
            check.error(f"{where}: regression step {step_id} fails at this commit")
        result.steps.append(entry)
    if (
        p_decision == _VIOLATES
        and steps
        and not any(s.get("purpose") == "remediation" for s in steps if isinstance(s, dict))
    ):
        check.error("a record that proposes violates_policy names at least one remediation step")

    # -- covers, supersedes -------------------------------------------------------------
    covers = [c for c in (_list(raw.get("covers")) or []) if isinstance(c, str)]
    for fp in covers:
        if not _FP_RE.match(fp):
            check.error(f"`covers`: {fp!r} is not a finding fingerprint (16 hex digits)")
    result.covers = covers
    supersedes = [s for s in (_list(raw.get("supersedes")) or []) if isinstance(s, str)]
    for sid in supersedes:
        if not ID_RE.match(sid):
            check.error(f"`supersedes`: {sid!r} is not a record id")
    result.supersedes = supersedes

    if result.errors:
        result.status = "rejected"
        return result

    # -- effective status --------------------------------------------------------------
    assert pattern is not None and mechanism is not None
    required = list(pattern.links)
    result.required = required
    counted = [link for link in links if link["counted"]]
    supported = [x for x in counted if x["established_by"] == "investigated"]
    supported_kinds = {x["kind"] for x in supported}
    runtime_kinds = {x["kind"] for x in counted if x["established_by"] == "runtime-only"}
    missing = [k for k in required if k not in supported_kinds]
    runtime = [k for k in required if k in runtime_kinds and k not in supported_kinds]
    result.missing = missing
    result.runtime = runtime
    result.ruled_out = sorted(ruled_out & set(required), key=required.index)
    # Runtime-only links never bridge a chain: connectedness is over supported links.
    chain = _chain(supported, required, check)
    connected = bool(chain)
    result.connected = connected
    result.complete = not missing and connected
    contradictory = "yes" in control_states and (
        "no" in control_states or "unknown" in control_states
    )
    if contradictory:
        check.note(
            f"the record says {pattern.absent_control} is on the path and also that it is "
            "not, or that it cannot tell; it closes nothing"
        )
    control_located = control_read = False
    if control_claims and not result.complete:
        check.note(
            f"{pattern.absent_control} is said to be on the path, but the chain it sits on is "
            "not complete; it closes nothing"
        )
    elif control_claims:
        for where, located, on_link, hops in control_claims:
            problem = _control_problem(
                located, on_link, hops, supported, chain, absent_control, ruled_out, check
            )
            if problem is None:
                control_located = True
                control_read = control_read or all(
                    check.tree_of(file) is not None
                    for file in _closing_files(located, supported, chain, result.surface, check)
                )
            else:
                check.note(f"{where}: {problem}; it closes nothing")
    result.control_on_path = control_located and not contradictory
    cited_kinds = {x["kind"] for x in links}
    both = sorted(ruled_out & cited_kinds)
    for kind in both:
        check.note(f"the record cites a {kind} link and also rules {kind} out")

    status, decision = p_status, p_decision
    if status == _OBSERVED:
        status = _SUPPORTED
        check.note(
            "observed_behavior becomes supported_mechanism: a record reads code; observed "
            "behaviour comes only from an evaluation report"
        )
    if decision == _VIOLATES:
        problems: list[str] = []
        if status == _SIGNAL:
            decision = _REVIEW
            check.note("a detected signal cannot violate the policy; the decision is a review")
        if status == _UNKNOWN:
            decision = _REVIEW
        if missing:
            problems.append(
                "the trace lacks "
                + ", ".join(f"{k} (runtime-only)" if k in runtime else k for k in missing)
            )
        elif not connected:
            problems.append(
                "the cited links do not form one chain of supported links (`from` edges, "
                "`via` hops across files)"
            )
        if absent_control:
            if "yes" in control_states:
                problems.append(
                    f"the record finds {pattern.absent_control} on the path, so it cannot "
                    "establish its absence"
                )
            elif "no" not in control_states:
                problems.append(
                    f"the record does not show {pattern.absent_control} absent on the path"
                )
            elif not control_searched:
                problems.append(
                    f"the record does not say where it looked for {pattern.absent_control} "
                    "(`searched`)"
                )
        if problems:
            status, decision = _UNKNOWN, _REVIEW
            for problem in problems:
                check.note(problem + "; the claim is unknown and goes to review")
        if decision == _VIOLATES and benign_supported:
            decision = _REVIEW
            check.note("a benign reading was found supported; a person weighs the two")
        if decision == _VIOLATES and open_items:
            decision = _REVIEW
            check.note("questions stay open or evidence is missing; the decision is a review")
    elif decision == _CLOSE:
        closes_by_control = result.control_on_path
        if status != _SUPPORTED:
            decision = _REVIEW
            check.note(
                "a closing reading must be supported by the cited code; the decision is a review"
            )
        if decision == _CLOSE and closes_by_control and not control_read:
            decision = _REVIEW
            check.note(
                f"{pattern.absent_control} is outside the Python the syntax tree read, and this "
                "tool does no deep analysis there, so the machine cannot show it runs; a person "
                "weighs it and can still close it"
            )
        if decision == _CLOSE and surface_fetched:
            status, decision = _UNKNOWN, _REVIEW
            check.note(
                "the surface is a prompt fetched at run time: what it says cannot be ruled out "
                "from the tree; the claim is unknown and goes to review"
            )
        uncovered = [k for k in required if k not in supported_kinds and k not in ruled_out]
        broken = [k for k in required if k in ruled_out and k not in cited_kinds]
        fetched = _ruled_out_at_run_time(broken, result, scan)
        if fetched:
            status, decision = _UNKNOWN, _REVIEW
            result.runtime = [*runtime, *(k for k in fetched if k not in runtime)]
            check.note(
                f"{', '.join(fetched)} is ruled out, and a prompt fetched at run time is in play: "
                "what it says cannot be read from the tree, so no citation answers it; the claim "
                "is unknown and goes to review"
            )
        if decision == _CLOSE and not closes_by_control and both:
            decision = _REVIEW
            check.note(
                "a link both cited and ruled out cannot break the chain; the decision is a review"
            )
        if decision == _CLOSE and not closes_by_control:
            if uncovered:
                status, decision = _UNKNOWN, _REVIEW
                check.note(
                    "the record neither traces nor rules out "
                    + ", ".join(uncovered)
                    + "; the claim is unknown and goes to review"
                )
            elif not broken:
                decision = _REVIEW
                check.note(
                    "every required link is traced; a benign reading of a complete trace is for "
                    "a person to weigh"
                )
        if decision == _CLOSE and not closes_by_control:
            contradicted = _scan_contradictions(
                broken, ruled_citations, result.surface, scan, links
            )
            if contradicted:
                decision = _REVIEW
                for kind, where in contradicted:
                    check.note(
                        f"the scan lists {kind} in this unit ({where}); ruling it out needs a "
                        "citation of each of those rows that answers it"
                    )
        if decision == _CLOSE and benign_supported:
            decision = _REVIEW
            check.note("a reading under which the mechanism is present was found supported")
        if decision == _CLOSE and open_items:
            decision = _REVIEW
            check.note("questions stay open or evidence is missing; the decision is a review")
    # Whatever was proposed: the tree does not carry a link only a run can show.
    if runtime and status == _SUPPORTED:
        status, decision = _UNKNOWN, _REVIEW
        check.note("a required link is runtime-only; the claim is unknown and goes to review")
    if control_fetched:
        status, decision = _UNKNOWN, _REVIEW
        if pattern.absent_control not in result.runtime:
            result.runtime = [*result.runtime, pattern.absent_control]
        check.note(
            f"{pattern.absent_control} is said to sit in a prompt fetched at run time; the claim "
            "is unknown and goes to review"
        )
    result.effective = {"evidence_status": status, "decision": decision}
    result.claim = {_VIOLATES: "establishes", _CLOSE: "closes"}.get(decision, "review")

    _check_covers(result, scan, check)
    result.status = "accepted"
    return result


def _chain(links: list[dict[str, Any]], required: list[str], check: _Checker) -> set[str]:
    """The ids of the links in a connected component of `from` edges that holds a link of
    every required kind; empty when none does. An edge between two files counts only with a
    `via` hop, in one of them, that imports or calls the other (`_hop_joins`)."""
    by_id = {link["id"]: link for link in links}
    present = {link["kind"] for link in links}
    if not set(required) <= present:
        return set()
    parent = {link_id: link_id for link_id in by_id}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for link in links:
        source = link.get("from")
        if not source:
            continue
        if source not in by_id:
            check.note(
                f"link {link['id']} follows {source}, which is not a supported link of the "
                "record; the edge does not count"
            )
            continue
        if by_id[source]["file"] != link["file"]:
            joined = {by_id[source]["file"], link["file"]}
            if not any(
                hop["file"] in joined and _hop_joins(hop, next(iter(joined - {hop["file"]})), check)
                for hop in link["via"]
            ):
                check.note(
                    f"the edge from {source} to {link['id']} crosses files with no `via` hop "
                    "that imports or calls the other file; it does not count"
                )
                continue
        parent[find(link["id"])] = find(source)
    groups: dict[str, list[dict[str, Any]]] = {}
    for link in links:
        groups.setdefault(find(link["id"]), []).append(link)
    return {
        link["id"]
        for group in groups.values()
        if set(required) <= {link["kind"] for link in group}
        for link in group
    }


_QUOTED_RE = re.compile(r"""(["'`])((?:\\.|(?!\1).)*)\1""")


def _hop_joins(hop: dict[str, Any], other: str, check: _Checker) -> bool:
    """The hop imports `other` or opens it, on a line that runs. From Python the syntax tree
    shows the import of a Python file. Anywhere else a line can only name the file: a string
    literal on a line that runs (no comment) holds the file's name with its extension, or for a
    code file its path as a module (`"./telemetry"`), with any folders before it matching the
    file's own. A word that only looks like the file's stem (`persona = ...`, a log message)
    joins nothing."""
    scan = check.scan
    file = hop["file"]
    lo, hi = hop["line"], hop["end_line"] or hop["line"]
    tree = check.tree_of(file)
    if tree is not None and scan.reading_of(other) == "deep":
        return any(
            check.imports_file(file, path, level, other) for path, level in tree.paths_in(lo, hi)
        )
    if tree is not None:
        if any(
            check.imports_file(file, path, level, other) for path, level in tree.paths_in(lo, hi)
        ):
            return True
        literals = [
            text
            for first, _last, text in tree.strings
            if lo <= first <= hi and check.runs(file, first)
        ]
    else:
        lines = check.lines_of(file) or []
        comment = ("#", "//", "/*", "*")
        literals = [
            match.group(2)
            for n in range(lo, hi + 1)
            if not lines[n - 1].strip().startswith(comment)
            for match in _QUOTED_RE.finditer(lines[n - 1])
        ]
    module = scan.reading_of(other) in ("deep", "read")
    return any(_names_file(text, other, module) for text in literals)


def _names_file(text: str, other: str, module: bool) -> bool:
    """A string names the file `other`: its name with the extension, or (`module`) its stem as
    the last part of a path; the folders written before it are the last folders of its own."""
    path = PurePosixPath(other)
    text = text.replace("\\", "/")
    spellings = [path.name, *([path.stem] if module and path.suffix else [])]
    folders = [part for part in path.parent.parts if part not in (".", "")]
    for spelling in spellings:
        pattern = rf"(?<![\w.@-]){re.escape(spelling)}(?![\w-]|\.\w)"
        if spelling == path.stem:
            pattern = rf"(?:^|/){re.escape(spelling)}$"
        for match in re.finditer(pattern, text):
            before = re.search(r"[\w./@-]*$", text[: match.start()]).group()
            written = [part for part in before.split("/") if part not in ("", ".", "..")]
            size = min(len(written), len(folders))
            if written[len(written) - size :] == folders[len(folders) - size :]:
                return True
    return False


def _followed(
    link: dict[str, Any], kind: str, by_id: dict[str, dict[str, Any]], chain: set[str]
) -> list[dict[str, Any]]:
    """The links of `kind` that `link` comes after, walking back the `from` edges of `chain`."""
    found: list[dict[str, Any]] = []
    seen = {link["id"]}
    source = link.get("from")
    while source in chain and source not in seen:
        seen.add(source)
        if by_id[source]["kind"] == kind:
            found.append(by_id[source])
        source = by_id[source].get("from")
    return found


def _transformation_problem(
    control: str,
    located: dict[str, Any],
    hops: list[dict[str, Any]],
    supported: list[dict[str, Any]],
    chain: set[str],
    ruled_out: set[str],
    check: _Checker,
) -> str | None:
    """Why the data is not shown transformed before it leaves; None when it is.

    Every send the record cites follows, on the chain, a transformation link that runs and
    is on the way to it, by the test a control passes (`_shown_before`): in its function
    before it, or reached by a real call there. The location of the control can be that call.
    A send that is no supported link cannot be shown to. `logging` is cited or ruled out: a
    raw copy in a log is a send the chain does not show."""
    by_id = {link["id"]: link for link in supported}
    if "logging" not in ruled_out and not any(x["kind"] == "logging" for x in supported):
        return (
            f"{control} closes only with `logging` cited or ruled out: a raw copy in a log or "
            "a trace leaves the service as a send does"
        )
    for send in (x for x in check.result.links if x["kind"] in _SEND_KINDS):
        where = f"{send['file']}:{send['line']}"
        if send["id"] not in by_id:
            return f"the {send['kind']} at {where} is not a supported link, so it is not shown"
        before = [
            step
            for step in _followed(send, "transformation", by_id, chain)
            if not check.names_only(step)
            and (step["file"] != send["file"] or (step["end_line"] or step["line"]) < send["line"])
            and _shown_before(
                step,
                send["file"],
                send["line"],
                [located, *hops, *step["via"], *send["via"]],
                check,
            )
        ]
        if not before:
            return (
                f"{control} needs the transformation itself cited as a link, on a line that "
                f"runs and before the {send['kind']} at {where}, which follows it (`from`)"
            )
    return None


def _control_problem(
    located: dict[str, Any],
    on_link: dict[str, Any],
    hops: list[dict[str, Any]],
    supported: list[dict[str, Any]],
    chain: set[str],
    control: str | None,
    ruled_out: set[str],
    check: _Checker,
) -> str | None:
    """Why a control said to be on the path is not shown there; None when it is.

    The link it guards is the chain's intervention or transmission: a control on the prompt or
    on the way in says nothing of what reaches the person. It takes a line that runs (not an
    import, a comment, a definition's header, an expression with no effect, code that never
    runs: `_Tree`), wholly at or before every intervention and transmission of the chain, on
    the path to it; in the unit a unit surface names, and with a link of the chain on the
    surface's own line for any other surface. On a unit surface, every model call of the unit
    is answered (`_call_answered`). In Python, the line is in the function of that link, not
    in another arm of an `if` or a `try`, not in an `except` branch the link is outside; a
    line elsewhere needs a `via` hop that meets the same test and that the syntax tree shows
    reaching it through an import, with no local definition hiding the name (`_hop_reaches`).
    A control in another language or in a config file, from Python, needs a hop that names the
    file. Elsewhere only the file and the order can be read. A transformation (anonymisation)
    needs `_transformation_problem` to find nothing. This is the mechanical floor: whether the
    line does what the record says is for the skeptic pass. A control outside Python passes
    here at best: the claim stays a review (`validate_record`).
    """
    scan = check.scan
    surface = check.result.surface
    file = on_link["file"]
    if on_link["id"] not in chain:
        return f"link {on_link['id']} is not on the connected chain of the pattern"
    if on_link["kind"] not in _GUARDED_KINDS:
        return (
            f"link {on_link['id']} is a {on_link['kind']} link: a control guards the chain's "
            "intervention or transmission, what reaches the person or leaves the service"
        )
    if surface.get("type") in _UNIT_SURFACES:
        if getattr(scan.walked.get(file), "unit", None) != _unit_of(surface, scan):
            return f"link {on_link['id']} is outside the unit the record answers"
    elif not _chain_on_surface(surface, supported, chain, check):
        return f"no link of the chain sits in the surface at {surface.get('file')}"
    if check.names_only(located):
        return (
            f"{located['file']}:{located['line']} is an import, a comment, a definition's header "
            "or a line that never runs: it names the control and does not show it runs"
        )
    if control in _TRANSFORMING_CONTROLS:
        problem = _transformation_problem(
            control, located, hops, supported, chain, ruled_out, check
        )
        if problem is not None:
            return problem
    guarded = [x for x in supported if x["id"] in chain and x["kind"] in _GUARDED_KINDS]
    for link in guarded:
        if not _shown_before(located, link["file"], link["line"], hops, check):
            target = _target_of(located, link["file"], check)
            return (
                f"{located['file']}:{located['line']} is not at or before link {link['id']} on "
                f"the way to it in its "
                f"{'function' if check.tree_of(link['file']) is not None else 'file'}, and no "
                f"`via` hop there reaches {target.name if target else 'it'}"
            )
    for where, line in _unit_calls(surface, scan):
        if not _call_answered(where, line, located, hops, guarded, check):
            return (
                f"the model call at {where}:{line} is in the unit, and the control is not on the "
                "way to it nor to a guarded link that call's reply reaches"
            )
    for where, line in _prompt_calls(surface, check):
        if not _call_answered(where, line, located, hops, guarded, check):
            return (
                f"the model call at {where}:{line} takes the prompt the record answers, and the "
                "control is not on the way to it nor to a guarded link that call's reply reaches"
            )
    return None


def _chain_on_surface(
    surface: dict[str, Any],
    supported: list[dict[str, Any]],
    chain: set[str],
    check: _Checker,
) -> bool:
    """A link of the chain covers the surface's own line (its whole statement, in Python): the
    window around it holds what the surface is near, not what it is. A surface that is a whole
    file (line 0, or a span to its end) is covered by a link anywhere in it."""
    file = surface.get("file")
    line = surface.get("line") or 0
    span = surface.get("span")
    lo, hi = 1, 10**9
    if line and not (span and span[1] >= 10**9):
        tree = check.tree_of(file)
        stmt = tree.statement_at(line) if tree is not None else None
        lo, hi = _statement_lines(stmt) if stmt is not None else (line, line)
    return any(
        x["id"] in chain
        and x["file"] == file
        and x["line"] <= hi
        and (x["end_line"] or x["line"]) >= lo
        for x in supported
    )


def _unit_calls(surface: dict[str, Any], scan: MachineScan) -> list[tuple[str, int]]:
    """The model calls of the unit a unit surface names; none for any other surface."""
    if surface.get("type") not in _UNIT_SURFACES:
        return []
    unit = str(_unit_of(surface, scan))
    return sorted(
        {
            (str(row.get("file")), int(row.get("line") or 0))
            for row in scan.ctx.inventory.llm_calls or []
            if str(row.get("unit")) == unit and not _is_import_row(row)
        }
    )


def _prompt_calls(surface: dict[str, Any], check: _Checker) -> list[tuple[str, int]]:
    """The model calls a prompt surface reaches; none for any other surface. In a parsed
    Python file: each call fed from a name the prompt's statement binds (`_Tree.bound_from`),
    each call the scan ties to the prompt, and every call of another file that imports the
    prompt's file and names what it binds. Anywhere else the machine cannot tell which calls
    take the prompt: every model call of its unit."""
    if surface.get("type") != "prompt":
        return []
    scan = check.scan
    rows = sorted(
        {
            (str(row.get("file")), int(row.get("line") or 0), str(row.get("unit")))
            for row in scan.ctx.inventory.llm_calls or []
            if not _is_import_row(row)
        }
    )
    file, line = str(surface.get("file") or ""), int(surface.get("line") or 0)
    tree = check.tree_of(file) if file else None
    if tree is None or not line:
        unit = _unit_of(surface, scan)
        return [(f, n) for f, n, u in rows if unit is None or u == str(unit)]
    reached = tree.bound_from(line, {n for f, n, _u in rows if f == file})
    found = {(f, n) for f, n, _u in rows if f == file and n in reached}
    facts = scan.ctx.pyfacts
    if facts is not None:
        for prompts, feeds in (
            (facts.prompt_literals, facts.literal_feeds_call),
            (facts.prompt_assemblies, facts.assembly_feeds_call),
        ):
            for index, call in feeds.items():
                prompt = prompts[index]
                if prompt.file == file and prompt.line <= line <= max(prompt.end_line, prompt.line):
                    found.add((facts.llm_calls[call].file, facts.llm_calls[call].line))
    stmt = tree.statement_at(line)
    names = (
        {n.id for n in ast.walk(stmt) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
        if stmt is not None and tree.scope_at(line) is tree.module
        else set()
    )
    for other in sorted({f for f, _n, _u in rows if f != file}):
        text = "\n".join(check.lines_of(other) or [])
        if not any(re.search(rf"\b{re.escape(name)}\b", text) for name in names):
            continue
        held = check.tree_of(other)
        if held is None or any(
            check.imports_file(other, path, level, file) for _a, _b, path, level in held.imports
        ):
            found.update((f, n) for f, n, _u in rows if f == other)
    return sorted(found)


def _closing_files(
    located: dict[str, Any],
    supported: list[dict[str, Any]],
    chain: set[str],
    surface: dict[str, Any],
    check: _Checker,
) -> set[str]:
    """What the machine must have read for a control to close: the control, every link of the
    chain, every model call a unit surface answers for or a prompt surface reaches."""
    return {
        located["file"],
        *(x["file"] for x in supported if x["id"] in chain),
        *(file for file, _line in _unit_calls(surface, check.scan)),
        *(file for file, _line in _prompt_calls(surface, check)),
    }


def _comes_before(cited: dict[str, Any], file: str, line: int, check: _Checker) -> bool:
    """`cited` is wholly at or before `line` of `file`, and in Python a line of it that runs
    is surely on the path to that line (`_Tree.same_path`): not in a block that may not run
    unless that line is in it too, and not the header of such a block the citation reaches
    into (the header runs; what the citation shows inside may not)."""
    first, last = cited["line"], cited["end_line"] or cited["line"]
    if cited["file"] != file or last > line:
        return False
    tree = check.tree_of(file)
    return tree is None or any(
        check.runs(file, number)
        and tree.same_path(number, line)
        and not tree.heads_into(number, first, last)
        for number in range(first, last + 1)
    )


def _shown_before(
    cited: dict[str, Any], file: str, line: int, hops: list[dict[str, Any]], check: _Checker
) -> bool:
    """`cited` runs on the way to `line` of `file`: it sits there, or a hop there reaches it."""
    return _comes_before(cited, file, line, check) or any(
        _hop_reaches(hop, cited, file, line, check) for hop in hops
    )


def _hop_reaches(
    hop: dict[str, Any], located: dict[str, Any], file: str, line: int, check: _Checker
) -> bool:
    """The hop runs on the way to `line` of `file` and reaches `located`. From parsed Python to
    parsed Python, a call (or, for a constant, a read) on the hop must be bound to `located`
    (`_bound_to`), in no part of an expression that may not run; an `async def` must be
    awaited (directly, or as an argument of an awaited call such as `asyncio.gather`), and a
    generator reaches nothing. Otherwise only the text of the hop can be read: it names what
    `_target_of` gives. No name at all reaches nothing from Python."""
    if not _comes_before(hop, file, line, check) or check.names_only(hop):
        return False
    target = _target_of(located, file, check)
    python = check.scan.reading_of(file) == "deep"
    if target is None:
        return not python
    lo, hi = hop["line"], hop["end_line"] or hop["line"]
    tree = check.tree_of(file)
    if tree is not None and check.tree_of(located["file"]) is not None:
        # Calling a generator runs none of its body; nothing here shows it iterated.
        return not target.yields and any(
            lo <= use.line <= hi
            and not use.maybe
            and tree.same_path(use.line, line)
            and (use.called or not target.must_call)
            and (use.awaited or not target.awaits)
            and _bound_to(use, tree, file, target, located["file"], check)
            for use in tree.uses
        )
    numbers = range(lo, hi + 1)
    if tree is not None:
        text = " ".join(
            tree.code(n)
            for n in numbers
            if tree.same_path(n, line) and not tree.heads_into(n, lo, hi)
        )
    else:
        text = " ".join((check.lines_of(file) or [])[lo - 1 : hi])
    return bool(re.search(rf"\b{re.escape(target.name)}\b", text))


def _bound_to(
    use: _Use, tree: _Tree, file: str, target: _Target, target_file: str, check: _Checker
) -> bool:
    """Every binding of the name the code uses leads to the target: the definition itself in
    the file, or, through an import (a package's re-export included, `_Checker.resolves`), the
    target's name in the target's file, which binds that name there and nowhere else (a
    `global` statement in a function binds it in the module too). No parsed file stores to
    that name as an attribute of its module (`safety.crisis_check = ...`), nor to the name the
    code uses. A local name, a stub, an object's attribute or an import of another file does
    not lead there."""
    bindings = tree.bindings_of(use.parts[0], use.scope)
    held = check.tree_of(target_file)
    if not bindings or held is None or check.patched(target_file, target.name):
        return False
    for binding in bindings:
        if binding.path is None:
            if (
                file != target_file
                or use.parts != (target.name,)
                or not target.lo <= binding.line <= target.hi
            ):
                return False
            continue
        path = (*binding.path, *use.parts[1:])
        if not check.resolves(file, path, binding.level, target_file, target.name):
            return False
        if len(use.parts) == 1 and check.patched(file, use.parts[0]):
            return False
        others = held.module.bindings.get(target.name, [])
        if not others or not all(target.lo <= other.line <= target.hi for other in others):
            return False
    return True


def _target_of(located: dict[str, Any], link_file: str, check: _Checker) -> _Target | None:
    """What a line on the way must reach to reach `located`: in Python the function that holds
    it (called), or at module level the name that statement binds (read); from Python, the
    stem of a file Python does not read. None where nothing can be named: a class body, a
    line at module level that binds no name, an `except` branch, a file that does not parse."""
    scan = check.scan
    file = located["file"]
    if scan.reading_of(file) != "deep":
        python_link = scan.reading_of(link_file) == "deep"
        return _Target(PurePosixPath(file).stem, False) if python_link else None
    tree = check.tree_of(file)
    if tree is None:
        return None
    last = located["end_line"] or located["line"]
    running = [
        n for n in range(located["line"], last + 1) if check.runs(file, n) and not tree.in_except(n)
    ]
    if not running:
        return None
    scope = tree.scope_at(running[0])
    if isinstance(scope.node, _DEFS):
        return _Target(
            scope.node.name,
            True,
            scope.lo,
            scope.hi,
            awaits=isinstance(scope.node, ast.AsyncFunctionDef),
            yields=any(
                isinstance(node, (ast.Yield, ast.YieldFrom)) for node in _own_nodes(scope.node)
            ),
        )
    stmt = tree.statement_at(running[0])
    if scope is not tree.module or not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
        return None
    targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
    names = [target.id for target in targets if isinstance(target, ast.Name)]
    return _Target(names[0], False, *_statement_lines(stmt)) if names else None


def _call_answered(
    file: str,
    line: int,
    located: dict[str, Any],
    hops: list[dict[str, Any]],
    guarded: list[dict[str, Any]],
    check: _Checker,
) -> bool:
    """The control is on the way to the model call, or, in the same function, the call's reply
    can only go on to a guarded link: nothing returns or raises between them. A second handler,
    or a raw call that returns early, is neither."""
    if _shown_before(located, file, line, hops, check):
        return True
    tree = check.tree_of(file)
    return tree is not None and any(
        link["file"] == file
        and line <= link["line"]
        and tree.same_path(line, link["line"], surely=False)
        and not tree.exits_between(line, link["line"])
        for link in guarded
    )


def _ruled_out_at_run_time(broken: list[str], result: RecordResult, scan: MachineScan) -> list[str]:
    """The ruled-out kinds that rest on a prompt fetched at run time: what a prompt carries,
    when the surface is such a prompt or the scan lists one anywhere in the tree. The unit
    does not limit this: a service can fetch the prompt a unit next to it sends."""
    kinds = [kind for kind in broken if kind in _PROMPT_BORNE]
    fetched = result.surface.get("type") in _RUNTIME_SURFACES or any(
        str(row.get("kind")) in ("remote", "runtime") for row in scan.ctx.inventory.prompts or []
    )
    return kinds if fetched else []


def _is_import_row(row: dict[str, Any]) -> bool:
    """An `llm_calls` row that is the import of a client, not a call of it."""
    return str(row.get("api") or "").startswith(("import ", "from "))


def _unit_of(surface: dict[str, Any], scan: MachineScan) -> str | None:
    record = scan.walked.get(surface.get("file") or "")
    if record is not None:
        return getattr(record, "unit", None)
    return next(
        (u.id for u in scan.ctx.inventory.units or [] if (u.root or ".") == surface.get("file")),
        None,
    )


def _finding_rows(kind: str, units: set[str], scan: MachineScan) -> list[dict[str, Any]]:
    """Where the findings that report `kind` sit, in the units. A finding reports the first of
    these kinds its pattern requires: AUD-1102 reports an inference, and the objective it would
    serve is what a trace looks for, so that finding says nothing of an objective."""
    rows: list[dict[str, Any]] = []
    for finding in scan.findings:
        pattern = scan.policy.pattern_of(finding.display_id)
        links = pattern.links if pattern is not None else ()
        if next((k for k in links if k in _FINDING_ROWS), None) != kind:
            continue
        for leg in finding.evidence:
            if leg.line and str(getattr(scan.walked.get(leg.file), "unit", None)) in units:
                rows.append({"file": leg.file, "line": leg.line, "kind": "finding"})
    return rows


def _scan_contradictions(
    broken: list[str],
    cited: dict[str, list[dict[str, Any]]],
    surface: dict[str, Any],
    scan: MachineScan,
    links: Iterable[dict[str, Any]] = (),
) -> list[tuple[str, str]]:
    """Ruled-out kinds the scan lists in the record's units (its surface's and its links'),
    when a citation of the ruled-out entry is not at each of those rows. A link the syntax tree
    established counts as a row whatever finding it came with: the kind is what is ruled out,
    not the pattern. For the prompt of a prompt surface, the rows are those inside that
    surface: the other prompts of the unit are surfaces of their own. So are the signals and
    findings of an objective or an inference, when the plan gives the surface a span."""
    units = {str(_unit_of(surface, scan))} | {
        str(getattr(scan.walked.get(link["file"]), "unit", None)) for link in links
    }
    own_prompt = surface.get("type") == "prompt"
    line = surface.get("line") or 0
    span = surface.get("span")
    lo, hi = span or (line, line)

    def in_surface(row: dict[str, Any]) -> bool:
        return str(row.get("file")) == surface.get("file") and lo <= int(row.get("line") or 0) <= hi

    out: list[tuple[str, str]] = []
    for kind in broken:
        # Not every kind has rows of its own; a link the syntax tree established counts for all.
        section = _SCAN_ROWS.get(kind, "")
        rows = [
            row
            for row in getattr(scan.ctx.inventory, section, None) or []
            if str(row.get("unit")) in units
            and not (section == "llm_calls" and _is_import_row(row))
            and (kind not in _SIGNAL_ROWS or str(row.get("kind")) in _SIGNAL_ROWS[kind])
        ]
        if kind in _FINDING_ROWS:
            rows += _finding_rows(kind, units, scan)
            if own_prompt and span:
                rows = [row for row in rows if in_surface(row)]
        # A link the syntax tree established, for any finding, in the unit.
        for finding in scan.findings:
            for flow_link in finding.flow.links if finding.flow is not None else ():
                in_unit = str(getattr(scan.walked.get(flow_link.file), "unit", None)) in units
                if flow_link.kind == kind and flow_link.supported and in_unit:
                    rows.append({"file": flow_link.file, "line": flow_link.line, "kind": "ast"})
        if not rows:
            continue
        if kind == "prompt" and own_prompt:
            rows = [row for row in rows if in_surface(row)] or [
                {"file": surface.get("file"), "line": line}
            ]
        unanswered: list[str] = []
        for row in rows:
            where = f"{row.get('file')}:{row.get('line')}"
            if where not in unanswered and not any(
                c["file"] == str(row.get("file"))
                and c["line"] <= int(row.get("line") or 0) <= (c["end_line"] or c["line"])
                for c in cited.get(kind, [])
            ):
                unanswered.append(where)
        if unanswered:
            out.append((kind, ", ".join(unanswered)))
    return out


def _check_covers(result: RecordResult, scan: MachineScan, check: _Checker) -> None:
    """A covered fingerprint counts when the scan reports it under the record's pattern and a
    link of the record cites the line its first evidence leg points at."""
    by_fp = {f.fingerprint: f for f in scan.findings}
    for fp in result.covers:
        finding = by_fp.get(fp)
        if finding is None:
            check.note(f"covers {fp}, which the scan does not report")
            continue
        pattern = scan.policy.pattern_of(finding.display_id)
        if finding.mechanism != result.mechanism or pattern is None or pattern.id != result.pattern:
            check.note(
                f"covers {fp} ({finding.display_id}), a finding of "
                f"{pattern.display_id if pattern else finding.mechanism}, not of "
                f"{result.mechanism}/{result.pattern}"
            )
            continue
        leg = finding.evidence[0] if finding.evidence else None
        unit_level = leg is not None and (leg.file in (".", "") or leg.line == 0)
        if unit_level:
            if (
                result.surface.get("type") == "person_facing_unit"
                and _unit_of(result.surface, scan) == finding.scope.unit
            ):
                result.covers_valid.append(fp)
            else:
                check.note(
                    f"covers {fp} ({finding.display_id}), a unit-level finding: only a record "
                    "on that unit's person-facing surface covers it"
                )
            continue
        if leg is None or not any(
            file == leg.file and lo <= leg.line <= hi and role == "link"
            for file, lo, hi, role in check.citations
        ):
            check.note(f"covers {fp} ({finding.display_id}) but no link cites its evidence line")
            continue
        result.covers_valid.append(fp)


def _bind_skeptic(
    skeptic: dict[str, Any], claimed: str, path: Path, result: RecordResult, check: _Checker
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "claimed": claimed,
        "result": "not_run",
        "bound": False,
        "file": None,
        "reason": _text(skeptic.get("reason")),
        "untrusted_text_checked": False,
    }
    if claimed not in ("upheld", "refuted"):
        return out
    name = _text(skeptic.get("file"))
    if not name:
        check.note("the skeptic result names no file; it is treated as not run")
        return out
    outside = "the skeptic file must sit in the record's directory; it is treated as not run"
    if not _SKEPTIC_NAME_RE.fullmatch(name):
        check.note(outside)
        return out
    skeptic_path = path.parent / name
    try:
        info = skeptic_path.lstat()
    except OSError as exc:
        why = exc.strerror or exc
        check.note(f"the skeptic file cannot be read ({why}); it is treated as not run")
        return out
    if not stat.S_ISREG(info.st_mode):  # a link, a device, a pipe or a directory
        check.note(outside)
        return out
    if info.st_size > _MAX_RECORD_BYTES:
        check.note("the skeptic file is larger than 8 MiB; it is treated as not run")
        return out
    try:
        doc = load_json(skeptic_path)
    except RecordError as exc:
        check.note(f"the skeptic file cannot be read ({exc}); it is treated as not run")
        return out
    why = None
    who = (
        doc.get("skeptic") if isinstance(doc, dict) and isinstance(doc.get("skeptic"), dict) else {}
    )
    claims = doc.get("claims") if isinstance(doc, dict) else None
    if (
        not isinstance(doc, dict)
        or doc.get("schema") != SKEPTIC_SCHEMA
        or doc.get("kind") != SKEPTIC_KIND
    ):
        why = f"it is not a {SKEPTIC_SCHEMA} document"
    elif doc.get("record_id") != result.id:
        why = "it names another record"
    elif doc.get("record_sha256") != result.digest:
        why = "its record_sha256 does not match this record (the record changed after the pass)"
    elif not all(_text(who.get(k)) for k in ("agent", "model", "version", "session")):
        why = "it does not name the skeptic's agent, model, version and session"
    elif _text(who.get("session")) == result.investigator.get("session"):
        why = "it ran in the investigator's own session, not a fresh context"
    elif _text(doc.get("result")) != claimed:
        why = f"it says {_text(doc.get('result')) or 'nothing'}, the record says {claimed}"
    elif not isinstance(claims, list) or not claims:
        why = "it lists no claim it tried to refute"
    elif not all(
        isinstance(c, dict)
        and _text(c.get("claim"))
        and _text(c.get("result")).lower() in ("upheld", "refuted")
        and _text(c.get("reason"))
        for c in claims
    ):
        why = "a claim in it is not {claim, result: upheld or refuted, reason}"
    if why is not None:
        check.note(f"the skeptic file is not bound to the record: {why}; it is treated as not run")
        return out
    parsed = [
        {
            "claim": _text(c.get("claim")),
            "result": _text(c.get("result")).lower(),
            "reason": _text(c.get("reason")),
        }
        for c in claims
    ]
    effective = claimed
    if claimed == "upheld" and any(c["result"] == "refuted" for c in parsed):
        effective = "refuted"
        check.note(
            "the skeptic pass says upheld but refutes one of its claims; it counts as a refutation"
        )
    out.update(
        {
            "result": effective,
            "bound": True,
            "file": name,
            "skeptic": {k: _text(who.get(k)) for k in ("agent", "model", "version", "session")},
            "claims": parsed,
            "untrusted_text_checked": doc.get("untrusted_text_checked") is True,
        }
    )
    return out


# ---------------------------------------------------------------------------
# Verification steps
# ---------------------------------------------------------------------------


def _step_shape(step: dict[str, Any], kind: str) -> str | None:
    if kind in ("absent", "present"):
        if not _text(step.get("file")) or not _text(step.get("quote")):
            return f"a `{kind}` step needs `file` and `quote`"
        if redact(str(step.get("quote"))) != str(step.get("quote")):
            return "the step's quote carries a secret-shaped string"
    elif kind == "no_finding":
        if not re.match(r"^AUD-\d{3,5}(?:/[a-z0-9-]+)?$", _text(step.get("rule"))):
            return (
                "a `no_finding` step needs `rule` (a rule id such as AUD-1108 or AUD-1105/persona)"
            )
    elif kind == "evaluation":
        if not _text(step.get("family")):
            return "an `evaluation` step needs `family` (a scenario family)"
    elif kind == "reinvestigate":
        if not _text(step.get("note")):
            return "a `reinvestigate` step needs `note`: what to read again"
    return None


def _quote_step(kind: str, relpath: str, quote: str, scan: MachineScan) -> tuple[bool | None, str]:
    """An `absent` or `present` step on one file: True passes, False fails, None cannot run."""
    record = scan.walked.get(relpath)
    if record is None:
        return None, (
            f"{relpath} is not in the walked tree, so the step cannot run: a file that "
            "disappears, moves or is skipped is not evidence either way"
        )
    try:
        text = "\n".join(file_lines(record.path))
    except OSError:
        return None, f"{relpath} cannot be read, so the step cannot run"
    found = quote_in_text(text, quote)
    state = "present in" if found else "absent from"
    return (not found if kind == "absent" else found), f"the quote is {state} {relpath}"


def run_step(
    step: dict[str, Any], scan: MachineScan, places: Iterable[str] = ()
) -> tuple[bool | None, str]:
    """Run one verification step against `scan`. True passes, False fails, None cannot run
    (`reinvestigate`, or an `absent`, `present` or `no_finding` step whose file the walk does
    not read: a file that is not read has no findings, which shows nothing).

    `places` are the files the step's file may have gone to: a rename target, or the files a
    deleted one's text may have moved to. An `absent` or `present` step reads them too, so a
    rename never dodges it. The quote in any of them fails an `absent` step; a `present` step
    passes when the quote is in its file or in one of them. A step that cannot run on its own
    file, and finds the quote nowhere it went, still cannot run: it named another file."""
    kind = _text(step.get("kind"))
    if kind in ("absent", "present"):
        relpath = _text(step.get("file")).replace("\\", "/")
        quote = str(step.get("quote"))
        now, detail = _quote_step(kind, relpath, quote, scan)
        moved = sorted({str(place) for place in places} - {relpath})
        if not moved:
            return now, detail
        if now is None:
            detail = f"the step cannot run on {relpath}"
        ran = {place: _quote_step(kind, place, quote, scan)[0] for place in moved}
        unread = [place for place in moved if ran[place] is None]
        if len(unread) == len(moved):
            return now, f"{detail}; {', '.join(moved)}, where it may have gone, cannot be read"
        unread_note = f" ({', '.join(unread)} cannot be read)" if unread else ""
        if kind == "absent":
            holding = [place for place in moved if ran[place] is False]
            if holding:
                return False, (
                    f"{detail}; the quote is present in {', '.join(holding)}, where "
                    f"{relpath} may have gone"
                )
            return now, (
                f"{detail}; the quote is absent from "
                + ", ".join(place for place in moved if place not in unread)
                + f", where {relpath} may have gone{unread_note}"
            )
        holding = [place for place in moved if ran[place] is True]
        if now is True or holding:
            return True, detail + (
                f"; the quote is present in {', '.join(holding)}, where {relpath} may have gone"
                if holding
                else ""
            )
        return False, (
            f"{detail}; the quote is absent from "
            + ", ".join(place for place in moved if place not in unread)
            + f" too, where {relpath} may have gone{unread_note}"
        )
    if kind == "no_finding":
        rule = _text(step.get("rule"))
        relpath = _text(step.get("file")).replace("\\", "/") or None
        roots = {u.root or "." for u in scan.ctx.inventory.units or []}
        if relpath is not None and relpath not in scan.walked and relpath not in roots:
            return None, (
                f"{relpath} is not in the walked tree, so the step cannot run: a file the walk "
                "does not read has no findings, which shows nothing"
            )
        hits = [
            f
            for f in scan.findings
            if (f.display_id == rule or ("/" not in rule and f.id == rule))
            and (relpath is None or any(leg.file == relpath for leg in f.evidence))
        ]
        return (not hits), f"{len(hits)} finding(s) of {rule}" + (
            f" in {relpath}" if relpath else ""
        )
    if kind == "evaluation":
        from aisafe.rules._common import evaluation_demonstrates

        family = _text(step.get("family"))
        verdict, record = evaluation_demonstrates(
            scan.ctx, family, int(getattr(scan.policy, "evaluation_max_age_days", 30) or 30)
        )
        source = getattr(record, "file", None) or "no fresh report"
        if verdict is True:
            return True, f"{family} passed in {source}"
        if verdict is False:
            return False, f"{family} failed in {source}"
        return False, f"{family} not demonstrated ({source})"
    return None, "read again by a person or an agent; never passes mechanically"


def quote_spans(text: str, quote: str) -> list[tuple[int, int]]:
    """The lines (first, last) of every place the quote occurs in the text, both normalised:
    what `quote_in_text` matches, located. A quote may run across lines."""
    q = normalise(quote)
    if not q:
        return []
    flat = ""
    starts: list[int] = []
    numbers: list[int] = []
    for number, line in enumerate(text.split("\n"), start=1):
        part = normalise(line)
        if not part:
            continue
        if flat:
            flat += " "
        starts.append(len(flat))
        numbers.append(number)
        flat += part
    spans = []
    index = flat.find(q)
    while index != -1:
        first = numbers[bisect_right(starts, index) - 1]
        last = numbers[bisect_right(starts, index + len(q) - 1) - 1]
        spans.append((first, last))
        index = flat.find(q, index + 1)
    if not spans and quote_in_text(text, quote):
        # Not expected; a match this cannot place is one no citation covers.
        spans.append((0, 0))
    return spans


def quote_places(
    step: dict[str, Any], files: Iterable[str], scan: MachineScan
) -> dict[str, list[tuple[int, int]]]:
    """The files among `files` that hold the quote of an `absent` step, its own file aside,
    each with the lines (first, last) of every place the quote occurs there. The step reads
    one file, so a copy beside a stub passes it. A file the walk does not read is read here
    too, since a move out of its sight is the case this is for; one over
    `_MAX_SEARCHED_BYTES` is not, and stays in the `files_not_read` gap."""
    quote = str(step.get("quote") or "")
    own = _text(step.get("file")).replace("\\", "/")
    hits: dict[str, list[tuple[int, int]]] = {}
    for relpath in sorted(set(files) - {own}):
        record = scan.walked.get(relpath)
        path = record.path if record is not None else scan.root / relpath
        try:
            if record is None and (
                path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_SEARCHED_BYTES
            ):
                continue
            text = "\n".join(file_lines(path))
        except OSError:
            continue
        spans = quote_spans(text, quote)
        if spans:
            hits[relpath] = spans
    return hits


def quote_copies(step: dict[str, Any], files: Iterable[str], scan: MachineScan) -> list[str]:
    """The files among `files` that hold the quote of an `absent` step, its own file aside
    (`quote_places` says where in each)."""
    return sorted(quote_places(step, files, scan))


# ---------------------------------------------------------------------------
# Files and the batch
# ---------------------------------------------------------------------------


def find_record_files(path: Path) -> tuple[list[Path], list[dict[str, str]]]:
    """The record files under `path` (itself when it is a file), and the documents there
    that are something else, with what they are. Every `*.json` is parsed: where its `schema`
    key sits does not matter. A file that cannot be read, that is too large, or whose label is
    not the exact one of another document may be a record that broke: it counts as one, and
    is rejected, so the assessment lists a gap instead of dropping it."""
    path = Path(path)
    candidates = (
        [path]
        if path.is_file()
        else sorted(p for p in path.rglob("*") if p.suffix.lower() == ".json")
    )
    records: list[Path] = []
    skipped: list[dict[str, str]] = []
    for candidate in candidates:
        try:
            if candidate.stat().st_size > _MAX_RECORD_BYTES:
                records.append(candidate)
                continue
            doc = json.loads(candidate.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError, RecursionError):  # ValueError: not UTF-8, not JSON, ...
            records.append(candidate)
            continue
        schema = doc.get("schema") if isinstance(doc, dict) else None
        kind = doc.get("kind") if isinstance(doc, dict) else None
        label = (schema, kind) if isinstance(schema, str) and isinstance(kind, str) else None
        if label == (SKEPTIC_SCHEMA, SKEPTIC_KIND):
            skipped.append({"path": candidate.as_posix(), "why": "a skeptic pass"})
        elif label == (SIGNOFF_SCHEMA, SIGNOFF_KIND):
            skipped.append({"path": candidate.as_posix(), "why": SIGNOFF_SKIPPED})
        elif label in _OTHER_DOCUMENTS and not path.is_file():
            skipped.append({"path": candidate.as_posix(), "why": f"a document of kind {kind}"})
        else:
            records.append(candidate)
    return records, skipped


def validate_paths(
    paths: Iterable[Path],
    scan: MachineScan,
    *,
    working_tree: bool = False,
    plan_surfaces: dict[str, dict[str, Any]] | None = None,
) -> ValidationRun:
    """Validate every record file under `paths` against `scan`, then the batch: ids used
    twice, supersessions (unknown id, a cycle, another mechanism, surface or pattern, a weaker
    claim over a violation)."""
    run = ValidationRun(
        root=scan.root, state=scan.state.to_dict(), mode=scan.mode, working_tree=working_tree
    )
    if not scan.state.clean and not working_tree:
        if scan.state.status_failed:
            run.fatal = (
                "git could not report the state of the tree, so it is not taken for the "
                "commit; fix git, or pass --working-tree to check the files as they are"
            )
            return run
        shown = ", ".join(scan.state.dirty[:5]) + (" ..." if len(scan.state.dirty) > 5 else "")
        run.fatal = (
            f"{len(scan.state.dirty)} file(s) differ from commit {scan.state.commit}: {shown}. "
            "Commit them, or pass --working-tree to check the files as they are on disk"
        )
        return run
    files: list[Path] = []
    for path in paths:
        found, skipped = find_record_files(Path(path))
        files.extend(found)
        run.skipped.extend(skipped)
    if not files:
        run.fatal = "no investigation record found"
        return run
    for file in sorted(set(files), key=lambda p: p.as_posix()):
        try:
            if file.stat().st_size > _MAX_RECORD_BYTES:
                raise RecordError(f"{file.as_posix()}: larger than 8 MiB; not read")
            raw = load_json(file)
        except (OSError, RecordError) as exc:
            result = RecordResult(path=file.as_posix())
            result.errors.append(str(exc))
            run.results.append(result)
            continue
        result = validate_record(
            raw,
            file,
            scan,
            mode=scan.mode,
            plan_surfaces=plan_surfaces,
            working_tree=working_tree,
        )
        if working_tree and result.accepted:
            result.notes.append("checked against the working tree, not a commit")
        run.results.append(result)
    _batch(run.results)
    return run


def _upheld(result: RecordResult) -> bool:
    return bool(result.skeptic.get("bound")) and result.skeptic.get("result") == "upheld"


def _hypothesis(result: RecordResult) -> tuple[Any, ...]:
    """What a record answers: its pattern on its surface (the plan's id, or, for a surface the
    plan did not list, its type, file and line)."""
    surface = result.surface
    place = surface.get("id") or (surface.get("type"), surface.get("file"), surface.get("line"))
    return (result.pattern, place)


def _batch(results: list[RecordResult]) -> None:
    owner: dict[str, RecordResult] = {}
    seen: dict[str, list[RecordResult]] = {}
    for result in results:
        if result.id is not None:
            seen.setdefault(result.id, []).append(result)
    for record_id, same in seen.items():
        if len(same) > 1:
            # Two files claim one id: neither is the record, whichever was written first.
            for result in same:
                result.status = "rejected"
                others = ", ".join(r.path for r in same if r is not result)
                result.errors.append(f"id {record_id} is also used by {others}")
    for result in results:
        if result.id is not None and result.accepted:
            owner[result.id] = result
    # Records of another commit: a fix that changes, renames or deletes what one cites gives
    # it more errors than the commit, and a new record may still name it. That replaces
    # nothing: it stays rejected (or, in a retest, is judged by its steps), so a violation it
    # established is not lifted here. An error starts with these words only when the commit
    # differs; another error can quote them from a path. An id two files claim is neither's.
    stale = {
        r.id
        for r in results
        if r.id is not None
        and r.status == "rejected"
        and len(seen[r.id]) == 1
        and any(e.startswith(_OTHER_COMMIT) for e in r.errors)
    }
    for result in results:
        if not result.accepted:
            continue
        for sid in result.supersedes:
            target = owner.get(sid)
            if target is None and sid in stale:
                result.notes.append(f"supersedes {sid}, a record of another commit")
                continue
            if target is None:
                result.status = "rejected"
                result.errors.append(
                    f"supersedes {sid}, which is not an accepted record here: to supersede a "
                    "record of an earlier commit, keep its record file in this folder"
                )
            elif target is result:
                result.status = "rejected"
                result.errors.append("a record cannot supersede itself")
            elif target.mechanism != result.mechanism:
                result.status = "rejected"
                result.errors.append(f"supersedes {sid}, a record of {target.mechanism}")
            elif _hypothesis(target) != _hypothesis(result):
                result.status = "rejected"
                result.errors.append(
                    f"supersedes {sid}, a record of another surface or pattern: a record replaces "
                    "only a reading of the same hypothesis"
                )
            elif (
                target.claim == "establishes"
                and _upheld(target)
                and not (result.claim == "establishes" and _upheld(result))
            ):
                result.status = "rejected"
                result.errors.append(
                    f"supersedes {sid}, a violation its skeptic pass upheld, with a record that "
                    "is not one: a violation is replaced only by another upheld violation"
                )
            elif (
                target.proposed.get("decision") == _VIOLATES
                and result.proposed.get("decision") != _VIOLATES
            ):
                # Whatever the machine made of it: a closing that replaced a proposal lowered
                # to a review could then be signed, and the violation would be gone by name.
                result.status = "rejected"
                result.errors.append(
                    f"supersedes {sid}, which proposes a violation, with a record that does not: "
                    "a proposed violation is replaced only by another proposed violation"
                )
            elif _CLAIM_RANK.get(result.claim or "", 0) < _CLAIM_RANK.get(target.claim or "", 0):
                result.status = "rejected"
                result.errors.append(
                    f"supersedes {sid}, which {target.claim} the mechanism, with a weaker "
                    f"claim ({result.claim}): a closing record never lowers a violation"
                )
    graph = {r.id: [s for s in r.supersedes if s in owner] for r in results if r.accepted and r.id}
    for start in list(graph):
        seen: set[str] = set()
        stack = [start]
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            for nxt in graph.get(node, []):
                if nxt == start:
                    owner[start].status = "rejected"
                    owner[start].errors.append("supersessions form a cycle")
                    stack = []
                    break
                stack.append(nxt)
    # Taken before the loop: a record superseded in it still replaces what it names.
    for result in [r for r in results if r.accepted]:
        for sid in result.supersedes:
            target = owner.get(sid)
            if target is not None and target.accepted:
                target.status = "superseded"
                target.notes.append(f"superseded by {result.id}")


def render_validation(run: ValidationRun) -> str:
    lines = [
        "aisafe investigate validate",
        "===========================",
        f"record validation | mode: {run.mode}",
        f"target: {run.root.as_posix()} at {run.state.get('commit') or 'no commit'}"
        + (" (working tree)" if run.working_tree else "")
        + (
            "; git could not report the state of the tree" if run.state.get("status_failed") else ""
        ),
    ]
    if run.fatal:
        lines += ["", f"not validated: {run.fatal}"]
        return "\n".join(lines) + "\n"
    lines.append(
        f"{len(run.results)} record(s): {len(run.accepted)} accepted, {len(run.rejected)} "
        f"rejected, {sum(1 for r in run.results if r.status == 'superseded')} superseded"
    )
    for item in run.skipped:
        lines.append(f"not a record: {item['path']} ({item['why']})")
    for result in run.results:
        lines.append("")
        head = f"{result.status}: {result.path}"
        if result.id:
            head += f" ({result.id})"
        if result.claim and result.status != "rejected":
            head += f" | claim: {result.claim}"
        lines.append(head)
        if result.mechanism and result.pattern:
            lines.append(
                f"  {result.mechanism}/{result.pattern} on {result.surface.get('type')} "
                f"{result.surface.get('file')}:{result.surface.get('line')}"
            )
        if result.proposed:
            lines.append(
                "  proposed: {evidence_status} | {decision}".format(
                    **{**{"evidence_status": "-", "decision": "-"}, **result.proposed}
                )
            )
        if result.effective:
            lines.append("  effective: {evidence_status} | {decision}".format(**result.effective))
            lines.append(
                f"  trace: {'complete' if result.complete else 'partial'}"
                + (f"; missing {', '.join(result.missing)}" if result.missing else "")
                + (f"; ruled out {', '.join(result.ruled_out)}" if result.ruled_out else "")
            )
            skeptic = result.skeptic
            suffix = ""
            if not skeptic.get("bound") and skeptic.get("claimed") not in (None, "", "not_run"):
                suffix = f" (record says {skeptic.get('claimed')})"
            lines.append(f"  skeptic: {skeptic.get('result')}{suffix}")
        for error in result.errors:
            lines.append(f"  - rejected because: {error}")
        for note in result.notes:
            lines.append(f"  - note: {note}")
        for reading in result.readings:
            lines.append(f"  - {reading}")
    return "\n".join(lines) + "\n"
