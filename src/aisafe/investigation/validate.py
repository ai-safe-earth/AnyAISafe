"""src/aisafe/investigation/validate.py
-------------------------------------
`aisafe investigate validate FILE|DIR`: the mechanical check of investigation records
against the audited tree. Deterministic; no model, no network.

A record is **rejected** when a required field is empty or malformed; when a cited file is
not one the scan walked, or (in a git tree) not one the commit tracks; when a quote is not
at the cited line or a content hash differs; when the record was made at another commit or
in another mode; when its surface id names another surface of the plan, or it cites nothing
in its surface's file; when its free text pronounces a verdict or a quote carries a
secret-shaped string; when a remediation step already passes (it tests nothing) or a
regression step fails; when a file it depends on has changed; when its id is used twice; or
when it supersedes an unknown record, a record of another mechanism, or a violation with a
weaker claim (a closing record never lowers a violation).

An accepted record keeps its proposal only as far as the evidence carries it. Each
downgrade is written down in `notes`:

- `observed_behavior` becomes `supported_mechanism`: a record reads code, and observed
  behaviour comes only from an evaluation report;
- a `violates_policy` proposal becomes `unknown` / `requires_contextual_review` when a link
  the pattern requires is missing, only runtime-only, in an unsupported language, or not
  connected to the rest of the chain by supported links; when a pattern's absent control is
  not shown absent on the path (with where it was looked for); it becomes a review when a
  benign reading was found supported, when questions stay open or evidence is missing;
- a `no_violation_identified_in_scope` proposal stays one only when the record shows the
  chain broken (every required link either traced or ruled out in `absent_links`, at least
  one ruled out) or, for a pattern with an absent control, a complete chain with the control
  on it: its location in the file of the link it sits on, or reached by `via` hops; a
  complete trace with a benign reading is for a person to weigh, so it becomes a review; a
  ruled-out link the scan lists in the same unit needs a citation of that row; a surface
  fetched at run time cannot be closed from the tree.

A skeptic result counts only when its file sits next to the record, is bound to it
(`record_sha256`), was written in another session than the investigation and refutes none
of its claims; a pass with one refuted claim is a refutation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

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
from aisafe.investigation.text import content_sha256, file_lines, quote_at, quote_in_text

__all__ = [
    "RecordResult",
    "ValidationRun",
    "find_record_files",
    "render_validation",
    "run_step",
    "validate_paths",
    "validate_record",
]

_FP_RE = re.compile(r"^[0-9a-f]{16}$")
_SURFACE_ID_RE = re.compile(r"^s-[0-9a-f]{12}(?:-\d+)?$")
_FUTURE_TOLERANCE = timedelta(hours=1)
_MAX_RECORD_BYTES = 8 * 1024 * 1024
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
    "storage": "memory_stores",
    "person_data": "person_signals",
    "transmission": "person_signals",
}
# For the kinds read from the person signals, which signal kinds count.
_SIGNAL_ROWS = {
    "person_data": frozenset({"profile_name", "profile_placeholder", "profile_sdk"}),
    "transmission": frozenset({"profile_sdk"}),
}
_CLAIM_RANK = {"establishes": 2, "review": 1, "closes": 0}


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
    readings: list[str] = field(default_factory=list)
    digest: str | None = None
    raw: dict[str, Any] | None = None

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
                f"{where}: the text pronounces a verdict ({', '.join(sorted(set(words)))}); "
                "a record says what was read, never a verdict on the system"
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
                f"the record was made at commit {result.commit or 'none'}; the tree is at {here}. "
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
    remote_lines = {
        (str(row.get("file")), int(row.get("line") or 0))
        for row in scan.ctx.inventory.prompts or []
        if str(row.get("kind")) in ("remote", "runtime")
    }
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
        last_line = cited["end_line"] or cited["line"]
        runtime = how == "runtime-only" or (
            kind in ("prompt", "person_data")
            and any((cited["file"], n) in remote_lines for n in range(cited["line"], last_line + 1))
        )
        if runtime and how != "runtime-only":
            check.note(
                f"{where}: {cited['file']}:{cited['line']} is a prompt the scan lists as fetched "
                "or built at run time; the link counts as runtime-only"
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
                "counted": reading != "unsupported" and kind in kinds_of_view,
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
    control_located = False
    control_searched = False
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
                elif on_link is None:
                    check.note(
                        f"{where}: a control on the path names the `link` of the chain it sits "
                        "on; without one it does not close anything"
                    )
                elif on_link["file"] != located["file"] and not hops:
                    check.note(
                        f"{where}: the control is in {located['file']}, the link it sits on in "
                        f"{on_link['file']}; `via` hops cite the way between them"
                    )
                else:
                    control_located = True

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
        for c_index, citation in enumerate(_list(item.get("citations")) or []):
            cited = check.citation(citation, f"{where}.citations[{c_index}]", role="absent")
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

    # The record answers the surface it names: something it cites is in that file, and
    # inside the surface's span when the plan gives one.
    if surface is not None and s_type not in _UNIT_SURFACES and s_file in scan.walked:
        in_file = [(lo, hi) for file, lo, hi, _role in check.citations if file == s_file]
        span = result.surface.get("span")
        if not in_file:
            check.error(f"the record cites nothing in {s_file}, the file of the surface it answers")
        elif span and not any(lo <= span[1] and hi >= span[0] for lo, hi in in_file):
            check.error(
                f"the record cites nothing in lines {span[0]}-{span[1]} of {s_file}, the "
                "surface it answers"
            )
    result.cited_files = sorted({file for file, _lo, _hi, _role in check.citations})

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
        if kind in ("absent", "present") and passes is None:
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
    connected = _connected(supported, required, check)
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
    result.control_on_path = control_located and result.complete and not contradictory
    if control_located and not result.complete:
        check.note(
            f"{pattern.absent_control} is shown on the path, but the chain it sits on is not "
            "complete; it closes nothing"
        )
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
        if decision == _CLOSE and s_type in _RUNTIME_SURFACES:
            status, decision = _UNKNOWN, _REVIEW
            check.note(
                "the surface is a prompt fetched at run time: what it says cannot be ruled out "
                "from the tree; the claim is unknown and goes to review"
            )
        uncovered = [k for k in required if k not in supported_kinds and k not in ruled_out]
        broken = [k for k in required if k in ruled_out and k not in cited_kinds]
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
                broken, ruled_citations, result.surface, scan, pattern.id
            )
            if contradicted:
                decision = _REVIEW
                for kind, where in contradicted:
                    check.note(
                        f"the scan lists {kind} in this unit ({where}); ruling it out needs a "
                        "citation of that row that answers it"
                    )
        if decision == _CLOSE and runtime and not closes_by_control:
            status, decision = _UNKNOWN, _REVIEW
            check.note("a required link is runtime-only; the claim is unknown and goes to review")
        if decision == _CLOSE and benign_supported:
            decision = _REVIEW
            check.note("a reading under which the mechanism is present was found supported")
        if decision == _CLOSE and open_items:
            decision = _REVIEW
            check.note("questions stay open or evidence is missing; the decision is a review")
    result.effective = {"evidence_status": status, "decision": decision}
    result.claim = {_VIOLATES: "establishes", _CLOSE: "closes"}.get(decision, "review")

    _check_covers(result, scan, check)
    result.status = "accepted"
    return result


def _connected(links: list[dict[str, Any]], required: list[str], check: _Checker) -> bool:
    """One connected component of `from` edges holds a link of every required kind; an
    edge between two files counts only with a `via` hop."""
    by_id = {link["id"]: link for link in links}
    present = {link["kind"] for link in links}
    if not set(required) <= present:
        return False
    if len(set(required)) <= 1:
        return True
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
            if not any(hop["file"] in joined for hop in link["via"]):
                check.note(
                    f"the edge from {source} to {link['id']} crosses files with no `via` hop "
                    "in either file (the import or the call between them); it does not count"
                )
                continue
        parent[find(link["id"])] = find(source)
    groups: dict[str, set[str]] = {}
    for link in links:
        groups.setdefault(find(link["id"]), set()).add(link["kind"])
    return any(set(required) <= kinds for kinds in groups.values())


def _unit_of(surface: dict[str, Any], scan: MachineScan) -> str | None:
    record = scan.walked.get(surface.get("file") or "")
    if record is not None:
        return getattr(record, "unit", None)
    return next(
        (u.id for u in scan.ctx.inventory.units or [] if (u.root or ".") == surface.get("file")),
        None,
    )


def _scan_contradictions(
    broken: list[str],
    cited: dict[str, list[dict[str, Any]]],
    surface: dict[str, Any],
    scan: MachineScan,
    pattern_id: str = "",
) -> list[tuple[str, str]]:
    """Ruled-out kinds the scan lists in the surface's unit, when no citation of the ruled-out
    entry is at one of those rows."""
    unit = _unit_of(surface, scan)
    out: list[tuple[str, str]] = []
    for kind in broken:
        section = _SCAN_ROWS.get(kind)
        if section is None:
            continue
        rows = [
            row
            for row in getattr(scan.ctx.inventory, section, None) or []
            if str(row.get("unit")) == str(unit)
            and not (
                section == "llm_calls"
                and str(row.get("api") or "").startswith(("import ", "from "))
            )
            and (kind not in _SIGNAL_ROWS or str(row.get("kind")) in _SIGNAL_ROWS[kind])
        ]
        # A link the syntax tree established for a finding of this pattern in the unit.
        for finding in scan.findings:
            pattern = scan.policy.pattern_of(finding.display_id)
            if finding.flow is None or pattern is None or pattern.id != pattern_id:
                continue
            for flow_link in finding.flow.links:
                if flow_link.kind == kind and flow_link.supported:
                    rows.append({"file": flow_link.file, "line": flow_link.line, "kind": "ast"})
        if not rows:
            continue
        if kind == "prompt" and any(str(r.get("kind")) in ("remote", "runtime") for r in rows):
            first = next(r for r in rows if str(r.get("kind")) in ("remote", "runtime"))
            out.append(("a prompt fetched at run time", f"{first.get('file')}:{first.get('line')}"))
            continue
        answered = any(
            c["file"] == str(row.get("file"))
            and c["line"] <= int(row.get("line") or 0) <= (c["end_line"] or c["line"])
            for row in rows
            for c in cited.get(kind, [])
        )
        if not answered:
            first = rows[0]
            out.append((kind, f"{first.get('file')}:{first.get('line')}"))
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
    name = _text(skeptic.get("file")).replace("\\", "/")
    if not name:
        check.note("the skeptic result names no file; it is treated as not run")
        return out
    out["file"] = name
    base = path.parent.resolve()
    skeptic_path = (path.parent / name).resolve()
    if Path(name).is_absolute() or ".." in Path(name).parts or base not in skeptic_path.parents:
        check.note("the skeptic file must sit in the record's directory; it is treated as not run")
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
    if why is not None:
        check.note(f"the skeptic file is not bound to the record: {why}; it is treated as not run")
        return out
    parsed = [
        {
            "claim": _text(c.get("claim")),
            "result": _text(c.get("result")),
            "reason": _text(c.get("reason")),
        }
        for c in claims
        if isinstance(c, dict)
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


def run_step(step: dict[str, Any], scan: MachineScan) -> tuple[bool | None, str]:
    """Run one verification step against `scan`. True passes, False fails, None cannot run
    (`reinvestigate`, or an `absent`/`present` step whose file the walk does not read)."""
    kind = _text(step.get("kind"))
    if kind in ("absent", "present"):
        relpath = _text(step.get("file")).replace("\\", "/")
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
        found = quote_in_text(text, str(step.get("quote")))
        state = "present in" if found else "absent from"
        return (not found if kind == "absent" else found), f"the quote is {state} {relpath}"
    if kind == "no_finding":
        rule = _text(step.get("rule"))
        relpath = _text(step.get("file")).replace("\\", "/") or None
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


# ---------------------------------------------------------------------------
# Files and the batch
# ---------------------------------------------------------------------------


def find_record_files(path: Path) -> tuple[list[Path], list[dict[str, str]]]:
    """The record files under `path` (itself when it is a file), and every other `*.json`
    there with why it is not one. Every file is parsed: where its `schema` key sits does not
    matter. Skeptic passes are listed as such."""
    path = Path(path)
    candidates = [path] if path.is_file() else sorted(path.rglob("*.json"))
    records: list[Path] = []
    skipped: list[dict[str, str]] = []
    for candidate in candidates:
        try:
            size = candidate.stat().st_size
        except OSError:
            skipped.append({"path": candidate.as_posix(), "why": "cannot be read"})
            continue
        if size > _MAX_RECORD_BYTES:
            skipped.append({"path": candidate.as_posix(), "why": "larger than 8 MiB"})
            continue
        try:
            doc = json.loads(candidate.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            # A file that does not parse may be a record that broke: it is validated, and
            # rejected, so the assessment counts it as a gap instead of dropping it.
            records.append(candidate)
            continue
        schema = doc.get("schema") if isinstance(doc, dict) else None
        if schema == SKEPTIC_SCHEMA:
            skipped.append({"path": candidate.as_posix(), "why": "a skeptic pass"})
        elif schema == INVESTIGATION_SCHEMA or path.is_file():
            records.append(candidate)
        else:
            skipped.append({"path": candidate.as_posix(), "why": f"schema {schema!r}"})
    return records, skipped


def validate_paths(
    paths: Iterable[Path],
    scan: MachineScan,
    *,
    working_tree: bool = False,
    plan_surfaces: dict[str, dict[str, Any]] | None = None,
) -> ValidationRun:
    """Validate every record file under `paths` against `scan`, then the batch: ids used
    twice, supersessions (unknown id, a cycle, another mechanism, a weaker claim over a
    violation)."""
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
            raw = load_json(file)
        except RecordError as exc:
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
    stale = {
        r.id
        for r in results
        if r.id is not None
        and r.status == "rejected"
        and r.errors
        and all("the record was made at commit" in e for e in r.errors)
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
                result.errors.append(f"supersedes {sid}, which is not an accepted record here")
            elif target is result:
                result.status = "rejected"
                result.errors.append("a record cannot supersede itself")
            elif target.mechanism != result.mechanism:
                result.status = "rejected"
                result.errors.append(f"supersedes {sid}, a record of {target.mechanism}")
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
    for result in results:
        if result.accepted:
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
        + (" (working tree)" if run.working_tree else ""),
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
