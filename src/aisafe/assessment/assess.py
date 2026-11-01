"""src/aisafe/assessment/assess.py
--------------------------------
`aisafe assess PATH --investigations DIR`: the assessment, distinct from the scan.

It merges five inputs and keeps them apart in the document:

- **machine**: the scan (`aisafe audit`'s findings before any person's decision, with the
  workbench's fixed options) and the validated investigation records with their skeptic
  passes;
- **human**: the review records and the decisions a named person recorded in them, shown
  beside the outcome and never changing it;
- **signoffs**: a person's sign-offs from the records directory
  (`investigation.signoff`), each accepted or refused with why. The one human input that
  moves an outcome, and only two ways: a record at review becomes a closing, and an unread
  file leaves the `files_not_read` gap. A sign-off never moves a retest: a violation stays
  unremediated however a record at the new commit is signed;
- **auditee**: responses and evidence from the team being audited (from the engagement),
  shown beside and never changing it;
- **evaluation**: the evaluation reports the scan read (in auditor mode, only the one the
  auditor ran and passed with `--evaluation-report`).

With an engagement (`--engagement DIR`) the document also carries who audits whom, the
scope and the authorisations, and a `legal` section: the selected legal profiles read
against the engagement's applicability answers (`aisafe.legal.evaluate`), kept apart from
the ethical outcome and never changing it or the exit code. The organisational evidence
the legal profiles need and the `missing_evidence` of the accepted records become evidence
requests, merged into DIR/evidence-requests.json by the CLI. In auditor mode the engagement
is required, must lie outside the audited tree, must name this tree as its target and this
commit among its commits, and must name the auditor, the auditee, the independence
statement and a written authorisation.

The outcome per mechanism comes from `outcome.mechanism_outcomes`. Without an accepted
investigation record made at this commit the command exits 2: an assessment never falls
back to the scan, and a retest is no exception.

`--retest PREVIOUS` re-runs the verification steps of the previous assessment's records on
this commit. The steps, the covered fingerprints, the mechanism, the pattern, the surface
and the claim's basis come from each record's embedded copy, its fields stripped the way
the validator strips them; the fields derived beside it are not evidence. Every embedded
copy must match its digest: one that does not refuses the retest (exit 2), since a derived
field beside a broken copy could otherwise lower a violation.

Steps fail a record; passing steps never show a remediation by themselves: they are
evidence of a change, whatever their kind. A record is `remediated` only on a commit, with
every walked file as that commit holds it, and only when all of this holds: every
remediation step failed at its commit (re-checked there through git for the quote steps, and
unknown when git cannot; read from the previous assessment otherwise, and said so) and does
not fail now; no regression step fails; no current record establishes the mechanism on the
surface; the scan reports no supported violation of the mechanism in the surface's file, in
a file the record cites, in a file changed since the record's commit or, for a person-facing
unit, anywhere in that unit; the surface's file or a file the record cites changed, its text
and not only its name (when git cannot say, or nothing changed, the status is
`not_verified`); and a record at this commit closes the hypothesis on the surface, with its
skeptic pass upheld, the text addressed to auditors near it checked, and no other record
contesting it. Two things stay open until a closing answers them, any closing of the
mechanism at this commit: a changed file that still holds the quote of an `absent` step
needs a closing that cites it, and any other finding of the mechanism in the files watched
above needs a closing that covers it.

A record on the surface closes it: the same plan id while the plan still lists the surface,
and otherwise the same type in the same file. When the surface's file moved, a record whose
`supersedes` names the old id closes it from the rename target (`git diff --find-renames`);
when the file was deleted, from a changed or cited file the plan lists a surface in, or from
any surface when there is none, since the deletion is then the whole change. So a fix that
deletes or renames the surface's file, or rewrites its anchor line, can still be shown, and
a closing that read something else cannot.

A violation established at the previous commit, with its skeptic pass bound and upheld, and
not shown remediated stands in this assessment, and in the retest of this assessment: its
record is kept in `remediation.carried_records`, and is retested again. The previous
assessment of this same commit shows no fix. A surface new or changed since the previous
assessment blocks like a high-priority one until a deciding record answers it, and goes on
blocking at the next retest while a hypothesis on it has no deciding record.

The previous assessment is an unsigned document, and the retest reads it as it stands. The
digest binds a record's embedded copy to the digest beside it, nothing more. One partial
check runs against an edit: each record `outcome.mechanisms[].establishing` names must have
an entry that reads as an upheld violation, or the retest is refused (exit 2). What stays
undetectable: an edit that removes an entry and its name in `establishing` together, one
that recomputes a digest after changing the embedded record the same way on both sides, and
any change to a verdict the document does not cross-check. A skeptic pass is a separate file
outside the digest, so whether it was bound and upheld is the previous assessment's word.

In auditor mode a retest must also name the same auditor and auditee, and the previous commit
must be an ancestor of this one; when git cannot say, the retest is refused. Paths are never
compared: a clone in another folder is legitimate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Iterable, Sequence

from aisafe.assessment.outcome import (
    _UNREMEDIATED,
    OUTCOMES,
    _skeptic_upheld,
    _untrusted_near,
    least_favourable,
    mechanism_outcomes,
    unread_files,
)
from aisafe.discovery.patterns import AUDIT_DIR, LEGACY_AUDIT_DIRS
from aisafe.discovery.walk import run_git
from aisafe.evidence.model import MODES, Decision, EvidenceStatus, Finding, now_iso
from aisafe.investigation.plan import DEFAULT_BUDGET, build_plan
from aisafe.investigation.records import RecordError, load_json, record_digest
from aisafe.investigation.scan import MachineScan, machine_scan
from aisafe.investigation.signoff import apply_signoffs, bind_signoffs, scene_of
from aisafe.investigation.text import content_sha256, quote_in_text
from aisafe.investigation.validate import (
    SIGNOFF_SKIPPED,
    RecordResult,
    _text,
    _unit_of,
    quote_copies,
    run_step,
    validate_paths,
)

if TYPE_CHECKING:
    from aisafe.engagement.model import Engagement

__all__ = [
    "ASSESSMENT_KIND",
    "ASSESSMENT_LABEL",
    "ASSESSMENT_SCHEMA",
    "AssessmentRun",
    "assessment_disclaimer",
    "run_assessment",
]

ASSESSMENT_SCHEMA = "aisg/assessment/1"
ASSESSMENT_KIND = "assessment"
ASSESSMENT_LABEL = "assessment"
_DISCLAIMER = (
    "This assessment records what an investigation established about the mechanisms of "
    "policy {version} within the scope listed: the commit, the surfaces read and the ones "
    "left out. It is not legal advice, not a certification and not a compliance claim. A "
    "mechanism with no violation identified is not shown absent beyond the surfaces read."
)
# A commit id from the previous assessment reaches git only as a full object id, never as
# text git could read as an option.
_COMMIT_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_STRONG = frozenset({EvidenceStatus.SUPPORTED_MECHANISM, EvidenceStatus.OBSERVED_BEHAVIOR})
_UNIT_SURFACE = "person_facing_unit"
# How `outcome.establishing` marks a violation carried from an earlier commit.
_CARRIED_MARK = " (previous commit)"


def assessment_disclaimer(version: str) -> str:
    return _DISCLAIMER.format(version=version)


@dataclass
class AssessmentRun:
    document: dict[str, Any] | None = None
    fatal: str | None = None
    exit_code: int = 2
    scan: MachineScan | None = None
    records: list[RecordResult] = field(default_factory=list)
    # With an engagement: the evidence requests to write back (merged), and every input
    # the bundle manifest hashes ({role, path}).
    requests: dict[str, Any] | None = None
    bundle_inputs: list[dict[str, Any]] = field(default_factory=list)


def _finding_row(finding: Finding) -> dict[str, Any]:
    leg = finding.evidence[0] if finding.evidence else None
    return {
        "fingerprint": finding.fingerprint,
        "id": finding.display_id,
        "mechanism": finding.mechanism,
        "severity": finding.severity.value,
        "evidence_status": finding.evidence_status.value,
        "decision": finding.decision.value,
        "file": None if leg is None else leg.file,
        "line": None if leg is None else leg.line,
        "snippet": None if leg is None else leg.snippet,
        "trace_complete": finding.trace_complete,
        "missing_links": list(finding.missing_links),
    }


def _record_doc(result: RecordResult) -> dict[str, Any]:
    out = result.to_dict()
    out["raw"] = result.raw
    return out


def _people(records: Sequence[RecordResult]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    investigators: dict[tuple[str, str, str, str], dict[str, str]] = {}
    operators: dict[tuple[str, str], dict[str, str]] = {}
    for record in records:
        who = record.investigator
        key = (who.get("agent", ""), who.get("model", ""), who.get("version", ""), "investigator")
        investigators.setdefault(
            key, {"agent": key[0], "model": key[1], "version": key[2], "role": key[3]}
        )
        skeptic = (record.skeptic or {}).get("skeptic")
        if isinstance(skeptic, dict):
            key = (
                skeptic.get("agent", ""),
                skeptic.get("model", ""),
                skeptic.get("version", ""),
                "skeptic",
            )
            investigators.setdefault(
                key, {"agent": key[0], "model": key[1], "version": key[2], "role": key[3]}
            )
        op = record.operator
        operators.setdefault((op.get("name", ""), op.get("role", "")), dict(op))
    return list(investigators.values()), list(operators.values())


def _human(scan: MachineScan) -> dict[str, Any]:
    from aisafe.rules._common import review_decision_for

    decisions = []
    for finding in scan.findings:
        recorded = review_decision_for(scan.ctx, finding.fingerprint)
        if recorded is None:
            continue
        decisions.append(
            {
                "fingerprint": finding.fingerprint,
                "id": finding.display_id,
                "decision": str(getattr(recorded, "decision", "") or ""),
                "justification": str(getattr(recorded, "justification", "") or ""),
            }
        )
    return {
        "review_records": list(scan.ctx.inventory.review_records or []),
        "review_decisions": decisions,
        "note": (
            "Decisions a named person recorded in a review record, shown beside the outcome. "
            "They never change it."
        ),
    }


def _signed_not_read(signed: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each file a bound sign-off left out of the gap: still not read, and said so."""
    return [
        {
            "path": item["path"],
            "by": row["by"],
            "reason": row["reason"],
            "signoff": row["id"],
            "self_assessed": row["self_assessed"],
        }
        for row in signed
        for item in row["files"]
    ]


def _scope(
    scan: MachineScan,
    plan: dict[str, Any],
    records: Sequence[RecordResult],
    signed: Sequence[dict[str, Any]] = (),
) -> dict[str, Any]:
    by_surface: dict[str, list[RecordResult]] = {}
    for record in records:
        sid = record.surface.get("id")
        if sid:
            by_surface.setdefault(sid, []).append(record)
    queued = set(plan["queued"])
    surfaces = []
    for surface in plan["surfaces"]:
        mine = by_surface.get(surface["id"], [])
        surfaces.append(
            {
                "id": surface["id"],
                "rank": surface["rank"],
                "type": surface["type"],
                "file": surface["file"],
                "line": surface["line"],
                "priority": surface["priority"],
                "queued": surface["id"] in queued,
                "supported": surface["supported"],
                "hypotheses": [
                    {
                        "mechanism": h["mechanism"],
                        "pattern": h["pattern"],
                        "signalled": h["signalled"],
                        "records": [
                            {"id": r.id, "claim": r.claim}
                            for r in mine
                            if r.mechanism == h["mechanism"] and r.pattern == h["pattern"]
                        ],
                    }
                    for h in surface["hypotheses"]
                ],
            }
        )
    not_investigated = [s["id"] for s in surfaces if not by_surface.get(s["id"])]
    deciding = {
        (r.surface.get("id"), r.mechanism, r.pattern)
        for r in records
        if r.claim in ("establishes", "closes") and r.surface.get("id")
    }
    return {
        "mechanisms": [m.id for m in scan.policy.mechanisms],
        "plan": {"sha256": plan["plan_sha256"], "budget": plan["budget"], **plan["counts"]},
        "investigated": {
            "surfaces": sum(1 for s in surfaces if by_surface.get(s["id"])),
            "deciding_hypotheses": len(deciding),
            "records": len(records),
        },
        "surfaces": surfaces,
        "discovered_surfaces": [
            {"record": r.id, **r.surface} for r in records if not r.surface.get("id")
        ],
        "unassessed": {
            "surfaces_not_investigated": not_investigated,
            "unsupported": list(plan["unsupported"]),
            "unsupported_files": list(plan["not_read"].get("unsupported_files") or []),
            "tracked_not_walked": None
            if plan["not_read"].get("tracked_not_walked") is None
            else list(plan["not_read"]["tracked_not_walked"]),
            "dirs_not_walked": list(plan["not_read"].get("dirs_not_walked") or []),
            "signed_off_not_read": _signed_not_read(signed),
            "marker_skipped": list(plan["not_read"]["marker_skipped"]),
            "own_output_skipped": list(plan["not_read"]["own_output_skipped"]),
            "oversize_files": plan["not_read"]["oversize_files"],
            "unknown": [u.to_dict() if hasattr(u, "to_dict") else dict(u) for u in scan.unknown],
        },
        "untrusted_text": list(plan["untrusted_text"]),
    }


# ---------------------------------------------------------------------------
# Retest
# ---------------------------------------------------------------------------


def _load_previous(previous: Path) -> dict[str, Any]:
    try:
        prev = load_json(previous)
    except RecordError as exc:
        raise ValueError(f"--retest: {exc}") from exc
    if not isinstance(prev, dict) or prev.get("schema") != ASSESSMENT_SCHEMA:
        raise ValueError(f"--retest: {previous.as_posix()} is not an {ASSESSMENT_SCHEMA} document")
    return prev


def _git_stdout(root: Path, *args: str) -> bytes | None:
    """stdout of a read-only git command run in `root`, or None when it fails."""
    return run_git(args, root, timeout=60)


def _at_commit(root: Path, commit: str, relpath: str) -> str | None:
    """The file as the previous commit holds it, read through `git show`; None when git
    cannot say."""
    if not _COMMIT_RE.fullmatch(commit or ""):
        return None
    out = _git_stdout(root, "show", f"{commit}:./{relpath}")
    return None if out is None else out.decode("utf-8", errors="replace").replace("\r\n", "\n")


@dataclass(frozen=True)
class _Changes:
    """What differs between a commit and the tree as read now, under the tree's root.
    `files` holds both sides of a rename, `renames` maps an old path to its new one, and
    `moved_only` holds both sides of a rename that kept the text byte for byte."""

    files: frozenset[str]
    renames: dict[str, str]
    moved_only: frozenset[str]

    def text_of(self, files: Iterable[str | None]) -> bool:
        """Whether a file among `files` changed its text, not only its name."""
        return any(file in self.files and file not in self.moved_only for file in files)


def _changed_files(scan: MachineScan, commit: str | None) -> _Changes | None:
    """What changed since `commit` (see `_Changes`); None when git cannot say."""
    state = scan.state
    if not state.is_git or state.status_failed or not _COMMIT_RE.fullmatch(commit or ""):
        return None
    out = _git_stdout(
        scan.root,
        "diff",
        "--name-status",
        "--find-renames",
        "--no-ext-diff",
        "--no-textconv",
        "--relative",
        "-z",
        str(commit),
        str(state.commit),
        "--",
    )
    if out is None:
        return None
    fields = out.decode("utf-8", errors="replace").split("\0")
    files: set[str] = set(state.dirty)
    renames: dict[str, str] = {}
    moved_only: set[str] = set()
    index = 0
    while index + 1 < len(fields):
        status = fields[index]
        if status.startswith("R"):
            old, new = fields[index + 1], fields[index + 2]
            files |= {old, new}
            renames[old] = new
            if status == "R100":
                moved_only |= {old, new}
            index += 3
        else:
            files.add(fields[index + 1])
            index += 2
    return _Changes(frozenset(files), renames, frozenset(moved_only - set(state.dirty)))


def _system_files(files: Iterable[str], scan: MachineScan, inputs: Iterable[Path]) -> list[str]:
    """`files` without the audit's own: its output folder, what the walk skipped as its own
    output, and the records and the previous assessment this run reads. They quote the text
    they judge, so a hit there says nothing about the system."""
    own = set(getattr(scan.ctx.inventory, "own_output_skipped", None) or ())
    read = {Path(path).resolve() for path in inputs}
    return [
        file
        for file in sorted(files)
        if file not in own
        and not {AUDIT_DIR, *LEGACY_AUDIT_DIRS} & set(PurePosixPath(file).parts)
        and (scan.root / file).resolve() not in read
    ]


def _before(step: dict[str, Any], scan: MachineScan, commit: str | None) -> tuple[Any, str]:
    """Whether the step passed at the record's commit. A quote step is known only when git
    re-checks it there; when git cannot, it is unknown (None), never the previous
    assessment's word. Any other kind: the previous assessment's own value, and it says so."""
    spec = step.get("spec") or {}
    if step.get("kind") in ("absent", "present"):
        text = None
        if commit and scan.state.is_git:
            text = _at_commit(scan.root, commit, str(spec.get("file") or ""))
        if text is None:
            return None, "not re-checked: git cannot show the file at that commit"
        found = quote_in_text(text, str(spec.get("quote") or ""))
        return (not found if step.get("kind") == "absent" else found), "re-checked at that commit"
    return step.get("passes_at_record"), "as the previous assessment recorded it"


def _listed(block: Any, key: str) -> list[Any]:
    """`block[key]` when that is a list; an empty list otherwise."""
    value = block.get(key) if isinstance(block, dict) else None
    return value if isinstance(value, list) else []


def _all_entries(prev: dict[str, Any]) -> list[Any]:
    """Every record entry of `prev`, carried ones first."""
    return [
        *_listed(prev.get("remediation"), "carried_records"),
        *_listed(prev.get("machine"), "records"),
    ]


def _retested_entries(prev: dict[str, Any]) -> list[dict[str, Any]]:
    """The records a retest of `prev` answers for: the ones it carried because a retest
    before it did not show them remediated, and the ones it embedded. One record is one
    digest: an id says nothing, since a later record may reuse it for another reading. The
    carried copy comes first and wins: a re-run at the same commit can list the same digest
    with its skeptic file gone, and that copy would lose a violation that stands."""
    entries = []
    seen = set()
    for entry in _all_entries(prev):
        digest = entry.get("digest")
        if digest not in seen:
            entries.append(entry)
            seen.add(digest)
    return entries


def _intact(entry: Any) -> bool:
    """Whether the entry's embedded record matches the digest stored beside it."""
    return (
        isinstance(entry, dict)
        and isinstance(entry.get("raw"), dict)
        and record_digest(entry["raw"]) == entry.get("digest")
    )


def _claim_of(entry: dict[str, Any], raw: dict[str, Any]) -> str | None:
    """The claim as the embedded record makes it. A violation is read from the record, with
    the lowering the record alone can show (validation also lowers a trace it cannot follow,
    and that is not in the record); the `claim` beside it never lowers it. Any other claim
    decides nothing here: the derived one, for the reader."""
    proposed = raw.get("proposed") if isinstance(raw.get("proposed"), dict) else {}
    readings = [c for c in raw.get("counterevidence") or [] if isinstance(c, dict)]
    if (
        _text(proposed.get("decision")) == "violates_policy"
        and _text(proposed.get("evidence_status")) in ("supported_mechanism", "observed_behavior")
        and not raw.get("open_questions")
        and not raw.get("missing_evidence")
        and not any(_text(reading.get("result")) == "supported" for reading in readings)
    ):
        return "establishes"
    return "review" if entry.get("claim") == "establishes" else entry.get("claim")


def _upheld_before(entry: dict[str, Any]) -> bool:
    """Whether the previous assessment says a skeptic pass was bound and upheld the record."""
    skeptic = entry.get("skeptic") if isinstance(entry.get("skeptic"), dict) else {}
    return bool(skeptic.get("bound")) and skeptic.get("result") == "upheld"


def _entries_problem(prev: dict[str, Any]) -> str | None:
    """Why the previous assessment's records cannot be retested; None when they can. A broken
    embedded copy says nothing, and the fields beside it could lower a violation. A record
    the outcome names as establishing must have an entry that reads so: the one cheap check
    against an edited document (the module docstring says what it leaves undetected)."""
    entries = _all_entries(prev)
    broken = [entry for entry in entries if not _intact(entry)]
    if broken:
        names = [str(e.get("id")) if isinstance(e, dict) else "an entry" for e in broken]
        return (
            f"--retest: the previous assessment's copy of {', '.join(names)} is missing or does "
            "not match its digest, so its own steps cannot be read; the retest is refused"
        )
    standing = {
        (_text(entry["raw"].get("mechanism")), _text(entry["raw"].get("id")))
        for entry in entries
        if _claim_of(entry, entry["raw"]) == "establishes" and _upheld_before(entry)
    }
    for mechanism in _listed(prev.get("outcome"), "mechanisms"):
        mechanism_id = _text(mechanism.get("id")) if isinstance(mechanism, dict) else ""
        for name in _listed(mechanism, "establishing"):
            record = str(name).removesuffix(_CARRIED_MARK)
            if (mechanism_id, record) not in standing:
                return (
                    f"--retest: the previous assessment says {record} established "
                    f"{mechanism_id}, and no entry in it reads as that upheld violation: the "
                    "document was edited; the retest is refused"
                )
    return None


def _surface_of(raw: dict[str, Any]) -> dict[str, Any]:
    """The embedded record's surface, its file spelled as validation spells it."""
    surface = raw.get("surface") if isinstance(raw.get("surface"), dict) else {}
    return {
        **surface,
        "id": _text(surface.get("id")) or None,
        "type": _text(surface.get("type")) or None,
        "file": _text(surface.get("file")).replace("\\", "/") or None,
    }


def _record_commit(entry: dict[str, Any], prev_commit: str | None) -> str | None:
    """The commit the record was made at: a carried record is older than the assessment
    that carried it."""
    target = entry["raw"].get("target")
    return _text(target.get("commit") if isinstance(target, dict) else None) or prev_commit


def _own_steps(entry: dict[str, Any], raw: dict[str, Any]) -> list[dict[str, Any]]:
    """The record's own verification steps, from its embedded copy. Only what validation
    measured at the record's commit comes from the derived list beside it."""
    recorded = {
        step.get("id"): step.get("passes_at_record")
        for step in entry.get("steps") or []
        if isinstance(step, dict)
    }
    steps = []
    for index, item in enumerate(raw.get("verification_steps") or []):
        if not isinstance(item, dict):
            continue
        step_id = _text(item.get("id")) or f"v{index + 1}"
        spec = {key: _text(item[key]) for key in ("rule", "family", "note") if key in item}
        if "file" in item:
            spec["file"] = _text(item["file"]).replace("\\", "/")
        if "quote" in item:
            spec["quote"] = item["quote"]
        steps.append(
            {
                "id": step_id,
                "purpose": _text(item.get("purpose")),
                "kind": _text(item.get("kind")),
                "spec": spec,
                "passes_at_record": recorded.get(step_id),
            }
        )
    return steps


def _cited_files(entry: dict[str, Any], raw: dict[str, Any]) -> set[str]:
    """Every file the record cites: the list validation wrote, and the links and their hops
    as the embedded record holds them."""
    files = {str(file) for file in entry.get("cited_files") or []}
    for item in raw.get("links") or []:
        if isinstance(item, dict):
            hops = [hop for hop in item.get("via") or [] if isinstance(hop, dict)]
            files |= {
                _text(place["file"]).replace("\\", "/")
                for place in (item, *hops)
                if _text(place.get("file"))
            }
    return files


def _on_surface(record: RecordResult, surface: dict[str, Any]) -> bool:
    """One surface: the same plan id, or the same type in the same file. A surface's id
    hashes its anchor line, so rewording that line gives it a new id, and a record may name
    no id at all."""
    surface_id = surface.get("id")
    if surface_id and record.surface.get("id") == surface_id:
        return True
    return record.surface.get("type") == surface.get("type") and (
        record.surface.get("file") == surface.get("file")
    )


def _places(
    scan: MachineScan,
    surface: dict[str, Any],
    changes: _Changes | None,
    cited: set[str],
    plan: dict[str, Any],
) -> set[str] | None:
    """Where the surface may have gone: the rename target of its file; when its file was
    deleted, the changed and cited files the plan lists a surface in; nowhere when its file
    is still there, or when git cannot say. None means anywhere: a deleted file and no such
    file, so the deletion is the whole change, and a README in the same commit, which holds
    no surface, says nothing."""
    file = surface.get("file")
    if changes is None or not file:
        return set()
    if file in changes.renames:
        return {changes.renames[file]}
    if file in changes.files and not (scan.root / file).exists():
        return ({s["file"] for s in plan["surfaces"]} & (changes.files | cited)) or None
    return set()


def _closes_surface(
    record: RecordResult, surface: dict[str, Any], planned: bool, places: set[str] | None
) -> bool:
    """Whether an upheld closing speaks for this surface. While the plan lists the surface,
    only a record on its id does: a closing on the prompt beside it read something else.
    Otherwise a record on the same file does, and a record that supersedes the old one does
    from where the surface went (`_places`). A unit is a folder, which no rename names: any
    record on a unit that supersedes the old one."""
    if planned:
        return record.surface.get("id") == surface.get("id")
    if surface.get("type") == _UNIT_SURFACE:
        return record.surface.get("type") == _UNIT_SURFACE
    return places is None or _on_surface(record, surface) or record.surface.get("file") in places


def _undecided_blocking(prev: dict[str, Any]) -> set[str]:
    """The surfaces the previous retest held blocking with a hypothesis no deciding record
    answered. A clean commit on top of them answers nothing."""
    blocking = {
        s
        for s in _listed((prev.get("remediation") or {}).get("plan_changes"), "blocking")
        if isinstance(s, str)
    }
    return {
        surface["id"]
        for surface in _listed(prev.get("scope"), "surfaces")
        if surface.get("id") in blocking
        and any(
            not any(r.get("claim") in ("establishes", "closes") for r in _listed(hyp, "records"))
            for hyp in _listed(surface, "hypotheses")
        )
    }


def _plan_changes(
    scan: MachineScan, plan: dict[str, Any], prev: dict[str, Any], changed: _Changes | None
) -> dict[str, list[str]]:
    """How the plan moved since the previous assessment. `blocking`: the surfaces new or
    changed since then (every surface when git cannot say what changed), and the ones
    `carried_blocking`, which blocked there and stayed undecided."""
    prev_ids = {s.get("id") for s in (prev.get("scope") or {}).get("surfaces") or []}
    now_ids = {s["id"] for s in plan["surfaces"]}
    new_ids = now_ids - prev_ids
    undecided = _undecided_blocking(prev) & now_ids
    if changed is None:
        changed_ids = now_ids & prev_ids
    else:
        units = {getattr(scan.walked.get(file), "unit", None) for file in changed.files} - {None}
        changed_ids = {
            s["id"]
            for s in plan["surfaces"]
            if s["id"] in prev_ids
            and (
                s["file"] in changed.files
                or (s["type"] == "person_facing_unit" and s.get("unit") in units)
            )
        }
    return {
        "new_surfaces": sorted(new_ids),
        "new_high_surfaces": sorted(
            s["id"] for s in plan["surfaces"] if s["id"] in new_ids and s["priority"] == "high"
        ),
        "changed_surfaces": sorted(changed_ids),
        "gone_surfaces": sorted(prev_ids - now_ids),
        "carried_blocking": sorted(undecided),
        "blocking": sorted(new_ids | changed_ids | undecided),
    }


def _outcome_surfaces(
    surfaces: Sequence[dict[str, Any]], remediation: dict[str, Any] | None
) -> list[dict[str, Any]]:
    """The surfaces as the outcome reads them. In a retest a surface new or changed since
    the previous assessment, or still undecided from the retest before, blocks like a
    high-priority one, whatever its priority; the document keeps the priority the plan gave
    it."""
    blocking = set(((remediation or {}).get("plan_changes") or {}).get("blocking") or ())
    return [{**s, "priority": "high"} if s["id"] in blocking else s for s in surfaces]


def _engagement_of(prev: dict[str, Any]) -> dict[str, Any] | None:
    """Who audited whom in the previous assessment, as it says; None when it had no engagement."""
    before = prev.get("engagement")
    if not isinstance(before, dict):
        return None
    return {key: before.get(key) for key in ("auditor", "auditee", "sha256")}


def _retest(
    previous: Path,
    prev: dict[str, Any],
    scan: MachineScan,
    records: Sequence[RecordResult],
    plan: dict[str, Any],
    inputs: Iterable[Path] = (),
) -> dict[str, Any]:
    prev_commit = (prev.get("target") or {}).get("commit")
    same_commit = prev_commit is not None and prev_commit == scan.state.commit
    on_commit = scan.state.is_git and scan.state.clean and scan.state.commit is not None
    dirty = sorted(scan.state.dirty)
    changed = _changed_files(scan, prev_commit)
    changed_since = {prev_commit: changed}
    inputs = [*inputs, previous]
    reported = {f.fingerprint for f in scan.findings}
    planned_ids = {s["id"] for s in plan["surfaces"]}
    not_walked = set(scan.tracked_not_walked or ())
    results = []
    carried_records = []
    for entry in _retested_entries(prev):
        raw = entry["raw"]
        steps = _own_steps(entry, raw)
        claim = _claim_of(entry, raw)
        upheld_before = _upheld_before(entry)
        established = claim == "establishes" and upheld_before
        if not steps and not established:
            continue
        record_id = _text(raw.get("id"))
        mechanism, pattern = _text(raw.get("mechanism")), _text(raw.get("pattern"))
        surface = _surface_of(raw)
        record_commit = _record_commit(entry, prev_commit)
        if record_commit not in changed_since:
            changed_since[record_commit] = _changed_files(scan, record_commit)
        # A carried record is older than the previous assessment: what changed since then
        # says nothing about what moved between its own commit and that one.
        changes = changed_since[record_commit]
        since = None if changes is None else changes.files
        ran = []
        for step in steps:
            now, detail = run_step({"kind": step.get("kind"), **step["spec"]}, scan)
            before, source = _before(step, scan, record_commit)
            ran.append(
                {
                    "id": step.get("id"),
                    "purpose": step.get("purpose"),
                    "kind": step.get("kind"),
                    "before": before,
                    "before_source": source,
                    "now": now,
                    "detail": detail,
                }
            )
        fixes = [s for s in ran if s["purpose"] == "remediation"]
        regressions = [s for s in ran if s["purpose"] == "regression" and s["now"] is False]
        unrun = [s for s in ran if s["purpose"] == "regression" and s["now"] is None]
        covers = [_text(fp) for fp in raw.get("covers") or [] if isinstance(fp, str)]
        still = [fp for fp in covers if fp in reported]
        gone = [fp for fp in covers if fp not in reported]
        cited = _cited_files(entry, raw)
        # A changed file the walk does not read may hold the text: a move out of sight.
        unread = sorted(
            {f for f in cited if f not in scan.walked} | (set(since or ()) & not_walked)
        )
        is_unit = surface.get("type") == _UNIT_SURFACE
        # Whether the code the record read changed at all: a new reading of the same text
        # shows no fix, and a rename alone leaves the text as it was.
        text_changed = changes is not None and changes.text_of({surface.get("file"), *cited})
        planned = surface.get("id") in planned_ids
        on_surface = [
            r
            for r in records
            if r.mechanism == mechanism and (_on_surface(r, surface) or record_id in r.supersedes)
        ]
        now_records = [r for r in on_surface if r.pattern == pattern]
        # Every record that may answer for this mechanism at this commit. A person's sign-off
        # never lowers a violation: to an established one, the record it closed is still a
        # record at review, and it contests.
        closings = [
            r
            for r in records
            if r.mechanism == mechanism
            and r.claim == "closes"
            and _skeptic_upheld(r)
            and (
                (r.skeptic or {}).get("untrusted_text_checked")
                or not _untrusted_near(r, plan["untrusted_text"])
            )
            and not (established and r.signoffs)
        ]
        upheld_closings = [r for r in now_records if r in closings]
        contested = [r for r in now_records if r not in upheld_closings]
        places = set() if planned else _places(scan, surface, changes, cited, plan)
        closed_again = [r for r in upheld_closings if _closes_surface(r, surface, planned, places)]
        established_again = [r for r in on_surface if r.claim == "establishes"]
        # An `absent` step reads one file: the same text in another changed file is open
        # until a closing has read that file.
        searched = _system_files(since or (), scan, inputs)
        cited_now = {file for r in closings for file in r.cited_files}
        copies = sorted(
            {
                file
                for step in steps
                if step.get("kind") == "absent"
                for file in quote_copies(step["spec"], searched, scan)
                if file not in cited_now
            }
        )
        unit = _unit_of(surface, scan) if is_unit else None
        watched = {surface.get("file"), *cited, *(since or ())}
        in_sight = [
            f
            for f in scan.findings
            if f.mechanism == mechanism
            and (
                any(leg.file in watched for leg in f.evidence)
                or (
                    unit is not None
                    and (
                        f.scope.unit == unit
                        or any(
                            getattr(scan.walked.get(leg.file), "unit", None) == unit
                            for leg in f.evidence
                        )
                    )
                )
            )
        ]
        violating = [
            f for f in in_sight if f.decision is Decision.VIOLATES and f.evidence_status in _STRONG
        ]
        # A weaker finding of the mechanism is a signal, not a violation: open, not failed.
        covered = {fp for r in closings for fp in r.covers_valid}
        signals = [f for f in in_sight if f not in violating and f.fingerprint not in covered]
        why: list[str] = []
        if same_commit:
            # Nothing was fixed on a new commit: a violation the previous assessment
            # established stands, and `same_commit` would let it drop.
            status = "not_verified" if established else "same_commit"
            why.append(
                "the previous assessment is of this commit"
                + (f" and {len(dirty)} file(s) differ from it" if dirty else "")
                + ": a fix counts only on a new commit"
            )
        elif regressions:
            status = "regressed"
            why.append("a regression step fails now")
        elif not fixes and established:
            # The validator refuses such a record, so the copy was edited with its digest.
            status = "not_verified"
            why.append("a violation with no remediation step cannot be shown remediated")
        elif not fixes:
            blocked = [str(s["id"]) for s in unrun] + unread
            if established_again:
                status = "regressed"
                why.append("a record at this commit establishes the mechanism on the surface")
            elif violating:
                status = "regressed"
                why.append(
                    "the scan reports " + ", ".join(sorted({f.display_id for f in violating}))
                )
            elif contested or copies or (blocked and not closed_again):
                status = "needs_reinvestigation"
                why.append(
                    "no uncontested record at this commit closes the hypothesis"
                    + (f", and these cannot be checked: {', '.join(blocked)}" if blocked else "")
                )
                if contested:
                    why.append("contested by " + ", ".join(str(r.id or r.path) for r in contested))
                if copies:
                    why.append(
                        f"the step's quote is in {', '.join(copies)}, which no closing cites"
                    )
            else:
                status = "held"
                why.append(
                    "no remediation step; a record at this commit closes the hypothesis and "
                    "every regression step that can run passes"
                    if blocked
                    else "no remediation step; every regression step ran and passes"
                )
        elif any(s["now"] is False for s in fixes):
            status = "not_remediated"
            why.append("a remediation step still fails")
        elif any(s["before"] is not False for s in fixes if s["kind"] != "reinvestigate"):
            status = "not_verified"
            why.append(
                "a remediation step already passed at the previous commit"
                if any(s["before"] is True for s in fixes)
                else "a remediation step was not shown to fail at the previous commit"
            )
        elif established_again:
            status = "not_remediated"
            why.append("a record at this commit establishes the mechanism on the surface")
        elif violating:
            status = "not_remediated"
            why.append(
                "the scan reports "
                + ", ".join(sorted({f.display_id for f in violating}))
                + (
                    " in the surface's unit"
                    if unit is not None
                    else " in the surface's file, a file the record cites or a changed file"
                )
            )
        elif still:
            status = "not_remediated"
            why.append("a finding the record covers is still reported")
        elif not text_changed:
            status = "not_verified"
            why.append(
                "git cannot say what changed since the record's commit"
                if changes is None
                else "neither the surface's file nor a file the record cites changed its text "
                "since the record's commit: a new reading of the same code shows no fix"
            )
        elif closed_again and not (contested or copies or signals):
            status = "remediated"
            why.append(
                "the steps pass and a record at this commit closes the hypothesis on the "
                "surface: " + ", ".join(r.id or "" for r in closed_again)
            )
        else:
            status = "needs_reinvestigation"
            why.append(
                "passing steps show a change, not a remediation: a record at this commit has "
                "to close the hypothesis on the surface, with nothing contesting it"
            )
            if unread:
                why.append("the walk does not read " + ", ".join(unread))
            if contested:
                why.append("contested by " + ", ".join(str(r.id or r.path) for r in contested))
            if upheld_closings and not closed_again:
                why.append(
                    "no closing sits on the surface as it is now"
                    + (f": {', '.join(sorted(places))}" if places else "")
                )
            if copies:
                why.append(
                    f"the step's quote is still in {', '.join(copies)}, which no closing cites"
                )
            if signals:
                named = {
                    f"{f.display_id} in {f.evidence[0].file if f.evidence else 'the unit'}"
                    for f in signals
                }
                why.append(f"the scan reports {', '.join(sorted(named))}: no closing covers it")
        if status == "remediated" and not on_commit:
            status = "not_verified"
            why = [
                "the steps ran on a tree that is not a commit"
                + (f" ({', '.join(dirty)} differ from {scan.state.commit})" if dirty else "")
                + ": a fix counts only when the steps pass on a commit"
            ]
        if established and status in _UNREMEDIATED:
            carried_records.append(entry)
        results.append(
            {
                "record": record_id,
                "mechanism": mechanism,
                "pattern": pattern,
                "surface": surface,
                # `establishes` here is what the outcome stands on: a claim no skeptic pass
                # upheld never established anything.
                "claim_before": "unchallenged"
                if claim == "establishes" and not upheld_before
                else claim,
                "status": status,
                "why": why,
                "steps": ran,
                "still_reported": still,
                "not_reported": gone,
                "reinvestigated_by": [{"id": r.id, "claim": r.claim} for r in on_surface],
            }
        )
    return {
        "previous": {
            "file": previous.as_posix(),
            "sha256": content_sha256(previous),
            "commit": prev_commit,
            "generated_at": prev.get("generated_at"),
            "mode": prev.get("mode"),
            "engagement": _engagement_of(prev),
        },
        # True only when nothing changed: the same commit, and the tree as it holds it.
        "same_commit": same_commit and scan.state.clean,
        "dirty": dirty,
        "results": results,
        "carried_records": carried_records,
        "plan_changes": _plan_changes(scan, plan, prev, changed),
        "note": (
            "A remediation counts only on a commit, when every remediation step of the record "
            "failed at its commit and passes on this one, the code the record read changed, "
            "nothing at this commit shows the mechanism on that surface, and an upheld record "
            "at this commit closes the hypothesis there. Steps fail a record; steps that pass "
            "are evidence of a change, never a remediation by themselves. A finding no longer "
            "reported is not reported, and a step that cannot run is never a pass."
        ),
    }


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


# Engagement fields an auditor-mode assessment cannot do without: accountability has a name.
_AUDITOR_NEEDS = frozenset(
    {
        "auditor.name",
        "auditor.organisation",
        "auditee.name",
        "independence.statement",
        "independence.by",
        "independence.date",
        "authorisations",
        "scope.commits",
    }
)


def _engagement_problem(engagement: Engagement, path: Path, mode: str) -> str | None:
    """Why the engagement cannot be used for this run; None when it can. Auditor mode is
    strict: outside the tree, naming this tree, complete where accountability needs it."""
    from aisafe.engagement.model import inside, missing_fields

    if engagement.mode != mode:
        return f"the engagement is in {engagement.mode} mode; this run is in {mode} mode"
    if inside(engagement.dir, path):
        # The engagement lives outside the audited tree, in either mode.
        return "the engagement directory must be outside the audited tree"
    if mode != "auditor":
        return None
    scope = engagement.data.get("scope") or {}
    target = scope.get("target")
    named = engagement.dir / str(target) if target else None
    if named is None or not _same_dir(named, Path(path)):
        return f"the engagement names {target!r} as its target, not {Path(path).as_posix()}"
    need = [m for m in missing_fields(engagement.data) if m.split(":")[0] in _AUDITOR_NEEDS]
    if need:
        return "the engagement is not complete for auditor mode: " + "; ".join(need)
    return None


def _inside_tree(path: Path, tree: Path) -> bool:
    try:
        path.resolve().relative_to(tree.resolve())
    except ValueError:
        return False
    return True


def _same_dir(a: Path, b: Path) -> bool:
    """One directory, however it is reached (a junction, a symlink, another spelling)."""
    try:
        return a.resolve() == b.resolve() or a.samefile(b)
    except OSError:
        return False


def _who(block: Any, key: str) -> str:
    """A name as compared across assessments: case and spacing aside."""
    value = block.get(key) if isinstance(block, dict) else None
    return " ".join(str(value or "").split()).casefold()


def _previous_problem(prev: dict[str, Any], mode: str, engagement: Engagement | None) -> str | None:
    """Why the previous assessment cannot be retested here; None when it can. In auditor
    mode it must be the same auditor and the same auditee. Paths say nothing: a clone in
    another folder, or an engagement directory moved whole, is legitimate."""
    if prev.get("mode") != mode:
        return (
            f"--retest: the previous assessment is in {prev.get('mode')} mode, this run in {mode}"
        )
    if mode == "auditor" and engagement is not None:
        before = prev.get("engagement")
        for block, key in (("auditor", "name"), ("auditor", "organisation"), ("auditee", "name")):
            then = before.get(block) if isinstance(before, dict) else None
            if _who(then, key) != _who(engagement.data.get(block), key):
                return f"--retest: the previous assessment has another {block} ({block}.{key})"
    return None


def _target_problem(prev: dict[str, Any], scan: MachineScan) -> str | None:
    """Why the previous assessment's commit is not in this commit's past; None when it is.
    Commits, never paths: when git cannot say, that is the refusal. The count is of commits
    the previous one has and this one does not: none means an ancestor, or the same commit."""
    before = str((prev.get("target") or {}).get("commit") or "")
    now = scan.state.commit
    count = None
    if now and _COMMIT_RE.fullmatch(before):
        count = _git_stdout(scan.root, "rev-list", "--count", before, f"^{now}")
    if count is None:
        return (
            f"--retest: git cannot say whether the previous assessment's commit "
            f"({before or 'none'}) is an ancestor of this commit ({now}): an auditor retests "
            "the same system's later commit, so the retest is refused"
        )
    if count.strip() != b"0":
        return (
            f"--retest: the previous assessment's commit ({before}) is not an ancestor of this "
            f"commit ({now}): it assessed another target"
        )
    return None


def _record_requests(records: Sequence[RecordResult]) -> list[dict[str, Any]]:
    """One evidence request per `missing_evidence` line of an accepted record."""
    from aisafe.legal.evaluate import record_request_id

    out = []
    for record in records:
        for text in (record.raw or {}).get("missing_evidence") or []:
            if isinstance(text, str) and text.strip() and record.id:
                out.append(
                    {
                        "id": record_request_id(record.id, text),
                        "source": {"record": record.id, "missing_evidence": text.strip()},
                        "what": text.strip(),
                    }
                )
    return out


def _review_facts(scan: MachineScan, today: date) -> list[dict[str, Any]]:
    """The review records as the outcome reads them: each inventory row with `stale`, why
    the record no longer stands, and the files it binds. The same check AUD-1107 runs, on
    every record: that rule stays silent on a tree without person signals, and silence is
    never a result. Every problem with the record files is a row too, so a record the parser
    dropped, or a second record file nobody read, never reads better than a stale record.
    Such a row's one reason is the problem: it has no date, and no policy of its own."""
    from aisafe.rules.review import _current_hash

    review = getattr(scan.ctx, "review", None)
    max_age = scan.policy.review_max_age_days
    rows: list[dict[str, Any]] = [
        {
            **record.to_inventory(),
            "stale": record.is_stale(lambda p: _current_hash(scan.ctx, p), today, max_age),
            "artifact_files": sorted(record.artifact_paths),
            "units": list(record.units),
        }
        for record in getattr(review, "records", None) or []
    ]
    rows += [
        {
            "file": review.file,
            "reviewed_at": None,
            "policy_version": scan.policy.version,
            "stale": [error],
        }
        for error in getattr(review, "errors", None) or []
    ]
    return rows


def _rules_that_ran(scan: MachineScan) -> list[str]:
    """The rules that were evaluated: `run_rules` skips, silently, the ones that need an AI
    surface when the inventory has none, and turns a rule that crashed into a `rule <id>`
    UNKNOWN item, which is no silence to read."""
    ai_surface = any(unit.ai_surface for unit in scan.ctx.inventory.units or [])
    crashed = {
        item.what.removeprefix("rule ") for item in scan.unknown if item.what.startswith("rule ")
    }
    return [
        rule.id
        for rule in scan.rules
        if rule.id not in crashed
        and (ai_surface or not getattr(rule, "requires_ai_surface", False))
    ]


def run_assessment(
    path: str | Path,
    investigations: Sequence[Path],
    *,
    mode: str = "self-assessment",
    working_tree: bool = False,
    retest: Path | None = None,
    budget: int = DEFAULT_BUDGET,
    engagement: Engagement | None = None,
    evaluation_report: str | None = None,
    today: date | None = None,
) -> AssessmentRun:
    """Build the assessment document (see the module docstring)."""
    from aisafe.reporting.report import TOOL_NAME, tool_version

    today = today or datetime.now(timezone.utc).date()
    if mode not in MODES:
        return AssessmentRun(fatal=f"mode must be one of {', '.join(MODES)}")
    if mode == "auditor" and engagement is None:
        return AssessmentRun(
            fatal=(
                "auditor mode needs an engagement (`aisafe engagement init`, then --engagement DIR)"
            )
        )
    if mode == "auditor" and working_tree:
        return AssessmentRun(
            fatal="in auditor mode an assessment is of a commit: --working-tree is refused"
        )
    if engagement is not None:
        problem = _engagement_problem(engagement, Path(path), mode)
        if problem is not None:
            return AssessmentRun(fatal=problem)
    for item in investigations:
        if not Path(item).exists():
            return AssessmentRun(fatal=f"no such file or directory: {Path(item).as_posix()}")
    prev = _load_previous(Path(retest)) if retest is not None else None
    if prev is not None:
        problem = _previous_problem(prev, mode, engagement) or _entries_problem(prev)
        if problem is not None:
            return AssessmentRun(fatal=problem)
    if mode == "auditor" and evaluation_report is not None:
        if _inside_tree(Path(evaluation_report), Path(path)):
            return AssessmentRun(
                fatal=(
                    "--evaluation-report is inside the audited tree: in auditor mode only a "
                    "report the auditor ran, kept outside the tree, is read"
                )
            )
    if evaluation_report is not None:
        # The flag names a file relative to the working directory, not to the tree: resolve
        # it once, so the scan, the document and the bundle name the same file.
        evaluation_report = Path(evaluation_report).resolve().as_posix()
    scan = machine_scan(path, mode=mode, evaluation_report=evaluation_report)
    if mode == "auditor" and engagement is not None:
        commit = scan.state.commit
        if commit is None or not any(commit.startswith(c) for c in engagement.commits):
            return AssessmentRun(
                fatal=(
                    f"the tree is at commit {commit or 'none'}, which the engagement's "
                    "scope.commits does not list: an auditor assesses the commits in scope"
                ),
                scan=scan,
            )
        if prev is not None:
            problem = _target_problem(prev, scan)
            if problem is not None:
                return AssessmentRun(fatal=problem, scan=scan)
    plan = build_plan(scan, budget=budget)
    run = validate_paths(
        investigations,
        scan,
        working_tree=working_tree,
        plan_surfaces={s["id"]: s for s in plan["surfaces"]},
    )
    if run.fatal is not None:
        return AssessmentRun(fatal=run.fatal, scan=scan)
    if prev is not None:
        # The records of the previous assessment, made at its commit, are retested below
        # through their steps; here they are neither accepted nor rejected.
        prev_commit = (prev.get("target") or {}).get("commit")
        prev_records = {
            (_text(entry["raw"].get("id")), _record_commit(entry, prev_commit), entry["digest"])
            for entry in _retested_entries(prev)
        }
        for result in run.results:
            if (
                result.status == "rejected"
                and result.commit is not None
                and (result.id, result.commit, result.digest) in prev_records
                and result.commit != scan.state.commit
            ):
                result.status = "previous"
                result.notes.append(
                    "a record of the previous assessment's commit: retested through its "
                    "steps, not validated against this commit"
                )
    accepted = [r for r in run.results if r.accepted]
    if not accepted:
        return AssessmentRun(
            fatal=(
                f"none of the {len(run.results)} investigation record(s) was accepted at this "
                "commit; an assessment never falls back to the scan, and a retest needs a "
                "record made on the new code"
            ),
            scan=scan,
            records=run.results,
        )
    rejected = [r for r in run.results if r.status == "rejected"]
    superseded = [r for r in run.results if r.status == "superseded"]
    previous_records = [r for r in run.results if r.status == "previous"]
    tracked_not_walked = plan["not_read"]["tracked_not_walked"]
    unsupported_files = plan["not_read"]["unsupported_files"]
    # Before the retest and the outcome: to them a signed record is a closing.
    signoffs = bind_signoffs(
        [Path(row["path"]) for row in run.skipped if row["why"] == SIGNOFF_SKIPPED],
        scene_of(
            scan,
            unread_files(tracked_not_walked, unsupported_files),
            today=today,
            results=accepted,
            engagement=engagement,
        ),
    )
    apply_signoffs(accepted, signoffs.accepted)
    remediation = None
    if retest is not None and prev is not None:
        read = [*(r.path for r in run.results), *(row["path"] for row in run.skipped)]
        remediation = _retest(Path(retest), prev, scan, accepted, plan, map(Path, read))
    carried = (remediation or {}).get("results") or []
    outcomes = mechanism_outcomes(
        scan.policy,
        records=accepted,
        rejected=rejected,
        findings=scan.findings,
        surfaces=_outcome_surfaces(plan["surfaces"], remediation),
        untrusted=plan["untrusted_text"],
        review_records=_review_facts(scan, today),
        rules_ran=_rules_that_ran(scan),
        carried=carried,
        today=today,
        tracked_not_walked=tracked_not_walked,
        unsupported_files=unsupported_files,
        signed_files=signoffs.accepted,
        dirs_not_walked=plan["not_read"]["dirs_not_walked"],
    )
    overall = least_favourable(o.outcome for o in outcomes)
    investigators, operators = _people(accepted)
    state = scan.state
    inputs = []
    bundle_inputs: list[dict[str, Any]] = []
    for result in run.results:
        try:
            inputs.append(
                {
                    "role": "investigation record",
                    "path": result.path,
                    "sha256": content_sha256(Path(result.path)),
                }
            )
            bundle_inputs.append({"role": "investigation record", "path": result.path})
        except OSError:
            continue
        skeptic_file = (result.skeptic or {}).get("file")
        if skeptic_file:
            skeptic_path = Path(result.path).parent / skeptic_file
            try:
                inputs.append(
                    {
                        "role": "skeptic pass",
                        "path": skeptic_path.as_posix(),
                        "sha256": content_sha256(skeptic_path),
                    }
                )
                bundle_inputs.append({"role": "skeptic pass", "path": skeptic_path.as_posix()})
            except OSError:
                pass
    for row in [*signoffs.accepted, *signoffs.refused]:
        try:
            inputs.append(
                {
                    "role": "sign-off",
                    "path": row["file"],
                    "sha256": content_sha256(Path(row["file"])),
                }
            )
            bundle_inputs.append({"role": "sign-off", "path": row["file"]})
        except OSError:
            continue
    if remediation is not None:
        inputs.append(
            {
                "role": "previous assessment",
                "path": remediation["previous"]["file"],
                "sha256": remediation["previous"]["sha256"],
            }
        )
        bundle_inputs.append(
            {"role": "previous assessment", "path": remediation["previous"]["file"]}
        )
    if evaluation_report is not None:
        # The path as given, resolved from where the command ran: what was read.
        bundle_inputs.append(
            {"role": "evaluation report", "path": Path(evaluation_report).resolve().as_posix()}
        )
    for report in scan.ctx.evaluation:
        file = getattr(report, "file", None)
        if file and evaluation_report is None:
            where = Path(file) if Path(file).is_absolute() else scan.root / file
            bundle_inputs.append({"role": "evaluation report", "path": where.as_posix()})
    if working_tree:
        for rel in state.dirty if not state.status_failed else ():
            bundle_inputs.append(
                {"role": "working-tree file", "path": (scan.root / rel).as_posix()}
            )
    from aisafe.policy import charter_path, policy_path

    bundle_inputs.append({"role": "policy", "path": policy_path().as_posix()})
    bundle_inputs.append({"role": "policy charter", "path": charter_path().as_posix()})

    legal = None
    requests_doc = None
    auditee: dict[str, Any] = {
        "note": (
            "What the team being audited said or supplied, shown beside the outcome; it never "
            "changes it."
        ),
        "responses": [],
        "evidence": [],
        "problems": [],
    }
    engagement_doc = None
    if engagement is not None:
        from aisafe.engagement import model as eng_model
        from aisafe.legal.evaluate import evaluate_legal
        from aisafe.legal.profile import definition_questions, load_profiles

        profiles = load_profiles(policy=scan.policy)
        existing = eng_model.load_requests(engagement.dir)
        legal_args: dict[str, Any] = {
            "answers": engagement.answers,
            "today": today,
            "policy": scan.policy,
            "outcomes": outcomes,
            "records": accepted,
            "surfaces": plan["surfaces"],
            "findings": scan.findings,
            "evaluation": scan.ctx,
            "carried": carried,
        }
        # First pass: which organisational evidence the applicable provisions ask for. The
        # requests are merged, then the section is read again against the merged states.
        _, wanted = evaluate_legal(
            profiles, requests=eng_model.request_states(engagement.dir, existing), **legal_args
        )
        requests_doc = eng_model.merge_requests(
            existing, [*wanted, *_record_requests(accepted)], today=today.isoformat()
        )
        states = eng_model.request_states(engagement.dir, requests_doc)
        legal, _ = evaluate_legal(profiles, requests=states, **legal_args)
        legal["answers_source"] = eng_model.answers_source(engagement.data)
        responses, problems = eng_model.load_responses(engagement.dir)
        auditee["responses"] = responses
        auditee["evidence"] = list(states.values())
        auditee["problems"] = problems
        engagement_doc = {
            **engagement.summary(),
            "to_fill_in": eng_model.missing_fields(
                engagement.data, definitions=definition_questions(profiles)
            ),
        }
        bundle_inputs.append({"role": "engagement", "path": engagement.path.as_posix()})
        requests_path = engagement.dir / eng_model.REQUESTS_FILE
        if requests_path.is_file():
            bundle_inputs.append(
                {"role": "evidence requests (as read)", "path": requests_path.as_posix()}
            )
        for request in states.values():
            for document in request["documents"]:
                bundle_inputs.append(
                    {
                        "role": f"evidence document ({request['id']})",
                        "path": (engagement.dir / str(document["path"])).as_posix(),
                    }
                )
        for response in responses:
            bundle_inputs.append(
                {
                    "role": "auditee response",
                    "path": (engagement.dir / response["file"]).as_posix(),
                }
            )
        for profile in profiles:
            bundle_inputs.append({"role": "legal profile", "path": profile.path.as_posix()})
        authorisations = eng_model.authorisation_states(engagement.dir, engagement.data)
        if mode == "auditor" and evaluation_report is not None:
            # A document that no longer matches its sha256 stops counting, as evidence does.
            engagement_doc["evaluation_endpoint_named"] = any(
                str(auth.get("endpoint") or "").strip() and auth["state"] in (None, "intact")
                for auth in authorisations
            )
        for auth in authorisations:
            document = auth.get("document") or {}
            if document.get("path"):
                bundle_inputs.append(
                    {
                        "role": "written authorisation",
                        "path": (engagement.dir / str(document["path"])).as_posix(),
                    }
                )

    exit_code = 0 if all(o.outcome == OUTCOMES[-1] for o in outcomes) and not rejected else 1
    scope_eng = (engagement.data.get("scope") or {}) if engagement is not None else {}
    document: dict[str, Any] = {
        "schema": ASSESSMENT_SCHEMA,
        "kind": ASSESSMENT_KIND,
        "label": ASSESSMENT_LABEL,
        "mode": mode,
        "tool": {"name": TOOL_NAME, "version": tool_version()},
        "generated_at": now_iso(),
        "disclaimer": assessment_disclaimer(scan.policy.version),
        "target": {
            "path": scan.root.as_posix(),
            "commit": state.commit,
            "git": state.is_git,
            # None when git could not say which files differ: unknown, never 0.
            "dirty": None if state.status_failed else list(state.dirty),
            "status_failed": state.status_failed,
            "working_tree": working_tree,
            "deployment": scope_eng.get("deployment"),
            "configuration": scope_eng.get("configuration"),
        },
        "engagement": engagement_doc,
        "policy": {"version": scan.policy.version},
        "investigators": investigators,
        "operators": operators,
        "scope": _scope(scan, plan, accepted, signoffs.accepted),
        "outcome": {
            "overall": overall,
            "order": list(OUTCOMES),
            "mechanisms": [o.to_dict() for o in outcomes],
        },
        "machine": {
            "scan": {
                "label": "scan report",
                "findings": [_finding_row(f) for f in scan.findings],
                "unknown": len(scan.unknown),
                "rules": [rule.id for rule in scan.rules],
            },
            "records": [_record_doc(r) for r in accepted],
            "superseded": [_record_doc(r) for r in superseded],
            "rejected": [r.to_dict() for r in rejected],
            "previous": [{**r.to_dict(), "previous": True} for r in previous_records],
            "skipped_files": list(run.skipped),
        },
        "human": _human(scan),
        "signoffs": signoffs.to_dict(),
        "auditee": auditee,
        "evaluation": [
            {
                "file": getattr(r, "file", None),
                "generated_at": getattr(r, "generated_at", None),
                "age_days": getattr(r, "age_days", None),
                "families": list(getattr(r, "families", []) or []),
            }
            for r in scan.ctx.evaluation
        ],
        "remediation": remediation,
        "legal": legal,
        "inputs": inputs,
        "exit_code": exit_code,
    }
    if engagement is not None:
        auditee["unmatched"] = eng_model.place_responses(auditee["responses"], document)
    return AssessmentRun(
        document=document,
        exit_code=exit_code,
        scan=scan,
        records=run.results,
        requests=requests_doc,
        bundle_inputs=bundle_inputs,
    )
