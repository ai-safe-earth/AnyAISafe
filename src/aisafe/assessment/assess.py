"""src/aisafe/assessment/assess.py
--------------------------------
`aisafe assess PATH --investigations DIR`: the assessment, distinct from the scan.

It merges four inputs and keeps them apart in the document:

- **machine**: the scan (`aisafe audit`'s findings before any person's decision, with the
  workbench's fixed options) and the validated investigation records with their skeptic
  passes;
- **human**: the review records and the decisions a named person recorded in them, shown
  beside the outcome and never changing it;
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
and the claim's basis come from each record's embedded copy, which must match its digest;
the fields derived beside it are not evidence. A record is `remediated` only on a commit,
with every walked file as that commit holds it, and only when every remediation step
failed at its commit (re-checked there through git for the quote steps, and unknown when
git cannot; read from the previous assessment otherwise, and said so) and passes now; when
no current record establishes the mechanism on the surface; and when the scan reports no
supported violation of the mechanism in the surface's file, in a file the record cites, in
a file changed since the record's commit or, for a person-facing unit, anywhere in that
unit. A step that cannot run is never a pass: a step on a file no longer read, a regression
step included. A record at this commit has to close the hypothesis, with its skeptic pass
upheld, the text addressed to auditors near it checked, and no other record contesting it,
when a step cannot run; when a file the record cites, or a file changed since its commit,
is not read; when the surface's file did not change (for a person-facing unit, no file the
record cites); when another record contests it; or when the remediation steps are only
`no_finding` and `present` (a finding that disappears is "not reported", and a quote that
appears is not shown on the path).

A record on the surface closes it: the same plan id while the plan still lists the surface,
and otherwise the same type in the same file, or, when the surface's file is gone or was
rewritten, a record whose `supersedes` names the old id. So a fix that deletes or renames
the surface's file, or rewrites its anchor line, can still be shown.

A violation established at the previous commit, with its skeptic pass bound and upheld, and
not shown remediated stands in this assessment, and in the retest of this assessment: its
record is kept in `remediation.carried_records`, and is retested again. The previous
assessment of this same commit shows no fix. A surface new or changed since the previous
assessment blocks like a high-priority one until a deciding record answers it.

The previous assessment is an unsigned document, and the retest reads it as it stands. The
digest binds a record's embedded copy to the digest beside it, nothing more: a person who
removes a whole entry, or recomputes a digest, leaves no trace here. A skeptic pass is a
separate file outside the digest, so whether it was bound and upheld is the previous
assessment's word.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Sequence

from aisafe.assessment.outcome import (
    _UNREMEDIATED,
    OUTCOMES,
    _skeptic_upheld,
    _untrusted_near,
    least_favourable,
    mechanism_outcomes,
)
from aisafe.discovery.walk import run_git
from aisafe.evidence.model import MODES, Decision, EvidenceStatus, Finding, now_iso
from aisafe.investigation.plan import DEFAULT_BUDGET, build_plan
from aisafe.investigation.records import RecordError, load_json, record_digest
from aisafe.investigation.scan import MachineScan, machine_scan
from aisafe.investigation.text import content_sha256, quote_in_text
from aisafe.investigation.validate import RecordResult, _unit_of, run_step, validate_paths

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
# Step kinds that never show a remediation on their own: a finding that disappears is "not
# reported", and a quote that appears is not shown on the path.
_NOT_ALONE = frozenset({"no_finding", "present"})
_UNIT_SURFACE = "person_facing_unit"


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


def _scope(
    scan: MachineScan, plan: dict[str, Any], records: Sequence[RecordResult]
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


def _changed_files(scan: MachineScan, commit: str | None) -> set[str] | None:
    """The files that differ between `commit` and the tree as read now, under the tree's
    root; None when git cannot say."""
    state = scan.state
    if not state.is_git or state.status_failed or not _COMMIT_RE.fullmatch(commit or ""):
        return None
    out = _git_stdout(
        scan.root,
        "diff",
        "--name-only",
        "--no-renames",
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
    named = out.decode("utf-8", errors="replace").split("\0")
    return {name for name in named if name} | set(state.dirty)


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


def _retested_entries(prev: dict[str, Any]) -> list[dict[str, Any]]:
    """The records a retest of `prev` answers for: the ones it embedded, and the ones it
    carried because a retest before it did not show them remediated. One record is one
    digest: an id says nothing, since a later record may reuse it for another reading."""
    entries = list((prev.get("machine") or {}).get("records") or [])
    seen = {entry.get("digest") for entry in entries}
    for entry in (prev.get("remediation") or {}).get("carried_records") or []:
        digest = entry.get("digest")
        if digest is None or digest not in seen:
            entries.append(entry)
            seen.add(digest)
    return entries


def _embedded(entry: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    """Whether the entry's embedded record matches the digest stored beside it, and that
    record (an empty one when it does not)."""
    raw = entry.get("raw")
    if isinstance(raw, dict) and record_digest(raw) == entry.get("digest"):
        return True, raw
    return False, {}


def _claim_of(entry: dict[str, Any], raw: dict[str, Any]) -> str | None:
    """The claim as the embedded record makes it. A violation is read from the record, with
    the lowering the record alone can show (validation also lowers a trace it cannot follow,
    and that is not in the record); the `claim` beside it never lowers it. Any other claim
    decides nothing here: the derived one, for the reader."""
    proposed = raw.get("proposed") if isinstance(raw.get("proposed"), dict) else {}
    readings = [c for c in raw.get("counterevidence") or [] if isinstance(c, dict)]
    if (
        proposed.get("decision") == "violates_policy"
        and proposed.get("evidence_status") in ("supported_mechanism", "observed_behavior")
        and not raw.get("open_questions")
        and not raw.get("missing_evidence")
        and not any(reading.get("result") == "supported" for reading in readings)
    ):
        return "establishes"
    return "review" if entry.get("claim") == "establishes" else entry.get("claim")


def _surface_of(raw: dict[str, Any]) -> dict[str, Any]:
    """The embedded record's surface, its file spelled as validation spells it."""
    surface = raw.get("surface") if isinstance(raw.get("surface"), dict) else {}
    return {**surface, "file": str(surface.get("file") or "").replace("\\", "/") or None}


def _record_commit(entry: dict[str, Any], prev_commit: str | None) -> str | None:
    """The commit the record was made at: a carried record is older than the assessment
    that carried it."""
    _, raw = _embedded(entry)
    return (raw.get("target") or {}).get("commit") or prev_commit


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
        step_id = str(item.get("id") or "").strip() or f"v{index + 1}"
        steps.append(
            {
                "id": step_id,
                "purpose": item.get("purpose"),
                "kind": item.get("kind"),
                "spec": {
                    key: item[key]
                    for key in ("file", "quote", "rule", "family", "note")
                    if key in item
                },
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
            files |= {str(place["file"]) for place in (item, *hops) if place.get("file")}
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


def _closes_surface(
    record: RecordResult, surface: dict[str, Any], planned: bool, moved: bool
) -> bool:
    """Whether an upheld closing speaks for this surface. While the plan lists the surface,
    only a record on its id does: a closing on the prompt beside it read something else.
    When the surface's file is gone or was rewritten, `moved`, nothing can sit on the old id,
    so a record that supersedes the old one counts too."""
    if planned:
        return record.surface.get("id") == surface.get("id")
    return moved or _on_surface(record, surface)


def _plan_changes(
    scan: MachineScan, plan: dict[str, Any], prev: dict[str, Any], changed: set[str] | None
) -> dict[str, list[str]]:
    """How the plan moved since the previous assessment. `blocking`: the surfaces new or
    changed since then; every surface when git cannot say what changed."""
    prev_ids = {s.get("id") for s in (prev.get("scope") or {}).get("surfaces") or []}
    now_ids = {s["id"] for s in plan["surfaces"]}
    new_ids = now_ids - prev_ids
    if changed is None:
        changed_ids = now_ids & prev_ids
    else:
        units = {getattr(scan.walked.get(file), "unit", None) for file in changed} - {None}
        changed_ids = {
            s["id"]
            for s in plan["surfaces"]
            if s["id"] in prev_ids
            and (
                s["file"] in changed
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
        "blocking": sorted(new_ids | changed_ids),
    }


def _outcome_surfaces(
    surfaces: Sequence[dict[str, Any]], remediation: dict[str, Any] | None
) -> list[dict[str, Any]]:
    """The surfaces as the outcome reads them. In a retest a surface new or changed since
    the previous assessment blocks like a high-priority one, whatever its priority; the
    document keeps the priority the plan gave it."""
    blocking = set(((remediation or {}).get("plan_changes") or {}).get("blocking") or ())
    return [{**s, "priority": "high"} if s["id"] in blocking else s for s in surfaces]


def _retest(
    previous: Path,
    prev: dict[str, Any],
    scan: MachineScan,
    records: Sequence[RecordResult],
    plan: dict[str, Any],
) -> dict[str, Any]:
    prev_commit = (prev.get("target") or {}).get("commit")
    same_commit = prev_commit is not None and prev_commit == scan.state.commit
    on_commit = scan.state.is_git and scan.state.clean and scan.state.commit is not None
    dirty = sorted(scan.state.dirty)
    changed = _changed_files(scan, prev_commit)
    changed_since = {prev_commit: changed}
    reported = {f.fingerprint for f in scan.findings}
    planned_ids = {s["id"] for s in plan["surfaces"]}
    not_walked = set(scan.tracked_not_walked or ())
    results = []
    carried_records = []
    for entry in _retested_entries(prev):
        intact, raw = _embedded(entry)
        steps = _own_steps(entry, raw)
        if intact and not steps:
            continue
        # A broken copy says nothing: the row keeps what the document says, as not verified.
        recorded = raw if intact else entry
        record_id = recorded.get("id")
        mechanism, pattern = recorded.get("mechanism"), recorded.get("pattern")
        surface = _surface_of(recorded)
        claim = _claim_of(entry, raw) if intact else entry.get("claim")
        skeptic = entry.get("skeptic") or {}
        upheld_before = bool(skeptic.get("bound")) and skeptic.get("result") == "upheld"
        established = claim == "establishes" and upheld_before
        record_commit = _record_commit(entry, prev_commit)
        if record_commit not in changed_since:
            changed_since[record_commit] = _changed_files(scan, record_commit)
        # A carried record is older than the previous assessment: what changed since then
        # says nothing about what moved between its own commit and that one.
        since = changed_since[record_commit]
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
        covers = [fp for fp in raw.get("covers") or [] if isinstance(fp, str)]
        still = [fp for fp in covers if fp in reported]
        gone = [fp for fp in covers if fp not in reported]
        cited = _cited_files(entry, raw)
        # A changed file the walk does not read may hold the text: a move out of sight.
        unread = sorted(
            {f for f in cited if f not in scan.walked} | (set(since or ()) & not_walked)
        )
        is_unit = surface.get("type") == _UNIT_SURFACE
        # Nothing shows the surface's text changed, whatever a step on another file says.
        same_text = since is None or (
            not cited & since if is_unit else surface.get("file") not in since
        )
        planned = surface.get("id") in planned_ids
        on_surface = [
            r
            for r in records
            if r.mechanism == mechanism and (_on_surface(r, surface) or record_id in r.supersedes)
        ]
        now_records = [r for r in on_surface if r.pattern == pattern]
        upheld_closings = [
            r
            for r in now_records
            if r.claim == "closes"
            and _skeptic_upheld(r)
            and (
                (r.skeptic or {}).get("untrusted_text_checked")
                or not _untrusted_near(r, plan["untrusted_text"])
            )
        ]
        contested = [r for r in now_records if r not in upheld_closings]
        closed_again = [
            r
            for r in upheld_closings
            if _closes_surface(r, surface, planned, moved=not planned and not same_text)
        ]
        established_again = [r for r in on_surface if r.claim == "establishes"]
        unit = _unit_of(surface, scan) if is_unit else None
        watched = {surface.get("file"), *cited, *(since or ())}
        violating = [
            f
            for f in scan.findings
            if f.mechanism == mechanism
            and f.decision is Decision.VIOLATES
            and f.evidence_status in _STRONG
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
        elif not intact:
            status = "not_verified"
            why.append(
                "the previous assessment's copy of the record is missing or does not match its "
                "digest, so the record's own steps cannot be read"
            )
        elif regressions:
            status = "regressed"
            why.append("a regression step fails now")
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
            elif contested or (blocked and not closed_again):
                status = "needs_reinvestigation"
                why.append(
                    "no uncontested record at this commit closes the hypothesis"
                    + (f", and these cannot be checked: {', '.join(blocked)}" if blocked else "")
                )
                if contested:
                    why.append("contested by " + ", ".join(str(r.id or r.path) for r in contested))
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
        elif (
            unread
            or unrun
            or contested
            or same_text
            or any(s["now"] is None for s in fixes)
            or all(s["kind"] in _NOT_ALONE for s in fixes)
        ):
            if closed_again and not contested:
                status = "remediated"
                why.append(
                    "the mechanical steps pass and a record at this commit closes the hypothesis "
                    "on the surface: " + ", ".join(r.id or "" for r in closed_again)
                )
            else:
                status = "needs_reinvestigation"
                why.append(
                    "a step cannot run mechanically, or the only evidence is a finding no longer "
                    "reported or a quote now present; a record at this commit has to close the "
                    "hypothesis, with nothing contesting it"
                )
                if unread:
                    why.append("the walk does not read " + ", ".join(unread))
                if same_text:
                    why.append("nothing shows the text on the surface changed")
                if contested:
                    why.append("contested by " + ", ".join(str(r.id or r.path) for r in contested))
        else:
            status = "remediated"
            why.append("every remediation step failed at the previous commit and passes now")
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
        },
        # True only when nothing changed: the same commit, and the tree as it holds it.
        "same_commit": same_commit and scan.state.clean,
        "dirty": dirty,
        "results": results,
        "carried_records": carried_records,
        "plan_changes": _plan_changes(scan, plan, prev, changed),
        "note": (
            "A remediation counts only on a commit, when every remediation step of the record "
            "failed at its commit and passes on this one, and nothing at this commit shows the "
            "mechanism on that surface. A step on another file shows nothing when the "
            "surface's own file did not change. A finding no longer reported is not reported, "
            "and a quote that appears is not shown on the path: neither is ever a remediation "
            "on its own. A step that cannot run is never a pass. Steps that pass are evidence "
            "of a change, not proof the mechanism is gone: a record at this commit closes it."
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


def _previous_problem(prev: dict[str, Any], mode: str, engagement: Engagement | None) -> str | None:
    """Why the previous assessment cannot be retested here; None when it can."""
    if prev.get("mode") != mode:
        return (
            f"--retest: the previous assessment is in {prev.get('mode')} mode, this run in {mode}"
        )
    if mode == "auditor" and engagement is not None:
        before = (prev.get("engagement") or {}).get("path")
        if not before or not _same_dir(Path(str(before)).parent, engagement.dir):
            return "--retest: the previous assessment was made in another engagement"
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
        problem = _previous_problem(prev, mode, engagement)
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
        prev_commits: dict[Any, set[str | None]] = {}
        for entry in _retested_entries(prev):
            prev_commits.setdefault(entry.get("id"), set()).add(_record_commit(entry, prev_commit))
        for result in run.results:
            if (
                result.status == "rejected"
                and result.commit is not None
                and result.commit in prev_commits.get(result.id, ())
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
    remediation = None
    if retest is not None and prev is not None:
        remediation = _retest(Path(retest), prev, scan, accepted, plan)
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
        tracked_not_walked=plan["not_read"]["tracked_not_walked"],
        unsupported_files=plan["not_read"]["unsupported_files"],
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
        for auth in eng_model.authorisation_states(engagement.dir, engagement.data):
            document = auth.get("document") or {}
            if document.get("path"):
                bundle_inputs.append(
                    {
                        "role": "written authorisation",
                        "path": (engagement.dir / str(document["path"])).as_posix(),
                    }
                )
        auditee["unmatched"] = _unmatched_responses(responses, outcomes, accepted, scan, legal)

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
        "scope": _scope(scan, plan, accepted),
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
    return AssessmentRun(
        document=document,
        exit_code=exit_code,
        scan=scan,
        records=run.results,
        requests=requests_doc,
        bundle_inputs=bundle_inputs,
    )


def _unmatched_responses(
    responses: Sequence[dict[str, Any]],
    outcomes: Sequence[Any],
    records: Sequence[RecordResult],
    scan: MachineScan,
    legal: dict[str, Any] | None,
) -> list[str]:
    """Responses whose `to` names no mechanism, record, finding or provision of this
    assessment: shown, never placed beside the wrong thing."""
    known = {o.id for o in outcomes} | {r.id for r in records if r.id}
    known |= {f.fingerprint for f in scan.findings}
    for prof in (legal or {}).get("profiles") or []:
        known |= {f"{prof['id']}/{prov['id']}" for prov in prof.get("provisions") or []}
    return [str(r.get("file")) for r in responses if r.get("to") not in known]
