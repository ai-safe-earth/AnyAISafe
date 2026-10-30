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
this commit. A record is `remediated` only when every remediation step failed at its commit
(re-checked there through git for the quote steps, read from the previous assessment
otherwise, and said so) and passes now; when no remediation step is a bare `no_finding`
(a finding that disappears is "not reported", never remediated); when no current record
establishes the same hypothesis on the same surface; and when the scan reports no
supported violation of the mechanism in the surface's file. A step whose file is no longer
read cannot run, and a step that cannot run is never a pass. A violation established at the
previous commit and not shown remediated stands in this assessment.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Sequence

from aisafe.assessment.outcome import OUTCOMES, least_favourable, mechanism_outcomes
from aisafe.evidence.model import MODES, Decision, EvidenceStatus, Finding, now_iso
from aisafe.investigation.plan import DEFAULT_BUDGET, build_plan
from aisafe.investigation.records import RecordError, load_json
from aisafe.investigation.scan import MachineScan, machine_scan
from aisafe.investigation.text import content_sha256, quote_in_text
from aisafe.investigation.validate import RecordResult, run_step, validate_paths

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
_GIT_SAFE = ("-c", "core.fsmonitor=false")
_STRONG = frozenset({EvidenceStatus.SUPPORTED_MECHANISM, EvidenceStatus.OBSERVED_BEHAVIOR})


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


def _at_commit(root: Path, commit: str, relpath: str) -> str | None:
    """The file as the previous commit holds it, read through `git show`; None when git
    cannot say."""
    try:
        proc = subprocess.run(
            ["git", *_GIT_SAFE, "-C", str(root), "show", f"{commit}:./{relpath}"],
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", errors="replace").replace("\r\n", "\n")


def _before(step: dict[str, Any], scan: MachineScan, commit: str | None) -> tuple[Any, str]:
    """Whether the step passed at the previous commit: re-checked through git for a quote
    step, else the previous assessment's own value, and which of the two it is."""
    recorded = step.get("passes_at_record")
    spec = step.get("spec") or {}
    if step.get("kind") in ("absent", "present") and commit and scan.state.is_git:
        text = _at_commit(scan.root, commit, str(spec.get("file") or ""))
        if text is not None:
            found = quote_in_text(text, str(spec.get("quote") or ""))
            return (
                not found if step.get("kind") == "absent" else found
            ), "re-checked at that commit"
    return recorded, "as the previous assessment recorded it"


def _retest(
    previous: Path,
    prev: dict[str, Any],
    scan: MachineScan,
    records: Sequence[RecordResult],
    plan: dict[str, Any],
) -> dict[str, Any]:
    prev_commit = (prev.get("target") or {}).get("commit")
    same_commit = prev_commit is not None and prev_commit == scan.state.commit
    reported = {f.fingerprint for f in scan.findings}
    current: dict[tuple[Any, Any, Any], list[RecordResult]] = {}
    for record in records:
        key = (record.surface.get("id"), record.mechanism, record.pattern)
        current.setdefault(key, []).append(record)
    results = []
    for entry in (prev.get("machine") or {}).get("records") or []:
        steps = entry.get("steps") or []
        if not steps:
            continue
        surface = entry.get("surface") or {}
        ran = []
        for step in steps:
            spec = {"kind": step.get("kind"), **(step.get("spec") or {})}
            now, detail = run_step(spec, scan)
            before, source = _before(step, scan, prev_commit)
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
        still = [fp for fp in entry.get("covers_valid") or [] if fp in reported]
        gone = [fp for fp in entry.get("covers") or [] if fp not in reported]
        key = (surface.get("id"), entry.get("mechanism"), entry.get("pattern"))
        now_records = current.get(key, [])
        closed_again = [
            r
            for r in now_records
            if r.claim == "closes"
            and (r.skeptic or {}).get("bound")
            and (r.skeptic or {}).get("result") == "upheld"
        ]
        established_again = [r for r in now_records if r.claim == "establishes"]
        violating = [
            f
            for f in scan.findings
            if f.mechanism == entry.get("mechanism")
            and f.decision is Decision.VIOLATES
            and f.evidence_status in _STRONG
            and any(leg.file == surface.get("file") for leg in f.evidence)
        ]
        why: list[str] = []
        if same_commit:
            status = "same_commit"
            why.append("the previous assessment is of this commit: nothing changed to retest")
        elif regressions:
            status = "regressed"
            why.append("a regression step fails now")
        elif not fixes:
            status = "held"
            why.append("no remediation step; every regression step that can run passes")
        elif any(s["now"] is False for s in fixes):
            status = "not_remediated"
            why.append("a remediation step still fails")
        elif any(s["before"] is True for s in fixes):
            status = "not_verified"
            why.append("a remediation step already passed at the previous commit")
        elif established_again:
            status = "not_remediated"
            why.append("a record at this commit establishes the same hypothesis on the surface")
        elif violating:
            status = "not_remediated"
            why.append(
                "the scan reports "
                + ", ".join(sorted({f.display_id for f in violating}))
                + " in the surface's file"
            )
        elif still:
            status = "not_remediated"
            why.append("a finding the record covers is still reported")
        elif any(s["now"] is None for s in fixes) or all(s["kind"] == "no_finding" for s in fixes):
            if closed_again:
                status = "remediated"
                why.append(
                    "the mechanical steps pass and a record at this commit closes the hypothesis "
                    "on the surface: " + ", ".join(r.id or "" for r in closed_again)
                )
            else:
                status = "needs_reinvestigation"
                why.append(
                    "a step cannot run mechanically, or the only evidence is a finding no longer "
                    "reported; a record at this commit has to close the hypothesis"
                )
        else:
            status = "remediated"
            why.append("every remediation step failed at the previous commit and passes now")
        results.append(
            {
                "record": entry.get("id"),
                "mechanism": entry.get("mechanism"),
                "pattern": entry.get("pattern"),
                "surface": surface,
                "claim_before": entry.get("claim"),
                "status": status,
                "why": why,
                "steps": ran,
                "still_reported": still,
                "not_reported": gone,
                "reinvestigated_by": [{"id": r.id, "claim": r.claim} for r in now_records],
            }
        )
    prev_ids = {s.get("id") for s in (prev.get("scope") or {}).get("surfaces") or []}
    now_ids = {s["id"] for s in plan["surfaces"]}
    new_high = [
        s["id"] for s in plan["surfaces"] if s["id"] not in prev_ids and s["priority"] == "high"
    ]
    return {
        "previous": {
            "file": previous.as_posix(),
            "sha256": content_sha256(previous),
            "commit": prev_commit,
            "generated_at": prev.get("generated_at"),
        },
        "same_commit": same_commit,
        "results": results,
        "plan_changes": {
            "new_surfaces": sorted(now_ids - prev_ids),
            "new_high_surfaces": sorted(new_high),
            "gone_surfaces": sorted(prev_ids - now_ids),
        },
        "note": (
            "A remediation counts only when every remediation step of the record failed at "
            "its commit and passes on this one, and nothing at this commit shows the mechanism "
            "on that surface. A finding that is no longer reported is not reported, never "
            "remediated. Steps that pass are evidence of a change, not proof the mechanism is "
            "gone: a record at this commit closes it."
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
        prev_ids = {r.get("id") for r in (prev.get("machine") or {}).get("records") or []}
        for result in run.results:
            if (
                result.status == "rejected"
                and result.id in prev_ids
                and result.commit is not None
                and result.commit == prev_commit
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
        surfaces=plan["surfaces"],
        untrusted=plan["untrusted_text"],
        review_records=list(scan.ctx.inventory.review_records or []),
        rules_ran=[rule.id for rule in scan.rules],
        carried=carried,
        today=today,
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
