"""src/aisafe/assessment/outcome.py
---------------------------------
The outcome of an assessment, per mechanism and overall. A pure function of its inputs:
the validated records, the scan's findings, the plan's surfaces, the review records and
the retest. Nothing here reads a file.

Per mechanism M1 to M7, in this order:

1. `violations_identified` when a record establishes the mechanism (a validated
   `violates_policy` claim with a complete, connected trace and a skeptic pass that upheld
   it), when the scan holds a finding that violates the policy on supported or observed
   evidence, or when a retest shows that a violation established at the previous commit was
   not remediated. A closing record never lowers it; when records disagree, both are listed.
2. `inconclusive` when a blocking gap remains: a high-priority surface carrying a hypothesis
   of the mechanism without a deciding record for that hypothesis (left out by the budget,
   or never reached, or in an unsupported language), whether or not anything else was
   investigated; a skeptic pass that refuted a deciding claim; a deciding claim whose
   skeptic pass did not run or is not bound to the record; a record whose claim rests on a
   runtime-only link, or that a person still has to weigh; a record that was rejected (one
   whose mechanism cannot be read blocks every mechanism); a supported or observed scan
   finding no deciding record covers; a closing record next to text addressed to an auditor
   or an AI tool (in a file it cites, in its unit's agent instruction files, or in the record
   itself) that its skeptic pass did not say it checked; a closing on no surface of the plan.
3. `no_violation_identified_within_assessed_scope` when a record closes the mechanism and
   no gap remains. It says "closed on k of n surface hypotheses": the scope, never more.
4. `not_assessed` otherwise: no surface of the plan carries the mechanism, or nothing
   decided it and nothing blocks. Scan silence is never a result.

Investigating less never reads better: an uninvestigated high-priority surface is a gap
whether or not other records exist.

M8 (missing or stale review) is read from the scan's AUD-1106 and AUD-1107 facts and the
review records, never from an investigation record.

The overall outcome is the least favourable of the eight: violations_identified, then
inconclusive, then not_assessed, then no_violation_identified_within_assessed_scope.
Acceptances and baselines are not inputs: they never change an outcome.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import PurePosixPath
from typing import Any, Iterable, Sequence

from aisafe.evidence.model import Decision, EvidenceStatus, Finding
from aisafe.policy import Policy

__all__ = [
    "OUTCOMES",
    "Gap",
    "MechanismOutcome",
    "least_favourable",
    "mechanism_outcomes",
]

VIOLATIONS = "violations_identified"
INCONCLUSIVE = "inconclusive"
NOT_ASSESSED = "not_assessed"
NO_VIOLATION = "no_violation_identified_within_assessed_scope"
# Least favourable first: the order `least_favourable` reads.
OUTCOMES: tuple[str, ...] = (VIOLATIONS, INCONCLUSIVE, NOT_ASSESSED, NO_VIOLATION)
_STRONG = frozenset({EvidenceStatus.SUPPORTED_MECHANISM, EvidenceStatus.OBSERVED_BEHAVIOR})
# A violation established at the previous commit stands unless the retest shows it
# remediated: a step still failing, a regression, or a remediation nobody could verify.
_UNREMEDIATED = frozenset({"not_remediated", "regressed", "needs_reinvestigation", "not_verified"})


@dataclass(frozen=True)
class Gap:
    kind: str
    detail: str
    surface: str | None = None
    record: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "detail": self.detail,
            "surface": self.surface,
            "record": self.record,
        }


@dataclass
class MechanismOutcome:
    id: str
    name: str
    outcome: str
    basis: list[str] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    establishing: list[str] = field(default_factory=list)
    closing: list[str] = field(default_factory=list)
    reviews: list[str] = field(default_factory=list)
    unchallenged: list[str] = field(default_factory=list)
    scan: list[dict[str, Any]] = field(default_factory=list)
    closed_on: dict[str, int] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "outcome": self.outcome,
            "basis": list(self.basis),
            "gaps": [gap.to_dict() for gap in self.gaps],
            "establishing": list(self.establishing),
            "closing": list(self.closing),
            "reviews": list(self.reviews),
            "unchallenged": list(self.unchallenged),
            "scan": [dict(row) for row in self.scan],
            "closed_on": self.closed_on,
        }


def least_favourable(outcomes: Iterable[str]) -> str:
    present = list(outcomes)
    for outcome in OUTCOMES:
        if outcome in present:
            return outcome
    return NOT_ASSESSED


def _scan_row(finding: Finding) -> dict[str, Any]:
    leg = finding.evidence[0] if finding.evidence else None
    return {
        "fingerprint": finding.fingerprint,
        "id": finding.display_id,
        "severity": finding.severity.value,
        "evidence_status": finding.evidence_status.value,
        "decision": finding.decision.value,
        "file": None if leg is None else leg.file,
        "line": None if leg is None else leg.line,
    }


def _skeptic(record: Any) -> dict[str, Any]:
    return getattr(record, "skeptic", None) or {}


def _skeptic_upheld(record: Any) -> bool:
    skeptic = _skeptic(record)
    return bool(skeptic.get("bound")) and skeptic.get("result") == "upheld"


def _skeptic_refuted(record: Any) -> bool:
    skeptic = _skeptic(record)
    return bool(skeptic.get("bound")) and skeptic.get("result") == "refuted"


def _ancestors(relpath: str) -> set[str]:
    parts = PurePosixPath(relpath).parts[:-1]
    return {"/".join(parts[:i]) for i in range(len(parts) + 1)}


def _untrusted_near(record: Any, untrusted: Sequence[dict[str, Any]]) -> list[str]:
    """Where text addressed to auditors or AI tools sits next to a closing record: in a file
    it cites or its surface's file, in an agent instruction file of a directory above them,
    or in the record's own `untrusted_text`."""
    files = set(getattr(record, "cited_files", None) or [])
    surface_file = (record.surface or {}).get("file")
    if surface_file:
        files.add(surface_file)
    dirs: set[str] = set()
    for file in files:
        dirs |= _ancestors(file)
    if (record.surface or {}).get("type") == "person_facing_unit":
        dirs |= _ancestors((surface_file or ".") + "/x")
    hits = []
    for item in untrusted:
        where = str(item.get("file"))
        if int(item.get("line") or 0) == 0:
            # An agent instruction file speaks for its directory; one in a hidden config
            # directory (.github, .cursor, .claude) speaks for the whole repository.
            parent = str(PurePosixPath(where).parent)
            if parent == "." or parent.startswith("."):
                parent = ""
            if parent in dirs:
                hits.append(where)
        elif where in files:
            hits.append(f"{where}:{item.get('line')}")
    if getattr(record, "untrusted", None):
        hits.append("the record's own untrusted_text")
    return sorted(set(hits))


def mechanism_outcomes(
    policy: Policy,
    *,
    records: Sequence[Any],
    rejected: Sequence[Any],
    findings: Sequence[Finding],
    surfaces: Sequence[dict[str, Any]],
    untrusted: Sequence[dict[str, Any]] = (),
    review_records: Sequence[dict[str, Any]] = (),
    rules_ran: Iterable[str] = (),
    carried: Sequence[dict[str, Any]] = (),
    today: date | None = None,
) -> list[MechanismOutcome]:
    """One outcome per policy mechanism, in policy order (see the module docstring).
    `records` are the accepted ones (superseded records left out); `rejected` the
    rejected ones; `untrusted` the plan's `untrusted_text`; `carried` the retest rows of
    the previous assessment's records."""
    ran = set(rules_ran)
    known = {m.id for m in policy.mechanisms}
    unplaced = [r for r in rejected if r.mechanism not in known]
    out: list[MechanismOutcome] = []
    for mechanism in policy.mechanisms:
        if not mechanism.patterns:
            out.append(_review_mechanism(policy, mechanism, findings, review_records, ran, today))
            continue
        mine = [r for r in records if r.mechanism == mechanism.id]
        their_rejected = [r for r in rejected if r.mechanism == mechanism.id]
        scan_m = [f for f in findings if f.mechanism == mechanism.id]
        strong = [f for f in scan_m if f.evidence_status in _STRONG]
        still = [
            row
            for row in carried
            if row.get("mechanism") == mechanism.id
            and row.get("claim_before") == "establishes"
            and row.get("status") in _UNREMEDIATED
        ]
        result = MechanismOutcome(
            id=mechanism.id,
            name=mechanism.name,
            outcome=NOT_ASSESSED,
            scan=[_scan_row(f) for f in strong],
        )
        establishing = [
            r for r in mine if r.claim == "establishes" and r.complete and _skeptic_upheld(r)
        ]
        closing = [r for r in mine if r.claim == "closes" and _skeptic_upheld(r)]
        result.establishing = [r.id for r in establishing] + [
            f"{row.get('record')} (previous commit)" for row in still
        ]
        result.closing = [r.id for r in closing]
        result.reviews = [r.id for r in mine if r.claim == "review"]
        # Deciding claims no skeptic pass upheld: shown, never counted.
        result.unchallenged = [
            r.id for r in mine if r.claim in ("establishes", "closes") and not _skeptic_upheld(r)
        ]
        scan_violations = [f for f in strong if f.decision is Decision.VIOLATES]

        # -- gaps ----------------------------------------------------------------
        gaps: list[Gap] = []
        deciding_on: set[tuple[str | None, str | None]] = {
            (r.surface.get("id"), r.pattern) for r in mine if r.claim in ("establishes", "closes")
        }
        hypotheses: list[tuple[str, str]] = []
        for surface in surfaces:
            for hyp in surface.get("hypotheses") or []:
                if hyp.get("mechanism") != mechanism.id:
                    continue
                hypotheses.append((surface["id"], str(hyp.get("pattern"))))
                if surface.get("priority") != "high":
                    continue
                if (surface["id"], hyp.get("pattern")) in deciding_on:
                    continue
                where = surface["file"] + (f":{surface['line']}" if surface.get("line") else "")
                why = "not investigated"
                if not surface.get("supported", True):
                    why = "in a language the workbench does not read"
                gaps.append(
                    Gap(
                        "high_surface_not_investigated",
                        f"{surface['type']} {where}: {mechanism.id}/{hyp.get('pattern')} {why}",
                        surface=surface["id"],
                    )
                )
        for record in mine:
            if record.claim in ("establishes", "closes"):
                if _skeptic_refuted(record):
                    gaps.append(
                        Gap("skeptic_refuted", "a skeptic pass refuted the claim", record=record.id)
                    )
                elif not _skeptic_upheld(record):
                    gaps.append(
                        Gap(
                            "skeptic_not_run",
                            "no skeptic pass bound to the record upheld the claim",
                            record=record.id,
                        )
                    )
            if record.runtime:
                gaps.append(
                    Gap(
                        "runtime_only",
                        "a required link exists only at run time: " + ", ".join(record.runtime),
                        record=record.id,
                    )
                )
            if record.claim == "review":
                gaps.append(
                    Gap(
                        "record_at_review",
                        f"the record's claim is {record.effective.get('evidence_status')} / "
                        f"{record.effective.get('decision')}: a person weighs it",
                        record=record.id,
                    )
                )
            if record.claim == "closes":
                near = _untrusted_near(record, untrusted)
                if near and not _skeptic(record).get("untrusted_text_checked"):
                    gaps.append(
                        Gap(
                            "untrusted_text_near_closing",
                            "text addressed to an auditor or an AI tool sits next to the "
                            f"closing reading ({', '.join(near)}); the skeptic pass did not say "
                            "it checked the reading does not follow it",
                            record=record.id,
                        )
                    )
        for record in [*their_rejected, *unplaced]:
            gaps.append(
                Gap(
                    "rejected_record",
                    "a record of this mechanism was rejected"
                    if record in their_rejected
                    else "a rejected record names no mechanism it could be kept apart from",
                    record=record.id or record.path,
                )
            )
        covered = {
            fp for r in mine if r.claim in ("establishes", "closes") for fp in r.covers_valid
        }
        for finding in strong:
            if finding.decision is Decision.REVIEW and finding.fingerprint not in covered:
                row = _scan_row(finding)
                gaps.append(
                    Gap(
                        "scan_finding_to_decide",
                        f"{finding.display_id} ({finding.evidence_status.value}) at "
                        f"{row['file']}:{row['line']}: no deciding record covers it",
                    )
                )
        plan_closed = {
            (r.surface.get("id"), r.pattern) for r in closing if r.surface.get("id") is not None
        }
        n = len(set(hypotheses))
        k = len(set(hypotheses) & plan_closed)
        if closing and n and not k:
            gaps.append(
                Gap(
                    "closed_off_plan",
                    f"the closing record(s) answer no surface hypothesis of the plan; {n} carry "
                    f"{mechanism.id}",
                )
            )
        result.gaps = gaps

        # -- outcome ---------------------------------------------------------------
        if establishing or scan_violations or still:
            result.outcome = VIOLATIONS
            if establishing:
                result.basis.append("established by " + ", ".join(r.id for r in establishing))
            if scan_violations:
                result.basis.append(
                    "the scan reports "
                    + ", ".join(sorted({f.display_id for f in scan_violations}))
                    + " as violating the policy on supported or observed evidence"
                )
            if still:
                result.basis.append(
                    "the retest shows "
                    + ", ".join(str(row.get("record")) for row in still)
                    + " not remediated: the violation established at the previous commit stands"
                )
            if closing:
                result.basis.append(
                    "readings disagree: "
                    + ", ".join(r.id for r in closing)
                    + " close the mechanism on other surfaces; a closing record never lowers a "
                    "violation"
                )
        elif gaps:
            result.outcome = INCONCLUSIVE
            result.basis.append(f"{len(gaps)} blocking gap(s)")
        elif closing:
            result.outcome = NO_VIOLATION
            result.closed_on = {"closed": k, "of": n}
            result.basis.append(
                "closed by "
                + ", ".join(r.id for r in closing)
                + f" on {k} of {n} surface hypothesis(es) of the plan carrying it"
            )
        else:
            result.outcome = NOT_ASSESSED
            if not hypotheses:
                result.basis.append(f"no surface of the plan carries {mechanism.id}")
            else:
                result.basis.append(
                    f"no deciding record for {mechanism.id}; {len(hypotheses)} surface "
                    "hypothesis(es) of normal or low priority carry it"
                )
        out.append(result)
    return out


def _review_mechanism(
    policy: Policy,
    mechanism: Any,
    findings: Sequence[Finding],
    review_records: Sequence[dict[str, Any]],
    ran: set[str],
    today: date | None,
) -> MechanismOutcome:
    """M8, from the scan's review and control facts and the review records."""
    scan_m = [f for f in findings if f.mechanism == mechanism.id]
    result = MechanismOutcome(
        id=mechanism.id,
        name=mechanism.name,
        outcome=NOT_ASSESSED,
        scan=[_scan_row(f) for f in scan_m],
    )
    if not set(mechanism.rules) <= ran:
        result.basis.append("the review rules did not all run")
        return result
    violations = [
        f for f in scan_m if f.decision is Decision.VIOLATES and f.evidence_status in _STRONG
    ]
    if violations:
        result.outcome = VIOLATIONS
        result.basis.append(
            "the scan reports " + ", ".join(sorted({f.display_id for f in violations}))
        )
        return result
    if scan_m:
        result.outcome = INCONCLUSIVE
        result.gaps = [Gap("scan_finding_to_decide", f"{f.display_id}: {f.title}") for f in scan_m]
        result.basis.append(f"{len(scan_m)} review or control finding(s) a person decides")
        return result
    current = [
        row
        for row in review_records
        if str(row.get("policy_version")) == policy.version
        and _fresh(row.get("reviewed_at"), policy.review_max_age_days, today)
    ]
    if current:
        result.outcome = NO_VIOLATION
        result.basis.append(
            f"{len(current)} review record(s) under policy {policy.version}, within "
            f"{policy.review_max_age_days} days, and no review or control finding remains"
        )
    elif review_records:
        result.outcome = INCONCLUSIVE
        result.gaps = [
            Gap(
                "stale_review_record",
                f"no review record is under policy {policy.version} and within "
                f"{policy.review_max_age_days} days",
            )
        ]
        result.basis.append("the review records are stale or under another policy")
    else:
        result.basis.append("no review record and no finding to read")
    return result


def _fresh(value: Any, max_age_days: int, today: date | None) -> bool:
    try:
        reviewed = date.fromisoformat(str(value)[:10])
    except ValueError:
        return False
    now = today or date.today()
    return 0 <= (now - reviewed).days <= max_age_days
