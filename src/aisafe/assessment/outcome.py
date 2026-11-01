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
   that names no mechanism a record can decide blocks M1 to M7); a supported or observed
   scan finding no deciding record covers; a closing record next to text addressed to an
   auditor or an AI tool (in a file it cites or says it read, anywhere in the unit it closes,
   in an agent instruction file above them, or in the record itself) that its skeptic pass
   did not say it checked; a closing that answers no surface hypothesis of the plan, whether
   or not the plan carries the mechanism; a file of the tree nobody read that may hold code
   or prompts (a tracked file the walk skipped, a file in a language this version does not
   read), or a tree whose tracked files git could not list. Outside git no commit lists the
   tree, so a file the walk says it skipped counts the same way, and so does a directory it
   did not go into (`vendor`, `build`, one a `.gitignore` line hides): the directory is
   named, not walked. Caches, pictures, fonts, recordings, drawings, style sheets and
   dependency lock files do not count: they hold neither.
3. `no_violation_identified_within_assessed_scope` when a record closes the mechanism and
   no gap remains. It says "closed on k of n surface hypotheses": the scope, never more.
4. `not_assessed` otherwise: no surface of the plan carries the mechanism, or nothing
   decided it and nothing blocks. Scan silence is never a result.

Investigating less never reads better: an uninvestigated high-priority surface is a gap
whether or not other records exist.

M8 (missing or stale review) is read from the scan's AUD-1106 and AUD-1107 facts and the
review records, never from an investigation record. It closes only when every review record
stands (under this policy, within the review window, and bound to the artifacts as they are
now), when between them the records bind every file of the plan's surfaces (a record that
names units binds files of those units only; the surface of a person-facing unit is a
directory and asks for no file; a record binds a surface only when its `scope` holds every
mechanism among the surface's hypotheses, so a review of M1 says nothing about a surface
that carries M5), and when no file stayed unread as above. A record whose binding nobody
checked (no `stale` fact) does not stand. Neither does a record the parser dropped or a
record file nobody read: each problem with the record files is a row of its own.

A sign-off (`investigation.signoff`) is a person's decision, and it clears two gaps and no
other: `record_at_review`, for a record `apply_signoffs` turned into a closing (which also
decides that record's own surface hypothesis), and the files it names in `files_not_read`.
It lowers no violation and answers no scan finding, and the basis line names who decided.

The overall outcome is the least favourable of the eight: violations_identified, then
inconclusive, then not_assessed, then no_violation_identified_within_assessed_scope.
Acceptances and baselines are not inputs: they never change an outcome.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import PurePosixPath
from typing import Any, Collection, Iterable, Sequence

from aisafe.evidence.model import Decision, EvidenceStatus, Finding
from aisafe.policy import Policy

__all__ = [
    "OUTCOMES",
    "Gap",
    "MechanismOutcome",
    "least_favourable",
    "mechanism_outcomes",
    "unread_files",
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
# Unread files that block no outcome, by suffix, because they hold neither code nor prompts.
# Binary media never reaches the walk's text, so these count only among the files the walk
# did not read: one it read as text is not what its name says, and stays unread text.
_BINARY_MEDIA = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".bmp",
        ".ico",
        ".tif",
        ".tiff",
        ".avif",
        ".heic",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".mp3",
        ".wav",
        ".ogg",
        ".flac",
        ".m4a",
        ".aac",
        ".mp4",
        ".mov",
        ".webm",
        ".avi",
        ".mkv",
    }
)
# Text that no program runs and no model is sent: drawings, style sheets, dependency pins.
_TEXT_NOT_CODE = frozenset({".svg", ".css", ".scss", ".sass", ".less", ".lock"})
# How many files a gap names before it only counts them.
_NAMED = 10


@dataclass(frozen=True)
class Gap:
    kind: str
    detail: str
    surface: str | None = None
    record: str | None = None
    # The pattern the gap concerns, when one is known; None reads as every pattern of the
    # mechanism (the legal section treats it so).
    pattern: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "detail": self.detail,
            "surface": self.surface,
            "record": self.record,
            "pattern": self.pattern,
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
    # The sign-offs this outcome stands on, by id.
    signoffs: list[str] = field(default_factory=list)
    # The `files_not_read` gap sign-offs emptied: gone from the outcome, kept for the legal
    # section, which a person's sign-off does not move. Not part of the document.
    signed_gap: Gap | None = None

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
            "signoffs": list(self.signoffs),
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
    it cites or read (`depends_on`) or its surface's file, anywhere in the person-facing unit
    it closes (the unit is what it speaks for, so the note need not sit in a cited file), in
    an agent instruction file of a directory above them, or in the record's own
    `untrusted_text`."""
    files = set(getattr(record, "cited_files", None) or [])
    raw = getattr(record, "raw", None) or {}
    # Spelt as validation reads it, so a note there is found however the record spells it.
    files |= {
        str(item.get("file")).strip().replace("\\", "/") for item in raw.get("depends_on") or []
    }
    surface_file = (record.surface or {}).get("file")
    if surface_file:
        files.add(surface_file)
    dirs: set[str] = set()
    for file in files:
        dirs |= _ancestors(file)
    unit_root = None
    if (record.surface or {}).get("type") == "person_facing_unit":
        unit_root = str(surface_file or ".").rstrip("/") or "."
        dirs |= _ancestors(unit_root + "/x")
    hits = []
    for item in untrusted:
        where = str(item.get("file"))
        if unit_root is not None and (unit_root == "." or where.startswith(unit_root + "/")):
            hits.append(f"{where}:{item.get('line')}" if item.get("line") else where)
        elif int(item.get("line") or 0) == 0:
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


def _some(files: Sequence[str]) -> str:
    shown = ", ".join(files[:_NAMED])
    return f"{shown} and {len(files) - _NAMED} more" if len(files) > _NAMED else shown


def _signed(record: Any) -> list[dict[str, Any]]:
    """The sign-offs that turned this record into a closing; [] for any other record."""
    return getattr(record, "signoffs", None) or []


def _who(row: dict[str, Any]) -> str:
    label = "auditor" if row.get("mode") == "auditor" else "self-assessed"
    return f"{row.get('by')} ({label}, sign-off {row.get('id')})"


def unread_files(
    tracked_not_walked: Sequence[str] | None, unsupported_files: Sequence[str]
) -> set[str]:
    """The files of the tree nobody read that may hold code or prompts: what `files_not_read`
    counts, and the only files a sign-off can name."""

    def suffix(rel: str) -> str:
        return PurePosixPath(rel).suffix.lower()

    unread = {rel for rel in tracked_not_walked or () if suffix(rel) not in _BINARY_MEDIA}
    unread |= set(unsupported_files)
    return {rel for rel in unread if suffix(rel) not in _TEXT_NOT_CODE}


def _files_not_read(
    tracked_not_walked: Sequence[str] | None,
    unsupported_files: Sequence[str],
    signed: Collection[str] = (),
    dirs_not_walked: Sequence[str] = (),
) -> Gap | None:
    """The blocking gap of the files nobody read, or None. `tracked_not_walked` is None when
    git could not list the commit's files: unknown, never empty, and no sign-off clears it.
    Outside git there is no commit: it holds the files the walk says it skipped, and
    `dirs_not_walked` the directories it did not go into, each of which may hold anything.
    `signed`: files a bound sign-off took out of the count."""
    unread = unread_files(tracked_not_walked, unsupported_files) - set(signed)
    parts = []
    if tracked_not_walked is None:
        parts.append("git could not list the commit's files: what the walk skipped is unknown")
    if unread:
        parts.append(
            f"{len(unread)} file(s) that may hold code or prompts were not read: "
            + _some(sorted(unread))
        )
    if dirs_not_walked:
        parts.append(
            f"{len(dirs_not_walked)} director(ies) outside git that may hold code or prompts "
            "were not walked: "
            + _some([f"{rel}/" for rel in sorted(dirs_not_walked)])
            + " (committing the tree gives a precise list)"
        )
    return Gap("files_not_read", "; ".join(parts)) if parts else None


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
    tracked_not_walked: Sequence[str] | None = (),
    unsupported_files: Sequence[str] = (),
    dirs_not_walked: Sequence[str] = (),
    signed_files: Sequence[dict[str, Any]] = (),
) -> list[MechanismOutcome]:
    """One outcome per policy mechanism, in policy order (see the module docstring).
    `records` are the accepted ones (superseded records left out); `rejected` the
    rejected ones; `untrusted` the plan's `untrusted_text`; `carried` the retest rows of
    the previous assessment's records; `tracked_not_walked` and `unsupported_files` the
    files of the tree the scan did not read, `dirs_not_walked` its directories outside git;
    `signed_files` the bound sign-offs, whose files leave that count."""
    ran = set(rules_ran)
    file_signoffs = [row for row in signed_files if row.get("files")]
    signed = {item["path"] for row in file_signoffs for item in row["files"]}
    not_read = _files_not_read(tracked_not_walked, unsupported_files, signed, dirs_not_walked)
    # Nothing is left of the gap, and a person's decision is why: the basis says so.
    signed_gap = None
    if signed and not_read is None:
        signed_gap = _files_not_read(tracked_not_walked, unsupported_files)
    by_person = [
        f"{len(row['files'])} unread file(s) left out by a person's decision: {_who(row)}"
        for row in file_signoffs
    ]
    # M8 has no patterns: no record may name it, so a rejected one naming it is unplaced too.
    known = {m.id for m in policy.mechanisms if m.patterns}
    unplaced = [r for r in rejected if r.mechanism not in known]
    out: list[MechanismOutcome] = []
    for mechanism in policy.mechanisms:
        if not mechanism.patterns:
            review = _review_mechanism(
                policy, mechanism, findings, review_records, ran, today, surfaces, not_read
            )
            review.signed_gap = signed_gap
            if signed_gap is not None and review.outcome == NO_VIOLATION:
                review.signoffs = [str(row.get("id")) for row in file_signoffs]
                review.basis.extend(by_person)
            out.append(review)
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
            signed_gap=signed_gap,
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
        # First: the terminal summary shows only the first few gaps of a mechanism.
        gaps: list[Gap] = [not_read] if not_read else []
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
                        pattern=str(hyp.get("pattern")),
                    )
                )
        for record in mine:
            if record.claim in ("establishes", "closes"):
                if _skeptic_refuted(record):
                    gaps.append(
                        Gap(
                            "skeptic_refuted",
                            "a skeptic pass refuted the claim",
                            record=record.id,
                            pattern=record.pattern,
                        )
                    )
                elif not _skeptic_upheld(record):
                    gaps.append(
                        Gap(
                            "skeptic_not_run",
                            "no skeptic pass bound to the record upheld the claim",
                            record=record.id,
                            pattern=record.pattern,
                        )
                    )
            if record.runtime:
                gaps.append(
                    Gap(
                        "runtime_only",
                        "a required link exists only at run time: " + ", ".join(record.runtime),
                        record=record.id,
                        pattern=record.pattern,
                    )
                )
            if record.claim == "review":
                gaps.append(
                    Gap(
                        "record_at_review",
                        f"the record's claim is {record.effective.get('evidence_status')} / "
                        f"{record.effective.get('decision')}: a person weighs it",
                        record=record.id,
                        pattern=record.pattern,
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
                            pattern=record.pattern,
                        )
                    )
        # A pattern that is not this mechanism's says nothing about what the record held
        # back: the gap then reads as every pattern, and the legal section treats it so.
        own_patterns = [pattern.id for pattern in mechanism.patterns]
        for record in their_rejected:
            pattern = getattr(record, "pattern", None)
            gaps.append(
                Gap(
                    "rejected_record",
                    "a record of this mechanism was rejected",
                    record=record.id or record.path,
                    pattern=pattern if pattern in own_patterns else None,
                )
            )
        for record in unplaced:
            gaps.append(
                Gap(
                    "rejected_record",
                    "a rejected record names no mechanism a record can decide",
                    record=record.id or record.path,
                )
            )
        # A sign-off answers a record at review, never a finding of the scan.
        covered = {
            fp
            for r in mine
            if r.claim in ("establishes", "closes") and not _signed(r)
            for fp in r.covers_valid
        }
        for finding in strong:
            if finding.decision is Decision.REVIEW and finding.fingerprint not in covered:
                row = _scan_row(finding)
                gaps.append(
                    Gap(
                        "scan_finding_to_decide",
                        f"{finding.display_id} ({finding.evidence_status.value}) at "
                        f"{row['file']}:{row['line']}: no deciding record covers it",
                        pattern=getattr(policy.pattern_of(finding.display_id), "id", None),
                    )
                )
        plan_closed = {
            (r.surface.get("id"), r.pattern) for r in closing if r.surface.get("id") is not None
        }
        n = len(set(hypotheses))
        k = len(set(hypotheses) & plan_closed)
        if closing and not k:
            carried_by = f"{n} carry" if n else "no surface of the plan carries"
            gaps.append(
                Gap(
                    "closed_off_plan",
                    "the closing record(s) answer no surface hypothesis of the plan; "
                    f"{carried_by} {mechanism.id}",
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
            for record in closing:
                for row in _signed(record):
                    result.basis.append(f"{record.id} closed by a person's decision: {_who(row)}")
                    result.signoffs.append(str(row.get("id")))
            if signed_gap is not None:
                result.basis.extend(by_person)
                result.signoffs.extend(str(row.get("id")) for row in file_signoffs)
            result.signoffs = sorted(set(result.signoffs))
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
    surfaces: Sequence[dict[str, Any]],
    not_read: Gap | None,
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
    if not review_records:
        result.basis.append("no review record and no finding to read")
        return result
    # One standing record does not answer for another: AUD-1107 reads every record too, but
    # only those covering a unit with person signals, so silence from it proves nothing here.
    fallen = [
        (row, reasons)
        for row in review_records
        if (reasons := _why_review_fell(row, policy, today))
    ]
    result.gaps = [not_read] if not_read else []
    if not_read:
        result.basis.append("files that may hold code or prompts were not read")
    if fallen:
        result.gaps += [Gap("stale_review_record", _fallen_detail(*row)) for row in fallen]
        result.basis.append(f"{len(fallen)} review record(s) no longer stand")
    elif unreviewed := _unreviewed_files(surfaces, review_records):
        result.gaps.append(
            Gap(
                "surface_not_reviewed",
                f"no review record binds {len(unreviewed)} file(s) of the plan's surfaces, "
                "with every mechanism they carry in its scope: " + _some(unreviewed),
            )
        )
        result.basis.append("the review records do not bind every file of the plan's surfaces")
    if result.gaps:
        result.outcome = INCONCLUSIVE
    else:
        result.outcome = NO_VIOLATION
        result.basis.append(
            f"{len(review_records)} review record(s) under policy {policy.version}, within "
            f"{policy.review_max_age_days} days, bound to the artifacts as they are now and to "
            "every file of the plan's surfaces, within their scope, and no review or control "
            "finding remains"
        )
    return result


def _fallen_detail(row: dict[str, Any], reasons: list[str]) -> str:
    """A row with no date is a problem with the record files, not a record: the parser
    dropped it, or a second file was never read. Its reason names the file."""
    reviewed_at = row.get("reviewed_at")
    if reviewed_at is None:
        return "a review record that does not count: " + "; ".join(reasons)
    return f"the review record of {reviewed_at} in {row.get('file')}: " + "; ".join(reasons)


def _unreviewed_files(
    surfaces: Sequence[dict[str, Any]], review_records: Sequence[dict[str, Any]]
) -> list[str]:
    """The files of the plan's surfaces no review record binds, read as `ReviewRecord.covers`
    reads a file. The surface of a person-facing unit is a directory, so no file test applies
    to it; its unit and its mechanisms do. A record binds a surface only when its `scope`
    holds every mechanism of the surface's hypotheses; a surface with none asks for the
    file binding alone."""

    def binds(row: dict[str, Any], surface: dict[str, Any]) -> bool:
        units = row.get("units") or ()
        carried = {hyp.get("mechanism") for hyp in surface.get("hypotheses") or []}
        return (
            (
                surface.get("type") == "person_facing_unit"
                or surface.get("file") in (row.get("artifact_files") or ())
            )
            and (not units or surface.get("unit") in units)
            and carried <= set(row.get("scope") or ())
        )

    return sorted(
        {
            str(surface.get("file"))
            for surface in surfaces
            if not any(binds(row, surface) for row in review_records)
        }
    )


def _why_review_fell(row: dict[str, Any], policy: Policy, today: date | None) -> list[str]:
    """Why a review record no longer stands; [] when it does. `stale` holds the reasons of
    `ReviewRecord.is_stale`; a row without it was never checked against the artifacts."""
    stale = row.get("stale")
    reasons = ["its artifacts were not checked"] if stale is None else [str(r) for r in stale]
    version = str(row.get("policy_version"))
    if version != policy.version:
        reasons.append(f"it is under policy {version}, not {policy.version}")
    if not reasons and not _fresh(row.get("reviewed_at"), policy.review_max_age_days, today):
        reasons.append(f"it is not within the {policy.review_max_age_days} day review window")
    return reasons


def _fresh(value: Any, max_age_days: int, today: date | None) -> bool:
    try:
        reviewed = date.fromisoformat(str(value)[:10])
    except ValueError:
        return False
    now = today or date.today()
    return 0 <= (now - reviewed).days <= max_age_days
