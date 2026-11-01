"""src/aisafe/legal/evaluate.py
----------------------------
The legal section of an assessment: each selected profile's provisions read against the
engagement's applicability answers, the audit date and the evidence. A pure function of
its inputs; nothing here reads a file. The section is kept apart from the ethical
outcome: it never changes a mechanism's outcome or the exit code.

Per provision, in this order:

0. a provision whose text could not be checked against its source ->
   `requires_specialist_review`, whatever else holds;
1. not in force on the audit date: on a date the law states -> `not_applicable` ("not in
   force on the audit date"); on a derived date -> `requires_specialist_review` (a date
   counted or inferred never removes a duty on its own);
2. a condition answered against it -> `not_applicable`, with the condition;
3. a condition unanswered (or answered `unknown`, or a definition without its reason) ->
   `insufficient_evidence`, with the answers needed;
4. any evidence showing a required control absent or failing -> `gap_identified`;
5. any required evidence missing -> `insufficient_evidence`, with what is missing (the
   organisational items become evidence requests);
6. legal elements no code can show, or a provision whose ceiling says so ->
   `requires_specialist_review`, with the evidence that was met;
7. otherwise `satisfied_within_scope`: every listed piece of evidence present and
   validated, within the scope of the assessment.

Scanner silence never counts: no item is met by the absence of a finding. A code item is
met only by validated records whose skeptic pass upheld them, on every plan surface that
carries the hypothesis, while the ethical outcome holds no blocking gap for that pattern.
A person's sign-off moves the ethical outcome and no legal item: a record it closed is no
upheld closing here, and the unread files it left out still hold the item back.
Applicability answers that name nobody (`answered_by` empty) decide nothing. A `gap_identified` result is a reading of the evidence against a
testable control, not a finding of infringement.
"""

from __future__ import annotations

import hashlib
from datetime import date
from typing import Any, Sequence

from aisafe.evidence.model import Decision, EvidenceStatus, Finding
from aisafe.legal.profile import LIST_ANSWERS, RESULTS, LegalProfile

__all__ = ["LEGAL_NOTE", "evaluate_legal", "record_request_id"]

GAP = "gap_identified"
INSUFFICIENT = "insufficient_evidence"
SPECIALIST = "requires_specialist_review"
SATISFIED = "satisfied_within_scope"
NOT_APPLICABLE = "not_applicable"
LEGAL_NOTE = (
    "Legal results are kept apart from the ethical outcome: they never change a mechanism's "
    "outcome or the exit code. They read the provisions of the selected profiles against "
    "the engagement's answers and the evidence listed, within the scope of this assessment. "
    "A gap identified is a reading of the evidence against a testable control, not a finding "
    "of infringement. Ethical and legal conclusions never merge: legally permissible "
    "behaviour can still violate the charter. Not legal advice."
)
_STRONG = frozenset({EvidenceStatus.SUPPORTED_MECHANISM, EvidenceStatus.OBSERVED_BEHAVIOR})
_UNREMEDIATED = frozenset({"not_remediated", "regressed", "needs_reinvestigation", "not_verified"})


def record_request_id(record_id: str, text: str) -> str:
    """The evidence request id for one `missing_evidence` line of a record."""
    digest = hashlib.sha256(text.strip().encode("utf-8")).hexdigest()[:8]
    return f"record/{record_id}/{digest}"


# ---------------------------------------------------------------------------
# Applicability
# ---------------------------------------------------------------------------


def _condition(cond: dict[str, Any], answers: dict[str, Any]) -> dict[str, Any]:
    """One condition read against the answers: value True, False or None, and why."""
    row = {"why": cond.get("why"), "cite": (cond.get("quote") or {}).get("cite")}
    if "answer" in cond:
        key = cond["answer"]
        value = answers.get(key)
        row["answer"] = key
        if value in (None, "", []) or (key in LIST_ANSWERS and not isinstance(value, list)):
            return {**row, "value": None, "detail": f"{key} is not answered"}
        if key in LIST_ANSWERS:
            if "unknown" in value:
                return {**row, "value": None, "detail": f"{key} includes 'unknown'"}
            wanted = cond["includes_any"] if "includes_any" in cond else [cond["includes"]]
            hit = sorted(set(wanted) & set(value))
            if hit:
                return {**row, "value": True, "detail": f"{key} includes {', '.join(hit)}"}
            return {
                **row,
                "value": False,
                "detail": f"{key} is {', '.join(value)}; needs one of {', '.join(wanted)}",
            }
        if value == cond.get("equals"):
            return {**row, "value": True, "detail": f"{key} is {value}"}
        if value in (cond.get("false_if") or []):
            return {**row, "value": False, "detail": f"{key} is {value}"}
        return {**row, "value": None, "detail": f"{key} is {value}: it does not decide"}
    definitions = answers.get("definitions") or {}
    ids = [cond["definition"]] if "definition" in cond else list(cond.get("definitions_any") or [])
    row["definitions"] = ids
    row["question"] = cond.get("question")
    values = []
    details = []
    for definition in ids:
        entry = definitions.get(definition) or {}
        answer = entry.get("answer")
        if answer in ("meets", "does_not_meet") and not str(entry.get("reason") or "").strip():
            values.append(None)
            details.append(f"{definition}: {answer} without a reason")
        elif answer == "meets":
            values.append(True)
            details.append(f"{definition}: meets")
        elif answer == "does_not_meet":
            values.append(False)
            details.append(f"{definition}: does not meet")
        else:
            values.append(None)
            details.append(f"{definition}: not answered")
    if any(v is True for v in values):
        value: bool | None = True
    elif values and all(v is False for v in values):
        value = False
    else:
        value = None
    return {**row, "value": value, "detail": "; ".join(details)}


def _applicability(rows: Sequence[dict[str, Any]]) -> str:
    values = [row["value"] for row in rows]
    if any(v is False for v in values):
        return "does_not_apply"
    if any(v is None for v in values):
        return "undetermined"
    return "applies"


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


class _Evidence:
    """What the evidence items read: the ethical outcome, the accepted records, the plan
    surfaces, the scan findings, the evaluation context and the request states."""

    def __init__(
        self,
        *,
        policy: Any,
        outcomes: Sequence[Any],
        records: Sequence[Any],
        surfaces: Sequence[dict[str, Any]],
        findings: Sequence[Finding],
        evaluation: Any,
        requests: dict[str, dict[str, Any]],
        carried: Sequence[dict[str, Any]],
    ) -> None:
        self.policy = policy
        self.outcomes = {o.id: o for o in outcomes}
        self.records = list(records)
        self.surfaces = list(surfaces)
        self.findings = list(findings)
        self.evaluation = evaluation
        self.requests = requests
        self.carried = list(carried)

    def _upheld(self, record: Any) -> bool:
        skeptic = getattr(record, "skeptic", None) or {}
        return bool(skeptic.get("bound")) and skeptic.get("result") == "upheld"

    def pattern_item(self, item: dict[str, Any]) -> dict[str, Any]:
        """A `control` or `closed` item: gap when the pattern is established (by a record,
        a supported or observed scan violation, or a violation carried from the previous
        commit); met when every plan surface carrying the hypothesis has an upheld closing
        record and the ethical outcome holds no blocking gap for the pattern; for a control
        item, each of those surfaces must also show the control on its path or rule out the
        person's link (no message from a person reaches the call, or no reply reaches them),
        and at least one must show the control; missing otherwise."""
        mech, pattern = item["mechanism"], item["pattern"]
        outcome = self.outcomes.get(mech)
        row: dict[str, Any] = {
            "kind": item["kind"],
            "what": item.get("what"),
            "pattern": f"{mech}/{pattern}",
            "control": item.get("control"),
        }
        established = set(getattr(outcome, "establishing", None) or [])
        establishing = [
            r.id
            for r in self.records
            if r.mechanism == mech and r.pattern == pattern and r.id in established
        ]
        scan = sorted(
            {
                f.display_id
                for f in self.findings
                if f.mechanism == mech
                and f.decision is Decision.VIOLATES
                and f.evidence_status in _STRONG
                and (p := self.policy.pattern_of(f.display_id)) is not None
                and p.id == pattern
            }
        )
        carried = [
            str(r.get("record"))
            for r in self.carried
            if r.get("mechanism") == mech
            and r.get("pattern") == pattern
            and r.get("claim_before") == "establishes"
            and r.get("status") in _UNREMEDIATED
        ]
        if establishing or scan or carried:
            parts = []
            if establishing:
                parts.append("established by " + ", ".join(establishing))
            if scan:
                parts.append("the scan reports " + ", ".join(scan) + " as violating the policy")
            if carried:
                parts.append("not remediated since the previous commit: " + ", ".join(carried))
            return {**row, "status": "gap", "detail": "; ".join(parts), "records": establishing}
        # The ethical outcome's gaps for this pattern (or for no pattern in particular)
        # keep the item from being met: a record a gap names does not count, and a gap that
        # names no record (a finding nobody decided, a closing off the plan) blocks it.
        signed_gap = getattr(outcome, "signed_gap", None)
        gaps = [
            g
            for g in [
                *(getattr(outcome, "gaps", None) or []),
                *([signed_gap] if signed_gap else []),
            ]
            if g.pattern in (None, pattern)
        ]
        blocked = {g.record for g in gaps if g.record}
        # A refuted or unchallenged record, a record at review, a rejected record, a finding
        # nobody decided: each holds the item back, as it holds the ethical outcome back.
        loose = [g for g in gaps if g.kind != "high_surface_not_investigated"]
        surfaces = [
            s
            for s in self.surfaces
            if any(
                h.get("mechanism") == mech and h.get("pattern") == pattern
                for h in s.get("hypotheses") or []
            )
        ]
        if not surfaces:
            return {
                **row,
                "status": "missing",
                "detail": f"no surface of the plan carries {mech}/{pattern}",
                "records": [],
            }
        carrying = {s["id"] for s in surfaces}
        closing: dict[str, list[Any]] = {}
        for record in self.records:
            sid = (record.surface or {}).get("id")
            if (
                sid in carrying
                and record.mechanism == mech
                and record.pattern == pattern
                and record.claim == "closes"
                and not getattr(record, "signoffs", None)
                and self._upheld(record)
                and record.id not in blocked
            ):
                closing.setdefault(sid, []).append(record)
        open_surfaces = [s["id"] for s in surfaces if s["id"] not in closing]
        used = sorted({r.id for rs in closing.values() for r in rs})
        # A sign-off takes its record's gap away, and this section does not read a sign-off:
        # the signed record stays the loose end it was, whatever else closes the surface.
        signed = sorted(
            {
                r.id
                for r in self.records
                if r.mechanism == mech and r.pattern == pattern and getattr(r, "signoffs", None)
            }
        )
        if open_surfaces:
            return {
                **row,
                "status": "missing",
                "detail": (
                    f"{len(open_surfaces)} of {len(surfaces)} plan surface(s) carrying "
                    f"{mech}/{pattern} have no upheld closing record: "
                    + ", ".join(open_surfaces[:6])
                    + (" ..." if len(open_surfaces) > 6 else "")
                ),
                "records": used,
            }
        if loose or signed:
            return {
                **row,
                "status": "missing",
                "detail": "the ethical outcome holds a blocking gap for it: "
                + "; ".join(
                    [
                        *(g.detail for g in loose[:3]),
                        *(f"{rid} is closed only by a person's sign-off" for rid in signed[:3]),
                    ]
                ),
                "records": used,
            }
        if item["kind"] == "control":
            # A closing that breaks the chain at another link (no confidant role in the
            # prompt, say) still leaves a person talking to the model without the control.
            weak = [
                sid
                for sid, records in closing.items()
                if not any(
                    getattr(r, "control_on_path", False)
                    or set(getattr(r, "ruled_out", None) or []) & {"ingress", "intervention"}
                    for r in records
                )
            ]
            if weak:
                return {
                    **row,
                    "status": "missing",
                    "detail": (
                        f"on {len(weak)} surface(s) the closing breaks the chain at another "
                        "link, so a person still reaches the model there and no record shows "
                        f"the {item.get('control')} control on that path: " + ", ".join(weak[:6])
                    ),
                    "records": used,
                }
            by_control = sorted(
                {
                    r.id
                    for rs in closing.values()
                    for r in rs
                    if getattr(r, "control_on_path", False)
                }
            )
            if not by_control:
                return {
                    **row,
                    "status": "missing",
                    "detail": (
                        f"every surface is closed, but no record shows the {item.get('control')} "
                        "control on the path"
                    ),
                    "records": used,
                }
            return {
                **row,
                "status": "met",
                "detail": (
                    f"closed on {len(surfaces)} plan surface(s); the {item.get('control')} "
                    "control is on the path in " + ", ".join(by_control)
                ),
                "records": used,
            }
        return {
            **row,
            "status": "met",
            "detail": f"closed on {len(surfaces)} plan surface(s) by " + ", ".join(used),
            "records": used,
        }

    def indicators_item(self, item: dict[str, Any]) -> dict[str, Any]:
        """Article 5's reading of the linked mechanisms: missing while any is not assessed
        or inconclusive, or closed through a sign-off, which this section does not read;
        otherwise the violations established, as indicators."""
        rows = []
        missing = []
        present = []
        for mech in item.get("mechanisms") or []:
            outcome = self.outcomes.get(mech)
            value = getattr(outcome, "outcome", "not_assessed")
            rows.append({"mechanism": mech, "outcome": value})
            if value in ("not_assessed", "inconclusive"):
                missing.append(f"{mech} {value}")
            elif getattr(outcome, "signoffs", None):
                missing.append(f"{mech} closed through a person's sign-off")
            elif value == "violations_identified":
                present.append(mech)
        base = {"kind": "indicators", "what": item.get("what"), "mechanisms": rows}
        if missing:
            return {
                **base,
                "status": "missing",
                "detail": "the linked mechanisms are not all decided: " + ", ".join(missing),
            }
        if present:
            return {
                **base,
                "status": "indicators",
                "detail": "violations established, to weigh as indicators: " + ", ".join(present),
            }
        return {
            **base,
            "status": "indicators",
            "detail": "no violation of the linked mechanisms identified within the assessed scope",
        }

    def evaluation_item(self, item: dict[str, Any]) -> dict[str, Any]:
        from aisafe.rules._common import evaluation_demonstrates

        family = item["family"]
        max_age = int(getattr(self.policy, "evaluation_max_age_days", 30) or 30)
        verdict, report = evaluation_demonstrates(self.evaluation, family, max_age)
        where = getattr(report, "file", None) if report is not None else None
        row = {"kind": "evaluation", "family": family, "what": item.get("what"), "report": where}
        if verdict is True:
            return {**row, "status": "met", "detail": f"every {family} case passed in {where}"}
        if verdict is False and item.get("fail") == "missing":
            # The family reads the reply only: a notice shown elsewhere is not in it.
            return {
                **row,
                "status": "missing",
                "detail": (
                    f"a {family} case failed in {where}; the family reads only the reply, so "
                    "a notice shown outside it is not seen: the item is not met"
                ),
            }
        if verdict is False:
            return {**row, "status": "gap", "detail": f"a {family} case failed in {where}"}
        return {
            **row,
            "status": "missing",
            "detail": (
                f"no fresh evaluation report (within {max_age} days) shows every {family} case "
                "passing" + (f"; {where} was read" if where else "")
            ),
        }

    def organisational_item(self, request_id: str, item: dict[str, Any]) -> dict[str, Any]:
        state = self.requests.get(request_id)
        row = {"kind": "organisational", "request": request_id, "what": item.get("what")}
        if state is None:
            return {**row, "status": "missing", "detail": "requested by this assessment"}
        return {
            **row,
            "status": "met" if state["counted"] else "missing",
            "detail": state["detail"],
            "documents": state.get("documents") or [],
        }


def _in_force(spec: dict[str, Any], today: date) -> tuple[str, bool]:
    """("in_force" | "not_yet" | "ended", whether a derived date decides it)."""
    start = spec.get("from")
    end = spec.get("until")
    if start and today < date.fromisoformat(str(start)):
        return "not_yet", bool(spec.get("from_derived"))
    if end and today >= date.fromisoformat(str(end)):
        return "ended", bool(spec.get("until_derived"))
    return "in_force", False


def _provision(
    profile: LegalProfile,
    prov: dict[str, Any],
    *,
    profile_rows: Sequence[dict[str, Any]],
    answers: dict[str, Any],
    today: date,
    evidence: _Evidence,
    wanted: list[dict[str, Any]],
) -> dict[str, Any]:
    rows = [*profile_rows, *(_condition(c, answers) for c in prov.get("applies_if") or [])]
    applicability = _applicability(rows)
    in_force = dict(prov.get("in_force") or {})
    state, derived_decides = _in_force(in_force, today)
    in_force["on_audit_date"] = state
    out: dict[str, Any] = {
        "id": prov["id"],
        "citation": prov.get("citation"),
        "title": prov.get("title"),
        "verified": bool(prov.get("verified")),
        "in_force": in_force,
        "applicability": applicability,
        "conditions": rows,
        "mechanisms": list(prov.get("mechanisms") or []),
        "evidence": {"code": [], "evaluation": [], "organisational": []},
        "specialist": list(prov.get("specialist") or []),
        "controls": list(prov.get("controls") or []),
        "replaced_by": prov.get("replaced_by"),
        "notes": list(prov.get("notes") or []),
        "text": [{"cite": t.get("cite"), "quote": t.get("quote")} for t in prov.get("text") or []],
    }
    reasons: list[str] = []
    if prov.get("replaced_by"):
        rep = prov["replaced_by"]
        reasons.append(f"replaced by {rep.get('law')} from {rep.get('from')}: {rep.get('note')}")

    def done(result: str, *why: str) -> dict[str, Any]:
        out["result"] = result
        out["reasons"] = [*why, *reasons]
        return out

    if not prov.get("verified"):
        # A text nobody could check against its source decides nothing, not even that the
        # provision does not apply.
        return done(
            SPECIALIST,
            "the provision's text could not be checked against its source: "
            + str(prov.get("unverified_reason") or ""),
        )
    if state != "in_force":
        when = (
            f"applies from {in_force.get('from')}"
            if state == "not_yet"
            else f"applied until {in_force.get('until')}"
        )
        if derived_decides:
            return done(
                SPECIALIST,
                f"not in force on the audit date ({today.isoformat()}) only by a derived date: "
                f"{when}; {in_force.get('basis')}. A derived date never removes a duty on its "
                "own: a lawyer confirms it",
            )
        return done(NOT_APPLICABLE, f"not in force on the audit date ({today.isoformat()}): {when}")
    if applicability == "does_not_apply":
        false = [r["detail"] for r in rows if r["value"] is False]
        return done(NOT_APPLICABLE, "does not apply: " + "; ".join(false))
    if applicability == "undetermined":
        open_rows = [r["detail"] for r in rows if r["value"] is None]
        return done(
            INSUFFICIENT,
            "applicability undetermined; answer in the engagement: " + "; ".join(open_rows),
        )
    items = prov.get("evidence") or {}
    for item in items.get("code") or []:
        if item["kind"] == "indicators":
            out["evidence"]["code"].append(evidence.indicators_item(item))
        else:
            out["evidence"]["code"].append(evidence.pattern_item(item))
    for item in items.get("evaluation") or []:
        out["evidence"]["evaluation"].append(evidence.evaluation_item(item))
    for item in items.get("organisational") or []:
        request_id = f"{profile.id}/{prov['id']}/{item['id']}"
        wanted.append(
            {
                "id": request_id,
                "source": {"profile": profile.id, "provision": prov["id"], "item": item["id"]},
                "what": item["what"],
            }
        )
        out["evidence"]["organisational"].append(evidence.organisational_item(request_id, item))
    every = [row for group in out["evidence"].values() for row in group]
    gaps = [row for row in every if row["status"] == "gap"]
    missing = [row for row in every if row["status"] == "missing"]
    met = [row for row in every if row["status"] in ("met", "indicators")]
    if gaps and prov.get("ceiling") is None:
        return done(GAP, *(f"{_label(row)}: {row['detail']}" for row in gaps))
    if missing:
        return done(INSUFFICIENT, *(f"{_label(row)}: {row['detail']}" for row in missing))
    if prov.get("ceiling") or out["specialist"]:
        # Under a ceiling a control shown absent is weighed by the specialist with the
        # rest, so it is listed first, never dropped.
        return done(
            SPECIALIST,
            "the evidence listed is present; legal elements no code can show remain: "
            + " | ".join(out["specialist"] or ["see the provision"]),
            *(f"{_label(row)}: {row['detail']}" for row in [*gaps, *met]),
        )
    return done(
        SATISFIED,
        "every piece of evidence listed is present and validated, within the scope assessed",
        *(f"{_label(row)}: {row['detail']}" for row in met),
    )


def _label(row: dict[str, Any]) -> str:
    if row["kind"] == "evaluation":
        return f"evaluation {row.get('family')}"
    if row["kind"] == "organisational":
        return f"document {row.get('request')}"
    if row["kind"] == "indicators":
        return "linked mechanisms"
    return f"code {row.get('pattern')}"


def evaluate_legal(
    profiles: Sequence[LegalProfile],
    *,
    answers: dict[str, Any],
    today: date,
    policy: Any,
    outcomes: Sequence[Any],
    records: Sequence[Any],
    surfaces: Sequence[dict[str, Any]],
    findings: Sequence[Finding],
    evaluation: Any,
    requests: dict[str, dict[str, Any]],
    carried: Sequence[dict[str, Any]] = (),
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """The legal section, and the organisational evidence requests it needs
    ({id, source, what}) for the provisions that apply and are in force."""
    evidence = _Evidence(
        policy=policy,
        outcomes=outcomes,
        records=records,
        surfaces=surfaces,
        findings=findings,
        evaluation=evaluation,
        requests=requests,
        carried=carried,
    )
    selected = set(answers.get("jurisdictions") or [])
    # Answers that name nobody decide nothing: accountability has a name.
    unnamed = not str(answers.get("answered_by") or "").strip()
    reading = {"definitions": {}} if unnamed else answers
    wanted: list[dict[str, Any]] = []
    out_profiles = []
    not_selected = []
    for profile in profiles:
        if profile.jurisdiction not in selected:
            not_selected.append(
                {"id": profile.id, "jurisdiction": profile.jurisdiction, "title": profile.title}
            )
            continue
        data = profile.data
        profile_rows = [_condition(c, reading) for c in data.get("applicability") or []]
        if unnamed:
            profile_rows.insert(
                0,
                {
                    "why": "the applicability answers name the person who gave them",
                    "cite": None,
                    "answer": "answered_by",
                    "value": None,
                    "detail": "applicability.answered_by is empty: answers that name nobody "
                    "decide nothing",
                },
            )
        review = data.get("legal_review") or {}
        provisions = []
        for prov in data.get("provisions") or []:
            asked: list[dict[str, Any]] = []
            row = _provision(
                profile,
                prov,
                profile_rows=profile_rows,
                answers=reading,
                today=today,
                evidence=evidence,
                wanted=asked,
            )
            if row["applicability"] == "applies" and row["result"] != NOT_APPLICABLE:
                wanted.extend(asked)
            provisions.append(row)
        counts = {result: 0 for result in RESULTS}
        for row in provisions:
            counts[row["result"]] += 1
        out_profiles.append(
            {
                "id": profile.id,
                "title": profile.title,
                "jurisdiction": profile.jurisdiction,
                "profile_version": data.get("profile_version"),
                "source": dict(data.get("source") or {}),
                "sources": [dict(s) for s in data.get("sources") or []],
                "file": profile.path.name,
                "sha256": profile.sha256,
                "legal_review": {"by": review.get("by"), "date": review.get("date")},
                "review_status": (
                    f"reviewed by {review['by']} on {review['date']}"
                    if profile.reviewed
                    else "not reviewed by a lawyer"
                ),
                "applicability": _applicability(profile_rows),
                "conditions": profile_rows,
                "provisions": provisions,
                "counts": counts,
                "not_covered": list(data.get("not_covered") or []),
                "notes": list(data.get("notes") or []),
            }
        )
    totals = {result: 0 for result in RESULTS}
    for prof in out_profiles:
        for result, n in prof["counts"].items():
            totals[result] += n
    section = {
        "note": LEGAL_NOTE,
        "audit_date": today.isoformat(),
        "answers": {
            key: answers.get(key)
            for key in (
                "answered_by",
                "answered_on",
                "markets",
                "jurisdictions",
                "roles",
                "product_type",
                "minors",
                "age_assurance",
                "eu_placement",
                "definitions",
            )
        },
        "profiles": out_profiles,
        "not_selected": not_selected,
        "counts": totals,
        "order": list(RESULTS),
    }
    return section, wanted
