"""tests/unit/test_legal.py
------------------------
The legal profiles (`aisg/legal-profile/1`) and their evaluation: the shipped profiles load
and quote their sources; a broken profile is refused; applicability never follows from the
jurisdiction alone; a date the law states and a derived date are treated differently; a
result is `satisfied_within_scope` only when every listed piece of evidence is present and
validated, and scanner silence never counts.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import date
from types import SimpleNamespace
from typing import Any

import pytest

from aisafe.evidence.model import Decision, EvidenceStatus
from aisafe.legal.evaluate import evaluate_legal, record_request_id
from aisafe.legal.profile import (
    PROFILES_DIR,
    RESULTS,
    check_profile,
    definition_questions,
    load_profiles,
)
from aisafe.policy import load_policy

POLICY = load_policy()
PROFILES = {p.id: p for p in load_profiles()}
PATTERNS = {(m.id, p.id): p.absent_control for m in POLICY.mechanisms for p in m.patterns}
MECHANISMS = {m.id for m in POLICY.mechanisms}
TODAY = date(2026, 10, 30)


# ---------------------------------------------------------------------------
# Fakes for the inputs the evaluation reads
# ---------------------------------------------------------------------------


@dataclass
class Rec:
    id: str
    mechanism: str
    pattern: str
    claim: str
    surface: dict[str, Any]
    control_on_path: bool = False
    skeptic: dict[str, Any] = field(default_factory=lambda: {"bound": True, "result": "upheld"})
    ruled_out: list[str] = field(default_factory=list)


@dataclass
class Out:
    id: str
    outcome: str = "not_assessed"
    establishing: list[str] = field(default_factory=list)
    gaps: list[Any] = field(default_factory=list)


def _surface(sid: str, *pairs: tuple[str, str]) -> dict[str, Any]:
    return {
        "id": sid,
        "type": "person_facing_unit",
        "file": ".",
        "line": 0,
        "priority": "high",
        "hypotheses": [{"mechanism": m, "pattern": p} for m, p in pairs],
    }


def _evaluation(**families: dict[str, int]) -> Any:
    report = SimpleNamespace(
        file="eval.json",
        families=list(families),
        age_days=1,
        body={"by_family": families},
    )
    return SimpleNamespace(evaluation=[report] if families else [])


def _answers(**over: Any) -> dict[str, Any]:
    base = {
        "answered_by": "T. Auditor",
        "answered_on": "2026-10-30",
        "markets": ["EU", "US-NY", "US-CA"],
        "jurisdictions": ["EU", "US-NY", "US-CA"],
        "roles": ["provider", "operator"],
        "product_type": "companion chatbot",
        "minors": "none_known",
        "age_assurance": "none",
        "eu_placement": ["placed_on_market"],
        "definitions": {
            key: {"answer": "meets", "reason": "the auditor's reading"}
            for key in definition_questions(list(PROFILES.values()))
        },
    }
    base.update(over)
    return base


def _run(
    *,
    answers: dict[str, Any] | None = None,
    today: date = TODAY,
    outcomes: list[Out] | None = None,
    records: list[Rec] | None = None,
    surfaces: list[dict[str, Any]] | None = None,
    findings: list[Any] | None = None,
    evaluation: Any = None,
    requests: dict[str, dict[str, Any]] | None = None,
    profiles: list[Any] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    return evaluate_legal(
        profiles if profiles is not None else list(PROFILES.values()),
        answers=answers if answers is not None else _answers(),
        today=today,
        policy=POLICY,
        outcomes=outcomes or [Out(m) for m in sorted(MECHANISMS)],
        records=records or [],
        surfaces=surfaces or [],
        findings=findings or [],
        evaluation=evaluation if evaluation is not None else _evaluation(),
        requests=requests or {},
    )


def _prov(section: dict[str, Any], profile: str, provision: str) -> dict[str, Any]:
    prof = next(p for p in section["profiles"] if p["id"] == profile)
    return next(p for p in prof["provisions"] if p["id"] == provision)


def _received(*ids: str) -> dict[str, dict[str, Any]]:
    return {
        i: {"id": i, "status": "received", "counted": True, "detail": "received", "documents": []}
        for i in ids
    }


CRISIS = ("M5", "confidant_without_crisis_path")
DISCLOSURE = ("M6", "no_disclosure_on_path")


# ---------------------------------------------------------------------------
# The shipped profiles
# ---------------------------------------------------------------------------


def test_the_shipped_profiles_load_quote_their_sources_and_are_not_reviewed() -> None:
    assert set(PROFILES) == {"eu-ai-act", "us-ny-gbl-47", "us-ca-sb243"}
    for profile in PROFILES.values():
        data = profile.data
        assert data["source"]["url"].startswith("https://")
        assert data["source"]["version"] and data["source"]["checked_on"] == "2026-10-30"
        # Null until a lawyer reviewed it; reports print that status.
        assert data["legal_review"] == {"by": None, "date": None} and not profile.reviewed
        for prov in data["provisions"]:
            assert prov["verified"] is True and prov["text"], prov["id"]
            for quote in prov["text"]:
                assert quote["quote"].strip() and quote["excerpt"] and quote["url"]
            assert "from" in prov["in_force"] and prov["in_force"]["basis"]


def test_the_initial_profiles_cover_the_provisions_the_milestone_names() -> None:
    ids = {(pid, prov["id"]) for pid, p in PROFILES.items() for prov in p.data["provisions"]}
    assert {
        ("eu-ai-act", "art-5-1-a"),
        ("eu-ai-act", "art-5-1-b"),
        ("eu-ai-act", "art-50-1"),
        ("eu-ai-act", "art-50-3"),
        ("us-ny-gbl-47", "gbl-1701"),
        ("us-ny-gbl-47", "gbl-1702"),
        ("us-ca-sb243", "bpc-22602-a"),
        ("us-ca-sb243", "bpc-22602-b-1"),
        ("us-ca-sb243", "bpc-22602-b-2"),
        ("us-ca-sb243", "bpc-22602-c"),
    } <= ids
    eu = {p["id"]: p for p in PROFILES["eu-ai-act"].data["provisions"]}
    # Article 50(1) applies from 2 August 2026: the omnibus did not defer it.
    assert eu["art-50-1"]["in_force"]["from"] == "2026-08-02"
    assert not eu["art-50-1"]["in_force"]["from_derived"]
    ca = {p["id"]: p for p in PROFILES["us-ca-sb243"].data["provisions"]}
    minors = ca["bpc-22602-c"]
    assert minors["replaced_by"]["law"].startswith("SB 1119")
    assert minors["in_force"]["until"] == "2027-01-01" and minors["in_force"]["until_derived"]


def test_testable_duties_map_to_the_crisis_and_identity_controls() -> None:
    def code(pid: str, prov_id: str) -> set[tuple[str, str]]:
        prov = next(p for p in PROFILES[pid].data["provisions"] if p["id"] == prov_id)
        return {(i["mechanism"], i["pattern"]) for i in prov["evidence"]["code"] if "pattern" in i}

    def families(pid: str, prov_id: str) -> set[str]:
        prov = next(p for p in PROFILES[pid].data["provisions"] if p["id"] == prov_id)
        return {i["family"] for i in prov["evidence"]["evaluation"]}

    # AUD-1108 serves M5/confidant_without_crisis_path; AUD-1105 serves M6.
    assert CRISIS in code("us-ny-gbl-47", "gbl-1701") and CRISIS in code(
        "us-ca-sb243", "bpc-22602-b-1"
    )
    assert "crisis_disclosure" in families("us-ny-gbl-47", "gbl-1701")
    assert DISCLOSURE in code("eu-ai-act", "art-50-1") and DISCLOSURE in code(
        "us-ny-gbl-47", "gbl-1702"
    )
    assert "identity_question" in families("eu-ai-act", "art-50-1")
    assert "AUD-1108" in POLICY.pattern_by_id(*CRISIS).rules
    assert any(r.startswith("AUD-1105") for r in POLICY.pattern_by_id(*DISCLOSURE).rules)


def _broken(mutate) -> list[str]:
    import yaml

    data = yaml.safe_load((PROFILES_DIR / "us-ny-gbl-47.yaml").read_text(encoding="utf-8"))
    data = copy.deepcopy(data)
    mutate(data)
    return check_profile(data, patterns=PATTERNS, mechanisms=MECHANISMS)


@pytest.mark.parametrize(
    "mutate, needle",
    [
        (lambda d: d.pop("legal_review"), "legal_review"),
        (lambda d: d.__setitem__("legal_review", {"by": "X", "date": None}), "reviewer and a date"),
        (lambda d: d["source"].pop("checked_on"), "checked_on"),
        (
            lambda d: d["applicability"].append(
                {"answer": "jurisdictions", "includes": "US-NY", "why": "x"}
            ),
            "not an applicability answer",
        ),
        (
            lambda d: d["applicability"].append(
                {"answer": "minors", "equals": "unknown", "why": "x"}
            ),
            "never decides",
        ),
        (
            lambda d: d["provisions"][0]["evidence"]["code"][0].__setitem__(
                "control", "ai_disclosure"
            ),
            "absent control",
        ),
        (
            lambda d: d["provisions"][0]["evidence"]["evaluation"][0].__setitem__("family", "nope"),
            "evaluation family",
        ),
        (lambda d: d["provisions"][0].__setitem__("text", []), "quotes its text"),
        (
            lambda d: d["provisions"][0]["evidence"]["code"].append(
                {"kind": "indicators", "mechanisms": ["M5"], "what": "x"}
            ),
            "ceiling",
        ),
        (lambda d: d["provisions"][1].__setitem__("id", d["provisions"][0]["id"]), "repeated"),
    ],
)
def test_a_broken_profile_is_refused(mutate, needle: str) -> None:
    errors = _broken(mutate)
    assert any(needle in e for e in errors), errors


# ---------------------------------------------------------------------------
# Applicability and dates
# ---------------------------------------------------------------------------


def test_selecting_a_jurisdiction_never_establishes_applicability() -> None:
    answers = {"jurisdictions": ["EU", "US-NY", "US-CA"], "definitions": {}}
    section, wanted = _run(answers=answers)
    assert wanted == []
    for prof in section["profiles"]:
        assert prof["applicability"] == "undetermined"
        for prov in prof["provisions"]:
            assert prov["result"] == "insufficient_evidence", prov["id"]
            assert prov["applicability"] == "undetermined"


def test_a_profile_not_selected_is_listed_and_not_evaluated() -> None:
    section, _ = _run(answers=_answers(jurisdictions=["US-NY"]))
    assert [p["id"] for p in section["profiles"]] == ["us-ny-gbl-47"]
    assert {p["id"] for p in section["not_selected"]} == {"eu-ai-act", "us-ca-sb243"}


def test_an_answer_against_a_condition_makes_it_not_applicable_with_the_reason() -> None:
    answers = _answers()
    answers["definitions"]["us-ny-gbl-47/operator"] = {
        "answer": "does_not_meet",
        "reason": "the auditee neither operates nor provides the companion",
    }
    section, _ = _run(answers=answers)
    row = _prov(section, "us-ny-gbl-47", "gbl-1701")
    assert row["result"] == "not_applicable" and "operator" in row["reasons"][0]
    # The generic roles answer does not settle who is an operator under New York law.
    section, _ = _run(answers=_answers(roles=["provider"]))
    assert _prov(section, "us-ny-gbl-47", "gbl-1701")["applicability"] == "applies"


def test_answers_that_name_nobody_decide_nothing() -> None:
    section, wanted = _run(answers=_answers(answered_by=None))
    assert wanted == []
    for prof in section["profiles"]:
        assert prof["applicability"] == "undetermined"
        assert any("name nobody" in str(c.get("detail")) for c in prof["conditions"])


def test_a_definition_answered_without_its_reason_does_not_decide() -> None:
    answers = _answers()
    answers["definitions"]["us-ny-gbl-47/ai-companion"] = {"answer": "meets", "reason": None}
    section, _ = _run(answers=answers)
    row = _prov(section, "us-ny-gbl-47", "gbl-1701")
    assert row["applicability"] == "undetermined" and row["result"] == "insufficient_evidence"
    assert "without a reason" in row["reasons"][0]


def test_a_provision_not_yet_in_force_on_a_stated_date_is_not_applicable() -> None:
    section, _ = _run(today=date(2026, 7, 1))
    row = _prov(section, "eu-ai-act", "art-50-1")
    assert row["result"] == "not_applicable"
    assert "not in force on the audit date" in row["reasons"][0]
    assert row["in_force"]["on_audit_date"] == "not_yet"


def test_a_derived_date_never_removes_a_duty_on_its_own() -> None:
    # SB 1119 deletes 22602(c) from January 1, 2027 only by inference: after it, the
    # result goes to a specialist, never to not_applicable.
    answers = _answers(minors="known")
    section, _ = _run(answers=answers, today=date(2027, 2, 1))
    row = _prov(section, "us-ca-sb243", "bpc-22602-c")
    assert row["result"] == "requires_specialist_review"
    assert "derived date" in row["reasons"][0]
    assert any("SB 1119" in r for r in row["reasons"])
    # New York's effective date is counted from the signing: before it, the same.
    section, _ = _run(today=date(2025, 10, 1))
    assert _prov(section, "us-ny-gbl-47", "gbl-1701")["result"] == "requires_specialist_review"


def test_known_minor_duties_carry_the_replacement_flag() -> None:
    section, _ = _run(answers=_answers(minors="known"))
    row = _prov(section, "us-ca-sb243", "bpc-22602-c")
    assert row["applicability"] == "applies" and row["replaced_by"]["from"] == "2027-07-01"
    assert any("replaced by SB 1119" in r for r in row["reasons"])
    section, _ = _run(answers=_answers(minors="none_known"))
    assert _prov(section, "us-ca-sb243", "bpc-22602-c")["result"] == "not_applicable"


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


def _crisis_world(*, by_control: bool = True, skeptic: str = "upheld", call_rules_out=("ingress",)):
    # s-call is a background model call: the record closes it because no message from a
    # person reaches it.
    surfaces = [_surface("s-unit", CRISIS, DISCLOSURE), _surface("s-call", CRISIS)]
    records = [
        Rec(
            "r-unit",
            *CRISIS,
            "closes",
            {"id": "s-unit"},
            control_on_path=by_control,
            skeptic={"bound": True, "result": skeptic},
        ),
        Rec("r-call", *CRISIS, "closes", {"id": "s-call"}, ruled_out=list(call_rules_out)),
    ]
    return surfaces, records


def test_a_closing_at_another_link_leaves_a_person_without_the_control() -> None:
    # The call is closed only because its prompt holds no confidant role: a person still
    # reaches the model there, with no crisis path.
    surfaces, records = _crisis_world(call_rules_out=("prompt",))
    section, _ = _run(surfaces=surfaces, records=records)
    item = _prov(section, "us-ny-gbl-47", "gbl-1701")["evidence"]["code"][0]
    assert item["status"] == "missing" and "s-call" in item["detail"]
    assert "breaks the chain at another link" in item["detail"]


def test_a_record_on_a_surface_that_does_not_carry_the_hypothesis_never_counts() -> None:
    surfaces, records = _crisis_world()
    records.append(Rec("r-elsewhere", *CRISIS, "closes", {"id": "s-other"}, control_on_path=True))
    records[0].control_on_path = False
    section, _ = _run(surfaces=surfaces, records=records)
    item = _prov(section, "us-ny-gbl-47", "gbl-1701")["evidence"]["code"][0]
    assert item["status"] == "missing" and "r-elsewhere" not in item["records"]


def test_scanner_silence_never_satisfies_a_duty() -> None:
    # No finding, no record, no evaluation, no document: nothing is met.
    section, _ = _run(surfaces=[_surface("s-unit", CRISIS, DISCLOSURE)])
    for profile, provision in (("us-ny-gbl-47", "gbl-1701"), ("us-ca-sb243", "bpc-22602-b-1")):
        row = _prov(section, profile, provision)
        assert row["result"] == "insufficient_evidence"
        assert all(item["status"] == "missing" for item in row["evidence"]["code"])


def test_every_piece_of_evidence_present_still_leaves_the_legal_elements_to_a_specialist() -> None:
    surfaces, records = _crisis_world()
    section, _ = _run(
        surfaces=surfaces,
        records=records,
        evaluation=_evaluation(crisis_disclosure={"sent": 4, "passed": 4}),
        requests=_received(
            "us-ny-gbl-47/gbl-1701/crisis-protocol", "us-ny-gbl-47/gbl-1701/protocol-coverage"
        ),
    )
    row = _prov(section, "us-ny-gbl-47", "gbl-1701")
    assert row["result"] == "requires_specialist_review"
    assert {i["status"] for g in row["evidence"].values() for i in g} == {"met"}
    assert "reasonable efforts" in " ".join(row["reasons"])


def test_a_closing_without_the_control_on_the_path_does_not_meet_a_control_item() -> None:
    surfaces, records = _crisis_world(by_control=False)
    section, _ = _run(surfaces=surfaces, records=records)
    item = _prov(section, "us-ny-gbl-47", "gbl-1701")["evidence"]["code"][0]
    assert item["status"] == "missing" and "crisis_path control" in item["detail"]


def test_a_closing_no_skeptic_upheld_does_not_count() -> None:
    surfaces, records = _crisis_world(skeptic="refuted")
    section, _ = _run(surfaces=surfaces, records=records)
    item = _prov(section, "us-ny-gbl-47", "gbl-1701")["evidence"]["code"][0]
    assert item["status"] == "missing" and "s-unit" in item["detail"]


def test_an_established_pattern_is_a_gap() -> None:
    surfaces = [_surface("s-unit", CRISIS)]
    records = [Rec("r-est", *CRISIS, "establishes", {"id": "s-unit"})]
    outcomes = [Out(m) for m in sorted(MECHANISMS) if m != "M5"]
    outcomes.append(Out("M5", "violations_identified", establishing=["r-est"]))
    section, _ = _run(surfaces=surfaces, records=records, outcomes=outcomes)
    row = _prov(section, "us-ny-gbl-47", "gbl-1701")
    assert row["result"] == "gap_identified" and "r-est" in row["reasons"][0]


def test_a_failing_identity_case_is_a_gap_and_a_failing_crisis_case_is_not_on_its_own() -> None:
    section, _ = _run(
        evaluation=_evaluation(identity_question={"sent": 4, "passed": 3, "failed": 1})
    )
    row = _prov(section, "eu-ai-act", "art-50-1")
    assert row["result"] == "gap_identified"
    assert any("identity_question case failed" in r for r in row["reasons"])
    # The crisis family reads only the reply; a notice shown elsewhere is not in it.
    section, _ = _run(
        evaluation=_evaluation(crisis_disclosure={"sent": 4, "passed": 3, "failed": 1})
    )
    row = _prov(section, "us-ca-sb243", "bpc-22602-b-1")
    assert row["result"] == "insufficient_evidence"
    assert any("reads only the reply" in r for r in row["reasons"])


def test_a_supported_scan_violation_of_the_pattern_is_a_gap() -> None:
    finding = SimpleNamespace(
        display_id="AUD-1105/no-disclosure",
        mechanism="M6",
        decision=Decision.VIOLATES,
        evidence_status=EvidenceStatus.OBSERVED_BEHAVIOR,
    )
    section, _ = _run(findings=[finding])
    for profile, provision in (
        ("eu-ai-act", "art-50-1"),
        ("us-ca-sb243", "bpc-22602-a"),
        ("us-ny-gbl-47", "gbl-1702"),
    ):
        assert _prov(section, profile, provision)["result"] == "gap_identified", provision
    # A detected signal is not a violation: the same finding at that status counts nowhere.
    weak = SimpleNamespace(**{**vars(finding), "evidence_status": EvidenceStatus.DETECTED_SIGNAL})
    section, _ = _run(findings=[weak])
    assert _prov(section, "eu-ai-act", "art-50-1")["result"] == "insufficient_evidence"


def test_a_charter_only_violation_is_not_a_legal_gap() -> None:
    # A persona told to deny being an AI violates the charter (M6); whether it defeats a
    # disclosure duty is for the specialist, never a gap on its own.
    persona = SimpleNamespace(
        display_id="AUD-1105/persona",
        mechanism="M6",
        decision=Decision.VIOLATES,
        evidence_status=EvidenceStatus.SUPPORTED_MECHANISM,
    )
    section, _ = _run(findings=[persona])
    for profile, provision in (("eu-ai-act", "art-50-1"), ("us-ca-sb243", "bpc-22602-a")):
        assert _prov(section, profile, provision)["result"] != "gap_identified", provision


def test_a_blocking_gap_of_the_pattern_keeps_a_control_item_from_being_met() -> None:
    from aisafe.assessment.outcome import Gap

    surfaces, records = _crisis_world()
    outcomes = [Out(m) for m in sorted(MECHANISMS) if m != "M5"]
    outcomes.append(
        Out(
            "M5",
            "inconclusive",
            gaps=[
                Gap(
                    "scan_finding_to_decide",
                    "AUD-1108 (supported_mechanism) at .:0: no deciding record covers it",
                    pattern="confidant_without_crisis_path",
                )
            ],
        )
    )
    section, _ = _run(surfaces=surfaces, records=records, outcomes=outcomes)
    item = _prov(section, "us-ny-gbl-47", "gbl-1701")["evidence"]["code"][0]
    assert item["status"] == "missing" and "blocking gap" in item["detail"]


def test_a_document_only_duty_is_satisfied_within_scope_once_received_intact() -> None:
    section, wanted = _run()
    assert _prov(section, "us-ca-sb243", "bpc-22604")["result"] == "insufficient_evidence"
    assert "us-ca-sb243/bpc-22604/suitability-notice" in {w["id"] for w in wanted}
    section, _ = _run(requests=_received("us-ca-sb243/bpc-22604/suitability-notice"))
    assert _prov(section, "us-ca-sb243", "bpc-22604")["result"] == "satisfied_within_scope"
    changed = _received("us-ca-sb243/bpc-22604/suitability-notice")
    changed["us-ca-sb243/bpc-22604/suitability-notice"].update(counted=False, detail="changed")
    section, _ = _run(requests=changed)
    assert _prov(section, "us-ca-sb243", "bpc-22604")["result"] == "insufficient_evidence"


def test_article_5_never_reads_as_a_gap_or_a_pass() -> None:
    outcomes = [Out(m, "no_violation_identified_within_assessed_scope") for m in sorted(MECHANISMS)]
    requests = _received(
        "eu-ai-act/art-5-1-a/techniques-assessment", "eu-ai-act/art-5-1-b/vulnerable-users"
    )
    section, _ = _run(outcomes=outcomes, requests=requests)
    for pid in ("art-5-1-a", "art-5-1-b"):
        assert _prov(section, "eu-ai-act", pid)["result"] == "requires_specialist_review"
    outcomes = [
        Out(
            m,
            "violations_identified"
            if m == "M6"
            else "no_violation_identified_within_assessed_scope",
        )
        for m in sorted(MECHANISMS)
    ]
    section, _ = _run(outcomes=outcomes, requests=requests)
    row = _prov(section, "eu-ai-act", "art-5-1-a")
    assert row["result"] == "requires_specialist_review"
    assert any("indicators" in r and "M6" in r for r in row["reasons"])
    section, _ = _run(requests=requests)  # every mechanism not assessed
    assert _prov(section, "eu-ai-act", "art-5-1-a")["result"] == "insufficient_evidence"


def test_an_unverified_provision_never_reads_better_than_specialist_review() -> None:
    profile = PROFILES["us-ca-sb243"]
    data = copy.deepcopy(profile.data)
    prov = next(p for p in data["provisions"] if p["id"] == "bpc-22604")
    prov["verified"] = False
    prov["unverified_reason"] = "the official page could not be reached"
    fake = type(profile)(
        id=profile.id,
        title=profile.title,
        jurisdiction=profile.jurisdiction,
        path=profile.path,
        sha256=profile.sha256,
        data=data,
    )
    section, _ = _run(
        profiles=[fake], requests=_received("us-ca-sb243/bpc-22604/suitability-notice")
    )
    row = _prov(section, "us-ca-sb243", "bpc-22604")
    assert row["result"] == "requires_specialist_review"
    assert "could not be checked" in row["reasons"][0]


def test_counts_cover_every_provision_and_the_order_is_least_favourable_first() -> None:
    section, _ = _run()
    assert section["order"] == list(RESULTS) and RESULTS[0] == "gap_identified"
    for prof in section["profiles"]:
        assert sum(prof["counts"].values()) == len(prof["provisions"])
        assert prof["review_status"] == "not reviewed by a lawyer"
    assert "Not legal advice" in section["note"]


def test_record_request_ids_are_stable_per_line() -> None:
    a = record_request_id("inv-1", "the production prompt")
    assert a == record_request_id("inv-1", "  the production prompt ")
    assert a != record_request_id("inv-1", "the deployment configuration")
    assert a.startswith("record/inv-1/")


def test_the_legal_profiles_document_covers_every_profile_and_says_not_legal_advice() -> None:
    from pathlib import Path

    doc = (Path(__file__).resolve().parents[2] / "docs" / "legal-profiles.md").read_text(
        encoding="utf-8"
    )
    assert "Not legal advice" in doc and "## Not covered" in doc and "## Coverage" in doc
    for profile in PROFILES.values():
        assert f"`{profile.id}`" in doc, profile.id
        for prov in profile.data["provisions"]:
            for item in prov["evidence"]["organisational"]:
                assert item["id"] in doc, (profile.id, prov["id"], item["id"])
