"""tests/unit/test_reporting_mechanisms.py
---
The coverage table (`rules.coverage_table`) and the separation of evidence status from
decision. A mechanism row says which of its rules ran, how many AI surfaces there were,
how many findings landed on it and the decision the report takes for the mechanism as a
whole: `not_assessed` when nothing ran or no surface, `no_violation_identified_in_scope`
when rules ran on a surface and found nothing, else the strongest decision among its
findings. The decision never reads the evidence status: both are printed, counted and
serialised side by side and never folded into one score.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aisafe.evidence.model import (
    AuditContext,
    Basis,
    Confidence,
    Decision,
    Evidence,
    EvidenceKind,
    EvidenceStatus,
    Finding,
    Inventory,
    MatchKind,
    Recommendation,
    Report,
    Scope,
    Severity,
    Tier,
    Unit,
)
from aisafe.policy import load_policy
from aisafe.reporting import report as report_mod
from aisafe.reporting.report import build_report, compute_exit_code, render, summarise
from aisafe.rules import AuditRule, coverage_table

POLICY = load_policy()
ROW_KEYS = ["id", "name", "rules", "ran", "surfaces", "findings", "decision"]


def make_finding(
    rule_id: str,
    *,
    evidence_status: EvidenceStatus = EvidenceStatus.DETECTED_SIGNAL,
    decision: Decision = Decision.REVIEW,
    severity: Severity = Severity.MEDIUM,
    mechanism: str | None = None,
    snippet: str = "x",
) -> Finding:
    placed = POLICY.mechanism_of(rule_id)
    return Finding(
        id=rule_id,
        title=f"title for {rule_id}",
        severity=severity,
        priority=POLICY.order_of(rule_id),
        mechanism=(placed.id if placed is not None else "") if mechanism is None else mechanism,
        policy_version=POLICY.version,
        evidence_status=evidence_status,
        decision=decision,
        basis=Basis.PRESENCE,
        confidence=Confidence(EvidenceKind.CODE, MatchKind.GREP),
        scope=Scope("file", "u1", "app.py"),
        evidence=[Evidence("match", "app.py", 1, snippet)],
        recommendation=Recommendation(Tier.T2, "fix", ("a", "b", "c"), ("objective",)),
    )


def rule_named(rule_id: str) -> type[AuditRule]:
    return type(
        f"Rule_{rule_id.replace('-', '_')}",
        (AuditRule,),
        {
            "id": rule_id,
            "title": f"rule {rule_id}",
            "severity": Severity.HIGH,
            "basis": Basis.PRESENCE,
            "evidence_kind": EvidenceKind.CODE,
            "match_kind": MatchKind.GREP,
            "recommendation": Recommendation(Tier.T2, "fix", ("a", "b", "c"), ("objective",)),
            "tier": Tier.T2,
        },
    )


def ctx_with_surfaces(n: int) -> AuditContext:
    units = [
        Unit(f"u{i}", f"svc{i}", "pyproject.toml", "python", ai_surface=i < n)
        for i in range(max(n, 1))
    ]
    return AuditContext(root=Path("target"), inventory=Inventory(units=units))


# ---------------------------------------------------------------------------
# coverage_table
# ---------------------------------------------------------------------------


def test_rows_follow_the_policy_order_and_shape():
    rows = coverage_table(POLICY, [], [], None)
    assert [row["id"] for row in rows] == [m.id for m in POLICY.mechanisms]
    assert [row["name"] for row in rows] == [m.name for m in POLICY.mechanisms]
    for row, mechanism in zip(rows, POLICY.mechanisms):
        assert list(row) == ROW_KEYS
        assert row["rules"] == list(mechanism.rules)
        assert row["ran"] == [] and row["surfaces"] == 0 and row["findings"] == 0
        assert row["decision"] == "not_assessed"


def test_no_surface_means_not_assessed_even_when_rules_ran():
    rows = coverage_table(POLICY, [rule_named("AUD-1104")], [], ctx_with_surfaces(0))
    m4 = next(row for row in rows if row["id"] == "M4")
    assert m4["ran"] == ["AUD-1104"] and m4["surfaces"] == 0
    assert m4["decision"] == "not_assessed"


def test_rules_ran_on_a_surface_and_found_nothing_is_no_violation_in_scope():
    rows = coverage_table(POLICY, [rule_named("AUD-1104")], [], ctx_with_surfaces(2))
    by_id = {row["id"]: row for row in rows}
    assert by_id["M4"]["decision"] == "no_violation_identified_in_scope"
    assert by_id["M4"]["surfaces"] == 2 and by_id["M4"]["findings"] == 0
    # Another mechanism's rules did not run: not assessed, whatever the surface count.
    assert by_id["M1"]["decision"] == "not_assessed" and by_id["M1"]["ran"] == []


def test_ran_lists_only_the_mechanisms_own_rules_sorted():
    m5 = POLICY.mechanism_by_id("M5")
    assert len(m5.rules) >= 2
    rows = coverage_table(
        POLICY, [rule_named(r) for r in reversed(m5.rules)], [], ctx_with_surfaces(1)
    )
    by_id = {row["id"]: row for row in rows}
    assert by_id["M5"]["ran"] == sorted(m5.rules)
    assert by_id["M4"]["ran"] == []


def test_decision_is_the_strongest_among_the_mechanisms_findings():
    rules = [rule_named("AUD-1104"), rule_named("AUD-1101")]
    findings = [
        make_finding("AUD-1104", decision=Decision.REVIEW),
        make_finding("AUD-1104", decision=Decision.VIOLATES, snippet="y"),
        make_finding("AUD-1101", decision=Decision.REVIEW),
    ]
    rows = coverage_table(POLICY, rules, findings, ctx_with_surfaces(1))
    by_id = {row["id"]: row for row in rows}
    assert by_id["M4"]["findings"] == 2 and by_id["M4"]["decision"] == "violates_policy"
    assert by_id["M1"]["findings"] == 1 and by_id["M1"]["decision"] == "requires_contextual_review"
    assert Decision.VIOLATES.rank() > Decision.REVIEW.rank() > Decision.NO_VIOLATION.rank()


def test_findings_are_placed_by_their_mechanism_field_not_their_id():
    # A finding carries the mechanism it was decided under; the table trusts it.
    rules = [rule_named("AUD-1104"), rule_named("AUD-1109")]
    moved = make_finding("AUD-1104", decision=Decision.VIOLATES, mechanism="M5")
    rows = coverage_table(POLICY, rules, [moved], ctx_with_surfaces(1))
    by_id = {row["id"]: row for row in rows}
    assert by_id["M5"]["findings"] == 1 and by_id["M5"]["decision"] == "violates_policy"
    assert by_id["M4"]["findings"] == 0
    assert by_id["M4"]["decision"] == "no_violation_identified_in_scope"


def test_unplaced_findings_touch_no_row():
    rows = coverage_table(
        POLICY, [], [make_finding("AUD-9999", mechanism="")], ctx_with_surfaces(1)
    )
    assert all(row["findings"] == 0 for row in rows)


# ---------------------------------------------------------------------------
# evidence status and decision stay separate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "decision"),
    [
        (EvidenceStatus.DETECTED_SIGNAL, Decision.VIOLATES),
        (EvidenceStatus.SUPPORTED_MECHANISM, Decision.REVIEW),
        (EvidenceStatus.OBSERVED_BEHAVIOR, Decision.REVIEW),
        (EvidenceStatus.UNKNOWN, Decision.NOT_ASSESSED),
    ],
)
def test_every_pairing_is_representable_and_counted_separately(status, decision):
    finding = make_finding("AUD-1104", evidence_status=status, decision=decision)
    assert finding.evidence_status is status and finding.decision is decision
    summary = summarise([finding], [], [], None, "low", 0)
    assert summary["by_evidence_status"][status.value] == 1
    assert summary["by_decision"][decision.value] == 1
    assert sum(summary["by_evidence_status"].values()) == 1
    assert sum(summary["by_decision"].values()) == 1
    assert "score" not in summary


def test_coverage_decision_never_reads_the_evidence_status():
    rules = [rule_named("AUD-1108")]
    observed = [
        make_finding(
            "AUD-1108", evidence_status=EvidenceStatus.OBSERVED_BEHAVIOR, decision=Decision.REVIEW
        ),
    ]
    detected = [
        make_finding(
            "AUD-1108", evidence_status=EvidenceStatus.DETECTED_SIGNAL, decision=Decision.VIOLATES
        ),
    ]
    strongest = [
        row
        for row in coverage_table(POLICY, rules, observed, ctx_with_surfaces(1))
        if row["id"] == "M5"
    ]
    assert strongest[0]["decision"] == "requires_contextual_review"
    weakest = [
        row
        for row in coverage_table(POLICY, rules, detected, ctx_with_surfaces(1))
        if row["id"] == "M5"
    ]
    assert weakest[0]["decision"] == "violates_policy"


def test_renderers_print_both_on_one_line_and_serialise_both():
    finding = make_finding(
        "AUD-1104", evidence_status=EvidenceStatus.DETECTED_SIGNAL, decision=Decision.VIOLATES
    )
    ctx = ctx_with_surfaces(1)
    code = compute_exit_code([finding], [], fail_on="low")
    report = build_report(
        ctx, [finding], [], [], None, rules=[rule_named("AUD-1104")], fail_on="low", exit_code=code
    )
    line = "status: detected_signal | decision: violates_policy"
    for fmt in ("terminal", "markdown", "html"):
        assert line in render(report, fmt), fmt
    doc = json.loads(render(report, "json"))
    entry = doc["findings"][0]
    assert entry["evidence_status"] == "detected_signal" and entry["decision"] == "violates_policy"
    assert list(entry).index("evidence_status") + 1 == list(entry).index("decision")
    sarif = json.loads(render(report, "sarif"))
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props["evidence_status"] == "detected_signal" and props["decision"] == "violates_policy"
    m4 = next(row for row in doc["mechanisms"] if row["id"] == "M4")
    assert m4 == {
        "id": "M4",
        "name": POLICY.mechanism_by_id("M4").name,
        "rules": list(POLICY.mechanism_by_id("M4").rules),
        "ran": ["AUD-1104"],
        "surfaces": 1,
        "findings": 1,
        "decision": "violates_policy",
    }


def test_markdown_table_and_terminal_lines_match_the_coverage_rows():
    findings = [make_finding("AUD-1101", decision=Decision.REVIEW)]
    report = build_report(
        ctx_with_surfaces(1),
        findings,
        [],
        [],
        None,
        rules=[rule_named("AUD-1101")],
        fail_on="low",
        exit_code=1,
    )
    md = render(report, "markdown")
    table = md[md.index("## Mechanisms") : md.index("## UNKNOWN")]
    body = [ln for ln in table.splitlines() if ln.startswith("| M")]
    assert len(body) == len(POLICY.mechanisms)
    m1 = POLICY.mechanism_by_id("M1")
    assert (
        f"| M1 | {m1.name} | {', '.join(m1.rules)} | AUD-1101 | 1 | 1 | requires_contextual_review |"
        in body
    )
    assert all("| not_assessed |" in ln for ln in body if not ln.startswith("| M1 "))
    term = render(report, "terminal")
    # The terminal wraps at 100 columns; the status line is longer, so compare unwrapped.
    flat = " ".join(term.split())
    assert (
        "rules AUD-1101 | ran AUD-1101 | surfaces 1 | findings 1 | decision requires_contextual_review"
        in flat
    )


def test_hand_built_report_falls_back_to_policy_rows():
    findings = [make_finding("AUD-1104", decision=Decision.VIOLATES)]
    report = Report(findings=findings, policy=POLICY.to_dict())
    rows = report_mod._mechanism_rows(report)
    assert [row["id"] for row in rows] == [m.id for m in POLICY.mechanisms]
    by_id = {row["id"]: row for row in rows}
    assert by_id["M4"]["decision"] == "violates_policy" and by_id["M4"]["findings"] == 1
    assert by_id["M4"]["ran"] == [] and by_id["M4"]["surfaces"] == 0
    assert by_id["M1"]["decision"] == "not_assessed"
    page = render(report, "html")
    assert "findings 1 | UNKNOWN 0" in page and "violates_policy" in page


def test_html_boxes_carry_the_coverage_decisions():
    findings = [make_finding("AUD-1104", decision=Decision.REVIEW)]
    report = build_report(
        ctx_with_surfaces(1),
        findings,
        [],
        [],
        None,
        rules=[rule_named("AUD-1104"), rule_named("AUD-1101")],
        fail_on="low",
        exit_code=1,
    )
    page = render(report, "html")
    svg = page[page.index("<svg") : page.index("</svg>")]
    assert svg.count("requires_contextual_review") == 1
    assert svg.count("no_violation_identified_in_scope") == 1  # M1 ran on a surface, found nothing
    assert svg.count("not_assessed") == len(POLICY.mechanisms) - 2
