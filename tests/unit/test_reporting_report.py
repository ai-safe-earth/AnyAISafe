"""tests/unit/test_reporting_report.py
---
Pins for the audit renderers: schema-first JSON, the disclaimer (naming the policy
version) in every format, no compliance language and never the banned word,
`[UNMEASURED]` on every finding, `[REPORTED <age>d, <source>]` on evaluation-derived
findings, ASCII terminal output, the mandatory `below --fail-on` summary line, the
exit-code rule (new and re-review count, unchanged does not), the summary shape with the
evidence and decision counts, findings grouped by mechanism in policy order and sorted by
severity inside, the status/decision/control line, the chain line, the Mechanisms table,
rule-level blocks printed once per rule id, the quiet mode, the baseline lines with the
re-review and stale-acceptance markers, and the SARIF property bag order.

Findings are built by hand; nothing here depends on the rule registry being populated.
The `rules[]` catalogue always lists the whole registry plus the rule that ran, so a local
`AuditRule` subclass with an id outside the policy stands in for "the rule that ran".
"""

from __future__ import annotations

import json
import re
from importlib import metadata
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from aisafe.evidence.model import (
    DISCLAIMER_TEMPLATE,
    REPORT_KEYS,
    AuditContext,
    Basis,
    Confidence,
    ControlStatus,
    Decision,
    Evidence,
    EvidenceKind,
    EvidenceStatus,
    Finding,
    Flow,
    FlowLink,
    Inventory,
    MatchKind,
    Recommendation,
    Report,
    ReportRecord,
    Scope,
    Severity,
    Tier,
    Unit,
    UnknownItem,
    disclaimer,
)
from aisafe.policy import POLICY_VERSION, load_policy
from aisafe.reporting.html import TEMPLATES as HTML_TEMPLATES
from aisafe.reporting.report import (
    _T_ACCEPTED_REASON,
    _TEMPLATES,
    BANNED_PHRASES,
    DISTRIBUTION,
    EVALUATION_KINDS,
    FAIL_ON_CHOICES,
    FORMATS,
    SARIF_LEVEL,
    all_templates,
    build_report,
    catalogue,
    check_templates,
    compute_exit_code,
    render,
    summarise,
    to_terminal,
    tool_version,
)
from aisafe.review.baseline import BaselineDiff
from aisafe.rules import ALL_RULES, AuditRule, coverage_table

POLICY = load_policy()
RENDERED = ("terminal", "markdown", "html")

# The negative-phrase list, pinned independently of `report.BANNED_PHRASES`. Assembled
# from fragments so no audit file -- this test included -- carries one as a literal.
EXPECTED_BANNED = (
    " ".join(("is", "compliant")),
    " ".join(("compliance", "verified")),
    "certi" + "fied",
    " ".join(("meets", "the", "requirements")),
    " ".join(("fully", "compliant")),
    " ".join(("passes", "the", "eu")),
    " ".join(("nist", "compliant")),
)
# The one word the design bans outright, assembled for the same reason.
CLEAN_WORD = re.compile(r"\bcl" + r"ean\b", re.IGNORECASE)

# An id the policy does not place: its findings land under "Not attributed".
DUMMY_RULE_ID = "AUD-199"

REPORT_BLOCK = {
    "file": "evaluation-report.json",
    "schema": "aisg/1",
    "generated_at": "2026-10-01T00:00:00Z",
    "age_source": "generated_at",
    "age_days": 12,
}
ALTERNATIVES = ("rewrite the objective", "remove the metric", "add a review step")
FAILURE_MODES = ("scope over-approximates in monorepos", "grep tier")
REFERENCES = ("EU:Art.5(1)(a)", "GDPR:Art.22")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def make_finding(
    rule_id: str = "AUD-1104",
    *,
    severity: Severity | str = Severity.HIGH,
    evidence_status: EvidenceStatus | str = EvidenceStatus.SUPPORTED_MECHANISM,
    decision: Decision | str = Decision.VIOLATES,
    basis: Basis | str = Basis.PRESENCE,
    file: str = "prompts/system.md",
    line: int = 3,
    snippet: str = "Your goal is to maximize engagement.",
    role: str = "match",
    sub: str | None = None,
    precision: float | None = None,
    evidence_kind: EvidenceKind | str = EvidenceKind.CODE,
    match_kind: MatchKind | str = MatchKind.GREP,
    report: dict[str, Any] | None = None,
    notes: str | None = None,
    gitignored: bool = False,
    title: str | None = None,
    scope: Scope | None = None,
    flow: Flow | None = None,
    control_status: ControlStatus | None = None,
    encoded_objective: str | None = None,
    declared_purpose: str | None = None,
    person_data_use: str | None = None,
    affected_population: str | None = None,
    coverage_gaps: tuple[str, ...] = (),
    uncertainty: str | None = None,
    references: tuple[str, ...] = REFERENCES,
    alternatives: tuple[str, ...] = ALTERNATIVES,
    removes: tuple[str, ...] = ("objective",),
    known_failure_modes: tuple[str, ...] = FAILURE_MODES,
    tier: Tier = Tier.T2,
) -> Finding:
    mechanism = POLICY.mechanism_of(rule_id)
    return Finding(
        id=rule_id,
        sub=sub,
        title=title or f"title for {rule_id}",
        severity=severity,
        priority=POLICY.order_of(rule_id),
        mechanism=mechanism.id if mechanism is not None else "",
        policy_version=POLICY.version,
        rule_version=2,
        evidence_status=evidence_status,
        decision=decision,
        basis=basis,
        confidence=Confidence(evidence_kind, match_kind, precision),
        scope=scope or Scope(kind="file", unit="u1", name=file),
        evidence=[Evidence(role=role, file=file, line=line, snippet=snippet)],
        flow=flow,
        declared_purpose=declared_purpose,
        encoded_objective=encoded_objective,
        person_data_use=person_data_use,
        control_status=control_status,
        affected_population=affected_population,
        references=references,
        recommendation=Recommendation(
            tier=tier, summary=f"fix for {rule_id}", alternatives=alternatives, removes=removes
        ),
        known_failure_modes=known_failure_modes,
        coverage_gaps=coverage_gaps,
        uncertainty=uncertainty,
        report=report,
        notes=notes,
        gitignored=gitignored,
    )


def established_flow() -> Flow:
    return Flow(
        links=[
            FlowLink("objective", "prompts/system.md", 3, "maximize engagement", "declared"),
            FlowLink("prompt", "prompts/system.md", 3, "system prompt file", "ast"),
            FlowLink("intervention", "app.py", 20, "anthropic call", "ast"),
        ]
    )


def partial_flow() -> Flow:
    return Flow(
        links=[
            FlowLink("person_data", "analytics.py", 9, "segment.identify(", "co-located"),
            FlowLink("prompt", "app.py", 19, "fstring prompt assembly", "ast"),
            FlowLink("intervention", "app.py", 20, "anthropic call", "ast"),
        ]
    )


def lexical_flow() -> Flow:
    return Flow(
        links=[
            FlowLink("prompt", "bot.py", 4, "prompt = ...", "co-located"),
            FlowLink("intervention", "bot.py", 9, "openai call", "co-located"),
        ]
    )


def every_kind() -> list[Finding]:
    """One finding of every shape the renderers must handle, deliberately unsorted."""
    return [
        make_finding(
            "AUD-1104",
            snippet="Your goal is to maximize engagement caf\u00e9",
            encoded_objective="maximize engagement",
            flow=established_flow(),
        ),
        make_finding(
            "AUD-1104",
            sub="vulnerable",
            severity=Severity.CRITICAL,
            file="app.py",
            line=12,
            snippet="Many users are lonely teens; keep them talking.",
            affected_population="lonely teens",
        ),
        make_finding(
            "AUD-1101",
            severity=Severity.MEDIUM,
            evidence_status=EvidenceStatus.DETECTED_SIGNAL,
            decision=Decision.REVIEW,
            file="app.py",
            line=19,
            snippet="prompt = f'{SYSTEM_PROMPT} {user_profile}'",
            flow=partial_flow(),
            declared_purpose="a language tutor",
            person_data_use="user_profile",
            coverage_gaps=(
                "grep tier only: the flow from the profile to the model call was not established",
            ),
            uncertainty="the profile may hold task settings only",
            scope=Scope(kind="unit", unit="u1", name="."),
        ),
        make_finding(
            "AUD-1108",
            evidence_status=EvidenceStatus.OBSERVED_BEHAVIOR,
            evidence_kind=EvidenceKind.REPORT,
            match_kind=MatchKind.STRUCTURED,
            file="evaluation-report.json",
            line=0,
            snippet="crisis_disclosure: 2 of 6 scenarios failed",
            report=dict(REPORT_BLOCK),
            control_status=ControlStatus.NONE,
        ),
        make_finding(
            "AUD-1106",
            sub="claimed",
            severity=Severity.MEDIUM,
            evidence_status=EvidenceStatus.DETECTED_SIGNAL,
            decision=Decision.REVIEW,
            file="guard.py",
            line=4,
            snippet="from guardrails import Guard",
            control_status=ControlStatus.CLAIMED,
            notes="this control, at any status, does not resolve the objective reported by AUD-1104",
            removes=("record",),
        ),
        make_finding(
            "AUD-1107",
            sub="missing",
            severity=Severity.LOW,
            evidence_status=EvidenceStatus.DETECTED_SIGNAL,
            decision=Decision.REVIEW,
            basis=Basis.ABSENCE,
            evidence_kind=EvidenceKind.ABSENCE,
            match_kind=MatchKind.STRUCTURED,
            role="absence",
            file=".",
            line=0,
            snippet="no review record covers the unit",
            scope=Scope(kind="unit", unit="u1", name="."),
            removes=("record",),
        ),
        make_finding(
            "AUD-1109",
            file="prompts/local.md",
            line=2,
            snippet="tell the user you missed them whenever they come back",
            gitignored=True,
        ),
        make_finding(
            DUMMY_RULE_ID,
            severity=Severity.INFO,
            evidence_status=EvidenceStatus.DETECTED_SIGNAL,
            decision=Decision.REVIEW,
            file="notes.md",
            line=1,
            snippet="a note",
        ),
    ]


SORTED_IDS = [
    "AUD-1104/vulnerable",  # critical
    "AUD-1104",  # high, mechanism 4
    "AUD-1108",  # high, mechanism 5, file sorts before prompts/
    "AUD-1109",  # high, mechanism 5
    "AUD-1101",  # medium, mechanism 1
    "AUD-1106/claimed",  # medium, mechanism 8
    "AUD-1107/missing",  # low
    DUMMY_RULE_ID,  # info, unplaced
]


class DummyRule(AuditRule):
    id = DUMMY_RULE_ID
    title = "test double outside the policy"
    severity = Severity.INFO
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.GREP
    references = ("LLM09",)
    recommendation = Recommendation(Tier.T1, "narrow", ("a", "b", "c"), ("record",))
    tier = Tier.T1
    known_failure_modes = ("a test double",)


class PlacedRule(DummyRule):
    id = "AUD-1104"
    version = 2
    title = "placed by the policy under M4"


def make_ctx(inventory: Inventory | None = None) -> AuditContext:
    inventory = inventory or Inventory(
        target={"path": "C:\\work\\target", "git_sha": "abc123", "dirty": False},
        units=[
            Unit(id="u1", root=".", manifest="pyproject.toml", language="python", ai_surface=True)
        ],
        languages={"python": 3},
        llm_calls=[{"file": "app.py", "line": 20}],
        prompts=[{"file": "prompts/system.md"}, {"file": "app.py"}],
        person_signals=[{"file": "app.py", "kind": "profile_name"}],
        memory_stores=[{"file": "app.py", "kind": "memory"}],
    )
    options = SimpleNamespace(exclude=("tests/fixtures",))
    return AuditContext(root=Path("C:/work/target"), inventory=inventory, options=options)


def unknown_items() -> list[UnknownItem]:
    return [
        UnknownItem(
            category="coverage",
            what="remote prompt app.py:3",
            why="fetched at runtime",
            how_to_resolve="export the prompt to a file",
            file="app.py",
            rule_ids=("AUD-1104",),
        ),
        UnknownItem(
            category="deep", what="typescript deep analysis", why="not available", file="."
        ),
        UnknownItem(
            category="runtime",
            what="review record",
            why="reviewed_at is not a date",
            file="aisafe-review.yaml",
            rule_ids=("AUD-1107",),
        ),
    ]


def report_records() -> list[ReportRecord]:
    return [
        ReportRecord(
            kind="evaluation",
            file="evaluation-report.json",
            schema="aisg/1",
            generated_at="2026-10-01T00:00:00Z",
            age_source="generated_at",
            age_days=12,
            families=["crisis_disclosure"],
            config_digest="abc",
            body={
                "summary": {"sent": 6, "passed": 4, "failed": 2, "errors": 0, "note": "text"},
                "by_family": {"crisis_disclosure": {"sent": 6, "passed": 4, "failed": 2}},
            },
        ),
        ReportRecord(
            kind="probe",
            file="probe-report.json",
            schema="aisg/1",
            age_source="git",
            age_days=40,
            body={"summary": {"sent": 48, "passed": 40}},
        ),
    ]


def build(
    findings: list[Finding] | None = None,
    *,
    fail_on: str = "low",
    unknown: list[UnknownItem] | None = None,
    baseline: BaselineDiff | None = None,
    rules: list[type[AuditRule]] | None = None,
    inventory_included: bool = True,
) -> Report:
    findings = every_kind() if findings is None else findings
    unknown = unknown_items() if unknown is None else unknown
    code = compute_exit_code(findings, unknown, fail_on=fail_on)
    return build_report(
        make_ctx(),
        findings,
        unknown,
        report_records(),
        baseline,
        rules=[DummyRule] if rules is None else rules,
        fail_on=fail_on,
        exit_code=code,
        inventory_included=inventory_included,
    )


def outputs(report: Report) -> dict[str, str]:
    return {fmt: render(report, fmt) for fmt in FORMATS}


# ---------------------------------------------------------------------------
# constants and self-check
# ---------------------------------------------------------------------------


def test_banned_phrases_match_the_design_list():
    assert BANNED_PHRASES == EXPECTED_BANNED
    assert all(p == p.lower() for p in BANNED_PHRASES)


def test_templates_carry_no_banned_phrase_and_no_banned_word():
    assert check_templates() == []
    assert DISCLAIMER_TEMPLATE in _TEMPLATES
    # `all_templates()` is what `check_templates` and `--debug` scan: this module's strings
    # plus the html renderer's, so a phrase in either is caught.
    assert set(all_templates()) == set(_TEMPLATES) | set(HTML_TEMPLATES)
    for template in all_templates():
        assert not CLEAN_WORD.search(template), template
        assert template.isascii(), template
    joined = " ".join(_TEMPLATES).lower()
    for gone in ("bucket", "measured 1", "external tools", "trifecta"):
        assert gone not in joined, gone


def test_formats_levels_and_kinds():
    assert FORMATS == ("terminal", "json", "sarif", "markdown", "html")
    assert FAIL_ON_CHOICES == ("critical", "high", "medium", "low", "info", "never")
    assert EVALUATION_KINDS == ("evaluation", "probe")
    assert SARIF_LEVEL[Severity.CRITICAL] == "error"
    assert SARIF_LEVEL[Severity.HIGH] == "error"
    assert SARIF_LEVEL[Severity.MEDIUM] == "warning"
    assert SARIF_LEVEL[Severity.LOW] == "note"
    assert SARIF_LEVEL[Severity.INFO] == "note"


def test_tool_version_comes_from_package_metadata():
    try:
        expected = metadata.version(DISTRIBUTION)
    except metadata.PackageNotFoundError:
        expected = "unknown"
    assert tool_version() == expected


def test_catalogue_uses_attribute_values_and_the_policy_mechanism():
    rows = catalogue([DummyRule, PlacedRule], ran_ids={DUMMY_RULE_ID})
    assert rows == [
        {
            "id": DUMMY_RULE_ID,
            "title": "test double outside the policy",
            "version": 1,
            "mechanism": "",
            "measured_precision": None,
            "ran": True,
            "experimental": False,
        },
        {
            "id": "AUD-1104",
            "title": "placed by the policy under M4",
            "version": 2,
            "mechanism": "M4",
            "measured_precision": None,
            "ran": False,
            "experimental": False,
        },
    ]


# ---------------------------------------------------------------------------
# exit code and summary
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "fail_on", "expected"),
    [
        (Severity.MEDIUM, "high", 0),
        (Severity.HIGH, "high", 1),
        (Severity.CRITICAL, "never", 0),
        (Severity.INFO, "low", 0),
        (Severity.LOW, "low", 1),
    ],
)
def test_compute_exit_code_threshold(severity, fail_on, expected):
    finding = make_finding(severity=severity)
    assert compute_exit_code([finding], [], fail_on=fail_on) == expected


def test_compute_exit_code_fail_on_unknown_by_category():
    deep_only = [UnknownItem(category="deep", what="ts", why="python only")]
    both = deep_only + [UnknownItem(category="coverage", what="remote prompt", why="runtime")]
    assert compute_exit_code([], deep_only, fail_on="low", fail_on_unknown={"coverage"}) == 0
    assert compute_exit_code([], both, fail_on="low", fail_on_unknown={"coverage"}) == 1
    assert compute_exit_code([], both, fail_on="low", fail_on_unknown=None) == 0
    assert compute_exit_code([], both, fail_on="low", fail_on_unknown=set()) == 0


def test_compute_exit_code_excuses_unchanged_but_counts_new_and_re_review():
    finding = make_finding(severity=Severity.CRITICAL)
    finding.baseline_status = "unchanged"
    assert compute_exit_code([finding], [], fail_on="low") == 0
    finding.baseline_status = "new"
    assert compute_exit_code([finding], [], fail_on="low") == 1
    finding.baseline_status = "re-review"
    assert compute_exit_code([finding], [], fail_on="low") == 1


def test_compute_exit_code_rejects_unknown_level():
    with pytest.raises(ValueError):
        compute_exit_code([], [], fail_on="loud")


def test_summarise_shape_and_order():
    findings = every_kind()
    summary = summarise(findings, unknown_items(), report_records(), None, "high", 1)
    assert list(summary) == [
        "findings",
        "by_severity",
        "by_evidence_status",
        "by_decision",
        "below_threshold",
        "fail_on",
        "unknown_items",
        "unknown_by_category",
        "exit_code",
        "top",
        "suppressed",
        "baseline_new",
        "re_review",
        "stale_acceptances",
    ]
    assert "by_bucket" not in summary and "reported" not in summary
    assert list(summary["by_severity"]) == ["critical", "high", "medium", "low", "info"]
    assert list(summary["by_evidence_status"]) == [
        "detected_signal",
        "supported_mechanism",
        "observed_behavior",
        "unknown",
    ]
    assert list(summary["by_decision"]) == [
        "violates_policy",
        "requires_contextual_review",
        "no_violation_identified_in_scope",
        "not_assessed",
    ]
    assert list(summary["unknown_by_category"]) == ["coverage", "deep", "reports", "runtime"]
    assert summary["findings"] == 8
    assert summary["by_severity"] == {"critical": 1, "high": 3, "medium": 2, "low": 1, "info": 1}
    assert summary["by_evidence_status"] == {
        "detected_signal": 4,
        "supported_mechanism": 3,
        "observed_behavior": 1,
        "unknown": 0,
    }
    assert summary["by_decision"] == {
        "violates_policy": 4,
        "requires_contextual_review": 4,
        "no_violation_identified_in_scope": 0,
        "not_assessed": 0,
    }
    assert summary["below_threshold"] == 4  # medium, medium, low, info under fail_on high
    assert summary["fail_on"] == "high"
    assert summary["unknown_items"] == 3
    assert summary["unknown_by_category"] == {"coverage": 1, "deep": 1, "reports": 0, "runtime": 1}
    assert summary["exit_code"] == 1
    assert summary["top"] == findings[0].display_id
    assert summary["suppressed"] == 0
    assert summary["baseline_new"] is None
    assert summary["re_review"] == 0 and summary["stale_acceptances"] == 0


def test_summarise_counts_re_review_and_stale_acceptances_separately():
    findings = every_kind()
    findings[0].baseline_status = "re-review"
    findings[0].re_review = True
    findings[1].baseline_status = "unchanged"
    findings[1].accepted_reason = "reviewed with the product owner"
    findings[1].acceptance_policy_version = "0.9.0"
    findings[1].re_review = True
    summary = summarise(findings, [], [], None, "low", 1)
    assert summary["re_review"] == 1
    assert summary["stale_acceptances"] == 1


def test_summarise_with_baseline_reports_new_count():
    findings = every_kind()
    diff = BaselineDiff(new=findings[:2], gone=["deadbeef"], unchanged=findings[2:], file="b.json")
    summary = summarise(findings, [], [], diff, "low", 1)
    assert summary["baseline_new"] == 2


# ---------------------------------------------------------------------------
# build_report
# ---------------------------------------------------------------------------


def test_build_report_sorts_by_severity_then_mechanism_order_and_fills_blocks():
    report = build()
    assert [f.display_id for f in report.findings] == SORTED_IDS
    assert report.tool == {"name": "aisafe-audit", "version": tool_version()}
    assert report.target == {
        "path": "C:/work/target",
        "git_sha": "abc123",
        "dirty": False,
        "exclude": ["tests/fixtures"],
    }
    assert report.policy == POLICY.to_dict()
    assert report.policy["version"] == POLICY_VERSION
    assert report.disclaimer == disclaimer(POLICY_VERSION)
    assert f"(version {POLICY_VERSION})" in report.disclaimer
    assert report.baseline is None
    assert not hasattr(report, "measured")
    assert report.mechanisms == coverage_table(POLICY, [DummyRule], report.findings, make_ctx())
    assert [row["id"] for row in report.mechanisms] == [m.id for m in POLICY.mechanisms]


def test_build_report_catalogues_the_whole_registry_plus_the_rule_that_ran():
    report = build()
    assert report.rules == catalogue([*ALL_RULES, DummyRule], {DUMMY_RULE_ID})
    ids = [row["id"] for row in report.rules]
    assert len(ids) == len(set(ids)), "one catalogue row per rule id"
    assert set(ids) == {rule.id for rule in ALL_RULES} | {DUMMY_RULE_ID}
    assert {row["id"] for row in report.rules if row["ran"]} == {DUMMY_RULE_ID}
    for row in report.rules:
        assert set(row) == {
            "id",
            "title",
            "version",
            "mechanism",
            "measured_precision",
            "ran",
            "experimental",
        }
        assert row["measured_precision"] is None and row["experimental"] is False


def test_build_report_lists_a_registry_rule_that_ran_once():
    if not ALL_RULES:
        pytest.skip("the rule registry is empty in this checkout")
    real = ALL_RULES[0]
    report = build(rules=[real])
    assert [row["id"] for row in report.rules] == [rule.id for rule in ALL_RULES]
    assert {row["id"] for row in report.rules if row["ran"]} == {real.id}


def test_build_report_extracts_the_numeric_summary_of_evaluation_reports():
    report = build()
    evaluation, probe = report.reports
    assert evaluation["source"] == "evaluation-report.json"
    assert evaluation["kind"] == "evaluation"
    assert evaluation["age_source"] == "generated_at" and evaluation["age_days"] == 12
    assert evaluation["families"] == ["crisis_disclosure"]
    assert evaluation["config_digest"] == "abc"
    assert evaluation["summary"] == {"sent": 6, "passed": 4, "failed": 2, "errors": 0}
    assert probe["source"] == "probe-report.json" and probe["kind"] == "probe"
    assert probe["summary"] == {"sent": 48, "passed": 40}
    for entry in report.reports:
        assert "guards" not in entry and "body" not in entry


def test_build_report_tolerates_malformed_report_bodies():
    records = [
        ReportRecord(kind="evaluation", file="e.json", schema="aisg/1", body={"summary": [1, 2]}),
        ReportRecord(kind="probe", file="p.json", schema="aisg/1", body={}),
        ReportRecord(kind="evaluation", file="n.json", schema="aisg/1", body={"summary": "x"}),
    ]
    report = build_report(make_ctx(), [], [], records, None, rules=[], fail_on="low", exit_code=0)
    assert [r["summary"] for r in report.reports] == [{}, {}, {}]


def test_build_report_can_omit_inventory():
    report = build_report(
        make_ctx(), [], [], [], None, rules=[], fail_on="low", exit_code=0, inventory_included=False
    )
    assert report.inventory is None
    assert json.loads(render(report, "json"))["inventory"] == {}
    assert "(not included)" in render(report, "terminal")


def test_report_to_dict_key_order_and_no_legacy_blocks():
    doc = json.loads(render(build(), "json"))
    assert list(doc) == list(REPORT_KEYS)
    assert "measured" not in doc and "external_tools" not in json.dumps(doc)
    assert doc["policy"]["version"] == POLICY_VERSION
    assert [row["id"] for row in doc["mechanisms"]] == [m.id for m in POLICY.mechanisms]
    assert all("bucket" not in f for f in doc["findings"])


def test_own_output_skipped_is_one_line_in_every_rendered_format():
    report = build()
    report.inventory.own_output_skipped = ["audit-report.json", "out/audit.html"]
    for fmt in RENDERED:
        text = render(report, fmt)
        assert text.count("own output skipped: audit-report.json, out/audit.html") == 1, fmt
    assert json.loads(render(report, "json"))["inventory"]["own_output_skipped"] == [
        "audit-report.json",
        "out/audit.html",
    ]
    sarif = json.loads(render(report, "sarif"))
    assert set(sarif) == {"$schema", "version", "runs"}
    assert sarif["runs"][0]["properties"]["own_output_skipped"] == [
        "audit-report.json",
        "out/audit.html",
    ]
    report.inventory.own_output_skipped = []
    for fmt in RENDERED:
        assert render(report, fmt).count("own output skipped: none") == 1, fmt


def test_sarif_run_property_bag_is_the_first_key_of_the_run():
    """
    The walker decides "own output" from the head of a file. With the bag after
    `results`, a SARIF written into the tree was past the head and got scanned like any
    other file, reproducing its own findings. The root stays exactly the three keys the
    2.1.0 schema allows.
    """
    text = render(build(), "sarif")
    doc = json.loads(text)
    assert list(doc) == ["$schema", "version", "runs"]
    run = doc["runs"][0]
    assert list(run) == ["properties", "tool", "results"]
    assert list(run["properties"])[:4] == [
        "aisg_schema",
        "own_output_skipped",
        "oversize_files",
        "policy",
    ]
    assert run["properties"]["policy"] == POLICY.to_dict()
    assert text.index('"aisg_schema"') < text.index('"results"')
    report = build()
    report.inventory = None
    props = json.loads(render(report, "sarif"))["runs"][0]["properties"]
    assert props["own_output_skipped"] == [] and props["oversize_files"] is None


def test_sarif_written_into_the_tree_is_skipped_by_the_walker(tmp_path: Path):
    from aisafe.discovery.walk import walk

    text = render(build(), "sarif")
    for name in (".aisafe-audit/audit.sarif", "out/audit.json"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    skipped: list[str] = []
    records, _, unknown = walk(tmp_path, own_output_skipped=skipped)
    assert [r.relpath for r in records] == ["app.py"]
    assert sorted(skipped) == [".aisafe-audit/audit.sarif", "out/audit.json"]
    assert unknown == []


def test_oversize_count_is_one_inventory_line_in_every_rendered_format():
    report = build()
    report.inventory.target["oversize_files"] = 2
    for fmt in RENDERED:
        assert render(report, fmt).count("oversize files skipped: 2") == 1, fmt
    props = json.loads(render(report, "sarif"))["runs"][0]["properties"]
    assert props["oversize_files"] == 2
    del report.inventory.target["oversize_files"]
    for fmt in RENDERED:
        assert render(report, fmt).count("oversize files skipped: not recorded") == 1, fmt
    assert json.loads(render(report, "sarif"))["runs"][0]["properties"]["oversize_files"] is None


# ---------------------------------------------------------------------------
# renderer invariants across formats
# ---------------------------------------------------------------------------


def test_json_schema_is_first_key():
    doc = json.loads(render(build(), "json"))
    assert list(doc)[0] == "schema"
    assert doc["schema"] == "aisg/1" and doc["kind"] == "audit"
    assert doc["findings"][0]["id"] == "AUD-1104/vulnerable"
    assert doc["rules"][0]["measured_precision"] is None


def test_disclaimer_names_the_policy_version_in_every_format():
    out = outputs(build())
    expected = disclaimer(POLICY_VERSION)
    sentence = "not an assessment of compliance with any regulation"
    assert json.loads(out["json"])["disclaimer"] == expected
    assert json.loads(out["sarif"])["runs"][0]["properties"]["disclaimer"] == expected
    for fmt in RENDERED:
        assert sentence in out[fmt], fmt
        assert f"(version {POLICY_VERSION})" in out[fmt], fmt
    assert out["markdown"].splitlines()[0] == "# aisafe audit"
    assert out["markdown"].splitlines()[2].startswith("> ")


def test_no_banned_phrase_and_never_the_banned_word_in_any_format():
    for fmt, text in outputs(build()).items():
        lowered = text.lower()
        for phrase in BANNED_PHRASES:
            assert phrase not in lowered, (fmt, phrase)
        assert not CLEAN_WORD.search(text), fmt


def test_target_snippet_with_banned_word_does_not_trip_the_self_check():
    snippet = "# " + "certi" + "fied"
    report = build([make_finding(snippet=snippet)])
    for fmt in FORMATS:
        assert snippet in render(report, fmt)
    assert check_templates() == []


def test_sub_finding_renders_with_its_slash_id():
    out = outputs(build())
    for fmt in RENDERED:
        assert "AUD-1104/vulnerable" in out[fmt], fmt
    assert any(f["id"] == "AUD-1104/vulnerable" for f in json.loads(out["json"])["findings"])
    sarif = json.loads(out["sarif"])
    assert "AUD-1104/vulnerable" in {r["ruleId"] for r in sarif["runs"][0]["results"]}


def test_render_rejects_unknown_format_and_dispatches_html():
    with pytest.raises(ValueError, match="pdf"):
        render(build(), "pdf")
    page = render(build(), "html")
    assert page.splitlines()[0] == "<!-- # aisafe-audit: ignore-file -->"
    assert page.isascii()


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------


def test_sarif_shape_levels_and_properties():
    report = build()
    doc = json.loads(render(report, "sarif"))
    assert set(doc) == {"$schema", "version", "runs"}
    assert doc["version"] == "2.1.0" and doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    assert run["properties"]["aisg_schema"] == "aisg/1"
    driver = run["tool"]["driver"]
    assert driver["name"] == "aisafe-audit" and driver["version"] == tool_version()
    by_id = {r["id"]: r for r in driver["rules"]}
    assert "AUD-1104/vulnerable" in by_id  # a sub-finding gets its own rule entry
    props = by_id["AUD-1104"]["properties"]
    assert set(props) == {
        "measured_precision",
        "tier",
        "version",
        "mechanism",
        "ran",
        "experimental",
    }
    assert props["measured_precision"] is None and props["mechanism"] == "M4"
    results = {r["ruleId"]: r for r in run["results"]}
    assert results["AUD-1104/vulnerable"]["level"] == "error"
    assert results["AUD-1106/claimed"]["level"] == "warning"
    assert results["AUD-1107/missing"]["level"] == "note"
    first = run["results"][0]
    assert first["ruleId"] == "AUD-1104/vulnerable"
    assert first["message"]["text"].startswith("[UNMEASURED] ")
    assert first["partialFingerprints"] == {"aisgFingerprint/v1": report.findings[0].fingerprint}
    location = first["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "app.py" and location["region"]["startLine"] == 12
    assert set(first["properties"]) >= {
        "severity",
        "priority",
        "mechanism",
        "policy_version",
        "rule_version",
        "evidence_status",
        "decision",
        "basis",
        "confidence",
        "scope",
        "sub",
        "flow",
        "flow_established",
        "control_status",
        "references",
        "report",
        "gitignored",
        "baseline_status",
        "recommendation",
    }
    assert "bucket" not in first["properties"]
    assert first["properties"]["evidence_status"] == "supported_mechanism"
    assert first["properties"]["decision"] == "violates_policy"
    assert first["properties"]["policy_version"] == POLICY_VERSION
    assert first["properties"]["rule_version"] == 2
    assert first["properties"]["references"] == list(REFERENCES)
    assert first["properties"]["recommendation"]["removes"] == ["objective"]
    assert "accepted_reason" not in first["properties"]
    flowed = results["AUD-1104"]["properties"]
    assert flowed["flow"]["established"] is True and flowed["flow_established"] is True
    assert results["AUD-1106/claimed"]["properties"]["control_status"] == "claimed"
    assert results["AUD-1101"]["properties"]["control_status"] is None
    assert run["properties"]["summary"]["findings"] == 8
    assert [u["category"] for u in run["properties"]["unknown"]] == ["coverage", "deep", "runtime"]
    assert [row["id"] for row in run["properties"]["mechanisms"]] == [
        m.id for m in POLICY.mechanisms
    ]
    assert "external_tools" not in run["properties"]


def test_sarif_reported_and_gitignored_findings():
    doc = json.loads(render(build(), "sarif"))
    results = {r["ruleId"]: r for r in doc["runs"][0]["results"]}
    reported = results["AUD-1108"]
    assert reported["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    assert reported["properties"]["report"]["age_days"] == 12
    assert reported["properties"]["evidence_status"] == "observed_behavior"
    gitignored = [r for r in doc["runs"][0]["results"] if r["properties"]["gitignored"]]
    assert [r["ruleId"] for r in gitignored] == ["AUD-1109"]


def test_sarif_has_no_nulls_where_the_schema_wants_an_object_or_string():
    doc = json.loads(render(build(), "sarif"))
    for run in doc["runs"]:
        for rule in run["tool"]["driver"]["rules"]:
            assert isinstance(rule["shortDescription"]["text"], str)
            if "help" in rule:
                assert isinstance(rule["help"]["text"], str)
        for result in run["results"]:
            assert isinstance(result["message"]["text"], str)
            for loc in result.get("locations", []) + result.get("relatedLocations", []):
                region = loc["physicalLocation"]["region"]
                assert region["startLine"] >= 1
                assert isinstance(region["snippet"], dict)
                assert isinstance(region["snippet"]["text"], str)


# ---------------------------------------------------------------------------
# Markdown and terminal: tags, order, detail lines
# ---------------------------------------------------------------------------


def test_unmeasured_tag_appears_once_per_finding():
    report = build()
    for fmt in ("markdown", "terminal"):
        text = render(report, fmt)
        assert text.count("[UNMEASURED]") == 8, fmt
        assert "[MEASURED" not in text, fmt


def test_reported_tag_on_an_evaluation_derived_finding():
    report = build()
    for fmt in ("markdown", "terminal"):
        text = render(report, fmt)
        line = next(ln for ln in text.splitlines() if "[REPORTED 12d, generated_at]" in ln)
        assert "AUD-1108" in line, fmt
    doc = json.loads(render(report, "json"))
    (entry,) = [f for f in doc["findings"] if f["id"] == "AUD-1108"]
    assert entry["evidence_status"] == "observed_behavior"
    assert entry["confidence"]["evidence_kind"] == "report"
    assert entry["report"] == REPORT_BLOCK


def test_reported_tag_without_age():
    block = dict(REPORT_BLOCK, age_days=None, age_source="unknown")
    report = build([make_finding("AUD-1108", report=block)])
    for fmt in ("markdown", "terminal"):
        assert "[REPORTED age unknown]" in render(report, fmt), fmt


def test_markdown_order_groups_by_mechanism_and_ends_with_the_tables():
    text = render(build(), "markdown")
    order = [
        "# aisafe audit",
        "> ",
        "8 findings (",
        "severity: critical 1, high 3, medium 2, low 1, info 1",
        "evidence: detected_signal 4 | supported_mechanism 3 | observed_behavior 1 | unknown 0",
        "decisions: violates_policy 4 | requires_contextual_review 4",
        "## Findings",
        f"### M1 {POLICY.mechanism_by_id('M1').name}",
        f"### M4 {POLICY.mechanism_by_id('M4').name}",
        "### M5 ",
        "### M8 ",
        "### Not attributed",
        "## Mechanisms",
        "| id | name | rules | ran | surfaces | findings | decision |",
        "| M1 |",
        "| M8 |",
        "## UNKNOWN",
        "[coverage] remote prompt app.py:3: fetched at runtime",
        "resolve: export the prompt to a file",
        "file: app.py",
        "rules: AUD-1104",
        "## Inventory",
        "units: 1",
        "languages: 1 (python 3)",
        "llm_calls: 1",
        "prompts: 2",
        "person_signals: 1",
        "memory_stores: 1",
        "review_records: 0",
        "own output skipped: none",
        "exit code: 1",
    ]
    position = -1
    for needle in order:
        found = text.find(needle, position + 1)
        assert found > position, needle
        position = found
    assert (
        "M4 Optimisation of attention, retention or spending through psychological pressure" in text
    )
    for gone in (
        "buckets:",
        "## External tools",
        "tools:",
        "mcp servers",
        "hosts:",
        "### Pinned",
        "### P1",
    ):
        assert gone not in text, gone


def test_finding_detail_lines_in_markdown():
    text = render(build(), "markdown")
    for line in (
        "scope: file prompts/system.md",
        "scope: unit .",
        "status: supported_mechanism | decision: violates_policy",
        "status: detected_signal | decision: requires_contextual_review | control: claimed",
        "status: observed_behavior | decision: violates_policy | control: none",
        "[match] prompts/system.md:3: Your goal is to maximize engagement caf\u00e9",
        "[absence] .:0: no review record covers the unit",
        "chain: objective (declared) -> prompt (ast) -> intervention (ast) [established]",
        "chain: person data (co-located) -> prompt (ast) -> intervention (ast) "
        "[not established: a co-located link is lexical co-occurrence]",
        "purpose: declared: (none) | encoded: maximize engagement",
        "purpose: declared: a language tutor | encoded: (none)",
        "population: lonely teens",
        "fix (T2, removes objective): fix for AUD-1104",
        "fix (T2, removes record): fix for AUD-1106",
        "alternatives: rewrite the objective; remove the metric; add a review step",
        "references: EU:Art.5(1)(a), GDPR:Art.22",
        "known failure modes: scope over-approximates in monorepos; grep tier",
        "gaps: grep tier only: the flow from the profile to the model call was not established",
        "uncertainty: the profile may hold task settings only",
        "note: this control, at any status, does not resolve the objective reported by AUD-1104",
        "(gitignored)",
    ):
        assert line in text, line
    # A finding without a control assessment prints no control segment at all.
    assert "| control: -" not in text and "control: None" not in text


def test_chain_of_co_located_links_is_called_lexical_co_occurrence():
    report = build([make_finding(flow=lexical_flow())])
    for fmt in ("markdown", "terminal", "html"):
        text = render(report, fmt)
        assert (
            "chain: prompt (co-located) -> intervention (co-located) [lexical co-occurrence only]"
            in text
        )
        assert "verified" not in text.lower(), fmt
    plain = render(build([make_finding()]), "markdown")
    assert "chain:" not in plain  # no flow, no chain line


def test_review_decision_line_is_rendered_and_never_hides_the_finding():
    finding = make_finding()
    finding.review_decision = "no_violation_identified_in_scope"
    finding.review_justification = "the objective line is a quoted example"
    report = build([finding])
    for fmt in RENDERED:
        text = render(report, fmt)
        assert (
            "review decision: no_violation_identified_in_scope -- the objective line is a quoted example"
            in text
        )
        assert "AUD-1104" in text
    doc = json.loads(render(report, "json"))
    assert doc["findings"][0]["review_decision"] == "no_violation_identified_in_scope"
    assert doc["summary"]["findings"] == 1


def test_terminal_is_ascii_with_every_kind_present():
    text = render(build(), "terminal")
    assert text.isascii()
    assert "\\xe9" in text  # the non-ASCII snippet char was escaped, not dropped
    assert max(len(line) for line in text.splitlines()) <= 100
    assert "[#####]" in text and "[#....]" in text  # critical and info bars
    findings_block = text.split("\nMechanisms\n")[0]
    assert findings_block.index("AUD-1104/vulnerable") < findings_block.index("AUD-1101")
    assert "status: supported_mechanism | decision: violates_policy" in text


def test_terminal_summary_line_is_verbatim():
    text = render(build(fail_on="high"), "terminal")
    assert "8 findings (4 below --fail-on high, not counted in exit code); 3 unknown items" in text
    assert "exit code: 1" in text


def test_terminal_mechanisms_table_follows_the_findings():
    text = render(build(), "terminal")
    assert "\nMechanisms\n----------\n" in text
    m4 = POLICY.mechanism_by_id("M4")
    assert f"M4 {m4.name}" in text
    status = next(ln for ln in text.splitlines() if ln.strip().startswith("rules AUD-1104"))
    assert "| ran (none) |" in status and "| surfaces 1 |" in status
    assert "| findings 2 |" in status and "| decision not_assessed" in status


def test_terminal_quiet_prints_summary_lines_mechanisms_and_unknown_only():
    text = to_terminal(build(), quiet=True)
    assert "not an assessment of compliance with any regulation" in text
    assert "8 findings (" in text
    lines = text.splitlines()
    count_at = next(i for i, ln in enumerate(lines) if ln.startswith("8 findings ("))
    assert lines[count_at + 1] == "severity: critical 1, high 3, medium 2, low 1, info 1"
    assert lines[count_at + 2] == (
        "evidence: detected_signal 4 | supported_mechanism 3 | observed_behavior 1 | unknown 0"
    )
    assert lines[count_at + 3] == "decisions: violates_policy 4 | requires_contextual_review 4"
    assert "Mechanisms" in text and "UNKNOWN" in text and "fetched at runtime" in text
    assert "Findings" not in text and "Inventory" not in text
    assert "title for" not in text and "[UNMEASURED]" not in text
    for marker in (
        "scope:",
        "fix (",
        "alternatives",
        "references:",
        "known failure modes",
        "[match]",
    ):
        assert marker not in text, marker
    assert not any(ln.startswith("[#") for ln in lines)
    assert text.isascii()
    assert set(lines) <= set(to_terminal(build()).splitlines())


# ---------------------------------------------------------------------------
# rule-level blocks once per rule id
# ---------------------------------------------------------------------------

ALTERNATIVES_LINE = "alternatives: rewrite the objective; remove the metric; add a review step"
FAILURE_MODES_LINE = "known failure modes: scope over-approximates in monorepos; grep tier"
REFERENCES_LINE = "references: EU:Art.5(1)(a), GDPR:Art.22"
SEE_FIRST = "alternatives / references / known failure modes: see the first AUD-1104 above"


def two_of_the_same_rule() -> list[Finding]:
    return [
        make_finding("AUD-1104", line=3, snippet="maximize engagement"),
        make_finding("AUD-1104", line=4, snippet="keep the user talking"),
    ]


def test_terminal_prints_rule_blocks_once_and_references_them_after():
    text = render(build(two_of_the_same_rule()), "terminal")
    assert text.count(ALTERNATIVES_LINE) == 1
    assert text.count(FAILURE_MODES_LINE) == 1
    assert text.count(REFERENCES_LINE) == 1
    assert text.count(SEE_FIRST) == 1
    first = text.index("maximize engagement")
    second = text.index("keep the user talking")
    assert first < text.index(ALTERNATIVES_LINE) < second < text.index(SEE_FIRST)
    assert text.count("fix (T2, removes objective): fix for AUD-1104") == 2
    assert text.count("scope: file prompts/system.md") == 2
    assert text.count("[UNMEASURED]") == 2


def test_terminal_reference_appears_once_across_every_kind():
    report = build()
    distinct = len({f.id for f in report.findings})
    assert distinct == 7  # AUD-1104 twice, six other rules once
    text = render(report, "terminal")
    assert text.count(ALTERNATIVES_LINE) == distinct
    assert text.count(FAILURE_MODES_LINE) == distinct
    assert text.count("see the first ") == 1
    assert "see the first AUD-1104/vulnerable above" in text


def test_markdown_anchors_the_first_occurrence_and_links_the_rest():
    text = render(build(two_of_the_same_rule()), "markdown")
    assert text.count('<a id="aud-1104"></a>') == 1
    assert text.count("see the first [AUD-1104](#aud-1104) above") == 1
    assert text.count(ALTERNATIVES_LINE) == 1
    anchored = next(ln for ln in text.splitlines() if 'id="aud-1104"' in ln)
    assert anchored.startswith('- <a id="aud-1104"></a>**AUD-1104** ')
    single = render(build([make_finding("AUD-1104")]), "markdown")
    assert "<a id=" not in single and "see the first" not in single


def test_reference_names_the_display_id_of_the_first_finding_of_the_rule():
    findings = [
        make_finding("AUD-1104", sub="vulnerable", severity=Severity.CRITICAL, line=1),
        make_finding("AUD-1104", severity=Severity.MEDIUM, line=2, snippet="other"),
    ]
    term = render(build(findings), "terminal")
    assert "see the first AUD-1104/vulnerable above" in term
    md = render(build(findings), "markdown")
    assert '<a id="aud-1104-vulnerable"></a>**AUD-1104/vulnerable**' in md
    assert "see the first [AUD-1104/vulnerable](#aud-1104-vulnerable) above" in md


def test_a_block_that_differs_from_the_first_is_printed_in_full():
    first, second = two_of_the_same_rule()
    second.recommendation = Recommendation(Tier.T3, "different fix", ("x", "y", "z"), ("record",))
    second.known_failure_modes = ("something else",)
    for fmt in ("terminal", "markdown"):
        text = render(build([first, second]), fmt)
        assert text.count(ALTERNATIVES_LINE) == 1, fmt
        assert "alternatives: x; y; z" in text, fmt
        assert "known failure modes: something else" in text, fmt
        assert text.count(REFERENCES_LINE) == 1, fmt
        assert "references: see the first " in text, fmt
        assert "alternatives / references" not in text, fmt


def test_first_finding_of_a_rule_never_carries_a_reference():
    text = render(build([make_finding("AUD-1104")]), "terminal")
    assert "see the first" not in text
    assert ALTERNATIVES_LINE in text and FAILURE_MODES_LINE in text and REFERENCES_LINE in text


def test_reference_line_is_a_renderer_template():
    assert any("see the first" in t for t in _TEMPLATES)
    assert any('<a id="' in t for t in _TEMPLATES)


def test_zero_findings_still_prints_mechanisms_unknown_and_disclaimer():
    report = build([])
    assert report.summary["findings"] == 0 and report.summary["top"] is None
    out = outputs(report)
    line = "0 findings (0 below --fail-on low, not counted in exit code); 3 unknown items"
    assert line in out["terminal"] and line in out["markdown"]
    for fmt, text in out.items():
        assert "fetched at runtime" in text, fmt
        assert not CLEAN_WORD.search(text), fmt
    assert "## Mechanisms" in out["markdown"]
    assert out["markdown"].count("| M") == len(POLICY.mechanisms)
    assert "not_assessed" in out["markdown"]
    assert "## UNKNOWN" in out["markdown"] and "(none)" in out["markdown"]


def test_empty_unknown_list_is_explicit():
    report = build([], unknown=[])
    md = render(report, "markdown")
    assert md.split("## UNKNOWN")[1].split("## Inventory")[0].strip() == "(none)"
    term = render(report, "terminal")
    assert "UNKNOWN\n-------\n(none)" in term


def test_info_only_exits_zero_but_stays_a_finding():
    finding = make_finding(DUMMY_RULE_ID, severity=Severity.INFO, decision=Decision.REVIEW)
    assert compute_exit_code([finding], unknown_items(), fail_on="low") == 0
    report = build([finding], fail_on="low")
    assert report.summary["exit_code"] == 0
    assert report.summary["below_threshold"] == 1 and report.summary["findings"] == 1
    out = outputs(report)
    assert "1 finding (1 below --fail-on low, not counted in exit code)" in out["terminal"]
    assert json.loads(out["json"])["summary"]["below_threshold"] == 1


# ---------------------------------------------------------------------------
# baseline lines and markers
# ---------------------------------------------------------------------------

BASELINE_LINE = "baseline: 7 new, 1 unchanged, 1 no longer reported (audit-baseline.json)"
GONE = "0123456789abcdef"


def with_baseline() -> Report:
    """every_kind() diffed against a baseline: AUD-1107/missing unchanged, seven new, one gone."""
    findings = every_kind()
    diff = BaselineDiff(
        file="audit-baseline.json",
        gone=[GONE],
        no_longer_reported=[{"fingerprint": GONE}],
        kind="audit-baseline",
        policy_version=POLICY_VERSION,
        current_policy_version=POLICY_VERSION,
    )
    for finding in findings:
        finding.baseline_status = "unchanged" if finding.id == "AUD-1107" else "new"
        (diff.unchanged if finding.baseline_status == "unchanged" else diff.new).append(finding)
    return build(findings, baseline=diff)


def test_baseline_block_and_tags_render():
    report = with_baseline()
    assert list(report.baseline) == [
        "file",
        "kind",
        "new",
        "unchanged",
        "re_review",
        "stale_acceptances",
        "accepted",
        "generated_at",
        "policy_version",
        "no_longer_reported",
    ]
    assert (report.baseline["new"], report.baseline["unchanged"]) == (7, 1)
    assert report.baseline["re_review"] == 0 and report.baseline["stale_acceptances"] == 0
    assert report.baseline["policy_version"] == POLICY_VERSION
    assert report.summary["baseline_new"] == 7
    text = render(report, "terminal")
    assert BASELINE_LINE in text
    assert text.count("[baseline: new]") == 7
    assert text.count("[baseline: unchanged]") == 1
    doc = json.loads(render(report, "json"))
    assert doc["baseline"] == report.baseline
    assert {f["baseline_status"] for f in doc["findings"]} == {"new", "unchanged"}


def test_baseline_block_without_the_new_keys_still_renders():
    report = with_baseline()
    report.baseline = {"file": "audit-baseline.json", "new": 7, "unchanged": 1}
    bare = "baseline: 7 new, 1 unchanged, 0 no longer reported (audit-baseline.json)"
    for fmt in FORMATS:
        text = render(report, fmt)
        assert text
        if fmt in ("terminal", "html"):
            assert text.isascii(), fmt
    for fmt in RENDERED:
        assert bare in render(report, fmt), fmt


def test_no_renderer_calls_an_absent_fingerprint_fixed():
    report = with_baseline()
    for fmt in FORMATS:
        text = render(report, fmt).lower()
        assert ("fix" + "ed") not in text, fmt


@pytest.mark.parametrize("quiet", [False, True])
def test_baseline_line_follows_the_count_line_in_both_terminal_modes(quiet: bool):
    text = to_terminal(with_baseline(), quiet=quiet)
    lines = text.splitlines()
    count_at = next(i for i, ln in enumerate(lines) if ln.startswith("8 findings ("))
    assert lines[count_at + 1] == BASELINE_LINE
    assert lines[count_at + 2].startswith("severity: ")
    assert lines[count_at + 3].startswith("evidence: ")
    assert lines[count_at + 4].startswith("decisions: ")
    assert text.count(BASELINE_LINE) == 1
    assert text.count("[baseline: new]") == (0 if quiet else 7)


def test_baseline_line_precedes_findings_in_markdown():
    text = render(with_baseline(), "markdown")
    assert text.count(BASELINE_LINE) == 1
    assert text.index("8 findings (") < text.index(BASELINE_LINE) < text.index("## Findings")


def test_no_baseline_line_without_a_baseline():
    for quiet in (False, True):
        assert "baseline:" not in to_terminal(build(), quiet=quiet)
    assert "baseline:" not in render(build(), "markdown")


def test_accepted_reason_is_shown_on_the_finding_in_terminal_and_markdown():
    reason = "the objective line is a quoted example in the style guide"
    report = with_baseline()
    unchanged = next(f for f in report.findings if f.baseline_status == "unchanged")
    unchanged.accepted_reason = reason
    line = "accepted: " + reason
    assert _T_ACCEPTED_REASON in _TEMPLATES
    for fmt in ("terminal", "markdown"):
        text = render(report, fmt)
        assert text.count(line) == 1, fmt
        assert text.count("accepted: ") == 1, fmt
        at = text.index(line)
        block = text[text.rindex("scope: ", 0, at) : at]
        assert "fix (" in block
    assert line not in to_terminal(report, quiet=True)
    doc = json.loads(render(report, "json"))
    assert [f["accepted_reason"] for f in doc["findings"] if f.get("accepted_reason")] == [reason]
    sarif = json.loads(render(report, "sarif"))
    accepted = [r for r in sarif["runs"][0]["results"] if "accepted_reason" in r["properties"]]
    assert [r["properties"]["accepted_reason"] for r in accepted] == [reason]


def with_re_review() -> Report:
    """A suppression taken under an older policy: the finding counts again and says why."""
    findings = every_kind()
    diff = BaselineDiff(
        file="audit-baseline.json",
        kind="audit-baseline",
        gone=[GONE],
        no_longer_reported=[{"fingerprint": GONE}],
        policy_version="0.9.0",
        current_policy_version=POLICY_VERSION,
    )
    for finding in findings:
        if finding.id == "AUD-1107":
            finding.baseline_status = "re-review"
            finding.re_review = True
            diff.re_review.append(finding)
        elif finding.id == "AUD-1106":
            finding.baseline_status = "unchanged"
            finding.accepted_reason = "the import is a type stub"
            finding.acceptance_policy_version = "0.9.0"
            finding.re_review = True
            diff.unchanged.append(finding)
            diff.stale_acceptances.append(finding)
        else:
            finding.baseline_status = "new"
            diff.new.append(finding)
    return build(findings, baseline=diff)


RE_REVIEW_LINE = (
    "baseline: 6 new, 1 unchanged, 1 re-review, 1 no longer reported "
    "(audit-baseline.json, written under policy 0.9.0)"
)
STALE_LINE = (
    f"stale acceptances: 1 accepted under an older policy; re-review under {POLICY_VERSION}"
)


def test_re_review_and_stale_acceptance_markers_render():
    report = with_re_review()
    assert report.summary["re_review"] == 1 and report.summary["stale_acceptances"] == 1
    assert report.summary["baseline_new"] == 6
    assert report.baseline["re_review"] == 1 and report.baseline["stale_acceptances"] == 1
    assert report.baseline["policy_version"] == "0.9.0"
    for fmt in RENDERED:
        text = render(report, fmt)
        assert RE_REVIEW_LINE in text, fmt
        assert STALE_LINE in text, fmt
    for fmt in ("terminal", "markdown"):
        text = render(report, fmt)
        assert text.count("[baseline: re-review]") == 1, fmt
        assert (
            "re-review: the baseline lists this fingerprint without a reason and was not "
            f"written under policy {POLICY_VERSION}"
        ) in text, fmt
        assert (
            "accepted: the import is a type stub (accepted under policy 0.9.0; "
            f"re-review under {POLICY_VERSION})"
        ) in text, fmt
    doc = json.loads(render(report, "json"))
    re_reviewed = [f for f in doc["findings"] if f.get("baseline_status") == "re-review"]
    assert [f["id"] for f in re_reviewed] == ["AUD-1107/missing"] and re_reviewed[0][
        "re_review"
    ] is True
    stale = [f for f in doc["findings"] if f.get("acceptance_policy_version")]
    assert [f["id"] for f in stale] == ["AUD-1106/claimed"]
    assert stale[0]["baseline_status"] == "unchanged" and stale[0]["re_review"] is True


def test_re_review_counts_toward_the_exit_code_and_a_stale_acceptance_does_not():
    report = with_re_review()
    re_reviewed = [f for f in report.findings if f.baseline_status == "re-review"]
    stale = [f for f in report.findings if f.acceptance_policy_version]
    assert compute_exit_code(re_reviewed, [], fail_on="low") == 1
    assert compute_exit_code(stale, [], fail_on="low") == 0


@pytest.mark.parametrize("quiet", [False, True])
def test_re_review_lines_follow_the_count_line(quiet: bool):
    lines = to_terminal(with_re_review(), quiet=quiet).splitlines()
    count_at = next(i for i, ln in enumerate(lines) if ln.startswith("8 findings ("))
    assert lines[count_at + 1] == RE_REVIEW_LINE
    assert lines[count_at + 2] == STALE_LINE
    assert lines[count_at + 3].startswith("severity: ")
