"""tests/unit/test_reporting_html.py
---
Pins for the html renderer: the ignore marker on line 1, ASCII end to end whatever the
target contained, the disclaimer (with the policy version) and the UNKNOWN count before
the first figure, the mechanism map (eight boxes in two rows of four plus the
not-attributed strip) with `findings N | UNKNOWN M`, a decision and `[UNMEASURED]` on
every box at zero findings too, no severity name and no `--good` token in the figure,
UNKNOWN placement, one section per mechanism with the policy's own words, the plan table
columns with `who` always `you`, the caps, document 2 sections only with a baseline, the
"no longer reported" wording, the re-review groups, the banner when rules did not run,
byte identity, the dispatch and the templates self-check.

Findings are built by hand with a fixed `generated_at`, so nothing here depends on the
clock or on the rule registry.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from aisafe.evidence.model import (
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
from aisafe.reporting import html as html_mod
from aisafe.reporting.html import NOT_ATTRIBUTED, TEMPLATES, render_html
from aisafe.reporting.report import (
    BANNED_PHRASES,
    FORMATS,
    all_templates,
    build_report,
    check_templates,
    compute_exit_code,
    render,
)
from aisafe.review.baseline import BaselineDiff
from aisafe.rules import AuditRule

POLICY = load_policy()
MECHANISM_IDS = [m.id for m in POLICY.mechanisms]
MARKER = "<!-- # aisafe-audit: ignore-file -->"
ABSENCE = "Absence of a finding is not evidence of safety."
GENERATED_AT = "2026-09-06T12:00:00Z"
CLEAN_WORD = re.compile(r"\bcl" + r"ean\b", re.IGNORECASE)
FIXED_WORD = re.compile(r"\bfix" + r"ed\b", re.IGNORECASE)
DUMMY_RULE_ID = "AUD-9999"
PLAN_HEADERS = (
    "#",
    "id",
    "severity",
    "mechanism",
    "decision",
    "remediation (removes)",
    "tier",
    "who",
    "status",
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def make_finding(
    rule_id: str = "AUD-1104",
    *,
    severity: Severity | str = Severity.HIGH,
    file: str = "app.py",
    line: int = 12,
    snippet: str = "Your goal is to maximize engagement.",
    unit: str | None = "u1",
    sub: str | None = None,
    title: str | None = None,
    notes: str | None = None,
    baseline_status: str | None = None,
    accepted_reason: str | None = None,
    evidence_status: EvidenceStatus | str = EvidenceStatus.SUPPORTED_MECHANISM,
    decision: Decision | str = Decision.VIOLATES,
    control_status: ControlStatus | None = None,
    flow: Flow | None = None,
    removes: tuple[str, ...] = ("objective",),
    scope_kind: str = "file",
    **extra: Any,
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
        basis=Basis.PRESENCE,
        confidence=Confidence(EvidenceKind.CODE, MatchKind.GREP, None),
        scope=Scope(kind=scope_kind, unit=unit, name=file),
        evidence=[Evidence(role="match", file=file, line=line, snippet=snippet)],
        flow=flow,
        control_status=control_status,
        references=("EU:Art.5(1)(a)",),
        recommendation=Recommendation(Tier.T2, f"fix for {rule_id}", ("a", "b", "c"), removes),
        known_failure_modes=("grep tier",),
        baseline_status=baseline_status,
        accepted_reason=accepted_reason,
        notes=notes,
        **extra,
    )


class DummyRule(AuditRule):
    id = DUMMY_RULE_ID
    title = "test double"
    severity = Severity.INFO
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.GREP
    references = ("LLM09",)
    recommendation = Recommendation(Tier.T1, "narrow", ("a", "b", "c"), ("record",))
    tier = Tier.T1


def placed(rule_id: str) -> type[AuditRule]:
    """A rule double carrying a registered id, so the coverage table counts it as ran."""
    return type(f"Ran_{rule_id.replace('-', '_')}", (DummyRule,), {"id": rule_id})


def make_inventory(**overrides: Any) -> Inventory:
    fields: dict[str, Any] = dict(
        target={"path": "C:\\work\\target", "git_sha": "abc123", "dirty": False},
        units=[
            Unit(
                id="u1",
                root="services/agent",
                manifest="pyproject.toml",
                language="python",
                ai_surface=True,
            ),
            Unit(id="u2", root="web", manifest="package.json", language="typescript"),
        ],
        languages={"python": 3, "typescript": 1},
        llm_calls=[{"file": "app.py", "line": 3, "provider": "anthropic", "sdk": "anthropic"}],
        prompts=[{"file": "prompts/system.md", "line": 1, "kind": "file"}],
        person_signals=[{"file": "app.py", "line": 12, "kind": "engagement"}],
        own_output_skipped=["audit-report.json"],
    )
    fields.update(overrides)
    return Inventory(**fields)


def build(
    findings: list[Finding] | None = None,
    *,
    unknown: list[UnknownItem] | None = None,
    baseline: BaselineDiff | None = None,
    rules: list[type[AuditRule]] | None = None,
    inventory: Inventory | None = None,
    inventory_included: bool = True,
    fail_on: str = "low",
    reports: list[ReportRecord] | None = None,
) -> Report:
    findings = [make_finding()] if findings is None else findings
    unknown = [] if unknown is None else unknown
    ctx = AuditContext(root=Path("C:/work/target"), inventory=inventory or make_inventory())
    code = compute_exit_code(findings, unknown, fail_on=fail_on)
    report = build_report(
        ctx,
        findings,
        unknown,
        reports or [],
        baseline,
        rules=[DummyRule] if rules is None else rules,
        fail_on=fail_on,
        exit_code=code,
        inventory_included=inventory_included,
    )
    report.generated_at = GENERATED_AT
    return report


def svg_of(page: str) -> str:
    start, end = page.index("<svg"), page.index("</svg>")
    return page[start:end]


def before_svg(page: str) -> str:
    return page[: page.index("<svg")]


def box_lines(page: str, key: str) -> tuple[str, str]:
    """(status line, decision) under one map box, by its mechanism id."""
    svg = svg_of(page)
    idx = svg.index(f'class="svgt">{key}<')
    tail = svg[idx:]
    status = re.search(r">(findings \d+ \| UNKNOWN \d+)<", tail)
    assert status, key
    decision = re.search(r'class="svgm">([a-z_]+)</text>', tail[status.end() :])
    assert decision, key
    return status.group(1), decision.group(1)


def section_of(page: str, key: str) -> str:
    start = page.index(f'id="sec-{key}"')
    rest = page[start:]
    end = re.search(r'<h3 id="sec-|<h2 id="', rest[10:])
    return rest[: end.start() + 10] if end else rest


def plan_rows(page: str) -> list[list[str]]:
    plan = page[page.index('<h2 id="plan">') :]
    end = re.search(r'<h2 id="(?:remaining|unknown)">', plan)
    plan = plan[: end.start()]
    rows = re.findall(r"<tr>(.*?)</tr>", plan)
    return [re.findall(r"<td>(.*?)</td>", row) for row in rows[1:]]


def with_baseline(
    *,
    accepted: list[dict[str, Any]] | None = None,
    generated_at: str | None = "2026-09-01T12:00:00Z",
    no_longer_reported: list[dict[str, Any]] | None = None,
    gone: list[str] | None = None,
    new: list[Finding] | None = None,
    re_review: list[Finding] | None = None,
    stale: list[Finding] | None = None,
    kind: str | None = "audit-baseline",
    policy_version: str | None = POLICY_VERSION,
) -> BaselineDiff:
    return BaselineDiff(
        file="audit-baseline.json",
        kind=kind,
        new=list(new or []),
        gone=["0123456789abcdef"] if gone is None else gone,
        accepted=accepted or [],
        generated_at=generated_at,
        re_review=list(re_review or []),
        stale_acceptances=list(stale or []),
        policy_version=policy_version,
        current_policy_version=POLICY_VERSION,
        no_longer_reported=(
            [
                {
                    "fingerprint": "0123456789abcdef",
                    "rule": "AUD-1104",
                    "file": "old.py:1",
                    "title": "old title",
                }
            ]
            if no_longer_reported is None
            else no_longer_reported
        ),
    )


# ---------------------------------------------------------------------------
# document shape
# ---------------------------------------------------------------------------


def test_line_one_is_the_ignore_marker_then_a_standalone_document():
    page = render_html(build())
    lines = page.splitlines()
    assert lines[0] == MARKER
    assert lines[1] == "<!doctype html>"
    assert '<html lang="en">' in page
    assert '<meta charset="utf-8">' in page
    assert '<meta name="aisg-schema" content="aisg/1">' in page
    assert re.search(r'<meta name="aisg-tool" content="aisafe [^"]+">', page)
    assert "<title>" in page and "<style>" in page
    assert "<script" not in page
    assert 'src="' not in page and 'href="http' not in page and "@import" not in page
    assert page.endswith("</html>\n")


def test_ascii_end_to_end_with_a_hostile_reason_and_snippet():
    reason = 'because <script>alert(1)</script> & caf\u00e9 "quoted" \u2192'
    finding = make_finding(snippet="keep them talking caf\u00e9 <b>", accepted_reason=reason)
    page = render_html(build([finding], baseline=with_baseline()))
    assert page.isascii()
    assert "<script>" not in page
    assert "&lt;script&gt;" in page
    assert "&amp; caf&#xe9;" in page
    assert "&#x2192;" in page
    # A text node needs no quote entity; the reason reads as the operator typed it.
    assert '"quoted"' in page and "&quot;" not in page
    assert "keep them talking caf&#xe9; &lt;b&gt;" in page


def test_read_this_first_precedes_the_figure():
    unknown = [UnknownItem(category="deep", what="typescript deep analysis", why="not available")]
    page = render_html(build(unknown=unknown))
    head = before_svg(page)
    assert disclaimer(POLICY_VERSION) in head
    assert ABSENCE in head
    assert "UNKNOWN: 1 item the audit could not establish" in head
    section = re.search(r"listed in section (\d+)", head).group(1)
    assert f'<h2 id="unknown">{section}. UNKNOWN</h2>' in page
    assert "severity: critical 0, high 1, medium 0, low 0, info 0" in head
    assert (
        "evidence: detected_signal 0 | supported_mechanism 1 | observed_behavior 0 | unknown 0"
        in head
    )
    assert "decisions: violates_policy 1 | requires_contextual_review 0" in head
    assert ABSENCE in page[page.index("<footer>") :]


def test_first_survey_header_and_resolved_options():
    page = render_html(build(fail_on="high"))
    assert "Document 1 of 2" in page
    assert "Compared against: none -- this is the first survey" in page
    assert (
        "commit abc123 -- uncommitted changes: no -- generated 2026-09-06T12:00:00Z -- aisafe "
    ) in page
    assert f"-- policy version {POLICY_VERSION}" in page
    assert "fail-on: high" in page
    assert "Since the baseline" not in page
    assert "Remaining actions" not in page
    assert "Prompt and algorithm audit: C:/work/target" in page


# ---------------------------------------------------------------------------
# the mechanism map
# ---------------------------------------------------------------------------


def test_every_box_is_drawn_with_its_numbers_decision_and_unmeasured():
    page = render_html(build([]))
    svg = svg_of(page)
    assert svg.count("<rect ") == len(MECHANISM_IDS) + 1
    assert svg.count("[UNMEASURED]") == len(MECHANISM_IDS) + 1
    assert "mechanisms M1 to M4" in svg and "mechanisms M5 to M8" in svg
    for key in MECHANISM_IDS:
        status, decision = box_lines(page, key)
        assert status == "findings 0 | UNKNOWN 0", key
        assert decision == "not_assessed", key
    assert "Not attributed / UNKNOWN" in svg
    assert "UNKNOWN not attributed to a mechanism: 0 | findings 0 [UNMEASURED]" in svg
    assert 'stroke-dasharray="7 5"' in svg
    assert svg.count("var(--warn)") == 1
    assert "Fig. 1: mechanism map of C:/work/target" in svg
    assert f"the mechanisms of the policy (version {POLICY_VERSION})" in page


def test_no_severity_name_and_no_good_token_anywhere():
    findings = [
        make_finding("AUD-1104", severity=Severity.CRITICAL),
        make_finding("AUD-1109", severity=Severity.HIGH, file="prompts/p.md"),
        make_finding("AUD-1107", severity=Severity.INFO, file=".", decision=Decision.REVIEW),
    ]
    page = render_html(build(findings))
    svg = svg_of(page).lower()
    for name in ("critical", "high", "medium", "low", "info"):
        assert not re.search(rf"\b{name}\b", svg), name
    assert "--good" not in page
    style = page[page.index("<style>") : page.index("</style>")]
    assert "%" not in style


def test_unknown_items_land_on_the_rule_mechanism_or_the_not_attributed_box():
    unknown = [
        UnknownItem(category="coverage", what="remote prompt", why="x", rule_ids=("AUD-1104",)),
        UnknownItem(category="deep", what="typescript deep analysis", why="not available"),
        UnknownItem(category="runtime", what="nothing ran", why="y"),
    ]
    page = render_html(build([], unknown=unknown))
    assert box_lines(page, "M4")[0] == "findings 0 | UNKNOWN 1"
    assert "UNKNOWN not attributed to a mechanism: 2 |" in svg_of(page)
    assert "UNKNOWN: 3 items the audit could not establish" in page
    tail = page[page.index('<h2 id="unknown">') :]
    assert "[coverage] remote prompt: x" in tail
    assert "[runtime] nothing ran: y" in tail
    m4 = section_of(page, "M4")
    assert "UNKNOWN items counted on this box: 1; see section" in m4


def test_findings_are_placed_by_mechanism_and_the_box_decides():
    findings = [
        make_finding("AUD-1104"),
        make_finding("AUD-1104", line=13, snippet="keep the user talking"),
        make_finding("AUD-1101", severity=Severity.MEDIUM, decision=Decision.REVIEW),
    ]
    page = render_html(build(findings, rules=[placed("AUD-1104"), placed("AUD-1101")]))
    assert box_lines(page, "M4") == ("findings 2 | UNKNOWN 0", "violates_policy")
    assert box_lines(page, "M1") == ("findings 1 | UNKNOWN 0", "requires_contextual_review")
    assert box_lines(page, "M2") == ("findings 0 | UNKNOWN 0", "not_assessed")


def test_a_box_whose_rules_did_not_run_says_not_assessed_even_with_findings():
    # The coverage row trusts what ran: a finding placed on a mechanism none of whose
    # rules ran (a hand-built report) is counted, and the decision stays not_assessed.
    page = render_html(build([make_finding("AUD-1104")], rules=[DummyRule]))
    assert box_lines(page, "M4") == ("findings 1 | UNKNOWN 0", "not_assessed")


def test_a_finding_of_an_unplaced_rule_goes_to_the_not_attributed_section():
    page = render_html(build([make_finding(DUMMY_RULE_ID, severity=Severity.INFO)]))
    assert "UNKNOWN not attributed to a mechanism: 0 | findings 1 [UNMEASURED]" in svg_of(page)
    assert f'id="sec-{NOT_ATTRIBUTED}"' in page
    assert NOT_ATTRIBUTED == "not_attributed"
    section = section_of(page, NOT_ATTRIBUTED)
    assert "findings 1 | UNKNOWN 0" in section and f"{DUMMY_RULE_ID} title for" in section


def test_rules_ran_reflects_the_catalogue_and_the_coverage_rows():
    class Ran(DummyRule):
        id = "AUD-1104"

    report = build([], rules=[Ran])
    page = render_html(report)
    ran, total = re.search(r"(\d+) of (\d+) rules ran", page).groups()
    assert int(ran) == sum(1 for row in report.rules if row["ran"]) >= 1
    assert int(total) == len(report.rules)
    m4 = POLICY.mechanism_by_id("M4")
    assert f"rules ran 1/{len(m4.rules)}" in section_of(page, "M4")
    assert box_lines(page, "M4")[1] == "no_violation_identified_in_scope"
    for key in MECHANISM_IDS:
        if key != "M4":
            assert "rules ran 0/" in section_of(page, key), key


def test_byte_identical_on_two_renders():
    report = build()
    assert render_html(report) == render_html(report)
    assert render_html(report) == render_html(build())


# ---------------------------------------------------------------------------
# sections and the finding block
# ---------------------------------------------------------------------------


def test_mechanism_sections_carry_the_policy_words():
    page = render_html(build([make_finding()], rules=[placed("AUD-1104")]))
    m4 = POLICY.mechanism_by_id("M4")
    section = section_of(page, "M4")
    assert f"M4 {m4.name}" in section
    assert (
        "findings 1 | UNKNOWN 0 | decision violates_policy | rules ran 1/1 [UNMEASURED]" in section
    )
    assert f"Prohibited: {m4.prohibited[:40]}" in section
    assert f"Distinct from: {m4.distinct_from[:40]}" in section
    assert f"Rules: {', '.join(m4.rules)}" in section
    assert "Findings placed here" in section
    empty = section_of(page, "M2")
    assert "<p>(none)</p>" in empty and "[UNMEASURED]" in empty
    assert "decision not_assessed | rules ran 0/1" in empty


def test_findings_cap_at_twelve_per_section_and_the_plan_lists_all():
    findings = [make_finding("AUD-1104", line=i, snippet=f"keep talking {i}") for i in range(15)]
    page = render_html(build(findings))
    section = section_of(page, "M4")
    assert section.count('<article class="finding"') == html_mod.MAX_FINDINGS_PER_SECTION
    assert "+3 more in the JSON" in section
    assert len(plan_rows(page)) == 15


def test_finding_block_head_status_chain_and_fix():
    flow = Flow(
        links=[
            FlowLink("objective", "app.py", 12, "maximize engagement", "declared"),
            FlowLink("prompt", "app.py", 12, "fstring", "ast"),
            FlowLink("intervention", "app.py", 20, "anthropic call", "ast"),
        ]
    )
    finding = make_finding(
        flow=flow,
        control_status=ControlStatus.CLAIMED,
        encoded_objective="maximize engagement",
        declared_purpose="a tutor",
        affected_population="lonely teens",
        coverage_gaps=("grep tier only",),
        uncertainty="the line may be quoted",
        notes="see <b>docs</b> & caf\u00e9",
    )
    page = render_html(build([finding]))
    assert "AUD-1104 title for AUD-1104 -- high [UNMEASURED]" in page
    assert "status: supported_mechanism | decision: violates_policy | control: claimed" in page
    assert "[match] app.py:12" in page
    # The arrow is a text node, so the page carries it as an entity.
    assert (
        "chain: objective (declared) -&gt; prompt (ast) -&gt; intervention (ast) [established]"
        in page
    )
    assert "purpose: declared: a tutor | encoded: maximize engagement" in page
    assert "population: lonely teens" in page
    assert "fix (T2, removes objective): fix for AUD-1104" in page
    assert "references: EU:Art.5(1)(a)" in page
    assert "gaps: grep tier only" in page and "uncertainty: the line may be quoted" in page
    assert "note: see &lt;b&gt;docs&lt;/b&gt; &amp; caf&#xe9;" in page
    assert page.isascii()
    # The alternatives and the known failure modes stay in the JSON and the terminal; the
    # policy's own words elsewhere on the page may spell "alternatives", so read the block.
    article = page[page.index('<article class="finding"') : page.index("</article>")]
    assert "alternatives" not in article and "known failure modes" not in article
    assert "ASSERTED" not in page and "bucket" not in page.lower()


def test_review_decision_is_shown_on_the_finding():
    finding = make_finding(
        review_decision="requires_contextual_review", review_justification="owner asked"
    )
    page = render_html(build([finding]))
    assert "review decision: requires_contextual_review -- owner asked" in page


def test_accepted_reason_is_rendered_verbatim_and_a_move_is_named():
    finding = make_finding("AUD-1104", accepted_reason="quoted example in the style guide")
    entry = {
        "fingerprint": finding.fingerprint,
        "rule": "AUD-1104",
        "file": "old/app.py:12",
        "reason": "quoted example in the style guide",
    }
    page = render_html(build([finding], baseline=with_baseline(accepted=[entry])))
    assert "Operator-recorded reason: quoted example in the style guide" in page
    assert "recorded at old/app.py:12, now reported at app.py:12" in page
    same = dict(entry, file="app.py:12")
    page2 = render_html(build([finding], baseline=with_baseline(accepted=[same])))
    assert "now reported at" not in page2


def test_stale_acceptance_is_marked_on_the_finding_and_in_the_plan():
    finding = make_finding(
        "AUD-1104",
        accepted_reason="reviewed under the first policy",
        acceptance_policy_version="0.9.0",
        re_review=True,
        baseline_status="unchanged",
    )
    page = render_html(
        build([finding], baseline=with_baseline(stale=[finding], policy_version="0.9.0"))
    )
    assert (
        "Operator-recorded reason: reviewed under the first policy (accepted under policy 0.9.0; "
        f"re-review under {POLICY_VERSION})"
    ) in page
    (row,) = plan_rows(page)
    assert row[8] == "accepted under an older policy; re-review"
    assert "Accepted under an older policy, re-review: 1" in page
    assert "baseline policy version 0.9.0" in page


# ---------------------------------------------------------------------------
# the plan
# ---------------------------------------------------------------------------


def test_plan_columns_who_is_always_you_and_no_package_lines():
    findings = [
        make_finding("AUD-1104"),
        make_finding(
            "AUD-1109", unit="u2", file="web/persona.md", line=2, snippet="say you missed them"
        ),
        make_finding(
            "AUD-1105", sub="persona", file=".claude/settings.json", line=3, snippet="deny"
        ),
        make_finding(
            "AUD-1106",
            sub="claimed",
            severity=Severity.MEDIUM,
            decision=Decision.REVIEW,
            control_status=ControlStatus.CLAIMED,
            removes=("record",),
            file="guard.py",
        ),
        make_finding(
            "AUD-1107",
            sub="missing",
            severity=Severity.LOW,
            decision=Decision.REVIEW,
            removes=("record",),
            file=".",
            line=0,
            accepted_reason="known",
        ),
    ]
    page = render_html(build(findings, baseline=with_baseline()))
    plan = page[page.index('<h2 id="plan">') : page.index('<h2 id="remaining">')]
    header = re.findall(r"<tr>(.*?)</tr>", plan)[0]
    assert re.findall(r"<th>(.*?)</th>", header) == list(PLAN_HEADERS)
    rows = plan_rows(page)
    assert len(rows) == 5
    assert {row[7] for row in rows} == {"you"}
    assert {row[3] for row in rows} == {"M4", "M5", "M6", "M8"}
    assert {row[4] for row in rows} == {"violates_policy", "requires_contextual_review"}
    assert "fix for AUD-1104 (removes objective)" in {row[5] for row in rows}
    assert "fix for AUD-1106 (removes record)" in {row[5] for row in rows}
    assert {row[6] for row in rows} == {"T2"}
    assert sorted(row[8] for row in rows) == ["-", "-", "-", "-", "accepted"]
    for gone in (
        "package",
        "approval needed",
        "Python-only",
        "aisafe: ",
        "subsystem",
        "control</th>",
    ):
        assert gone not in plan, gone
    assert (
        "Prefer a remediation that removes the objective, the inference or the intervention" in plan
    )


def test_an_accepted_finding_is_not_open_and_a_re_reviewed_one_is():
    accepted = make_finding(
        "AUD-1104", accepted_reason="approval is manual today", baseline_status="unchanged"
    )
    open_one = make_finding("AUD-1104", line=20, snippet="keep them talking", baseline_status="new")
    stale = make_finding(
        "AUD-1109",
        file="prompts/p.md",
        accepted_reason="first policy",
        acceptance_policy_version="0.9.0",
        re_review=True,
        baseline_status="unchanged",
    )
    assert len({accepted.fingerprint, open_one.fingerprint, stale.fingerprint}) == 3
    diff = with_baseline(new=[open_one], stale=[stale])
    page = render_html(build([accepted, open_one, stale], baseline=diff))
    statuses = sorted(row[8] for row in plan_rows(page))
    assert statuses == ["accepted", "accepted under an older policy; re-review", "new"]
    since = page[page.index('<h2 id="since">') : page.index('<h2 id="map">')]
    assert "2 open rows in the plan" in since
    tail = page[page.index('<h2 id="remaining">') : page.index('<h2 id="unknown">')]
    groups = re.findall(r"<h3>(.*?)</h3>", tail)
    assert groups == [
        "Open",
        "Re-review: the baseline entry was not taken under the current policy",
        "Accepted with a recorded reason",
        "Still UNKNOWN",
    ]
    open_group = tail[tail.index("<h3>Open</h3>") : tail.index("<h3>Re-review")]
    assert f'href="#f-{open_one.fingerprint}"' in open_group
    assert f'href="#f-{accepted.fingerprint}"' not in open_group
    re_review_group = tail[tail.index("<h3>Re-review") : tail.index("<h3>Accepted with")]
    assert f'href="#f-{stale.fingerprint}"' in re_review_group
    assert "the operator wrote: first policy" in re_review_group
    accepted_group = tail[tail.index("<h3>Accepted with") : tail.index("<h3>Still UNKNOWN")]
    assert f'href="#f-{accepted.fingerprint}"' in accepted_group
    assert "the operator wrote: approval is manual today" in accepted_group


# ---------------------------------------------------------------------------
# document 2
# ---------------------------------------------------------------------------


def test_document_two_sections_only_with_a_baseline():
    without = render_html(build())
    with_ = render_html(build(baseline=with_baseline()))
    for heading in ("Since the baseline", "Remaining actions", "What changed", "What is left"):
        assert heading not in without
        assert heading in with_
    assert "Document 2 of 2: compared against a baseline." in with_
    assert '<h2 id="since">1. Since the baseline</h2>' in with_
    assert '<h2 id="map">1. Mechanism map</h2>' in without
    assert '<h2 id="map">2. Mechanism map</h2>' in with_


def test_no_longer_reported_never_the_past_participle():
    finding = make_finding(baseline_status="new")
    page = render_html(build([finding], baseline=with_baseline(new=[finding])))
    assert "No longer reported: 1" in page
    assert "AUD-1104 old title -- old.py:1" in page
    assert "no longer reported at this fingerprint; a rename or a move also produces this" in page
    assert "New since the baseline: 1" in page
    assert "Re-review (suppressed in a baseline not written under this policy version): 0" in page
    assert "Accepted under an older policy, re-review: 0" in page
    assert "baseline: 1 new, 0 unchanged, 1 no longer reported (audit-baseline.json)" in page
    assert not FIXED_WORD.search(page)
    assert ("fix" + "ed") not in page.lower()


def test_re_review_group_in_the_since_section():
    finding = make_finding(baseline_status="re-review", re_review=True)
    page = render_html(
        build([finding], baseline=with_baseline(re_review=[finding], policy_version="0.9.0"))
    )
    assert "Re-review (suppressed in a baseline not written under this policy version): 1" in page
    assert (
        "baseline: 0 new, 0 unchanged, 1 re-review, 1 no longer reported "
        "(audit-baseline.json, written under policy 0.9.0)"
    ) in page
    assert (
        "re-review: the baseline lists this fingerprint without a reason and was not written "
        f"under policy {POLICY_VERSION}"
    ) in page


def test_no_longer_reported_without_an_index_still_counts():
    unnamed = with_baseline(no_longer_reported=[{"fingerprint": "0123456789abcdef"}])
    page = render_html(build(baseline=unnamed))
    assert "0123456789abcdef -- not in this run (the baseline did not record rule or file)" in page
    assert "No longer reported: 1" in page
    report = build()
    report.baseline = {"file": "b.json", "new": 1, "unchanged": 0, "fix" + "ed": 2}
    page = render_html(report)
    assert "No longer reported: 0" in page
    assert "baseline: 1 new, 0 unchanged, 0 no longer reported (b.json)" in page
    assert page.isascii()


def test_header_baseline_age_reasons_and_policy_version():
    page = render_html(build(baseline=with_baseline()))
    assert "Compared against: audit-baseline.json, written 5 days ago" in page
    assert "operator-recorded reasons: none" in page
    assert f"baseline policy version {POLICY_VERSION}" in page
    reasons = [{"fingerprint": "f", "rule": "AUD-1104", "file": "a.py:1", "reason": "r"}]
    page = render_html(build(baseline=with_baseline(accepted=reasons)))
    assert "operator-recorded reasons: 1" in page
    page = render_html(build(baseline=with_baseline(generated_at=None)))
    assert "Compared against: audit-baseline.json, age unknown" in page
    page = render_html(build(baseline=with_baseline(generated_at="2026-09-06T09:30:00Z")))
    assert "written 2 hours ago" in page
    page = render_html(build(baseline=with_baseline(policy_version=None)))
    assert "baseline policy version not recorded" in page


def test_header_says_when_the_baseline_was_a_report():
    page = render_html(build(baseline=with_baseline(kind="audit")))
    assert "operator-recorded reasons: none: the baseline was a report, not a baseline file" in page
    page = render_html(build(baseline=with_baseline(kind="audit-baseline")))
    assert "the baseline was a report" not in page


def test_header_lists_the_resolved_exclude():
    report = build(baseline=with_baseline())
    report.target = dict(report.target or {}, exclude=["tests/fixtures", "__pycache__"])
    page = render_html(report)
    assert "fail-on: low; exclude: tests/fixtures, __pycache__" in page
    report.target = dict(report.target, exclude=[])
    assert "exclude:" not in render_html(report)


# ---------------------------------------------------------------------------
# inventory-only, footer, dispatch, templates
# ---------------------------------------------------------------------------


def test_rules_did_not_run_shows_the_banner_and_no_plan():
    page = render_html(build([], rules=[]))
    assert "Rules did not run." in page
    assert 'id="plan"' not in page
    assert "0 of " in page and " rules ran." in page
    for key in MECHANISM_IDS:
        assert box_lines(page, key)[1] == "not_assessed"


def test_footer_carries_the_summary_exit_code_and_provenance():
    page = render_html(build(fail_on="high"))
    footer = page[page.index("<footer>") :]
    assert "1 finding (0 below --fail-on high, not counted in exit code); 0 unknown items" in footer
    assert "exit code: 1" in footer
    assert ABSENCE in footer
    assert re.search(r"generated by aisafe [^;]+; the JSON report is authoritative", footer)


def test_inventory_counts_and_evaluation_reports_read():
    record = ReportRecord(
        kind="evaluation",
        file="evaluation-report.json",
        schema="aisg/1",
        generated_at="2026-10-01T00:00:00Z",
        age_source="generated_at",
        age_days=12,
        body={"summary": {"sent": 6}},
    )
    page = render_html(build(reports=[record]))
    tail = page[page.index('id="inventory"') :]
    assert "Evaluation reports read from disk" in tail
    assert "evaluation-report.json -- evaluation [REPORTED 12d, generated_at]" in tail
    for line in (
        "units: 2",
        "languages: 2 (python 3, typescript 1)",
        "llm_calls: 1",
        "prompts: 1",
        "person_signals: 1",
        "memory_stores: 0",
        "review_records: 0",
        "own output skipped: audit-report.json",
    ):
        assert line in tail, line
    for gone in ("tools:", "mcp servers", "hosts:", "secrets:", "External tools", "trade"):
        assert gone not in page, gone
    without = render_html(build(inventory=make_inventory(own_output_skipped=[])))
    assert "own output skipped: none" in without
    assert "<p>(none)</p>" in without[without.index('id="inventory"') :]


def test_quiet_is_accepted_and_ignored():
    report = build()
    assert render_html(report, quiet=True) == render_html(report, quiet=False)


def test_render_dispatches_html_and_rejects_unknown():
    report = build()
    assert "html" in FORMATS
    assert render(report, "html") == render_html(report)
    with pytest.raises(ValueError, match="pdf"):
        render(report, "pdf")


def test_templates_carry_no_banned_phrase_and_no_banned_word():
    assert check_templates() == []
    assert MARKER in TEMPLATES
    assert ABSENCE in TEMPLATES
    for header in PLAN_HEADERS:
        assert header in TEMPLATES
    assert set(TEMPLATES) <= set(all_templates())
    for template in TEMPLATES:
        assert template.isascii(), template
        assert not CLEAN_WORD.search(template), template
        assert not FIXED_WORD.search(template), template
        for phrase in BANNED_PHRASES:
            assert phrase not in template.lower(), template


def test_page_carries_no_banned_phrase_or_word():
    page = render_html(build(baseline=with_baseline())).lower()
    for phrase in BANNED_PHRASES:
        assert phrase not in page
    assert not CLEAN_WORD.search(page)


def test_clip_and_wrap_count_wide_characters_by_cell():
    one = "\u65e5"
    assert html_mod._clip("ab" + one * 20, 10) == "ab" + one * 2 + "..."
    assert html_mod._width(html_mod._clip("ab" + one * 20, 10)) <= 10
    assert html_mod._clip("plain ascii", 30) == "plain ascii"
    name = POLICY.mechanism_by_id("M5").name
    lines = html_mod._wrap_name(name)
    assert 1 <= len(lines) <= html_mod._NAME_LINES
    assert all(html_mod._width(line) <= html_mod._NAME_WIDTH for line in lines)
    page = render_html(build([]))
    assert "".join(lines[:1])[:10] in svg_of(page)
