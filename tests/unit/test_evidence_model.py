"""tests/unit/test_evidence_model.py
---------------------------------
Pins for the evidence model: enum ranks and wire strings (equal to the policy's keys),
fingerprint stability, redaction, the chain's `links_supported` and the finding's
`trace_complete` against its policy pattern, the finding's key
order and optional blocks, sorting by severity then mechanism order, the report envelope
and the inventory shape, and the UNMEASURED default.

Every secret-shaped sample below is assembled at runtime so no committed file carries a
key-shaped string.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from aisafe.evidence.model import (
    DEFAULT_REPORT,
    DISCLAIMER,
    DISCLAIMER_TEMPLATE,
    FINDING_KEYS,
    FLOW_ESTABLISHED_BY,
    FLOW_LINK_KINDS,
    INVENTORY_KEYS,
    LINK_KINDS_BY_VIEW,
    PERSON_DATA_LINK_KINDS,
    REDACT_PATTERNS,
    REMOVES,
    REPORT_KEYS,
    SCHEMA_VERSION,
    SEVERITY_ORDER,
    SUPPORTED_LINK_STATUSES,
    ArtifactRef,
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
    Hit,
    Inventory,
    MatchKind,
    Recommendation,
    Report,
    ReportRecord,
    Scope,
    Severity,
    Tier,
    Unit,
    UnknownCategory,
    UnknownItem,
    disclaimer,
    fingerprint,
    now_iso,
    redact,
    sort_findings,
    truncate_snippet,
)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def make_finding(
    rule_id: str = "AUD-1104",
    *,
    priority: int = 4,
    severity: Severity | str = Severity.HIGH,
    file: str = "prompts/system.md",
    line: int = 3,
    snippet: str = "Your goal is to maximize engagement.",
    sub: str | None = None,
    evidence: list[Evidence] | None = None,
    **extra,
) -> Finding:
    if evidence is None:
        evidence = [Evidence(role="match", file=file, line=line, snippet=snippet)]
    return Finding(
        id=rule_id,
        title=f"title for {rule_id}",
        severity=severity,
        priority=priority,
        mechanism="M4",
        policy_version="1.0.0",
        rule_version=2,
        basis=Basis.PRESENCE,
        confidence=Confidence(EvidenceKind.CODE, MatchKind.GREP),
        scope=Scope("unit", "u1", "services/agent"),
        evidence=evidence,
        references=("EU:Art.5(1)(a)",),
        recommendation=Recommendation(
            Tier.T1, "rewrite the objective", ("a", "b", "c"), ("objective",)
        ),
        known_failure_modes=("grep depth",),
        sub=sub,
        **extra,
    )


def roundtrip(obj) -> dict:
    """JSON round trip proves serialisability and preserves key order."""
    return json.loads(json.dumps(obj.to_dict()))


# ---------------------------------------------------------------------------
# constants and enums
# ---------------------------------------------------------------------------


def test_constants():
    assert SCHEMA_VERSION == "aisg/1"
    assert DEFAULT_REPORT == "audit-report.json"
    assert "not a certification" in DISCLAIMER
    assert "not an assessment of compliance with any regulation" in DISCLAIMER
    assert "UNMEASURED" in DISCLAIMER
    assert "Absence of a finding is not evidence of safety." in DISCLAIMER
    assert disclaimer("1.0.0") == DISCLAIMER_TEMPLATE.format(v="1.0.0")
    assert "(version 1.0.0)" in disclaimer("1.0.0")
    assert set(REMOVES) == {"objective", "inference", "intervention", "feedback", "record"}


def test_severity_ranks_descend_from_critical():
    ranks = [s.rank() for s in SEVERITY_ORDER]
    assert ranks == sorted(ranks, reverse=True)
    assert Severity.CRITICAL.rank() > Severity.HIGH.rank() > Severity.MEDIUM.rank()
    assert Severity.MEDIUM.rank() > Severity.LOW.rank() > Severity.INFO.rank()
    assert Severity.INFO.rank() == 0
    assert set(SEVERITY_ORDER) == set(Severity)
    assert Severity("high") is Severity.HIGH


def test_enum_values_are_the_wire_strings():
    assert {b.value for b in Basis} == {"presence", "absence"}
    assert {e.value for e in EvidenceKind} == {"code", "config", "absence", "report"}
    assert {m.value for m in MatchKind} == {"grep", "structured", "ast"}
    assert {t.value for t in Tier} == {"T1", "T2", "T3"}
    assert {c.value for c in UnknownCategory} == {"coverage", "deep", "reports", "runtime"}
    assert {s.value for s in EvidenceStatus} == {
        "detected_signal",
        "supported_mechanism",
        "observed_behavior",
        "unknown",
    }
    assert {d.value for d in Decision} == {
        "violates_policy",
        "requires_contextual_review",
        "no_violation_identified_in_scope",
        "not_assessed",
    }
    assert {c.value for c in ControlStatus} == {
        "none",
        "claimed",
        "wired",
        "exercised",
        "demonstrated",
        "unknown",
    }


def test_decision_and_evidence_and_control_ranks_order_strength():
    assert Decision.VIOLATES.rank() > Decision.REVIEW.rank() > Decision.NO_VIOLATION.rank()
    assert Decision.NO_VIOLATION.rank() > Decision.NOT_ASSESSED.rank()
    assert (
        EvidenceStatus.OBSERVED_BEHAVIOR.rank()
        > EvidenceStatus.SUPPORTED_MECHANISM.rank()
        > EvidenceStatus.DETECTED_SIGNAL.rank()
        > EvidenceStatus.UNKNOWN.rank()
    )
    assert (
        ControlStatus.DEMONSTRATED.rank()
        > ControlStatus.EXERCISED.rank()
        > ControlStatus.WIRED.rank()
        > ControlStatus.CLAIMED.rank()
        > ControlStatus.NONE.rank()
        > ControlStatus.UNKNOWN.rank()
    )


# ---------------------------------------------------------------------------
# fingerprint
# ---------------------------------------------------------------------------


def test_fingerprint_shape_and_stability():
    fp = fingerprint("AUD-1104", "prompts/x.md", "x = 1")
    assert re.fullmatch(r"[0-9a-f]{16}", fp)
    assert fp == fingerprint("AUD-1104", "prompts/x.md", "x = 1")
    base = fingerprint("AUD-1104", "svc/app.py", "result1 = run_step2(payload)")
    assert base == fingerprint("AUD-1104", "svc/app.py", "result2 = run_step3(payload)")
    assert base == fingerprint("AUD-1104", "svc/app.py", "  result1   =\trun_step2(payload)  ")


def test_fingerprint_keeps_pure_numbers_and_differs_by_rule_and_path():
    assert fingerprint("A", "f.py", "max_tokens = 4096") != fingerprint(
        "A", "f.py", "max_tokens = 2048"
    )
    snippet = "keep them talking"
    assert fingerprint("AUD-1104", "a.md", snippet) != fingerprint("AUD-1109", "a.md", snippet)
    assert fingerprint("AUD-1104", "a.md", snippet) != fingerprint("AUD-1104", "b.md", snippet)
    win = str(Path("services") / "agent" / "app.py")
    assert fingerprint("A", win, "x") == fingerprint("A", "services/agent/app.py", "x")


# ---------------------------------------------------------------------------
# redaction
# ---------------------------------------------------------------------------


def secret_samples() -> list[tuple[str, str]]:
    """(expected prefix, literal) pairs, every literal built at runtime."""
    return [
        ("sk-ant-", "sk-ant-" + "api03-" + "x" * 40),
        ("sk-", "sk-" + "proj-" + "A" * 30 + "1234"),
        ("ghp_", "ghp_" + "a" * 32 + "wxyz"),
        ("github_pat_", "github_pat_" + "c" * 22 + "_" + "d" * 36 + "ef12"),
        ("AKIA", "AKIA" + "Q" * 12 + "ABCD"),
        ("xoxb-", "xoxb-" + "1234567890-" + "abcdef" * 4),
        ("AIza", "AIza" + "Sy" + "z" * 29 + "9999"),
    ]


@pytest.mark.parametrize("prefix,literal", secret_samples())
def test_redact_prefixed_tokens(prefix: str, literal: str):
    line = f'client = Client(api_key="{literal}")'
    out = redact(line)
    assert literal not in out
    assert f"<redacted:{prefix}...{literal[-4:]}>" in out
    assert out.startswith('client = Client(api_key="') and out.endswith('")')


def test_redact_table_covers_every_listed_prefix():
    names = {name for name, _ in REDACT_PATTERNS}
    assert {"anthropic", "openai", "github_pat", "github", "aws", "slack", "google"} <= names
    for _name, pattern in REDACT_PATTERNS:
        assert pattern.groups >= 1


def test_redact_key_value_bearer_and_idempotence():
    key = "pass" + "word"
    value = "hunter2" + "hunter2"
    out = redact(f"{key} = '{value}'")
    assert value not in out and f"<redacted:...{value[-4:]}>" in out
    token = "eyJ" + "a" * 30 + "b1c2"
    out = redact("Authorization: Bearer " + token)
    assert token not in out and "Bearer <redacted:...b1c2>" in out
    once = redact('api_key = "' + "sk-ant-" + "api03-" + "y" * 40 + '"')
    assert redact(once) == once


@pytest.mark.parametrize(
    "benign",
    [
        "max_tokens=4096",
        "token_count = 12345678",
        'secret_key = os.environ["SECRET_KEY"]',
        "what is the capital of france",
        "",
    ],
)
def test_redact_leaves_benign_lines_alone(benign: str):
    assert redact(benign) == benign


def test_truncate_snippet_normalises_redacts_and_caps():
    literal = "ghp_" + "q" * 36
    out = truncate_snippet("   token =\t'" + literal + "'   " + "x" * 300)
    assert len(out) <= 160 and literal not in out and "<redacted:ghp_" in out
    assert out.endswith("...")
    assert truncate_snippet("  a   b  ") == "a b"
    straddle = "k" * 150 + " " + "sk-ant-" + "api03-" + "w" * 60
    assert "sk-ant-api03" not in truncate_snippet(straddle)


# ---------------------------------------------------------------------------
# value objects
# ---------------------------------------------------------------------------


def test_confidence_label_unmeasured_when_precision_none():
    c = Confidence(EvidenceKind.CODE, MatchKind.AST)
    assert c.precision is None and c.label == "UNMEASURED"
    assert Confidence("code", "ast", 0.5).label == "MEASURED"
    assert roundtrip(c) == {
        "evidence_kind": "code",
        "match_kind": "ast",
        "precision": None,
        "label": "UNMEASURED",
    }


def test_evidence_snippet_is_always_redacted_and_short():
    literal = "AKIA" + "Z" * 16
    e = Evidence(role="match", file="cfg\\prod.env", line=3, snippet="  KEY=" + literal + "  ")
    assert literal not in e.snippet and e.file == "cfg/prod.env"
    assert len(Evidence("r", "f", 1, "z" * 500).snippet) <= 160


def test_scope_rejects_unknown_kind():
    Scope("repo")
    Scope("function", "u1", "app.py::main")
    with pytest.raises(ValueError):
        Scope("module")


def test_hit_artifact_and_recommendation_shapes():
    h = Hit(file="a.py", line=1, col=0, snippet="x", table="person_signal", key="engagement:keep")
    assert h.unit is None and h.lang is None
    a = ArtifactRef("prompts\\x.md", "ab" * 32)
    assert a.file == "prompts/x.md" and roundtrip(a) == {
        "file": "prompts/x.md",
        "sha256": "ab" * 32,
    }
    r = Recommendation("T2", "remove it", ["a", "b"], ["objective", "inference"])
    assert r.tier is Tier.T2 and r.removes == ("objective", "inference")
    assert roundtrip(r) == {
        "tier": "T2",
        "summary": "remove it",
        "alternatives": ["a", "b"],
        "removes": ["objective", "inference"],
    }
    with pytest.raises(ValueError):
        Recommendation("T2", "x", (), ("banner",))


def test_flow_links_sort_and_links_supported_rule():
    links = [
        FlowLink("intervention", "app.py", 20, "return reply", "ast"),
        FlowLink("prompt", "app.py", 12, "prompt = f'...'", "ast"),
        FlowLink("person_data", "app.py", 10, "user_profile = ...", "ast"),
    ]
    flow = Flow(links=links)
    assert flow.kinds() == ("person_data", "prompt", "intervention")
    assert flow.links_supported is True
    weak = Flow(links=links + [FlowLink("objective", "app.py", 1, "reward = x", "co-located")])
    assert weak.links_supported is False
    assert Flow().links_supported is False
    assert roundtrip(flow) == {
        "view": "influence",
        "links": [link.to_dict() for link in flow.links],
        "links_supported": True,
    }
    # The removed property stays removed: a reader that asks for it fails loudly.
    assert not hasattr(flow, "established")
    with pytest.raises(ValueError):
        FlowLink("banner", "a", 1, "x", "ast")
    with pytest.raises(ValueError):
        FlowLink("prompt", "a", 1, "x", "guessed")
    assert FLOW_LINK_KINDS[0] == "objective" and FLOW_LINK_KINDS[-1] == "feedback"
    assert set(FLOW_ESTABLISHED_BY) == {
        "ast",
        "declared",
        "investigated",
        "co-located",
        "runtime-only",
    }
    assert SUPPORTED_LINK_STATUSES == ("ast", "declared", "investigated")


def test_completeness_is_measured_against_the_required_links():
    flow = Flow(
        links=[
            FlowLink("objective", "app.py", 2, "keep them talking", "declared"),
            FlowLink("prompt", "app.py", 2, "SYSTEM = ...", "ast"),
            FlowLink("intervention", "app.py", 9, "call", "co-located"),
        ]
    )
    assert flow.missing(("objective", "intervention")) == ("intervention",)
    assert flow.complete_for(("objective", "prompt")) is True
    assert flow.complete_for(()) is False  # nothing required is never complete
    assert flow.complete_for(("objective", "intervention")) is False


def test_runtime_only_and_investigated_links():
    with pytest.raises(ValueError):
        FlowLink("prompt", "a.py", 1, "x", "investigated")  # an investigated link names its record
    cited = FlowLink("prompt", "a.py", 1, "x", "investigated", record="inv-1")
    remote = FlowLink("intervention", "a.py", 4, "fetch(prompt_url)", "runtime-only")
    assert cited.supported and not remote.supported
    assert cited.to_dict()["record"] == "inv-1" and "record" not in remote.to_dict()
    flow = Flow(links=[cited, remote])
    assert flow.missing(("prompt", "intervention")) == ("intervention",)


def test_person_data_view_takes_only_its_own_kinds():
    assert LINK_KINDS_BY_VIEW == {
        "influence": FLOW_LINK_KINDS,
        "person-data": PERSON_DATA_LINK_KINDS,
    }
    flow = Flow(
        links=[
            FlowLink("storage", "store.py", 5, "db.save(mood)", "investigated", record="r"),
            FlowLink("collection", "app.py", 3, "text = req.json", "investigated", record="r"),
        ],
        view="person-data",
    )
    assert flow.kinds() == ("collection", "storage")
    with pytest.raises(ValueError):
        Flow(links=[FlowLink("prompt", "a.py", 1, "x", "ast")], view="person-data")
    with pytest.raises(ValueError):
        Flow(view="audit")


def test_finding_trace_follows_its_pattern():
    prompt_only = Flow(links=[FlowLink("prompt", "prompts/system.md", 3, "x", "declared")])
    finding = make_finding(flow=prompt_only)  # AUD-1104: pattern objective
    assert finding.trace_pattern.id == "objective"
    assert finding.required_links == ("objective", "intervention")
    assert finding.links_supported is True
    assert finding.missing_links == ("objective", "intervention")
    assert finding.trace_complete is False and finding.flow_established is False
    full = Flow(
        links=[
            FlowLink("objective", "app.py", 4, "maximise engagement", "declared"),
            FlowLink("intervention", "app.py", 9, "call", "ast"),
            FlowLink("feedback", "train.py", 1, "reward = engagement", "co-located"),
        ]
    )
    complete = make_finding(flow=full)
    # Complete although a link is co-located: the pattern's links are all supported.
    assert complete.trace_complete is True and complete.links_supported is False
    assert complete.flow_established is True
    # No chain: every required link is missing; a rule with no pattern draws no trace.
    assert make_finding().missing_links == ("objective", "intervention")
    assert make_finding().trace_complete is False
    review = make_finding("AUD-1107", sub="missing")
    assert review.trace_pattern is None and review.trace_complete is None
    assert review.flow_established is False and review.missing_links == ()


def test_a_chain_of_another_view_does_not_complete_a_pattern():
    influence = Flow(
        links=[
            FlowLink("person_data", "app.py", 2, "profile", "ast"),
            FlowLink("prompt", "app.py", 3, "prompt", "ast"),
            FlowLink("intervention", "app.py", 9, "call", "ast"),
        ]
    )
    store = make_finding("AUD-1101", sub="store", flow=influence)  # pattern storage, person-data
    assert store.trace_pattern.view == "person-data"
    assert store.missing_links == ("collection", "storage")
    assert store.trace_complete is False
    binding = make_finding("AUD-1101", flow=influence)
    assert binding.trace_pattern.id == "binding" and binding.trace_complete is True


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


def test_finding_defaults_and_coercion():
    f = make_finding(severity="high")
    assert f.gitignored is False and f.suppressed is False
    assert f.sub is None and f.report is None and f.baseline_status is None
    assert f.evidence_status is EvidenceStatus.DETECTED_SIGNAL
    assert f.decision is Decision.REVIEW
    assert f.control_status is None and f.flow is None and f.flow_established is False
    assert f.re_review is False
    assert f.severity is Severity.HIGH
    assert f.fingerprint == fingerprint(
        "AUD-1104", "prompts/system.md", "Your goal is to maximize engagement."
    )
    assert f.location == ("prompts/system.md", 3)


def test_finding_to_dict_key_order_and_new_fields():
    f = make_finding(
        evidence_status=EvidenceStatus.SUPPORTED_MECHANISM,
        decision=Decision.VIOLATES,
        control_status=ControlStatus.CLAIMED,
        flow=Flow(links=[FlowLink("prompt", "prompts/system.md", 3, "x", "declared")]),
        encoded_objective="maximize engagement",
        declared_purpose="a tutor",
        artifacts=(ArtifactRef("prompts/system.md", "00" * 32),),
        coverage_gaps=("grep tier only",),
        uncertainty="the line may be quoted",
    )
    d = roundtrip(f)
    assert list(d) == list(FINDING_KEYS)
    assert d["id"] == "AUD-1104" and d["rule_id"] == "AUD-1104" and d["sub"] is None
    assert d["mechanism"] == "M4" and d["policy_version"] == "1.0.0" and d["rule_version"] == 2
    assert d["evidence_status"] == "supported_mechanism" and d["decision"] == "violates_policy"
    assert d["control_status"] == "claimed"
    # One declared prompt link: every present link is supported, the trace is partial.
    assert d["flow"]["links_supported"] is True and d["links_supported"] is True
    assert d["flow"]["pattern"] == "objective" and d["pattern"] == "objective"
    assert d["flow"]["required"] == ["objective", "intervention"]
    assert d["flow"]["missing"] == d["missing_links"] == ["objective", "intervention"]
    assert d["trace_complete"] is False and d["flow"]["trace_complete"] is False
    # The deprecated aliases follow trace_complete, not the old reading.
    assert d["flow_established"] is False and d["flow"]["established"] is False
    assert d["declared_purpose"] == "a tutor" and d["encoded_objective"] == "maximize engagement"
    assert d["artifacts"] == [{"file": "prompts/system.md", "sha256": "00" * 32}]
    assert d["references"] == ["EU:Art.5(1)(a)"]
    assert d["recommendation"]["removes"] == ["objective"]
    assert d["coverage_gaps"] == ["grep tier only"] and d["uncertainty"]
    assert "bucket" not in d and "controls" not in d and "related_lint_rules" not in d
    assert "report" not in d and "baseline_status" not in d and "notes" not in d


def test_finding_optional_blocks_emitted_when_set():
    rec = ReportRecord("evaluation", "evaluation-report.json", "aisg/1", None, "mtime", 7)
    f = make_finding(
        "AUD-1108",
        report=rec.finding_report(),
        baseline_status="unchanged",
        accepted_reason="reviewed on 2026-10-01",
        acceptance_policy_version="0.9.0",
        re_review=True,
        review_decision="requires_contextual_review",
        review_justification="the owner wants a second look",
        notes="n",
    )
    d = roundtrip(f)
    tail = list(d)[len(FINDING_KEYS) :]
    assert tail == [
        "report",
        "baseline_status",
        "accepted_reason",
        "acceptance_policy_version",
        "re_review",
        "review_decision",
        "review_justification",
        "notes",
    ]
    assert d["report"]["age_days"] == 7 and d["re_review"] is True


def test_sub_finding_has_its_own_display_id_and_fingerprint():
    plain = make_finding()
    sub = make_finding(sub="vulnerable")
    assert sub.display_id == "AUD-1104/vulnerable"
    assert sub.fingerprint != plain.fingerprint
    assert roundtrip(sub)["id"] == "AUD-1104/vulnerable" and roundtrip(sub)["rule_id"] == "AUD-1104"


def test_absence_finding_without_evidence_fingerprints_on_the_scope():
    f = Finding(
        id="AUD-1106",
        title="t",
        severity=Severity.MEDIUM,
        priority=8,
        basis=Basis.ABSENCE,
        confidence=Confidence(EvidenceKind.ABSENCE, MatchKind.STRUCTURED),
        scope=Scope("unit", "u1", "."),
        recommendation=Recommendation(Tier.T2, "s", ("a", "b", "c"), ("record",)),
    )
    assert f.location == ("", 0)
    assert f.fingerprint == fingerprint("AUD-1106", ".", "")


def test_sort_findings_by_severity_then_mechanism_order_then_location():
    a = make_finding("AUD-1107", priority=8, severity=Severity.LOW, file="z.md", line=1)
    b = make_finding("AUD-1101", priority=1, severity=Severity.HIGH, file="b.py", line=9)
    c = make_finding("AUD-1104", priority=4, severity=Severity.HIGH, file="a.md", line=2)
    d = make_finding("AUD-1109", priority=5, severity=Severity.CRITICAL, file="m.md", line=1)
    ordered = sort_findings([a, b, c, d])
    assert [f.id for f in ordered] == ["AUD-1109", "AUD-1101", "AUD-1104", "AUD-1107"]


# ---------------------------------------------------------------------------
# UnknownItem, Unit, ReportRecord, Inventory, Report, AuditContext
# ---------------------------------------------------------------------------


def test_unknown_item_shape():
    item = UnknownItem(
        "coverage", "remote prompt app.py:3", "fetched at runtime", "read it", "app.py"
    )
    assert item.category is UnknownCategory.COVERAGE
    assert roundtrip(item) == {
        "category": "coverage",
        "what": "remote prompt app.py:3",
        "why": "fetched at runtime",
        "how_to_resolve": "read it",
        "file": "app.py",
    }


def test_unit_and_report_record_shapes():
    u = Unit("u1", "services\\agent", "services\\agent\\pyproject.toml", "python", True)
    assert u.root == "services/agent" and u.manifest.endswith("pyproject.toml")
    r = ReportRecord(
        "evaluation",
        "x\\evaluation-report.json",
        "aisg/1",
        "2026-10-29T00:00:00Z",
        "generated_at",
        0,
        ["crisis_disclosure"],
        "abc",
        {"by_family": {}},
    )
    d = roundtrip(r)
    assert d["file"] == "x/evaluation-report.json" and "body" not in d
    assert d["families"] == ["crisis_disclosure"]
    assert set(r.finding_report()) == {"file", "schema", "generated_at", "age_source", "age_days"}


def test_inventory_and_report_key_order():
    inv = Inventory(units=[Unit("u0", ".", None, "python", True)])
    d = roundtrip(inv)
    assert list(d) == list(INVENTORY_KEYS)
    assert d["schema"] == SCHEMA_VERSION and d["kind"] == "inventory"
    assert {"prompts", "person_signals", "memory_stores", "personas", "review_records"} <= set(d)
    assert "tools" not in d and "mcp" not in d and "secrets" not in d
    report = Report(findings=[make_finding()], inventory=inv, policy={"version": "1.0.0"})
    rd = roundtrip(report)
    assert list(rd) == list(REPORT_KEYS)
    assert rd["schema"] == SCHEMA_VERSION and rd["kind"] == "audit"
    assert rd["policy"] == {"version": "1.0.0"}
    assert "measured" not in rd and "external_tools" not in rd
    assert rd["findings"][0]["id"] == "AUD-1104"


def test_audit_context_defaults(tmp_path: Path):
    ctx = AuditContext(root=tmp_path, inventory=Inventory())
    assert ctx.pyfacts is None and ctx.checks is None and ctx.review is None
    assert ctx.evaluation == [] and ctx.flows == [] and ctx.artifacts == {}
    assert not hasattr(ctx, "external") and not hasattr(ctx, "lint")


def test_now_iso_shape():
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", now_iso())
