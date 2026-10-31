"""tests/unit/test_assessment.py
-----------------------------
`aisafe assess`: the outcome logic on hand-built inputs (violations never lowered, blocking
gaps, closed on k of n surfaces, M8 from the review facts, the least favourable overall),
the command (exit 2 without an accepted record, the three files and their marker line,
labels and mode, inputs kept apart, baselines and review decisions never changing an
outcome), and the retest across two commits.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from investigation_helpers import copy_tree, link, make_record, surface_of, write_record

from aisafe.assessment.assess import run_assessment
from aisafe.assessment.cli import main as assess_main
from aisafe.assessment.outcome import OUTCOMES, least_favourable, mechanism_outcomes
from aisafe.assessment.render import TEMPLATES, render_html, render_markdown
from aisafe.discovery import walk
from aisafe.discovery.patterns import OWN_HTML_MARKER_LINE
from aisafe.investigation.plan import build_plan
from aisafe.investigation.scan import machine_scan
from aisafe.policy import load_policy
from aisafe.reporting.report import BANNED_PHRASES

GIT = shutil.which("git")
needs_git = pytest.mark.skipif(GIT is None, reason="git not on PATH")
POLICY = load_policy()


# ---------------------------------------------------------------------------
# Outcome logic on hand-built inputs
# ---------------------------------------------------------------------------


@dataclass
class R:
    """The fields of a validated record the outcome reads."""

    id: str
    mechanism: str
    pattern: str
    claim: str
    surface: dict[str, Any]
    complete: bool = True
    skeptic: dict[str, Any] = field(default_factory=lambda: {"bound": True, "result": "upheld"})
    runtime: list[str] = field(default_factory=list)
    covers_valid: list[str] = field(default_factory=list)
    effective: dict[str, str] = field(
        default_factory=lambda: {"evidence_status": "supported_mechanism", "decision": "x"}
    )
    path: str = "r.json"


def _surface(sid: str, priority: str = "high", hyps=(("M6", "concealment_instruction"),)) -> dict:
    return {
        "id": sid,
        "type": "prompt",
        "file": f"{sid}.md",
        "line": 1,
        "priority": priority,
        "supported": True,
        "hypotheses": [{"mechanism": m, "pattern": p, "signalled": True} for m, p in hyps],
    }


def _m(outcomes, mid: str):
    return next(o for o in outcomes if o.id == mid)


def _run(records=(), rejected=(), findings=(), surfaces=(), **kw):
    return mechanism_outcomes(
        POLICY,
        records=list(records),
        rejected=list(rejected),
        findings=list(findings),
        surfaces=list(surfaces),
        rules_ran=[r for m in POLICY.mechanisms for r in m.rules],
        **kw,
    )


def test_investigating_less_never_reads_better() -> None:
    # A high-priority surface carries M6 and nothing decides it: a gap, records or not.
    m6 = _m(_run(surfaces=[_surface("s-1")]), "M6")
    assert m6.outcome == "inconclusive"
    assert [g.kind for g in m6.gaps] == ["high_surface_not_investigated"]
    # Only normal-priority surfaces and no record: not assessed, never no violation.
    m6 = _m(_run(surfaces=[_surface("s-1", priority="normal")]), "M6")
    assert m6.outcome == "not_assessed" and "no deciding record for M6" in m6.basis[0]
    # No surface carries the mechanism at all.
    m3 = _m(_run(surfaces=[_surface("s-1")]), "M3")
    assert m3.outcome == "not_assessed" and "no surface of the plan carries M3" in m3.basis[0]


def test_a_closing_on_no_plan_surface_is_a_gap() -> None:
    records = [R("r1", "M6", "concealment_instruction", "closes", {"id": None})]
    m6 = _m(_run(records, surfaces=[_surface("s-1", priority="normal")]), "M6")
    assert m6.outcome == "inconclusive" and [g.kind for g in m6.gaps] == ["closed_off_plan"]


def test_a_closing_record_on_every_high_surface_closes_with_its_scope() -> None:
    surfaces = [_surface("s-1"), _surface("s-2"), _surface("s-3", priority="normal")]
    records = [
        R("r1", "M6", "concealment_instruction", "closes", {"id": "s-1"}),
        R("r2", "M6", "concealment_instruction", "closes", {"id": "s-2"}),
    ]
    m6 = _m(_run(records, surfaces=surfaces), "M6")
    assert m6.outcome == "no_violation_identified_within_assessed_scope"
    assert m6.closed_on == {"closed": 2, "of": 3}


def test_a_high_surface_left_uninvestigated_is_a_blocking_gap() -> None:
    surfaces = [_surface("s-1"), _surface("s-2")]
    records = [R("r1", "M6", "concealment_instruction", "closes", {"id": "s-1"})]
    m6 = _m(_run(records, surfaces=surfaces), "M6")
    assert m6.outcome == "inconclusive"
    assert [g.kind for g in m6.gaps] == ["high_surface_not_investigated"] and m6.gaps[
        0
    ].surface == "s-2"


@pytest.mark.parametrize(
    ("skeptic", "gap"),
    [
        ({"bound": True, "result": "refuted"}, "skeptic_refuted"),
        ({"bound": False, "result": "not_run"}, "skeptic_not_run"),
    ],
)
def test_a_deciding_claim_without_an_upheld_skeptic_pass_is_inconclusive(skeptic, gap) -> None:
    records = [R("r1", "M6", "concealment_instruction", "closes", {"id": "s-1"}, skeptic=skeptic)]
    m6 = _m(_run(records, surfaces=[_surface("s-1")]), "M6")
    assert m6.outcome == "inconclusive" and gap in [g.kind for g in m6.gaps]
    # An unchallenged violation is not yet established either.
    records = [
        R("r1", "M6", "concealment_instruction", "establishes", {"id": "s-1"}, skeptic=skeptic)
    ]
    assert _m(_run(records, surfaces=[_surface("s-1")]), "M6").outcome == "inconclusive"


def test_a_closing_record_never_lowers_a_violation() -> None:
    surfaces = [_surface("s-1"), _surface("s-2")]
    records = [
        R("r1", "M6", "concealment_instruction", "establishes", {"id": "s-1"}),
        R("r2", "M6", "concealment_instruction", "closes", {"id": "s-2"}),
    ]
    m6 = _m(_run(records, surfaces=surfaces), "M6")
    assert m6.outcome == "violations_identified"
    assert any("readings disagree" in b for b in m6.basis)


def test_runtime_only_evidence_and_a_review_claim_are_gaps() -> None:
    records = [
        R("r1", "M6", "concealment_instruction", "review", {"id": "s-1"}, runtime=["prompt"])
    ]
    m6 = _m(_run(records, surfaces=[_surface("s-1")]), "M6")
    assert m6.outcome == "inconclusive"
    assert {g.kind for g in m6.gaps} >= {
        "runtime_only",
        "record_at_review",
        "high_surface_not_investigated",
    }


def test_a_rejected_record_and_text_addressed_to_auditors_are_gaps() -> None:
    records = [R("r1", "M6", "concealment_instruction", "closes", {"id": "s-1", "file": "s-1.md"})]
    rejected = [R("r9", "M6", "concealment_instruction", "review", {"id": "s-1"})]
    untrusted = [{"file": "s-1.md", "line": 3, "snippet": "note to the AI auditor", "why": "x"}]
    m6 = _m(
        _run(records, rejected=rejected, surfaces=[_surface("s-1")], untrusted=untrusted),
        "M6",
    )
    assert m6.outcome == "inconclusive"
    assert {g.kind for g in m6.gaps} == {"rejected_record", "untrusted_text_near_closing"}
    # A skeptic pass that says it checked the untrusted text answers that gap; an agent
    # instruction file at the root reaches every closing record.
    checked = {"bound": True, "result": "upheld", "untrusted_text_checked": True}
    records = [
        R(
            "r1",
            "M6",
            "concealment_instruction",
            "closes",
            {"id": "s-1", "file": "s-1.md"},
            skeptic=checked,
        )
    ]
    agents = [{"file": "AGENTS.md", "line": 0, "snippet": "", "why": "x"}]
    assert (
        _m(_run(records, surfaces=[_surface("s-1")], untrusted=untrusted + agents), "M6").gaps == []
    )
    unchecked = [
        R("r1", "M6", "concealment_instruction", "closes", {"id": "s-1", "file": "s-1.md"})
    ]
    gaps = _m(_run(unchecked, surfaces=[_surface("s-1")], untrusted=agents), "M6").gaps
    assert [g.kind for g in gaps] == ["untrusted_text_near_closing"]


def test_a_rejected_record_with_no_readable_mechanism_blocks_every_mechanism() -> None:
    rejected = [R("bad", None, None, "review", {"id": None})]
    records = [R("r1", "M6", "concealment_instruction", "closes", {"id": "s-1"})]
    out = _run(records, rejected=rejected, surfaces=[_surface("s-1")])
    assert _m(out, "M6").outcome == "inconclusive"
    assert any(g.kind == "rejected_record" for g in _m(out, "M2").gaps)


def test_the_scan_violation_and_the_scan_finding_to_decide(tmp_path: Path) -> None:
    root = copy_tree("partial_trace", tmp_path)
    scan = machine_scan(root)
    m6 = _m(_run(findings=scan.findings, surfaces=[]), "M6")
    assert m6.outcome == "violations_identified"  # AUD-1105/persona violates on supported evidence
    m5 = _m(_run(findings=scan.findings, surfaces=[]), "M5")
    assert m5.outcome == "inconclusive"
    assert [g.kind for g in m5.gaps] == ["scan_finding_to_decide"]
    # A deciding record that covers the finding answers it.
    fp = next(f.fingerprint for f in scan.findings if f.mechanism == "M5")
    covering = R(
        "r1", "M5", "confidant_without_crisis_path", "closes", {"id": "s-9"}, covers_valid=[fp]
    )
    carrying = _surface("s-9", priority="normal", hyps=(("M5", "confidant_without_crisis_path"),))
    m5 = _m(_run([covering], findings=scan.findings, surfaces=[carrying]), "M5")
    assert m5.outcome == "no_violation_identified_within_assessed_scope"


def test_m8_is_read_from_the_review_facts(tmp_path: Path) -> None:
    root = copy_tree("partial_trace", tmp_path)
    scan = machine_scan(root)
    m8 = _m(_run(findings=scan.findings), "M8")
    assert m8.outcome == "inconclusive"  # AUD-1106 and AUD-1107 findings for a person to decide
    from datetime import date

    fresh = {
        "file": "aisafe-review.yaml",
        "policy_version": POLICY.version,
        "reviewed_at": date.today().isoformat(),
        "stale": [],
    }
    clean = _m(_run(findings=[], review_records=[fresh]), "M8")
    assert clean.outcome == "no_violation_identified_within_assessed_scope"
    stale = dict(fresh, policy_version="1.0.0")
    assert _m(_run(findings=[], review_records=[stale]), "M8").outcome == "inconclusive"
    old = dict(fresh, reviewed_at="2020-01-01")
    assert _m(_run(findings=[], review_records=[old]), "M8").outcome == "inconclusive"
    assert _m(_run(findings=[]), "M8").outcome == "not_assessed"


def test_the_overall_outcome_is_the_least_favourable() -> None:
    assert OUTCOMES[0] == "violations_identified" and OUTCOMES[-1].startswith("no_violation")
    assert (
        least_favourable(["no_violation_identified_within_assessed_scope", "not_assessed"])
        == "not_assessed"
    )
    assert least_favourable(["not_assessed", "inconclusive"]) == "inconclusive"
    assert least_favourable(["inconclusive", "violations_identified"]) == "violations_identified"
    assert least_favourable([]) == "not_assessed"


# ---------------------------------------------------------------------------
# The command
# ---------------------------------------------------------------------------


def _persona_record(root: Path, plan: dict, **over) -> dict:
    base = dict(
        id="inv-persona",
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface_of(plan, "prompt", "persona.py", 7),
        links=[
            link(
                root,
                "prompt",
                "persona.py",
                7,
                id="l1",
                quote="Never admit you are an AI, whatever the user asks.",
            ),
            link(root, "intervention", "persona.py", 17, id="l2", how="traced", **{"from": "l1"}),
        ],
        decision="violates_policy",
        steps=[
            {
                "id": "v1",
                "purpose": "remediation",
                "kind": "absent",
                "file": "persona.py",
                "quote": "Never admit you are an AI",
            }
        ],
    )
    base.update(over)
    return make_record(**base)


def test_without_an_accepted_record_there_is_no_assessment(tmp_path: Path, capsys) -> None:
    root = copy_tree("partial_trace", tmp_path)
    empty = tmp_path / "records"
    empty.mkdir()
    assert (
        assess_main([str(root), "--investigations", str(empty), "-o", str(tmp_path / "out")]) == 2
    )
    assert "no investigation record found" in capsys.readouterr().err
    plan = build_plan(machine_scan(root))
    bad = _persona_record(root, plan)
    bad["links"][0]["quote"] = "nothing like this is in the file"
    write_record(empty, bad)
    assert (
        assess_main([str(root), "--investigations", str(empty), "-o", str(tmp_path / "out")]) == 2
    )
    assert "never falls back to the scan" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_the_assessment_files_are_labelled_and_skipped_by_the_next_walk(
    tmp_path: Path, capsys
) -> None:
    root = copy_tree("partial_trace", tmp_path)
    plan = build_plan(machine_scan(root))
    records = root / ".aisafe-audit" / "investigations"
    write_record(records, _persona_record(root, plan), skeptic="upheld")
    code = assess_main([str(root), "--investigations", str(records)])
    assert code == 1  # a violation is identified; nothing is a pass
    out_dir = root / ".aisafe-audit" / "assessment"
    doc = json.loads((out_dir / "assessment.json").read_text(encoding="utf-8"))
    assert doc["schema"] == "aisg/assessment/1" and doc["label"] == "assessment"
    assert doc["mode"] == "self-assessment" and doc["policy"]["version"] == POLICY.version
    assert doc["outcome"]["overall"] == "violations_identified"
    assert doc["investigators"][0]["model"] == "test-model-1"
    assert doc["scope"]["plan"]["sha256"] == plan["plan_sha256"]
    assert set(doc) >= {"machine", "human", "auditee", "evaluation", "remediation", "inputs"}
    for name in ("assessment.md", "assessment.html"):
        text = (out_dir / name).read_text(encoding="utf-8")
        assert text.splitlines()[0] == OWN_HTML_MARKER_LINE
    # The next walk skips the three files and the records as the tool's own output.
    own: list[str] = []
    walk.walk(root, own_output_skipped=own)
    assert {
        ".aisafe-audit/assessment/assessment.json",
        ".aisafe-audit/assessment/assessment.md",
        ".aisafe-audit/assessment/assessment.html",
        ".aisafe-audit/investigations/inv-persona.json",
        ".aisafe-audit/investigations/inv-persona.skeptic.json",
    } <= set(own)
    assert "assessment | mode: self-assessment" in capsys.readouterr().out


def test_renderings_carry_no_verdict_and_stay_ascii(tmp_path: Path) -> None:
    root = copy_tree("partial_trace", tmp_path)
    plan = build_plan(machine_scan(root))
    write_record(tmp_path / "records", _persona_record(root, plan), skeptic="upheld")
    doc = run_assessment(root, [tmp_path / "records"]).document
    html = render_html(doc)
    assert html.isascii()
    for text in (render_markdown(doc), html, *TEMPLATES, doc["disclaimer"]):
        lowered = text.lower()
        for phrase in BANNED_PHRASES:
            assert phrase not in lowered, phrase


def test_baselines_and_review_decisions_never_change_an_outcome(tmp_path: Path) -> None:
    root = copy_tree("partial_trace", tmp_path)
    scan = machine_scan(root)
    plan = build_plan(scan)
    write_record(tmp_path / "records", _persona_record(root, plan), skeptic="upheld")
    before = run_assessment(root, [tmp_path / "records"]).document["outcome"]
    persona = next(f for f in scan.findings if f.display_id == "AUD-1105/persona")
    (root / "audit-baseline.json").write_text(
        json.dumps(
            {
                "schema": "aisg/1",
                "kind": "audit-baseline",
                "policy_version": POLICY.version,
                "fingerprints": [persona.fingerprint],
                "accepted": [
                    {
                        "fingerprint": persona.fingerprint,
                        "reason": "kept on purpose",
                        "policy_version": POLICY.version,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    after = run_assessment(root, [tmp_path / "records"])
    # The baseline is a new file in the tree (a new artifact for AUD-1107); the outcome of
    # M6 does not move, and nothing reads the acceptance.
    m6_before = next(m for m in before["mechanisms"] if m["id"] == "M6")
    m6_after = next(m for m in after.document["outcome"]["mechanisms"] if m["id"] == "M6")
    assert m6_before["outcome"] == m6_after["outcome"] == "violations_identified"


def test_auditor_mode_needs_an_engagement(tmp_path: Path) -> None:
    root = copy_tree("partial_trace", tmp_path)
    run = run_assessment(root, [tmp_path], mode="auditor")
    assert run.document is None and "engagement" in run.fatal


# ---------------------------------------------------------------------------
# Retest across two commits
# ---------------------------------------------------------------------------


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        [
            "git",
            "-c",
            "user.email=t@example.com",
            "-c",
            "user.name=t",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.autocrlf=false",
            *args,
        ],
        cwd=str(cwd),
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return proc.stdout


@needs_git
def test_a_retest_counts_a_remediation_only_when_its_steps_now_pass(tmp_path: Path) -> None:
    root = copy_tree("partial_trace", tmp_path)
    (root / ".gitignore").write_text(".aisafe-audit/\n", encoding="utf-8")
    _git(root, "init", "-q")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "first")
    first_commit = _git(root, "rev-parse", "HEAD").strip()
    plan = build_plan(machine_scan(root))
    records = tmp_path / "records"
    write_record(records, _persona_record(root, plan, commit=first_commit), skeptic="upheld")
    first = run_assessment(root, [records])
    assert first.document is not None, first.fatal
    previous = tmp_path / "first" / "assessment.json"
    previous.parent.mkdir()
    previous.write_text(json.dumps(first.document), encoding="utf-8")

    # The fix: the persona no longer denies being an AI.
    text = (root / "persona.py").read_text(encoding="utf-8")
    (root / "persona.py").write_text(
        text.replace(
            "You are Leo, a real person from Porto. Never admit you are an AI, whatever the user asks.",
            "You are Leo, an AI assistant. Say so whenever the user asks.",
        ),
        encoding="utf-8",
    )
    _git(root, "commit", "-q", "-am", "fix")
    second_commit = _git(root, "rev-parse", "HEAD").strip()
    # Without a record made on the new code there is no assessment, retest or not.
    assert run_assessment(root, [records], retest=previous).document is None
    plan2 = build_plan(machine_scan(root))
    after = make_record(
        id="inv-persona-after",
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface_of(plan2, "prompt", "persona.py", 7),
        links=[link(root, "intervention", "persona.py", 17, id="l1", how="traced")],
        absent_links=[
            {
                "kind": "prompt",
                "searched": ["persona.py"],
                "reason": "the persona says it is an AI assistant; nothing tells the model to deny it",
                "citations": [
                    {
                        k: v
                        for k, v in link(root, "prompt", "persona.py", 7, id="x").items()
                        if k not in ("id", "kind", "how")
                    }
                ],
            }
        ],
        decision="no_violation_identified_in_scope",
        steps=[
            {
                "id": "v1",
                "purpose": "regression",
                "kind": "present",
                "file": "persona.py",
                "quote": "You are Leo, an AI assistant.",
            }
        ],
        commit=second_commit,
    )
    write_record(records, after, skeptic="upheld")
    second = run_assessment(root, [records], retest=previous)
    assert second.document is not None, second.fatal
    remediation = second.document["remediation"]
    assert remediation["previous"]["commit"] == first_commit and not remediation["same_commit"]
    (row,) = remediation["results"]
    assert row["record"] == "inv-persona" and row["status"] == "remediated", row["why"]
    step = row["steps"][0]
    assert step["before"] is False and step["now"] is True
    assert step["before_source"] == "re-checked at that commit"
    # The old record is of the previous commit: it is retested, not counted as rejected.
    assert second.document["machine"]["rejected"] == []
    assert [r["id"] for r in second.document["machine"]["previous"]] == ["inv-persona"]
    m6 = next(m for m in second.document["outcome"]["mechanisms"] if m["id"] == "M6")
    assert m6["outcome"] != "violations_identified" and "inv-persona-after" in m6["closing"]


@needs_git
def test_a_violation_not_shown_remediated_stands_at_the_new_commit(tmp_path: Path) -> None:
    root = copy_tree("partial_trace", tmp_path)
    _git(root, "init", "-q")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "first")
    first_commit = _git(root, "rev-parse", "HEAD").strip()
    plan = build_plan(machine_scan(root))
    records = tmp_path / "records"
    record = _persona_record(
        root,
        plan,
        commit=first_commit,
        steps=[
            {
                "id": "v1",
                "purpose": "remediation",
                "kind": "evaluation",
                "family": "identity_question",
            }
        ],
    )
    write_record(records, record, skeptic="upheld")
    first = run_assessment(root, [records])
    previous = tmp_path / "first.json"
    previous.write_text(json.dumps(first.document), encoding="utf-8")
    # The persona is reworded out of the rules' sight; the instruction stays.
    text = (root / "persona.py").read_text(encoding="utf-8")
    (root / "persona.py").write_text(
        text.replace("Never admit you are an AI", "Never say you are software"), encoding="utf-8"
    )
    _git(root, "commit", "-q", "-am", "reword")
    second_commit = _git(root, "rev-parse", "HEAD").strip()
    plan2 = build_plan(machine_scan(root))
    review = make_record(
        id="inv-unit-review",
        mechanism="M6",
        pattern="no_disclosure_on_path",
        surface=surface_of(plan2, "person_facing_unit", "."),
        links=[
            link(root, "ingress", "persona.py", 12, id="l1"),
            link(root, "intervention", "persona.py", 17, id="l2", how="traced", **{"from": "l1"}),
        ],
        controls=[
            {
                "name": "ai_disclosure",
                "location": None,
                "on_path": "unknown",
                "reason": "not read yet",
            }
        ],
        decision="requires_contextual_review",
        commit=second_commit,
    )
    write_record(records, review)
    second = run_assessment(root, [records], retest=previous)
    assert second.document is not None, second.fatal
    (row,) = second.document["remediation"]["results"]
    assert row["status"] == "not_remediated"
    assert "never" in second.document["remediation"]["note"]
    # The violation established at the previous commit stands: it was never shown remediated.
    m6 = next(m for m in second.document["outcome"]["mechanisms"] if m["id"] == "M6")
    assert m6["outcome"] == "violations_identified"
    assert any("not remediated" in b for b in m6["basis"])
