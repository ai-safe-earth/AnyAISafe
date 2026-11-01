"""tests/unit/test_fixes4_validate.py
----------------------------------
Fourth-round regressions, found by investigators during a demonstration run. A record's
effective claim is never more favourable than the evidence, so each section also pins the
honest record that must keep its claim.

- ruling out `objective` or `inference` needs a citation of what the scan holds of that kind;
- ruling out `storage` needs a citation of the analytics row too;
- a required link that is run-time only makes the claim unknown, a proposed review included;
- the plan names the version of the code that ran, whatever stale metadata says;
- a plan's span stops at the end of the file;
- the terminal output of `investigate validate` prints each record's claim;
- the skill says what `how: runtime-only` means for a store beyond the tree.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest
from investigation_helpers import cite, link, make_record, surface_of, write_record

import aisafe
from aisafe.evidence.model import Flow, FlowLink
from aisafe.investigation.plan import build_plan
from aisafe.investigation.scan import machine_scan
from aisafe.investigation.validate import (
    RecordResult,
    ValidationRun,
    render_validation,
    validate_paths,
)
from aisafe.reporting.report import tool_version

CLOSE = "no_violation_identified_in_scope"
REVIEW = "requires_contextual_review"
SUPPORTED = "supported_mechanism"
UNKNOWN_REVIEW = {"evidence_status": "unknown", "decision": REVIEW}
SUPPORTED_REVIEW = {"evidence_status": SUPPORTED, "decision": REVIEW}
SUPPORTED_CLOSE = {"evidence_status": SUPPORTED, "decision": CLOSE}
REGRESSION = [{"id": "v1", "purpose": "regression", "kind": "reinvestigate", "note": "read again"}]
REPO = Path(__file__).resolve().parents[2]
SKILL_DOC = "skills/ai-safety-audit/references/investigate.md"

PERSONA = "prompts/persona.md"
STYLE = "prompts/style.md"
PERSONA_TEXT = """\
# Persona

You help people plan their week.
Your goal is to keep the user talking as long as possible.
Infer the user's mood from their messages and use it to persuade them to stay.
"""
STYLE_TEXT = """\
# Style

Answer in plain words and keep it short.
"""
TRACKING_TEXT = '''\
"""Analytics."""

import analytics


def track_message(user_id: str, text: str) -> None:
    analytics.track(user_id, "message", {"text": text})
'''
APP_TEXT = '''\
"""Chat."""

from pathlib import Path

import anthropic
from fastapi import FastAPI, Request

from tracking import track_message

app = FastAPI()
client = anthropic.Anthropic()
HERE = Path(__file__).parent
PERSONA = (HERE / "prompts" / "persona.md").read_text(encoding="utf-8")
STYLE = (HERE / "prompts" / "style.md").read_text(encoding="utf-8")


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    text = body["text"]
    track_message(body["user_id"], text)
    reply = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=400,
        system=PERSONA + STYLE,
        messages=[{"role": "user", "content": text}],
    )
    return {"reply": reply.content[0].text}
'''
OBJECTIVE_LINE = 4  # of PERSONA_TEXT
INFERENCE_LINE = 5
ANALYTICS_IMPORT = 3  # of TRACKING_TEXT
ANALYTICS_SEND = 7
MESSAGE_IN = 19  # of APP_TEXT
REPLY_OUT = 28


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "tree"
    (root / "prompts").mkdir(parents=True)
    files = {
        PERSONA: PERSONA_TEXT,
        STYLE: STYLE_TEXT,
        "tracking.py": TRACKING_TEXT,
        "app.py": APP_TEXT,
    }
    for name, text in files.items():
        (root / name).write_text(text, encoding="utf-8", newline="\n")
    return root


@pytest.fixture()
def tree(tmp_path: Path) -> tuple[Path, Any, dict]:
    root = _tree(tmp_path)
    scan = machine_scan(root)
    return root, scan, build_plan(scan)


def _validate(tmp_path: Path, scan, plan: dict, record: dict) -> RecordResult:
    records = tmp_path / "records"
    write_record(records, record)
    run = validate_paths([records], scan, plan_surfaces={s["id"]: s for s in plan["surfaces"]})
    assert run.fatal is None, run.fatal
    result = next(r for r in run.results if r.id == record["id"])
    assert result.accepted, result.errors
    return result


def _ruled_out(root: Path, kind: str, file: str, line: int) -> dict:
    return {
        "kind": kind,
        "searched": [file],
        "reason": "the line was read and it says something else",
        "citations": [cite(root, file, line)],
    }


def _reply(root: Path) -> dict:
    return link(root, "intervention", "app.py", REPLY_OUT, id="l1")


def _objective_closing(root: Path, surface: dict, *absent: dict) -> dict:
    return make_record(
        id="inv-m4",
        mechanism="M4",
        pattern="objective",
        surface=surface,
        links=[_reply(root)],
        absent_links=list(absent),
        decision=CLOSE,
        steps=REGRESSION,
    )


def _inference_closing(root: Path, plan: dict, line: int) -> dict:
    return make_record(
        id="inv-m2",
        mechanism="M2",
        pattern="inference_for_influence",
        surface=_prompt(plan),
        links=[_reply(root), link(root, "objective", PERSONA, OBJECTIVE_LINE, id="l2")],
        absent_links=[_ruled_out(root, "inference", PERSONA, line)],
        decision=CLOSE,
        steps=REGRESSION,
    )


def _prompt(plan: dict, file: str = PERSONA) -> dict:
    return surface_of(plan, "prompt", file)


# ---------------------------------------------------------------------------
# 1. Ruling out an objective or an inference
# ---------------------------------------------------------------------------


def test_ruling_out_the_objective_needs_a_citation_of_the_line_that_carries_it(
    tree, tmp_path: Path
) -> None:
    root, scan, plan = tree
    record = _objective_closing(root, _prompt(plan), _ruled_out(root, "objective", PERSONA, 3))
    result = _validate(tmp_path, scan, plan, record)
    assert result.claim == "review" and result.effective == SUPPORTED_REVIEW
    assert any(f"{PERSONA}:{OBJECTIVE_LINE}" in note for note in result.notes), result.notes


def test_a_rule_out_that_cites_the_objective_and_answers_it_keeps_its_closing(
    tree, tmp_path: Path
) -> None:
    root, scan, plan = tree
    absent = _ruled_out(root, "objective", PERSONA, OBJECTIVE_LINE)
    absent["citations"].append(cite(root, PERSONA, INFERENCE_LINE))
    record = _objective_closing(root, _prompt(plan), absent)
    result = _validate(tmp_path, scan, plan, record)
    assert result.claim == "closes" and result.effective == SUPPORTED_CLOSE


def test_ruling_out_the_inference_needs_a_citation_of_the_line_that_carries_it(
    tree, tmp_path: Path
) -> None:
    root, scan, plan = tree
    result = _validate(tmp_path, scan, plan, _inference_closing(root, plan, 3))
    assert result.claim == "review"
    assert any(f"{PERSONA}:{INFERENCE_LINE}" in note for note in result.notes), result.notes


def test_a_rule_out_that_cites_the_inference_and_answers_it_keeps_its_closing(
    tree, tmp_path: Path
) -> None:
    root, scan, plan = tree
    result = _validate(tmp_path, scan, plan, _inference_closing(root, plan, INFERENCE_LINE))
    assert result.claim == "closes"


def test_a_finding_of_that_kind_counts_with_no_signal_row(tree, tmp_path: Path) -> None:
    """A prompt literal in Python gives a finding and no inventory row: the rule promotes it."""
    root, scan, plan = tree
    scan.ctx.inventory.person_signals = []
    record = _objective_closing(root, _prompt(plan), _ruled_out(root, "objective", PERSONA, 3))
    result = _validate(tmp_path, scan, plan, record)
    assert result.claim == "review"
    assert any(f"{PERSONA}:{OBJECTIVE_LINE}" in note for note in result.notes), result.notes


def test_on_a_unit_surface_every_objective_of_the_unit_is_answered(tree, tmp_path: Path) -> None:
    root, scan, plan = tree
    surface = surface_of(plan, "person_facing_unit", ".")
    record = _objective_closing(root, surface, _ruled_out(root, "objective", PERSONA, 3))
    result = _validate(tmp_path, scan, plan, record)
    assert result.claim == "review"


def test_an_objective_in_another_prompt_does_not_stop_a_closing(tree, tmp_path: Path) -> None:
    """The other prompts of the unit are surfaces of their own."""
    root, scan, plan = tree
    record = _objective_closing(root, _prompt(plan, STYLE), _ruled_out(root, "objective", STYLE, 3))
    result = _validate(tmp_path, scan, plan, record)
    assert result.claim == "closes"


def test_a_surface_the_plan_did_not_list_has_no_span_to_narrow_to(tree, tmp_path: Path) -> None:
    root, scan, plan = tree
    surface = {"id": None, "type": "prompt", "file": STYLE, "line": 1}
    record = _objective_closing(root, surface, _ruled_out(root, "objective", STYLE, 3))
    result = _validate(tmp_path, scan, plan, record)
    assert result.claim == "review"


def test_a_link_the_syntax_tree_established_still_counts_outside_the_span(
    tree, tmp_path: Path
) -> None:
    """The span narrows the signals and findings, never an established link."""
    root, scan, plan = tree
    flow = Flow(links=[FlowLink("objective", PERSONA, OBJECTIVE_LINE, "the goal", "ast")])
    scan.findings = [dataclasses.replace(scan.findings[0], flow=flow), *scan.findings[1:]]
    record = _objective_closing(root, _prompt(plan, STYLE), _ruled_out(root, "objective", STYLE, 3))
    result = _validate(tmp_path, scan, plan, record)
    assert result.claim == "review"


# ---------------------------------------------------------------------------
# 2. Ruling out storage
# ---------------------------------------------------------------------------


def _storage_closing(root: Path, plan: dict, line: int) -> dict:
    return make_record(
        id="inv-m1",
        mechanism="M1",
        pattern="storage",
        view="person-data",
        surface=surface_of(plan, "external_destination", "tracking.py"),
        links=[link(root, "collection", "app.py", MESSAGE_IN, id="l1")],
        absent_links=[_ruled_out(root, "storage", "tracking.py", line)],
        decision=CLOSE,
        steps=REGRESSION,
    )


def test_ruling_out_storage_needs_a_citation_of_the_analytics_row(tree, tmp_path: Path) -> None:
    root, scan, plan = tree
    result = _validate(tmp_path, scan, plan, _storage_closing(root, plan, ANALYTICS_IMPORT))
    assert result.claim == "review" and result.effective == SUPPORTED_REVIEW
    assert any(f"tracking.py:{ANALYTICS_SEND}" in note for note in result.notes), result.notes


def test_ruling_out_storage_still_needs_a_citation_of_a_memory_store(tree, tmp_path: Path) -> None:
    root, scan, plan = tree
    surface = surface_of(plan, "memory_store", PERSONA)
    record = _storage_closing(root, plan, ANALYTICS_SEND)
    record["surface"] = surface
    record["absent_links"].append(_ruled_out(root, "storage", PERSONA, 3))
    result = _validate(tmp_path, scan, plan, record)
    assert result.claim == "review"
    assert any(f"{PERSONA}:{INFERENCE_LINE}" in note for note in result.notes), result.notes


def test_a_rule_out_of_storage_that_cites_the_analytics_row_keeps_its_closing(
    tree, tmp_path: Path
) -> None:
    root, scan, plan = tree
    inventory = scan.ctx.inventory
    inventory.memory_stores = []  # the persona prompt's memory row is in the unit too
    inventory.person_signals = [r for r in inventory.person_signals if r["kind"] != "memory"]
    result = _validate(tmp_path, scan, plan, _storage_closing(root, plan, ANALYTICS_SEND))
    assert result.claim == "closes"


# ---------------------------------------------------------------------------
# 3. A required link that is run-time only
# ---------------------------------------------------------------------------


def _storage_record(root: Path, plan: dict, decision: str, how: str, **extra: Any) -> dict:
    return make_record(
        id="inv-store",
        mechanism="M1",
        pattern="storage",
        view="person-data",
        surface=surface_of(plan, "external_destination", "tracking.py"),
        links=[
            link(root, "collection", "app.py", MESSAGE_IN, id="l1"),
            link(root, "storage", "tracking.py", ANALYTICS_SEND, id="l2", how=how),
        ],
        decision=decision,
        steps=REGRESSION,
        **extra,
    )


def test_a_proposed_review_with_a_run_time_only_required_link_reads_unknown(
    tree, tmp_path: Path
) -> None:
    root, scan, plan = tree
    record = _storage_record(root, plan, REVIEW, "runtime-only")
    result = _validate(tmp_path, scan, plan, record)
    assert result.effective == UNKNOWN_REVIEW and result.claim == "review"
    assert result.missing == ["storage"] and result.runtime == ["storage"]
    assert any("runtime-only" in note for note in result.notes), result.notes


def test_a_closing_lowered_to_review_with_a_run_time_only_link_reads_unknown(
    tree, tmp_path: Path
) -> None:
    root, scan, plan = tree
    absent = [_ruled_out(root, "storage", "tracking.py", ANALYTICS_SEND)]
    record = _storage_record(root, plan, CLOSE, "runtime-only", absent_links=absent)
    result = _validate(tmp_path, scan, plan, record)
    assert result.effective == UNKNOWN_REVIEW


def test_a_proposed_review_with_every_link_read_stays_supported(tree, tmp_path: Path) -> None:
    root, scan, plan = tree
    result = _validate(tmp_path, scan, plan, _storage_record(root, plan, REVIEW, "read"))
    assert result.effective == SUPPORTED_REVIEW


# ---------------------------------------------------------------------------
# 4. The tool's version
# ---------------------------------------------------------------------------


def test_the_plan_names_the_running_code_whatever_stale_metadata_says(
    tree, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A leftover `aisafe.egg-info` next to the source said 0.1.0 under the 0.2.0 code."""
    _root, scan, _plan = tree
    monkeypatch.setattr("importlib.metadata.version", lambda name: "0.0.1-stale")
    assert tool_version() == aisafe.__version__
    assert build_plan(scan)["tool"]["version"] == aisafe.__version__


# ---------------------------------------------------------------------------
# 5. A span stops at the end of the file
# ---------------------------------------------------------------------------


def test_a_span_stops_at_the_end_of_the_file(tree) -> None:
    _root, _scan, plan = tree
    spans = {(s["type"], s["file"]): s["span"] for s in plan["surfaces"]}
    assert spans["external_destination", "tracking.py"] == [1, 7]
    assert spans["memory_store", PERSONA] == [1, 5]
    assert spans["model_entry", "app.py"] == [7, 28]


def test_a_span_inside_the_file_keeps_its_window(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    tail = "".join(f"# a line {n}\n" for n in range(40))
    (root / "tracking.py").write_text(TRACKING_TEXT + tail, encoding="utf-8", newline="\n")
    plan = build_plan(machine_scan(root))
    surface = next(s for s in plan["surfaces"] if s["type"] == "external_destination")
    assert surface["span"] == [1, ANALYTICS_SEND + 15]


def test_a_whole_file_surface_keeps_its_mark(tree) -> None:
    """`_chain_on_surface` reads a span to 10**9 as a surface that is a whole file."""
    _root, _scan, plan = tree
    surface = next(s for s in plan["surfaces"] if s["type"] == "prompt" and s["file"] == PERSONA)
    assert surface["span"] == [1, 10**9]


# ---------------------------------------------------------------------------
# 6. The claim in the terminal
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("claim", ["establishes", "closes", "review"])
def test_the_terminal_output_prints_the_claim_on_the_record_line(claim: str) -> None:
    result = RecordResult(path="r.json", id="inv-a", status="accepted", claim=claim)
    run = ValidationRun(root=Path("."), state={}, mode="self-assessment", results=[result])
    assert f"accepted: r.json (inv-a) | claim: {claim}\n" in render_validation(run)


def test_a_rejected_record_prints_no_claim() -> None:
    result = RecordResult(path="r.json", id="inv-a", status="rejected", claim="closes")
    run = ValidationRun(root=Path("."), state={}, mode="self-assessment", results=[result])
    assert "claim:" not in render_validation(run)


# ---------------------------------------------------------------------------
# 7. The skill's note on a store beyond the tree
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("copy", ["src/aisafe", "plugins/aisafe"])
def test_the_skill_says_what_runtime_only_means_for_a_store_beyond_the_tree(copy: str) -> None:
    text = " ".join((REPO / copy / SKILL_DOC).read_text(encoding="utf-8").split())
    assert "A store the data goes out to" in text
    assert "closest honest fit" in text
