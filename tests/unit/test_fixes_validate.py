"""tests/unit/test_fixes_validate.py
---------------------------------
Regressions for what a review found in `aisafe investigate validate`. In each, a record, or
a file next to it, could make a claim or an assessment more favourable than the evidence:

- a control "on the path" that is an import, a definition, a line after the send, or a line
  in another function nothing calls; an anonymisation with no transformation before the send;
- a file that may be a record, dropped without a word;
- a record on a person-facing unit that reads another unit, or that names a surface only in
  its counterevidence;
- a link ruled out by citing another row of the scan than the one that contradicts it, or
  from another unit than the one that holds the record's links;
- a skeptic pass whose claims are refuted in another spelling, or not results at all;
- a skeptic file named by an absolute, network or device path, or too large to read;
- a violation replaced by a record on another surface;
- a prompt ruled out that exists only at run time.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from investigation_helpers import cite, copy_tree, link, make_record, surface_of, write_record

from aisafe.assessment.assess import run_assessment
from aisafe.investigation import validate as validate_module
from aisafe.investigation.plan import build_plan
from aisafe.investigation.scan import machine_scan
from aisafe.investigation.validate import validate_paths

CLOSE = "no_violation_identified_in_scope"
REGRESSION = [{"id": "v1", "purpose": "regression", "kind": "reinvestigate", "note": "read again"}]


def _setup(name: str, tmp_path: Path):
    root = copy_tree(name, tmp_path)
    scan = machine_scan(root)
    return root, scan, build_plan(scan)


def _rescan(root: Path):
    scan = machine_scan(root)
    return scan, build_plan(scan)


def _results(scan, plan, records: Path) -> dict[str | None, Any]:
    run = validate_paths([records], scan, plan_surfaces={s["id"]: s for s in plan["surfaces"]})
    assert run.fatal is None, run.fatal
    return {r.id: r for r in run.results}


def _mechanism(root: Path, records: Path, mechanism: str) -> dict:
    run = run_assessment(root, [records])
    assert run.document is not None, run.fatal
    return next(m for m in run.document["outcome"]["mechanisms"] if m["id"] == mechanism)


def _line_of(root: Path, file: str, needle: str) -> int:
    lines = (root / file).read_text(encoding="utf-8").split("\n")
    return next(i for i, text in enumerate(lines, 1) if needle in text)


def _hop(root: Path, file: str, line: int) -> dict:
    return {**cite(root, file, line), "step": "the way between them"}


def _replace(root: Path, file: str, old: str, new: str) -> None:
    path = root / file
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


# ---------------------------------------------------------------------------
# A control on the path (findings 3, 45)
# ---------------------------------------------------------------------------


def _crisis_record(root: Path, plan: dict, location: dict, *, link_id: str = "l3", **extra) -> dict:
    links = [
        link(
            root,
            "ingress",
            "companion.py",
            _line_of(root, "companion.py", "body = await request.json()"),
            id="l1",
        ),
        link(
            root,
            "prompt",
            "companion.py",
            _line_of(root, "companion.py", "You are a caring friend"),
            id="l2",
            how="traced",
            quote="You are a caring friend who listens without",
            **{"from": "l1"},
        ),
        link(
            root,
            "intervention",
            "companion.py",
            _line_of(root, "companion.py", "reply.content[0].text"),
            id="l3",
            how="traced",
            **{"from": "l2"},
        ),
        *extra.pop("more_links", []),
    ]
    return make_record(
        id="inv-m5-crisis",
        mechanism="M5",
        pattern="confidant_without_crisis_path",
        surface=surface_of(plan, "person_facing_unit", "."),
        links=links,
        controls=[
            {
                "name": "crisis_path",
                "location": location,
                "on_path": "yes",
                "link": link_id,
                "reason": "the record says the check runs on the path",
                **extra,
            }
        ],
        decision=CLOSE,
        steps=REGRESSION,
    )


@pytest.mark.parametrize(
    ("file", "line", "end_line", "hop"),
    [
        pytest.param("companion.py", 4, None, None, id="the import of a function never called"),
        pytest.param("companion.py", 1, None, None, id="an unrelated import"),
        pytest.param("safety.py", 7, 10, ("companion.py", 4), id="the import as the only hop"),
        pytest.param("safety.py", 7, None, ("safety.py", 1), id="a hop in the control's own file"),
        pytest.param("safety.py", 7, None, ("companion.py", 15), id="a hop that calls nothing"),
        pytest.param("safety.py", 6, None, ("companion.py", 4), id="a definition's header"),
    ],
)
def test_a_control_nothing_calls_closes_nothing(
    tmp_path: Path, file: str, line: int, end_line: int | None, hop: tuple[str, int] | None
) -> None:
    root, scan, plan = _setup("control_not_on_path", tmp_path)
    records = tmp_path / "records"
    location = cite(root, file, line, end_line=end_line)
    via = {"via": [_hop(root, *hop)]} if hop else {}
    write_record(records, _crisis_record(root, plan, location, **via), skeptic="upheld")
    result = _results(scan, plan, records)["inv-m5-crisis"]
    assert result.accepted, result.errors
    assert result.complete and not result.control_on_path and result.claim == "review"
    assert _mechanism(root, records, "M5")["closing"] == []


def _wired(root: Path) -> int:
    """The crisis check called in the handler, before the model; returns the call's line."""
    _replace(
        root,
        "companion.py",
        "    body = await request.json()\n",
        '    body = await request.json()\n    urgent = crisis_check(body["text"])\n'
        '    if urgent:\n        return {"reply": urgent}\n',
    )
    return _line_of(root, "companion.py", "urgent = crisis_check")


def test_a_control_called_on_the_path_closes(tmp_path: Path) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    call = _wired(root)
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    # The call in the handler, and the definition reached by that call.
    write_record(records, _crisis_record(root, plan, cite(root, "companion.py", call)))
    assert _results(scan, plan, records)["inv-m5-crisis"].claim == "closes"
    definition = cite(root, "safety.py", 7, end_line=10)
    record = _crisis_record(root, plan, definition, via=[_hop(root, "companion.py", call)])
    write_record(records, record)
    result = _results(scan, plan, records)["inv-m5-crisis"]
    assert result.control_on_path and result.claim == "closes"


def test_a_control_after_the_reply_is_not_on_the_way_to_it(tmp_path: Path) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    _replace(
        root,
        "companion.py",
        '    return {"reply": reply.content[0].text}\n',
        '    await deliver(reply.content[0].text)\n    crisis_check(body["text"])\n',
    )
    scan, plan = _rescan(root)
    after = _line_of(root, "companion.py", 'crisis_check(body["text"])')
    records = tmp_path / "records"
    write_record(records, _crisis_record(root, plan, cite(root, "companion.py", after)))
    result = _results(scan, plan, records)["inv-m5-crisis"]
    assert result.complete and not result.control_on_path and result.claim == "review"


def test_a_helper_in_the_same_file_that_nothing_calls_is_not_on_the_path(tmp_path: Path) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    _replace(
        root,
        "companion.py",
        "app = FastAPI()\n",
        'def crisis_gate(text):\n    return "988" if "hurt" in text else None\n\n\n'
        "app = FastAPI()\n",
    )
    scan, plan = _rescan(root)
    body = _line_of(root, "companion.py", 'return "988"')
    records = tmp_path / "records"
    write_record(records, _crisis_record(root, plan, cite(root, "companion.py", body)))
    result = _results(scan, plan, records)["inv-m5-crisis"]
    assert result.complete and not result.control_on_path and result.claim == "review"


def test_a_control_on_a_link_outside_the_chain_closes_nothing(tmp_path: Path) -> None:
    root, scan, plan = _setup("control_not_on_path", tmp_path)
    records = tmp_path / "records"
    decoy = link(root, "intervention", "safety.py", 9, id="l9")
    record = _crisis_record(
        root, plan, cite(root, "safety.py", 8), link_id="l9", more_links=[decoy]
    )
    write_record(records, record)
    result = _results(scan, plan, records)["inv-m5-crisis"]
    assert result.complete and not result.control_on_path and result.claim == "review"


def _bypass_closing(root: Path, plan: dict, location: int) -> dict:
    via = [_hop(root, "chat.py", 16)]
    return make_record(
        id="inv-m1-closing",
        mechanism="M1",
        pattern="transmission",
        view="person-data",
        surface=surface_of(plan, "external_destination", "telemetry.py"),
        links=[
            link(root, "collection", "chat.py", 15, id="l1"),
            link(
                root,
                "transmission",
                "telemetry.py",
                22,
                id="l2",
                how="traced",
                **{"from": "l1"},
                via=via,
            ),
        ],
        controls=[
            {
                "name": "anonymisation",
                "location": cite(root, "telemetry.py", location),
                "on_path": "yes",
                "link": "l2",
                "reason": "the record says the event is anonymised before it leaves",
            }
        ],
        decision=CLOSE,
        steps=REGRESSION,
    )


@pytest.mark.parametrize("line", [13, 20, 21], ids=["the def line", "the raw send", "the call"])
def test_anonymisation_without_the_transformation_read_closes_nothing(
    tmp_path: Path, line: int
) -> None:
    root, scan, plan = _setup("logging_bypass", tmp_path)
    records = tmp_path / "records"
    write_record(records, _bypass_closing(root, plan, line), skeptic="upheld")
    result = _results(scan, plan, records)["inv-m1-closing"]
    assert result.accepted, result.errors
    assert not result.control_on_path and result.claim == "review"
    assert _mechanism(root, records, "M1")["closing"] == []


def test_a_transformation_the_send_does_not_follow_closes_nothing(tmp_path: Path) -> None:
    root, scan, plan = _setup("sanitised_transmission", tmp_path)
    records = tmp_path / "records"
    via = [_hop(root, "chat.py", 16)]
    record = make_record(
        id="inv-m1-side",
        mechanism="M1",
        pattern="transmission",
        view="person-data",
        surface=surface_of(plan, "external_destination", "telemetry.py"),
        links=[
            link(root, "collection", "chat.py", 15, id="l1"),
            link(
                root,
                "transformation",
                "telemetry.py",
                10,
                id="l2",
                how="traced",
                **{"from": "l1"},
                via=via,
            ),
            # The send follows the collection, not the transformation.
            link(
                root,
                "transmission",
                "telemetry.py",
                15,
                id="l3",
                how="traced",
                **{"from": "l1"},
                via=via,
            ),
        ],
        controls=[
            {
                "name": "anonymisation",
                "location": cite(root, "telemetry.py", 14),
                "on_path": "yes",
                "link": "l3",
                "reason": "the record says the event is anonymised before it leaves",
            }
        ],
        decision=CLOSE,
        steps=REGRESSION,
    )
    write_record(records, record)
    result = _results(scan, plan, records)["inv-m1-side"]
    assert result.complete and not result.control_on_path and result.claim == "review"


# ---------------------------------------------------------------------------
# A file that may be a record is never dropped (findings 4, 27)
# ---------------------------------------------------------------------------


def _tone_record(root: Path, plan: dict) -> dict:
    return make_record(
        id="inv-m2-tone",
        mechanism="M2",
        pattern="inference_for_influence",
        surface=surface_of(plan, "prompt", "assistant.py", 7),
        links=[
            link(
                root,
                "inference",
                "assistant.py",
                8,
                id="l1",
                quote="analyze its emotional tone and suggest a kinder wording.",
            ),
            link(root, "intervention", "assistant.py", 18, id="l2", how="traced", **{"from": "l1"}),
        ],
        absent_links=[
            {
                "kind": "objective",
                "searched": ["assistant.py", "the reply path"],
                "reason": "the tone goes back to the person as the rewrite they asked for",
                "citations": [],
            }
        ],
        decision=CLOSE,
        steps=REGRESSION,
    )


@pytest.fixture()
def tone(tmp_path: Path):
    root, scan, plan = _setup("benign_lookalike", tmp_path)
    records = tmp_path / "records"
    write_record(records, _tone_record(root, plan), skeptic="upheld")
    assert _mechanism(root, records, "M2")["closing"] == ["inv-m2-tone"]
    return root, scan, plan, records


@pytest.mark.parametrize(
    "body",
    [
        {"schema": "aisafe/investigation/1", "kind": "investigation", "id": "inv-gone"},
        {"kind": "investigation", "id": "inv-gone"},
        {"id": "inv-gone", "mechanism": "M2"},
        [{"schema": "aisg/investigation/1", "kind": "investigation"}],
        {"schema": ["aisg/investigation/1"], "kind": "investigation"},
        {"schema": "aisg/skeptic/1", "kind": "investigation"},
        {"schema": "aisg/investigation/1", "padding": "x" * (8 * 1024 * 1024 + 1)},
    ],
    ids=["misspelt", "no schema", "no label", "an array", "odd schema", "mixed", "too large"],
)
def test_a_json_file_that_may_be_a_record_is_rejected_never_skipped(tone, body) -> None:
    root, scan, plan, records = tone
    stray = records / "stray.json"
    stray.write_text(json.dumps(body), encoding="utf-8")
    run = validate_paths([records], scan)
    assert run.exit_code == 1 and run.skipped[0]["why"] == "a skeptic pass"
    assert stray.as_posix() in [r.path for r in run.rejected]
    # Given alone, the same file gets the same answer.
    alone = validate_paths([stray], scan)
    assert [r.status for r in alone.results] == ["rejected"]
    mech = _mechanism(root, records, "M2")
    assert mech["outcome"] == "inconclusive"
    assert "rejected_record" in {gap["kind"] for gap in mech["gaps"]}


def test_a_deeply_nested_file_is_a_rejected_record_not_a_crash(tone) -> None:
    _root, scan, _plan, records = tone
    (records / "deep.json").write_text("[" * 200_000, encoding="utf-8")
    run = validate_paths([records], scan)
    assert run.fatal is None and [r.path.rsplit("/", 1)[-1] for r in run.rejected] == ["deep.json"]


@pytest.mark.parametrize(
    "body",
    [
        {"schema": "aisg/investigation-plan/1", "kind": "investigation-plan"},
        {"schema": "aisg/investigation-validation/1", "kind": "investigation-validation"},
        {"schema": "aisg/assessment/1", "kind": "assessment"},
        {"schema": "aisg/1", "kind": "audit"},
    ],
    ids=["plan", "validation", "assessment", "scan report"],
)
def test_the_workbench_own_documents_stay_out_of_the_records(tone, body) -> None:
    root, scan, _plan, records = tone
    (records / "other.json").write_text(json.dumps(body), encoding="utf-8")
    run = validate_paths([records], scan)
    assert run.exit_code == 0 and len(run.skipped) == 2
    assert _mechanism(root, records, "M2")["closing"] == ["inv-m2-tone"]


# ---------------------------------------------------------------------------
# A record answers the surface it names (findings 5, 35)
# ---------------------------------------------------------------------------

_HANDLER = """from fastapi import FastAPI, Request
import anthropic

app = FastAPI()
client = anthropic.Anthropic()

DISCLOSURE = "I am an AI assistant, not a person."


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    reply = client.messages.create(
        model="m", max_tokens=300, messages=[{"role": "user", "content": body["text"]}]
    )
    return {"reply": REPLY}
"""


def _two_units(tmp_path: Path) -> Path:
    """unit_a returns the model's text as it is; unit_b puts a disclosure in front of it."""
    root = tmp_path / "mono"
    for name, reply in (
        ("unit_a", "reply.content[0].text"),
        ("unit_b", 'DISCLOSURE + " " + reply.content[0].text'),
    ):
        (root / name).mkdir(parents=True)
        (root / name / "pyproject.toml").write_text(
            f'[project]\nname = "{name}"\nversion = "0.1.0"\n'
            'dependencies = ["anthropic", "fastapi"]\n',
            encoding="utf-8",
        )
        (root / name / "app.py").write_text(_HANDLER.replace("REPLY", reply), encoding="utf-8")
    return root


def _disclosure_record(root: Path, plan: dict, record_id: str, unit: str, **extra) -> dict:
    links = [
        link(root, "ingress", "unit_b/app.py", 12, id="l1"),
        link(root, "intervention", "unit_b/app.py", 16, id="l2", how="traced", **{"from": "l1"}),
        *extra.pop("more_links", []),
    ]
    return make_record(
        id=record_id,
        mechanism="M6",
        pattern="no_disclosure_on_path",
        surface=surface_of(plan, "person_facing_unit", unit),
        links=links,
        controls=[
            {
                "name": "ai_disclosure",
                "location": cite(root, "unit_b/app.py", 16),
                "on_path": "yes",
                "link": "l2",
                "reason": "the reply starts with the disclosure",
            }
        ],
        decision=CLOSE,
        steps=REGRESSION,
        **extra,
    )


def test_a_unit_record_must_cite_a_link_in_its_unit(tmp_path: Path) -> None:
    root = _two_units(tmp_path)
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    write_record(records, _disclosure_record(root, plan, "r-b", "unit_b"), skeptic="upheld")
    write_record(records, _disclosure_record(root, plan, "r-a", "unit_a"), skeptic="upheld")
    by_id = _results(scan, plan, records)
    assert by_id["r-b"].accepted and by_id["r-b"].claim == "closes"
    assert by_id["r-a"].status == "rejected"
    assert any("cites no link in unit_a" in error for error in by_id["r-a"].errors)
    m6 = _mechanism(root, records, "M6")
    assert m6["outcome"] == "inconclusive"
    assert any(
        gap["kind"] == "high_surface_not_investigated" and "unit_a" in gap["detail"]
        for gap in m6["gaps"]
    )


def test_a_counterevidence_citation_in_the_unit_does_not_answer_it(tmp_path: Path) -> None:
    root = _two_units(tmp_path)
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    counter = [
        {
            "reading": "unit_a discloses too",
            "result": "refuted",
            "reason": "read the other unit",
            "citations": [cite(root, "unit_a/app.py", 16)],
        }
    ]
    record = _disclosure_record(root, plan, "r-a", "unit_a", counterevidence=counter)
    write_record(records, record, skeptic="upheld")
    assert _results(scan, plan, records)["r-a"].status == "rejected"


def test_a_stray_link_in_the_unit_does_not_move_a_chain_from_another(tmp_path: Path) -> None:
    root = _two_units(tmp_path)
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    stray = link(root, "ingress", "unit_a/app.py", 12, id="l9")
    record = _disclosure_record(root, plan, "r-a", "unit_a", more_links=[stray])
    write_record(records, record, skeptic="upheld")
    result = _results(scan, plan, records)["r-a"]
    assert result.accepted and not result.control_on_path and result.claim == "review"


def test_a_surface_named_only_in_the_counterevidence_is_not_answered(tmp_path: Path) -> None:
    root, scan, plan = _setup("partial_trace", tmp_path)
    records = tmp_path / "records"
    record = make_record(
        id="inv-1",
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface_of(plan, "prompt", "persona.py", 7),
        links=[link(root, "intervention", "persona.py", 17, id="l1", how="traced")],
        counterevidence=[
            {
                "reading": "the persona is fiction",
                "result": "refuted",
                "reason": "nothing frames it so",
                "citations": [cite(root, "persona.py", 7)],
            }
        ],
        decision="requires_contextual_review",
        steps=[],
    )
    write_record(records, record)
    result = _results(scan, plan, records)["inv-1"]
    assert result.status == "rejected" and any("lines 7-7" in e for e in result.errors)


# ---------------------------------------------------------------------------
# Ruling out a link the scan lists (finding 14)
# ---------------------------------------------------------------------------

_SECOND_ROUTE = """

@app.post("/other")
async def other(request: Request):
    reply = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "hi"}])
    return {"reply": reply.choices[0].message.content}
"""


def _with_second_call(root: Path) -> int:
    with (root / "persona.py").open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(_SECOND_ROUTE)
    return _line_of(root, "persona.py", "async def other") + 1


def _no_intervention(root: Path, plan: dict, citations: list[dict]) -> dict:
    return make_record(
        id="inv-1",
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
            )
        ],
        absent_links=[
            {
                "kind": "intervention",
                "searched": ["persona.py"],
                "reason": "the record says this prompt reaches no person",
                "citations": citations,
            }
        ],
        decision=CLOSE,
        steps=REGRESSION,
    )


def test_ruling_a_link_out_needs_a_citation_of_each_row_the_scan_lists(tmp_path: Path) -> None:
    root = copy_tree("partial_trace", tmp_path)
    second = _with_second_call(root)
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    decoy = cite(root, "persona.py", second)
    write_record(records, _no_intervention(root, plan, [decoy]))
    result = _results(scan, plan, records)["inv-1"]
    assert result.effective["decision"] == "requires_contextual_review"
    assert any("persona.py:13" in note for note in result.notes)
    # Citing every row the scan lists answers them all.
    both = [cite(root, "persona.py", 13, end_line=17), decoy]
    write_record(records, _no_intervention(root, plan, both))
    assert _results(scan, plan, records)["inv-1"].claim == "closes"


def test_the_prompt_of_a_prompt_surface_needs_its_own_rows_cited(tmp_path: Path) -> None:
    root, scan, plan = _setup("partial_trace", tmp_path)
    records = tmp_path / "records"
    record = make_record(
        id="inv-1",
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface_of(plan, "prompt", "persona.py", 15),
        links=[link(root, "intervention", "persona.py", 17, id="l1", how="traced")],
        absent_links=[
            {
                "kind": "prompt",
                "searched": ["persona.py"],
                "reason": "the record says the assembly holds no such instruction",
                "citations": [cite(root, "persona.py", 15)],
            }
        ],
        decision=CLOSE,
        steps=REGRESSION,
    )
    write_record(records, record)
    result = _results(scan, plan, records)["inv-1"]
    assert result.effective["decision"] == "requires_contextual_review"
    assert any("persona.py:7" in note for note in result.notes)


def test_a_surface_in_another_unit_does_not_move_the_check_from_the_links(tmp_path: Path) -> None:
    # M5: the scan holds no flow of this pattern, so only the unit's rows can contradict it.
    root = copy_tree("partial_trace", tmp_path)
    (root / "tools").mkdir()
    (root / "tools" / "pyproject.toml").write_text(
        '[project]\nname = "tools"\nversion = "0.1.0"\n', encoding="utf-8"
    )
    (root / "tools" / "util.py").write_text("HELP = 'a small helper script'\n", encoding="utf-8")
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    record = make_record(
        id="inv-1",
        mechanism="M5",
        pattern="attachment_instruction",
        surface={"id": None, "type": "prompt", "file": "tools/util.py", "line": 1},
        links=[
            link(root, "objective", "persona.py", 7, id="l1"),
            link(root, "prompt", "persona.py", 7, id="l2", **{"from": "l1"}),
        ],
        absent_links=[
            {
                "kind": "intervention",
                "searched": ["tools/util.py"],
                "reason": "the record says nothing here reaches a person",
                "citations": [cite(root, "tools/util.py", 1)],
            }
        ],
        decision=CLOSE,
        steps=REGRESSION,
    )
    write_record(records, record)
    result = _results(scan, plan, records)["inv-1"]
    assert result.accepted and result.effective["decision"] == "requires_contextual_review"
    assert any("persona.py:13" in note for note in result.notes)


# ---------------------------------------------------------------------------
# What a skeptic pass says (findings 17, 26, 48)
# ---------------------------------------------------------------------------


def _set_claims(records: Path, claims: Any) -> None:
    path = records / "inv-m2-tone.skeptic.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["claims"] = claims
    path.write_text(json.dumps(doc), encoding="utf-8")


GOOD_CLAIM = {"claim": "the reading holds", "result": "upheld", "reason": "read it"}


@pytest.mark.parametrize("value", ["refuted", "Refuted", "REFUTED", "  Refuted  "])
def test_a_refuted_claim_is_a_refutation_in_any_case(tone, value: str) -> None:
    root, scan, plan, records = tone
    _set_claims(records, [GOOD_CLAIM, {"claim": "x", "result": value, "reason": "y"}])
    result = _results(scan, plan, records)["inv-m2-tone"]
    assert result.skeptic["bound"] and result.skeptic["result"] == "refuted"
    mech = _mechanism(root, records, "M2")
    assert mech["outcome"] == "inconclusive"
    assert "skeptic_refuted" in {gap["kind"] for gap in mech["gaps"]}


@pytest.mark.parametrize(
    "claim",
    [
        {"claim": "x", "result": "partly_refuted", "reason": "y"},
        {"claim": "x", "result": "not_run", "reason": "y"},
        {"claim": "x", "result": "", "reason": "y"},
        {"claim": "x", "result": False, "reason": "y"},
        {"claim": "x", "reason": "y"},
        {"claim": "x", "verdict": "refuted", "reason": "y"},
        {"claim": "", "result": "upheld", "reason": "y"},
        {},
        None,
        "refuted: the persona is sent as it is",
    ],
    ids=[
        "another word",
        "not run",
        "empty",
        "not text",
        "missing",
        "another key",
        "no claim",
        "empty object",
        "null",
        "a string",
    ],
)
def test_a_claim_that_is_no_result_leaves_the_pass_not_run(tone, claim: Any) -> None:
    root, scan, plan, records = tone
    _set_claims(records, [GOOD_CLAIM, claim])
    result = _results(scan, plan, records)["inv-m2-tone"]
    assert not result.skeptic["bound"] and result.skeptic["result"] == "not_run"
    mech = _mechanism(root, records, "M2")
    assert mech["outcome"] == "inconclusive"
    assert "skeptic_not_run" in {gap["kind"] for gap in mech["gaps"]}


# ---------------------------------------------------------------------------
# Where a skeptic file may be (finding 21)
# ---------------------------------------------------------------------------

_OUTSIDE = [
    "C:/elsewhere/inv-m2-tone.skeptic.json",
    "D:inv-m2-tone.skeptic.json",
    "//host.invalid/share/inv-m2-tone.skeptic.json",
    "\\\\host.invalid\\share\\inv-m2-tone.skeptic.json",
    "//?/UNC/host.invalid/share/inv-m2-tone.skeptic.json",
    "//./pipe/inv-m2-tone.skeptic.json",
    "/elsewhere/inv-m2-tone.skeptic.json",
    "../elsewhere/inv-m2-tone.skeptic.json",
    "sub/inv-m2-tone.skeptic.json",
    "inv-m2-tone.skeptic.json\x00.txt",
]


def _set_skeptic_file(records: Path, name: str) -> None:
    path = records / "inv-m2-tone.json"
    saved = json.loads(path.read_text(encoding="utf-8"))
    saved["skeptic"]["file"] = name
    path.write_text(json.dumps(saved), encoding="utf-8")


@pytest.mark.parametrize("name", _OUTSIDE)
def test_a_skeptic_file_outside_the_directory_is_never_touched(
    tone, name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, scan, plan, records = tone
    _set_skeptic_file(records, name)
    touched: list[str] = []

    def spy(method: str) -> None:
        real = getattr(Path, method)

        def wrapper(self: Path, *args: Any, **kwargs: Any) -> Any:
            if "elsewhere" in str(self) or "host.invalid" in str(self) or "pipe" in str(self):
                touched.append(str(self))
            return real(self, *args, **kwargs)

        monkeypatch.setattr(Path, method, wrapper)

    for method in ("resolve", "stat", "lstat", "open", "read_text", "read_bytes"):
        spy(method)
    real_load = validate_module.load_json

    def load(path: Path) -> Any:
        if Path(path).name != "inv-m2-tone.json":
            touched.append(str(path))
        return real_load(path)

    monkeypatch.setattr(validate_module, "load_json", load)
    result = _results(scan, plan, records)["inv-m2-tone"]
    assert touched == []
    assert result.skeptic["result"] == "not_run" and not result.skeptic["bound"]
    assert result.skeptic["file"] is None


def test_an_unbound_skeptic_file_is_no_input_of_the_assessment(tone) -> None:
    root, _scan, _plan, records = tone
    outside = records.parent / "elsewhere"
    outside.mkdir()
    (records / "inv-m2-tone.skeptic.json").rename(outside / "inv-m2-tone.skeptic.json")
    _set_skeptic_file(records, "../elsewhere/inv-m2-tone.skeptic.json")
    document = run_assessment(root, [records]).document
    assert document is not None
    assert "skeptic pass" not in {row["role"] for row in document["inputs"]}


def test_a_skeptic_file_next_to_the_record_is_listed(tone) -> None:
    root, _scan, _plan, records = tone
    document = run_assessment(root, [records]).document
    assert document is not None
    assert "skeptic pass" in {row["role"] for row in document["inputs"]}


def test_a_skeptic_file_over_the_size_limit_counts_as_not_run(tone) -> None:
    _root, scan, plan, records = tone
    path = records / "inv-m2-tone.skeptic.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["padding"] = "x" * (8 * 1024 * 1024 + 1)
    path.write_text(json.dumps(doc), encoding="utf-8")
    result = _results(scan, plan, records)["inv-m2-tone"]
    assert not result.skeptic["bound"] and any("8 MiB" in note for note in result.notes)


def test_a_directory_is_no_skeptic_file(tone) -> None:
    _root, scan, plan, records = tone
    (records / "folder.json").mkdir()
    _set_skeptic_file(records, "folder.json")
    result = _results(scan, plan, records)["inv-m2-tone"]
    assert result.skeptic["result"] == "not_run" and result.skeptic["file"] is None


# ---------------------------------------------------------------------------
# What a record may replace (finding 25)
# ---------------------------------------------------------------------------


def test_a_record_replaces_only_a_reading_of_the_same_hypothesis(tmp_path: Path) -> None:
    root, scan, plan = _setup("partial_trace", tmp_path)
    records = tmp_path / "records"
    concealment = make_record(
        id="inv-concealment",
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
    )
    # Another surface, another pattern, the same mechanism, and just as strong a claim.
    no_disclosure = make_record(
        id="inv-no-disclosure",
        mechanism="M6",
        pattern="no_disclosure_on_path",
        surface=surface_of(plan, "person_facing_unit", "."),
        links=[
            link(root, "ingress", "persona.py", 12, id="l1"),
            link(root, "intervention", "persona.py", 17, id="l2", how="traced", **{"from": "l1"}),
        ],
        controls=[
            {
                "name": "ai_disclosure",
                "location": None,
                "on_path": "no",
                "searched": ["persona.py"],
                "reason": "nothing tells the person",
            }
        ],
        decision="violates_policy",
        supersedes=["inv-concealment"],
    )
    write_record(records, concealment, skeptic="upheld")
    write_record(records, no_disclosure, skeptic="upheld")
    by_id = _results(scan, plan, records)
    assert by_id["inv-concealment"].accepted
    assert by_id["inv-no-disclosure"].status == "rejected"
    assert any("another surface or pattern" in e for e in by_id["inv-no-disclosure"].errors)


# ---------------------------------------------------------------------------
# A prompt that exists only at run time (finding 28)
# ---------------------------------------------------------------------------


def _ruled_out_prompt(root: Path, file: str, line: int) -> list[dict]:
    return [
        {
            "kind": "prompt",
            "searched": [file, "the prompt the service returns"],
            "reason": "the record says the fetched prompt holds no such instruction",
            "citations": [cite(root, file, line)],
        }
    ]


@pytest.mark.parametrize(
    "where",
    [("remote_prompt", "bot.py", 13), ("model_entry", "bot.py", None)],
    ids=["its own surface", "the model call of its unit"],
)
def test_a_prompt_fetched_at_run_time_cannot_be_ruled_out(tmp_path: Path, where) -> None:
    root, scan, plan = _setup("runtime_prompt", tmp_path)
    records = tmp_path / "records"
    record = make_record(
        id="inv-m6-remote",
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface_of(plan, *where),
        links=[link(root, "intervention", "bot.py", 15, id="l1", how="traced")],
        absent_links=_ruled_out_prompt(root, "bot.py", 13),
        decision=CLOSE,
        steps=REGRESSION,
    )
    write_record(records, record, skeptic="upheld")
    result = _results(scan, plan, records)["inv-m6-remote"]
    assert result.effective == {
        "evidence_status": "unknown",
        "decision": "requires_contextual_review",
    }
    assert result.runtime == ["prompt"]
    assert "runtime_only" in {gap["kind"] for gap in _mechanism(root, records, "M6")["gaps"]}


_BOT = """from fastapi import FastAPI, Request
import anthropic
from promptclient import load_prompt

app = FastAPI()
client = anthropic.Anthropic()


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    persona = load_prompt()
    reply = client.messages.create(model="m", max_tokens=300, system=persona, messages=[{"role": "user", "content": body["text"]}])
    return {"reply": reply.content[0].text}
"""
_CLIENT = """import requests

PROMPT_URL = "https://prompts.example.invalid/companion/latest"


def load_prompt():
    system_prompt = requests.get(PROMPT_URL, timeout=5).text
    return system_prompt
"""


def test_a_prompt_fetched_in_another_unit_cannot_be_ruled_out_either(tmp_path: Path) -> None:
    root = tmp_path / "two"
    for name, file, text in (
        ("app", "bot.py", _BOT),
        ("promptclient", "promptclient.py", _CLIENT),
    ):
        (root / name).mkdir(parents=True)
        (root / name / "pyproject.toml").write_text(
            f'[project]\nname = "{name}"\nversion = "0.1.0"\n', encoding="utf-8"
        )
        (root / name / file).write_text(text, encoding="utf-8")
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    record = make_record(
        id="inv-m6-remote",
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface_of(plan, "model_entry", "app/bot.py"),
        links=[link(root, "intervention", "app/bot.py", 14, id="l1", how="traced")],
        absent_links=_ruled_out_prompt(root, "promptclient/promptclient.py", 7),
        decision=CLOSE,
        steps=REGRESSION,
    )
    write_record(records, record, skeptic="upheld")
    result = _results(scan, plan, records)["inv-m6-remote"]
    assert result.effective["evidence_status"] == "unknown" and result.claim == "review"
    assert result.runtime == ["prompt"]


def test_a_no_finding_step_on_a_file_the_walk_does_not_read_is_rejected(tmp_path: Path) -> None:
    root, scan, plan = _setup("benign_lookalike", tmp_path)
    records = tmp_path / "records"
    record = _tone_record(root, plan)
    record["verification_steps"] = [
        {
            "id": "v1",
            "purpose": "regression",
            "kind": "no_finding",
            "rule": "AUD-1108",
            "file": "gone.py",
        }
    ]
    write_record(records, record, skeptic="upheld")
    result = _results(scan, plan, records)["inv-m2-tone"]
    assert result.status == "rejected"
    assert any("not in the walked tree" in error for error in result.errors)
