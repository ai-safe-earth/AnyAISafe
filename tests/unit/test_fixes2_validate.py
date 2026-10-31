"""tests/unit/test_fixes2_validate.py
----------------------------------
Second-round regressions for `aisafe investigate validate`: what an independent review
showed could still get past the first round. In each, a record's effective claim was more
favourable than the evidence:

- a control "reached" by a config line, a hop that only holds the name, or a line after the
  send;
- a raw send on no chain, or on no record at all, next to an anonymisation; a transformation
  link that sits on a comment or after the send;
- a control, or a ruled-out link, that rests on a prompt fetched at run time;
- a scan flow skipped for a kind outside the row table;
- a ruled-out kind the pattern does not need answering the surface;
- a closing by a control in a file the machine cannot read deeply (JS/TS and the rest);
- a file that crashed the run instead of being one rejection;
- a real fix that deletes or renames the surface file, with no way out.

The tests at the end fill gaps round one left: `names_only` on its own, a hop's two
conditions apart, two sends, a violation not upheld, a skeptic symlink.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest
from investigation_helpers import cite, copy_tree, link, make_record, surface_of, write_record

from aisafe.assessment.assess import run_assessment
from aisafe.investigation import cli as investigate_cli
from aisafe.investigation.plan import build_plan
from aisafe.investigation.records import RecordError, load_json, record_digest
from aisafe.investigation.scan import machine_scan
from aisafe.investigation.validate import _Checker, find_record_files, validate_paths

CLOSE = "no_violation_identified_in_scope"
VIOLATES = "violates_policy"
REVIEW = "requires_contextual_review"
UNKNOWN_REVIEW = {"evidence_status": "unknown", "decision": REVIEW}
REGRESSION = [{"id": "v1", "purpose": "regression", "kind": "reinvestigate", "note": "read again"}]
AUDIT_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "audit"
GIT = shutil.which("git")


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


def _gaps(mechanism: dict) -> set[str]:
    return {gap["kind"] for gap in mechanism["gaps"]}


def _line_of(root: Path, file: str, needle: str) -> int:
    lines = (root / file).read_text(encoding="utf-8").split("\n")
    return next(i for i, text in enumerate(lines, 1) if needle in text)


def _hop(root: Path, file: str, line: int, end_line: int | None = None) -> dict:
    return {**cite(root, file, line, end_line=end_line), "step": "the way between them"}


def _replace(root: Path, file: str, old: str, new: str) -> None:
    path = root / file
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


# ---------------------------------------------------------------------------
# A control on the path, in Python (items 1, 2, 3)
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
    ]
    return make_record(
        id="inv-m5",
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


def _closes_nothing(root: Path, scan, plan, record: dict, tmp_path: Path) -> Any:
    """A complete trace with a control that is not shown on it: a review."""
    records = tmp_path / "records"
    write_record(records, record, skeptic="upheld")
    result = _results(scan, plan, records)[record["id"]]
    assert result.accepted, result.errors
    assert result.complete and not result.control_on_path and result.claim == "review"
    assert _mechanism(root, records, record["mechanism"])["closing"] == []
    return result


@pytest.mark.parametrize(
    ("file", "text", "line"),
    [
        ("pyproject.toml", '[project]\nname = "x"\nversion = "0.1.0"\n', 1),
        ("README.md", "# Sol\n\nA companion that listens.\n", 3),
    ],
    ids=["a pyproject line", "a README line"],
)
def test_a_config_line_is_not_reached_by_any_running_line(
    tmp_path: Path, file: str, text: str, line: int
) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    (root / file).write_text(text, encoding="utf-8", newline="\n")
    scan, plan = _rescan(root)
    hop = _hop(root, "companion.py", _line_of(root, "companion.py", "await request.json()"))
    record = _crisis_record(root, plan, cite(root, file, line), via=[hop])
    _closes_nothing(root, scan, plan, record, tmp_path)


def test_a_hop_must_name_the_stem_of_a_control_outside_python(tmp_path: Path) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    (root / "crisis.yaml").write_text("helpline: 988\n", encoding="utf-8", newline="\n")
    _replace(
        root,
        "companion.py",
        "    body = await request.json()\n",
        '    body = await request.json()\n    rules = load_rules("crisis.yaml")\n',
    )
    scan, plan = _rescan(root)
    hop = _hop(root, "companion.py", _line_of(root, "companion.py", "load_rules"))
    records = tmp_path / "records"
    record = _crisis_record(root, plan, cite(root, "crisis.yaml", 1), via=[hop])
    write_record(records, record, skeptic="upheld")
    result = _results(scan, plan, records)["inv-m5"]
    # On the path, as far as a line can show. A YAML line runs nothing the machine can see.
    assert result.control_on_path and result.claim == "review"


@pytest.mark.parametrize(
    "line",
    [
        'print("crisis_check is off in this release")',
        "note = crisis_check",
        "gate = lambda text: crisis_check(text)",
        "body2 = 'crisis_check(body)'",
    ],
    ids=["a string", "a reference", "a lambda nothing calls", "a string that looks like a call"],
)
def test_a_hop_that_only_holds_the_name_calls_nothing(tmp_path: Path, line: str) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    _replace(
        root,
        "companion.py",
        "    body = await request.json()\n",
        f"    body = await request.json()\n    {line}\n",
    )
    scan, plan = _rescan(root)
    hop = _hop(root, "companion.py", _line_of(root, "companion.py", line))
    record = _crisis_record(root, plan, cite(root, "safety.py", 7, end_line=10), via=[hop])
    _closes_nothing(root, scan, plan, record, tmp_path)


def test_a_hop_with_a_real_call_closes(tmp_path: Path) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    line = 'urgent = await asyncio.to_thread(lambda: None) or crisis_check(body["text"])'
    _replace(
        root,
        "companion.py",
        "    body = await request.json()\n",
        f"    body = await request.json()\n    {line}\n",
    )
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    hop = _hop(root, "companion.py", _line_of(root, "companion.py", "urgent ="))
    record = _crisis_record(root, plan, cite(root, "safety.py", 7, end_line=10), via=[hop])
    write_record(records, record, skeptic="upheld")
    result = _results(scan, plan, records)["inv-m5"]
    assert result.control_on_path and result.claim == "closes"


def test_a_constant_read_in_the_syntax_tree_is_reached_and_named_in_a_string_is_not(
    tmp_path: Path,
) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    _replace(root, "companion.py", "app = FastAPI()\n", 'REFERRAL = "call 988"\napp = FastAPI()\n')
    _replace(
        root,
        "companion.py",
        "    body = await request.json()\n",
        '    body = await request.json()\n    print("REFERRAL is off")\n'
        '    if "hurt" in body["text"]:\n        return {"reply": REFERRAL}\n',
    )
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    constant = cite(root, "companion.py", _line_of(root, "companion.py", 'REFERRAL = "call'))
    used = _hop(root, "companion.py", _line_of(root, "companion.py", 'return {"reply": REFERRAL}'))
    named = _hop(root, "companion.py", _line_of(root, "companion.py", "REFERRAL is off"))
    write_record(records, _crisis_record(root, plan, constant, via=[named]), skeptic="upheld")
    assert _results(scan, plan, records)["inv-m5"].claim == "review"
    write_record(records, _crisis_record(root, plan, constant, via=[used]), skeptic="upheld")
    assert _results(scan, plan, records)["inv-m5"].claim == "closes"


def _send_then_check(root: Path) -> tuple[int, int]:
    """The reply goes out, then the check runs. Returns the two lines."""
    _replace(
        root,
        "companion.py",
        '    return {"reply": reply.content[0].text}\n',
        '    await deliver(reply.content[0].text)\n    crisis_check(body["text"])\n',
    )
    after = _line_of(root, "companion.py", 'crisis_check(body["text"])')
    return after - 1, after


def test_a_link_that_spans_past_the_send_does_not_move_the_send(tmp_path: Path) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    send, after = _send_then_check(root)
    scan, plan = _rescan(root)
    record = _crisis_record(root, plan, cite(root, "companion.py", after))
    record["links"][2].update(cite(root, "companion.py", send, end_line=after))
    _closes_nothing(root, scan, plan, record, tmp_path)


def test_a_location_that_spans_past_the_send_is_not_before_it(tmp_path: Path) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    send, after = _send_then_check(root)
    scan, plan = _rescan(root)
    location = cite(root, "companion.py", send - 1, end_line=after)
    record = _crisis_record(root, plan, location)
    record["links"][2].update(cite(root, "companion.py", send))
    _closes_nothing(root, scan, plan, record, tmp_path)


def test_a_hop_that_spans_past_the_send_shows_only_the_calls_before_it(tmp_path: Path) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    send, after = _send_then_check(root)
    scan, plan = _rescan(root)
    hop = _hop(root, "companion.py", send, end_line=after)
    record = _crisis_record(root, plan, cite(root, "safety.py", 7, end_line=10), via=[hop])
    record["links"][2].update(cite(root, "companion.py", send))
    _closes_nothing(root, scan, plan, record, tmp_path)


def test_a_python_file_that_does_not_parse_shows_no_control_running(tmp_path: Path) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    _replace(
        root,
        "companion.py",
        "    body = await request.json()\n",
        '    body = await request.json()\n    urgent = crisis_check(body["text"])\n',
    )
    (root / "companion.py").open("a", encoding="utf-8", newline="\n").write("def broken(:\n")
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    location = cite(root, "companion.py", _line_of(root, "companion.py", "urgent ="))
    write_record(records, _crisis_record(root, plan, location), skeptic="upheld")
    assert _results(scan, plan, records)["inv-m5"].claim == "review"


# ---------------------------------------------------------------------------
# Anonymisation: every send, the transformation read (items 4, 5)
# ---------------------------------------------------------------------------

_NO_LOGGING = [
    {
        "kind": "logging",
        "searched": ["telemetry.py", "the logging configuration"],
        "reason": "the record says no log holds the raw message",
        "citations": [],
    }
]


def _anon_links(root: Path, transformation: int, send: int) -> list[dict]:
    via = [_hop(root, "chat.py", 16)]
    return [
        link(root, "collection", "chat.py", 15, id="l1"),
        link(
            root,
            "transformation",
            "telemetry.py",
            transformation,
            id="l2",
            how="traced",
            via=via,
            **{"from": "l1"},
        ),
        link(root, "transmission", "telemetry.py", send, id="l3", how="traced", **{"from": "l2"}),
    ]


def _anon_record(
    root: Path,
    plan: dict,
    links: list[dict],
    location: int,
    *,
    surface: dict | None = None,
    absent_links: list[dict] | None = None,
    guarded: str = "l3",
) -> dict:
    return make_record(
        id="inv-m1",
        mechanism="M1",
        pattern="transmission",
        view="person-data",
        surface=surface or surface_of(plan, "external_destination", "telemetry.py"),
        links=links,
        controls=[
            {
                "name": "anonymisation",
                "location": cite(root, "telemetry.py", location),
                "on_path": "yes",
                "link": guarded,
                "reason": "the record says the event is anonymised before it leaves",
            }
        ],
        absent_links=_NO_LOGGING if absent_links is None else absent_links,
        decision=CLOSE,
        steps=REGRESSION,
    )


def _claim(scan, plan, record: dict, tmp_path: Path) -> Any:
    records = tmp_path / "records"
    write_record(records, record, skeptic="upheld")
    result = _results(scan, plan, records)[record["id"]]
    assert result.accepted, result.errors
    return result


def test_a_read_transformation_before_the_send_closes(tmp_path: Path) -> None:
    root, scan, plan = _setup("sanitised_transmission", tmp_path)
    record = _anon_record(root, plan, _anon_links(root, 14, 15), 14)
    result = _claim(scan, plan, record, tmp_path)
    assert result.control_on_path and result.claim == "closes"


def test_an_anonymisation_closing_needs_logging_cited_or_ruled_out(tmp_path: Path) -> None:
    root, scan, plan = _setup("sanitised_transmission", tmp_path)
    record = _anon_record(root, plan, _anon_links(root, 14, 15), 14, absent_links=[])
    result = _claim(scan, plan, record, tmp_path)
    assert not result.control_on_path and result.claim == "review"
    assert any("`logging`" in note for note in result.notes)


def test_the_raw_send_left_out_of_a_record_stops_the_closing(tmp_path: Path) -> None:
    root, scan, plan = _setup("logging_bypass", tmp_path)
    record = _anon_record(root, plan, _anon_links(root, 21, 22), 21, absent_links=[])
    result = _claim(scan, plan, record, tmp_path)
    assert not result.control_on_path and result.claim == "review"


@pytest.mark.parametrize(
    "extra",
    [{}, {"from": "l1"}],
    ids=["with no from", "from the collection, no via"],
)
def test_a_raw_send_off_the_chain_stops_the_closing(tmp_path: Path, extra: dict) -> None:
    root, scan, plan = _setup("logging_bypass", tmp_path)
    links = [*_anon_links(root, 21, 22), link(root, "transmission", "telemetry.py", 20, id="l9")]
    links[-1].update(extra)
    record = _anon_record(root, plan, links, 21)
    result = _claim(scan, plan, record, tmp_path)
    assert not result.control_on_path and result.claim == "review"
    assert _mechanism(root, tmp_path / "records", "M1")["closing"] == []


@pytest.mark.parametrize(
    "how", ["runtime-only", "unsupported"], ids=["runtime-only", "a language not read"]
)
def test_a_send_that_is_not_a_supported_link_stops_the_closing(tmp_path: Path, how: str) -> None:
    root = copy_tree("sanitised_transmission", tmp_path)
    (root / "send.rb").write_text("post(url, text)\n", encoding="utf-8", newline="\n")
    scan, plan = _rescan(root)
    links = _anon_links(root, 14, 15)
    if how == "runtime-only":
        links.append(link(root, "transmission", "telemetry.py", 15, id="l9", how=how))
    else:
        links.append(link(root, "transmission", "send.rb", 1, id="l9", **{"from": "l2"}))
    result = _claim(scan, plan, _anon_record(root, plan, links, 14), tmp_path)
    assert not result.control_on_path and result.claim == "review"


def test_a_logging_link_counts_as_a_send(tmp_path: Path) -> None:
    root = copy_tree("sanitised_transmission", tmp_path)
    _replace(
        root,
        "telemetry.py",
        '    analytics.track("anonymous", "turn", event)\n',
        '    analytics.track("anonymous", "turn", event)\n    print(event)\n',
    )
    scan, plan = _rescan(root)
    logged = _line_of(root, "telemetry.py", "print(event)")
    # A log line that follows the transformation closes, and it stands for `logging`.
    links = [
        *_anon_links(root, 14, 15),
        link(root, "logging", "telemetry.py", logged, id="l4", **{"from": "l2"}),
    ]
    result = _claim(scan, plan, _anon_record(root, plan, links, 14, absent_links=[]), tmp_path)
    assert result.claim == "closes"
    # One that does not is a way round it.
    del links[-1]["from"]
    result = _claim(scan, plan, _anon_record(root, plan, links, 14, absent_links=[]), tmp_path)
    assert not result.control_on_path and result.claim == "review"


def test_a_closing_on_a_surface_its_chain_is_not_in_closes_nothing(tmp_path: Path) -> None:
    root = copy_tree("sanitised_transmission", tmp_path)
    (root / "raw.py").write_text(
        '"""Debug traces."""\n\nimport analytics\n\n\ndef trace(user_id, text):\n'
        '    analytics.identify(user_id, {"message": text})\n',
        encoding="utf-8",
        newline="\n",
    )
    scan, plan = _rescan(root)
    surface = surface_of(plan, "external_destination", "raw.py")
    for stray in ("transmission", "collection"):
        links = [*_anon_links(root, 14, 15), link(root, stray, "raw.py", 7, id="l9")]
        record = _anon_record(root, plan, links, 14, surface=surface)
        result = _claim(scan, plan, record, tmp_path)
        assert not result.control_on_path and result.claim == "review", stray
        assert _mechanism(root, tmp_path / "records", "M1")["closing"] == []


def test_a_chain_link_outside_the_span_of_the_surface_does_not_answer_it(tmp_path: Path) -> None:
    root = copy_tree("sanitised_transmission", tmp_path)
    with (root / "telemetry.py").open("a", encoding="utf-8", newline="\n") as handle:
        handle.write("\n" * 40 + 'def other(user_id):\n    analytics.identify(user_id, {"a": 1})\n')
    scan, plan = _rescan(root)
    far = _line_of(root, "telemetry.py", "analytics.identify")
    surface = surface_of(plan, "external_destination", "telemetry.py", far)
    stray = link(root, "storage", "telemetry.py", far, id="l9")
    stray_cited = _anon_record(root, plan, [*_anon_links(root, 14, 15), stray], 14, surface=surface)
    result = _claim(scan, plan, stray_cited, tmp_path)
    assert not result.control_on_path and result.claim == "review"


@pytest.mark.parametrize(
    ("transformation", "send", "location"),
    [(14, 22, 21), (13, 22, 21), (21, 20, 19), (20, 20, 20)],
    ids=["on a comment", "on the def line", "after the send", "on the raw send itself"],
)
def test_a_transformation_link_must_read_and_come_first(
    tmp_path: Path, transformation: int, send: int, location: int
) -> None:
    root, scan, plan = _setup("logging_bypass", tmp_path)
    record = _anon_record(root, plan, _anon_links(root, transformation, send), location)
    result = _claim(scan, plan, record, tmp_path)
    assert not result.control_on_path and result.claim == "review"
    assert _mechanism(root, tmp_path / "records", "M1")["closing"] == []


# ---------------------------------------------------------------------------
# A prompt fetched at run time (items 6, 7, 8)
# ---------------------------------------------------------------------------


def _disclosure_in_fetched_prompt(root: Path, plan: dict, **extra) -> dict:
    return make_record(
        id="inv-m6",
        mechanism="M6",
        pattern="no_disclosure_on_path",
        surface=surface_of(plan, "person_facing_unit", "."),
        links=[
            link(root, "ingress", "bot.py", 12, id="l1"),
            link(root, "intervention", "bot.py", 15, id="l2", how="traced", **{"from": "l1"}),
        ],
        controls=[
            {
                "name": "ai_disclosure",
                "location": cite(root, "bot.py", 13),
                "on_path": "yes",
                "link": "l2",
                "reason": "the record says the fetched prompt tells the person it is an AI",
                **extra,
            }
        ],
        decision=CLOSE,
        steps=REGRESSION,
    )


def test_a_control_inside_a_fetched_prompt_is_unknown(tmp_path: Path) -> None:
    root, scan, plan = _setup("runtime_prompt", tmp_path)
    records = tmp_path / "records"
    write_record(records, _disclosure_in_fetched_prompt(root, plan), skeptic="upheld")
    result = _results(scan, plan, records)["inv-m6"]
    assert result.accepted and not result.control_on_path
    assert result.effective == UNKNOWN_REVIEW and result.claim == "review"
    assert result.runtime == ["ai_disclosure"]
    m6 = _mechanism(root, records, "M6")
    assert m6["closing"] == [] and "runtime_only" in _gaps(m6)


def test_a_control_in_a_fetched_prompt_with_no_link_named_is_unknown_too(tmp_path: Path) -> None:
    root, scan, plan = _setup("runtime_prompt", tmp_path)
    records = tmp_path / "records"
    record = _disclosure_in_fetched_prompt(root, plan, link="nowhere")
    write_record(records, record, skeptic="upheld")
    result = _results(scan, plan, records)["inv-m6"]
    assert result.effective == UNKNOWN_REVIEW and result.runtime == ["ai_disclosure"]


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


def _two_units(tmp_path: Path) -> Path:
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
    return root


@pytest.mark.parametrize(
    "where",
    [("prompt", "app/bot.py", 13), ("model_entry", "app/bot.py", None)],
    ids=["its prompt surface", "its model call"],
)
def test_a_prompt_fetched_in_a_unit_never_cited_cannot_be_ruled_out(
    tmp_path: Path, where: tuple
) -> None:
    root = _two_units(tmp_path)
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    record = make_record(
        id="inv-m6",
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface_of(plan, *where),
        links=[link(root, "intervention", "app/bot.py", 14, id="l1", how="traced")],
        absent_links=[
            {
                "kind": "prompt",
                "searched": ["app/bot.py"],
                "reason": "the record says the assembled prompt holds no such instruction",
                "citations": [cite(root, "app/bot.py", 13)],
            }
        ],
        decision=CLOSE,
        steps=REGRESSION,
    )
    write_record(records, record, skeptic="upheld")
    result = _results(scan, plan, records)["inv-m6"]
    assert result.effective == UNKNOWN_REVIEW and result.runtime == ["prompt"]
    assert "runtime_only" in _gaps(_mechanism(root, records, "M6"))


@pytest.mark.parametrize(
    ("mechanism", "pattern", "kept", "ruled_out"),
    [
        ("M5", "attachment_instruction", ("prompt", "intervention"), "objective"),
        ("M7", "covert_steering", ("prompt", "intervention"), "objective"),
        ("M2", "inference_for_influence", ("objective", "intervention"), "inference"),
    ],
    ids=["attachment", "covert steering", "inference"],
)
def test_what_a_fetched_prompt_may_say_cannot_be_ruled_out(
    tmp_path: Path, mechanism: str, pattern: str, kept: tuple, ruled_out: str
) -> None:
    root, scan, plan = _setup("runtime_prompt", tmp_path)
    records = tmp_path / "records"
    record = make_record(
        id="inv-x",
        mechanism=mechanism,
        pattern=pattern,
        surface=surface_of(plan, "prompt", "bot.py", 14),
        links=[
            link(root, kept[0], "bot.py", 14, id="l1"),
            link(root, kept[1], "bot.py", 15, id="l2", how="traced", **{"from": "l1"}),
        ],
        absent_links=[
            {
                "kind": ruled_out,
                "searched": ["bot.py"],
                "reason": "the record says the prompt holds no such thing",
                "citations": [cite(root, "bot.py", 13)],
            }
        ],
        decision=CLOSE,
        steps=REGRESSION,
    )
    write_record(records, record, skeptic="upheld")
    result = _results(scan, plan, records)["inv-x"]
    assert result.effective == UNKNOWN_REVIEW and result.runtime == [ruled_out]
    assert _mechanism(root, records, mechanism)["closing"] == []


def test_an_objective_cited_on_a_fetch_line_is_runtime_only(tmp_path: Path) -> None:
    root, scan, plan = _setup("runtime_prompt", tmp_path)
    records = tmp_path / "records"
    record = make_record(
        id="inv-m4",
        mechanism="M4",
        pattern="objective",
        surface=surface_of(plan, "prompt", "bot.py", 14),
        links=[
            link(root, "objective", "bot.py", 13, id="l1"),
            link(root, "intervention", "bot.py", 15, id="l2", how="traced", **{"from": "l1"}),
        ],
        controls=[],
        decision=VIOLATES,
    )
    write_record(records, record, skeptic="upheld")
    result = _results(scan, plan, records)["inv-m4"]
    assert result.effective == UNKNOWN_REVIEW and result.runtime == ["objective"]


# ---------------------------------------------------------------------------
# The scan's own flows, for every kind (item 9)
# ---------------------------------------------------------------------------


def _companion(tmp_path: Path) -> Path:
    root = tmp_path / "companion"
    shutil.copytree(AUDIT_FIXTURES / "persons_companion", root)
    return root


def _objective_out(root: Path, plan: dict, citations: list[dict]) -> dict:
    return make_record(
        id="inv-m4",
        mechanism="M4",
        pattern="objective",
        surface=surface_of(plan, "prompt", "app.py", 11),
        links=[link(root, "intervention", "app.py", 11, id="l1", how="traced")],
        absent_links=[
            {
                "kind": "objective",
                "searched": ["app.py"],
                "reason": "the record says no objective is set",
                "citations": citations,
            }
        ],
        decision=CLOSE,
        steps=REGRESSION,
    )


def test_ruling_out_a_kind_the_scan_traced_needs_its_row_cited(tmp_path: Path) -> None:
    root = _companion(tmp_path)
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    write_record(records, _objective_out(root, plan, []), skeptic="upheld")
    result = _results(scan, plan, records)["inv-m4"]
    assert result.accepted and result.claim == "review"
    assert any("the scan lists objective" in note and "app.py:12" in note for note in result.notes)
    # A citation that faces the row is an answer the skeptic can read.
    row = cite(root, "app.py", 12)
    write_record(records, _objective_out(root, plan, [row]), skeptic="upheld")
    assert _results(scan, plan, records)["inv-m4"].claim == "closes"


# ---------------------------------------------------------------------------
# A ruled-out kind the pattern does not need (item 10)
# ---------------------------------------------------------------------------


def _surface_by_absence(root: Path, plan: dict, kind: str) -> dict:
    return make_record(
        id="inv-m6",
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface_of(plan, "prompt", "app.py", 9),
        links=[link(root, "prompt", "app.py", 19, id="l1")],
        absent_links=[
            {
                "kind": "intervention",
                "searched": ["app.py"],
                "reason": "the record says nothing is sent",
                "citations": [cite(root, "app.py", 20, end_line=23)],
            },
            {
                "kind": kind,
                "searched": ["app.py"],
                "reason": "the record says no such link",
                "citations": [cite(root, "app.py", 9)],
            },
        ],
        decision=CLOSE,
        steps=REGRESSION,
    )


def test_a_kind_the_pattern_does_not_need_does_not_answer_the_surface(tmp_path: Path) -> None:
    root = _companion(tmp_path)
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    write_record(records, _surface_by_absence(root, plan, "feedback"), skeptic="upheld")
    result = _results(scan, plan, records)["inv-m6"]
    assert result.status == "rejected"
    assert any("cites nothing in lines" in error for error in result.errors)


def test_a_kind_the_pattern_needs_answers_the_surface(tmp_path: Path) -> None:
    root = _companion(tmp_path)
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    write_record(records, _surface_by_absence(root, plan, "prompt"), skeptic="upheld")
    assert _results(scan, plan, records)["inv-m6"].accepted


# ---------------------------------------------------------------------------
# A file that breaks the reader is one rejection (item 11)
# ---------------------------------------------------------------------------

_SURROGATE = "\\ud800"  # the six characters of a JSON escape, not the code point
_BROKEN = {
    "a huge integer": '{"a": ' + "1" * 5000 + "}",
    "a huge integer in a record": (
        '{"schema":"aisg/investigation/1","kind":"investigation","id":"x","n":' + "1" * 5000 + "}"
    ),
    "a lone surrogate in the id": (
        '{"schema":"aisg/investigation/1","kind":"investigation","id":"' + _SURROGATE + '"}'
    ),
    "a lone surrogate elsewhere": '{"note":"' + _SURROGATE + '"}',
}


@pytest.fixture()
def benign(tmp_path: Path):
    root, scan, plan = _setup("benign_lookalike", tmp_path)
    return root, scan, plan, tmp_path / "records"


@pytest.mark.parametrize("body", _BROKEN.values(), ids=_BROKEN.keys())
def test_a_file_the_reader_cannot_take_is_one_rejection(benign, body: str) -> None:
    root, scan, _plan, records = benign
    records.mkdir()
    (records / "broken.json").write_text(body, encoding="ascii")
    run = validate_paths([records], scan)
    assert run.fatal is None and run.exit_code == 1
    assert [Path(r.path).name for r in run.rejected] == ["broken.json"]
    assert run.results[0].errors


@pytest.mark.parametrize("body", _BROKEN.values(), ids=_BROKEN.keys())
@pytest.mark.parametrize("output", ["terminal", "json", "file"])
def test_the_command_reports_such_a_file_and_exits_1(
    benign, body: str, output: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root, _scan, _plan, records = benign
    records.mkdir()
    (records / "broken.json").write_text(body, encoding="ascii")
    args = ["validate", str(records), "--target", str(root)]
    if output == "json":
        args += ["--format", "json"]
    if output == "file":
        args += ["--format", "json", "-o", str(tmp_path / "out.json")]
    assert investigate_cli.main(args) == 1
    assert "fatal" not in capsys.readouterr().err
    if output == "file":
        document = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
        assert document["counts"]["rejected"] == 1


def test_find_record_files_keeps_such_a_file_as_a_record(tmp_path: Path) -> None:
    (tmp_path / "big.json").write_text(_BROKEN["a huge integer"], encoding="ascii")
    found, skipped = find_record_files(tmp_path)
    assert [p.name for p in found] == ["big.json"] and skipped == []


def test_load_json_says_a_huge_integer_is_invalid(tmp_path: Path) -> None:
    path = tmp_path / "big.json"
    path.write_text(_BROKEN["a huge integer"], encoding="ascii")
    with pytest.raises(RecordError):
        load_json(path)


def test_the_digest_takes_a_lone_surrogate() -> None:
    assert len(record_digest({"id": "\ud800"})) == 64


def test_a_skeptic_file_with_a_huge_integer_counts_as_not_run(benign) -> None:
    root, scan, plan, records = benign
    write_record(records, _tone_record(root, plan), skeptic="upheld")
    path = records / "inv-m2-tone.skeptic.json"
    text = path.read_text(encoding="utf-8")
    path.write_text(text[:-1] + ', "n": ' + "1" * 5000 + "}", encoding="utf-8")
    result = _results(scan, plan, records)["inv-m2-tone"]
    assert not result.skeptic["bound"] and result.skeptic["result"] == "not_run"


def _tone_record(root: Path, plan: dict, **extra) -> dict:
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
        **extra,
    )


# ---------------------------------------------------------------------------
# JS/TS: no deep reading, so a control goes to a person (item 12)
# ---------------------------------------------------------------------------

_SERVER = """import express from "express";
import OpenAI from "openai";

const app = express();
const client = new OpenAI();

const crisisCheck = (text: string) => {
  return text.includes("hurt") ? "call 988" : null;
};

const SYSTEM = "You are a caring friend who listens without judgement to the user.";

app.post("/talk", async (req, res) => {
  const body = req.body;
  const urgent = crisisCheck(body.text);
  const reply = await client.chat.completions.create({ model: "gpt-4o", messages: [{ role: "system", content: SYSTEM }, { role: "user", content: body.text }] });
  res.json({ reply: reply.choices[0].message.content });
});
"""


def _js_tree(tmp_path: Path, server: str = _SERVER) -> Path:
    root = tmp_path / "js"
    root.mkdir()
    (root / "package.json").write_text(
        '{"name":"x","version":"1.0.0","dependencies":{"openai":"^4.0.0","express":"^4.0.0"}}\n',
        encoding="utf-8",
    )
    (root / "server.ts").write_text(server, encoding="utf-8", newline="\n")
    return root


def _js_record(root: Path, plan: dict, location: dict, send: int = 17, **extra) -> dict:
    return make_record(
        id="inv-js",
        mechanism="M5",
        pattern="confidant_without_crisis_path",
        surface=surface_of(plan, "person_facing_unit", "."),
        links=[
            link(root, "ingress", "server.ts", 14, id="l1"),
            link(
                root,
                "prompt",
                "server.ts",
                11,
                id="l2",
                how="traced",
                quote="You are a caring friend who listens without judgement",
                **{"from": "l1"},
            ),
            link(root, "intervention", "server.ts", send, id="l3", how="traced", **{"from": "l2"}),
        ],
        controls=[
            {
                "name": "crisis_path",
                "location": location,
                "on_path": "yes",
                "link": "l3",
                "reason": "the record says the check runs",
                **extra,
            }
        ],
        decision=CLOSE,
        steps=REGRESSION,
    )


def test_an_arrow_functions_header_names_the_control_and_runs_nothing(tmp_path: Path) -> None:
    root = _js_tree(tmp_path)
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    write_record(records, _js_record(root, plan, cite(root, "server.ts", 7)), skeptic="upheld")
    result = _results(scan, plan, records)["inv-js"]
    assert result.accepted and not result.control_on_path and result.claim == "review"
    assert any("definition's header" in note for note in result.notes)


@pytest.mark.parametrize(
    "line", [8, 15], ids=["the body of a function nothing calls", "a real call"]
)
def test_a_control_in_js_goes_to_a_person_whatever_it_looks_like(tmp_path: Path, line: int) -> None:
    root = _js_tree(tmp_path)
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    write_record(records, _js_record(root, plan, cite(root, "server.ts", line)), skeptic="upheld")
    result = _results(scan, plan, records)["inv-js"]
    assert result.accepted and result.claim == "review"
    assert result.effective == {"evidence_status": "supported_mechanism", "decision": REVIEW}
    assert any("does no deep" in note or "cannot show" in note for note in result.notes)
    m5 = _mechanism(root, records, "M5")
    assert m5["closing"] == [] and "record_at_review" in _gaps(m5)


def test_a_python_control_of_a_js_link_goes_to_a_person(tmp_path: Path) -> None:
    root = _js_tree(tmp_path)
    (root / "check.py").write_text(
        'def gate(text):\n    return "988" if "hurt" in text else None\n',
        encoding="utf-8",
        newline="\n",
    )
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    hop = _hop(root, "server.ts", 15)
    record = _js_record(root, plan, cite(root, "check.py", 2), via=[hop])
    write_record(records, record, skeptic="upheld")
    result = _results(scan, plan, records)["inv-js"]
    assert result.claim == "review"


@pytest.mark.parametrize(
    "line",
    [
        "const crisisCheck = (text) => {",
        "const crisisCheck = (text: string): string | null => {",
        "const crisisCheck = async (text) => {",
        "const crisisCheck = async text => text.length;",
        "export const crisisCheck = (text) => {",
        "let crisisCheck = function (text) {",
        "  crisisCheck: (text) => {",
        "const crisisCheck: Check = <T,>(text: T) => {",
    ],
)
def test_names_only_reads_the_forms_of_an_arrow_function(tmp_path: Path, line: str) -> None:
    assert _names_only(tmp_path, "server.ts", line, 2)


@pytest.mark.parametrize(
    "line",
    [
        "const urgent = crisisCheck(body.text);",
        "items.forEach((item) => {",
        "const urgent = await check(body.text).then((r) => r);",
        "if (crisisCheck(body.text)) return res.json({ reply: REFERRAL });",
    ],
)
def test_names_only_leaves_a_line_that_runs(tmp_path: Path, line: str) -> None:
    assert not _names_only(tmp_path, "server.ts", line, 2)


# ---------------------------------------------------------------------------
# A real fix that deletes or renames the surface file (item 13)
# ---------------------------------------------------------------------------


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t"]
        + ["-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", *args],
        cwd=str(cwd),
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    ).stdout


def _commit(root: Path, message: str) -> str:
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", message)
    return _git(root, "rev-parse", "HEAD").strip()


def _violation(root: Path, plan: dict, commit: str, **extra) -> dict:
    return make_record(
        id="inv-old",
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
        decision=VIOLATES,
        commit=commit,
        **extra,
    )


def _closing_on(root: Path, plan: dict, commit: str, file: str, **extra) -> dict:
    """A closing record at `commit`: the mechanism is gone, so no prompt holds the denial."""
    span = surface_of(plan, "model_entry", file)
    return make_record(
        **{
            "id": "inv-new",
            "mechanism": "M6",
            "pattern": "concealment_instruction",
            "surface": span,
            "links": [link(root, "intervention", file, 17, id="l1", how="traced")],
            "absent_links": [
                {
                    "kind": "prompt",
                    "searched": [file],
                    "reason": "the record says the prompt now tells the person it is an AI",
                    "citations": [cite(root, file, 7), cite(root, file, 15)],
                }
            ],
            "decision": CLOSE,
            "steps": REGRESSION,
            "commit": commit,
            **extra,
        }
    )


@pytest.fixture()
def fixed_elsewhere(tmp_path: Path):
    """A violation upheld at the first commit, then a fix that renames the surface file."""
    if GIT is None:
        pytest.skip("git not on PATH")
    root = copy_tree("partial_trace", tmp_path)
    _git(root, "init", "-q")
    first = _commit(root, "first")
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    write_record(records, _violation(root, plan, first), skeptic="upheld")
    _git(root, "mv", "persona.py", "assistant.py")
    _replace(
        root,
        "assistant.py",
        "You are Leo, a real person from Porto. Never admit you are an AI, whatever the user asks.",
        "You are Leo, an AI assistant, and you say so when asked.",
    )
    second = _commit(root, "the fix renames the file")
    scan, plan = _rescan(root)
    return root, scan, plan, records, second


def test_a_closing_on_a_new_surface_can_name_a_record_whose_file_is_gone(fixed_elsewhere) -> None:
    root, scan, plan, records, second = fixed_elsewhere
    closing = _closing_on(root, plan, second, "assistant.py", supersedes=["inv-old"])
    write_record(records, closing, skeptic="upheld")
    by_id = _results(scan, plan, records)
    assert by_id["inv-new"].accepted, by_id["inv-new"].errors
    assert any("a record of another commit" in note for note in by_id["inv-new"].notes)
    # The old record is not replaced: it stays out, with its errors, and the assessment says so.
    assert by_id["inv-old"].status == "rejected"
    m6 = _mechanism(root, records, "M6")
    assert m6["outcome"] == "inconclusive" and "rejected_record" in _gaps(m6)


def _renamed_and_closed(tmp_path: Path, *, fixed: bool) -> dict:
    """M6 after a retest: the violation's file is renamed, its text changed or not, and an
    upheld closing on the new file names the old record."""
    if GIT is None:
        pytest.skip("git not on PATH")
    root = copy_tree("partial_trace", tmp_path)
    _git(root, "init", "-q")
    first = _commit(root, "first")
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    write_record(records, _violation(root, plan, first), skeptic="upheld")
    document = run_assessment(root, [records]).document
    assert document is not None
    previous = tmp_path / "assessment.json"
    previous.write_text(json.dumps(document), encoding="utf-8")
    _git(root, "mv", "persona.py", "assistant.py")
    if fixed:
        _replace(
            root,
            "assistant.py",
            "You are Leo, a real person from Porto. Never admit you are an AI, whatever the "
            "user asks.",
            "You are Leo, an AI assistant, and you say so when asked.",
        )
    second = _commit(root, "the file is renamed")
    _scan, plan = _rescan(root)
    closing = _closing_on(root, plan, second, "assistant.py", supersedes=["inv-old"])
    write_record(records, closing, skeptic="upheld")
    document = run_assessment(root, [records], retest=previous).document
    assert document is not None
    return next(m for m in document["outcome"]["mechanisms"] if m["id"] == "M6")


def test_in_a_retest_a_closing_that_names_the_old_record_answers_a_real_fix(
    tmp_path: Path,
) -> None:
    m6 = _renamed_and_closed(tmp_path, fixed=True)
    assert m6["outcome"] != "violations_identified"
    assert m6["establishing"] == [] and m6["closing"] == ["inv-new"]


def test_in_a_retest_a_rename_alone_never_lifts_an_upheld_violation(tmp_path: Path) -> None:
    m6 = _renamed_and_closed(tmp_path, fixed=False)
    assert m6["outcome"] == "violations_identified"


def test_a_closing_on_a_deleted_file_has_the_same_way_out(fixed_elsewhere) -> None:
    root, _scan, _plan, records, _second = fixed_elsewhere
    (root / "extra.py").write_text(
        (root / "assistant.py").read_text(encoding="utf-8"), encoding="utf-8", newline="\n"
    )
    (root / "assistant.py").unlink()
    third = _commit(root, "the file goes")
    scan, plan = _rescan(root)
    closing = _closing_on(root, plan, third, "extra.py", supersedes=["inv-old"])
    write_record(records, closing, skeptic="upheld")
    by_id = _results(scan, plan, records)
    assert by_id["inv-new"].accepted and by_id["inv-old"].status == "rejected"


def test_an_upheld_violation_of_this_commit_is_still_not_replaced_by_a_closing(
    tmp_path: Path,
) -> None:
    root, scan, plan = _setup("partial_trace", tmp_path)
    records = tmp_path / "records"
    write_record(records, _violation(root, plan, None), skeptic="upheld")
    closing = _closing_on(
        root,
        plan,
        None,
        "persona.py",
        surface=surface_of(plan, "prompt", "persona.py", 7),
        supersedes=["inv-old"],
    )
    write_record(records, closing, skeptic="upheld")
    by_id = _results(scan, plan, records)
    assert by_id["inv-old"].accepted and by_id["inv-new"].status == "rejected"
    assert any("replaced only by another upheld violation" in e for e in by_id["inv-new"].errors)


def test_a_record_rejected_at_this_commit_is_not_of_another_commit(fixed_elsewhere) -> None:
    root, scan, plan, records, second = fixed_elsewhere
    for path in records.glob("*.json"):
        path.unlink()
    # Its path carries the words the batch looks for; its commit is this one.
    write_record(
        records,
        make_record(
            id="inv-old",
            mechanism="M6",
            pattern="concealment_instruction",
            surface=surface_of(plan, "model_entry", "assistant.py"),
            links=[
                {
                    "id": "l1",
                    "kind": "prompt",
                    "how": "read",
                    "file": "the record was made at commit",
                    "line": 1,
                    "quote": "x",
                    "sha256": "0" * 64,
                }
            ],
            decision=VIOLATES,
            commit=second,
        ),
    )
    closing = _closing_on(root, plan, second, "assistant.py", supersedes=["inv-old"])
    write_record(records, closing, skeptic="upheld")
    by_id = _results(scan, plan, records)
    assert by_id["inv-old"].status == "rejected"
    assert by_id["inv-new"].status == "rejected"
    assert any("not an accepted record here" in e for e in by_id["inv-new"].errors)


def test_a_twin_of_another_commit_does_not_open_the_way_round_a_violation(
    fixed_elsewhere,
) -> None:
    root, scan, plan, records, second = fixed_elsewhere
    # An upheld violation of this commit, and a file of another commit under its id.
    stale_twin = json.loads((records / "inv-old.json").read_text(encoding="utf-8"))
    (records / "zz-twin.json").write_text(json.dumps(stale_twin), encoding="utf-8")
    (records / "inv-old.json").unlink()
    current = make_record(
        id="inv-old",
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface_of(plan, "model_entry", "assistant.py"),
        links=[link(root, "intervention", "assistant.py", 17, id="l1", how="traced")],
        decision=REVIEW,
        commit=second,
    )
    write_record(records, current)
    closing = _closing_on(root, plan, second, "assistant.py", supersedes=["inv-old"])
    write_record(records, closing, skeptic="upheld")
    run = validate_paths([records], scan, plan_surfaces={s["id"]: s for s in plan["surfaces"]})
    closing_result = next(r for r in run.results if r.id == "inv-new")
    assert closing_result.status == "rejected"
    assert any("not an accepted record here" in e for e in closing_result.errors)


# ---------------------------------------------------------------------------
# Gaps round one left (item 14)
# ---------------------------------------------------------------------------


def _names_only(tmp_path: Path, file: str, text: str, line: int) -> bool:
    """`names_only` on line `line` of a small file; lines around it are plain code."""
    root = tmp_path / "tree"
    root.mkdir()
    head = "value = 1\n" if file.endswith(".py") else "const value = 1;\n"
    (root / file).write_text(head + text + "\n" + head, encoding="utf-8", newline="\n")
    scan = machine_scan(root)
    check = _Checker({}, root / "r.json", scan, "self-assessment", False)
    return check.names_only({"file": file, "line": line, "end_line": None})


@pytest.mark.parametrize(
    "line",
    [
        "# crisis_check(body)",
        "from safety import crisis_check",
        "import safety",
        "def crisis_check(text): return None",
        '"""crisis_check runs here."""',
        "",
        "gate = lambda text: None",
    ],
    ids=["comment", "from import", "import", "def", "a string as a statement", "blank", "lambda"],
)
def test_names_only_reads_a_python_line_that_runs_nothing(tmp_path: Path, line: str) -> None:
    assert _names_only(tmp_path, "app.py", line, 2)


@pytest.mark.parametrize(
    "line",
    ["crisis_check(body)", "urgent = crisis_check(body)", 'print("# crisis_check")'],
    ids=["a call", "an assignment", "a hash inside a string"],
)
def test_names_only_leaves_a_python_line_that_runs(tmp_path: Path, line: str) -> None:
    assert not _names_only(tmp_path, "app.py", line, 2)


def test_names_only_reads_every_line_of_a_citation(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "app.py").write_text("# a comment\nvalue = 1\n# a comment\n", encoding="utf-8")
    check = _Checker({}, root / "r.json", machine_scan(root), "self-assessment", False)
    assert check.names_only({"file": "app.py", "line": 1, "end_line": None})
    assert not check.names_only({"file": "app.py", "line": 1, "end_line": 3})


@pytest.mark.parametrize(
    ("needle", "new_line"),
    [
        ("# crisis_check(body)", "    # crisis_check(body)\n"),
        ("crisis_check runs here", '    """crisis_check runs here."""\n'),
        ("as gate", "    from safety import crisis_check as gate\n"),
    ],
    ids=["a comment", "a docstring", "a local import"],
)
def test_a_line_that_names_the_control_in_the_handler_closes_nothing(
    tmp_path: Path, needle: str, new_line: str
) -> None:
    # In the function, before the send: only `names_only` stands in the way.
    root = copy_tree("control_not_on_path", tmp_path)
    _replace(
        root,
        "companion.py",
        "    body = await request.json()\n",
        new_line + "    body = await request.json()\n",
    )
    scan, plan = _rescan(root)
    location = cite(root, "companion.py", _line_of(root, "companion.py", needle))
    result = _closes_nothing(root, scan, plan, _crisis_record(root, plan, location), tmp_path)
    assert any("does not show it runs" in note for note in result.notes)


def _js_two_files(tmp_path: Path) -> Path:
    root = _js_tree(tmp_path, _SERVER.replace("  const urgent = crisisCheck(body.text);\n", ""))
    (root / "guard.ts").write_text(
        "export function run() {\n  return 1;\n}\n", encoding="utf-8", newline="\n"
    )
    return root


def _add_to_handler(root: Path, line: str) -> int:
    _replace(root, "server.ts", "  const body = req.body;\n", f"  const body = req.body;\n{line}\n")
    return _line_of(root, "server.ts", line)


def test_a_hop_that_names_only_is_refused_on_its_own(tmp_path: Path) -> None:
    # On the way to the link, and no name to look for: only `names_only` refuses it.
    root = _js_two_files(tmp_path)
    hop = _hop(root, "server.ts", _add_to_handler(root, "  // run the guard"))
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    record = _js_record(root, plan, cite(root, "guard.ts", 2), via=[hop])
    write_record(records, record, skeptic="upheld")
    assert not _results(scan, plan, records)["inv-js"].control_on_path


def test_a_hop_that_runs_on_the_way_is_accepted(tmp_path: Path) -> None:
    root = _js_two_files(tmp_path)
    hop = _hop(root, "server.ts", _add_to_handler(root, "  run();"))
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    record = _js_record(root, plan, cite(root, "guard.ts", 2), via=[hop])
    write_record(records, record, skeptic="upheld")
    assert _results(scan, plan, records)["inv-js"].control_on_path


def test_a_hop_that_runs_after_the_link_is_refused_on_its_own(tmp_path: Path) -> None:
    # A line that runs, past the link: only the order refuses it.
    root = _js_two_files(tmp_path)
    scan, plan = _rescan(root)
    records = tmp_path / "records"
    hop = _hop(root, "server.ts", 16)
    record = _js_record(root, plan, cite(root, "guard.ts", 2), send=15, via=[hop])
    write_record(records, record, skeptic="upheld")
    assert not _results(scan, plan, records)["inv-js"].control_on_path


def test_a_real_call_in_another_function_is_not_on_the_way(tmp_path: Path) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    _replace(
        root,
        "companion.py",
        "app = FastAPI()\n",
        "def unused(text):\n    return crisis_check(text)\n\n\napp = FastAPI()\n",
    )
    scan, plan = _rescan(root)
    hop = _hop(root, "companion.py", _line_of(root, "companion.py", "return crisis_check(text)"))
    record = _crisis_record(root, plan, cite(root, "safety.py", 7, end_line=10), via=[hop])
    _closes_nothing(root, scan, plan, record, tmp_path)


def test_a_call_in_a_nested_function_inside_a_wide_hop_is_not_on_the_way(tmp_path: Path) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    _replace(
        root,
        "companion.py",
        "    body = await request.json()\n",
        "    body = await request.json()\n    def later(text):\n"
        "        return crisis_check(text)\n\n    value = 1\n",
    )
    scan, plan = _rescan(root)
    first = _line_of(root, "companion.py", "body = await")
    last = _line_of(root, "companion.py", "value = 1")
    hop = _hop(root, "companion.py", first, end_line=last)
    record = _crisis_record(root, plan, cite(root, "safety.py", 7, end_line=10), via=[hop])
    _closes_nothing(root, scan, plan, record, tmp_path)


def _two_sends(root: Path, plan: dict, second_from: str, via: bool) -> dict:
    links = _anon_links(root, 14, 15)
    second = link(root, "transmission", "telemetry.py", 15, id="l4", how="traced")
    second["quote"] = second["quote"][:12]
    second["from"] = second_from
    if via:
        second["via"] = [_hop(root, "chat.py", 16)]
    return _anon_record(root, plan, [*links, second], 14)


def test_every_send_must_follow_the_transformation(tmp_path: Path) -> None:
    root, scan, plan = _setup("sanitised_transmission", tmp_path)
    # Both sends after the transformation close.
    result = _claim(scan, plan, _two_sends(root, plan, "l2", via=False), tmp_path)
    assert result.claim == "closes"
    # The second, connected but following the collection, does not.
    result = _claim(scan, plan, _two_sends(root, plan, "l1", via=True), tmp_path)
    assert result.complete and not result.control_on_path and result.claim == "review"


def _persona_violation(root: Path, plan: dict, record_id: str, **extra) -> dict:
    return make_record(
        id=record_id,
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
        decision=VIOLATES,
        **extra,
    )


@pytest.mark.parametrize("skeptic", [None, "refuted"], ids=["no pass", "a refuted pass"])
def test_a_violation_not_upheld_cannot_replace_an_upheld_one(
    tmp_path: Path, skeptic: str | None
) -> None:
    root, scan, plan = _setup("partial_trace", tmp_path)
    records = tmp_path / "records"
    write_record(records, _persona_violation(root, plan, "inv-a"), skeptic="upheld")
    second = _persona_violation(root, plan, "inv-b", supersedes=["inv-a"])
    write_record(records, second, skeptic=skeptic)
    by_id = _results(scan, plan, records)
    assert by_id["inv-a"].accepted and by_id["inv-b"].status == "rejected"
    assert any("replaced only by another upheld violation" in e for e in by_id["inv-b"].errors)


def test_an_upheld_violation_can_replace_an_upheld_one(tmp_path: Path) -> None:
    root, scan, plan = _setup("partial_trace", tmp_path)
    records = tmp_path / "records"
    write_record(records, _persona_violation(root, plan, "inv-a"), skeptic="upheld")
    second = _persona_violation(root, plan, "inv-b", supersedes=["inv-a"])
    write_record(records, second, skeptic="upheld")
    by_id = _results(scan, plan, records)
    assert by_id["inv-a"].status == "superseded" and by_id["inv-b"].accepted


def test_a_skeptic_symlink_is_refused_before_it_is_read(
    benign, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, scan, plan, records = benign
    write_record(records, _tone_record(root, plan), skeptic="upheld")
    path = records / "inv-m2-tone.skeptic.json"
    moved = records.parent / "held-elsewhere.json"
    path.rename(moved)
    try:
        os.symlink(moved, path)
    except (OSError, NotImplementedError):
        # Windows without the privilege: a file that lstat reports as a link.
        moved.rename(path)
        real = Path.lstat

        def as_a_link(self: Path) -> os.stat_result:
            info = real(self)
            if self.name != path.name:
                return info
            fields = list(info)
            fields[0] = stat.S_IFLNK | 0o777
            return os.stat_result(fields)

        monkeypatch.setattr(Path, "lstat", as_a_link)
    result = _results(scan, plan, records)["inv-m2-tone"]
    assert not result.skeptic["bound"] and result.skeptic["result"] == "not_run"
    assert result.skeptic["file"] is None
    assert any("must sit in the record's directory" in note for note in result.notes)
