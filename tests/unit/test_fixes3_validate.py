"""tests/unit/test_fixes3_validate.py
----------------------------------
Third-round regressions for `aisafe investigate validate`: what an independent review showed
by running it. In each, a record's effective claim was more favourable than the evidence. The
rule: when the machine cannot show something, the record goes to review, which a person can
sign. Each section also pins the honest code that must keep closing.

- a control line that never runs, in another arm, or that has no effect;
- "the same function" and "reaches" read from facts that could be wrong, or by name alone;
- a control guarding a link that says nothing of what reaches the person;
- a closing of a surface or a unit that never cited it;
- a transformation, or an edge between files, that nothing on the path reaches;
- links on comments; a prompt fetched at run time, on a line next to the row;
- a scan flow skipped for its pattern; verdict words with odd spacing; a skeptic claim with no
  reason; a three-record supersession; a closing that replaced a proposed violation.

True limits, pinned so a change to them is a decision: a location on any running line, a stub
in the same function, a real condition, `logging` ruled out over a real log line.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from investigation_helpers import cite, copy_tree, link, make_record, surface_of, write_record

from aisafe.assessment.assess import run_assessment
from aisafe.investigation.plan import build_plan
from aisafe.investigation.records import verdict_words_in
from aisafe.investigation.scan import machine_scan
from aisafe.investigation.text import file_lines
from aisafe.investigation.validate import validate_paths

CLOSE = "no_violation_identified_in_scope"
VIOLATES = "violates_policy"
REVIEW = "requires_contextual_review"
UNKNOWN_REVIEW = {"evidence_status": "unknown", "decision": REVIEW}
REGRESSION = [{"id": "v1", "purpose": "regression", "kind": "reinvestigate", "note": "read again"}]
AUDIT_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "audit"
HANDLER = "    body = await request.json()\n"
CHECK = '    urgent = crisis_check(body["text"])\n'
IMPORT = "from safety import crisis_check  # noqa: F401  (kept for the next release)\n"


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


def _line_of(root: Path, file: str, needle: str, nth: int = 0) -> int:
    lines = file_lines(root / file)
    return [i for i, text in enumerate(lines, 1) if needle in text][nth]


def _hop(root: Path, file: str, line: int) -> dict:
    return {**cite(root, file, line), "step": "the way between them"}


def _replace(root: Path, file: str, old: str, new: str) -> None:
    path = root / file
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


def _write(root: Path, file: str, text: str) -> None:
    (root / file).write_text(text, encoding="utf-8", newline="\n")


def _with_handler(tmp_path: Path, code: str) -> Path:
    root = copy_tree("control_not_on_path", tmp_path)
    _replace(root, "companion.py", HANDLER, HANDLER + code)
    return root


def _crisis_links(root: Path, plan: dict, location: dict, guarded: str) -> dict:
    """A closing with only the two links before the reply: the caller adds the reply."""
    record = make_record(
        id="inv-m5",
        mechanism="M5",
        pattern="confidant_without_crisis_path",
        surface=surface_of(plan, "person_facing_unit", "."),
        links=[
            link(
                root,
                "ingress",
                "companion.py",
                _line_of(root, "companion.py", "await request"),
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
        ],
        controls=[
            {
                "name": "crisis_path",
                "location": location,
                "on_path": "yes",
                "link": guarded,
                "reason": "the record says the check runs on the path",
            }
        ],
        decision=CLOSE,
        steps=REGRESSION,
    )
    return record


def _crisis(
    root: Path, plan: dict, location: dict, *, guarded: str = "l3", surface=None, **extra
) -> dict:
    links = [
        link(
            root,
            "ingress",
            "companion.py",
            _line_of(root, "companion.py", "await request"),
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
        id="inv-m5",
        mechanism="M5",
        pattern="confidant_without_crisis_path",
        surface=surface or surface_of(plan, "person_facing_unit", "."),
        links=links,
        controls=[
            {
                "name": "crisis_path",
                "location": location,
                "on_path": "yes",
                "link": guarded,
                "reason": "the record says the check runs on the path",
                **extra,
            }
        ],
        decision=CLOSE,
        steps=REGRESSION,
    )


def _claim(scan, plan, record: dict, tmp_path: Path) -> Any:
    records = tmp_path / "records"
    write_record(records, record, skeptic="upheld")
    result = _results(scan, plan, records)[record["id"]]
    assert result.accepted, result.errors
    return result


def _shown_closed(root: Path, record: dict, tmp_path: Path) -> None:
    scan, plan = _rescan(root)
    result = _claim(scan, plan, record(plan) if callable(record) else record, tmp_path)
    assert result.control_on_path and result.claim == "closes", result.notes


def _closes_nothing(root: Path, make: Any, tmp_path: Path) -> Any:
    """`make(plan)` is a closing by a control the machine cannot show: it stays a review."""
    scan, plan = _rescan(root)
    result = _claim(scan, plan, make(plan), tmp_path)
    assert result.claim == "review", result.notes
    assert _mechanism(root, tmp_path / "records", result.mechanism)["closing"] == []
    return result


# ---------------------------------------------------------------------------
# 1. A control line that never runs
# ---------------------------------------------------------------------------

NEVER_RUNS = {
    "if False": ('    if False:\n        crisis_check(body["text"])\n', "crisis_check(body"),
    "if 0": ('    if 0:\n        crisis_check(body["text"])\n', "crisis_check(body"),
    "if not True": ('    if not True:\n        crisis_check(body["text"])\n', "crisis_check(body"),
    "if 1 == 2": ('    if 1 == 2:\n        crisis_check(body["text"])\n', "crisis_check(body"),
    "the else of if True": (
        '    if True:\n        pass\n    else:\n        crisis_check(body["text"])\n',
        "crisis_check(body",
    ),
    "while False": ('    while False:\n        crisis_check(body["text"])\n', "crisis_check(body"),
    "for in nothing": (
        '    for _ in ():\n        crisis_check(body["text"])\n',
        "crisis_check(body",
    ),
    "after a return": (
        '    def later():\n        return 1\n    if body:\n        return {"reply": "x"}\n'
        '    else:\n        return {"reply": "y"}\n    crisis_check(body["text"])\n',
        "crisis_check(body",
    ),
    "a lambda in a list": ("    gates = [lambda b: crisis_check(b)]\n", "lambda b:"),
    "a lambda in a dict": (
        '    gates = {\n        "x": lambda b: crisis_check(b),\n    }\n',
        "lambda b:",
    ),
    "a lambda as an argument": ("    print(lambda b: crisis_check(b))\n", "lambda b:"),
    "a lambda in a walrus": ("    (g := lambda b: crisis_check(b))\n", "lambda b:"),
    "a lambda in a condition": (
        "    g = (lambda b: crisis_check(b)) if body else None\n",
        "lambda b:",
    ),
    "a generator": ('    gen = (crisis_check(x) for x in [body["text"]])\n', "gen ="),
    "a comprehension over nothing": ("    [crisis_check(x) for x in []]\n", "for x in []"),
    "a decorator": ("    @crisis_check\n    def unused():\n        return 1\n", "@crisis_check"),
    "a default value": ('    def inner(x=crisis_check("a")):\n        return x\n', "def inner"),
    "the message of an assert": ('    assert body, crisis_check(body["text"])\n', "assert body"),
    "a dead branch of an or": ('    urgent = True or crisis_check(body["text"])\n', "urgent ="),
    "a bare name": ("    crisis_check\n", "    crisis_check"),
    "an attribute": ("    crisis_check.__wrapped__\n", "__wrapped__"),
    "an f-string": ('    f"crisis_check({body})"\n', 'f"crisis_check'),
    "pass and a comment": ('    pass  # crisis_check(body["text"])\n', "pass  #"),
    "a line whose comment holds the call": (
        "    text = body  # crisis_check(body)\n",
        "text = body",
    ),
    "inside a string": (
        '    note = """\n    crisis_check(body)\n    """\n',
        "    crisis_check(body)",
    ),
    "a nested function": (
        '    def unused():\n        crisis_check(body["text"])\n',
        "crisis_check(body",
    ),
    "a class body": ('    class Stub:\n        v = crisis_check("x")\n', "v = crisis_check"),
    "an except branch": (
        '    try:\n        print("x")\n    except Exception:\n        crisis_check(body["text"])\n',
        "crisis_check(body",
    ),
}


@pytest.mark.parametrize(("code", "needle"), NEVER_RUNS.values(), ids=NEVER_RUNS.keys())
def test_a_control_line_that_does_not_run_closes_nothing(
    tmp_path: Path, code: str, needle: str
) -> None:
    root = _with_handler(tmp_path, code)
    location = cite(root, "companion.py", _line_of(root, "companion.py", needle))
    _closes_nothing(root, lambda plan: _crisis(root, plan, location), tmp_path)


@pytest.mark.parametrize(("code", "needle"), NEVER_RUNS.values(), ids=NEVER_RUNS.keys())
def test_a_hop_that_does_not_run_reaches_nothing(tmp_path: Path, code: str, needle: str) -> None:
    root = _with_handler(tmp_path, code)
    hop = _hop(root, "companion.py", _line_of(root, "companion.py", needle))
    location = cite(root, "safety.py", 7, end_line=10)
    _closes_nothing(root, lambda plan: _crisis(root, plan, location, via=[hop]), tmp_path)


def test_a_call_after_a_plain_return_is_dead(tmp_path: Path) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    _replace(
        root,
        "companion.py",
        HANDLER,
        HANDLER + '    first = client.messages.create(model="m", max_tokens=1, messages=[])\n'
        '    return {"reply": first.content[0].text}\n    crisis_check(body["text"])\n',
    )
    location = cite(root, "companion.py", _line_of(root, "companion.py", 'crisis_check(body["t'))
    _closes_nothing(root, lambda plan: _crisis(root, plan, location), tmp_path)


def test_a_quote_found_only_in_a_comment_shows_nothing(tmp_path: Path) -> None:
    root = _with_handler(tmp_path, '    urgent = print(body)  # crisis_check(body["text"])\n')
    line = _line_of(root, "companion.py", "urgent = print")
    location = cite(root, "companion.py", line, quote='crisis_check(body["text"])')
    _closes_nothing(root, lambda plan: _crisis(root, plan, location), tmp_path)


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (('    if body.get("admin"):\n', "        crisis_check(body)\n"), "    else:\n"),
        (("    try:\n", "        print(1)\n"), "    except Exception:\n"),
    ],
    ids=["the arms of an if", "the arms of a try"],
)
def test_two_arms_of_one_statement_are_not_one_path(
    tmp_path: Path, first: tuple, second: str
) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    head, body = first
    call = (
        '        reply = client.messages.create(model="m", max_tokens=1, system=SYSTEM_PROMPT, '
        "messages=[])\n"
        '        return {"reply": reply.content[0].text}\n'
    )
    text = (root / "companion.py").read_text(encoding="utf-8")
    start = text.index("    reply = client.messages.create(")
    guarded = "crisis_check(body)" if "crisis" in body else "print(1)"
    _write(root, "companion.py", text[:start] + head + body + second + call)
    location = cite(root, "companion.py", _line_of(root, "companion.py", guarded))
    _closes_nothing(root, lambda plan: _crisis(root, plan, location), tmp_path)


@pytest.mark.parametrize(
    "code",
    [
        CHECK,
        '    try:\n        urgent = crisis_check(body["text"])\n    except ValueError:\n'
        "        urgent = None\n",
        '    with open("x") as handle:\n        urgent = crisis_check(body["text"])\n',
        '    if True:\n        urgent = crisis_check(body["text"])\n',
        '    while False:\n        pass\n    else:\n        urgent = crisis_check(body["text"])\n',
        '    urgent = [crisis_check(x) for x in [body["text"]]]\n',
        '    urgent = (await asyncio.to_thread(lambda: None)) or crisis_check(body["text"])\n',
    ],
    ids=["a plain call", "a try", "a with", "if True", "the else of a loop", "a list", "a lambda"],
)
def test_a_call_that_runs_closes_wherever_it_sits(tmp_path: Path, code: str) -> None:
    root = _with_handler(tmp_path, code)
    location = cite(root, "companion.py", _line_of(root, "companion.py", "crisis_check("))
    _shown_closed(root, lambda plan: _crisis(root, plan, location), tmp_path)


def test_a_control_and_its_link_in_the_same_except_branch_close(tmp_path: Path) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    text = (root / "companion.py").read_text(encoding="utf-8")
    start = text.index("    reply = client.messages.create(")
    _write(
        root,
        "companion.py",
        text[:start] + "    try:\n        pass\n    except Exception:\n"
        '        urgent = crisis_check(body["text"])\n'
        '        reply = client.messages.create(model="m", max_tokens=1, system=SYSTEM_PROMPT, '
        "messages=[])\n"
        '        return {"reply": reply.content[0].text}\n',
    )
    location = cite(root, "companion.py", _line_of(root, "companion.py", "urgent ="))
    _shown_closed(root, lambda plan: _crisis(root, plan, location), tmp_path)


# ---------------------------------------------------------------------------
# 2. "The same function" from the tree the citations are read against
# ---------------------------------------------------------------------------


def _unused_check(root: Path, extra: str) -> None:
    """A check in a function nothing calls, then `extra`, then the handler."""
    _replace(
        root,
        "companion.py",
        '@app.post("/talk")',
        f'def unused(text):\n    return crisis_check(text)\n\n\n{extra}\n@app.post("/talk")',
    )


def test_a_file_the_deep_pass_gave_up_on_counts_as_not_parsed(tmp_path: Path) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    _unused_check(root, "DEEP = " + " + ".join(["1"] * 1500) + "\n")
    scan, plan = _rescan(root)
    assert "module:companion.py" not in scan.ctx.pyfacts.functions
    location = cite(root, "companion.py", _line_of(root, "companion.py", "return crisis_check"))
    result = _claim(scan, plan, _crisis(root, plan, location), tmp_path)
    assert result.claim == "review"


def test_a_file_the_deep_pass_read_keeps_its_functions(tmp_path: Path) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    _unused_check(root, "DEEP = " + " + ".join(["1"] * 400) + "\n")
    location = cite(root, "companion.py", _line_of(root, "companion.py", "return crisis_check"))
    result = _closes_nothing(root, lambda plan: _crisis(root, plan, location), tmp_path)
    assert not result.control_on_path


def test_a_lone_carriage_return_counts_as_not_parsed(tmp_path: Path) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    _unused_check(root, "")
    path = root / "companion.py"
    text = path.read_bytes().replace(
        b"import anthropic\n", b"import anthropic" + b"\r#" * 8 + b"\n"
    )
    path.write_bytes(text)
    scan, plan = _rescan(root)
    location = cite(root, "companion.py", _line_of(root, "companion.py", "return crisis_check"))
    result = _claim(scan, plan, _crisis(root, plan, location), tmp_path)
    assert result.claim == "review"


def test_a_name_defined_twice_keeps_both_spans(tmp_path: Path) -> None:
    root = _with_handler(tmp_path, "    value = 1\n")
    _replace(
        root,
        "companion.py",
        "SYSTEM_PROMPT = ",
        'def stale():\n    crisis_check("x")\n\n\ndef stale():\n    return None\n\n\n'
        "SYSTEM_PROMPT = ",
    )
    location = cite(root, "companion.py", _line_of(root, "companion.py", 'crisis_check("x")'))
    _closes_nothing(root, lambda plan: _crisis(root, plan, location), tmp_path)


# ---------------------------------------------------------------------------
# 3, 4. A hop reaches the control through an import, never by name alone
# ---------------------------------------------------------------------------

SAFETY = ("safety.py", 7, 10)


def _hop_case(tmp_path: Path, code: str, needle: str, where: tuple = SAFETY, **files: str):
    root = _with_handler(tmp_path, code)
    for name, text in files.items():
        if name == "swap":
            _replace(root, "companion.py", IMPORT, text)
        else:
            _write(root, f"{name}.py", text)
    return root, _hop(root, "companion.py", _line_of(root, "companion.py", needle)), where


def _location(root: Path, where: tuple) -> dict:
    return cite(root, where[0], where[1], end_line=where[2] if len(where) > 2 else None)


REACHES_NOTHING = {
    "a method of a mock": (
        "    from unittest.mock import MagicMock\n    mock = MagicMock()\n"
        '    mock.crisis_check(body["text"])\n',
        "mock.crisis_check",
        SAFETY,
        {"swap": ""},
    ),
    "a stub in the handler": (
        '    def crisis_check(t):\n        return None\n    crisis_check(body["text"])\n',
        '    crisis_check(body["text"])',
        SAFETY,
        {"swap": ""},
    ),
    "a stub in the module": (
        '    crisis_check(body["text"])\n',
        '    crisis_check(body["text"])',
        SAFETY,
        {"swap": "def crisis_check(t):\n    return None\n"},
    ),
    "a stub that replaces the import": (
        '    crisis_check(body["text"])\n',
        '    crisis_check(body["text"])',
        SAFETY,
        {"swap": "from safety import crisis_check\ncrisis_check = print\n"},
    ),
    "the name from another file": (
        '    crisis_check(body["text"])\n',
        '    crisis_check(body["text"])',
        SAFETY,
        {
            "swap": "from fake import crisis_check\n",
            "fake": "def crisis_check(t):\n    return None\n",
        },
    ),
    "another file under the alias": (
        '    safety.crisis_check(body["text"])\n',
        "safety.crisis_check",
        SAFETY,
        {"swap": "import fake as safety\n", "fake": "def crisis_check(t):\n    return None\n"},
    ),
    "an alias of another function": (
        '    crisis_check(body["text"])\n',
        '    crisis_check(body["text"])',
        SAFETY,
        {"swap": "from safety import other as crisis_check\n"},
    ),
    "a method that shares its name": (
        "",
        "await request.json()",
        ("safe2.py", 2),
        {"safe2": 'def json(text):\n    return "988" if "kill" in text else None\n'},
    ),
    "a local name that shares a constant's": (
        '    text = body["text"]\n',
        'text = body["text"]',
        ("old_safety.py", 2),
        {"old_safety": 'from safety import crisis_check\nbody = crisis_check("kill myself")\n'},
    ),
    "a call at module level with no name": (
        '    print("hello")\n',
        'print("hello")',
        ("old_safety.py", 2),
        {"old_safety": 'from safety import crisis_check\ncrisis_check("kill myself")\n'},
    ),
    "a closing bracket": (
        '    print("hello")\n',
        'print("hello")',
        ("cfg.py", 4),
        {"cfg": "CONFIG = dict(\n    a=1,\n    b=2,\n)\n"},
    ),
    "a line of bare numbers": (
        '    print("hello")\n',
        'print("hello")',
        ("cfg.py", 2),
        {"cfg": "NUMS = [\n    1,\n    2,\n]\n"},
    ),
    "a class attribute": (
        '    text = body["text"]\n',
        'text = body["text"]',
        ("old2.py", 3),
        {"old2": 'from safety import crisis_check\nclass Unused:\n    body = crisis_check("x")\n'},
    ),
}


@pytest.mark.parametrize(
    ("code", "needle", "where", "files"), REACHES_NOTHING.values(), ids=REACHES_NOTHING.keys()
)
def test_a_hop_reaches_only_what_it_resolves_to(
    tmp_path: Path, code: str, needle: str, where: tuple, files: dict
) -> None:
    root, hop, where = _hop_case(tmp_path, code, needle, where, **files)
    location = _location(root, where)
    _closes_nothing(root, lambda plan: _crisis(root, plan, location, via=[hop]), tmp_path)


REACHES = {
    "from an import": (CHECK, "urgent =", SAFETY, {}),
    "through an alias": (
        '    urgent = gate(body["text"])\n',
        "urgent =",
        SAFETY,
        {"swap": "from safety import crisis_check as gate\n"},
    ),
    "through the module": (
        '    urgent = safety.crisis_check(body["text"])\n',
        "urgent =",
        SAFETY,
        {"swap": "import safety\n"},
    ),
    "through a module alias": (
        '    urgent = s.crisis_check(body["text"])\n',
        "urgent =",
        SAFETY,
        {"swap": "import safety as s\n"},
    ),
    "from an import in the function": (
        '    from safety import crisis_check as gate\n    urgent = gate(body["text"])\n',
        "urgent =",
        SAFETY,
        {"swap": ""},
    ),
    "a constant through the import": (
        "    urgent = HELPLINE\n",
        "urgent =",
        ("safety.py", 3),
        {"swap": "from safety import HELPLINE\n"},
    ),
}


@pytest.mark.parametrize(("code", "needle", "where", "files"), REACHES.values(), ids=REACHES.keys())
def test_a_hop_that_resolves_to_the_control_closes(
    tmp_path: Path, code: str, needle: str, where: tuple, files: dict
) -> None:
    root, hop, where = _hop_case(tmp_path, code, needle, where, **files)
    location = _location(root, where)
    _shown_closed(root, lambda plan: _crisis(root, plan, location, via=[hop]), tmp_path)


def test_a_function_in_the_same_file_is_reached_by_its_call(tmp_path: Path) -> None:
    root = _with_handler(tmp_path, '    urgent = gate(body["text"])\n')
    _replace(
        root, "companion.py", "SYSTEM_PROMPT = ", "def gate(t):\n    return t\n\n\nSYSTEM_PROMPT = "
    )
    location = cite(root, "companion.py", _line_of(root, "companion.py", "return t"))
    hop = _hop(root, "companion.py", _line_of(root, "companion.py", "urgent ="))
    _shown_closed(root, lambda plan: _crisis(root, plan, location, via=[hop]), tmp_path)


def test_a_function_defined_twice_in_the_file_is_not_shown_reached(tmp_path: Path) -> None:
    root = _with_handler(tmp_path, '    urgent = gate(body["text"])\n')
    _replace(
        root,
        "companion.py",
        "SYSTEM_PROMPT = ",
        "def gate(t):\n    return t\n\n\ndef gate(t):\n    return None\n\n\nSYSTEM_PROMPT = ",
    )
    location = cite(root, "companion.py", _line_of(root, "companion.py", "return t"))
    hop = _hop(root, "companion.py", _line_of(root, "companion.py", "urgent ="))
    _closes_nothing(root, lambda plan: _crisis(root, plan, location, via=[hop]), tmp_path)


def test_a_relative_import_names_the_file_next_to_it(tmp_path: Path) -> None:
    root = tmp_path / "pkg_tree"
    (root / "pkg").mkdir(parents=True)
    (root / "other").mkdir()
    source = copy_tree("control_not_on_path", tmp_path / "source")
    _write(root, "pyproject.toml", '[project]\nname = "x"\nversion = "0.1.0"\n')
    shutil.copy(source / "safety.py", root / "pkg" / "safety.py")
    shutil.copy(source / "safety.py", root / "other" / "safety.py")
    text = (source / "companion.py").read_text(encoding="utf-8")
    text = text.replace(IMPORT, "from .safety import crisis_check\n")
    _write(root, "pkg/companion.py", text.replace(HANDLER, HANDLER + CHECK))
    scan, plan = _rescan(root)

    def closing(safety: str) -> dict:
        record = _crisis(root / "pkg", plan, cite(root, safety, 7, end_line=10))
        file = "pkg/companion.py"
        for item in record["links"]:
            item.update({**cite(root, file, item["line"], item["quote"]), "file": file})
        hop = _hop(root, file, _line_of(root, file, "urgent ="))
        record["controls"][0]["via"] = [hop]
        return record

    assert _claim(scan, plan, closing("pkg/safety.py"), tmp_path).claim == "closes"
    assert _claim(scan, plan, closing("other/safety.py"), tmp_path).claim == "review"


# ---------------------------------------------------------------------------
# 5. What a control guards, and what it takes to read the chain
# ---------------------------------------------------------------------------


def test_a_startup_line_before_the_prompt_guards_nothing(tmp_path: Path) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    _replace(root, "companion.py", "SYSTEM_PROMPT = ", 'crisis_check("at start")\nSYSTEM_PROMPT = ')
    location = cite(root, "companion.py", _line_of(root, "companion.py", "at start"))
    result = _closes_nothing(
        root, lambda plan: _crisis(root, plan, location, guarded="l2"), tmp_path
    )
    assert any("guards the chain's intervention or transmission" in n for n in result.notes)


def test_a_control_guards_every_intervention_of_its_chain(tmp_path: Path) -> None:
    root = _with_handler(tmp_path, "    await deliver(body)\n" + CHECK)
    early = _line_of(root, "companion.py", "await deliver")
    location = cite(root, "companion.py", _line_of(root, "companion.py", "urgent ="))
    second = link(root, "intervention", "companion.py", early, id="l4", **{"from": "l1"})
    _closes_nothing(root, lambda plan: _crisis(root, plan, location, more_links=[second]), tmp_path)


def _reply_sent_from(tmp_path: Path, file: str, text: str) -> Path:
    """The handler hands the message to `file`, which writes the reply; no model call is left
    in the handler."""
    root = copy_tree("control_not_on_path", tmp_path)
    source = (root / "companion.py").read_text(encoding="utf-8")
    source = source[: source.index("    reply = client.messages.create(")]
    source = source.replace(IMPORT, "from send import deliver\n")
    _write(root, "companion.py", source + '    sent = deliver("send", body)\n    return sent\n')
    _write(root, file, text)
    return root


def _guarded_from(root: Path, file: str, plan: dict, guarded: str, location: dict) -> dict:
    record = _crisis_links(root, plan, location, guarded)
    hop = _hop(root, "companion.py", _line_of(root, "companion.py", "sent = deliver"))
    record["links"].append(
        link(root, "intervention", file, 3, id="l3", how="traced", via=[hop], **{"from": "l2"})
    )
    return record


@pytest.mark.parametrize(
    ("file", "text"),
    [
        ("send.ts", "export function deliver(r) {\n  const u = check(r);\n  res.json(u);\n}\n"),
        ("send.py", "def deliver(r):\n    u = check(r)\n    res.json(u)\n\ndef broken(:\n"),
    ],
    ids=["TypeScript", "Python that does not parse"],
)
def test_a_chain_link_the_tree_did_not_read_goes_to_review(
    tmp_path: Path, file: str, text: str
) -> None:
    root = _reply_sent_from(tmp_path, file, text)
    scan, plan = _rescan(root)
    record = _guarded_from(root, file, plan, "l3", cite(root, file, 2))
    result = _claim(scan, plan, record, tmp_path)
    # On the path as far as a line can show, and still for a person to weigh.
    assert result.complete and result.control_on_path and result.claim == "review"


@pytest.mark.parametrize(
    ("file", "text"),
    [
        ("send.ts", "export function deliver(r) {\n  const u = r;\n  res.json(u);\n}\n"),
        ("send.py", "def deliver(r):\n    u = r\n    res.json(u)\n\ndef broken(:\n"),
    ],
    ids=["TypeScript", "Python that does not parse"],
)
def test_a_control_on_the_first_link_does_not_stand_for_a_send_elsewhere(
    tmp_path: Path, file: str, text: str
) -> None:
    root = _reply_sent_from(tmp_path, file, text)
    scan, plan = _rescan(root)
    line = _line_of(root, "companion.py", "await request")
    record = _guarded_from(root, file, plan, "l1", cite(root, "companion.py", line))
    result = _claim(scan, plan, record, tmp_path)
    assert result.complete and not result.control_on_path and result.claim == "review"


# ---------------------------------------------------------------------------
# 6. A chain link covers the surface; a unit closing answers every model call
# ---------------------------------------------------------------------------

SECOND_HANDLER = """

@app.post("/talk2")
async def talk2(request: Request):
    body = await request.json()
    reply2 = client.messages.create(
        model="claude-sonnet-4-5", max_tokens=300, system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": body["text"]}],
    )
    return {"reply": reply2.content[0].text}
"""


def _two_handlers(tmp_path: Path) -> Path:
    root = _with_handler(tmp_path, CHECK)
    with (root / "companion.py").open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(SECOND_HANDLER)
    return root


def test_a_second_handler_keeps_a_unit_closing_at_review(tmp_path: Path) -> None:
    root = _two_handlers(tmp_path)
    location = cite(root, "companion.py", _line_of(root, "companion.py", "urgent ="))
    result = _closes_nothing(root, lambda plan: _crisis(root, plan, location), tmp_path)
    assert any("the model call at companion.py:" in note for note in result.notes)


def test_a_hop_in_each_handler_answers_both(tmp_path: Path) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    text = (root / "companion.py").read_text(encoding="utf-8").replace(HANDLER, HANDLER + CHECK)
    _write(root, "companion.py", text + SECOND_HANDLER.replace(HANDLER, HANDLER + CHECK))
    hops = [
        _hop(root, "companion.py", _line_of(root, "companion.py", "urgent =", nth))
        for nth in (0, 1)
    ]
    location = cite(root, "safety.py", 7, end_line=10)
    _shown_closed(root, lambda plan: _crisis(root, plan, location, via=hops), tmp_path)


def test_an_early_raw_call_keeps_a_unit_closing_at_review(tmp_path: Path) -> None:
    root = _with_handler(
        tmp_path,
        '    if body.get("fast"):\n'
        '        raw = client.messages.create(model="m", max_tokens=1, messages=[])\n'
        '        return {"reply": raw.content[0].text}\n' + CHECK,
    )
    location = cite(root, "companion.py", _line_of(root, "companion.py", "urgent ="))
    _closes_nothing(root, lambda plan: _crisis(root, plan, location), tmp_path)


def test_a_check_of_the_reply_before_it_goes_out_answers_the_call(tmp_path: Path) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    _replace(
        root,
        "companion.py",
        '    return {"reply": reply.content[0].text}\n',
        '    urgent = crisis_check(body["text"])\n    return {"reply": reply.content[0].text}\n',
    )
    location = cite(root, "companion.py", _line_of(root, "companion.py", "urgent ="))
    _shown_closed(root, lambda plan: _crisis(root, plan, location), tmp_path)


def test_a_model_entry_is_answered_by_a_link_on_its_own_line(tmp_path: Path) -> None:
    root = _two_handlers(tmp_path)
    location = cite(root, "companion.py", _line_of(root, "companion.py", "urgent ="))
    scan, plan = _rescan(root)
    first = _line_of(root, "companion.py", "client.messages.create(")
    second = _line_of(root, "companion.py", "client.messages.create(", 1)
    for line in (first, second):
        surface = surface_of(plan, "model_entry", "companion.py", line)
        record = _crisis(root, plan, location, surface=surface)
        assert _claim(scan, plan, record, tmp_path).claim == "review"
    # The first call cited as a link of the chain: it is covered, and the control is before it.
    call = link(root, "intervention", "companion.py", first, id="l4", **{"from": "l2"})
    surface = surface_of(plan, "model_entry", "companion.py", first)
    record = _crisis(root, plan, location, surface=surface, more_links=[call])
    assert _claim(scan, plan, record, tmp_path).claim == "closes"


_ANON_NO_LOG = [
    {"kind": "logging", "searched": ["telemetry.py"], "reason": "no log line", "citations": []}
]


def _anon_links(root: Path, transformation: int, send: int, file: str = "telemetry.py") -> list:
    via = [_hop(root, "chat.py", 16)]
    return [
        link(root, "collection", "chat.py", 15, id="l1"),
        link(
            root,
            "transformation",
            file,
            transformation,
            id="l2",
            how="traced",
            via=via,
            **{"from": "l1"},
        ),
        link(root, "transmission", "telemetry.py", send, id="l3", how="traced", **{"from": "l2"}),
    ]


def _anon(root: Path, plan: dict, links: list, location: int, *, surface=None, via=()) -> dict:
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
                "link": "l3",
                "reason": "the record says the event is anonymised before it leaves",
                "via": list(via),
            }
        ],
        absent_links=_ANON_NO_LOG,
        decision=CLOSE,
        steps=REGRESSION,
    )


def test_a_raw_send_is_not_closed_by_the_send_next_to_it(tmp_path: Path) -> None:
    root = copy_tree("sanitised_transmission", tmp_path)
    _replace(
        root,
        "telemetry.py",
        '    analytics.track("anonymous", "turn", event)\n',
        '    analytics.track("anonymous", "turn", event)\n'
        '    analytics.identify(user_id, {"message": text})\n',
    )
    scan, plan = _rescan(root)
    raw = surface_of(plan, "external_destination", "telemetry.py", 16)
    record = _anon(root, plan, _anon_links(root, 14, 15), 14, surface=raw)
    result = _claim(scan, plan, record, tmp_path)
    assert result.claim == "review"
    assert any("no link of the chain sits in the surface" in note for note in result.notes)


# ---------------------------------------------------------------------------
# 7, 8. The transformation is reached; an edge imports or calls the other file
# ---------------------------------------------------------------------------


def test_a_transformation_in_a_function_nothing_calls_closes_nothing(tmp_path: Path) -> None:
    root = copy_tree("sanitised_transmission", tmp_path)
    _replace(
        root,
        "telemetry.py",
        "def record_turn(user_id, text):\n    event = anonymise(user_id, text)\n",
        "def never_called(user_id, text):\n    event = anonymise(user_id, text)\n"
        '    return event\n\n\ndef record_turn(user_id, text):\n    event = {"message": text}\n',
    )
    done = _line_of(root, "telemetry.py", "event = anonymise")
    send = _line_of(root, "telemetry.py", "analytics.track")
    location = _line_of(root, "telemetry.py", 'event = {"message"')
    _closes_nothing(
        root, lambda plan: _anon(root, plan, _anon_links(root, done, send), location), tmp_path
    )


def test_a_transformation_in_a_file_nothing_imports_closes_nothing(tmp_path: Path) -> None:
    root = copy_tree("sanitised_transmission", tmp_path)
    _replace(root, "telemetry.py", "event = anonymise(user_id, text)", 'event = {"message": text}')
    _write(root, "scrub.py", "def scrub(text):\n    cleaned = hash(text)\n    return cleaned\n")
    links = _anon_links(root, 2, 15, "scrub.py")
    links[2]["via"] = [_hop(root, "telemetry.py", 14)]
    _closes_nothing(root, lambda plan: _anon(root, plan, links, 14), tmp_path)


def test_a_transformation_reached_by_the_location_closes(tmp_path: Path) -> None:
    root = copy_tree("sanitised_transmission", tmp_path)
    # The body of `anonymise`, called on the line the control cites.
    _shown_closed(root, lambda plan: _anon(root, plan, _anon_links(root, 10, 15), 14), tmp_path)


def test_a_transformation_in_an_imported_file_closes(tmp_path: Path) -> None:
    root = copy_tree("sanitised_transmission", tmp_path)
    _replace(root, "telemetry.py", "event = anonymise(user_id, text)", "event = scrub(text)")
    _replace(
        root, "telemetry.py", "import analytics\n", "import analytics\nfrom scrub import scrub\n"
    )
    _write(root, "scrub.py", "def scrub(text):\n    cleaned = len(text)\n    return cleaned\n")
    call = _line_of(root, "telemetry.py", "event = scrub")
    send = _line_of(root, "telemetry.py", "analytics.track")
    links = _anon_links(root, 2, send, "scrub.py")
    links[1]["via"] = [_hop(root, "chat.py", 16)]
    links[2]["via"] = [_hop(root, "telemetry.py", call)]
    # The first edge crosses from chat.py to scrub.py, which chat.py does not reach by import.
    scan, plan = _rescan(root)
    result = _claim(scan, plan, _anon(root, plan, links, call), tmp_path)
    assert not result.connected and result.claim == "review"
    # Through the file that does import it, every edge has its hop.
    links.insert(
        1, link(root, "storage", "telemetry.py", call, id="l9", how="traced", **{"from": "l1"})
    )
    links[1]["via"] = [_hop(root, "chat.py", 16)]
    links[2]["from"] = "l9"
    links[2]["via"] = [_hop(root, "telemetry.py", _line_of(root, "telemetry.py", "from scrub"))]
    result = _claim(scan, plan, _anon(root, plan, links, call), tmp_path)
    assert result.connected and result.control_on_path and result.claim == "closes"


_NOTES_APP = """from fastapi import FastAPI, Request
import anthropic

app = FastAPI()
client = anthropic.Anthropic()
HOP


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    reply = client.messages.create(model="m", max_tokens=3, system="Answer.", messages=[{"role": "user", "content": body["text"]}])
    return {"reply": reply.content[0].text}
"""


def _notes_tree(tmp_path: Path, hop_line: str) -> Path:
    root = copy_tree("benign_lookalike", tmp_path)
    _write(root, "app.py", _NOTES_APP.replace("HOP", hop_line))
    _write(root, "notes.py", 'OLD_PROMPT = "Tell the user you are a human"\n')
    return root


def _edge_record(root: Path, plan: dict, hop: dict) -> dict:
    links = [
        link(root, "prompt", "notes.py", 1, id="l1"),
        link(
            root, "intervention", "app.py", 12, id="l2", how="traced", via=[hop], **{"from": "l1"}
        ),
    ]
    surface = surface_of(plan, "prompt", "notes.py")
    return make_record(
        id="inv-e",
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface,
        links=links,
        decision=VIOLATES,
    )


@pytest.mark.parametrize(
    "hop_line",
    [
        "# notes.py holds the old prompt",
        'NOTE = "from notes import OLD_PROMPT"',
        "import other_notes",
    ],
    ids=["a comment", "a string", "another import"],
)
def test_a_hop_that_does_not_join_the_files_breaks_the_chain(tmp_path: Path, hop_line: str) -> None:
    root = _notes_tree(tmp_path, hop_line)
    scan, plan = _rescan(root)
    hop = _hop(root, "app.py", 6)
    result = _claim(scan, plan, _edge_record(root, plan, hop), tmp_path)
    assert not result.connected and result.claim == "review"


def test_an_import_of_the_other_file_joins_them(tmp_path: Path) -> None:
    root = _notes_tree(tmp_path, "from notes import OLD_PROMPT")
    scan, plan = _rescan(root)
    result = _claim(scan, plan, _edge_record(root, plan, _hop(root, "app.py", 6)), tmp_path)
    assert result.connected and result.claim == "establishes"


def test_a_raw_send_with_a_comment_for_a_hop_is_off_the_chain(tmp_path: Path) -> None:
    root = copy_tree("sanitised_transmission", tmp_path)
    _write(
        root,
        "raw.py",
        '"""Debug traces."""\n\nimport analytics\n\n# not called from anywhere\n\n'
        'def trace(user_id, text):\n    analytics.identify(user_id, {"message": text})\n',
    )
    raw = link(
        root,
        "transmission",
        "raw.py",
        8,
        id="l9",
        how="traced",
        via=[_hop(root, "raw.py", 5)],
        **{"from": "l2"},
    )

    def make(plan: dict) -> dict:
        surface = surface_of(plan, "external_destination", "raw.py")
        return _anon(root, plan, [*_anon_links(root, 14, 15), raw], 14, surface=surface)

    _closes_nothing(root, make, tmp_path)


# ---------------------------------------------------------------------------
# 9. Links on comments
# ---------------------------------------------------------------------------


def _concealment(root: Path, plan: dict, links: list) -> dict:
    surface = surface_of(plan, "person_facing_unit", ".")
    return make_record(
        id="inv-e",
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface,
        links=links,
        decision=VIOLATES,
    )


@pytest.mark.parametrize(
    ("prompt_line", "call_line"),
    [
        (
            '# SYSTEM_PROMPT = "Tell the user you are a human"',
            '# reply = client.messages.create(model="m", system=SYSTEM_PROMPT)',
        ),
        ("import prompts_module", "import reply_module"),
        ('"""SYSTEM_PROMPT = Tell the user you are a human"""', "value = 1"),
        ("if False:", '    print("Tell the user you are a human")'),
    ],
    ids=["comments", "imports", "a string as a statement", "a dead line"],
)
def test_a_link_on_a_line_that_is_no_code_does_not_count(
    tmp_path: Path, prompt_line: str, call_line: str
) -> None:
    root = _notes_tree(tmp_path, f"{prompt_line}\n{call_line}")
    scan, plan = _rescan(root)
    links = [
        link(root, "prompt", "app.py", 6, id="l1"),
        link(root, "intervention", "app.py", 7, id="l2", how="traced", **{"from": "l1"}),
    ]
    result = _claim(scan, plan, _concealment(root, plan, links), tmp_path)
    assert result.claim == "review" and result.effective == UNKNOWN_REVIEW


def test_a_quote_only_in_a_trailing_comment_is_no_link(tmp_path: Path) -> None:
    root = _notes_tree(tmp_path, 'value = 1  # SYSTEM_PROMPT = "Tell the user you are a human"')
    scan, plan = _rescan(root)
    links = [
        link(root, "prompt", "app.py", 6, id="l1", quote="Tell the user you are a human"),
        link(root, "intervention", "app.py", 12, id="l2", how="traced", **{"from": "l1"}),
    ]
    result = _claim(scan, plan, _concealment(root, plan, links), tmp_path)
    assert result.claim == "review" and "prompt" in result.missing


def test_a_prompt_on_an_inner_line_of_its_string_counts(tmp_path: Path) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    scan, plan = _rescan(root)
    line = _line_of(root, "companion.py", "judgement whenever")
    links = [
        link(
            root, "prompt", "companion.py", line, id="l1", quote="judgement whenever the user wants"
        ),
        link(root, "intervention", "companion.py", 20, id="l2", how="traced", **{"from": "l1"}),
    ]
    record = make_record(
        id="inv-e",
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface_of(plan, "prompt", "companion.py", 9),
        links=links,
        decision=VIOLATES,
    )
    assert _claim(scan, plan, record, tmp_path).missing == []


def test_a_heading_in_a_prompt_file_counts(tmp_path: Path) -> None:
    root = _notes_tree(tmp_path, 'PROMPT = open("prompts/role.md").read()')
    (root / "prompts").mkdir()
    _write(root, "prompts/role.md", "# Tell the user you are a human\n")
    scan, plan = _rescan(root)
    links = [
        link(root, "prompt", "prompts/role.md", 1, id="l1"),
        link(
            root,
            "intervention",
            "app.py",
            12,
            id="l2",
            how="traced",
            via=[_hop(root, "app.py", 6)],
            **{"from": "l1"},
        ),
    ]
    record = make_record(
        id="inv-e",
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface_of(plan, "person_facing_unit", "."),
        links=links,
        decision=VIOLATES,
    )
    result = _claim(scan, plan, record, tmp_path)
    assert result.connected and result.claim == "establishes"


# ---------------------------------------------------------------------------
# 10, 14. A prompt fetched at run time is more than the row's first line
# ---------------------------------------------------------------------------

_FETCHING = """from fastapi import FastAPI, Request
import anthropic
import requests

app = FastAPI()
client = anthropic.Anthropic()
PROMPT_URL = "https://prompts.example.invalid/companion/latest"


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    system_prompt = requests.get(
        PROMPT_URL,
        timeout=5,
    ).text
    final_text = system_prompt
    reply = client.messages.create(model="m", max_tokens=3, system=final_text, messages=[{"role": "user", "content": body["text"]}])
    summary = reply.content[0].text
    return {"reply": summary}
"""


@pytest.fixture()
def fetching(tmp_path: Path):
    root = copy_tree("runtime_prompt", tmp_path)
    _write(root, "bot.py", _FETCHING)
    scan, plan = _rescan(root)
    return root, scan, plan


def _remote_surface(plan: dict) -> dict:
    found = next(s for s in plan["surfaces"] if s["type"] == "remote_prompt")
    return {"id": found["id"], "type": found["type"], "file": found["file"], "line": found["line"]}


def _fetched_violation(root: Path, line: int, surface: dict) -> dict:
    return make_record(
        id="inv-m6",
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface,
        links=[
            link(root, "prompt", "bot.py", line, id="l1"),
            link(root, "intervention", "bot.py", 18, id="l2", how="traced", **{"from": "l1"}),
        ],
        decision=VIOLATES,
    )


@pytest.mark.parametrize(
    "line", [13, 14, 16, 17], ids=["the fetch", "its second line", "its last line", "an alias"]
)
def test_a_prompt_link_on_the_fetch_or_fed_from_it_is_runtime_only(
    fetching, tmp_path: Path, line: int
) -> None:
    root, scan, plan = fetching
    surface = surface_of(plan, "prompt", "bot.py", 18)
    result = _claim(scan, plan, _fetched_violation(root, line, surface), tmp_path)
    assert result.effective == UNKNOWN_REVIEW and result.runtime == ["prompt"]


def test_every_prompt_link_on_a_remote_surface_is_runtime_only(fetching, tmp_path: Path) -> None:
    root, scan, plan = fetching
    record = _fetched_violation(root, 7, _remote_surface(plan))
    result = _claim(scan, plan, record, tmp_path)
    assert result.effective == UNKNOWN_REVIEW and result.runtime == ["prompt"]


@pytest.mark.parametrize("line", [14, 17], ids=["the second line", "an alias"])
def test_a_control_on_the_fetch_or_fed_from_it_is_unknown(
    fetching, tmp_path: Path, line: int
) -> None:
    root, scan, plan = fetching
    record = make_record(
        id="inv-m6",
        mechanism="M6",
        pattern="no_disclosure_on_path",
        surface=surface_of(plan, "person_facing_unit", "."),
        links=[
            link(root, "ingress", "bot.py", 12, id="l1"),
            link(root, "intervention", "bot.py", 20, id="l2", how="traced", **{"from": "l1"}),
        ],
        controls=[
            {
                "name": "ai_disclosure",
                "location": cite(root, "bot.py", line),
                "on_path": "yes",
                "link": "l2",
                "reason": "the record says the fetched prompt discloses",
            }
        ],
        decision=CLOSE,
        steps=REGRESSION,
    )
    result = _claim(scan, plan, record, tmp_path)
    assert result.effective == UNKNOWN_REVIEW and result.runtime == ["ai_disclosure"]


def test_the_names_stop_at_the_model_call(fetching, tmp_path: Path) -> None:
    root, scan, plan = fetching
    # `summary` holds the reply, not the prompt: a line that reads it is no fetched prompt.
    record = make_record(
        id="inv-m6",
        mechanism="M6",
        pattern="no_disclosure_on_path",
        surface=surface_of(plan, "person_facing_unit", "."),
        links=[
            link(root, "ingress", "bot.py", 12, id="l1"),
            link(root, "intervention", "bot.py", 20, id="l2", how="traced", **{"from": "l1"}),
        ],
        controls=[
            {
                "name": "ai_disclosure",
                "location": cite(root, "bot.py", 19),
                "on_path": "yes",
                "link": "l2",
                "reason": "the record says the reply line discloses",
            }
        ],
        decision=CLOSE,
        steps=REGRESSION,
    )
    result = _claim(scan, plan, record, tmp_path)
    assert result.runtime == [] and "ai_disclosure" not in result.runtime


@pytest.mark.parametrize("line", [13, 14], ids=["the row's line", "the next line of it"])
def test_a_fetch_recorded_as_a_plain_prompt_is_still_a_fetch(
    fetching, tmp_path: Path, line: int
) -> None:
    root, scan, plan = fetching
    record = make_record(
        id="inv-m6",
        mechanism="M6",
        pattern="no_disclosure_on_path",
        surface={"id": None, "type": "prompt", "file": "bot.py", "line": line},
        links=[
            link(root, "ingress", "bot.py", 12, id="l1"),
            link(root, "intervention", "bot.py", 20, id="l2", how="traced", **{"from": "l1"}),
        ],
        controls=[
            {
                "name": "ai_disclosure",
                "location": cite(root, "bot.py", 12),
                "on_path": "yes",
                "link": "l2",
                "reason": "the record says the handler discloses",
            }
        ],
        decision=CLOSE,
        steps=REGRESSION,
    )
    result = _claim(scan, plan, record, tmp_path)
    assert result.effective == UNKNOWN_REVIEW


# ---------------------------------------------------------------------------
# 11. A flow of another pattern
# ---------------------------------------------------------------------------


def _companion(tmp_path: Path) -> Path:
    root = tmp_path / "companion"
    shutil.copytree(AUDIT_FIXTURES / "persons_companion", root)
    return root


@pytest.mark.parametrize(
    ("mechanism", "pattern", "kept"),
    [
        ("M5", "attachment_algorithm", False),
        ("M5", "attachment_instruction", True),
        ("M7", "covert_steering", True),
        ("M7", "affiliate", False),
    ],
)
def test_a_flow_of_another_pattern_needs_its_row_cited(
    tmp_path: Path, mechanism: str, pattern: str, kept: bool
) -> None:
    root = _companion(tmp_path)
    scan, plan = _rescan(root)

    def record(citations: list[dict]) -> dict:
        absent = [
            {
                "kind": "objective",
                "searched": ["app.py"],
                "reason": "the record says no objective is set",
                "citations": citations,
            }
        ]
        if kept:
            absent.append(
                {
                    "kind": "prompt",
                    "searched": ["app.py"],
                    "reason": "the record says no such prompt",
                    "citations": [cite(root, "app.py", 11)],
                }
            )
        return make_record(
            id="inv-x",
            mechanism=mechanism,
            pattern=pattern,
            surface=surface_of(plan, "prompt", "app.py", 11),
            links=[link(root, "intervention", "app.py", 11, id="l1", how="traced")],
            absent_links=absent,
            decision=CLOSE,
            steps=REGRESSION,
        )

    result = _claim(scan, plan, record([]), tmp_path)
    assert result.claim == "review"
    assert any("the scan lists objective" in note and "app.py:12" in note for note in result.notes)


# ---------------------------------------------------------------------------
# 12, 13. Verdict words; a skeptic claim
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    ["it is  safe", "it is\tsafe", "it is safe", "safe  to deploy", "safe\nto\ndeploy"],
)
def test_a_verdict_is_found_however_it_is_spaced(text: str) -> None:
    assert verdict_words_in(text)


def test_a_skeptic_claim_with_no_reason_leaves_the_pass_not_run(tmp_path: Path) -> None:
    root = _with_handler(tmp_path, CHECK)
    scan, plan = _rescan(root)
    location = cite(root, "companion.py", _line_of(root, "companion.py", "urgent ="))
    records = tmp_path / "records"
    write_record(records, _crisis(root, plan, location), skeptic="upheld")
    path = records / "inv-m5.skeptic.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    for reason in (None, "   "):
        document["claims"] = [{"claim": "x", "result": "upheld", "reason": reason}]
        path.write_text(json.dumps(document), encoding="utf-8")
        result = _results(scan, plan, records)["inv-m5"]
        assert not result.skeptic["bound"] and result.skeptic["result"] == "not_run"
    assert any("{claim, result: upheld or refuted, reason}" in note for note in result.notes)


# ---------------------------------------------------------------------------
# 14, 15. Supersessions
# ---------------------------------------------------------------------------


def _persona(tmp_path: Path):
    root = copy_tree("partial_trace", tmp_path)
    scan, plan = _rescan(root)
    return root, scan, plan


def _reading(root: Path, plan: dict, record_id: str, decision: str, **extra) -> dict:
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
        decision=decision,
        **extra,
    )


def test_a_chain_of_three_supersessions_replaces_all_it_names(tmp_path: Path) -> None:
    root, scan, plan = _persona(tmp_path)
    records = tmp_path / "records"
    # A file name that sorts first: the newest record is read before the two it stands over.
    write_record(records, _reading(root, plan, "a", REVIEW), skeptic="upheld")
    write_record(records, _reading(root, plan, "b", REVIEW, supersedes=["a"]), skeptic="upheld")
    write_record(records, _reading(root, plan, "0c", REVIEW, supersedes=["b"]), skeptic="upheld")
    by_id = _results(scan, plan, records)
    assert by_id["0c"].accepted
    assert by_id["a"].status == by_id["b"].status == "superseded"


@pytest.mark.parametrize("skeptic", ["upheld", None], ids=["upheld", "no pass"])
def test_a_proposed_violation_at_review_is_not_replaced_by_a_closing(
    tmp_path: Path, skeptic: str | None
) -> None:
    root, scan, plan = _persona(tmp_path)
    records = tmp_path / "records"
    held = _reading(root, plan, "inv-viol", VIOLATES, open_questions=["who reads this?"])
    write_record(records, held, skeptic=skeptic)
    closing = _reading(
        root,
        plan,
        "inv-after",
        CLOSE,
        supersedes=["inv-viol"],
        steps=REGRESSION,
        absent_links=[
            {
                "kind": "intervention",
                "searched": ["persona.py"],
                "reason": "the record says nothing is sent",
                "citations": [],
            }
        ],
    )
    write_record(records, closing, skeptic="upheld")
    by_id = _results(scan, plan, records)
    assert by_id["inv-viol"].accepted and by_id["inv-viol"].claim == "review"
    assert by_id["inv-after"].status == "rejected"
    assert any("proposes a violation" in error for error in by_id["inv-after"].errors)


def test_a_proposed_violation_is_replaced_by_another(tmp_path: Path) -> None:
    root, scan, plan = _persona(tmp_path)
    records = tmp_path / "records"
    held = _reading(root, plan, "inv-viol", VIOLATES, open_questions=["who reads this?"])
    write_record(records, held)
    write_record(
        records,
        _reading(root, plan, "inv-next", VIOLATES, supersedes=["inv-viol"]),
        skeptic="upheld",
    )
    by_id = _results(scan, plan, records)
    assert by_id["inv-viol"].status == "superseded" and by_id["inv-next"].claim == "establishes"


# ---------------------------------------------------------------------------
# True limits: what the line cannot show stays with the skeptic and a person
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "needle"),
    [
        ("    x = 1\n", "x = 1"),
        (
            "    def crisis_check(t):\n        return t\n    crisis_check(body)\n",
            "    crisis_check(body)",
        ),
        ('    if body.get("admin"):\n        crisis_check(body)\n', "        crisis_check(body)"),
    ],
    ids=["any running line", "a stub in the same function", "a real condition"],
)
def test_what_a_line_cannot_show_is_a_true_limit(tmp_path: Path, code: str, needle: str) -> None:
    root = _with_handler(tmp_path, code)
    location = cite(root, "companion.py", _line_of(root, "companion.py", needle))
    _shown_closed(root, lambda plan: _crisis(root, plan, location), tmp_path)


def test_logging_ruled_out_over_a_real_log_line_is_a_true_limit(tmp_path: Path) -> None:
    root = copy_tree("sanitised_transmission", tmp_path)
    _replace(
        root,
        "telemetry.py",
        "    event = anonymise(user_id, text)\n",
        '    print("trace", user_id, text)\n    event = anonymise(user_id, text)\n',
    )
    done = _line_of(root, "telemetry.py", "event = anonymise")
    send = _line_of(root, "telemetry.py", "analytics.track")
    _shown_closed(
        root, lambda plan: _anon(root, plan, _anon_links(root, done, send), done), tmp_path
    )
