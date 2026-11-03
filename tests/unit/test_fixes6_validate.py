"""tests/unit/test_fixes6_validate.py
----------------------------------
Sixth-round regressions for `aisafe investigate validate`, each confirmed by an independent
review that ran it. The rule: a closing never counts on code that may not run, and what the
machine cannot show goes to review. Each section also pins the honest code that must keep
its claim.

- a control in a block that may not run: an arm, a loop, a `try` whose handler carries on;
- the control rebound: `global` in a function, an attribute stored from outside;
- an `async def` never awaited, a generator never iterated;
- an edge to a prompt file joined by a word that only looks like its stem;
- a statement that reads a prompt fetched at run time, other than an assignment;
- a prompt surface whose prompt feeds a second, unguarded model call;
- a control in an `assert`, which `python -O` drops;
- a control re-exported through a package `__init__.py`, which closes.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest
from investigation_helpers import cite, copy_tree, link, make_record, surface_of, write_record

from aisafe.investigation.plan import build_plan
from aisafe.investigation.scan import machine_scan
from aisafe.investigation.text import file_lines
from aisafe.investigation.validate import _truth, validate_paths

CLOSE = "no_violation_identified_in_scope"
REGRESSION = [{"id": "v1", "purpose": "regression", "kind": "reinvestigate", "note": "read again"}]
HANDLER = "    body = await request.json()\n"
IMPORT = "from safety import crisis_check  # noqa: F401  (kept for the next release)\n"
APP_LINE = "app = FastAPI()\n"
CHECK = '    crisis_check(body["text"])\n'
SAFETY_BODY = '    lowered = text.lower()\n    return "988" if "end my life" in lowered else None\n'


def _write(root: Path, file: str, text: str) -> None:
    (root / file).parent.mkdir(parents=True, exist_ok=True)
    (root / file).write_text(text, encoding="utf-8", newline="\n")


def _replace(root: Path, file: str, old: str, new: str) -> None:
    text = (root / file).read_text(encoding="utf-8")
    assert old in text, (file, old)
    _write(root, file, text.replace(old, new))


def _line_of(root: Path, file: str, needle: str) -> int:
    return next(i for i, t in enumerate(file_lines(root / file), 1) if needle in t)


def _hop(root: Path, file: str, line: int) -> dict:
    return {**cite(root, file, line), "step": "the way between them"}


def _run(root: Path, make: Any, tmp_path: Path) -> Any:
    scan = machine_scan(root)
    plan = build_plan(scan)
    record = make(plan)
    records = tmp_path / "records"
    write_record(records, record, skeptic="upheld")
    run = validate_paths([records], scan, plan_surfaces={s["id"]: s for s in plan["surfaces"]})
    assert run.fatal is None, run.fatal
    result = next(r for r in run.results if r.id == record["id"])
    assert result.accepted, result.errors
    return result


def _crisis(root: Path, plan: dict, location: dict, hops=(), surface=None) -> dict:
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
                "link": "l3",
                "reason": "the record says the check runs on the path",
                "via": list(hops),
            }
        ],
        decision=CLOSE,
        steps=REGRESSION,
    )


def _crisis_case(
    tmp_path: Path,
    code: str,
    needle: str | None,
    *,
    imports: str | None = None,
    after_import: str = "",
    safety: str | None = None,
    files: dict[str, str] | None = None,
    where: tuple[str, int, int] = ("safety.py", 7, 10),
) -> Any:
    """The reviewer's shape: `code` in the handler, the check's body as the location, a hop
    on the line that holds `needle`."""
    root = copy_tree("control_not_on_path", tmp_path)
    _replace(root, "companion.py", HANDLER, HANDLER + code)
    if imports is not None:
        _replace(root, "companion.py", IMPORT, imports)
    if after_import:
        _replace(root, "companion.py", APP_LINE, after_import + APP_LINE)
    if safety is not None:
        _write(root, "safety.py", safety)
    for name, text in (files or {}).items():
        _write(root, name, text)

    def make(plan: dict) -> dict:
        location = cite(root, where[0], where[1], end_line=where[2])
        hops = (
            [_hop(root, "companion.py", _line_of(root, "companion.py", needle))] if needle else []
        )
        return _crisis(root, plan, location, hops)

    return _run(root, make, tmp_path)


def _closes(result: Any) -> None:
    assert result.control_on_path and result.claim == "closes", result.notes


def _review(result: Any) -> None:
    assert not result.control_on_path and result.claim == "review", result.notes


# ---------------------------------------------------------------------------
# 1. A control in a block that may not run
# ---------------------------------------------------------------------------

MAY_NOT_RUN = {
    "an arm that returns early": (
        '    if body.get("fast"):\n    ' + CHECK + '        return {"reply": "hi"}\n',
        "",
    ),
    "a module flag that is off": ("    if CRISIS_ON:\n    " + CHECK, "CRISIS_ON = False\n"),
    "a real condition": ('    if body.get("admin"):\n    ' + CHECK, ""),
    "an identity the syntax settles": ("    if None is not None:\n    " + CHECK, ""),
    "a loop that runs no time": ("    for _ in range(0):\n    " + CHECK, ""),
    "a while on a flag": (
        "    while CRISIS_ON:\n    " + CHECK + "        break\n",
        "CRISIS_ON = False\n",
    ),
    "a try that swallows": ("    try:\n    " + CHECK + "    except Exception:\n        pass\n", ""),
    "a match arm": ('    match body.get("mode"):\n        case "safe":\n        ' + CHECK, ""),
    "the else of a loop with a break": (
        "    for item in body:\n        break\n    else:\n    " + CHECK,
        "",
    ),
    "the right of an and": ('    body.get("check") and crisis_check(body["text"])\n', ""),
    "a branch of a conditional expression": (
        '    _ = crisis_check(body["text"]) if body.get("check") else None\n',
        "",
    ),
}


@pytest.mark.parametrize("case", sorted(MAY_NOT_RUN))
def test_a_control_that_may_not_run_goes_to_review(tmp_path: Path, case: str) -> None:
    code, after = MAY_NOT_RUN[case]
    _review(_crisis_case(tmp_path, code, "crisis_check(body", after_import=after))


def test_a_span_over_the_header_and_its_block_goes_to_review(tmp_path: Path) -> None:
    # The header line runs; what the citation shows inside the block may not.
    root = copy_tree("control_not_on_path", tmp_path)
    _replace(root, "companion.py", HANDLER, HANDLER + '    if body.get("admin"):\n    ' + CHECK)
    first = _line_of(root, "companion.py", "if body.get")
    location = cite(root, "companion.py", first, end_line=first + 1)
    _review(_run(root, lambda plan: _crisis(root, plan, location), tmp_path))


def test_the_truth_of_is_between_singletons_only() -> None:
    def truth(text: str):
        return _truth(ast.parse(text, mode="eval").body)

    assert truth("None is not None") is False
    assert truth("None is None") is True
    assert truth("1 is 1") is None  # identity of other constants is not the syntax's


HONEST = {
    "a plain call": (CHECK, "crisis_check(body"),
    "a call in the condition": (
        '    if crisis_check(body["text"]):\n        return {"reply": "call 988"}\n',
        "if crisis_check",
    ),
    "a finally": ("    try:\n        pass\n    finally:\n    " + CHECK, "crisis_check(body"),
    "a try whose handler re-raises": (
        "    try:\n    " + CHECK + "    except ValueError:\n        raise\n",
        "crisis_check(body",
    ),
    "the left of an or": ('    crisis_check(body["text"]) or None\n', "crisis_check(body"),
}


@pytest.mark.parametrize("case", sorted(HONEST))
def test_a_control_that_surely_runs_still_closes(tmp_path: Path, case: str) -> None:
    code, needle = HONEST[case]
    _closes(_crisis_case(tmp_path, code, needle))


def _anonymised(tmp_path: Path, old: str | None, new: str | None) -> Any:
    root = copy_tree("sanitised_transmission", tmp_path)
    if old is not None:
        _replace(root, "telemetry.py", old, new)

    def make(plan: dict) -> dict:
        send = _line_of(root, "telemetry.py", "analytics.track")
        links = [
            link(root, "collection", "chat.py", 15, id="l1"),
            link(
                root,
                "transformation",
                "telemetry.py",
                10,
                id="l2",
                how="traced",
                via=[_hop(root, "chat.py", 16)],
                **{"from": "l1"},
            ),
            link(
                root, "transmission", "telemetry.py", send, id="l3", how="traced", **{"from": "l2"}
            ),
        ]
        location = cite(root, "telemetry.py", _line_of(root, "telemetry.py", "event = anonymise"))
        return make_record(
            id="inv-m1",
            mechanism="M1",
            pattern="transmission",
            view="person-data",
            surface=surface_of(plan, "external_destination", "telemetry.py"),
            links=links,
            controls=[
                {
                    "name": "anonymisation",
                    "location": location,
                    "on_path": "yes",
                    "link": "l3",
                    "reason": "anonymised before it leaves",
                    "via": [],
                }
            ],
            absent_links=[
                {
                    "kind": "logging",
                    "searched": ["telemetry.py"],
                    "reason": "no log",
                    "citations": [],
                }
            ],
            decision=CLOSE,
            steps=REGRESSION,
        )

    return _run(root, make, tmp_path)


def test_anonymisation_in_one_arm_goes_to_review(tmp_path: Path) -> None:
    _closes(_anonymised(tmp_path, None, None))
    arm = (
        "    if user_id:\n        event = anonymise(user_id, text)\n"
        '    else:\n        event = {"text": text, "user": user_id}\n'
    )
    _review(_anonymised(tmp_path / "arm", "    event = anonymise(user_id, text)\n", arm))


# ---------------------------------------------------------------------------
# 2. The control rebound
# ---------------------------------------------------------------------------


def test_a_global_rebinding_in_a_function_goes_to_review(tmp_path: Path) -> None:
    off = "def _off():\n    global crisis_check\n    crisis_check = lambda t: None\n\n\n_off()\n"
    _review(_crisis_case(tmp_path, CHECK, "crisis_check(body", after_import=off))


@pytest.mark.parametrize(
    "patch",
    [
        "safety.crisis_check = lambda t: None\n",
        'setattr(safety, "crisis_check", lambda t: None)\n',
    ],
    ids=["an attribute", "setattr"],
)
def test_an_attribute_stored_over_the_control_goes_to_review(tmp_path: Path, patch: str) -> None:
    code = '    safety.crisis_check(body["text"])\n'
    _closes(
        _crisis_case(tmp_path / "honest", code, "safety.crisis_check(", imports="import safety\n")
    )
    _review(
        _crisis_case(
            tmp_path, code, "safety.crisis_check(", imports="import safety\n", after_import=patch
        )
    )


def test_an_attribute_stored_from_another_file_goes_to_review(tmp_path: Path) -> None:
    files = {"boot.py": "import safety\n\nsafety.crisis_check = print\n"}
    _review(_crisis_case(tmp_path, CHECK, "crisis_check(body", files=files))


GUARD = {"guard/safety.py": "def crisis_check(text):\n" + SAFETY_BODY}


def test_a_control_re_exported_by_a_package_closes(tmp_path: Path) -> None:
    files = {**GUARD, "guard/__init__.py": "from guard.safety import crisis_check\n"}
    result = _crisis_case(
        tmp_path,
        CHECK,
        "crisis_check(body",
        imports="from guard import crisis_check\n",
        files=files,
        where=("guard/safety.py", 2, 3),
    )
    _closes(result)


def test_a_re_export_the_package_rebinds_goes_to_review(tmp_path: Path) -> None:
    init = "from guard.safety import crisis_check\n\ncrisis_check = print\n"
    result = _crisis_case(
        tmp_path,
        CHECK,
        "crisis_check(body",
        imports="from guard import crisis_check\n",
        files={**GUARD, "guard/__init__.py": init},
        where=("guard/safety.py", 2, 3),
    )
    _review(result)


# ---------------------------------------------------------------------------
# 3. An `async def` never awaited, a generator never iterated
# ---------------------------------------------------------------------------

ASYNC_SAFETY = "async def crisis_check(text):\n" + SAFETY_BODY


def test_an_async_control_never_awaited_goes_to_review(tmp_path: Path) -> None:
    result = _crisis_case(
        tmp_path, CHECK, "crisis_check(body", safety=ASYNC_SAFETY, where=("safety.py", 2, 3)
    )
    _review(result)


@pytest.mark.parametrize(
    ("code", "needle", "imports"),
    [
        ('    await crisis_check(body["text"])\n', "await crisis_check", IMPORT),
        (
            '    await asyncio.gather(crisis_check(body["text"]))\n',
            "asyncio.gather",
            "import asyncio\nfrom safety import crisis_check\n",
        ),
    ],
    ids=["await", "gather"],
)
def test_an_async_control_awaited_closes(
    tmp_path: Path, code: str, needle: str, imports: str
) -> None:
    result = _crisis_case(
        tmp_path, code, needle, imports=imports, safety=ASYNC_SAFETY, where=("safety.py", 2, 3)
    )
    _closes(result)


def test_a_generator_control_goes_to_review(tmp_path: Path) -> None:
    safety = (
        "def crisis_check(text):\n    lowered = text.lower()\n"
        '    yield "988" if "end my life" in lowered else None\n'
    )
    result = _crisis_case(
        tmp_path, CHECK, "crisis_check(body", safety=safety, where=("safety.py", 2, 3)
    )
    _review(result)


# ---------------------------------------------------------------------------
# 4. An edge to a prompt file needs the file named in a string
# ---------------------------------------------------------------------------

PERSONA = "# Persona\n\nYou help people plan their week.\nYour goal is to keep the user talking as long as possible.\n"
APP = """import logging
from pathlib import Path

import anthropic
from fastapi import FastAPI, Request

log = logging.getLogger(__name__)
app = FastAPI()
client = anthropic.Anthropic()
SYSTEM = "You help people plan their week. Answer briefly."


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    HOPLINE
    reply = client.messages.create(model="m", max_tokens=400, system=SYSTEM, messages=[{"role": "user", "content": body["text"]}])
    return {"reply": reply.content[0].text}
"""


def _objective(tmp_path: Path, hopline: str) -> Any:
    root = tmp_path / "tree"
    _write(root, "prompts/persona.md", PERSONA)
    _write(root, "app.py", APP.replace("HOPLINE", hopline))

    def make(plan: dict) -> dict:
        hop = _hop(root, "app.py", _line_of(root, "app.py", hopline.strip()[:12]))
        return make_record(
            id="inv-m4",
            mechanism="M4",
            pattern="objective",
            surface=surface_of(plan, "prompt", "prompts/persona.md"),
            links=[
                link(root, "objective", "prompts/persona.md", 4, id="l1"),
                link(
                    root,
                    "intervention",
                    "app.py",
                    _line_of(root, "app.py", "reply.content"),
                    id="l2",
                    how="traced",
                    via=[hop],
                    **{"from": "l1"},
                ),
            ],
            decision="violates_policy",
        )

    return _run(root, make, tmp_path)


@pytest.mark.parametrize(
    "hopline",
    [
        'log.info("persona check skipped")',
        'persona = body.get("name")',
        'log.info("other/persona.md")',
    ],
    ids=["a log message", "a variable", "a file of that name elsewhere"],
)
def test_a_word_like_the_stem_joins_nothing(tmp_path: Path, hopline: str) -> None:
    result = _objective(tmp_path, hopline)
    assert not result.connected and result.claim != "establishes", result.notes
    assert any("crosses files with no `via` hop" in n for n in result.notes)


@pytest.mark.parametrize(
    "hopline",
    [
        'SYSTEM = open("prompts/persona.md").read()',
        'SYSTEM = (Path(__file__).parent / "prompts" / "persona.md").read_text()',
    ],
    ids=["its path", "its name"],
)
def test_a_string_that_names_the_file_joins(tmp_path: Path, hopline: str) -> None:
    result = _objective(tmp_path, hopline)
    assert result.connected and result.claim == "establishes", result.notes


# ---------------------------------------------------------------------------
# 5. Statements that read a prompt fetched at run time
# ---------------------------------------------------------------------------

BOT = """from fastapi import FastAPI, Request
import anthropic
import requests

app = FastAPI()
client = anthropic.Anthropic()
PROMPT_URL = "https://prompts.example.invalid/companion/latest"


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    system_prompt = requests.get(PROMPT_URL, timeout=5).text
    TAIL
"""


def _bot(tmp_path: Path, tail: str) -> Path:
    root = copy_tree("runtime_prompt", tmp_path)
    _write(root, "bot.py", BOT.replace("TAIL", tail))
    return root


def test_a_prompt_link_on_a_return_that_reads_the_fetched_name_is_runtime(tmp_path: Path) -> None:
    root = _bot(
        tmp_path,
        'return {"reply": client.messages.create(model="m", max_tokens=3, system=system_prompt, '
        'messages=[{"role": "user", "content": body["text"]}]).content[0].text}',
    )
    line = _line_of(root, "bot.py", "return {")

    def make(plan: dict) -> dict:
        return make_record(
            id="inv-m6",
            mechanism="M6",
            pattern="concealment_instruction",
            surface=surface_of(plan, "model_entry", "bot.py", line),
            links=[
                link(root, "prompt", "bot.py", line, id="l1", quote="system=system_prompt"),
                link(root, "intervention", "bot.py", line, id="l2", how="traced", **{"from": "l1"}),
            ],
            decision="violates_policy",
        )

    result = _run(root, make, tmp_path)
    assert result.claim == "review" and "prompt" in result.runtime, result.notes


def test_a_control_on_an_append_of_the_fetched_name_closes_nothing(tmp_path: Path) -> None:
    root = _bot(
        tmp_path,
        'msgs = []\n    msgs.append({"role": "system", "content": system_prompt})\n'
        '    reply = client.messages.create(model="m", max_tokens=3, messages=msgs + '
        '[{"role": "user", "content": body["text"]}])\n'
        '    return {"reply": reply.content[0].text}',
    )

    def make(plan: dict) -> dict:
        return make_record(
            id="inv-m6",
            mechanism="M6",
            pattern="no_disclosure_on_path",
            surface=surface_of(plan, "person_facing_unit", "."),
            links=[
                link(root, "ingress", "bot.py", _line_of(root, "bot.py", "await request"), id="l1"),
                link(
                    root,
                    "intervention",
                    "bot.py",
                    _line_of(root, "bot.py", "return {"),
                    id="l2",
                    how="traced",
                    **{"from": "l1"},
                ),
            ],
            controls=[
                {
                    "name": "ai_disclosure",
                    "location": cite(root, "bot.py", _line_of(root, "bot.py", "msgs.append")),
                    "on_path": "yes",
                    "link": "l2",
                    "reason": "the fetched system prompt discloses",
                }
            ],
            decision=CLOSE,
            steps=REGRESSION,
        )

    result = _run(root, make, tmp_path)
    _review(result)
    assert any("fetched or built at run time" in n for n in result.notes)


# ---------------------------------------------------------------------------
# 6. A prompt surface answers every model call its prompt reaches
# ---------------------------------------------------------------------------

SECOND = """

@app.post("/talk2")
async def talk2(request: Request):
    body = await request.json()
    reply = client.messages.create(model="m", max_tokens=300, system=SYSTEM_PROMPT, messages=[{"role": "user", "content": body["text"]}])
    return {"reply": reply.content[0].text}
"""


def _prompt_surface(tmp_path: Path, second: bool) -> Any:
    root = copy_tree("control_not_on_path", tmp_path)
    _replace(root, "companion.py", HANDLER, HANDLER + CHECK)
    if second:
        _write(root, "companion.py", (root / "companion.py").read_text(encoding="utf-8") + SECOND)

    def make(plan: dict) -> dict:
        location = cite(root, "safety.py", 7, end_line=10)
        hops = [_hop(root, "companion.py", _line_of(root, "companion.py", "crisis_check(body"))]
        surface = surface_of(plan, "prompt", "companion.py")
        return _crisis(root, plan, location, hops, surface=surface)

    return _run(root, make, tmp_path)


def test_a_prompt_surface_with_an_unguarded_second_call_goes_to_review(tmp_path: Path) -> None:
    _closes(_prompt_surface(tmp_path / "one", second=False))
    result = _prompt_surface(tmp_path, second=True)
    _review(result)
    assert any("takes the prompt the record answers" in n for n in result.notes)


# ---------------------------------------------------------------------------
# 7. A control in an `assert`
# ---------------------------------------------------------------------------


def test_a_control_in_an_assert_goes_to_review(tmp_path: Path) -> None:
    code = '    assert crisis_check(body["text"]) is None or True\n'
    _review(_crisis_case(tmp_path, code, "crisis_check(body"))


def test_the_skill_names_the_true_limits_of_this_round() -> None:
    doc = Path(__file__).resolve().parents[2] / "src/aisafe/skills/ai-safety-audit/references"
    text = " ".join((doc / "investigate.md").read_text(encoding="utf-8").split())
    for words in ("ignored return value", "decorator", "globals()", "functools.partial"):
        assert words in text, words
