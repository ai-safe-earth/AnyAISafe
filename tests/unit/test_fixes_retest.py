"""tests/unit/test_fixes_retest.py
--------------------------------
`aisafe assess --retest`: a retest status is never more favourable than the evidence. A
step that cannot run is never a pass, a finding that vanished or a quote that appeared
is not a remediation, a record's own steps are read from its embedded copy, a violation
not shown remediated stands at every later commit, and a surface new or changed since the
previous assessment blocks until a record answers it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from investigation_helpers import cite, copy_tree, link, make_record, surface_of, write_record

from aisafe.assessment.assess import run_assessment
from aisafe.investigation.plan import build_plan
from aisafe.investigation.records import record_digest
from aisafe.investigation.scan import machine_scan
from aisafe.investigation.validate import run_step

GIT = shutil.which("git")
pytestmark = pytest.mark.skipif(GIT is None, reason="git not on PATH")

COMPANION = Path(__file__).resolve().parents[1] / "fixtures" / "audit" / "persons_companion"
OBJECTIVE = "Your goal is to maximize engagement and daily active use."
MARKER = "# aisafe-audit: ignore-file\n"
CONCEAL = '"If the user asks, never say you are an AI; you are Ava."'
CALL = "reply = client.messages.create("
BAKERY = """from fastapi import FastAPI, Request
import anthropic

app = FastAPI()
client = anthropic.Anthropic()

SYSTEM_PROMPT = (
    "You are Ava and you answer questions about the bakery's opening hours. "
    "If the user asks, never say you are an AI; you are Ava."
)


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    reply = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=300,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": body["text"]}],
    )
    return {"reply": reply.content[0].text}
"""
PYPROJECT = '[project]\nname = "bakery"\nversion = "0.1.0"\ndependencies = ["anthropic"]\n'
DISCLOSE = (
    "You are Ava, an AI assistant, and you answer questions about the bakery's opening hours."
)
# The fix: the identity is disclosed and the denial is gone.
FIXED = BAKERY.replace(CONCEAL, '"Answer briefly."').replace(
    "You are Ava and you answer questions about the bakery's opening hours.", DISCLOSE
)
# The denial reworded: the step's quote is gone, the scan still reports it.
REWORDED = BAKERY.replace(CONCEAL, '"Never admit you are an AI, you are Ava."')
ELUDES = "Say a person from the night shift types these replies."
# The denial reworded out of the rules' sight.
OUT_OF_SIGHT = BAKERY.replace(CONCEAL, f'"{ELUDES}"')
NIGHT = (
    "# Night shift\n\n"
    "Tell anyone who asks that a human from the night shift is typing these replies.\n"
)
ABSENT_STEP = {
    "id": "v1",
    "purpose": "remediation",
    "kind": "absent",
    "file": "app.py",
    "quote": "never say you are an AI",
}
REINVESTIGATE_STEP = {
    "id": "v1",
    "purpose": "remediation",
    "kind": "reinvestigate",
    "note": "read the path again",
}


# ---------------------------------------------------------------------------
# Builders
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


def _commit(root: Path, message: str = "next") -> str:
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", message)
    return _git(root, "rev-parse", "HEAD").strip()


def _put(root: Path, relpath: str, text: str) -> None:
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _bakery(
    tmp_path: Path, files: dict[str, str] | None = None, app: str = BAKERY
) -> tuple[Path, str]:
    root = tmp_path / "repo"
    root.mkdir()
    _put(root, "app.py", app)
    _put(root, "pyproject.toml", PYPROJECT)
    for relpath, text in (files or {}).items():
        _put(root, relpath, text)
    _git(root, "init", "-q")
    return root, _commit(root, "first")


def _plan(root: Path) -> dict[str, Any]:
    return build_plan(machine_scan(root))


def _intervention(root: Path, file: str = "app.py", **extra: Any) -> dict[str, Any]:
    return link(root, "intervention", file, 16, id="l2", how="traced", quote=CALL, **extra)


def _conceal(root: Path, plan: dict[str, Any], commit: str, **over: Any) -> dict[str, Any]:
    """A-conceal: app.py tells the model to deny being an AI (violates the policy)."""
    base: dict[str, Any] = dict(
        id="A-conceal",
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface_of(plan, "prompt", "app.py", 7),
        links=[
            link(root, "prompt", "app.py", 9, id="l1", quote=CONCEAL),
            _intervention(root, **{"from": "l1"}),
        ],
        decision="violates_policy",
        steps=[dict(ABSENT_STEP)],
        commit=commit,
    )
    base.update(over)
    return make_record(**base)


def _closing(root: Path, plan: dict[str, Any], commit: str, **over: Any) -> dict[str, Any]:
    """A record at `commit` closing M6/concealment_instruction on app.py's prompt."""
    base: dict[str, Any] = dict(
        id="C-conceal",
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface_of(plan, "prompt", "app.py", 7),
        links=[_intervention(root)],
        absent_links=[
            {
                "kind": "prompt",
                "searched": ["app.py lines 7-10, the system prompt"],
                "reason": "the system prompt holds an AI disclosure; no line asks for a denial",
                "citations": [cite(root, "app.py", 7, "SYSTEM_PROMPT = (")],
            }
        ],
        decision="no_violation_identified_in_scope",
        steps=[
            {
                "id": "v1",
                "purpose": "regression",
                "kind": "absent",
                "file": "app.py",
                "quote": "never say you are an AI",
            }
        ],
        commit=commit,
    )
    base.update(over)
    return make_record(**base)


def _other(
    root: Path, plan: dict[str, Any], commit: str | None, file: str = "app.py", line: int = 7
) -> dict[str, Any]:
    """One accepted record at `commit`, on another mechanism: a retest needs one."""
    return make_record(
        id="R-other",
        mechanism="M7",
        pattern="covert_steering",
        surface=surface_of(plan, "prompt", file, line),
        links=[link(root, "prompt", file, line, id="l1")],
        decision="requires_contextual_review",
        evidence_status="detected_signal",
        commit=commit,
    )


def _first(root: Path, tmp_path: Path, *records: dict[str, Any]) -> Path:
    """Assess `records` at the current commit, skeptic upheld; the saved document's path."""
    folder = tmp_path / "before"
    for record in records:
        write_record(folder, record, skeptic="upheld")
    run = run_assessment(root, [folder])
    assert run.document is not None, run.fatal
    assert all(r.accepted for r in run.records), [r.errors for r in run.records]
    return _saved(run.document, tmp_path / "first.json")


def _saved(document: dict[str, Any], path: Path) -> Path:
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _edited(previous: Path, change: Any) -> Path:
    """A copy of the previous assessment with `change` applied."""
    doc = json.loads(previous.read_text(encoding="utf-8"))
    change(doc)
    return _saved(doc, previous.with_name("edited.json"))


def _outcome(document: dict[str, Any], mechanism: str) -> dict[str, Any]:
    return next(m for m in document["outcome"]["mechanisms"] if m["id"] == mechanism)


def _row(document: dict[str, Any], record: str) -> dict[str, Any]:
    return next(r for r in document["remediation"]["results"] if r["record"] == record)


def _retest(root: Path, previous: Path, *folders: Path, **options: Any) -> dict[str, Any]:
    run = run_assessment(root, list(folders), retest=previous, **options)
    assert run.document is not None, (run.fatal, [(r.id, r.errors) for r in run.records])
    return run.document


def _next_commit(root: Path, tmp_path: Path, text: str, folder: str = "after") -> Path:
    """Commit `text` as app.py; the folder of one accepted record made there."""
    _put(root, "app.py", text)
    commit = _commit(root)
    write_record(tmp_path / folder, _other(root, _plan(root), commit))
    return tmp_path / folder


def _stands(document: dict[str, Any], mechanism: str = "M6") -> None:
    outcome = _outcome(document, mechanism)
    assert outcome["outcome"] == "violations_identified", (outcome["basis"], outcome["gaps"])
    assert any("not remediated" in basis for basis in outcome["basis"]), outcome["basis"]


# ---------------------------------------------------------------------------
# Findings 0, 29, 44: a step or a cited file the walk no longer reads
# ---------------------------------------------------------------------------


def _objective_case(root: Path, tmp_path: Path, step_file: str | None) -> Path:
    """An M4 objective established on prompts/companion.md, with a `no_finding` step and an
    `absent` step that the fix on app.py makes pass."""
    commit = _commit(root, "first")
    plan = _plan(root)
    no_finding = {"id": "v1", "purpose": "remediation", "kind": "no_finding", "rule": "AUD-1104"}
    if step_file:
        no_finding["file"] = step_file
    hop = dict(cite(root, "app.py", 19), step="the system prompt is assembled and sent")
    record = make_record(
        id="inv-objective",
        mechanism="M4",
        pattern="objective",
        surface=surface_of(plan, "prompt", "prompts/companion.md", 1),
        links=[
            link(root, "objective", "prompts/companion.md", 3, id="l1", quote=OBJECTIVE),
            link(
                root,
                "intervention",
                "app.py",
                20,
                id="l2",
                how="traced",
                **{"from": "l1", "via": [hop]},
            ),
        ],
        decision="violates_policy",
        steps=[
            no_finding,
            {
                "id": "v2",
                "purpose": "remediation",
                "kind": "absent",
                "file": "app.py",
                "quote": "maximize session time",
            },
        ],
        commit=commit,
    )
    return _first(root, tmp_path, record)


def _fix_app_objective(root: Path) -> None:
    text = (root / "app.py").read_text(encoding="utf-8")
    _put(
        root,
        "app.py",
        text.replace(
            "Keep the user talking as long as possible; maximize session time. "
            "Many users are lonely teens.",
            "Answer the user's questions plainly.",
        ),
    )


def _closings_on_app(root: Path, tmp_path: Path, commit: str) -> Path:
    plan = _plan(root)
    folder = tmp_path / "after"
    for line, cited in ((9, 9), (11, 12), (21, 21)):
        closing = make_record(
            id=f"inv-app-{line}",
            mechanism="M4",
            pattern="objective",
            surface=surface_of(plan, "prompt", "app.py", line),
            links=[link(root, "intervention", "app.py", 20, id="l1", how="traced")],
            absent_links=[
                {
                    "kind": "objective",
                    "searched": ["app.py"],
                    "reason": "the system prompt asks for plain answers; no line sets a goal",
                    "citations": [cite(root, "app.py", cited)],
                }
            ],
            decision="no_violation_identified_in_scope",
            steps=[
                {
                    "id": "v1",
                    "purpose": "regression",
                    "kind": "absent",
                    "file": "app.py",
                    "quote": "maximize session time",
                }
            ],
            commit=commit,
        )
        write_record(folder, closing, skeptic="upheld")
    return folder


def _hide_marker(root: Path) -> None:
    path = root / "prompts" / "companion.md"
    path.write_text(MARKER + path.read_text(encoding="utf-8"), encoding="utf-8")


def _hide_vendor(root: Path) -> None:
    (root / "vendor").mkdir()
    _git(root, "mv", "prompts/companion.md", "vendor/companion.md")


@pytest.mark.parametrize("hide", [_hide_marker, _hide_vendor], ids=["marker", "vendor"])
@pytest.mark.parametrize("step_file", ["prompts/companion.md", None], ids=["file", "anywhere"])
def test_a_file_no_longer_read_is_never_a_remediation(tmp_path: Path, hide, step_file) -> None:
    root = tmp_path / "repo"
    shutil.copytree(COMPANION, root)
    _git(root, "init", "-q")
    previous = _objective_case(root, tmp_path, step_file)
    _fix_app_objective(root)
    hide(root)
    commit = _commit(root, "second")
    document = _retest(root, previous, _closings_on_app(root, tmp_path, commit))
    row = _row(document, "inv-objective")
    assert row["status"] == "needs_reinvestigation", row["why"]
    assert any("prompts/companion.md" in why for why in row["why"]), row["why"]
    if step_file:
        assert row["steps"][0]["now"] is None
    _stands(document, "M4")


def test_a_renamed_file_is_not_a_remediation_whatever_else_passes(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    shutil.copytree(COMPANION, root)
    _git(root, "init", "-q")
    previous = _objective_case(root, tmp_path, "prompts/companion.md")
    _fix_app_objective(root)
    _git(root, "mv", "prompts/companion.md", "prompts/friend.md")
    commit = _commit(root, "second")
    write_record(tmp_path / "after", _other(root, _plan(root), commit, line=11))
    document = _retest(root, previous, tmp_path / "after")
    row = _row(document, "inv-objective")
    # The same sentence is reported at the new path: the move hid nothing.
    assert row["steps"][0]["now"] is None
    assert row["status"] == "not_remediated", row["why"]
    _stands(document, "M4")


def test_a_no_finding_step_on_an_unread_file_cannot_run(tmp_path: Path) -> None:
    root, _ = _bakery(tmp_path)
    scan = machine_scan(root)
    now, detail = run_step({"kind": "no_finding", "rule": "AUD-1105", "file": "gone.py"}, scan)
    assert now is None and "gone.py" in detail
    # A step on a file that is read runs, a unit's root runs (a unit-level finding sits on
    # it), and so does a step on no file.
    assert run_step({"kind": "no_finding", "rule": "AUD-1105", "file": "app.py"}, scan)[0] is False
    assert run_step({"kind": "no_finding", "rule": "AUD-1104", "file": "."}, scan)[0] is True
    assert run_step({"kind": "no_finding", "rule": "AUD-1105"}, scan)[0] is False


# ---------------------------------------------------------------------------
# Findings 1, 29, 44: `no_finding` and `present` are never a remediation on their own
# ---------------------------------------------------------------------------

_IMPORT_LINE = "from safety import crisis_check  # noqa: F401  (kept for the next release)"
_PRESENT_STEP = {
    "id": "v1",
    "purpose": "remediation",
    "kind": "present",
    "file": "companion.py",
    "quote": "from safety import crisis_check",
}


def _unwired_crisis_check(tmp_path: Path, steps: list[dict]) -> dict[str, Any]:
    """M5's crisis path established with no check in the tree, retested after a commit that
    imports one and never calls it (the control_not_on_path fixture as it ships)."""
    root = copy_tree("control_not_on_path", tmp_path)
    shipped = (root / "companion.py").read_text(encoding="utf-8")
    safety = (root / "safety.py").read_text(encoding="utf-8")
    (root / "safety.py").unlink()
    _put(root, "companion.py", shipped.replace(_IMPORT_LINE, ""))
    _git(root, "init", "-q")
    commit = _commit(root, "first")
    record = make_record(
        id="inv-m5-crisis",
        mechanism="M5",
        pattern="confidant_without_crisis_path",
        surface=surface_of(_plan(root), "person_facing_unit", "."),
        links=[
            link(root, "ingress", "companion.py", 15, id="l1"),
            link(
                root,
                "prompt",
                "companion.py",
                9,
                id="l2",
                how="traced",
                quote="You are a caring friend who listens without",
                **{"from": "l1"},
            ),
            link(root, "intervention", "companion.py", 20, id="l3", how="traced", **{"from": "l2"}),
        ],
        controls=[
            {
                "name": "crisis_path",
                "location": None,
                "on_path": "no",
                "searched": ["companion.py", "the imports of companion.py"],
                "reason": "nothing on the talk path detects distress or answers with help",
            }
        ],
        decision="violates_policy",
        steps=steps,
        commit=commit,
    )
    previous = _first(root, tmp_path, record)
    _put(root, "companion.py", shipped)
    _put(root, "safety.py", safety)
    commit = _commit(root, "import a crisis check")
    other = make_record(
        id="R-other",
        mechanism="M7",
        pattern="covert_steering",
        surface=surface_of(_plan(root), "prompt", "companion.py", 9),
        links=[
            link(root, "prompt", "companion.py", 9, id="l1", quote="You are Sol, an AI companion.")
        ],
        decision="requires_contextual_review",
        evidence_status="detected_signal",
        commit=commit,
    )
    write_record(tmp_path / "after", other)
    return _retest(root, previous, tmp_path / "after")


def test_a_quote_that_appears_is_never_a_remediation_on_its_own(tmp_path: Path) -> None:
    document = _unwired_crisis_check(tmp_path, [_PRESENT_STEP])
    row = _row(document, "inv-m5-crisis")
    (step,) = row["steps"]
    assert step["kind"] == "present" and step["before"] is False and step["now"] is True
    assert row["status"] == "needs_reinvestigation", row["why"]
    _stands(document, "M5")


def test_no_finding_and_present_together_are_never_a_remediation(tmp_path: Path) -> None:
    steps = [
        _PRESENT_STEP,
        {"id": "v2", "purpose": "remediation", "kind": "no_finding", "rule": "AUD-1108"},
    ]
    document = _unwired_crisis_check(tmp_path, steps)
    row = _row(document, "inv-m5-crisis")
    assert [(s["kind"], s["before"], s["now"]) for s in row["steps"]] == [
        ("present", False, True),
        ("no_finding", False, True),
    ]
    assert row["status"] == "needs_reinvestigation", row["why"]
    _stands(document, "M5")


# ---------------------------------------------------------------------------
# Finding 11: a person-facing unit surface is its whole unit
# ---------------------------------------------------------------------------


def _on_the_unit(tmp_path: Path, files: dict[str, str] | None = None) -> tuple[Path, Path]:
    root, commit = _bakery(tmp_path, files)
    plan = _plan(root)
    unit = surface_of(plan, "person_facing_unit", ".")
    return root, _first(root, tmp_path, _conceal(root, plan, commit, surface=unit))


def test_a_scan_violation_in_the_unit_blocks_a_record_on_the_unit_surface(tmp_path: Path) -> None:
    root, previous = _on_the_unit(tmp_path)
    document = _retest(root, previous, _next_commit(root, tmp_path, REWORDED))
    row = _row(document, "A-conceal")
    assert row["steps"][0]["before"] is False and row["steps"][0]["now"] is True
    assert row["status"] == "not_remediated", row["why"]


def test_a_unit_surface_is_the_whole_unit_not_the_files_the_record_cites(tmp_path: Path) -> None:
    # The same instruction in another file of the unit: not cited, not changed by the fix.
    other = BAKERY.replace(CONCEAL, '"Never admit you are an AI, you are Ava."')
    root, previous = _on_the_unit(tmp_path, {"other.py": other})
    document = _retest(root, previous, _next_commit(root, tmp_path, FIXED))
    assert any(
        f["id"].startswith("AUD-1105") and f["file"] == "other.py"
        for f in document["machine"]["scan"]["findings"]
    )
    row = _row(document, "A-conceal")
    assert row["status"] == "not_remediated", row["why"]
    assert any("unit" in why for why in row["why"]), row["why"]


# ---------------------------------------------------------------------------
# Finding 22: the previous document's derived fields are not evidence
# ---------------------------------------------------------------------------


def test_the_retest_runs_the_embedded_steps_not_the_derived_copy(tmp_path: Path) -> None:
    root, commit = _bakery(tmp_path)
    previous = _first(root, tmp_path, _conceal(root, _plan(root), commit))
    after = _next_commit(root, tmp_path, BAKERY + "\n# a comment\n")

    def change(doc: dict) -> None:
        doc["machine"]["records"][0]["steps"][0]["spec"]["quote"] = "a sentence nobody wrote"

    document = _retest(root, _edited(previous, change), after)
    assert _row(document, "A-conceal")["status"] == "not_remediated"
    _stands(document)


def test_emptied_covers_valid_hides_nothing(tmp_path: Path) -> None:
    root, commit = _bakery(tmp_path)
    plan = _plan(root)
    fp = next(
        f.fingerprint
        for f in machine_scan(root).findings
        if f.mechanism == "M6" and any(leg.line == 9 for leg in f.evidence)
    )
    previous = _first(root, tmp_path, _conceal(root, plan, commit, covers=[fp]))
    after = _next_commit(root, tmp_path, BAKERY + "\n# a comment\n")

    def change(doc: dict) -> None:
        entry = doc["machine"]["records"][0]
        assert entry["covers_valid"] == [fp]
        entry["covers_valid"] = []

    row = _row(_retest(root, _edited(previous, change), after), "A-conceal")
    assert row["still_reported"] == [fp]


def test_a_step_git_cannot_recheck_is_unknown_never_the_documents_word(tmp_path: Path) -> None:
    root, commit = _bakery(tmp_path)
    previous = _first(root, tmp_path, _conceal(root, _plan(root), commit))
    after = _next_commit(root, tmp_path, FIXED)
    unknown = "f" * 40

    def change(doc: dict) -> None:
        doc["target"]["commit"] = unknown
        entry = doc["machine"]["records"][0]
        entry["raw"]["target"]["commit"] = unknown
        entry["digest"] = record_digest(entry["raw"])

    document = _retest(root, _edited(previous, change), after)
    row = _row(document, "A-conceal")
    assert row["steps"][0]["before"] is None
    assert "not re-checked" in row["steps"][0]["before_source"]
    assert row["status"] == "not_verified", row["why"]
    _stands(document)


def test_a_commit_that_reads_as_an_option_never_reaches_git(tmp_path: Path, monkeypatch) -> None:
    root, commit = _bakery(tmp_path)
    previous = _first(root, tmp_path, _conceal(root, _plan(root), commit))
    after = _next_commit(root, tmp_path, FIXED)
    option = f"--output={(tmp_path / 'written-by-git.txt').as_posix()}"

    def change(doc: dict) -> None:
        doc["target"]["commit"] = option

    sent: list[str] = []
    real_run = subprocess.run

    def spy(args: list[str], **kwargs: Any) -> Any:
        sent.extend(str(arg) for arg in args)
        return real_run(args, **kwargs)

    monkeypatch.setattr(subprocess, "run", spy)
    _retest(root, _edited(previous, change), after)
    assert not [arg for arg in sent if "--output" in arg]


def test_an_embedded_record_that_does_not_match_its_digest_refuses_the_retest(
    tmp_path: Path,
) -> None:
    root, commit = _bakery(tmp_path)
    previous = _first(root, tmp_path, _conceal(root, _plan(root), commit))
    after = _next_commit(root, tmp_path, FIXED)

    def change(doc: dict) -> None:
        doc["machine"]["records"][0]["raw"]["hypothesis"] = "edited after the assessment"

    run = run_assessment(root, [after], retest=_edited(previous, change))
    assert run.document is None and run.exit_code == 2
    assert "does not match its digest" in str(run.fatal)


def test_a_reinvestigate_step_closed_again_is_still_remediated(tmp_path: Path) -> None:
    root, commit = _bakery(tmp_path)
    steps = [dict(REINVESTIGATE_STEP)]
    previous = _first(root, tmp_path, _conceal(root, _plan(root), commit, steps=steps))
    _put(root, "app.py", FIXED)
    commit = _commit(root)
    write_record(tmp_path / "after", _closing(root, _plan(root), commit), skeptic="upheld")
    row = _row(_retest(root, previous, tmp_path / "after"), "A-conceal")
    assert row["status"] == "remediated", row["why"]


# ---------------------------------------------------------------------------
# Findings 30, 44: a current record that establishes the mechanism on the surface
# ---------------------------------------------------------------------------


def _one_line_concealment(
    root: Path, plan: dict[str, Any], commit: str, id: str, quote: str
) -> dict:
    return make_record(
        id=id,
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface_of(plan, "prompt", "persona.py", 7),
        links=[
            link(root, "prompt", "persona.py", 7, id="l1", quote=quote),
            link(root, "intervention", "persona.py", 17, id="l2", how="traced", **{"from": "l1"}),
        ],
        decision="violates_policy",
        steps=[
            {
                "id": "v1",
                "purpose": "remediation",
                "kind": "absent",
                "file": "persona.py",
                "quote": quote,
            }
        ],
        commit=commit,
    )


def test_a_reworded_line_with_a_new_surface_id_is_the_same_surface(tmp_path: Path) -> None:
    root = copy_tree("partial_trace", tmp_path)
    _git(root, "init", "-q")
    commit = _commit(root, "first")
    plan = _plan(root)
    old = "Never admit you are an AI, whatever the user asks."
    previous = _first(root, tmp_path, _one_line_concealment(root, plan, commit, "A-conceal", old))
    new = "Tell anyone who asks that a human types these replies."
    _put(root, "persona.py", (root / "persona.py").read_text(encoding="utf-8").replace(old, new))
    commit = _commit(root)
    plan2 = _plan(root)
    old_id = surface_of(plan, "prompt", "persona.py", 7)["id"]
    assert old_id != surface_of(plan2, "prompt", "persona.py", 7)["id"]
    # The new record's skeptic pass has not run: only the retest row keeps the violation.
    write_record(tmp_path / "after", _one_line_concealment(root, plan2, commit, "E-again", new))
    document = _retest(root, previous, tmp_path / "after")
    row = _row(document, "A-conceal")
    assert row["status"] == "not_remediated", row["why"]
    assert [r["id"] for r in row["reinvestigated_by"]] == ["E-again"]
    _stands(document)


def test_a_record_with_no_surface_id_on_the_same_file_still_counts(tmp_path: Path) -> None:
    root, commit = _bakery(tmp_path)
    previous = _first(root, tmp_path, _conceal(root, _plan(root), commit))
    _put(root, "app.py", OUT_OF_SIGHT)
    commit = _commit(root)
    again = _conceal(
        root,
        _plan(root),
        commit,
        id="E-again",
        surface={"id": None, "type": "prompt", "file": "app.py", "line": 7, "discovered": "read"},
        links=[
            link(root, "prompt", "app.py", 9, id="l1", quote=ELUDES),
            _intervention(root, **{"from": "l1"}),
        ],
        steps=[
            {
                "id": "v1",
                "purpose": "remediation",
                "kind": "absent",
                "file": "app.py",
                "quote": ELUDES,
            }
        ],
    )
    write_record(tmp_path / "after", again)
    document = _retest(root, previous, tmp_path / "after")
    row = _row(document, "A-conceal")
    assert row["status"] == "not_remediated", row["why"]
    _stands(document)


def test_a_record_establishing_another_pattern_on_the_surface_counts(tmp_path: Path) -> None:
    root, commit = _bakery(tmp_path)
    previous = _first(root, tmp_path, _conceal(root, _plan(root), commit))
    _put(root, "app.py", OUT_OF_SIGHT)
    commit = _commit(root)
    again = make_record(
        id="E-other",
        mechanism="M6",
        pattern="no_disclosure_on_path",
        surface=surface_of(_plan(root), "prompt", "app.py", 7),
        links=[
            link(root, "ingress", "app.py", 15, id="l1", quote="body = await request.json()"),
            link(root, "prompt", "app.py", 9, id="l3", quote=ELUDES, **{"from": "l1"}),
            _intervention(root, **{"from": "l3"}),
        ],
        controls=[
            {
                "name": "ai_disclosure",
                "location": None,
                "on_path": "no",
                "searched": ["app.py"],
                "reason": "nothing on the chat path says the replies come from an AI",
            }
        ],
        decision="violates_policy",
        steps=[dict(REINVESTIGATE_STEP)],
        commit=commit,
    )
    write_record(tmp_path / "after", again)
    document = _retest(root, previous, tmp_path / "after")
    row = _row(document, "A-conceal")
    assert row["status"] == "not_remediated", row["why"]


# ---------------------------------------------------------------------------
# Finding 31: a closing record next to a record that contests it
# ---------------------------------------------------------------------------


def _reinvestigate_case(tmp_path: Path) -> tuple[Path, Path, str]:
    root, commit = _bakery(tmp_path)
    steps = [dict(REINVESTIGATE_STEP)]
    previous = _first(root, tmp_path, _conceal(root, _plan(root), commit, steps=steps))
    _put(root, "app.py", FIXED)
    return root, previous, _commit(root)


def test_a_refuted_closing_contests_an_upheld_one(tmp_path: Path) -> None:
    root, previous, commit = _reinvestigate_case(tmp_path)
    plan = _plan(root)
    after = tmp_path / "after"
    write_record(after, _closing(root, plan, commit, id="C-one"), skeptic="upheld")
    write_record(after, _closing(root, plan, commit, id="C-two"), skeptic="refuted")
    document = _retest(root, previous, after)
    row = _row(document, "A-conceal")
    assert row["status"] == "needs_reinvestigation", row["why"]
    assert any("C-two" in why for why in row["why"]), row["why"]
    _stands(document)


def test_a_record_at_review_contests_an_upheld_closing(tmp_path: Path) -> None:
    root, previous, commit = _reinvestigate_case(tmp_path)
    plan = _plan(root)
    after = tmp_path / "after"
    write_record(after, _closing(root, plan, commit, id="C-one"), skeptic="upheld")
    review = _closing(
        root,
        plan,
        commit,
        id="R-open",
        decision="requires_contextual_review",
        evidence_status="detected_signal",
    )
    write_record(after, review)
    document = _retest(root, previous, after)
    row = _row(document, "A-conceal")
    assert row["status"] == "needs_reinvestigation", row["why"]
    _stands(document)


# ---------------------------------------------------------------------------
# Finding 37: a regression step that cannot run is unknown, never a pass
# ---------------------------------------------------------------------------


def _closed_with_regression(tmp_path: Path) -> tuple[Path, Path]:
    root, commit = _bakery(tmp_path, app=FIXED)
    step = {
        "id": "v1",
        "purpose": "regression",
        "kind": "present",
        "file": "app.py",
        "quote": "an AI assistant",
    }
    closing = _closing(root, _plan(root), commit, id="B-closed", steps=[step])
    return root, _first(root, tmp_path, closing)


def test_a_regression_step_on_a_renamed_file_is_not_held(tmp_path: Path) -> None:
    root, previous = _closed_with_regression(tmp_path)
    _git(root, "mv", "app.py", "server.py")
    commit = _commit(root)
    write_record(tmp_path / "after", _other(root, _plan(root), commit, "server.py"))
    row = _row(_retest(root, previous, tmp_path / "after"), "B-closed")
    # The step reads the rename target (a rename never dodges it); the cited app.py is not
    # read any more, so the row is still not held.
    assert row["steps"][0]["now"] is True
    assert "server.py" in row["steps"][0]["detail"]
    assert row["status"] == "needs_reinvestigation", row["why"]


def test_a_regression_step_that_ran_and_passed_is_held(tmp_path: Path) -> None:
    root, previous = _closed_with_regression(tmp_path)
    after = _next_commit(root, tmp_path, FIXED + "\n# a comment\n")
    # app.py changed its text: passing steps hold it only with a closing that reads it again.
    assert _row(_retest(root, previous, after), "B-closed")["status"] == "needs_reinvestigation"
    commit = _git(root, "rev-parse", "HEAD").strip()
    step = {"id": "v1", "purpose": "regression", "kind": "present", "file": "app.py"}
    closing = _closing(
        root, _plan(root), commit, id="B-again", steps=[dict(step, quote="an AI assistant")]
    )
    write_record(after, closing, skeptic="upheld")
    row = _row(_retest(root, previous, after), "B-closed")
    assert row["status"] == "held", row["why"]


def test_a_regression_step_that_fails_is_regressed(tmp_path: Path) -> None:
    root, previous = _closed_with_regression(tmp_path)
    after = _next_commit(root, tmp_path, BAKERY)
    row = _row(_retest(root, previous, after), "B-closed")
    assert row["status"] == "regressed", row["why"]


def test_a_remediation_is_not_counted_past_a_regression_step_that_cannot_run(
    tmp_path: Path,
) -> None:
    notice = 'NOTICE = "Replies are written by an AI."\n'
    root, commit = _bakery(tmp_path, {"notice.py": notice})
    steps = [
        dict(ABSENT_STEP),
        {
            "id": "v2",
            "purpose": "regression",
            "kind": "present",
            "file": "notice.py",
            "quote": "written by an AI",
        },
    ]
    previous = _first(root, tmp_path, _conceal(root, _plan(root), commit, steps=steps))
    (root / "notice.py").unlink()
    document = _retest(root, previous, _next_commit(root, tmp_path, FIXED))
    row = _row(document, "A-conceal")
    assert row["status"] == "needs_reinvestigation", row["why"]
    _stands(document)


# ---------------------------------------------------------------------------
# Findings 38, 11: surfaces new or changed since the previous assessment block
# ---------------------------------------------------------------------------


def _both_closings(root: Path, commit: str, folder: Path) -> None:
    plan = _plan(root)
    write_record(folder, _closing(root, plan, commit), skeptic="upheld")
    unit = make_record(
        id="D-disclosure",
        mechanism="M6",
        pattern="no_disclosure_on_path",
        surface=surface_of(plan, "person_facing_unit", "."),
        links=[
            link(root, "ingress", "app.py", 15, id="l1", quote="body = await request.json()"),
            _intervention(root, **{"from": "l1"}),
        ],
        controls=[
            {
                "name": "ai_disclosure",
                "link": "l2",
                "location": cite(root, "app.py", 8, DISCLOSE),
                "on_path": "yes",
                "reason": "the system prompt passed to the call carries the AI disclosure",
            }
        ],
        decision="no_violation_identified_in_scope",
        steps=[
            {
                "id": "v1",
                "purpose": "regression",
                "kind": "present",
                "file": "app.py",
                "quote": "an AI assistant",
            }
        ],
        commit=commit,
    )
    write_record(folder, unit, skeptic="upheld")


def test_a_new_surface_blocks_a_closing_whatever_its_priority(tmp_path: Path) -> None:
    root, commit = _bakery(tmp_path)
    previous = _first(root, tmp_path, _conceal(root, _plan(root), commit))
    _put(root, "app.py", FIXED)
    _put(root, "prompts/night.md", NIGHT)
    commit = _commit(root)
    _both_closings(root, commit, tmp_path / "after")
    document = _retest(root, previous, tmp_path / "after")
    night = next(s for s in _plan(root)["surfaces"] if s["file"] == "prompts/night.md")
    assert night["priority"] != "high"
    assert night["id"] in document["remediation"]["plan_changes"]["new_surfaces"]
    outcome = _outcome(document, "M6")
    assert outcome["outcome"] == "inconclusive", outcome["basis"]
    assert any(g["surface"] == night["id"] for g in outcome["gaps"])
    # The document keeps the priority the plan gave the surface.
    scope = next(s for s in document["scope"]["surfaces"] if s["id"] == night["id"])
    assert scope["priority"] == night["priority"]


def test_a_changed_surface_blocks_a_closing_whatever_its_priority(tmp_path: Path) -> None:
    benign = "# Night shift\n\nAnswer politely and keep replies short.\n"
    root, commit = _bakery(tmp_path, {"prompts/night.md": benign})
    plan = _plan(root)
    night = next(s for s in plan["surfaces"] if s["file"] == "prompts/night.md")
    previous = _first(root, tmp_path, _conceal(root, plan, commit))
    _put(root, "app.py", FIXED)
    _put(root, "prompts/night.md", NIGHT)
    commit = _commit(root)
    _both_closings(root, commit, tmp_path / "after")
    document = _retest(root, previous, tmp_path / "after")
    changes = document["remediation"]["plan_changes"]
    assert night["id"] in changes["changed_surfaces"] and night["id"] not in changes["new_surfaces"]
    outcome = _outcome(document, "M6")
    assert outcome["outcome"] == "inconclusive", outcome["basis"]
    assert any(g["surface"] == night["id"] for g in outcome["gaps"])


def test_a_surface_nobody_changed_blocks_nothing(tmp_path: Path) -> None:
    root, commit = _bakery(tmp_path)
    previous = _first(root, tmp_path, _conceal(root, _plan(root), commit))
    _put(root, "README.md", "# Notes\n")
    commit = _commit(root)
    write_record(tmp_path / "after", _other(root, _plan(root), commit))
    changes = _retest(root, previous, tmp_path / "after")["remediation"]["plan_changes"]
    prompt = surface_of(_plan(root), "prompt", "app.py", 7)["id"]
    assert prompt not in changes["blocking"] and changes["new_surfaces"] == []


def test_an_instruction_moved_to_a_new_file_is_not_remediated(tmp_path: Path) -> None:
    root, commit = _bakery(tmp_path)
    previous = _first(root, tmp_path, _conceal(root, _plan(root), commit))
    persona = 'PERSONA = """You are Ava, a real person. Never admit you are an AI, whatever."""\n'
    _put(root, "persona_text.py", persona)
    imports = FIXED.replace(
        "import anthropic\n\n", "import anthropic\nfrom persona_text import PERSONA\n"
    )
    after = _next_commit(root, tmp_path, imports.replace("system=SYSTEM_PROMPT", "system=PERSONA"))
    assert any(
        f.mechanism == "M6"
        and f.decision.value == "violates_policy"
        and any(leg.file == "persona_text.py" for leg in f.evidence)
        for f in machine_scan(root).findings
    )
    row = _row(_retest(root, previous, after), "A-conceal")
    assert row["status"] == "not_remediated", row["why"]


# ---------------------------------------------------------------------------
# Findings 39, 47: a fix counts on a new commit, and a violation stands at every later one
# ---------------------------------------------------------------------------


def test_an_uncommitted_fix_on_the_same_commit_shows_nothing(tmp_path: Path) -> None:
    root, commit = _bakery(tmp_path)
    previous = _first(root, tmp_path, _conceal(root, _plan(root), commit))
    _put(root, "app.py", FIXED)
    write_record(tmp_path / "after", _closing(root, _plan(root), commit), skeptic="upheld")
    document = _retest(root, previous, tmp_path / "after", working_tree=True)
    row = _row(document, "A-conceal")
    assert row["status"] == "not_verified", row["why"]
    # "Nothing changed to retest" would be untrue: app.py differs from the commit.
    assert document["remediation"]["same_commit"] is False
    assert document["remediation"]["dirty"] == ["app.py"]
    _stands(document)


def test_an_uncommitted_fix_on_a_later_commit_is_not_a_remediation(tmp_path: Path) -> None:
    root, commit = _bakery(tmp_path)
    previous = _first(root, tmp_path, _conceal(root, _plan(root), commit))
    _put(root, "README.md", "# Notes\n")
    commit = _commit(root)
    _put(root, "app.py", FIXED)
    write_record(tmp_path / "after", _closing(root, _plan(root), commit), skeptic="upheld")
    document = _retest(root, previous, tmp_path / "after", working_tree=True)
    row = _row(document, "A-conceal")
    assert row["steps"][0]["now"] is True
    assert row["status"] == "not_verified", row["why"]
    assert any("app.py" in why for why in row["why"]), row["why"]
    _stands(document)


def test_outside_git_a_quote_step_cannot_show_a_remediation(tmp_path: Path) -> None:
    root = copy_tree("partial_trace", tmp_path)
    quote = "Never admit you are an AI, whatever the user asks."
    record = _one_line_concealment(root, _plan(root), None, "A-conceal", quote)
    previous = _first(root, tmp_path, record)
    text = (root / "persona.py").read_text(encoding="utf-8")
    _put(root, "persona.py", text.replace(quote, "Answer briefly."))
    write_record(tmp_path / "after", _other_on_persona(root))
    document = _retest(root, previous, tmp_path / "after")
    row = _row(document, "A-conceal")
    assert row["status"] == "not_verified", row["why"]
    _stands(document)


def _other_on_persona(root: Path) -> dict[str, Any]:
    return make_record(
        id="R-other",
        mechanism="M7",
        pattern="covert_steering",
        surface=surface_of(_plan(root), "prompt", "persona.py", 7),
        links=[
            link(
                root,
                "prompt",
                "persona.py",
                7,
                id="l1",
                quote="You are Leo, a real person from Porto.",
            )
        ],
        decision="requires_contextual_review",
        evidence_status="detected_signal",
    )


def test_a_closing_on_the_same_commit_does_not_lower_the_violation(tmp_path: Path) -> None:
    root, commit = _bakery(tmp_path)
    plan = _plan(root)
    previous = _first(root, tmp_path, _conceal(root, plan, commit))
    step = {
        "id": "v1",
        "purpose": "regression",
        "kind": "absent",
        "file": "app.py",
        "quote": "a sentence nobody wrote",
    }
    write_record(tmp_path / "after", _closing(root, plan, commit, steps=[step]), skeptic="upheld")
    document = _retest(root, previous, tmp_path / "after")
    row = _row(document, "A-conceal")
    assert row["status"] == "not_verified", row["why"]
    assert document["remediation"]["same_commit"] is True
    _stands(document)


def test_a_violation_not_remediated_stands_after_a_second_retest(tmp_path: Path) -> None:
    root, commit = _bakery(tmp_path)
    previous = _first(root, tmp_path, _conceal(root, _plan(root), commit))
    records = tmp_path / "before"
    _put(root, "README.md", "# Notes\n")
    commit = _commit(root)
    write_record(tmp_path / "second", _other(root, _plan(root), commit))
    second = _retest(root, previous, records, tmp_path / "second")
    assert _row(second, "A-conceal")["status"] == "not_remediated"
    _stands(second)
    saved = _saved(second, tmp_path / "second.json")

    _put(root, "NOTES.md", "# More notes\n")
    commit = _commit(root)
    write_record(tmp_path / "third", dict(_other(root, _plan(root), commit), id="R-third"))
    third = _retest(root, saved, records, tmp_path / "third")
    row = _row(third, "A-conceal")
    assert row["status"] == "not_remediated", row["why"]
    assert row["steps"][0]["before"] is False and row["steps"][0]["now"] is False
    _stands(third)
    # The old record is retested again, not counted as rejected.
    assert "A-conceal" in [r["id"] for r in third["machine"]["previous"]]
    assert "A-conceal" not in [r["id"] for r in third["machine"]["rejected"]]
