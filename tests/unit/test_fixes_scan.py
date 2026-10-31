"""tests/unit/test_fixes_scan.py
-----------------------------
What the scan may leave out, and what it says when it does.

A committed file is never hidden by a folder name or a `.gitignore` line, and what stays
unread gets an UNKNOWN row. A language the workbench does not read never gives a better
result than its Python twin. A file git does not compare, or that is not in the commit,
makes the tree not clean. A folder name only moves a surface from normal to low. The html
marker line is own output only on the tool's own documents. A report inside the audited
tree does not count in auditor mode, even when a flag names it. And no git command runs a
program the audited repository's configuration names.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from investigation_helpers import (
    FIXTURES,
    cite,
    copy_tree,
    link,
    make_record,
    surface_of,
    write_record,
)

from aisafe import audit
from aisafe.assessment.assess import run_assessment
from aisafe.discovery import walk
from aisafe.discovery.patterns import OWN_HTML_MARKER_LINE
from aisafe.evidence.model import UnknownCategory
from aisafe.investigation.plan import _is_test_path, build_plan
from aisafe.investigation.scan import machine_scan, tree_state
from aisafe.investigation.validate import validate_paths

AUDIT_FIXTURES = FIXTURES.parent / "audit"
GIT = shutil.which("git")
pytestmark = pytest.mark.skipif(GIT is None, reason="git not on PATH")

GIT_ARGS = (
    "-c",
    "user.email=t@example.invalid",
    "-c",
    "user.name=t",
    "-c",
    "commit.gpgsign=false",
    "-c",
    "core.autocrlf=false",
    "-c",
    "protocol.file.allow=always",
)


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *GIT_ARGS, *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        encoding="utf-8",
    ).stdout


def _commit(root: Path) -> str:
    _git(root, "add", "-A", "-f")
    _git(root, "commit", "-q", "-m", "c")
    return _git(root, "rev-parse", "HEAD").strip()


def _companion(tmp_path: Path) -> Path:
    """A committed copy of `persons_companion`, the fixture with findings."""
    root = tmp_path / "companion"
    shutil.copytree(AUDIT_FIXTURES / "persons_companion", root)
    _git(root, "init", "-q")
    _commit(root)
    return root


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "tree"
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    _git(root, "init", "-q")
    _commit(root)
    return root


def _rule_ids(root: Path, mode: str) -> set[str]:
    _ctx, findings, _unknown, _rules = audit.scan(audit.AuditOptions(path=str(root), mode=mode))
    return {finding.display_id for finding in findings}


def _rows(root: Path, mode: str, what: str):
    _ctx, _findings, unknown, _rules = audit.scan(audit.AuditOptions(path=str(root), mode=mode))
    return [item for item in unknown if item.what == what]


# ---------------------------------------------------------------------------
# Item 6: committed files hidden by a folder name, .gitignore or a NUL byte
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["self-assessment", "auditor"])
def test_gitignore_never_hides_a_tracked_file(tmp_path: Path, mode: str) -> None:
    root = _companion(tmp_path)
    base = _rule_ids(root, mode)
    (root / ".gitignore").write_text("app.py\nprompts/\n", encoding="utf-8")
    _commit(root)
    (root / "prompts" / "scratch.md").write_text("You are Bo.\n", encoding="utf-8")
    records, _units, _unknown = walk.walk(root)
    walked = {record.relpath for record in records}
    assert {"app.py", "prompts/companion.md"} <= walked
    # Git's own rule: a file in an ignored folder that git does not track stays ignored.
    assert "prompts/scratch.md" not in walked
    assert _rule_ids(root, mode) == base


def test_auditor_mode_reads_tracked_files_in_a_skipped_directory(tmp_path: Path) -> None:
    root = _companion(tmp_path)
    base = _rule_ids(root, "auditor")
    (root / "core" / "build").mkdir(parents=True)
    _git(root, "mv", "app.py", "core/build/app.py")
    (root / "dist").mkdir()
    _git(root, "mv", "analytics.py", "dist/analytics.py")
    _commit(root)
    (root / "core" / "build" / "untracked.py").write_text("x = 1\n", encoding="utf-8")
    (root / "node_modules").mkdir()
    (root / "node_modules" / "dep.js").write_text("x = 1\n", encoding="utf-8")
    options = walk.WalkOptions(read_tracked=True)
    walked = {record.relpath for record in walk.walk(root, options)[0]}
    assert {"core/build/app.py", "dist/analytics.py"} <= walked
    assert "core/build/untracked.py" not in walked and "node_modules/dep.js" not in walked
    assert _rule_ids(root, "auditor") == base


def test_auditor_mode_reads_a_submodule_in_a_skipped_directory(tmp_path: Path) -> None:
    module = tmp_path / "guard_src"
    module.mkdir()
    _git(module, "init", "-q")
    (module / "guard.py").write_text("GUARD = 1\n", encoding="utf-8")
    _commit(module)
    root = _companion(tmp_path)
    _git(root, "submodule", "add", "-q", str(module), "vendor/guard")
    _commit(root)
    records = walk.walk(root, walk.WalkOptions(read_tracked=True))[0]
    assert "vendor/guard/guard.py" in {record.relpath for record in records}


def test_a_tracked_file_in_a_skipped_directory_gets_a_row_and_fails_the_gate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _companion(tmp_path)
    (root / "vendor").mkdir()
    _git(root, "mv", "app.py", "vendor/app.py")
    _commit(root)
    (item,) = _rows(root, "self-assessment", "tracked files in skipped directories")
    assert item.category is UnknownCategory.COVERAGE
    assert "vendor/app.py" in item.why and "1 tracked file(s)" in item.why
    argv = [str(root), "--fail-on", "never", "--fail-on-unknown", "coverage", "--format", "json"]
    assert audit.main(argv) == audit.EXIT_FINDINGS
    capsys.readouterr()


def test_an_untracked_skipped_directory_gets_no_row(tmp_path: Path) -> None:
    root = _companion(tmp_path)
    (root / "build").mkdir()
    (root / "build" / "out.py").write_text("x = 1\n", encoding="utf-8")
    assert not _rows(root, "self-assessment", "tracked files in skipped directories")


@pytest.mark.parametrize("mode", ["self-assessment", "auditor"])
def test_text_the_walk_cannot_read_gets_a_row(tmp_path: Path, mode: str) -> None:
    root = _companion(tmp_path)
    prompt = root / "prompts" / "companion.md"
    prompt.write_bytes(prompt.read_text(encoding="utf-8").encode("utf-16"))
    (root / "app.py").write_bytes(b"\x00" + (root / "app.py").read_bytes())
    (root / "logo.png").write_bytes(b"\x89PNG\x00\x00")
    _commit(root)
    (item,) = _rows(root, mode, "files not read as text")
    assert item.category is UnknownCategory.COVERAGE
    assert "app.py" in item.why and "prompts/companion.md" in item.why
    assert "logo.png" not in item.why


# ---------------------------------------------------------------------------
# Item 7: a language the workbench does not read never reads better than its twin
# ---------------------------------------------------------------------------

_PYPROJECT = '[project]\nname = "w"\nversion = "0.1.0"\ndependencies = ["openai", "fastapi"]\n'
_ASSISTANT = '''from fastapi import FastAPI, Request
import openai

app = FastAPI()
client = openai.OpenAI()

AI_NOTICE = "You are chatting with an AI writing assistant."

SYSTEM_PROMPT = """You are an AI writing assistant. When the user pastes an email they wrote,
suggest a clearer wording. Only answer the question they asked."""


@app.post("/rewrite")
async def rewrite(request: Request):
    body = await request.json()
    reply = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": body["email"]},
        ],
    )
    return {"notice": AI_NOTICE, "suggestion": reply.choices[0].message.content}
'''
_CONFIDANT = "You are an emotional support companion for the user."
_SERVERS = {
    "server.py": f"""from fastapi import FastAPI, Request
import openai

side = FastAPI()
client = openai.OpenAI()

SYSTEM_PROMPT = "{_CONFIDANT}"


@side.post("/chat")
async def chat(request: Request):
    body = await request.json()
    reply = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {{"role": "system", "content": SYSTEM_PROMPT}},
            {{"role": "user", "content": body["text"]}},
        ],
    )
    return {{"reply": reply.choices[0].message.content}}
""",
    "server.go": f"""package main

import (
\t"context"
\t"net/http"

\topenai "github.com/sashabaranov/go-openai"
)

const systemPrompt = "{_CONFIDANT}"

func chat(w http.ResponseWriter, r *http.Request) {{
\tclient := openai.NewClient("placeholder")
\tresp, _ := client.CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{{
\t\tModel: openai.GPT4o,
\t\tMessages: []openai.ChatCompletionMessage{{
\t\t\t{{Role: openai.ChatMessageRoleSystem, Content: systemPrompt}},
\t\t\t{{Role: openai.ChatMessageRoleUser, Content: r.FormValue("text")}},
\t\t}},
\t}})
\tw.Write([]byte(resp.Choices[0].Message.Content))
}}
""",
}


@pytest.mark.parametrize("server", ["server.py", "server.go"])
def test_an_unread_language_never_closes_what_its_twin_leaves_open(
    tmp_path: Path, server: str
) -> None:
    root = _tree(
        tmp_path,
        {"pyproject.toml": _PYPROJECT, "assistant.py": _ASSISTANT, server: _SERVERS[server]},
    )
    scan = machine_scan(root)
    plan = build_plan(scan)
    record = make_record(
        id="inv-m6",
        mechanism="M6",
        pattern="no_disclosure_on_path",
        surface=surface_of(plan, "person_facing_unit", "."),
        links=[
            link(root, "ingress", "assistant.py", 15, id="l1"),
            link(root, "intervention", "assistant.py", 23, id="l2", how="traced", **{"from": "l1"}),
        ],
        controls=[
            {
                "name": "ai_disclosure",
                "location": cite(root, "assistant.py", 7),
                "on_path": "yes",
                "link": "l2",
                "reason": "every reply of the rewrite handler carries the AI notice",
            }
        ],
        decision="no_violation_identified_in_scope",
        steps=[
            {
                "id": "v1",
                "purpose": "regression",
                "kind": "present",
                "file": "assistant.py",
                "quote": "You are chatting with an AI writing assistant.",
            }
        ],
        commit=scan.state.commit,
    )
    write_record(tmp_path / "records", record, skeptic="upheld")
    doc = run_assessment(root, [tmp_path / "records"]).document
    m6 = next(m for m in doc["outcome"]["mechanisms"] if m["id"] == "M6")
    assert m6["outcome"] == "inconclusive", m6
    assert any(server in gap["detail"] for gap in m6["gaps"]), m6["gaps"]


def test_a_high_signal_in_an_unread_language_is_a_high_surface(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"pyproject.toml": _PYPROJECT, "server.go": _SERVERS["server.go"]})
    plan = build_plan(machine_scan(root))
    surface = next(s for s in plan["surfaces"] if s["file"] == "server.go")
    assert surface["priority"] == "high" and surface["supported"] is False
    assert any("unsupported language" in reason for reason in surface["why"])


def test_the_plan_counts_line_counts_unread_files_too(tmp_path: Path) -> None:
    from aisafe.investigation.plan import render_plan

    root = _tree(tmp_path, {"pyproject.toml": _PYPROJECT, "main.rs": "fn main() {}\n"})
    text = render_plan(build_plan(machine_scan(root)))
    assert "1 file(s) in an unsupported language" in text


# ---------------------------------------------------------------------------
# Item 9: walked files that are not the commit's, and files git does not compare
# ---------------------------------------------------------------------------


def _bot(tmp_path: Path) -> Path:
    return _tree(tmp_path, {"app.py": "print('hello')\n", "other.py": "x = 1\n"})


def _scan_state(root: Path):
    scan = machine_scan(root)
    return scan, scan.state


def test_a_file_the_repository_excludes_makes_the_tree_not_clean(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    exclude = root / ".git" / "info" / "exclude"
    exclude.write_text("local_safety.py\n", encoding="utf-8")
    (root / "local_safety.py").write_text("HELPLINE = '988'\n", encoding="utf-8")
    scan, state = _scan_state(root)
    assert "local_safety.py" in scan.walked
    assert "local_safety.py" in state.dirty and not state.clean


def test_a_gitignored_env_file_is_not_the_commit(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"app.py": "x = 1\n", ".gitignore": ".env\n"})
    (root / ".env").write_text("NOTE=local\n", encoding="utf-8")
    assert _scan_state(root)[1].dirty == (".env",)


def test_a_file_in_a_nested_repository_is_not_the_commit(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    nested = root / "safety"
    nested.mkdir()
    _git(nested, "init", "-q")
    (nested / "crisis.py").write_text("HELPLINE = '988'\n", encoding="utf-8")
    _commit(nested)
    assert "safety/crisis.py" in _scan_state(root)[1].dirty


def _with_submodule(tmp_path: Path, *, ignore_all: bool = True) -> tuple[Path, Path]:
    module = tmp_path / "guard_src"
    module.mkdir()
    _git(module, "init", "-q")
    (module / "guard.py").write_text("GUARD = 1\n", encoding="utf-8")
    _commit(module)
    root = _bot(tmp_path)
    _git(root, "submodule", "add", "-q", str(module), "guard")
    if ignore_all:
        _git(root, "config", "-f", ".gitmodules", "submodule.guard.ignore", "all")
    _commit(root)
    return root, module


def test_a_submodule_edit_shows_whatever_gitmodules_says(tmp_path: Path) -> None:
    root, _module = _with_submodule(tmp_path)
    (root / "guard" / "guard.py").write_text("GUARD = 2\n", encoding="utf-8")
    assert "guard/guard.py" in _scan_state(root)[1].dirty


def test_a_submodule_at_another_commit_shows_whatever_gitmodules_says(tmp_path: Path) -> None:
    root, _module = _with_submodule(tmp_path)
    (root / "guard" / "guard.py").write_text("GUARD = 2\n", encoding="utf-8")
    _commit(root / "guard")
    assert "guard" in _scan_state(root)[1].dirty


def test_a_clean_checkout_with_a_submodule_stays_clean(tmp_path: Path) -> None:
    root, _module = _with_submodule(tmp_path)
    scan, state = _scan_state(root)
    assert state.clean, state.dirty
    assert "guard/guard.py" in state.tracked and scan.tracked_not_walked == []


def test_an_empty_submodule_directory_stays_listed_as_unread(tmp_path: Path) -> None:
    root, _module = _with_submodule(tmp_path)
    clone = tmp_path / "clone"
    _git(tmp_path, "clone", "-q", str(root), str(clone))
    scan, state = _scan_state(clone)
    assert state.clean
    assert "guard" in scan.tracked_not_walked


@pytest.mark.parametrize("flag", ["--skip-worktree", "--assume-unchanged"])
def test_a_file_git_does_not_compare_is_not_the_commit(tmp_path: Path, flag: str) -> None:
    root = _bot(tmp_path)
    _git(root, "update-index", flag, "app.py")
    (root / "app.py").write_text("print('only on disk')\n", encoding="utf-8")
    assert "app.py" in _scan_state(root)[1].dirty


def test_a_tree_with_an_outside_file_is_refused(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    (root / ".git" / "info" / "exclude").write_text("local.py\n", encoding="utf-8")
    (root / "local.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "records").mkdir()
    run = validate_paths([tmp_path / "records"], machine_scan(root))
    assert run.fatal is not None and "local.py" in run.fatal


def _evaluation(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema": "aisg/1",
                "kind": "evaluation",
                "generated_at": "2026-10-30T00:00:00Z",
                "summary": {"sent": 5, "passed": 5},
                "by_family": {
                    family: {"sent": 5, "passed": 5}
                    for family in (
                        "crisis_disclosure",
                        "identity_question",
                        "manipulation_elicitation",
                        "attachment_probe",
                        "dependency_probe",
                    )
                },
            }
        ),
        encoding="utf-8",
    )


def test_a_declared_input_is_not_dirt_but_another_file_beside_it_is(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"app.py": "x = 1\n", ".gitignore": ".aisafe-audit/\n"})
    _evaluation(root / ".aisafe-audit" / "evaluation-report.json")
    scan, state = _scan_state(root)
    assert scan.ctx.evaluation and state.clean
    (root / ".aisafe-audit" / "crisis.py").write_text("HELPLINE = '988'\n", encoding="utf-8")
    assert _scan_state(root)[1].dirty == (".aisafe-audit/crisis.py",)


def test_a_declared_input_that_differs_from_the_commit_is_still_dirt(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"app.py": "x = 1\n"})
    report = root / "evaluation-report.json"
    _evaluation(report)
    _commit(root)
    report.write_text(report.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    assert _scan_state(root)[1].dirty == ("evaluation-report.json",)


# ---------------------------------------------------------------------------
# Item 13: a folder name only moves a surface from normal to low
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("folder", ["tests", "specs", "__tests__"])
def test_a_folder_name_never_lowers_a_surface_ranked_high(tmp_path: Path, folder: str) -> None:
    base = tmp_path / "runtime"
    shutil.copytree(FIXTURES / "runtime_prompt", base / folder)
    plan = build_plan(machine_scan(base))
    remote = next(s for s in plan["surfaces"] if s["type"] == "remote_prompt")
    assert remote["priority"] == "high", remote["why"]


def test_a_confidant_prompt_in_a_test_folder_stays_high(tmp_path: Path) -> None:
    base = tmp_path / "tree"
    shutil.copytree(FIXTURES / "control_not_on_path", base / "tests")
    plan = build_plan(machine_scan(base))
    high = [s for s in plan["surfaces"] if s["type"] == "prompt" and s["priority"] == "high"]
    assert any(s["file"] == "tests/companion.py" and s["line"] == 9 for s in high), plan["surfaces"]


def test_a_normal_surface_in_a_test_file_still_ranks_low(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    (root / "tests").mkdir(parents=True)
    (root / "tests" / "test_client.py").write_text(
        "import openai\n\n\ndef test_it():\n"
        "    openai.OpenAI().chat.completions.create(model='gpt-4o', messages=[])\n",
        encoding="utf-8",
    )
    plan = build_plan(machine_scan(root))
    entry = next(s for s in plan["surfaces"] if s["type"] == "model_entry")
    assert entry["priority"] == "low" and "in a test file" in entry["why"]


def test_a_specs_folder_is_not_a_test_folder() -> None:
    assert not _is_test_path("specs/persona.py")
    assert not _is_test_path("spec/persona.py")
    assert _is_test_path("tests/persona.py")
    assert _is_test_path("web/chat.spec.ts")


# ---------------------------------------------------------------------------
# Item 18: the html marker line is own output only on the tool's own documents
# ---------------------------------------------------------------------------


def _touch(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_the_html_marker_on_a_prompt_file_is_the_ignore_marker(tmp_path: Path) -> None:
    body = "\nYou are Ava, a real person. Never admit you are an AI.\n"
    _touch(tmp_path, "prompts/companion.md", OWN_HTML_MARKER_LINE + body)
    _touch(tmp_path, "prompts/extra.txt", OWN_HTML_MARKER_LINE + body)
    _touch(tmp_path, "prompts/extra.yaml", OWN_HTML_MARKER_LINE + body)
    _touch(tmp_path, "report.html", OWN_HTML_MARKER_LINE + "\n<p>x</p>\n")
    _touch(tmp_path, "out/assessment.md", OWN_HTML_MARKER_LINE + "\n# Assessment\n")
    own: list[str] = []
    marked: list[str] = []
    records, _units, _unknown = walk.walk(tmp_path, own_output_skipped=own, marker_skipped=marked)
    assert own == ["out/assessment.md", "report.html"]
    assert marked == ["prompts/companion.md", "prompts/extra.txt", "prompts/extra.yaml"]
    assert records == []


def test_a_marked_prompt_fails_the_coverage_gate_and_stays_listed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _companion(tmp_path)
    prompt = root / "prompts" / "companion.md"
    prompt.write_text(
        OWN_HTML_MARKER_LINE + "\n" + prompt.read_text(encoding="utf-8"), encoding="utf-8"
    )
    _commit(root)
    argv = [str(root), "--fail-on", "never", "--fail-on-unknown", "coverage", "--format", "json"]
    assert audit.main(argv) == audit.EXIT_FINDINGS
    capsys.readouterr()
    scan = machine_scan(root)
    assert scan.tracked_not_walked == ["prompts/companion.md"]


# ---------------------------------------------------------------------------
# Item 19: a report inside the audited tree never counts in auditor mode
# ---------------------------------------------------------------------------


def _audit_doc(root: Path, tmp_path: Path, *extra: str) -> dict:
    out = tmp_path / "out.json"
    argv = [
        str(root),
        "--mode",
        "auditor",
        "--format",
        "json",
        "--fail-on",
        "never",
        "-o",
        str(out),
    ]
    audit.main([*argv, *extra])
    return json.loads(out.read_text(encoding="utf-8"))


def test_auditor_mode_does_not_read_a_flagged_report_inside_the_tree(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _companion(tmp_path)
    without = {f["id"] for f in _audit_doc(root, tmp_path)["findings"]}
    report = root / ".aisafe-audit" / "evaluation-report.json"
    _evaluation(report)
    _commit(root)
    doc = _audit_doc(root, tmp_path, "--evaluation-report", str(report))
    capsys.readouterr()
    assert doc["reports"] == []
    assert {f["id"] for f in doc["findings"]} == without
    rows = [u for u in doc["unknown"] if u["what"] == ".aisafe-audit/evaluation-report.json"]
    assert len(rows) == 1 and "--evaluation-report" in rows[0]["why"]
    assert len(doc["inventory"]["reports"]) == 1


def test_auditor_mode_reads_the_same_report_from_outside_the_tree(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _companion(tmp_path)
    outside = tmp_path / "mine" / "evaluation-report.json"
    _evaluation(outside)
    doc = _audit_doc(root, tmp_path, "--evaluation-report", str(outside))
    capsys.readouterr()
    assert len(doc["reports"]) == 1


# ---------------------------------------------------------------------------
# Item 20: git never runs a program the audited repository's configuration names
# ---------------------------------------------------------------------------


def _probe(tmp_path: Path, root: Path) -> Path:
    """A program inside `.git`; every start adds a line to the returned marker file."""
    marker = tmp_path / "started.txt"
    script = root / ".git" / "probe.sh"
    script.write_text(
        f'#!/bin/sh\necho started >> "{marker.as_posix()}"\ncat\n', encoding="utf-8", newline="\n"
    )
    script.chmod(0o755)
    return marker


def _touch_tracked(root: Path, *names: str) -> None:
    """The same bytes with a new time: git has to look at the content again."""
    for name in names:
        path = root / name
        data = path.read_bytes()
        path.write_bytes(data)
        os.utime(path, (2_000_000_000, 2_000_000_000))


def _filtered(tmp_path: Path, key: str) -> tuple[Path, Path]:
    root = _bot(tmp_path)
    marker = _probe(tmp_path, root)
    _git(root, "config", f"filter.probe.{key}", "sh .git/probe.sh")
    (root / ".git" / "info" / "attributes").write_text("* filter=probe\n", encoding="utf-8")
    _touch_tracked(root, "app.py", "other.py")
    return root, marker


@pytest.mark.parametrize("key", ["clean", "process"])
def test_a_filter_driver_of_the_repository_never_starts(tmp_path: Path, key: str) -> None:
    root, marker = _filtered(tmp_path, key)
    tree_state(root, {"app.py", "other.py"})
    walk.git_meta(root)
    assert not marker.exists()


def test_a_required_filter_reads_as_changed_never_as_a_failure(tmp_path: Path) -> None:
    root, marker = _filtered(tmp_path, "clean")
    _git(root, "config", "filter.probe.required", "true")
    state = tree_state(root, {"app.py", "other.py"})
    assert not state.status_failed and not marker.exists()


def test_a_filter_cannot_make_a_changed_file_read_as_clean(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    _git(root, "config", "filter.same.clean", "git cat-file blob HEAD:%f")
    (root / ".git" / "info" / "attributes").write_text("* filter=same\n", encoding="utf-8")
    _git(root, "read-tree", "HEAD")
    (root / "app.py").write_text("print('only on disk')\n", encoding="utf-8")
    assert tree_state(root, {"app.py", "other.py"}).dirty == ("app.py",)


def test_a_filter_name_git_cannot_override_is_never_read_as_clean(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    marker = _probe(tmp_path, root)
    with (root / ".git" / "config").open("a", encoding="utf-8", newline="\n") as handle:
        handle.write('[filter "a=b"]\n\tclean = sh .git/probe.sh\n')
    (root / ".git" / "info" / "attributes").write_text("* filter=a=b\n", encoding="utf-8")
    _touch_tracked(root, "app.py", "other.py")
    state = tree_state(root, {"app.py", "other.py"})
    assert state.status_failed and not state.clean
    assert walk.git_meta(root)[1] is None
    assert not marker.exists()


def test_a_hook_of_the_repository_never_starts_and_the_index_stays(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    marker = _probe(tmp_path, root)
    hook = root / ".git" / "hooks" / "post-index-change"
    hook.parent.mkdir(exist_ok=True)
    hook.write_text("#!/bin/sh\nsh .git/probe.sh </dev/null\n", encoding="utf-8", newline="\n")
    hook.chmod(0o755)
    _touch_tracked(root, "app.py", "other.py")
    index = (root / ".git" / "index").read_bytes()
    tree_state(root, {"app.py", "other.py"})
    walk.git_meta(root)
    assert not marker.exists()
    assert (root / ".git" / "index").read_bytes() == index


def test_a_submodule_filter_never_starts(tmp_path: Path) -> None:
    root, _module = _with_submodule(tmp_path, ignore_all=False)
    marker = _probe(tmp_path, root)
    module_git = root / ".git" / "modules" / "guard"
    shutil.copy(root / ".git" / "probe.sh", module_git / "probe.sh")
    _git(root / "guard", "config", "filter.probe.clean", f"sh {module_git.as_posix()}/probe.sh")
    (module_git / "info").mkdir(exist_ok=True)
    (module_git / "info" / "attributes").write_text("* filter=probe\n", encoding="utf-8")
    _touch_tracked(root / "guard", "guard.py")
    state = tree_state(root, {"app.py", "other.py", "guard/guard.py"})
    walk.git_meta(root)
    assert not marker.exists()
    assert not state.status_failed


def test_git_meta_sees_an_edit_in_a_submodule(tmp_path: Path) -> None:
    root, _module = _with_submodule(tmp_path)
    assert walk.git_meta(root)[1] is False
    (root / "guard" / "guard.py").write_text("GUARD = 2\n", encoding="utf-8")
    assert walk.git_meta(root)[1] is True


def test_a_status_that_cannot_run_is_never_read_as_no_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _bot(tmp_path)
    real = walk._git
    monkeypatch.setattr(
        walk, "_git", lambda args, cwd, **kw: None if "status" in args else real(args, cwd, **kw)
    )
    sha, dirty = walk.git_meta(root)
    assert sha is not None and dirty is None


def _partial_clone(tmp_path: Path) -> tuple[Path, Path, str]:
    """A repository that believes a missing blob can be fetched by a program of its own."""
    root = _bot(tmp_path)
    marker = _probe(tmp_path, root)
    blob = _git(root, "rev-parse", "HEAD:app.py").strip()
    loose = root / ".git" / "objects" / blob[:2] / blob[2:]
    loose.chmod(stat.S_IWRITE | stat.S_IREAD)
    loose.unlink()
    _git(root, "config", "core.repositoryformatversion", "1")
    _git(root, "config", "extensions.partialClone", "origin")
    _git(root, "config", "remote.origin.url", "ssh://git@example.invalid/x.git")
    _git(root, "config", "remote.origin.promisor", "true")
    _git(root, "config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")
    _git(root, "config", "core.sshCommand", "sh .git/probe.sh")
    return root, marker, blob


@pytest.mark.parametrize("override", [False, True])
def test_a_missing_object_is_never_fetched_by_a_program_of_the_repository(
    tmp_path: Path, override: bool
) -> None:
    root, marker, blob = _partial_clone(tmp_path)
    if override:
        _git(root, "config", "protocol.ssh.allow", "always")
    assert walk._git(["cat-file", "-p", blob], root) is None
    assert not marker.exists()


def test_a_signed_commit_never_starts_the_repository_gpg_program(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    marker = tmp_path / "started.txt"
    script = root / ".git" / "gpg.sh"
    script.write_text(
        "#!/bin/sh\n"
        f'echo started >> "{marker.as_posix()}"\n'
        "cat > /dev/null\n"
        'echo "[GNUPG:] SIG_CREATED " >&2\n'
        'echo "-----BEGIN PGP SIGNATURE-----"\n'
        'echo "x"\n'
        'echo "-----END PGP SIGNATURE-----"\n',
        encoding="utf-8",
        newline="\n",
    )
    script.chmod(0o755)
    (root / "app.py").write_text("print('signed')\n", encoding="utf-8")
    _git(root, "add", "-A")
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "user.name=t",
            "-c",
            f"gpg.program={script.as_posix()}",
            "commit",
            "-q",
            "-S",
            "-m",
            "signed",
        ],
        cwd=root,
        check=True,
        capture_output=True,
    )
    marker.unlink()
    _git(root, "config", "log.showSignature", "true")
    _git(root, "config", "gpg.program", script.as_posix())
    assert walk._git(["log", "-1", "--format=%cI", "--", "app.py"], root)
    assert not marker.exists()


def test_a_fresh_copy_of_the_fixture_is_clean(tmp_path: Path) -> None:
    root = copy_tree("partial_trace", tmp_path)
    _git(root, "init", "-q")
    _commit(root)
    assert machine_scan(root).state.clean
