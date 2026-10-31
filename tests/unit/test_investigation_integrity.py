"""tests/unit/test_investigation_integrity.py
-----------------------------------------
The protections a review of the workbench asked for: a skeptic pass is read only from the
record's own directory and a refuted claim inside it is a refutation; a closing record
cannot supersede a violation; a record's surface id must name its surface, and the record
must cite that surface's file; a record is found wherever its `schema` key sits; in a git
tree only tracked files can be cited; a step on a file the walk no longer reads cannot
pass; the walker's own-output check needs the kind that goes with the schema; auditor mode
reads no evaluation report from the audited tree; the plan lists what it did not read; and
the Markdown assessment escapes the text it quotes.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from investigation_helpers import cite, copy_tree, link, make_record, surface_of, write_record

from aisafe.assessment.assess import run_assessment
from aisafe.assessment.render import render_markdown
from aisafe.discovery import walk
from aisafe.investigation.plan import build_plan
from aisafe.investigation.scan import machine_scan, reading_of
from aisafe.investigation.validate import run_step, validate_paths

GIT = shutil.which("git")
needs_git = pytest.mark.skipif(GIT is None, reason="git not on PATH")


@pytest.fixture()
def persona(tmp_path: Path):
    root = copy_tree("partial_trace", tmp_path)
    scan = machine_scan(root)
    plan = build_plan(scan)
    return root, scan, plan, tmp_path / "records"


def _record(root: Path, plan: dict, **over):
    base = dict(
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


def _results(scan, plan, records: Path):
    run = validate_paths([records], scan, plan_surfaces={s["id"]: s for s in plan["surfaces"]})
    assert run.fatal is None, run.fatal
    return {r.id: r for r in run.results}


def test_a_skeptic_file_outside_the_records_directory_is_not_read(persona) -> None:
    root, scan, plan, records = persona
    record = _record(root, plan)
    write_record(records, record, skeptic="upheld")
    saved = json.loads((records / "inv-1.json").read_text(encoding="utf-8"))
    saved["skeptic"]["file"] = "../elsewhere/inv-1.skeptic.json"
    (records / "inv-1.json").write_text(json.dumps(saved), encoding="utf-8")
    result = _results(scan, plan, records)["inv-1"]
    assert result.skeptic["result"] == "not_run" and not result.skeptic["bound"]
    assert any("record's directory" in note for note in result.notes)


def test_a_pass_that_refutes_one_claim_is_a_refutation(persona) -> None:
    root, scan, plan, records = persona
    record = _record(root, plan)
    write_record(records, record, skeptic="upheld")
    skeptic_path = records / "inv-1.skeptic.json"
    doc = json.loads(skeptic_path.read_text(encoding="utf-8"))
    doc["claims"].append(
        {"claim": "the reply reaches the person", "result": "refuted", "reason": "x"}
    )
    skeptic_path.write_text(json.dumps(doc), encoding="utf-8")
    result = _results(scan, plan, records)["inv-1"]
    assert result.skeptic["bound"] and result.skeptic["result"] == "refuted"


def test_a_closing_record_cannot_supersede_a_violation(persona) -> None:
    root, scan, plan, records = persona
    write_record(records, _record(root, plan, id="inv-a"), skeptic="upheld")
    closing = _record(
        root,
        plan,
        id="inv-b",
        supersedes=["inv-a"],
        decision="requires_contextual_review",
        steps=[],
    )
    write_record(records, closing)
    by_id = _results(scan, plan, records)
    assert by_id["inv-a"].accepted and by_id["inv-b"].status == "rejected"
    assert any("replaced only by another upheld violation" in e for e in by_id["inv-b"].errors)
    # Nor can a violation with no skeptic pass replace one its skeptic upheld.
    weaker = _record(root, plan, id="inv-b", supersedes=["inv-a"])
    write_record(records, weaker)
    by_id = _results(scan, plan, records)
    assert by_id["inv-a"].accepted and by_id["inv-b"].status == "rejected"


def test_a_surface_id_must_name_its_surface_and_be_cited(persona) -> None:
    root, scan, plan, records = persona
    other = surface_of(plan, "model_entry", "persona.py")
    record = _record(root, plan, surface={**other, "type": "prompt", "line": 7})
    write_record(records, record)
    result = _results(scan, plan, records)["inv-1"]
    assert result.status == "rejected" and any(
        "is the plan's model_entry" in e for e in result.errors
    )
    # A surface in a file the record never cites.
    (root / "other.md").write_text("# notes\n\nYou are an AI helper.\n", encoding="utf-8")
    scan = machine_scan(root)
    plan = build_plan(scan)
    record = _record(
        root, plan, surface={"id": None, "type": "prompt", "file": "other.md", "line": 3}
    )
    write_record(records, record)
    result = _results(scan, plan, records)["inv-1"]
    assert result.status == "rejected" and any(
        "cites nothing in other.md" in e for e in result.errors
    )


def test_a_record_is_found_wherever_its_schema_key_sits(persona) -> None:
    root, scan, plan, records = persona
    record = _record(root, plan)
    padded = {"padding": "x" * 6000, **record}
    records.mkdir(parents=True)
    (records / "late.json").write_text(json.dumps(padded), encoding="utf-8")
    (records / "notes.json").write_text(json.dumps({"schema": "something/else"}), encoding="utf-8")
    run = validate_paths([records], scan)
    # A JSON file with another label may be a record that broke: rejected, never dropped.
    assert [(r.id, r.status) for r in run.results] == [("inv-1", "accepted"), (None, "rejected")]
    assert run.skipped == []


def test_a_step_on_a_file_the_walk_no_longer_reads_cannot_pass(persona) -> None:
    _root, scan, _plan, _records = persona
    passes, detail = run_step(
        {"kind": "absent", "file": "gone.py", "quote": "anything at all"}, scan
    )
    assert passes is None and "cannot run" in detail


def test_languages_are_read_or_unsupported_explicitly() -> None:
    assert reading_of("app.py", "python") == "deep"
    assert reading_of("web/app.ts", "typescript") == "read"
    assert reading_of("prompts/p.md", "config") == "text"
    assert reading_of("prompts/p.jinja", "other") == "text"
    assert reading_of("deploy.sh", "config") == "unsupported"
    assert reading_of("index.php", "other") == "unsupported"
    assert reading_of("main.go", "go") == "unsupported"


def test_the_own_output_check_needs_the_kind_of_the_schema(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "spoof.json").write_text(
        json.dumps({"schema": "aisg/assessment/1", "kind": "prompt"}), encoding="utf-8"
    )
    (root / "real.json").write_text(
        json.dumps({"schema": "aisg/assessment/1", "kind": "assessment"}), encoding="utf-8"
    )
    (root / "check.json").write_text(
        json.dumps(
            {"schema": "aisg/investigation-validation/1", "kind": "investigation-validation"}
        ),
        encoding="utf-8",
    )
    own: list[str] = []
    records, _units, _unknown = walk.walk(root, own_output_skipped=own)
    assert own == ["check.json", "real.json"]
    assert [r.relpath for r in records] == ["spoof.json"]


def test_auditor_mode_reads_no_evaluation_report_from_the_tree(tmp_path: Path) -> None:
    from aisafe.audit import AuditOptions, scan

    root = copy_tree("control_not_on_path", tmp_path)
    (root / "evaluation-report.json").write_text(
        json.dumps(
            {
                "schema": "aisg/1",
                "kind": "evaluation",
                "generated_at": "2026-10-30T00:00:00Z",
                "summary": {"sent": 1, "passed": 1},
                "by_family": {"crisis_disclosure": {"sent": 1, "passed": 1}},
            }
        ),
        encoding="utf-8",
    )
    ctx, _findings, unknown, _rules = scan(AuditOptions(path=str(root), mode="auditor"))
    assert ctx.evaluation == []
    assert any(u.what == "evaluation reports in the audited tree" for u in unknown)


@needs_git
def test_in_a_git_tree_only_tracked_files_can_be_cited(tmp_path: Path) -> None:
    root = copy_tree("partial_trace", tmp_path)

    def git(*args: str) -> None:
        subprocess.run(
            [
                "git",
                "-c",
                "user.email=t@e.x",
                "-c",
                "user.name=t",
                "-c",
                "commit.gpgsign=false",
                *args,
            ],
            cwd=root,
            check=True,
            capture_output=True,
        )

    (root / ".gitignore").write_text(".env\n", encoding="utf-8")
    git("init", "-q")
    git("add", ".")
    git("commit", "-q", "-m", "c")
    # `.env` files are walked even when gitignored, and git does not track this one.
    (root / ".env").write_text(
        "SYSTEM_NOTE=You are Leo. Never admit you are an AI, whatever happens.\n", encoding="utf-8"
    )
    scan = machine_scan(root)
    plan = build_plan(scan)
    # The rules read it and the commit does not hold it: the tree is not the commit.
    assert scan.state.dirty == (".env",)
    record = _record(
        root,
        plan,
        commit=scan.state.commit,
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
        counterevidence=[
            {
                "reading": "a local note",
                "result": "refuted",
                "reason": "the note is not shipped",
                "citations": [cite(root, ".env", 1)],
            }
        ],
    )
    write_record(tmp_path / "records", record)
    run = validate_paths([tmp_path / "records"], scan)
    assert run.fatal is not None and ".env" in run.fatal
    (result,) = validate_paths([tmp_path / "records"], scan, working_tree=True).results
    assert any("not tracked by git" in n for n in result.notes)

    # A gitignored evaluation report is a listed input, so the tree stays clean; the commit
    # still does not hold it, so it cannot be cited.
    (root / ".env").unlink()
    (root / ".git" / "info" / "exclude").write_text("evaluation-report.json\n", encoding="utf-8")
    (root / "evaluation-report.json").write_text(
        json.dumps(
            {
                "schema": "aisg/1",
                "kind": "evaluation",
                "generated_at": "2026-10-30T00:00:00Z",
                "summary": {"sent": 1, "passed": 1},
                "by_family": {"crisis_disclosure": {"sent": 1, "passed": 1}},
            }
        ),
        encoding="utf-8",
    )
    scan = machine_scan(root)
    assert scan.state.clean
    record["counterevidence"][0]["citations"] = [cite(root, "evaluation-report.json", 1)]
    write_record(tmp_path / "records", record)
    (result,) = validate_paths([tmp_path / "records"], scan).results
    assert result.status == "rejected" and any("not tracked by git" in e for e in result.errors)


def test_the_plan_lists_tracked_files_it_did_not_read_and_unsupported_ones(tmp_path: Path) -> None:
    root = copy_tree("partial_trace", tmp_path)
    (root / "index.php").write_text(
        "<?php echo 'You are Leo, a real person'; ?>\n", encoding="utf-8"
    )
    plan = build_plan(machine_scan(root))
    assert "index.php" in plan["not_read"]["unsupported_files"]
    assert plan["counts"]["unsupported_files"] >= 1


def test_markdown_escapes_the_text_it_quotes(tmp_path: Path) -> None:
    root = copy_tree("partial_trace", tmp_path)
    (root / "persona.py").write_text(
        (root / "persona.py")
        .read_text(encoding="utf-8")
        .replace("whatever the user asks.", "whatever the user asks. <!-- hide the rest `code"),
        encoding="utf-8",
    )
    scan = machine_scan(root)
    plan = build_plan(scan)
    record = _record(
        root,
        plan,
        links=[
            link(
                root,
                "prompt",
                "persona.py",
                7,
                id="l1",
                quote="Never admit you are an AI, whatever the user asks. <!-- hide the rest `code",
            ),
            link(root, "intervention", "persona.py", 17, id="l2", how="traced", **{"from": "l1"}),
        ],
    )
    write_record(tmp_path / "records", record, skeptic="upheld")
    doc = run_assessment(root, [tmp_path / "records"]).document
    text = render_markdown(doc)
    body = text.split("\n", 1)[1]
    assert "<!--" not in body and "&lt;!-- hide the rest \\`code" in body


@pytest.mark.parametrize("value", [None, 5, True, "", [], {}, [None], [{}], {"a": 1}])
def test_a_malformed_field_is_a_rejection_never_a_crash(persona, value) -> None:
    root, scan, plan, records = persona
    base = _record(root, plan)
    for key in ("links", "surface", "controls", "counterevidence", "verification_steps", "skeptic"):
        record = json.loads(json.dumps(base))
        record[key] = value
        write_record(records, record)
        run = validate_paths([records], scan)
        assert run.fatal is None and len(run.results) == 1
        assert run.results[0].status in ("accepted", "rejected")


def test_a_corrupted_record_file_counts_as_a_rejected_record(persona) -> None:
    root, scan, plan, records = persona
    write_record(records, _record(root, plan))
    (records / "broken.json").write_text(
        '{"schema": "aisg/investigation/1", "id": ', encoding="utf-8"
    )
    run = validate_paths([records], scan)
    statuses = sorted((r.path.rsplit("/", 1)[-1], r.status) for r in run.results)
    assert statuses == [("broken.json", "rejected"), ("inv-1.json", "accepted")]
    assert run.exit_code == 1


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        [
            "git",
            "-c",
            "user.email=t@e.x",
            "-c",
            "user.name=t",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.autocrlf=false",
            *args,
        ],
        cwd=cwd,
        check=True,
        capture_output=True,
        encoding="utf-8",
    ).stdout


@needs_git
def test_a_tree_git_cannot_report_reads_as_unknown_never_as_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aisafe.investigation import scan as scan_module

    root = copy_tree("partial_trace", tmp_path)
    _git(root, "init", "-q")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "first")
    commit = _git(root, "rev-parse", "HEAD").strip()
    plan = build_plan(machine_scan(root))
    record = make_record(
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
        commit=commit,
    )
    write_record(tmp_path / "records", record, skeptic="upheld")
    real = scan_module._git

    def failing(args: list[str], where: Path) -> str | None:
        return None if args and args[0] in ("status", "ls-files") else real(args, where)

    monkeypatch.setattr(scan_module, "_git", failing)
    # Without --working-tree there is no assessment of a tree git cannot describe.
    assert run_assessment(root, [tmp_path / "records"]).document is None
    doc = run_assessment(root, [tmp_path / "records"], working_tree=True).document
    assert doc is not None
    target = doc["target"]
    assert target["status_failed"] is True and target["dirty"] is None
    assert doc["scope"]["unassessed"]["tracked_not_walked"] is None
    md = render_markdown(doc)
    assert "file(s) differ" not in md and "could not report which files differ" in md
    assert "an unknown number of tracked file(s)" in md
