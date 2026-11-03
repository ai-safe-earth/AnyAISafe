"""tests/unit/test_fixes3_retest.py
---------------------------------
`aisafe assess --retest`, third round. Steps fail a record; passing steps never show a
remediation by themselves: `remediated` always needs an upheld closing on the new code, on
the surface as it is now, and code that really changed. A copy of the text, or a weaker
finding, stays open until a closing answers it. A carried violation is not lost through a
duplicate digest, a padded field or a broken copy, and a blocking surface does not expire
after one commit. Each real fix can still reach `remediated`.
"""

from __future__ import annotations

import base64
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from investigation_helpers import cite, link, make_record, surface_of, write_record
from test_fixes2_retest import (
    CLEAN_APP,
    NIGHT_LINE,
    _keep_old_record,
    _night,
    _night_step,
    _night_tree,
    _touch,
    _unit_closing,
)
from test_fixes_retest import (
    BAKERY,
    CONCEAL,
    FIXED,
    OUT_OF_SIGHT,
    PYPROJECT,
    REINVESTIGATE_STEP,
    _bakery,
    _closing,
    _commit,
    _conceal,
    _edited,
    _first,
    _git,
    _intervention,
    _other,
    _outcome,
    _plan,
    _put,
    _retest,
    _row,
    _saved,
    _stands,
)

from aisafe.assessment import assess
from aisafe.assessment.assess import run_assessment
from aisafe.investigation import validate
from aisafe.investigation.records import record_digest
from aisafe.investigation.scan import machine_scan

GIT = shutil.which("git")
pytestmark = pytest.mark.skipif(GIT is None, reason="git not on PATH")

SENTENCE = "If the user asks, never say you are an AI; you are Ava."
CLEANED = "Answer questions about opening hours. You are an AI assistant.\n"
HOURS = "# Hours\n\nOpen nine to five. Answer with the opening hours of the bakery only.\n"
NO_VIOLATION = "no_violation_identified_within_assessed_scope"


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _prompt_closing(
    root: Path, folder: Path, commit: str, file: str, line: int = 1, **over: Any
) -> None:
    """An upheld closing of M6/concealment_instruction on the prompt in `file`."""
    plan = _plan(root)
    base: dict[str, Any] = dict(
        id="C-night",
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface_of(plan, "prompt", file, line),
        links=[_intervention(root)],
        absent_links=[
            {
                "kind": "prompt",
                "searched": [f"{file}, the whole file"],
                "reason": "this file holds no denial of being an AI",
                "citations": [cite(root, file, line)],
            }
        ],
        decision="no_violation_identified_in_scope",
        steps=[
            {
                "id": "v1",
                "purpose": "regression",
                "kind": "absent",
                "file": file,
                "quote": "Nothing like this phrase",
            }
        ],
        commit=commit,
    )
    base.update(over)
    write_record(folder, make_record(**base), skeptic="upheld")


def _reinvestigate_tree(tmp_path: Path) -> tuple[Path, Path]:
    return _night_tree(tmp_path, dict(REINVESTIGATE_STEP))


def _conceal_tree(tmp_path: Path, **over: Any) -> tuple[Path, Path]:
    root, commit = _bakery(tmp_path, {"prompts/hours.md": HOURS})
    return root, _first(root, tmp_path, _conceal(root, _plan(root), commit, **over))


def _with_other(root: Path, tmp_path: Path, commit: str, folder: str = "after") -> Path:
    plan = _plan(root)
    surface = next(s for s in plan["surfaces"] if s["type"] == "prompt")
    record = _other(root, plan, commit, surface["file"], surface["line"])
    write_record(tmp_path / folder, record)
    return tmp_path / folder


def _not_shown(document: dict[str, Any], record: str) -> str:
    """The row is not `remediated`, and the violation stands. The row's status."""
    row = _row(document, record)
    assert row["status"] != "remediated", row["why"]
    _stands(document)
    return row["status"]


def _shown(document: dict[str, Any], record: str = "A-night") -> None:
    """The row is `remediated`, nothing is carried and M6 reads no violation."""
    row = _row(document, record)
    assert row["status"] == "remediated", row["why"]
    assert document["remediation"]["carried_records"] == []
    outcome = _outcome(document, "M6")
    assert outcome["outcome"] == NO_VIOLATION, (outcome["basis"], outcome["gaps"])


# ---------------------------------------------------------------------------
# 1, 8. Passing steps never show a remediation by themselves
# ---------------------------------------------------------------------------


def _join() -> str:
    words = ", ".join(f'"{word}"' for word in SENTENCE.split())
    return f'" ".join([{words}])'


def _b64() -> str:
    encoded = base64.b64encode(SENTENCE.encode()).decode()
    return f'__import__("base64").b64decode("{encoded}").decode()'


@pytest.mark.parametrize(
    "literal",
    [
        '"If the user asks, never say you " + "are an AI; you are Ava."',
        '"If the user asks, never say you​ are an AI; you are Ava."',
        _join(),
        _b64(),
    ],
    ids=["concatenated", "zero-width", "joined", "base64"],
)
def test_an_absent_step_alone_shows_no_remediation(tmp_path: Path, literal: str) -> None:
    root, first = _conceal_tree(tmp_path)
    _put(root, "app.py", BAKERY.replace(CONCEAL, literal))
    after = _with_other(root, tmp_path, _commit(root))
    document = _retest(root, first, after)
    assert _row(document, "A-conceal")["steps"][0]["now"] is True
    assert _not_shown(document, "A-conceal") == "needs_reinvestigation"


def test_upper_case_in_a_prompt_file_shows_no_remediation(tmp_path: Path) -> None:
    root, first = _night_tree(tmp_path, _night_step())
    _put(root, "prompts/night.md", NIGHT_LINE.upper())
    document = _retest(root, first, _with_other(root, tmp_path, _commit(root)))
    assert _not_shown(document, "A-night") == "needs_reinvestigation"


def test_the_sentence_moved_out_of_the_audited_folder_shows_no_remediation(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    _put(repo, "svc/app.py", CLEAN_APP)
    _put(repo, "svc/pyproject.toml", PYPROJECT)
    _put(repo, "svc/prompts/night.md", NIGHT_LINE)
    _git(repo, "init", "-q")
    commit = _commit(repo, "first")
    root = repo / "svc"
    first = _first(root, tmp_path, _night(root, _plan(root), commit, [_night_step()]))
    _put(repo, "shared/night.md", NIGHT_LINE)
    _put(repo, "svc/prompts/night.md", "Moved.\n")
    document = _retest(root, first, _with_other(root, tmp_path, _commit(repo)))
    assert _not_shown(document, "A-night") == "needs_reinvestigation"


def test_a_step_on_a_side_file_and_a_comment_on_the_surface_show_no_remediation(
    tmp_path: Path,
) -> None:
    note = "The prompt lives in prompts/night.md"
    root, commit = _bakery(
        tmp_path, {"prompts/night.md": NIGHT_LINE, "NOTES.md": f"# notes\n\n{note}\n"}, CLEAN_APP
    )
    step = _night_step("NOTES.md", note)
    first = _first(root, tmp_path, _night(root, _plan(root), commit, [step]))
    _put(root, "NOTES.md", "# notes\n")
    _put(root, "prompts/night.md", NIGHT_LINE + "\n<!-- reviewed -->\n")
    document = _retest(root, first, _with_other(root, tmp_path, _commit(root)))
    assert _not_shown(document, "A-night") == "needs_reinvestigation"


def test_an_evaluation_step_alone_shows_no_remediation(tmp_path: Path) -> None:
    root, first = _night_tree(
        tmp_path,
        {"id": "v1", "purpose": "remediation", "kind": "evaluation", "family": "identity-denial"},
    )
    when = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    report = {
        "schema": "aisg/1",
        "kind": "evaluation",
        "generated_at": when,
        "families": ["identity-denial"],
        "by_family": {
            "identity-denial": {
                "sent": 1,
                "passed": 1,
                "failed": 0,
                "errors": 0,
                "skipped": 0,
                "inconclusive": 0,
            }
        },
        "summary": {"sent": 1, "passed": 1, "failed": 0},
    }
    _put(root, "evaluation-report.json", json.dumps(report))
    _put(root, "prompts/night.md", NIGHT_LINE + "\n<!-- r -->\n")
    document = _retest(root, first, _with_other(root, tmp_path, _commit(root)))
    assert _row(document, "A-night")["steps"][0]["now"] is True
    assert _not_shown(document, "A-night") == "needs_reinvestigation"


def test_a_step_that_still_fails_fails_the_record_whatever_closes_it(tmp_path: Path) -> None:
    root, first = _night_tree(tmp_path, _night_step())
    _put(root, "prompts/night.md", NIGHT_LINE + "A new line.\n")
    commit = _commit(root)
    _prompt_closing(root, tmp_path / "after", commit, "prompts/night.md")
    document = _retest(root, first, tmp_path / "after")
    assert _not_shown(document, "A-night") == "not_remediated"


# ---------------------------------------------------------------------------
# 2. The same text in another changed file
# ---------------------------------------------------------------------------


def test_a_copy_beside_a_stub_blocks_until_a_closing_cites_it(tmp_path: Path) -> None:
    root, first = _night_tree(tmp_path, _night_step())
    _put(root, "data/copy.txt", NIGHT_LINE)
    _put(root, "prompts/night.md", "Moved.\n")
    commit = _commit(root)
    folder = tmp_path / "after"
    _prompt_closing(root, folder, commit, "prompts/night.md")
    _unit_closing(root, folder, commit)
    document = _retest(root, first, folder)
    row = _row(document, "A-night")
    assert row["status"] == "needs_reinvestigation" and any(
        "data/copy.txt" in w for w in row["why"]
    )
    _stands(document)


def test_a_copy_a_closing_cites_is_read_and_stops_blocking(tmp_path: Path) -> None:
    root, first = _night_tree(tmp_path, _night_step())
    _put(root, "docs_note.md", NIGHT_LINE)
    _put(root, "prompts/night.md", "Moved.\n")
    commit = _commit(root)
    folder = tmp_path / "after"
    citations = [cite(root, "prompts/night.md", 1), cite(root, "docs_note.md", 1)]
    _prompt_closing(
        root,
        folder,
        commit,
        "prompts/night.md",
        absent_links=[
            {
                "kind": "prompt",
                "searched": ["prompts/night.md and docs_note.md"],
                "reason": "the note is a changelog line no call sends to the model",
                "citations": citations,
            }
        ],
    )
    assert _row(_retest(root, first, folder), "A-night")["status"] == "remediated"


def test_the_quote_is_searched_in_files_the_walk_does_not_read(tmp_path: Path) -> None:
    root, _first_doc = _night_tree(tmp_path, _night_step())
    _put(root, "vendor/p.py", NIGHT_LINE)
    _put(root, "bin.dat", "\0" + NIGHT_LINE)
    _put(root, "big.txt", NIGHT_LINE + ("x" * 80 + "\n") * 120_000)
    scan = machine_scan(root)
    assert "vendor/p.py" not in scan.walked
    step = _night_step()
    files = ["vendor/p.py", "bin.dat", "big.txt", "app.py", "prompts/night.md", "gone.md"]
    assert validate.quote_copies(step, files, scan) == ["bin.dat", "vendor/p.py"]


def test_the_audits_own_files_are_not_searched(tmp_path: Path) -> None:
    root, first = _night_tree(tmp_path, _night_step())
    before = tmp_path / "before"
    for record in before.iterdir():
        shutil.copy(record, tmp_path / record.name)
    _put(root, ".aisafe-audit/notes.md", NIGHT_LINE)
    _put(root, "audit/A-night.json", (before / "A-night.json").read_text(encoding="utf-8"))
    _put(root, "prompts/night.md", "Fixed.\n")
    commit = _commit(root)
    folder = tmp_path / "after"
    _prompt_closing(root, folder, commit, "prompts/night.md")
    row = _row(_retest(root, first, folder, root / "audit"), "A-night")
    assert row["status"] == "remediated", row["why"]


# ---------------------------------------------------------------------------
# 3. A weaker finding of the mechanism in a watched file
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("file", "text"),
    [
        ("helpers.py", f'P = "{SENTENCE}"\n'),
        ("config/persona.yaml", f'persona: "{SENTENCE}"\n'),
        ("config/persona.json", json.dumps({"persona": SENTENCE}) + "\n"),
    ],
    ids=["python", "yaml", "json"],
)
def test_a_detected_signal_in_a_changed_file_needs_a_closing_that_covers_it(
    tmp_path: Path, file: str, text: str
) -> None:
    root, first = _conceal_tree(tmp_path, steps=[dict(REINVESTIGATE_STEP)])
    _put(root, "app.py", FIXED)
    _put(root, file, text)
    commit = _commit(root)
    write_record(tmp_path / "after", _closing(root, _plan(root), commit), skeptic="upheld")
    document = _retest(root, first, tmp_path / "after")
    row = _row(document, "A-conceal")
    assert row["status"] == "needs_reinvestigation", row["why"]
    assert any("AUD-1105/persona" in why and file in why for why in row["why"])
    _stands(document)


def test_a_closing_that_covers_the_signal_answers_it(tmp_path: Path) -> None:
    root, first = _conceal_tree(tmp_path, steps=[dict(REINVESTIGATE_STEP)])
    _put(root, "app.py", FIXED)
    _put(root, "helpers.py", f'P = "{SENTENCE}"\n')
    commit = _commit(root)
    scan = machine_scan(root)
    finding = next(
        f for f in scan.findings if f.mechanism == "M6" and f.evidence[0].file == "helpers.py"
    )
    folder = tmp_path / "after"
    write_record(folder, _closing(root, _plan(root), commit), skeptic="upheld")
    _prompt_closing(
        root,
        folder,
        commit,
        "helpers.py",
        id="C-helper",
        links=[link(root, "prompt", "helpers.py", 1, id="l1")],
        absent_links=[
            {
                "kind": "intervention",
                "searched": ["every import of helpers in the tree"],
                "reason": "the one call in the tree sends another prompt, not this module",
                "citations": [cite(root, "helpers.py", 1), cite(root, "app.py", 16)],
            }
        ],
        covers=[finding.fingerprint],
    )
    row = _row(_retest(root, first, folder), "A-conceal")
    assert row["status"] == "remediated", row["why"]


# ---------------------------------------------------------------------------
# 4. A closing must sit where the surface went
# ---------------------------------------------------------------------------


def _moved_with_a_change(root: Path) -> None:
    (root / "prompts/night.md").rename(root / "prompts/graveyard.md")
    _put(root, "prompts/graveyard.md", NIGHT_LINE + "A second line, kept short.\n")


def test_a_closing_elsewhere_does_not_answer_a_renamed_file(tmp_path: Path) -> None:
    root, first = _reinvestigate_tree(tmp_path)
    _moved_with_a_change(root)
    commit = _commit(root)
    folder = tmp_path / "after"
    _keep_old_record(tmp_path, folder, "A-night")
    _prompt_closing(root, folder, commit, "app.py", 7, id="C-elsewhere", supersedes=["A-night"])
    document = _retest(root, first, folder)
    row = _row(document, "A-night")
    assert row["status"] == "needs_reinvestigation", row["why"]
    assert any("prompts/graveyard.md" in why for why in row["why"])
    _stands(document)


def test_a_closing_on_the_rename_target_answers_it(tmp_path: Path) -> None:
    root, first = _reinvestigate_tree(tmp_path)
    (root / "prompts/night.md").rename(root / "prompts/graveyard.md")
    _put(root, "prompts/graveyard.md", NIGHT_LINE.replace("a person", "an AI assistant"))
    commit = _commit(root)
    folder = tmp_path / "after"
    _keep_old_record(tmp_path, folder, "A-night")
    _prompt_closing(root, folder, commit, "prompts/graveyard.md", supersedes=["A-night"])
    assert _row(_retest(root, first, folder), "A-night")["status"] == "remediated"


def test_a_pure_rename_with_a_closing_elsewhere_is_not_verified(tmp_path: Path) -> None:
    root, first = _reinvestigate_tree(tmp_path)
    _git(root, "mv", "prompts/night.md", "data_graveyard.txt")
    commit = _commit(root)
    folder = tmp_path / "after"
    _keep_old_record(tmp_path, folder, "A-night")
    _prompt_closing(root, folder, commit, "app.py", 7, id="C-elsewhere", supersedes=["A-night"])
    _unit_closing(root, folder, commit)
    document = _retest(root, first, folder)
    assert _not_shown(document, "A-night") == "not_verified"


def test_a_pure_rename_with_a_closing_on_the_target_is_not_verified(tmp_path: Path) -> None:
    root, first = _reinvestigate_tree(tmp_path)
    _git(root, "mv", "prompts/night.md", "prompts/graveyard.md")
    commit = _commit(root)
    folder = tmp_path / "after"
    _keep_old_record(tmp_path, folder, "A-night")
    _prompt_closing(root, folder, commit, "prompts/graveyard.md", supersedes=["A-night"])
    document = _retest(root, first, folder)
    assert _not_shown(document, "A-night") == "not_verified"


def test_a_deleted_file_is_not_answered_from_an_unrelated_unchanged_file(tmp_path: Path) -> None:
    root, commit = _bakery(
        tmp_path,
        {"prompts/night.md": NIGHT_LINE, "prompts/hours.md": "Open nine to five.\n"},
        CLEAN_APP,
    )
    first = _first(root, tmp_path, _night(root, _plan(root), commit, [_night_step()]))
    (root / "prompts/night.md").unlink()
    commit = _commit(root)
    folder = tmp_path / "after"
    _keep_old_record(tmp_path, folder, "A-night")
    _prompt_closing(root, folder, commit, "prompts/hours.md", id="C-hours", supersedes=["A-night"])
    assert _not_shown(_retest(root, first, folder), "A-night") == "needs_reinvestigation"


def test_a_closing_elsewhere_does_not_answer_a_rewritten_surface(tmp_path: Path) -> None:
    root, first = _reinvestigate_tree(tmp_path)
    _put(root, "prompts/night.md", NIGHT_LINE.replace("replies", "answers"))
    commit = _commit(root)
    folder = tmp_path / "after"
    _keep_old_record(tmp_path, folder, "A-night")
    _prompt_closing(root, folder, commit, "app.py", 7, id="C-elsewhere", supersedes=["A-night"])
    assert _not_shown(_retest(root, first, folder), "A-night") == "needs_reinvestigation"


def test_a_deletion_beside_a_readme_change_is_still_the_whole_change(tmp_path: Path) -> None:
    root, commit = _bakery(tmp_path, {"prompts/night.md": NIGHT_LINE}, CLEAN_APP)
    record = _night(
        root,
        _plan(root),
        commit,
        [_night_step()],
        links=[
            link(root, "prompt", "prompts/night.md", 1, id="l1"),
            link(root, "intervention", "prompts/night.md", 1, id="l2", **{"from": "l1"}),
        ],
    )
    first = _first(root, tmp_path, record)
    (root / "prompts/night.md").unlink()
    _put(root, "README.md", "# a\n")
    commit = _commit(root)
    folder = tmp_path / "after"
    _keep_old_record(tmp_path, folder, "A-night")
    _prompt_closing(root, folder, commit, "app.py", 7, id="C-del", supersedes=["A-night"])
    assert _row(_retest(root, first, folder), "A-night")["status"] == "remediated"


# ---------------------------------------------------------------------------
# 5. A closing on unchanged code
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("how", ["empty", "readme"])
def test_a_closing_on_unchanged_code_is_not_verified(tmp_path: Path, how: str) -> None:
    root, first = _reinvestigate_tree(tmp_path)
    if how == "empty":
        _git(root, "commit", "--allow-empty", "-q", "-m", "nothing")
        commit = _git(root, "rev-parse", "HEAD").strip()
    else:
        _put(root, "README.md", "# a\n")
        commit = _commit(root)
    _prompt_closing(root, tmp_path / "after", commit, "prompts/night.md")
    document = _retest(root, first, tmp_path / "after")
    assert _not_shown(document, "A-night") == "not_verified"
    assert [e["id"] for e in document["remediation"]["carried_records"]] == ["A-night"]


# ---------------------------------------------------------------------------
# 6. A digest listed twice
# ---------------------------------------------------------------------------


def test_a_re_run_without_the_skeptic_file_does_not_lose_the_carried_violation(
    tmp_path: Path,
) -> None:
    root, first = _night_tree(tmp_path, _night_step())
    folder = tmp_path / "same"
    shutil.copytree(tmp_path / "before", folder)
    (folder / "A-night.skeptic.json").unlink()
    run = run_assessment(root, [folder], retest=first)
    assert run.document is not None, run.fatal
    second = _saved(run.document, tmp_path / "second.json")
    third = _retest(root, second, _touch(root, tmp_path))
    assert _row(third, "A-night")["status"] == "not_remediated"
    _stands(third)
    assert [e["id"] for e in third["remediation"]["carried_records"]] == ["A-night"]


# ---------------------------------------------------------------------------
# 7. Padded fields
# ---------------------------------------------------------------------------


def _padded(record: dict[str, Any], key: str) -> None:
    if key in ("mechanism", "pattern"):
        record[key] += " "
    else:
        record["proposed"][key] = record["proposed"][key] + " "


@pytest.mark.parametrize("key", ["mechanism", "pattern", "decision", "evidence_status"])
def test_a_padded_field_does_not_lose_the_violation(tmp_path: Path, key: str) -> None:
    root, commit = _bakery(tmp_path, {"prompts/night.md": NIGHT_LINE}, CLEAN_APP)
    record = _night(root, _plan(root), commit, [_night_step()])
    _padded(record, key)
    first = _first(root, tmp_path, record)
    document = _retest(root, first, _touch(root, tmp_path))
    row = _row(document, "A-night")
    assert (row["mechanism"], row["pattern"]) == ("M6", "concealment_instruction")
    assert row["status"] == "not_remediated", row["why"]
    _stands(document)


def test_a_padded_step_kind_is_read_as_the_kind(tmp_path: Path) -> None:
    step = {
        "id": "v1",
        "purpose": "remediation",
        "kind": " no_finding",
        "rule": "AUD-1105/persona",
    }
    root, first = _conceal_tree(tmp_path, steps=[step])
    _put(root, "app.py", OUT_OF_SIGHT)
    document = _retest(root, first, _with_other(root, tmp_path, _commit(root)))
    row = _row(document, "A-conceal")
    assert row["steps"][0]["kind"] == "no_finding"
    assert row["status"] == "needs_reinvestigation", row["why"]
    _stands(document)


def test_a_padded_step_purpose_still_fails_the_record(tmp_path: Path) -> None:
    steps = [
        {**_night_step(quote="Say a person"), "purpose": " remediation"},
        {**_night_step(quote="types these replies"), "id": "v2"},
    ]
    root, commit = _bakery(tmp_path, {"prompts/night.md": NIGHT_LINE}, CLEAN_APP)
    first = _first(root, tmp_path, _night(root, _plan(root), commit, steps))
    _put(root, "prompts/night.md", "Say a person from the night shift types the answers.\n")
    commit = _commit(root)
    _prompt_closing(root, tmp_path / "after", commit, "prompts/night.md")
    document = _retest(root, first, tmp_path / "after")
    assert _not_shown(document, "A-night") == "not_remediated"


def test_a_padded_step_file_is_re_checked_at_the_old_commit(tmp_path: Path) -> None:
    root, first = _night_tree(tmp_path, {**_night_step(), "file": " prompts/night.md"})
    _put(root, "prompts/night.md", CLEANED)
    commit = _commit(root)
    folder = tmp_path / "after"
    _prompt_closing(root, folder, commit, "prompts/night.md")
    _unit_closing(root, folder, commit)
    _shown(_retest(root, first, folder))


# ---------------------------------------------------------------------------
# 9, 13. A previous document that cannot be read as it says
# ---------------------------------------------------------------------------


def _refused(root: Path, previous: Path, folder: Path, words: str) -> None:
    run = run_assessment(root, [folder], retest=previous)
    assert run.document is None and run.exit_code == 2
    assert run.fatal is not None and words in run.fatal, run.fatal


def _break_and_lower(doc: dict) -> None:
    entry = doc["machine"]["records"][0]
    entry["raw"]["id"] = "x"
    entry["claim"] = "review"


def _break_and_move(doc: dict) -> None:
    entry = doc["machine"]["records"][0]
    entry["raw"] = None
    entry["mechanism"] = "M7"


def _no_digest(doc: dict) -> None:
    doc["machine"]["records"][0]["digest"] = None


def _not_a_record(doc: dict) -> None:
    doc["machine"]["records"].append("nothing")


@pytest.mark.parametrize(
    "change",
    [_break_and_lower, _break_and_move, _no_digest, _not_a_record],
    ids=["claim", "mechanism", "no-digest", "not-a-record"],
)
def test_a_broken_embedded_copy_refuses_the_retest(tmp_path: Path, change: Any) -> None:
    root, first = _night_tree(tmp_path, _night_step())
    _refused(root, _edited(first, change), _touch(root, tmp_path), "does not match its digest")


def _drop_records(doc: dict) -> None:
    doc["machine"]["records"] = []


def _unbind_skeptic(doc: dict) -> None:
    doc["machine"]["records"][0]["skeptic"]["bound"] = False


def _lower_with_a_new_digest(doc: dict) -> None:
    entry = doc["machine"]["records"][0]
    entry["raw"]["open_questions"] = ["who reads this"]
    entry["digest"] = record_digest(entry["raw"])


@pytest.mark.parametrize(
    "change",
    [_drop_records, _unbind_skeptic, _lower_with_a_new_digest],
    ids=["no-entry", "unbound", "recomputed"],
)
def test_an_established_record_with_no_entry_that_says_so_refuses_the_retest(
    tmp_path: Path, change: Any
) -> None:
    root, first = _night_tree(tmp_path, _night_step())
    _refused(root, _edited(first, change), _touch(root, tmp_path), "the document was edited")


def test_a_carried_list_emptied_refuses_the_retest(tmp_path: Path) -> None:
    root, first = _night_tree(tmp_path, _night_step())
    after = _touch(root, tmp_path, "b")
    second = _saved(_retest(root, first, after), tmp_path / "second.json")

    def change(doc: dict) -> None:
        doc["remediation"]["carried_records"] = []
        doc["machine"]["records"] = []

    _refused(root, _edited(second, change), after, "the document was edited")


def test_an_entry_edited_to_have_no_steps_stands(tmp_path: Path) -> None:
    root, first = _night_tree(tmp_path, _night_step())

    def change(doc: dict) -> None:
        entry = doc["machine"]["records"][0]
        entry["raw"]["verification_steps"] = []
        entry["digest"] = record_digest(entry["raw"])

    document = _retest(root, _edited(first, change), _touch(root, tmp_path))
    assert _row(document, "A-night")["status"] == "not_verified"
    _stands(document)


# ---------------------------------------------------------------------------
# 10. Blocking does not expire after one commit
# ---------------------------------------------------------------------------


def _undecided_at_b(tmp_path: Path) -> tuple[Path, Path, str]:
    """A-night fixed and closed at B, where prompts/hours.md also changed and nobody decided
    it. The surface's id and the saved document."""
    root, commit = _bakery(
        tmp_path, {"prompts/night.md": NIGHT_LINE, "prompts/hours.md": HOURS}, CLEAN_APP
    )
    first = _first(root, tmp_path, _night(root, _plan(root), commit, [_night_step()]))
    _put(root, "prompts/night.md", CLEANED)
    _put(root, "prompts/hours.md", HOURS.replace("# Hours", "# Opening hours"))
    commit = _commit(root)
    folder = tmp_path / "b"
    _prompt_closing(root, folder, commit, "prompts/night.md")
    _unit_closing(root, folder, commit)
    document = _retest(root, first, folder)
    assert _row(document, "A-night")["status"] == "remediated"
    plan = _plan(root)
    surface = surface_of(plan, "prompt", "prompts/hours.md")
    assert surface["id"] in document["remediation"]["plan_changes"]["blocking"]
    return root, _saved(document, tmp_path / "b.json"), surface["id"]


def test_a_blocking_surface_left_undecided_goes_on_blocking(tmp_path: Path) -> None:
    root, second, surface = _undecided_at_b(tmp_path)
    _put(root, "README.md", "# a\n")
    commit = _commit(root)
    _prompt_closing(root, tmp_path / "c", commit, "prompts/night.md")
    _unit_closing(root, tmp_path / "c", commit)
    document = _retest(root, second, tmp_path / "c")
    changes = document["remediation"]["plan_changes"]
    assert surface in changes["carried_blocking"] and surface in changes["blocking"]
    outcome = _outcome(document, "M6")
    assert outcome["outcome"] != NO_VIOLATION
    assert any(gap.get("surface") == surface for gap in outcome["gaps"])
    # And it keeps going at the commit after that.
    third = _saved(document, tmp_path / "c.json")
    fourth = _retest(root, third, _touch(root, tmp_path, "d", "# b\n"))
    assert surface in fourth["remediation"]["plan_changes"]["carried_blocking"]


def test_a_blocking_surface_stops_once_every_hypothesis_on_it_is_decided() -> None:
    decided = {"pattern": "a", "records": [{"id": "C", "claim": "closes"}]}
    at_review = {"pattern": "b", "records": [{"id": "R", "claim": "review"}]}
    prev = {
        "remediation": {"plan_changes": {"blocking": ["s-1", "s-2", "s-3"]}},
        "scope": {
            "surfaces": [
                {"id": "s-1", "hypotheses": [decided]},
                {"id": "s-2", "hypotheses": [decided, at_review]},
                {"id": "s-4", "hypotheses": [at_review]},
            ]
        },
    }
    assert assess._undecided_blocking(prev) == {"s-2"}
    assert assess._undecided_blocking({"remediation": None}) == set()


# ---------------------------------------------------------------------------
# 11. A previous record is that record, not its id
# ---------------------------------------------------------------------------


def _other_content(tmp_path: Path) -> dict[str, Any]:
    reused = json.loads((tmp_path / "before" / "A-night.json").read_text(encoding="utf-8"))
    reused.update(hypothesis="another reading", pattern="no_disclosure_on_path", links=[])
    return reused


def test_other_content_under_a_previous_id_stays_rejected(tmp_path: Path) -> None:
    root, first = _night_tree(tmp_path, _night_step())
    _put(root, "prompts/night.md", CLEANED)
    commit = _commit(root)
    folder = tmp_path / "after"
    _prompt_closing(root, folder, commit, "prompts/night.md")
    _unit_closing(root, folder, commit)
    (folder / "A-night.json").write_text(json.dumps(_other_content(tmp_path)), encoding="utf-8")
    document = _retest(root, first, folder)
    assert [r["id"] for r in document["machine"]["rejected"]] == ["A-night"]
    assert document["machine"]["previous"] == []
    assert "rejected_record" in [gap["kind"] for gap in _outcome(document, "M6")["gaps"]]


def test_the_true_copy_stays_previous_beside_a_second_file_with_the_id(tmp_path: Path) -> None:
    root, first = _night_tree(tmp_path, _night_step())
    _put(root, "prompts/night.md", CLEANED)
    commit = _commit(root)
    folder = tmp_path / "after"
    _keep_old_record(tmp_path, folder, "A-night")
    _prompt_closing(root, folder, commit, "prompts/night.md")
    (folder / "zz.json").write_text(json.dumps(_other_content(tmp_path)), encoding="utf-8")
    document = _retest(root, first, folder)
    assert [r["id"] for r in document["machine"]["previous"]] == ["A-night"]
    assert [r["id"] for r in document["machine"]["rejected"]] == ["A-night"]


# ---------------------------------------------------------------------------
# 12. The message
# ---------------------------------------------------------------------------


def test_a_superseding_closing_without_the_old_record_file_says_what_to_do(tmp_path: Path) -> None:
    root, first = _night_tree(tmp_path, _night_step())
    (root / "prompts/night.md").unlink()
    _put(root, "prompts/hours.md", CLEANED)
    commit = _commit(root)
    folder = tmp_path / "after"
    _prompt_closing(root, folder, commit, "prompts/hours.md", supersedes=["A-night"])
    _unit_closing(root, folder, commit)
    document = _retest(root, first, folder)
    (rejected,) = document["machine"]["rejected"]
    assert any("keep its record file in this folder" in e for e in rejected["errors"])
    _stands(document)


# ---------------------------------------------------------------------------
# The reverse: a real fix still reaches `remediated`, end to end
# ---------------------------------------------------------------------------


def test_a_fix_in_place_is_shown(tmp_path: Path) -> None:
    root, first = _night_tree(tmp_path, _night_step())
    _put(root, "prompts/night.md", CLEANED)
    commit = _commit(root)
    folder = tmp_path / "after"
    _prompt_closing(root, folder, commit, "prompts/night.md")
    _unit_closing(root, folder, commit)
    _shown(_retest(root, first, folder))


@pytest.mark.parametrize("step", [_night_step(), dict(REINVESTIGATE_STEP)], ids=["absent", "note"])
def test_a_rename_and_a_fix_with_supersedes_are_shown(tmp_path: Path, step: dict) -> None:
    root, first = _night_tree(tmp_path, step)
    (root / "prompts/night.md").unlink()
    _put(root, "prompts/hours.md", CLEANED)
    commit = _commit(root)
    folder = tmp_path / "after"
    _keep_old_record(tmp_path, folder, "A-night")
    _prompt_closing(root, folder, commit, "prompts/hours.md", supersedes=["A-night"])
    _unit_closing(root, folder, commit)
    _shown(_retest(root, first, folder))


def test_a_deleted_file_with_supersedes_is_shown(tmp_path: Path) -> None:
    root, first = _night_tree(tmp_path, _night_step())
    (root / "prompts/night.md").unlink()
    commit = _commit(root)
    folder = tmp_path / "after"
    _keep_old_record(tmp_path, folder, "A-night")
    _prompt_closing(root, folder, commit, "app.py", 7, id="C-del", supersedes=["A-night"])
    _unit_closing(root, folder, commit)
    _shown(_retest(root, first, folder))


def test_a_carried_chain_is_shown(tmp_path: Path) -> None:
    root, first = _night_tree(tmp_path, _night_step())
    second = _saved(_retest(root, first, _touch(root, tmp_path, "b")), tmp_path / "b.json")
    _put(root, "prompts/night.md", CLEANED)
    commit = _commit(root)
    folder = tmp_path / "c"
    _prompt_closing(root, folder, commit, "prompts/night.md")
    _unit_closing(root, folder, commit)
    _shown(_retest(root, second, folder))


def test_a_chain_with_two_renames_is_shown(tmp_path: Path) -> None:
    root, first = _night_tree(tmp_path, _night_step())
    (root / "prompts/night.md").rename(root / "prompts/n2.md")
    commit = _commit(root)
    second = _retest(root, first, _with_other(root, tmp_path, commit, "b"))
    # The step reads the rename target, which still holds the line.
    assert _row(second, "A-night")["status"] == "not_remediated"
    saved = _saved(second, tmp_path / "b.json")
    (root / "prompts/n2.md").unlink()
    _put(root, "prompts/n3.md", CLEANED)
    commit = _commit(root)
    folder = tmp_path / "c"
    _keep_old_record(tmp_path, folder, "A-night")
    _prompt_closing(root, folder, commit, "prompts/n3.md", supersedes=["A-night"])
    _unit_closing(root, folder, commit)
    _shown(_retest(root, saved, folder))


def test_git_names_a_rename_and_a_rename_that_changed_nothing(tmp_path: Path) -> None:
    root, commit = _bakery(
        tmp_path,
        {
            "prompts/a b.md": "One line of text that stays as it is.\n",
            "prompts/c.md": "Another line of text.\nA second line.\nA third line.\n",
        },
    )
    _git(root, "mv", "prompts/a b.md", "prompts/d e.md")
    _git(root, "mv", "prompts/c.md", "prompts/f.md")
    _put(root, "prompts/f.md", "Another line of text.\nA second line.\nA third, now.\n")
    _commit(root)
    changes = assess._changed_files(machine_scan(root), commit)
    assert changes is not None
    assert changes.renames == {"prompts/a b.md": "prompts/d e.md", "prompts/c.md": "prompts/f.md"}
    assert changes.moved_only == {"prompts/a b.md", "prompts/d e.md"}
    assert not changes.text_of(["prompts/a b.md", "prompts/d e.md", "absent.md"])
    assert changes.text_of(["prompts/f.md"])
