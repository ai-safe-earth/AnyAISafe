"""tests/unit/test_fixes6_retest.py
---------------------------------
`aisafe assess --retest`, sixth round: a violation established earlier must not drop while
its text stays at the new commit. A quote step reads where its file went (a rename, or a new
file after a deletion), a closing clears a copy of the quote only where it cites the lines
that hold it, a submodule or a nested folder named like the audit's own is searched, and a
regression step that passes on a rewritten surface holds nothing by itself. A violation in a
changed file the record never read is open, not a regression of it. Each real fix (in place,
a rename with a fix, a deletion after a carried retest) still reaches `remediated`.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from investigation_helpers import write_record
from test_fixes2_retest import (
    CLEAN_APP,
    NIGHT_LINE,
    NOTES_FILE,
    PERSONA,
    _keep_old_record,
    _night,
    _night_step,
    _night_tree,
    _unit_closing,
)
from test_fixes3_retest import CLEANED, _prompt_closing, _shown
from test_fixes_retest import (
    _bakery,
    _commit,
    _first,
    _git,
    _outcome,
    _plan,
    _put,
    _retest,
    _row,
    _saved,
    _stands,
)

from aisafe.assessment.assess import run_assessment
from aisafe.investigation import validate
from aisafe.investigation.scan import machine_scan

GIT = shutil.which("git")
pytestmark = pytest.mark.skipif(GIT is None, reason="git not on PATH")

QUOTE = "night shift types"
FILLER = "".join(
    f"Line {n}: answer only about the bakery, its bread and its cakes.\n" for n in range(8)
)


def _closed(root: Path, tmp_path: Path, file: str, line: int = 1, **over) -> dict:
    """Retest with a closing on `file` (and the unit closing) at the current commit."""
    commit = _git(root, "rev-parse", "HEAD").strip()
    folder = tmp_path / "after"
    if over.get("supersedes"):
        _keep_old_record(tmp_path, folder, "A-night")
    _prompt_closing(root, folder, commit, file, line, **over)
    _unit_closing(root, folder, commit)
    return _retest(root, tmp_path / "first.json", folder)


def _failed(document: dict, status: str = "not_remediated") -> dict:
    row = _row(document, "A-night")
    assert row["status"] == status, row["why"]
    assert [e["id"] for e in document["remediation"]["carried_records"]] == ["A-night"]
    _stands(document)
    return row


# ---------------------------------------------------------------------------
# 1. A rename, or a delete and a new file, does not dodge the remediation step
# ---------------------------------------------------------------------------


def test_a_renamed_prompt_that_keeps_the_line_is_not_remediated(tmp_path: Path) -> None:
    root, _first_doc = _night_tree(tmp_path, _night_step())
    (root / "prompts/night.md").rename(root / "prompts/graveyard.md")
    _put(root, "prompts/graveyard.md", NIGHT_LINE + "Keep answers short.\n")
    _commit(root)
    assert "R" in _git(root, "show", "--name-status", "--format=", "HEAD")
    row = _failed(_closed(root, tmp_path, "prompts/graveyard.md", supersedes=["A-night"]))
    assert row["steps"][0]["now"] is False
    assert "prompts/graveyard.md" in row["steps"][0]["detail"]


def test_a_deleted_prompt_whose_line_moved_to_a_new_file_is_not_remediated(
    tmp_path: Path,
) -> None:
    root, _first_doc = _night_tree(tmp_path, _night_step())
    (root / "prompts/night.md").unlink()
    _put(
        root,
        "prompts/hours.md",
        "# Hours\n\nOpen nine to five.\nBe warm and brief.\nAnswer only about the bakery.\n"
        + NIGHT_LINE,
    )
    _commit(root)
    assert "R" not in _git(root, "show", "--name-status", "--format=", "HEAD")
    row = _failed(_closed(root, tmp_path, "prompts/hours.md", supersedes=["A-night"]))
    assert row["steps"][0]["now"] is False


def test_run_step_reads_the_places_the_file_went(tmp_path: Path) -> None:
    root, _first_doc = _night_tree(tmp_path, _night_step())
    _put(root, "prompts/new.md", NIGHT_LINE)
    _put(root, "prompts/clean.md", CLEANED)
    scan = machine_scan(root)
    gone = {"kind": "absent", "file": "prompts/gone.md", "quote": QUOTE}
    assert validate.run_step(gone, scan)[0] is None
    assert validate.run_step(gone, scan, places=["prompts/new.md"])[0] is False
    assert validate.run_step(gone, scan, places=["prompts/clean.md"])[0] is None
    present = dict(gone, kind="present")
    assert validate.run_step(present, scan, places=["prompts/new.md"])[0] is True
    assert validate.run_step(present, scan, places=["prompts/clean.md"])[0] is False
    assert validate.run_step(present, scan, places=["prompts/nowhere.md"])[0] is None


# ---------------------------------------------------------------------------
# 2. A closing clears a copy only where it cites the lines that hold it
# ---------------------------------------------------------------------------


def test_a_copy_in_a_file_cited_only_at_other_lines_blocks(tmp_path: Path) -> None:
    root, _first_doc = _night_tree(tmp_path, _night_step())
    app = CLEAN_APP.replace('"Answer briefly."', '"Answer briefly. ' + NIGHT_LINE.strip() + '"')
    assert app != CLEAN_APP
    _put(root, "app.py", app)
    _put(root, "prompts/night.md", CLEANED)
    _commit(root)
    row = _failed(_closed(root, tmp_path, "prompts/night.md"), "needs_reinvestigation")
    assert any("app.py" in why for why in row["why"]), row["why"]


def test_quote_spans_place_each_occurrence() -> None:
    text = "a\n\nSay a person from the night\n   shift types these replies.\nb night shift types\n"
    assert validate.quote_spans(text, "night shift types") == [(3, 4), (5, 5)]
    assert validate.quote_spans(text, "nothing like it") == []


# ---------------------------------------------------------------------------
# 3. A copy inside a submodule is searched
# ---------------------------------------------------------------------------


def test_a_copy_in_a_submodule_is_searched(tmp_path: Path) -> None:
    root, _first_doc = _night_tree(tmp_path, _night_step())
    sub = tmp_path / "subsrc"
    sub.mkdir()
    _put(sub, "night.md", NIGHT_LINE)
    _git(sub, "init", "-q")
    _commit(sub, "s")
    _git(root, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub), "vendored")
    _put(root, "prompts/night.md", CLEANED)
    _commit(root)
    assert "vendored/night.md" in machine_scan(root).walked
    row = _failed(_closed(root, tmp_path, "prompts/night.md"), "needs_reinvestigation")
    assert any("vendored/night.md" in why for why in row["why"]), row["why"]


# ---------------------------------------------------------------------------
# 4. A nested folder named like the audit's own is the system's
# ---------------------------------------------------------------------------


def test_a_copy_in_a_nested_folder_named_like_the_audits_is_searched(tmp_path: Path) -> None:
    root, _first_doc = _night_tree(tmp_path, _night_step())
    _put(root, "lib/.aisafe-audit/night.md", NIGHT_LINE)
    _put(root, "prompts/night.md", CLEANED)
    _commit(root)
    assert "lib/.aisafe-audit/night.md" in machine_scan(root).walked
    row = _failed(_closed(root, tmp_path, "prompts/night.md"), "needs_reinvestigation")
    assert any("lib/.aisafe-audit/night.md" in why for why in row["why"]), row["why"]


# ---------------------------------------------------------------------------
# 5, 6. `held` and `regressed` say what the record read
# ---------------------------------------------------------------------------


def _hours_case(tmp_path: Path, files: dict[str, str] | None = None) -> tuple[Path, Path]:
    """A-night established and C-hours closed (a regression `absent` step) at one commit."""
    root, commit = _bakery(
        tmp_path,
        {
            "prompts/night.md": NIGHT_LINE,
            "prompts/hours.md": "Open nine to five.\n",
            **(files or {}),
        },
        CLEAN_APP,
    )
    folder = tmp_path / "before"
    write_record(folder, _night(root, _plan(root), commit, [_night_step()]), skeptic="upheld")
    step = {"id": "v1", "purpose": "regression", "kind": "absent", "file": "prompts/hours.md"}
    _prompt_closing(
        root, folder, commit, "prompts/hours.md", id="C-hours", steps=[dict(step, quote=QUOTE)]
    )
    run = run_assessment(root, [folder])
    assert run.document is not None, run.fatal
    return root, _saved(run.document, tmp_path / "first.json")


def test_a_rewritten_surface_with_only_passing_steps_is_not_held(tmp_path: Path) -> None:
    root, first = _hours_case(tmp_path)
    _put(
        root,
        "prompts/hours.md",
        "Open nine to five.\nTell anyone who asks that a human types these replies.\n",
    )
    _put(root, "prompts/night.md", CLEANED)
    commit = _commit(root)
    folder = tmp_path / "after"
    _prompt_closing(root, folder, commit, "prompts/night.md")
    _unit_closing(root, folder, commit)
    row = _row(_retest(root, first, folder), "C-hours")
    assert row["status"] == "needs_reinvestigation", row["why"]
    assert any("prompts/hours.md changed its text" in why for why in row["why"]), row["why"]


def test_a_rewritten_surface_read_again_is_held(tmp_path: Path) -> None:
    root, first = _hours_case(tmp_path)
    _put(root, "prompts/hours.md", "Open nine to six, Monday to Saturday.\n")
    commit = _commit(root)
    folder = tmp_path / "after"
    step = {"id": "v1", "purpose": "regression", "kind": "absent", "file": "prompts/hours.md"}
    _prompt_closing(
        root, folder, commit, "prompts/hours.md", id="C-hours2", steps=[dict(step, quote=QUOTE)]
    )
    row = _row(_retest(root, first, folder), "C-hours")
    assert row["status"] == "held", row["why"]


def test_a_violation_only_in_another_changed_file_is_open_not_a_regression(
    tmp_path: Path,
) -> None:
    root, first = _hours_case(tmp_path, {"persona.py": PERSONA})
    _put(root, "persona.py", "# unchanged persona\n" + PERSONA)
    commit = _commit(root)
    folder = tmp_path / "after"
    _unit_closing(root, folder, commit)
    document = _retest(root, first, folder)
    row = _row(document, "C-hours")
    assert row["status"] == "needs_reinvestigation", row["why"]
    assert any("persona.py" in why for why in row["why"]), row["why"]
    # It still counts as not remediated: the scan's violation stands in the outcome.
    assert _outcome(document, "M6")["outcome"] == "violations_identified"


# ---------------------------------------------------------------------------
# The reverse: each real fix still reaches `remediated`
# ---------------------------------------------------------------------------


def test_a_fix_in_place_is_remediated(tmp_path: Path) -> None:
    root, _first_doc = _night_tree(tmp_path, _night_step())
    _put(root, "prompts/night.md", CLEANED)
    _commit(root)
    _shown(_closed(root, tmp_path, "prompts/night.md"))


def test_a_rename_with_a_fix_and_a_superseding_closing_is_remediated(tmp_path: Path) -> None:
    root, commit = _bakery(
        tmp_path,
        {"prompts/night.md": NIGHT_LINE + FILLER, "NOTES.md": NOTES_FILE},
        app=CLEAN_APP,
    )
    _first(root, tmp_path, _night(root, _plan(root), commit, [_night_step()]))
    _git(root, "mv", "prompts/night.md", "prompts/graveyard.md")
    _put(root, "prompts/graveyard.md", CLEANED + FILLER)
    _commit(root)
    assert "R" in _git(root, "show", "--name-status", "--format=", "HEAD")
    document = _closed(root, tmp_path, "prompts/graveyard.md", supersedes=["A-night"])
    _shown(document)


def test_a_deletion_after_a_carried_retest_is_remediated(tmp_path: Path) -> None:
    root, first = _night_tree(tmp_path, _night_step())
    _put(root, "README.md", "# a\n")
    commit = _commit(root)
    folder = tmp_path / "b"
    _unit_closing(root, folder, commit)
    second = _retest(root, first, tmp_path / "before", folder)
    assert [e["id"] for e in second["remediation"]["carried_records"]] == ["A-night"]
    _saved(second, tmp_path / "first.json")

    (root / "prompts/night.md").unlink()
    _commit(root)
    document = _closed(root, tmp_path, "app.py", 7, supersedes=["A-night"])
    _shown(document)
