"""tests/unit/test_unread_outside_git.py
--------------------------------------
Outside git nothing lists what the walk skipped, so the walk says it itself. A file it
stepped over is named; a directory it pruned is named and never walked; caches, which hold
nothing a person wrote, do not count. Each of them blocks an outcome the way a tracked file
the walk skipped does in git, and a tree in git reads as it did. `aisafe fleet` refuses
Python 3.10, where a package of the clone could stand in for the auditor.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from investigation_helpers import copy_tree, write_record
from test_fixes2_outcome import (
    COMPANION,
    COMPANION_PROMPT,
    NO_VIOLATION,
    _closing,
    _git,
    _mechanism,
    _review_row,
)
from test_fixes_outcome import _m, _run

from aisafe.assessment.assess import run_assessment
from aisafe.assessment.render import render_html, render_markdown, render_terminal
from aisafe.audit import AuditOptions, scan
from aisafe.devtools import fleet
from aisafe.discovery import walk
from aisafe.discovery.patterns import IGNORE_MARKER
from aisafe.investigation.plan import build_plan, render_plan
from aisafe.investigation.scan import machine_scan
from aisafe.policy import load_policy

VENDORED = {"vendor/companion.py": COMPANION, "vendor/prompt.md": COMPANION_PROMPT}
MARKED = {"prompts/companion.md": f"{IGNORE_MARKER}\n{COMPANION_PROMPT}"}
CACHES = {
    "__pycache__/assistant.cpython-313.pyc": b"\x00\x01compiled",
    ".pytest_cache/v/cache/lastfailed": "{}\n",
    ".ruff_cache/0.5/1234": b"\x00cache",
    ".mypy_cache/3.13/assistant.meta.json": "{}\n",
    "pkg/__pycache__/helper.pyc": b"\x00\x01compiled",
}


def _write(root: Path, files: dict[str, str | bytes]) -> None:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))


def _assess(root: Path, tmp_path: Path, commit: str | None) -> dict[str, Any]:
    plan = build_plan(machine_scan(root))
    records = tmp_path / "records"
    write_record(records, _closing(root, plan, commit=commit), skeptic="upheld")
    run = run_assessment(root, [records])
    assert run.document is not None, (run.fatal, [r.errors for r in run.records or []])
    return run.document


def _outside(tmp_path: Path, files: dict[str, str | bytes]) -> dict[str, Any]:
    """The closing of M2 on the writing assistant, on a tree that is no git repository."""
    root = copy_tree("benign_lookalike", tmp_path)
    _write(root, files)
    return _assess(root, tmp_path, None)


def _inside(
    tmp_path: Path,
    files: dict[str, str | bytes],
    after: dict[str, str | bytes] | None = None,
) -> dict[str, Any]:
    """The same closing at a commit that holds `files`; `after` lands outside the commit."""
    root = copy_tree("benign_lookalike", tmp_path)
    _write(root, files)
    _git(root, "init", "-q")
    _git(root, "add", "-A", "-f")
    _git(root, "commit", "-q", "-m", "c")
    _write(root, after or {})
    return _assess(root, tmp_path, _git(root, "rev-parse", "HEAD").strip())


def _blocked(doc: dict[str, Any], *named: str) -> str:
    """M2 and M4 are inconclusive on the unread-files gap; its text, which names `named`."""
    detail = ""
    for mid in ("M2", "M4"):
        mechanism = _mechanism(doc, mid)
        assert mechanism["outcome"] == "inconclusive", mechanism
        assert mechanism["gaps"][0]["kind"] == "files_not_read"
        detail = mechanism["gaps"][0]["detail"]
        for name in named:
            assert name in detail
    assert doc["outcome"]["overall"] == "inconclusive"
    return detail


# ---------------------------------------------------------------------------
# The two holes
# ---------------------------------------------------------------------------


def test_code_under_a_skipped_directory_blocks_outside_git(tmp_path: Path) -> None:
    doc = _outside(tmp_path, VENDORED)
    detail = _blocked(doc, "vendor/")
    assert "committing the tree gives a precise list" in detail
    # The directory is named; the walk never went in.
    assert doc["scope"]["unassessed"]["dirs_not_walked"] == ["vendor"]
    assert doc["scope"]["unassessed"]["tracked_not_walked"] == []


def test_a_file_under_the_marker_blocks_outside_git(tmp_path: Path) -> None:
    doc = _outside(tmp_path, MARKED)
    _blocked(doc, "prompts/companion.md")
    assert doc["scope"]["unassessed"]["tracked_not_walked"] == ["prompts/companion.md"]


@pytest.mark.parametrize(
    ("files", "named"),
    [
        (VENDORED, "vendor/"),
        ({"node_modules/left-pad/index.js": "module.exports = 1;\n"}, "node_modules/"),
        ({"build/app.py": COMPANION}, "build/"),
        ({"dist/app.py": COMPANION}, "dist/"),
        (
            {".gitignore": "generated/\n", "generated/app.py": COMPANION},
            "generated/",
        ),
        (
            {".gitignore": "extra_prompt.md\n", "extra_prompt.md": COMPANION_PROMPT},
            "extra_prompt.md",
        ),
    ],
    ids=["vendor", "node_modules", "build", "dist", "gitignored directory", "gitignored file"],
)
def test_what_the_walk_skipped_blocks_outside_git(
    tmp_path: Path, files: dict[str, str | bytes], named: str
) -> None:
    _blocked(_outside(tmp_path, files), named)


def test_the_same_tree_reads_the_same_way_in_git(tmp_path: Path) -> None:
    (tmp_path / "out").mkdir()
    (tmp_path / "in").mkdir()
    outside = _outside(tmp_path / "out", VENDORED)
    inside = _inside(tmp_path / "in", VENDORED)
    for mid in ("M2", "M4"):
        assert _mechanism(outside, mid)["outcome"] == _mechanism(inside, mid)["outcome"]


def test_the_gap_shows_in_every_report_format(tmp_path: Path) -> None:
    doc = _outside(tmp_path, VENDORED)
    for text in (render_markdown(doc), render_html(doc), render_terminal(doc)):
        assert r"gap (files\_not\_read)" in text or "gap (files_not_read)" in text
        assert "vendor/" in text and "precise list" in text
    assert "precise list" in json.dumps(doc)
    assert "1 director(ies) it did not go into" in render_markdown(doc)


def test_the_plan_names_what_the_walk_skipped(tmp_path: Path) -> None:
    root = copy_tree("benign_lookalike", tmp_path)
    _write(root, {**VENDORED, **MARKED})
    plan = build_plan(machine_scan(root))
    assert plan["not_read"]["dirs_not_walked"] == ["vendor"]
    assert plan["not_read"]["tracked_not_walked"] == ["prompts/companion.md"]
    summary = render_plan(plan)
    assert "vendor/" in summary and "prompts/companion.md" in summary
    assert "1 tracked" not in summary


def test_a_skipped_directory_stops_m8_closing() -> None:
    m1 = _m(_run(dirs_not_walked=["vendor"]), "M1")
    assert [g.kind for g in m1.gaps] == ["files_not_read"]
    m8 = _m(_run(review_records=[_review_row("app.py")], dirs_not_walked=["vendor"]), "M8")
    assert m8.outcome == "inconclusive" and [g.kind for g in m8.gaps] == ["files_not_read"]


# ---------------------------------------------------------------------------
# Every other way the walk leaves a file unread
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rel", "content"),
    [
        ("big_prompt.md", b"x" * (walk.DEFAULT_MAX_SIZE + 1)),
        ("wide_prompt.md", "﻿You are Leo.\n".encode("utf-16")),
        ("blob.bin", b"\x00\x01\x02"),
    ],
    ids=["oversize", "utf-16", "binary"],
)
def test_a_file_the_walk_could_not_read_is_named(tmp_path: Path, rel: str, content: bytes) -> None:
    root = copy_tree("benign_lookalike", tmp_path)
    _write(root, {rel: content})
    assert rel in machine_scan(root).tracked_not_walked


def test_a_symlink_the_walk_did_not_follow_is_named(tmp_path: Path) -> None:
    root = copy_tree("benign_lookalike", tmp_path)
    target = tmp_path / "elsewhere"
    target.mkdir()
    (target / "prompt.md").write_text(COMPANION_PROMPT, encoding="utf-8")
    try:
        (root / "linked").symlink_to(target, target_is_directory=True)
        (root / "linked.md").symlink_to(target / "prompt.md")
    except OSError:
        pytest.skip("this system does not let the test create a symlink")
    assert {"linked", "linked.md"} <= set(machine_scan(root).tracked_not_walked)


def test_a_directory_that_could_not_be_listed_is_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "tree"
    (root / "locked").mkdir(parents=True)
    real = os.scandir

    def scandir(path: Any) -> Any:
        if Path(path).name == "locked":
            raise PermissionError(13, "denied", str(path))
        return real(path)

    monkeypatch.setattr(os, "scandir", scandir)
    dirs: list[str] = []
    walk.walk(root, unread_dirs=dirs)
    assert dirs == ["locked"]


def test_pictures_outside_git_do_not_block(tmp_path: Path) -> None:
    doc = _outside(tmp_path, {"static/logo.png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"})
    assert doc["scope"]["unassessed"]["tracked_not_walked"] == ["static/logo.png"]
    assert _mechanism(doc, "M2")["outcome"] == NO_VIOLATION


# ---------------------------------------------------------------------------
# Caches, and directories named without being walked
# ---------------------------------------------------------------------------


def test_caches_do_not_block(tmp_path: Path) -> None:
    doc = _outside(tmp_path, CACHES)
    assert doc["scope"]["unassessed"]["dirs_not_walked"] == []
    assert doc["scope"]["unassessed"]["tracked_not_walked"] == []
    m2 = _mechanism(doc, "M2")
    assert m2["outcome"] == NO_VIOLATION and m2["gaps"] == []


def test_a_cache_hidden_by_a_gitignore_line_does_not_block(tmp_path: Path) -> None:
    files = {".gitignore": ".hypothesis/\n", ".hypothesis/examples/a": "x\n"}
    assert _mechanism(_outside(tmp_path, files), "M2")["outcome"] == NO_VIOLATION


def test_a_skipped_directory_is_named_once_and_never_walked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "tree"
    _write(root, {"app.py": "x = 1\n", "node_modules/a/b/c/index.js": "x;\n"})
    seen: list[str] = []
    real = os.scandir

    def scandir(path: Any) -> Any:
        seen.append(Path(path).as_posix())
        return real(path)

    monkeypatch.setattr(os, "scandir", scandir)
    dirs: list[str] = []
    files: list[str] = []
    walk.walk(root, unread_dirs=dirs, unread_files=files)
    assert dirs == ["node_modules"] and files == []
    assert not [path for path in seen if "node_modules" in path]


def test_a_long_list_of_directories_is_cut_and_counted() -> None:
    names = [f"pkg{n:02}/vendor" for n in range(30)]
    detail = _m(_run(dirs_not_walked=names), "M1").gaps[0].detail
    assert "30 " in detail and "pkg00/vendor/" in detail and "pkg29/vendor/" not in detail


# ---------------------------------------------------------------------------
# Trees in git, and repositories with no commit
# ---------------------------------------------------------------------------


def test_nothing_changes_in_git(tmp_path: Path) -> None:
    doc = _inside(tmp_path, {})
    assert _mechanism(doc, "M2")["outcome"] == NO_VIOLATION and _mechanism(doc, "M2")["gaps"] == []
    assert doc["scope"]["unassessed"]["dirs_not_walked"] == []


def test_in_git_a_tracked_file_is_named_and_the_text_stays_as_it_was(tmp_path: Path) -> None:
    doc = _inside(tmp_path, VENDORED)
    detail = _blocked(doc, "vendor/companion.py", "vendor/prompt.md")
    assert "committing" not in detail
    assert doc["scope"]["unassessed"]["dirs_not_walked"] == []
    assert "2 tracked file(s) the walk skipped" in render_terminal(doc)


def test_in_git_what_is_outside_the_commit_does_not_block(tmp_path: Path) -> None:
    doc = _inside(
        tmp_path,
        {".gitignore": "node_modules/\ngenerated/\n"},
        after={"node_modules/left-pad/index.js": "x;\n", "generated/app.py": "x = 1\n"},
    )
    assert _mechanism(doc, "M2")["outcome"] == NO_VIOLATION


def test_a_repository_with_no_commit_is_outside_git(tmp_path: Path) -> None:
    root = copy_tree("benign_lookalike", tmp_path)
    _write(root, {**VENDORED, **MARKED})
    _git(root, "init", "-q")
    machine = machine_scan(root)
    assert machine.state.is_git is False
    assert machine.dirs_not_walked == ["vendor"]
    assert machine.tracked_not_walked == ["prompts/companion.md"]


def test_a_list_git_could_not_give_stays_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = copy_tree("benign_lookalike", tmp_path)
    _write(root, VENDORED)
    _git(root, "init", "-q")
    _git(root, "add", "-A", "-f")
    _git(root, "commit", "-q", "-m", "c")
    monkeypatch.setattr(walk, "git_tree", lambda *a, **k: walk.GitTree(tracked=None))
    machine = machine_scan(root)
    assert machine.tracked_not_walked is None and machine.dirs_not_walked == []


@pytest.mark.parametrize("in_git", [False, True], ids=["outside git", "in git"])
def test_the_default_audit_says_nothing_new(tmp_path: Path, in_git: bool) -> None:
    root = copy_tree("benign_lookalike", tmp_path)
    _write(root, VENDORED)
    if in_git:
        _git(root, "init", "-q")
        _git(root, "add", "-A", "-f")
        _git(root, "commit", "-q", "-m", "c")
    ctx, *_ = scan(AuditOptions(path=str(root)), load_policy())
    assert ctx.unread_dirs == ["vendor"]
    inventory = json.dumps(ctx.inventory.to_dict(), default=str)
    assert "unread_dirs" not in inventory and "dirs_not_walked" not in inventory


# ---------------------------------------------------------------------------
# aisafe fleet needs Python 3.11
# ---------------------------------------------------------------------------


def _no_process(*_args: Any, **_kwargs: Any) -> None:
    raise AssertionError("the fleet started a process")


def test_fleet_refuses_a_python_that_cannot_keep_the_clone_off_the_import_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(fleet, "_safe_path_works", lambda: False)
    monkeypatch.setattr(fleet.subprocess, "run", _no_process)
    monkeypatch.setattr(fleet, "run_one", _no_process)
    listing = tmp_path / "fleet.yaml"
    listing.write_text(
        "repos:\n  - name: one\n    url: https://example.invalid/one.git\n", encoding="utf-8"
    )
    assert fleet.main([str(listing), "--out", "out"]) == fleet.EXIT_FATAL
    err = capsys.readouterr().err
    assert "Python 3.11" in err and "PYTHONSAFEPATH" in err and "aisafe" in err
    assert not (tmp_path / "out").exists()


def test_fleet_refuses_before_it_reads_the_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(fleet, "_safe_path_works", lambda: False)
    assert fleet.main(["missing.yaml"]) == fleet.EXIT_FATAL
    assert "Python 3.11" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("version", "works"), [((3, 10, 14), False), ((3, 11, 0), True), ((3, 13, 1), True)]
)
def test_the_version_check_reads_the_running_python(
    monkeypatch: pytest.MonkeyPatch, version: tuple[int, int, int], works: bool
) -> None:
    monkeypatch.setattr(fleet.sys, "version_info", version)
    assert fleet._safe_path_works() is works
