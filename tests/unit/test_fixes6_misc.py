"""tests/unit/test_fixes6_misc.py
-------------------------------
The walk follows no link to learn what it is, a skipped file's name is shown only when it is
safe, and a refusal never repeats the verdict words it refused.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aisafe.assessment.assess import _shown_skip
from aisafe.discovery import walk


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "t"
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "b" / "x.py").write_text("x = 1\n", encoding="utf-8")
    (root / "c.md").write_text("c\n", encoding="utf-8")
    return root


def _listing(rows) -> list[tuple[str, list[str], list[str]]]:
    return sorted((d, sorted(n), sorted(f)) for d, n, f in rows)


def test_the_walk_lists_what_os_walk_lists_on_an_ordinary_tree(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    assert _listing(walk._walk(str(root))) == _listing(os.walk(str(root)))


def test_pruning_dirnames_stops_the_walk_there(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    seen = []
    for dirpath, dirnames, _files in walk._walk(str(root)):
        seen.append(Path(dirpath).name)
        dirnames[:] = [d for d in dirnames if d != "a"]
    assert seen == ["t"]


def test_a_link_to_a_folder_is_listed_with_the_files_and_never_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _tree(tmp_path)
    link = root / "far"
    try:
        os.symlink(str(tmp_path), str(link), target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this machine cannot create a symlink")
    stats: list[str] = []
    real_stat = os.stat

    def spy(path, *args, **kwargs):
        stats.append(os.fspath(path))
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", spy)
    rows = list(walk._walk(str(root)))
    top = next(r for r in rows if Path(r[0]) == root)
    assert "far" in top[2] and "far" not in top[1]
    assert not [s for s in stats if s.endswith("far")]


def test_a_skipped_file_with_a_verdict_or_a_secret_in_its_name_is_not_shown() -> None:
    assert _shown_skip({"path": "records/notes.json", "why": "x"})["path"] == "records/notes.json"
    for name in ("records/the-system-is-certified.json", "records/AKIAIOSFODNN7EXAMPLE.json"):
        assert _shown_skip({"path": name, "why": "x"})["path"] != name
