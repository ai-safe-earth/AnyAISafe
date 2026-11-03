"""tests/unit/test_fixes6_scan.py
------------------------------
Two ways a repository still made the audit open a path on another machine, and the checks
that close them. A quoted object alternate is C-unquoted by git (`\\057` is `/`), so the
check reads it decoded. A submodule's or a nested repository's `.git` is opened by the
parent's `git status` before any check inside it, so the parent looks first. No test needs
a network: the host is `host.invalid`, and git is patched to fail if it starts where it
must not. Controls show plain git decodes the same way, and that ordinary trees still audit.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest
from test_fixes2_scan import NOT_LISTED, _bot, _commit, _git, _rows

from aisafe.discovery import walk

pytestmark = pytest.mark.skipif(walk.git_program() is None, reason="git not on PATH")

ALTERNATES = ".git/objects/info/alternates"
NESTED = "tree state not compared"
HOST = "//host.invalid/share"


def _files(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode("latin-1"))


def _no_git_starts(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError(f"git started: {args}")

    monkeypatch.setattr(walk.subprocess, "run", refuse)


def _no_git_in(monkeypatch: pytest.MonkeyPatch, *, refused: Path) -> list[list[str]]:
    """git runs, but never `git status` and never inside `refused`."""
    real = subprocess.run
    started: list[list[str]] = []

    def guarded(args: list[str], *rest: Any, **kwargs: Any) -> Any:
        command = list(args[len(walk.GIT_SAFE) + 1 :])
        if "status" in command or Path(kwargs.get("cwd", "")) == refused:
            raise AssertionError(f"git started: {command} in {kwargs.get('cwd')}")
        started.append(command)
        return real(args, *rest, **kwargs)

    monkeypatch.setattr(walk.subprocess, "run", guarded)
    return started


# ---------------------------------------------------------------------------
# A quoted object alternate
# ---------------------------------------------------------------------------

QUOTED = {
    "octal slashes": '"\\057\\057host.invalid/share/objects"\n',
    "octal backslashes": '"\\134\\134host.invalid\\134share\\134objects"\n',
    "one of each": '"/\\134host.invalid/share/objects"\n',
    "escaped backslashes": '"\\\\\\\\host.invalid\\\\share"\n',
    "after a local entry": "../objects\n" + '"\\057\\057host.invalid/share/objects"\n',
    "after the closing quote": '"x"y//host.invalid/share/objects\n',
    "past its line": '"x\n"\n//host.invalid/share/objects\n',
}


@pytest.mark.parametrize("text", QUOTED.values(), ids=QUOTED.keys())
def test_a_quoted_alternate_on_another_machine_starts_no_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str
) -> None:
    root = _bot(tmp_path)
    _files(root, {ALTERNATES: text})
    assert walk.network_reference(root) == ALTERNATES
    _no_git_starts(monkeypatch)
    assert walk.run_git(["cat-file", "-p", "HEAD"], root) is None
    assert walk.git_meta(root) == (None, None)


@pytest.mark.parametrize(
    "text",
    ['"\\q//host.invalid"\n', '"\\08"\n', '"never closed\n', '"\\057\\0"\n'],
    ids=["unknown escape", "bad octal", "unclosed", "short octal"],
)
def test_a_quoted_alternate_that_does_not_decode_counts_as_a_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str
) -> None:
    root = _bot(tmp_path)
    _files(root, {ALTERNATES: text})
    assert walk.network_reference(root) == ALTERNATES
    _no_git_starts(monkeypatch)
    assert walk.run_git(["rev-parse", "HEAD"], root) is None


def test_a_quoted_local_alternate_is_ordinary_and_git_decodes_it_the_same(
    tmp_path: Path,
) -> None:
    """Control: git reads the commit through an alternate spelled with octal escapes, so
    the decoding above is git's. `\\057` stands for every `/` of the local path."""
    source = _bot(tmp_path)
    clone = tmp_path / "clone"
    _git(tmp_path, "clone", "-q", "--shared", str(source), str(clone))
    objects = (source / ".git" / "objects").as_posix().replace("/", "\\057")
    _files(clone, {ALTERNATES: f'"{objects}"\n'})
    for pack in (clone / ".git" / "objects").rglob("*"):
        assert pack.is_dir() or pack.parent.name in ("info", "pack")
    assert walk.network_reference(clone) is None
    assert walk.run_git(["cat-file", "-t", "HEAD"], clone) == b"commit\n"
    # git skips the one character after a closing quote and reads on from there.
    plain = (source / ".git" / "objects").as_posix()
    _files(clone, {ALTERNATES: f'"{tmp_path.as_posix()}/none";{plain}\n'})
    assert walk.network_reference(clone) is None
    assert walk.run_git(["cat-file", "-t", "HEAD"], clone) == b"commit\n"
    _files(clone, {ALTERNATES: '"\\057\\057host.invalid/share/objects"\n'})
    assert walk.network_reference(clone) == ALTERNATES


def test_an_alternate_in_quotes_is_followed_to_the_next_alternates_file(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    second = tmp_path / "sec ond"
    _files(second, {"info/alternates": '"\\057\\057host.invalid/share/objects"\n'})
    _files(root, {ALTERNATES: '"' + second.as_posix().replace(" ", "\\040") + '"\n'})
    assert walk.network_reference(root) == "alternates"


# ---------------------------------------------------------------------------
# Configuration values, decoded as git decodes them
# ---------------------------------------------------------------------------


def test_an_include_quoted_around_a_comment_sign_is_followed(tmp_path: Path) -> None:
    """The coarse read cut `"inc;x.cfg"` at the `;` and looked for a file `inc`."""
    root = _bot(tmp_path)
    _files(root, {".git/inc;x.cfg": f"[core]\n\tworktree = {HOST}/x\n"})
    with open(root / ".git" / "config", "a", encoding="utf-8", newline="\n") as handle:
        handle.write('[include]\n\tpath = "inc;x.cfg" ; a comment\n')
    assert walk.network_reference(root) == ".git/inc;x.cfg"


def test_a_configuration_git_rejects_counts_as_naming_a_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """git stops at the bad line, after reading what is above it; nothing here reads past
    it as if it were trusted."""
    root = _bot(tmp_path)
    with open(root / ".git" / "config", "a", encoding="utf-8", newline="\n") as handle:
        handle.write("[core]\n\tattributesFile = C:\\q\n")
    assert walk.network_reference(root) == ".git/config"
    _no_git_starts(monkeypatch)
    assert walk.run_git(["rev-parse", "HEAD"], root) is None


CONFIGS = [
    "[core]\n\tbare = false\n",
    '[include]\n\tpath = "in;c" ; x\n',
    '[a "b\\\\\\"c"] k\n',
    "[s]\nk2 = a\\\n b  \n",
    '[s]\nk = "  lead" tail\t \n',
    '[s]\nk = a\\tb\\\\c\\"d\n',
    "[s]\nk = \\\n   //host/x\n",
    "[s]\r\nk = v\r\n",
    "[s.sub]\nk=v#c\n",
    "[s]\nk = \\q\n",
    '[s]\nk = "open\n',
    "[]\nk=v\n",
    "[s]\n1k = v\n",
    "[s]\nk v\n",
    '[s "x" ]\nk=v\n',
    "\xef\xbb\xbf[s]\nk=v\n",
    "[s]k=v\n[t]\nflag\n",
]


@pytest.mark.parametrize("text", CONFIGS)
def test_the_configuration_reads_as_git_reads_it(text: str) -> None:
    """Control: each key and value as `git config --list` gives them, or a refusal where
    git refuses the file."""
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "c.cfg"
        path.write_bytes(text.encode("latin-1"))
        proc = subprocess.run(
            [str(walk.git_program()), "config", "--file", str(path), "--list", "-z"],
            capture_output=True,
            check=False,
        )
    expected = None
    if proc.returncode == 0:
        expected = []
        for item in proc.stdout.decode("latin-1").split("\0"):
            if item:
                key, newline, value = item.partition("\n")
                expected.append((key.rpartition(".")[2], value if newline else None))
    entries = walk._config_entries(text)
    assert (None if entries is None else [(k, v) for _s, k, v in entries]) == expected


# ---------------------------------------------------------------------------
# A submodule, and a nested repository, on another machine
# ---------------------------------------------------------------------------


def _with_submodule(tmp_path: Path) -> Path:
    inner = tmp_path / "inner"
    inner.mkdir(parents=True)
    (inner / "x.txt").write_text("x\n", encoding="utf-8", newline="\n")
    _git(inner, "init", "-q")
    _commit(inner)
    root = _bot(tmp_path)
    _git(root, "submodule", "--quiet", "add", inner.as_uri(), "sub")
    _commit(root)
    return root


def test_a_submodule_gitdir_on_another_machine_runs_no_git_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _with_submodule(tmp_path)
    (root / "sub" / ".git").unlink()  # hidden on Windows, where it cannot be opened to write
    (root / "sub" / ".git").write_text(f"gitdir: {HOST}/sub\n", encoding="utf-8")
    assert walk.network_reference(root) is None
    assert walk.network_reference(root / "sub") == ".git"
    started = _no_git_in(monkeypatch, refused=root / "sub")
    tree = walk.git_tree(root)
    assert tree.status_failed and tree.network == ["sub/.git"] and "sub" in tree.unlisted
    assert tree.tracked is not None and "sub" not in tree.tracked
    assert started and all(command[0] == "ls-files" for command in started)
    sha, dirty = walk.git_meta(root)
    assert sha and dirty is None
    rows = _rows(root, NOT_LISTED)
    assert len(rows) == 1
    assert "not started in the submodule: sub/.git names a path on another machine" in (rows[0].why)
    assert not _rows(root, NESTED)


def test_a_submodule_reached_through_a_link_to_another_machine_runs_no_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A link on the way is checked before anything opens a path through it."""
    root = _with_submodule(tmp_path)
    link = root / "sub"
    real_is_link, real_target = walk.is_link, walk._link_target
    monkeypatch.setattr(walk, "is_link", lambda p: Path(p) == link or real_is_link(p))
    monkeypatch.setattr(walk, "_link_target", lambda p: HOST if Path(p) == link else real_target(p))
    assert walk._host_in_gitlink(root, "sub") == link
    _no_git_in(monkeypatch, refused=link)
    tree = walk.git_tree(root)
    assert tree.status_failed and tree.network == ["sub"]


def test_a_nested_repository_on_another_machine_runs_no_git_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An untracked folder with a `.git` file: `git status` reads the gitdir it names to
    tell a nested repository from a folder."""
    root = _bot(tmp_path)
    _files(root, {"lib/n/.git": f"gitdir: {HOST}/n\n", "lib/n/f.txt": "y\n"})
    _no_git_in(monkeypatch, refused=root / "lib" / "n")
    tree = walk.git_tree(root)
    assert tree.status_failed and tree.network == ["lib/n/.git"]
    assert tree.unlisted == set()
    sha, dirty = walk.git_meta(root)
    assert sha and dirty is None
    rows = _rows(root, NESTED)
    assert len(rows) == 1 and "lib/n/.git" in rows[0].why
    assert not _rows(root, NOT_LISTED)


def test_a_plain_nested_git_folder_is_ordinary(tmp_path: Path) -> None:
    """Control: plain git sees the nested repository as one folder, and so does the audit;
    the tree reads as dirty, as before."""
    root = _bot(tmp_path)
    nested = root / "lib" / "n"
    nested.mkdir(parents=True)
    (nested / "f.txt").write_text("y\n", encoding="utf-8", newline="\n")
    _git(nested, "init", "-q")
    tree = walk.git_tree(root)
    assert tree.network == [] and not tree.status_failed
    assert "lib/n/" in tree.untracked
    assert not _rows(root, NESTED)


def test_an_ordinary_repository_and_submodule_still_compare(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plain = _bot(tmp_path)
    assert walk.git_tree(plain).network == []
    assert walk.git_meta(plain)[1] is False
    root = _with_submodule(tmp_path / "with")
    tree = walk.git_tree(root)
    assert tree.network == [] and not tree.status_failed and not tree.unlisted
    assert "sub/x.txt" in (tree.tracked or set())
    assert walk.git_meta(root)[1] is False
    assert not _rows(root, NOT_LISTED) and not _rows(root, NESTED)
    (root / "sub" / "x.txt").write_text("changed\n", encoding="utf-8", newline="\n")
    assert "sub/x.txt" in walk.git_tree(root).changed


def test_the_reviewers_alternate_spelling_names_the_host() -> None:
    """The exact line the review used, with no file and no git: the check alone."""
    entries = walk._alternate_entries('"\\057\\057127.0.0.1/c$/x/A/.git/objects"\n')
    assert entries == ["//127.0.0.1/c$/x/A/.git/objects"]
    assert walk._HOST_VALUE_RE.match(entries[0])
