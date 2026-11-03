"""tests/unit/test_fixes3_scan.py
------------------------------
The audited repository again, and what is left of the ways it could start a program, write
outside itself, reach the network or keep a file out of the report. Each test builds the
small tree that did it; a marker file or a socket proves nothing started, and a control
shows where plain git behaves differently.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from test_fixes2_scan import (
    AUDIT_FIXTURES,
    NOT_LISTED,
    NOT_TEXT,
    OWN_ROW,
    _bot,
    _commit,
    _companion,
    _git,
    _rows,
)

from aisafe import audit
from aisafe.devtools import _git as devgit
from aisafe.devtools import fleet
from aisafe.discovery import discover, patterns, walk
from aisafe.discovery.patterns import OWN_HTML_MARKER_LINE
from aisafe.evidence.model import UnknownCategory
from aisafe.investigation.scan import machine_scan, tree_state

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not on PATH")

REPO = Path(__file__).resolve().parents[2]
UNREAD = "files and folders not read"
LOST = "tracked files not read"
PROMPT = (AUDIT_FIXTURES / "persons_companion" / "prompts" / "companion.md").read_text(
    encoding="utf-8"
)
POINTER = f"version https://git-lfs.github.com/spec/v1\noid sha256:{'a' * 64}\nsize 4096\n"
windows_only = pytest.mark.skipif(os.name != "nt", reason="Windows behaviour")


def _files(root: Path, files: dict[str, str | bytes]) -> None:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))


def _outside_git(tmp_path: Path, name: str = "tree") -> Path:
    """`persons_companion` with its prompt taken away, and no repository around it."""
    root = tmp_path / name
    shutil.copytree(AUDIT_FIXTURES / "persons_companion", root)
    shutil.rmtree(root / "prompts")
    return root


def _scan(root: Path, **options: Any) -> tuple[Any, list[Any], list[Any]]:
    ctx, findings, unknown, _rules = audit.scan(audit.AuditOptions(path=str(root), **options))
    return ctx, findings, unknown


def _ids(root: Path) -> list[str]:
    return sorted(finding.display_id for finding in _scan(root)[1])


def _named(rows: list[Any], name: str) -> bool:
    return any(name in row.why for row in rows)


def _link(link: Path, target: Path) -> None:
    """A junction on Windows, which needs no privilege, and a symlink elsewhere."""
    if os.name == "nt":
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            check=True,
            capture_output=True,
        )
    else:
        link.symlink_to(target, target_is_directory=True)


# ---------------------------------------------------------------------------
# A repository starts a program
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    ["lfs.extension.x.clean", "lfs.storage", "lfs.customtransfer.x.path", "lfs.url"],
)
def test_an_lfs_key_of_the_repository_blanks_the_lfs_driver(tmp_path: Path, key: str) -> None:
    root = _bot(tmp_path)
    _git(root, "config", key, "value")
    args = walk.status_args(root)
    assert args is not None
    assert "filter.lfs.clean=" in args and "filter.lfs.process=" in args


def test_the_lfs_keys_git_lfs_writes_itself_leave_the_driver_alone(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    url = "https://example.invalid/o/r.git/info/lfs"
    _git(root, "config", "lfs.repositoryformatversion", "0")
    _git(root, "config", f"lfs.{url}.access", "basic")
    _git(root, "config", f"lfs.{url}.locksverify", "true")
    args = walk.status_args(root)
    assert args is not None and not [arg for arg in args if arg.startswith("filter.lfs.")]


@pytest.mark.skipif(shutil.which("git-lfs") is None, reason="git-lfs not on PATH")
def test_an_lfs_extension_of_the_repository_never_starts(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    marker = tmp_path / "started"
    outside = tmp_path / "storage"
    _files(root, {".gitattributes": "*.py filter=lfs\n", "app.py": "print('changed')\n"})
    with open(root / ".git" / "config", "a", encoding="utf-8", newline="\n") as handle:
        handle.write(
            f'[lfs "extension.x"]\n\tclean = sh -c \'echo x > "{marker.as_posix()}"; cat\'\n'
            f"\tsmudge = cat\n\tpriority = 0\n[lfs]\n\tstorage = {outside.as_posix()}\n"
        )
    walk.git_tree(root)
    _scan(root)
    assert not marker.exists() and not outside.exists()


def _bare_shaped_folder(tmp_path: Path) -> Path:
    """A commit that delivers services/chat laid out as a bare repository, in a clone."""
    inner = _bot(tmp_path)
    outer = tmp_path / "outer"
    chat = outer / "services" / "chat"
    chat.mkdir(parents=True)
    for name in ("HEAD", "index", "objects", "refs"):
        source = inner / ".git" / name
        (shutil.copytree if source.is_dir() else shutil.copy)(source, chat / name)
    (chat / "refs" / "tags").mkdir(exist_ok=True)
    (chat / "refs" / "heads" / "keep").write_text("", encoding="utf-8")
    (chat / "config").write_text(
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tworktree = .\n",
        encoding="utf-8",
        newline="\n",
    )
    _files(chat, {"app.py": "print('hello')\n"})
    (chat / "refs" / "heads" / "keep").unlink()
    _git(outer, "init", "-q")
    _commit(outer)
    clone = tmp_path / "clone"
    _git(tmp_path, "clone", "-q", outer.as_uri(), str(clone))
    return clone / "services" / "chat"


def test_a_committed_folder_shaped_like_a_bare_repository_is_not_opened(tmp_path: Path) -> None:
    chat = _bare_shaped_folder(tmp_path)
    plain = subprocess.run(
        ["git", "rev-parse", "--git-dir"], cwd=chat, capture_output=True, text=True, check=False
    )
    assert plain.stdout.strip() == "."  # the fixture does fool plain git
    assert walk._git(["rev-parse", "--git-dir"], chat) is None
    assert walk.git_tree(chat).tracked is None
    assert _rows(chat, NOT_LISTED)


@pytest.mark.parametrize(
    ("key", "value"),
    [("url", "--upload-pack=x"), ("branch", "--upload-pack=x"), ("path", "-x")],
)
def test_a_list_value_that_reads_as_an_option_is_refused(key: str, value: str) -> None:
    raw = {"name": "a", "url": "https://example.invalid/r.git", key: value}
    if key == "path":
        del raw["url"]
    with pytest.raises(fleet.FleetError, match="must not start with"):
        fleet._target(raw, "list")


def test_no_url_or_branch_reaches_git_as_an_option(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []

    def run(args: list[str], *, cwd: Any, timeout: float) -> Any:
        calls.append(args)
        if args[0] == "fetch" and args[args.index("--") + 2] == "1" * 40:
            raise devgit.GitError("refused")
        return subprocess.CompletedProcess(args, 0, stdout="1" * 40, stderr="")

    monkeypatch.setattr(devgit, "_run", run)
    url, branch = "--upload-pack=x", "--upload-pack=y"
    devgit.fetch_pinned(url, "1" * 40, tmp_path / "a", branch=branch)
    devgit.clone_shallow(url, tmp_path / "b", branch=branch)
    for args in calls:
        for value in (url, branch):
            if value in args:
                assert "--" in args[: args.index(value)] or args[args.index(value) - 1] == (
                    "--branch"
                )


def test_a_pinned_fetch_and_a_clone_still_work(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    commit = _git(root, "rev-parse", "HEAD").strip()
    assert devgit.clone_shallow(root.as_uri(), tmp_path / "a") == commit
    assert devgit.fetch_pinned(root.as_uri(), commit, tmp_path / "b") == commit


@pytest.mark.parametrize("gap", ["relative", "empty"])
def test_only_absolute_pythonpath_entries_reach_a_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, gap: str
) -> None:
    entries = [str(tmp_path), "src" if gap == "relative" else ""]
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join(entries))
    seen = fleet._child_env()["PYTHONPATH"].split(os.pathsep)
    assert seen[1:] == [str(tmp_path)] and os.path.isabs(seen[0])


def test_the_bench_runs_the_auditor_and_not_the_clones_copy(tmp_path: Path) -> None:
    marker = tmp_path / "planted"
    root = _bot(tmp_path)
    _files(
        root,
        {
            "aisafe/__init__.py": "",
            "aisafe/cli.py": f"open({str(marker)!r}, 'w').write('x')\n",
        },
    )
    spec = importlib.util.spec_from_file_location("bench_run_fixes3", REPO / "bench" / "run.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module._child_env is fleet._child_env
    code, summary = module.audit(root, tmp_path / "report.json")
    assert not marker.exists()
    if fleet._safe_path_works():
        assert code == 0 and summary is not None
    else:
        # Before 3.11 the clone's own `aisafe` would be imported: the audit refuses instead.
        assert code == 2 and summary is None


# ---------------------------------------------------------------------------
# Writes and network
# ---------------------------------------------------------------------------


def test_the_audited_pyproject_chooses_neither_path_nor_format(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _bot(tmp_path)
    (root / "pyproject.toml").write_text(
        '[tool.aisafe-audit]\noutput = "../outside.txt"\nformat = "markdown"\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(root)
    assert audit.main(["."]) == audit.EXIT_OK
    assert not (tmp_path / "outside.txt").exists()


@pytest.mark.parametrize("flag", ["-o", "--write-baseline"])
def test_a_report_never_lands_through_a_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: str
) -> None:
    root = _bot(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    _link(root / ".aisafe-audit", outside)
    monkeypatch.chdir(root)
    code = audit.main([".", flag, ".aisafe-audit/audit-report.json"])
    os.rmdir(root / ".aisafe-audit") if os.name == "nt" else (root / ".aisafe-audit").unlink()
    assert code == audit.EXIT_FATAL
    assert not list(outside.iterdir())


def test_a_plain_output_path_is_written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _bot(tmp_path)
    monkeypatch.chdir(root)
    assert audit.main([".", "--format", "json", "-o", ".aisafe-audit/new/r.json"]) == audit.EXIT_OK
    assert (root / ".aisafe-audit" / "new" / "r.json").is_file()


def test_a_clone_leaves_large_files_unfetched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, str] = {}
    real = subprocess.run

    def run(*args: Any, **kwargs: Any) -> Any:
        seen.update(kwargs.get("env") or {})
        return real(*args, **kwargs)

    monkeypatch.setattr(devgit.subprocess, "run", run)
    devgit.clone_shallow(_bot(tmp_path).as_uri(), tmp_path / "clone")
    assert seen["GIT_LFS_SKIP_SMUDGE"] == "1"


HOST_CONFIGS = {
    "include": "[include]\n\tpath = //host.invalid/share/x\n",
    "backslashes": '[include]\n\tpath = "\\\\\\\\host.invalid\\\\share\\\\x"\n',
    "one of each": '[include]\n\tpath = "/\\\\host.invalid/share/x"\n',
    "same line": '[include] path = "//host.invalid/share/x"\n',
    "continued": "[include]\n\tpath = /\\\n/host.invalid/share/x\n",
    "split by quotes": '[include]\n\tpath = /"/"host.invalid/share/x\n',
    "includeif": '[includeIf "gitdir:**"]\n\tpath = //host.invalid/share/x\n',
    "prefix": "[include]\n\tpath = %(prefix)///host.invalid/share/x\n",
    "worktree": "[core]\n\tworktree = //host.invalid/share/x\n",
    "attributes": "[core]\n\tattributesFile = //host.invalid/share/x\n",
}


def _no_git_starts(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError(f"git started: {args}")

    monkeypatch.setattr(walk.subprocess, "run", refuse)


def _add_config(root: Path, text: str) -> None:
    with open(root / ".git" / "config", "a", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


@pytest.mark.parametrize("text", HOST_CONFIGS.values(), ids=HOST_CONFIGS.keys())
def test_a_network_path_in_the_config_starts_no_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str
) -> None:
    root = _bot(tmp_path)
    _add_config(root, text)
    assert walk.network_reference(root) == ".git/config"
    _no_git_starts(monkeypatch)
    assert walk.run_git(["rev-parse", "HEAD"], root) is None
    assert walk.run_git(["rev-parse", "HEAD"], root) is None


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        (".git/objects/info/alternates", "//host.invalid/share/objects\n"),
        (".git/objects/info/alternates", '"\\\\host.invalid\\share\\objects"\n'),
        (".git/commondir", "//host.invalid/share/.git\n"),
    ],
)
def test_a_network_path_in_a_git_file_starts_no_git(tmp_path: Path, rel: str, text: str) -> None:
    root = _bot(tmp_path)
    _files(root, {rel: text})
    assert walk.network_reference(root) == rel
    assert walk.run_git(["rev-parse", "HEAD"], root) is None


def test_a_gitdir_line_on_another_machine_starts_no_git(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    _files(root, {".git": "gitdir: //host.invalid/share/.git\n", "app.py": "print(1)\n"})
    assert walk.network_reference(root) == ".git"


def test_an_include_is_followed_to_the_file_that_names_the_host(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    _files(tmp_path, {"second.cfg": "[include]\n\tpath = //host.invalid/share/x\n"})
    _add_config(root, "[include]\n\tpath = ../../second.cfg ; a comment\n")
    assert walk.network_reference(root) == "second.cfg"


def test_an_alternate_is_followed_to_the_file_that_names_the_host(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    second = tmp_path / "second"
    _files(second, {"info/alternates": "//host.invalid/share/objects\n"})
    _files(root, {".git/objects/info/alternates": f"{second.as_posix()}\n"})
    assert walk.network_reference(root) == "alternates"


def test_a_chain_of_local_files_past_any_repository_counts_as_unread(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    many = "".join(f"[include]\n\tpath = cfg{n}\n" for n in range(70))
    _add_config(root, many)
    assert walk.network_reference(root) is not None


def test_a_git_folder_linked_to_a_local_folder_is_ordinary(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    moved = tmp_path / "moved"
    shutil.move(str(root / ".git"), moved)
    _link(root / ".git", moved)
    assert walk.network_reference(root) is None
    _add_config(root, HOST_CONFIGS["include"])
    assert walk.network_reference(root) is not None
    os.rmdir(root / ".git") if os.name == "nt" else (root / ".git").unlink()


def test_a_relative_folder_finds_the_repository_above_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _bot(tmp_path)
    _add_config(root, HOST_CONFIGS["include"])
    (root / "sub").mkdir()
    monkeypatch.chdir(root / "sub")
    assert walk.network_reference(Path(".")) == ".git/config"


def test_a_remote_on_a_file_share_is_ordinary(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    _add_config(
        root,
        '[remote "origin"]\n\turl = //files.invalid/git/r.git\n\tpushurl = //files.invalid/x\n'
        '[url "//files.invalid/"]\n\tinsteadOf = //other.invalid/\n',
    )
    assert walk.network_reference(root) is None
    assert walk.git_tree(root).tracked


def test_the_tree_reads_as_unknown_when_git_was_not_started(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    _add_config(root, HOST_CONFIGS["include"])
    assert walk.git_meta(root) == (None, None)
    rows = _rows(root, NOT_LISTED)
    assert len(rows) == 1 and ".git/config" in rows[0].why and "not started" in rows[0].why
    scan = machine_scan(root)
    assert scan.state.is_git and not scan.state.clean and scan.state.tracked is None
    assert scan.tracked_not_walked is None and scan.state.to_dict()["dirty"] is None


def _crafted_gitlink(tmp_path: Path, name: str, path: str) -> Path:
    """A repository whose index holds a gitlink at `path`, spelled after the checks."""
    root = tmp_path / name
    _files(root, {"app.py": "print('hello')\n"})
    _git(root, "init", "-q")
    commit = _commit(root)
    stand_in = "z" * len(path)
    _git(root, "update-index", "--add", "--cacheinfo", f"160000,{commit},{stand_in}")
    raw = bytearray((root / ".git" / "index").read_bytes())
    at = raw.find(stand_in.encode())
    raw[at : at + len(path)] = path.encode()
    body = bytes(raw[:-20])
    (root / ".git" / "index").write_bytes(body + hashlib.sha1(body).digest())
    return root


@pytest.mark.parametrize("spelling", ["up", "absolute"])
def test_a_gitlink_out_of_the_tree_is_no_submodule(tmp_path: Path, spelling: str) -> None:
    outside = _bot(tmp_path)
    path = "../bot" if spelling == "up" else outside.as_posix()
    root = _crafted_gitlink(tmp_path, "crafted", path)
    tree = walk.git_tree(root)
    assert tree.tracked == {"app.py"} and path in tree.unlisted
    assert tree.status_failed
    assert _rows(root, NOT_LISTED)


# ---------------------------------------------------------------------------
# Files hidden from the report
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "extra",
    [
        {"schema": "aisg/1"},
        {"schema": "aisg/1", "kind": "measure"},
        {"schema": "aisg/1", "guards": []},
        {"schema": "aisg/1", "kind": "evaluation"},
    ],
    ids=["schema", "measure", "guards", "evaluation"],
)
def test_a_prompt_stays_a_prompt_whatever_keys_it_carries(
    tmp_path: Path, extra: dict[str, Any]
) -> None:
    plain = _outside_git(tmp_path, "plain")
    _files(plain, {"prompts/companion.json": json.dumps({"system_prompt": PROMPT}, indent=1)})
    labelled = _outside_git(tmp_path, "labelled")
    _files(
        labelled,
        {"prompts/companion.json": json.dumps({**extra, "system_prompt": PROMPT}, indent=1)},
    )
    assert _ids(labelled) == _ids(plain)
    assert "prompts/companion.json" in {row["file"] for row in _scan(labelled)[0].inventory.prompts}


def test_words_in_the_head_make_no_report(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    body = {"notes": '"schema": "aisg/1"', "system_prompt": PROMPT}
    _files(root, {"config/x.json": json.dumps(body), "config/y.json": '{"schema": "aisg/1", x'})
    records, _units, _unknown = walk.walk(root)
    assert not [r for r in records if discover._looks_like_report(r)]


@pytest.mark.parametrize("kind", ["measure", "review", "decision", "audit-baseline"])
def test_a_document_that_says_the_tool_wrote_it_gets_a_row(tmp_path: Path, kind: str) -> None:
    root = tmp_path / "tree"
    _files(root, {"config/x.json": json.dumps({"schema": "aisg/1", "kind": kind})})
    rows = [u for u in _scan(root, mode="auditor")[2] if u.category is UnknownCategory.REPORTS]
    assert [row.what for row in rows] == ["config/x.json"]
    assert "not an evaluation report" in rows[0].why


def test_a_real_baseline_stays_silent(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    body = {"schema": "aisg/1", "kind": "audit-baseline", "fingerprints": ["a"]}
    _files(root, {"audit-baseline.json": json.dumps(body)})
    assert not [u for u in _scan(root)[2] if u.category is UnknownCategory.REPORTS]


@pytest.mark.parametrize(
    ("rel", "folder"),
    [
        ("prompts/__pycache__/companion.md", "prompts/__pycache__"),
        (".mypy_cache/p.py", ".mypy_cache"),
        (".pytest_cache/v/prompt.md", ".pytest_cache"),
        (".ruff_cache/p.txt", ".ruff_cache"),
    ],
)
def test_a_cache_holding_a_foreign_file_is_named(tmp_path: Path, rel: str, folder: str) -> None:
    root = tmp_path / "tree"
    _files(root, {rel: PROMPT, "app.py": "print(1)\n"})
    dirs: list[str] = []
    _records, _units, unknown = walk.walk(root, unread_dirs=dirs)
    assert dirs == [folder]
    assert [u.what for u in unknown] == [UNREAD] and folder in unknown[0].why


def test_the_hypothesis_folder_is_never_pruned(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    _files(root, {".hypothesis/prompt.txt": PROMPT})
    records, _units, _unknown = walk.walk(root)
    assert [r.relpath for r in records] == [".hypothesis/prompt.txt"]


def test_a_cache_holding_its_own_files_is_not(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    _files(
        root,
        {
            "app.py": "print(1)\n",
            "__pycache__/app.cpython-313.pyc": b"\x00compiled",
            ".mypy_cache/.gitignore": "*\n",
            ".mypy_cache/3.13/app.meta.json": "{}\n",
            ".mypy_cache/3.13/app.data.ff": b"\x00",
            ".mypy_cache/CACHEDIR.TAG": "tag\n",
            ".pytest_cache/README.md": "cache\n",
            ".pytest_cache/v/cache/lastfailed": "{}\n",
            ".ruff_cache/0.5.1/1234": b"\x00",
        },
    )
    dirs: list[str] = []
    _records, _units, unknown = walk.walk(root, unread_dirs=dirs)
    assert dirs == [] and unknown == []


def test_version_control_data_is_never_named(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    _files(root, {"app.py": "print(1)\n", ".hg/store/x.md": "x\n", ".svn/x.md": "x\n"})
    dirs: list[str] = []
    walk.walk(root, unread_dirs=dirs)
    assert dirs == []


def test_a_foreign_file_in_a_cache_in_git_stays_the_commits_business(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    _files(root, {"pkg/__pycache__/prompt.md": PROMPT})
    assert not _rows(root, UNREAD)


@pytest.mark.parametrize(
    ("files", "named"),
    [
        ({"vendor/prompts/companion.md": PROMPT}, "vendor"),
        ({"prompts/companion.md": PROMPT, ".gitignore": "*.md\n"}, "prompts/companion.md"),
        ({"prompts/companion.prompt": b"\x00" + PROMPT.encode()}, "prompts/companion.prompt"),
        ({"prompts/companion.j2": b"\x00" + PROMPT.encode()}, "prompts/companion.j2"),
        ({"prompts/companion.dat": b"\x00" + PROMPT.encode()}, "prompts/companion.dat"),
    ],
    ids=["vendor", "gitignore", "prompt", "j2", "dat"],
)
def test_outside_git_one_row_names_what_was_left_unread(
    tmp_path: Path, files: dict[str, Any], named: str
) -> None:
    root = _outside_git(tmp_path)
    _files(root, files)
    rows = _rows(root, UNREAD)
    assert len(rows) == 1 and named in rows[0].why


def test_a_gitignore_of_everything_outside_git_says_so(tmp_path: Path) -> None:
    root = _outside_git(tmp_path)
    _files(root, {".gitignore": "*\n", "sub/prompts/companion.md": PROMPT})
    _ctx, findings, unknown = _scan(root)
    assert not findings and [u for u in unknown if u.what == UNREAD]


def test_a_nul_byte_outside_git_in_any_unbinary_type_gets_the_not_text_row(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    _files(root, {"data.dat": b"\x00text", "logo.png": b"\x00picture"})
    rows = _rows(root, NOT_TEXT)
    assert len(rows) == 1 and "data.dat" in rows[0].why and "logo.png" not in rows[0].why


def test_a_picture_outside_git_adds_no_unread_row(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    _files(root, {"logo.png": b"\x00picture", "app.py": "print(1)\n"})
    assert not _rows(root, UNREAD)


def test_an_ordinary_commit_gets_no_new_row(tmp_path: Path) -> None:
    root = _companion(tmp_path)
    _files(root, {"logo.png": b"\x00picture"})
    _commit(root)
    unknown = _scan(root)[2]
    assert not [u for u in unknown if u.what in (LOST, UNREAD, NOT_TEXT, NOT_LISTED)]


def test_a_sparse_checkout_names_the_tracked_file_it_left_out(tmp_path: Path) -> None:
    root = _companion(tmp_path)
    _git(root, "sparse-checkout", "set", "--no-cone", "/*", "!/prompts/")
    assert not (root / "prompts" / "companion.md").exists()
    rows = _rows(root, LOST)
    assert len(rows) == 1 and "prompts/companion.md" in rows[0].why


def test_a_submodule_not_checked_out_is_named(tmp_path: Path) -> None:
    inner = _bot(tmp_path)
    root = _companion(tmp_path)
    _git(root, "submodule", "--quiet", "add", inner.as_uri(), "personas")
    _commit(root)
    clone = tmp_path / "clone"
    _git(tmp_path, "clone", "-q", root.as_uri(), str(clone))
    rows = _rows(clone, LOST)
    assert len(rows) == 1 and "personas" in rows[0].why


def test_a_checked_out_submodule_is_not_named(tmp_path: Path) -> None:
    inner = _bot(tmp_path)
    root = _companion(tmp_path)
    _git(root, "submodule", "--quiet", "add", inner.as_uri(), "personas")
    _commit(root)
    assert not _rows(root, LOST)


def test_a_deleted_tracked_file_is_named(tmp_path: Path) -> None:
    root = _companion(tmp_path)
    (root / "prompts" / "companion.md").unlink()
    assert _named(_rows(root, LOST), "prompts/companion.md")


def test_an_excluded_tracked_folder_is_not_named_again(tmp_path: Path) -> None:
    root = _companion(tmp_path)
    assert not _scan_rows(root, LOST, exclude=("prompts",))


def _scan_rows(root: Path, what: str, **options: Any) -> list[Any]:
    return [u for u in _scan(root, **options)[2] if u.what == what]


@windows_only
def test_a_folder_renamed_by_case_is_named(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    _files(root, {"Build/prompts/companion.md": PROMPT})
    _git(root, "init", "-q")
    _commit(root)
    os.rename(root / "Build", root / "tmp")
    os.rename(root / "tmp", root / "build")
    assert _named(_rows(root, LOST), "Build/prompts/companion.md")


@windows_only
def test_a_tracked_file_under_a_gitignore_line_by_case_is_named(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    _files(root, {"prompts/Companion.md": PROMPT, ".gitignore": "*.md\n"})
    _git(root, "init", "-q")
    _commit(root)
    os.rename(root / "prompts" / "Companion.md", root / "prompts" / "tmp")
    os.rename(root / "prompts" / "tmp", root / "prompts" / "companion.md")
    assert _named(_rows(root, LOST), "prompts/Companion.md")


@windows_only
def test_a_file_read_under_another_case_is_not_named(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    _files(root, {"prompts/Companion.md": PROMPT})
    _git(root, "init", "-q")
    _commit(root)
    os.rename(root / "prompts" / "Companion.md", root / "prompts" / "tmp")
    os.rename(root / "prompts" / "tmp", root / "prompts" / "companion.md")
    assert not _rows(root, LOST)


@pytest.mark.parametrize(
    "content",
    [
        b"\xff\xfe" + ("中" * 5000).encode("utf-16-le"),
        b"\xfe\xff" + ("中" * 5000).encode("utf-16-be"),
        ("中" * 5000).encode("utf-16-le") + "\ntext\n".encode("utf-16-le"),
        b"x" * 9000 + b"\x00",
    ],
    ids=["mark", "big-endian mark", "no mark", "late NUL"],
)
def test_a_wide_file_is_never_read_as_garbage(tmp_path: Path, content: bytes) -> None:
    root = tmp_path / "tree"
    _files(root, {"prompts/companion.md": content})
    records, _units, unknown = walk.walk(root)
    assert "prompts/companion.md" not in [r.relpath for r in records]
    assert [u for u in unknown if u.what == NOT_TEXT and "prompts/companion.md" in u.why]


def test_an_lfs_pointer_is_named_as_not_read(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    _files(root, {"prompts/companion.md": POINTER, "model.pt": POINTER, "app.py": "print(1)\n"})
    records, _units, unknown = walk.walk(root)
    assert sorted(r.relpath for r in records) == ["app.py"]
    rows = [u for u in unknown if u.what == NOT_TEXT]
    assert len(rows) == 1 and "prompts/companion.md" in rows[0].why and "LFS" in rows[0].why
    assert "model.pt" not in rows[0].why


def test_a_long_file_that_starts_like_a_pointer_is_read(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    _files(root, {"notes.md": POINTER + "x" * 2000})
    records, _units, _unknown = walk.walk(root)
    assert [r.relpath for r in records] == ["notes.md"]


def test_a_junction_is_a_link_and_outside_files_are_not_read(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    _files(outside, {"secret.md": PROMPT})
    root = _outside_git(tmp_path)
    _link(root / "prompts", outside)
    assert walk.is_link(root / "prompts") and not walk.is_link(outside)
    records, _units, unknown = walk.walk(root)
    assert not [r for r in records if r.relpath.startswith("prompts/")]
    assert [u for u in unknown if u.what == "symlinks skipped"]
    assert [u for u in unknown if u.what == UNREAD and "prompts" in u.why]


def test_a_loop_is_walked_once(tmp_path: Path) -> None:
    root = _outside_git(tmp_path)
    _files(root, {"prompts/companion.md": PROMPT})
    plain = _ids(root)
    _link(root / "loop", root)
    assert _ids(root) == plain


def test_a_cloud_placeholder_is_not_a_link() -> None:
    class Status:
        st_mode = 0o100644
        st_reparse_tag = 0x9000001A  # IO_REPARSE_TAG_CLOUD: a tag, and the file itself
        st_file_attributes = 0

    real = os.lstat
    os.lstat = lambda path: Status()  # type: ignore[assignment]
    try:
        assert not walk.is_link("x")
    finally:
        os.lstat = real  # type: ignore[assignment]


def test_a_name_with_a_lone_surrogate_costs_no_rule(tmp_path: Path) -> None:
    root = _outside_git(tmp_path, "control")
    _files(root, {"prompts/companion.md": PROMPT})
    named = _outside_git(tmp_path, "named")
    (named / "prompts").mkdir()
    try:
        (named / "prompts" / "comp\udc80anion.md").write_text(PROMPT, encoding="utf-8")
    except (OSError, UnicodeError):  # pragma: no cover - a file system that refuses the name
        pytest.skip("this file system refuses the name")
    assert _ids(named) == _ids(root)
    for record in _scan(named)[0].files:
        record.relpath.encode("utf-8")


# ---------------------------------------------------------------------------
# The workbench's list of what is unread, and of what differs
# ---------------------------------------------------------------------------


def test_a_tracked_file_rewritten_as_own_output_is_dirt(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    _files(root, {"prompts.json": json.dumps({"system_prompt": PROMPT})})
    _git(root, "init", "-q")
    _commit(root)
    assert machine_scan(root).state.clean
    _files(root, {"prompts.json": json.dumps({"schema": "aisg/1", "kind": "audit", "x": 1})})
    state = machine_scan(root).state
    assert state.dirty == ("prompts.json",) and not state.clean


def test_own_output_that_is_not_in_the_commit_is_no_dirt(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    _files(root, {"report.json": json.dumps({"schema": "aisg/1", "kind": "audit"})})
    assert tree_state(root, {"app.py", "other.py"}, {"report.json"}).clean


@pytest.mark.parametrize(
    ("rel", "content"),
    [
        ("system_prompt.html", f"{OWN_HTML_MARKER_LINE}\n{PROMPT}"),
        ("prompts.json", json.dumps({"schema": "aisg/1", "kind": "audit", "x": PROMPT})),
        ("signed.json", json.dumps({"schema": "aisg/signoff/1", "kind": "signoff", "x": PROMPT})),
    ],
    ids=["html marker", "kind audit", "kind signoff"],
)
def test_a_tracked_file_labelled_own_output_is_unread(
    tmp_path: Path, rel: str, content: str
) -> None:
    root = tmp_path / "tree"
    _files(root, {rel: content, "app.py": "print(1)\n"})
    _git(root, "init", "-q")
    _commit(root)
    scan = machine_scan(root)
    assert rel in (scan.ctx.inventory.own_output_skipped or [])
    assert scan.tracked_not_walked == [rel]
    assert _rows(root, OWN_ROW)


def test_cache_types_cover_every_cache_and_no_version_control_folder() -> None:
    pruned = patterns.NOTHING_WRITTEN_DIRS & patterns.SKIP_DIRS
    assert set(patterns.CACHE_OWN_TYPES) == pruned - {".git", ".hg", ".svn"}
