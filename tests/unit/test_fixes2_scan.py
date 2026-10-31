"""tests/unit/test_fixes2_scan.py
------------------------------
A repository under audit is hostile until shown otherwise. These tests build small
throwaway repositories whose configuration names a program that writes a marker file; the
marker is the proof that the program ran, and where a fixture could be mistaken for a safe
one a control shows plain git does start it. They also cover what git can be made to say
about a tree (`core.worktree`, replace refs, restored times), the skill's own files under
`.aisafe-audit/`, and what the walk says when it could not read or could not list a file.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from investigation_helpers import FIXTURES

import aisafe
from aisafe import audit
from aisafe.assessment import assess
from aisafe.assessment.assess import run_assessment
from aisafe.devtools import _git as devgit
from aisafe.devtools import fleet
from aisafe.discovery import walk
from aisafe.discovery.patterns import OWN_HTML_MARKER_LINE
from aisafe.evidence.model import SCHEMA_VERSION, UnknownCategory
from aisafe.investigation.scan import machine_scan, tree_state
from aisafe.investigation.validate import validate_paths

AUDIT_FIXTURES = FIXTURES.parent / "audit"
pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not on PATH")

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
NOT_LISTED = "tracked files not listed"
NOT_TEXT = "files not read as text"
OWN_ROW = "own output skipped outside the audit directory"
HELPLINE = "If you are in crisis, call the 988 helpline or a crisis hotline.\n"


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


def _companion(tmp_path: Path, name: str = "companion") -> Path:
    """A committed copy of `persons_companion`, the fixture with findings."""
    root = tmp_path / name
    shutil.copytree(AUDIT_FIXTURES / "persons_companion", root)
    _git(root, "init", "-q")
    _commit(root)
    return root


def _bot(tmp_path: Path) -> Path:
    root = tmp_path / "bot"
    root.mkdir()
    (root / "app.py").write_text("print('hello')\n", encoding="utf-8", newline="\n")
    (root / "other.py").write_text("print('other')\n", encoding="utf-8", newline="\n")
    _git(root, "init", "-q")
    _commit(root)
    return root


def _rule_ids(root: Path, mode: str = "self-assessment") -> set[str]:
    _ctx, findings, _unknown, _rules = audit.scan(audit.AuditOptions(path=str(root), mode=mode))
    return {finding.display_id for finding in findings}


def _rows(root: Path, what: str, mode: str = "self-assessment") -> list[object]:
    _ctx, _findings, unknown, _rules = audit.scan(audit.AuditOptions(path=str(root), mode=mode))
    return [item for item in unknown if item.what == what]


def _probe(tmp_path: Path, root: Path) -> Path:
    """A program inside `.git`; every start adds a line to the returned marker file."""
    marker = tmp_path / "started.txt"
    script = root / ".git" / "probe.sh"
    script.write_text(
        f'#!/bin/sh\necho started >> "{marker.as_posix()}"\ncat\n', encoding="utf-8", newline="\n"
    )
    script.chmod(0o755)
    return marker


def _drop_object(root: Path, oid: str) -> None:
    loose = root / ".git" / "objects" / oid[:2] / oid[2:]
    loose.chmod(stat.S_IWRITE | stat.S_IREAD)
    loose.unlink()


def _promisor(root: Path, url: str) -> None:
    """Make `root` a partial clone: a missing object is fetched from `url`."""
    _git(root, "config", "core.repositoryformatversion", "1")
    _git(root, "config", "extensions.partialClone", "origin")
    _git(root, "config", "remote.origin.url", url)
    _git(root, "config", "remote.origin.promisor", "true")
    _git(root, "config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")


def _helper_repo(tmp_path: Path, helper: str, missing: str) -> tuple[Path, Path, str]:
    """A partial clone whose missing object is fetched by a program of the repository's:
    `git remote-<helper>`, which `alias.remote-<helper>` makes a shell command."""
    root = _bot(tmp_path)
    marker = _probe(tmp_path, root)
    commit = _git(root, "rev-parse", "HEAD").strip()
    _drop_object(root, _git(root, "rev-parse", missing).strip())
    _promisor(root, f"{helper}::x")
    _git(root, "config", f"protocol.{helper}.allow", "always")
    _git(root, "config", f"alias.remote-{helper}", "!sh .git/probe.sh </dev/null")
    return root, marker, commit


# ---------------------------------------------------------------------------
# Item 1: no git command reaches a transport, and every git call goes one way
# ---------------------------------------------------------------------------


def test_the_helper_fixture_does_start_under_plain_git(tmp_path: Path) -> None:
    root, marker, _commit_id = _helper_repo(tmp_path, "evil", "HEAD^{tree}")
    subprocess.run(["git", "status", "--porcelain"], cwd=root, capture_output=True, check=False)
    assert marker.exists()


@pytest.mark.parametrize("helper", ["evil", "none"])
def test_a_missing_tree_starts_no_helper_in_the_audit(tmp_path: Path, helper: str) -> None:
    # "none" is the value of GIT_ALLOW_PROTOCOL, so the list alone would let it through.
    root, marker, _commit_id = _helper_repo(tmp_path, helper, "HEAD^{tree}")
    audit.scan(audit.AuditOptions(path=str(root)))
    machine_scan(root)
    assert not marker.exists()


@pytest.mark.parametrize("helper", ["evil", "none"])
def test_a_missing_blob_starts_no_helper_in_at_commit(tmp_path: Path, helper: str) -> None:
    root, marker, commit = _helper_repo(tmp_path, helper, "HEAD:app.py")
    assert assess._at_commit(root, commit, "app.py") is None
    assert not marker.exists()


def test_a_helper_named_by_remote_vcs_never_starts(tmp_path: Path) -> None:
    root, marker, _commit_id = _helper_repo(tmp_path, "none", "HEAD^{tree}")
    _git(root, "config", "remote.origin.url", "https://example.invalid/x.git")
    _git(root, "config", "remote.origin.vcs", "none")
    audit.scan(audit.AuditOptions(path=str(root)))
    assert not marker.exists()


@pytest.mark.parametrize("override", [False, True])
def test_a_partial_clone_over_ssh_starts_no_ssh_command(tmp_path: Path, override: bool) -> None:
    root = _bot(tmp_path)
    marker = _probe(tmp_path, root)
    blob = _git(root, "rev-parse", "HEAD:app.py").strip()
    _drop_object(root, blob)
    _promisor(root, "ssh://git@example.invalid/x.git")
    _git(root, "config", "core.sshCommand", "sh .git/probe.sh")
    if override:
        _git(root, "config", "protocol.ssh.allow", "always")
    assert walk._git(["cat-file", "-p", blob], root) is None
    assert not marker.exists()


def test_a_repository_protocol_allow_opens_no_connection(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    _drop_object(root, _git(root, "rev-parse", "HEAD^{tree}").strip())
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    server.settimeout(0.2)
    hits: list[object] = []
    stop = threading.Event()

    def accept() -> None:
        while not stop.is_set():
            try:
                connection, address = server.accept()
            except OSError:
                continue
            hits.append(address)
            connection.close()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        _promisor(root, f"ftp://127.0.0.1:{server.getsockname()[1]}/x.git")
        _git(root, "config", "protocol.ftp.allow", "always")
        walk.git_meta(root)
    finally:
        stop.set()
        thread.join()
        server.close()
    assert hits == []


def test_every_git_call_runs_absolute_safe_and_without_a_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _bot(tmp_path)
    commit = _git(root, "rev-parse", "HEAD").strip()
    seen: list[tuple[list[str], dict[str, str]]] = []
    real = subprocess.run

    def spy(argv: list[str], *args: object, **kwargs: object) -> object:
        seen.append((list(argv), kwargs.get("env")))
        return real(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", spy)
    audit.scan(audit.AuditOptions(path=str(root)))
    state = machine_scan(root).state
    assess._at_commit(root, commit, "app.py")
    assess._git_stdout(root, "rev-parse", "HEAD")
    walk.file_age(root / "missing.py", root)
    assert state.clean and len(seen) > 8
    for argv, env in seen:
        assert os.path.isabs(argv[0]) and Path(argv[0]).stem == "git"
        assert argv[1 : 1 + len(walk.GIT_SAFE)] == list(walk.GIT_SAFE)
        assert env["GIT_ALLOW_PROTOCOL"] == "none"


def test_no_module_starts_git_by_its_bare_name() -> None:
    package = Path(aisafe.__file__).parent
    bare = re.compile(r"""[\[(]\s*["']git["']\s*,""")
    assert [p.name for p in package.rglob("*.py") if bare.search(p.read_text("utf-8"))] == []


def test_the_clone_step_keeps_a_transport_and_no_program(tmp_path: Path) -> None:
    source = _bot(tmp_path)
    url = source.as_uri()
    assert (
        devgit.clone_shallow(url, tmp_path / "shallow") == _git(source, "rev-parse", "HEAD").strip()
        and (tmp_path / "shallow" / "app.py").is_file()
    )
    sha = _git(source, "rev-parse", "HEAD").strip()
    assert devgit.fetch_pinned(url, sha, tmp_path / "pinned") == sha
    assert devgit.fetch_pinned(str(source), sha[:8], tmp_path / "local-path") == sha

    marker = tmp_path / "ext.txt"
    with pytest.raises(devgit.GitError):
        devgit.clone_shallow(f"ext::sh -c 'echo x >> {marker.as_posix()}'", tmp_path / "ext")
    assert not marker.exists()


def test_a_clone_starts_no_hook_the_operator_templates_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _bot(tmp_path)
    marker = tmp_path / "hook.txt"
    template = tmp_path / "template" / "hooks"
    template.mkdir(parents=True)
    hook = template / "post-checkout"
    hook.write_text(f'#!/bin/sh\necho x >> "{marker.as_posix()}"\n', "utf-8", newline="\n")
    hook.chmod(0o755)
    monkeypatch.setenv("GIT_TEMPLATE_DIR", str(tmp_path / "template"))
    devgit.clone_shallow(source.as_uri(), tmp_path / "clone")
    assert not marker.exists()


# ---------------------------------------------------------------------------
# Item 2: a git.exe committed to the tree never starts
# ---------------------------------------------------------------------------


def test_git_is_found_on_the_path_alone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = Path(walk.git_program())
    planted = tmp_path / "tree"
    planted.mkdir()
    (planted / real.name).write_bytes(b"not git")
    monkeypatch.chdir(planted)
    monkeypatch.setenv("PATH", os.pathsep.join([".", "tree", str(real.parent)]))
    assert Path(walk.git_program()) == real


def test_no_git_on_the_path_reads_as_no_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    assert walk.git_program() is None
    assert walk.git_meta(tmp_path) == (None, False)
    assert devgit.git_available() is False
    with pytest.raises(devgit.GitError):
        devgit.head_sha(tmp_path)


def test_a_clone_folder_that_is_gone_is_a_git_error(tmp_path: Path) -> None:
    with pytest.raises(devgit.GitError):
        devgit.head_sha(tmp_path / "gone")


_PLANTED_GIT = """
using System; using System.IO;
class P { static int Main(string[] a) {
  File.AppendAllText(Environment.GetEnvironmentVariable("AISAFE_TEST_MARKER"), "started\\n");
  return 1;
} }
"""


@pytest.fixture(scope="module")
def planted_git(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A real `git.exe` that only writes the marker, built with the .NET compiler Windows
    ships."""
    if sys.platform != "win32":
        pytest.skip("Windows looks in the current directory for a program, POSIX does not")
    folder = tmp_path_factory.mktemp("planted")
    compiler = Path(os.environ["WINDIR"]) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
    if not compiler.is_file():
        pytest.skip("no .NET compiler on this machine")
    source = folder / "g.cs"
    source.write_text(_PLANTED_GIT, encoding="utf-8")
    exe = folder / "git.exe"
    subprocess.run(
        [str(compiler), "/nologo", f"/out:{exe}", str(source)], check=True, capture_output=True
    )
    return exe


def _plant(exe: Path, root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    shutil.copy(exe, root / "git.exe")
    marker = tmp_path / "planted.txt"
    monkeypatch.setenv("AISAFE_TEST_MARKER", str(marker))
    monkeypatch.delenv("NoDefaultCurrentDirectoryInExePath", raising=False)
    return marker


def test_a_planted_git_exe_never_starts_from_the_folder_of_the_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, planted_git: Path
) -> None:
    root = _bot(tmp_path)
    marker = _plant(planted_git, root, tmp_path, monkeypatch)
    commit = _git(root, "rev-parse", "HEAD").strip()
    monkeypatch.chdir(root)
    assert walk.git_meta(root)[0] == commit
    assert machine_scan(root).state.commit == commit
    assert assess._at_commit(root, commit, "app.py") == "print('hello')\n"
    assert devgit.head_sha(root) == commit
    assert not marker.exists()


def _run_one(root: Path, tmp_path: Path) -> fleet.RepoResult:
    target = fleet.Target(name="r", path=str(root))
    options = fleet.FleetOptions(list_path="x", fail_on="never", per_repo_timeout=120.0)
    out = tmp_path / "fleet-out"
    out.mkdir()
    return fleet.run_one(target, options, out, tmp_path)


def test_a_planted_git_exe_never_starts_in_a_fleet_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, planted_git: Path
) -> None:
    root = _bot(tmp_path)
    marker = _plant(planted_git, root, tmp_path, monkeypatch)
    result = _run_one(root, tmp_path)
    assert result.status == fleet.STATUS_OK, result.error
    assert result.sha and not marker.exists()


@pytest.mark.skipif(sys.version_info < (3, 11), reason="PYTHONSAFEPATH is new in Python 3.11")
def test_a_package_of_the_clone_is_never_imported_by_a_fleet_audit(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    marker = tmp_path / "imported.txt"
    planted = root / "aisafe"
    planted.mkdir()
    (planted / "__init__.py").write_text(
        f"open({str(marker)!r}, 'a').write('imported')\n", encoding="utf-8"
    )
    _commit(root)
    result = _run_one(root, tmp_path)
    assert result.status == fleet.STATUS_OK, result.error
    assert not marker.exists()


# ---------------------------------------------------------------------------
# Item 3: what git can be made to say about a tree
# ---------------------------------------------------------------------------


def test_core_worktree_elsewhere_is_never_read_as_clean(tmp_path: Path) -> None:
    root = _companion(tmp_path)
    copy = tmp_path / "clean-copy"
    shutil.copytree(root, copy, ignore=shutil.ignore_patterns(".git"))
    (root / "prompts" / "companion.md").write_text("edited after commit\n", encoding="utf-8")
    _git(root, "config", "core.worktree", copy.as_posix())
    assert _git(root, "status", "--porcelain") == ""  # plain git says clean
    state = machine_scan(root).state
    assert state.status_failed and not state.clean
    assert walk.git_meta(root)[1] is None


def test_a_replace_ref_never_changes_what_a_commit_holds(tmp_path: Path) -> None:
    root = _companion(tmp_path)
    head = _git(root, "rev-parse", "HEAD").strip()
    prompt = root / "prompts" / "companion.md"
    original = prompt.read_text(encoding="utf-8")
    prompt.write_text("You are a helpful assistant. Say you are an AI.\n", encoding="utf-8")
    clean = _commit(root)
    _git(root, "reset", "-q", "--soft", head)
    _git(root, "replace", head, clean)
    assert _git(root, "status", "--porcelain") == ""  # plain git says clean
    assert walk.git_meta(root) == (head, True)
    assert machine_scan(root).state.dirty == ("prompts/companion.md",)
    assert assess._at_commit(root, head, "prompts/companion.md") == original


def _same_size_edit(tmp_path: Path) -> Path:
    root = _bot(tmp_path)
    _git(root, "config", "core.trustctime", "false")  # the time git would still catch on POSIX
    path = root / "app.py"
    # A time well before the index's own, or git rereads the file as racy.
    os.utime(path, (1_000_000_000, 1_000_000_000))
    _git(root, "update-index", "--refresh")
    path.write_bytes(path.read_bytes().replace(b"hello", b"jello"))
    os.utime(path, (1_000_000_000, 1_000_000_000))
    assert _git(root, "status", "--porcelain") == ""  # plain git says clean
    return root


def test_a_same_size_edit_with_its_time_restored_is_seen(tmp_path: Path) -> None:
    root = _same_size_edit(tmp_path)
    assert tree_state(root, {"app.py", "other.py"}).dirty == ("app.py",)
    assert walk.git_meta(root)[1] is True


def test_the_fresh_index_stays_out_of_the_audited_tree(tmp_path: Path) -> None:
    root = _same_size_edit(tmp_path)
    index = (root / ".git" / "index").read_bytes()
    listing = sorted(str(path) for path in root.rglob("*"))
    walk.git_meta(root)
    assert sorted(str(path) for path in root.rglob("*")) == listing
    assert (root / ".git" / "index").read_bytes() == index


def test_a_file_a_sparse_checkout_left_off_the_disk_is_no_difference(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    _git(root, "update-index", "--skip-worktree", "other.py")
    (root / "other.py").unlink()
    state = tree_state(root, {"app.py"})
    assert state.clean and "other.py" in state.tracked
    assert walk.git_meta(root)[1] is False


def test_a_submodule_with_no_commit_is_never_read_as_clean(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    module = root / "sub"
    module.mkdir()
    _git(module, "init", "-q")
    _git(module, "commit", "-q", "--allow-empty", "-m", "m")
    sha = _git(module, "rev-parse", "HEAD").strip()
    _git(root, "update-index", "--add", "--cacheinfo", f"160000,{sha},sub")
    _git(root, "commit", "-q", "-m", "gitlink")
    _git(module, "update-ref", "-d", "HEAD")
    assert walk.git_meta(root)[1] is not False


# ---------------------------------------------------------------------------
# Item 4: the skill's own files under .aisafe-audit/
# ---------------------------------------------------------------------------


def _skill_tree(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "tree"
    shutil.copytree(FIXTURES / "benign_lookalike", root)
    (root / ".gitignore").write_text(".aisafe-audit/\n", encoding="utf-8")
    _git(root, "init", "-q")
    _commit(root)
    folder = root / ".aisafe-audit"
    folder.mkdir()
    return root, folder


def _phase_one(root: Path, folder: Path) -> None:
    argv = [str(root), "--format", "json", "-o", str(folder / "audit-report.json")]
    audit.main([*argv, "--write-baseline", str(folder / "audit-baseline.json"), "--fail-on=never"])


def test_the_skill_flow_with_a_gitignored_folder_stays_on_the_commit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root, folder = _skill_tree(tmp_path)
    _phase_one(root, folder)
    (folder / "pr-body.md").write_text("# What changed\n", encoding="utf-8")
    (folder / "investigations").mkdir()
    scan = machine_scan(root)
    assert scan.state.clean, scan.state.dirty
    assert {".aisafe-audit/audit-baseline.json", ".aisafe-audit/pr-body.md"} <= set(
        scan.ctx.inventory.own_output_skipped
    )
    assert "differ" not in str(validate_paths([folder / "investigations"], scan).fatal)
    assert "differ" not in str(run_assessment(root, [folder / "investigations"]).fatal)


def test_any_other_file_in_the_folder_still_counts(tmp_path: Path) -> None:
    root, folder = _skill_tree(tmp_path)
    _phase_one(root, folder)
    (folder / "notes.md").write_text(HELPLINE, encoding="utf-8")
    assert machine_scan(root).state.dirty == (".aisafe-audit/notes.md",)


@pytest.mark.parametrize("name", ["pr-body.md", "audit-baseline.json"])
def test_the_named_files_cannot_close_a_finding(tmp_path: Path, name: str) -> None:
    root = _companion(tmp_path)
    (root / ".gitignore").write_text(".aisafe-audit/\n", encoding="utf-8")
    _commit(root)
    base = {finding.display_id for finding in machine_scan(root).findings}
    assert any(rule.startswith("AUD-1108") for rule in base)
    folder = root / ".aisafe-audit"
    folder.mkdir()
    text = json.dumps({"reason": HELPLINE}) if name.endswith(".json") else HELPLINE
    (folder / name).write_text(text, encoding="utf-8")
    scan = machine_scan(root)
    assert {finding.display_id for finding in scan.findings} == base
    assert scan.state.clean


def test_the_pull_request_text_cannot_close_a_finding_in_the_plain_audit(tmp_path: Path) -> None:
    root = _companion(tmp_path)
    (root / ".gitignore").write_text(".aisafe-audit/\n", encoding="utf-8")
    _commit(root)
    base = _rule_ids(root)
    (root / ".aisafe-audit").mkdir()
    (root / ".aisafe-audit" / "pr-body.md").write_text(HELPLINE, encoding="utf-8")
    assert _rule_ids(root) == base


def test_a_named_file_the_commit_holds_is_read(tmp_path: Path) -> None:
    root, folder = _skill_tree(tmp_path)
    (folder / "pr-body.md").write_text("# Committed\n", encoding="utf-8")
    _commit(root)
    assert ".aisafe-audit/pr-body.md" in machine_scan(root).walked


def test_in_auditor_mode_the_named_files_are_the_tree_s_own(tmp_path: Path) -> None:
    root, folder = _skill_tree(tmp_path)
    (folder / "pr-body.md").write_text("# Left in the tree\n", encoding="utf-8")
    scan = machine_scan(root, mode="auditor")
    assert scan.state.dirty == (".aisafe-audit/pr-body.md",)


# ---------------------------------------------------------------------------
# Item 5: a file git does not compare
# ---------------------------------------------------------------------------


def test_an_assume_unchanged_edit_reads_dirty_in_git_meta(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    _git(root, "update-index", "--assume-unchanged", "app.py")
    (root / "app.py").write_text("print('edited')\n", encoding="utf-8")
    assert _git(root, "status", "--porcelain") == ""  # plain git says clean
    assert walk.git_meta(root)[1] is True


def test_a_flagged_file_with_no_edit_is_still_not_compared(tmp_path: Path) -> None:
    # The fresh index sees the edit above too; this is what `uncompared` adds to it.
    root = _bot(tmp_path)
    _git(root, "update-index", "--assume-unchanged", "app.py")
    assert walk.git_meta(root)[1] is True


# ---------------------------------------------------------------------------
# Item 6: filter drivers: the operator's stay, the repository's are blanked
# ---------------------------------------------------------------------------


def _global_filter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A repository whose blobs go through a filter only the operator's global file names,
    the way `git lfs install` does; the copy has new stat data, as `cp -r` gives."""
    config = tmp_path / "global.gitconfig"
    config.write_text('[filter "up"]\n\tclean = tr a-z A-Z\n', encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    root = _bot(tmp_path)
    (root / ".gitattributes").write_text("*.txt filter=up\n", encoding="utf-8", newline="\n")
    (root / "data.txt").write_text("hello\n", encoding="utf-8", newline="\n")
    _commit(root)
    assert _git(root, "show", "HEAD:data.txt") == "HELLO\n"
    copy = tmp_path / "copy"
    shutil.copytree(root, copy)
    return copy


def test_a_repository_with_the_operator_s_filter_reads_clean_after_a_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    copy = _global_filter(tmp_path, monkeypatch)
    assert tree_state(copy, {"app.py", "other.py", "data.txt", ".gitattributes"}).clean
    assert walk.git_meta(copy)[1] is False


@pytest.mark.parametrize("scope", ["--local", "--worktree"])
def test_a_repository_cannot_shadow_the_operator_s_filter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scope: str
) -> None:
    copy = _global_filter(tmp_path, monkeypatch)
    marker = _probe(tmp_path, copy)
    if scope == "--worktree":
        _git(copy, "config", "extensions.worktreeConfig", "true")
        _git(copy, "config", "core.repositoryformatversion", "1")
    _git(copy, "config", scope, "filter.up.process", "sh .git/probe.sh")
    walk.git_meta(copy)
    assert not marker.exists()
    assert "filter.up.clean=" in walk.status_args(copy)


def test_a_local_key_blanks_the_whole_driver_even_with_a_global_twin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    copy = _global_filter(tmp_path, monkeypatch)
    marker = _probe(tmp_path, copy)
    _git(copy, "config", "filter.up.clean", "sh .git/probe.sh")
    state = tree_state(copy, {"app.py", "other.py", "data.txt", ".gitattributes"})
    assert not marker.exists()
    assert state.dirty == ("data.txt",)


def test_a_filter_through_a_local_include_is_the_repository_s(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    marker = _probe(tmp_path, root)
    extra = root / ".git" / "more.cfg"
    extra.write_text('[filter "inc"]\n\tclean = sh .git/probe.sh\n', encoding="utf-8")
    _git(root, "config", "include.path", "more.cfg")
    (root / ".git" / "info" / "attributes").write_text("* filter=inc\n", encoding="utf-8")
    walk.git_meta(root)
    assert not marker.exists()


# ---------------------------------------------------------------------------
# Item 7: a tracked file with a NUL byte gets a row, whatever its name
# ---------------------------------------------------------------------------


def _with_prompt_as(tmp_path: Path, name: str, data: bytes) -> Path:
    root = _companion(tmp_path)
    _git(root, "mv", "prompts/companion.md", f"prompts/{name}")
    (root / "prompts" / name).write_bytes(data)
    _commit(root)
    return root


_PROMPT = (AUDIT_FIXTURES / "persons_companion" / "prompts" / "companion.md").read_bytes()


@pytest.mark.parametrize("mode", ["self-assessment", "auditor"])
@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("companion.jinja", b"\x00" + _PROMPT),
        ("companion.prompt", _PROMPT.decode("utf-8").encode("utf-16-le")),
        ("companion.php", b"\x00<?php $p = 'Never admit you are an AI';"),
        ("companion.bin", b"\x00" + _PROMPT),
    ],
    ids=["jinja", "utf-16-prompt", "php", "bin"],
)
def test_a_tracked_nul_file_gets_a_row(tmp_path: Path, name: str, data: bytes, mode: str) -> None:
    root = _with_prompt_as(tmp_path, name, data)
    rows = _rows(root, NOT_TEXT, mode)
    assert len(rows) == 1 and f"prompts/{name}" in rows[0].why
    assert rows[0].category == UnknownCategory.COVERAGE


def test_a_known_binary_file_gets_no_row(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    (root / "logo.PNG").write_bytes(b"\x89PNG\x00\x00")
    (root / "font.woff2").write_bytes(b"wOF2\x00\x00")
    _commit(root)
    assert _rows(root, NOT_TEXT) == []


def test_an_untracked_file_of_no_known_type_gets_no_row(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    (root / "cache.store").write_bytes(b"a\x00b")
    assert _rows(root, NOT_TEXT) == []


def test_when_git_cannot_list_a_nul_file_counts_as_tracked(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    (root / "persona.jinja").write_bytes(b"\x00text")
    _commit(root)
    (root / ".git" / "index").write_bytes(b"junk")
    assert len(_rows(root, NOT_TEXT)) == 1


# ---------------------------------------------------------------------------
# Item 8: a git failure inside a repository is said, and costs only what failed
# ---------------------------------------------------------------------------


def _moved_app(tmp_path: Path, *, broken_module: bool) -> Path:
    """`app.py` under a skipped folder, `prompts/` gitignored, and a submodule."""
    module = tmp_path / "module"
    module.mkdir()
    (module / "guard.py").write_text("GUARD = 1\n", encoding="utf-8")
    _git(module, "init", "-q")
    _commit(module)
    root = _companion(tmp_path)
    _git(root, "submodule", "add", "-q", str(module), "guard")
    (root / "core" / "build").mkdir(parents=True)
    _git(root, "mv", "app.py", "core/build/app.py")
    (root / ".gitignore").write_text("prompts/\n", encoding="utf-8")
    _commit(root)
    if broken_module:
        (root / ".git" / "modules" / "guard" / "index").write_bytes(b"junk")
    return root


def test_one_broken_submodule_does_not_empty_the_list(tmp_path: Path) -> None:
    healthy = tmp_path / "healthy"
    healthy.mkdir()
    base = _rule_ids(_moved_app(healthy, broken_module=False), "auditor")
    assert len(base) > 5
    root = _moved_app(tmp_path, broken_module=True)
    assert _rule_ids(root, "auditor") == base
    rows = _rows(root, NOT_LISTED, "auditor")
    assert len(rows) == 1 and "guard" in rows[0].why
    assert rows[0].category == UnknownCategory.COVERAGE
    assert walk._tracked(root) is not None and "core/build/app.py" in walk._tracked(root)


def test_a_broken_submodule_leaves_the_commit_unknown_to_the_workbench(tmp_path: Path) -> None:
    scan = machine_scan(_moved_app(tmp_path, broken_module=True), mode="auditor")
    assert scan.state.status_failed and scan.state.tracked is None
    assert scan.tracked_not_walked is None


def test_a_broken_index_is_said_and_never_reads_as_outside_git(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    (root / ".git" / "index").write_bytes(b"junk")
    assert walk._tracked(root) is None
    rows = _rows(root, NOT_LISTED)
    assert len(rows) == 1 and "this repository" in rows[0].why


def test_a_timed_out_listing_is_said(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _bot(tmp_path)
    real = subprocess.run

    def slow(argv: list[str], *args: object, **kwargs: object) -> object:
        if "ls-files" in argv:
            raise subprocess.TimeoutExpired(argv, 1.0)
        return real(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", slow)
    assert walk._tracked(root) is None
    assert len(_rows(root, NOT_LISTED)) == 1


def test_outside_git_there_is_nothing_to_say(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    assert walk._tracked(tmp_path) == frozenset()
    assert _rows(tmp_path, NOT_LISTED) == []


# ---------------------------------------------------------------------------
# Item 9: a file that claims to be the tool's own output
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["companion.html", "assessment.md"])
def test_the_marker_line_on_a_prompt_gets_a_row(tmp_path: Path, name: str) -> None:
    text = OWN_HTML_MARKER_LINE.encode() + b"\n" + _PROMPT
    root = _with_prompt_as(tmp_path, name, text)
    rows = _rows(root, OWN_ROW)
    assert len(rows) == 1 and f"prompts/{name}" in rows[0].why
    assert rows[0].category == UnknownCategory.COVERAGE


def _persona_tree(tmp_path: Path, name: str, extra: dict) -> Path:
    root = _companion(tmp_path, name)
    persona = {"name": "ava", **extra, "system_prompt": _PROMPT.decode("utf-8")}
    _git(root, "rm", "-q", "prompts/companion.md")
    (root / "prompts").mkdir(exist_ok=True)
    (root / "prompts" / "persona.json").write_text(json.dumps(persona), encoding="utf-8")
    _commit(root)
    return root


@pytest.mark.parametrize(
    "meta",
    [
        {"schema": "aisg/bundle/1", "kind": "bundle"},
        {"schema": SCHEMA_VERSION, "kind": "audit"},
    ],
    ids=["bundle", "audit"],
)
def test_nested_words_never_skip_a_document(tmp_path: Path, meta: dict) -> None:
    root = _persona_tree(tmp_path, "nested", {"meta": meta})
    skipped: list[str] = []
    records, _units, _unknown = walk.walk(root, own_output_skipped=skipped)
    assert "prompts/persona.json" in {record.relpath for record in records}
    assert skipped == [] and _rows(root, OWN_ROW) == []


def test_a_nested_bundle_label_changes_no_finding(tmp_path: Path) -> None:
    meta = {"schema": "aisg/bundle/1", "kind": "bundle"}
    root = _persona_tree(tmp_path, "nested", {"meta": meta})
    assert _rule_ids(root) == _rule_ids(_persona_tree(tmp_path, "control", {}))


def test_a_json_that_does_not_parse_is_not_own_output(tmp_path: Path) -> None:
    head = '{"schema": "' + SCHEMA_VERSION + '", "kind": "audit", "system_prompt": "x"'
    assert walk.is_own_report("r.json", head) is False
    assert walk.is_own_report("r.json", head + "}") is True


def test_a_kind_that_is_not_a_string_never_stops_the_walk(tmp_path: Path) -> None:
    doc = {"schema": "aisg/bundle/1", "kind": ["bundle"], "meta": {"kind": "bundle"}}
    (tmp_path / "x.json").write_text(json.dumps(doc), encoding="utf-8")
    records, _units, _unknown = walk.walk(tmp_path)
    assert [record.relpath for record in records] == ["x.json"]


def test_a_sarif_that_only_nests_the_words_is_walked(tmp_path: Path) -> None:
    (tmp_path / "x.sarif").write_text(
        json.dumps({"meta": {"aisg_schema": SCHEMA_VERSION, "own_output_skipped": []}}),
        encoding="utf-8",
    )
    skipped: list[str] = []
    records, _units, _unknown = walk.walk(tmp_path, own_output_skipped=skipped)
    assert [record.relpath for record in records] == ["x.sarif"] and skipped == []


def test_a_top_level_claim_outside_the_folder_gets_a_row(tmp_path: Path) -> None:
    root = _bot(tmp_path)
    claim = {"schema": SCHEMA_VERSION, "kind": "audit", "system_prompt": "Never say you are AI."}
    (root / "persona.json").write_text(json.dumps(claim), encoding="utf-8")
    _commit(root)
    rows = _rows(root, OWN_ROW)
    assert len(rows) == 1 and "persona.json" in rows[0].why


def test_a_real_report_under_the_audit_directory_gets_no_row(tmp_path: Path) -> None:
    root, folder = _skill_tree(tmp_path)
    _phase_one(root, folder)
    (folder / "pr-body.md").write_text("# What changed\n", encoding="utf-8")
    assert _rows(root, OWN_ROW) == []


def test_a_report_with_sorted_keys_under_the_audit_directory_is_own_output(tmp_path: Path) -> None:
    doc = {"aaa": ["x" * 200] * 100, "kind": "assessment", "schema": "aisg/assessment/1"}
    report = tmp_path / ".aisafe-audit" / "assessment.json"
    report.parent.mkdir()
    report.write_text(json.dumps(doc), encoding="utf-8")
    skipped: list[str] = []
    walk.walk(tmp_path, own_output_skipped=skipped)
    assert skipped == [".aisafe-audit/assessment.json"]


# ---------------------------------------------------------------------------
# Item 10: the defects round one fixed, each pinned by what it was
# ---------------------------------------------------------------------------


def _with_fsmonitor(tmp_path: Path) -> tuple[Path, Path, str]:
    root = _bot(tmp_path)
    marker = _probe(tmp_path, root)
    _git(root, "config", "core.fsmonitor", "sh .git/probe.sh")
    return root, marker, _git(root, "rev-parse", "HEAD").strip()


def test_the_fsmonitor_fixture_does_start_under_plain_git(tmp_path: Path) -> None:
    root, marker, _commit_id = _with_fsmonitor(tmp_path)
    subprocess.run(["git", "status", "--porcelain"], cwd=root, capture_output=True, check=False)
    assert marker.exists()


def test_a_file_system_monitor_of_the_repository_never_starts(tmp_path: Path) -> None:
    root, marker, commit = _with_fsmonitor(tmp_path)
    audit.scan(audit.AuditOptions(path=str(root)))
    walk.git_meta(root)
    machine_scan(root)
    assess._at_commit(root, commit, "app.py")
    assert not marker.exists()
