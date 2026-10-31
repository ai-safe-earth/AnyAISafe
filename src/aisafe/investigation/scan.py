"""src/aisafe/investigation/scan.py
---------------------------------
The scan an investigation stands on, and the state of the tree it was taken from.

`machine_scan` runs what `aisafe audit` runs, with the options fixed by the workbench and
never by the audited tree: Python deep analysis on, every default rule, no baseline, no
`[tool.aisafe-audit]` section applied, no recorded review decision applied. Its findings
are the machine's; a person's decision is read separately, as a human input. Two files the
skill writes under `.aisafe-audit/` (`walk.WORKBENCH_INPUTS`) stay unread unless the commit
holds them: their text is not the system's, and it could close a finding. Any other file in
that folder is read and counts as dirt, because that same text would close a finding.

`tree_state` asks git, read-only, which commit the tree is at, which files it tracks and
which of them differ from the commit. A quote is checked against the files on disk, so it
is a quote "in the audited commit" only when those files are the commit's: a cited file
must be tracked, and a tracked file that differs makes the tree dirty. So does a walked file
that is not in the commit, even one `git status` never lists (gitignored, excluded, inside a
nested repository), because the rules read it; and a tracked file git does not compare
(skip-worktree, assume-unchanged). A `git status` that fails is never read as clean, and
neither is a root outside the work tree git is looking at (`core.worktree`). Git runs
through `walk.run_git`, and `git status` with the repository's filter drivers blanked, so
the audited repository's own configuration starts no program.

`tracked_not_walked` are the files of the commit the walk did not read (a skipped
directory, a binary or UTF-16 file, the size limit, the ignore marker, an exclude): every
one of them is scope an assessment did not read, and is listed as such.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from aisafe.discovery import walk
from aisafe.evidence.model import AuditContext, Finding, UnknownItem
from aisafe.policy import Policy, load_policy

__all__ = [
    "CODE_LANGS_READ",
    "TEXT_SUFFIXES",
    "MachineScan",
    "TreeState",
    "machine_scan",
    "reading_of",
    "tree_state",
]

_GIT_TIMEOUT = 60.0
# How a cited file's language is read. Python has the syntax tree behind it; JS/TS are
# read by the investigator with no deterministic deep analysis behind the reading; prompt
# and configuration text is read as text. Every other code language is unsupported.
CODE_LANGS_READ: dict[str, str] = {"python": "deep", "typescript": "read"}
# Files read as text: prompt material, templates, configuration, documents. A suffix the
# walk does not know (PHP, Swift, C, Dart, ...) is code in a language this version does not
# read, and so is a shell script.
TEXT_SUFFIXES = frozenset(
    {
        "",
        ".md",
        ".markdown",
        ".txt",
        ".rst",
        ".prompt",
        ".jinja",
        ".jinja2",
        ".j2",
        ".mustache",
        ".hbs",
        ".handlebars",
        ".liquid",
        ".tmpl",
        ".tpl",
        ".njk",
        ".html",
        ".htm",
        ".xml",
        ".csv",
        ".tsv",
        ".yaml",
        ".yml",
        ".json",
        ".jsonl",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".env",
        ".properties",
    }
)
_SHELL_SUFFIXES = frozenset({".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd"})
# JS/TS the walk has no language for: read like the rest of JS/TS, with no deep analysis.
_JS_TS_SUFFIXES = frozenset({".mts", ".cts", ".vue", ".svelte"})


def reading_of(relpath: str, lang: str | None) -> str:
    """`deep`, `read`, `text` or `unsupported` for a walked file of language `lang`."""
    if lang is None:
        return "unsupported"
    if lang in CODE_LANGS_READ:
        return CODE_LANGS_READ[lang]
    suffix = PurePosixPath(relpath).suffix.lower()
    name = PurePosixPath(relpath).name.lower()
    if suffix in _JS_TS_SUFFIXES:
        return "read"
    if name.startswith(".env"):
        return "text"
    if suffix in _SHELL_SUFFIXES:
        return "unsupported"
    if lang in ("config", "other") and suffix in TEXT_SUFFIXES:
        return "text"
    if lang == "config" and name in ("dockerfile",):
        return "text"
    return "unsupported"


@dataclass(frozen=True)
class TreeState:
    """`commit`: HEAD, or None outside git. `dirty`: tracked files that differ from it or
    that git does not compare, and walked files that are not in it. `tracked`: the files of
    the commit, submodules included, None outside git. `status_failed`: git could not say,
    so the tree is not taken for clean."""

    commit: str | None
    is_git: bool
    dirty: tuple[str, ...] = ()
    tracked: frozenset[str] | None = None
    status_failed: bool = False

    @property
    def clean(self) -> bool:
        return not self.dirty and not self.status_failed

    def to_dict(self) -> dict[str, Any]:
        return {
            "commit": self.commit,
            "git": self.is_git,
            # None when git could not say: unknown, never an empty list.
            "dirty": None if self.status_failed else list(self.dirty),
            "status_failed": self.status_failed,
        }


@dataclass
class MachineScan:
    root: Path
    mode: str
    ctx: AuditContext
    findings: list[Finding]
    unknown: list[UnknownItem]
    rules: list[Any]
    state: TreeState
    policy: Policy
    walked: dict[str, Any] = field(default_factory=dict)
    # None when git could not list the commit's files: unknown, never empty.
    tracked_not_walked: list[str] | None = field(default_factory=list)

    def lang_of(self, relpath: str) -> str | None:
        record = self.walked.get(relpath)
        return None if record is None else getattr(record, "lang", None)

    def reading_of(self, relpath: str) -> str:
        """`deep`, `read`, `text` or `unsupported` for a walked file."""
        if relpath not in self.walked:
            return "unsupported"
        return reading_of(relpath, self.lang_of(relpath))

    def in_commit(self, relpath: str) -> bool:
        """A cited file is part of the audited commit: tracked by git (always true outside
        git, where there is no commit to be part of)."""
        if not self.state.is_git or self.state.tracked is None:
            return True
        return relpath in self.state.tracked


def _git(args: list[str], root: Path, **kwargs: Any) -> str | None:
    """stdout of a read-only git command run in `root`, or None when it fails."""
    kwargs.setdefault("timeout", _GIT_TIMEOUT)
    return walk._git(args, root, **kwargs)


def tree_state(
    root: Path,
    walked: set[str],
    skipped: set[str] = frozenset(),
    inputs: set[str] = frozenset(),
) -> TreeState:
    """The commit `root` is at, the files it tracks and the paths that differ (see the
    module docstring). `skipped` are paths the walk named as the tool's own output. `inputs`
    are files outside the commit that the assessment lists as inputs of its own (evaluation
    reports, review records); they are named there, so being gitignored is no dirt. Only
    that: an input git tracks and that differs, or an untracked one, stays dirty."""
    head = _git(["rev-parse", "HEAD"], root)
    if head is None:
        return TreeState(commit=None, is_git=False)
    commit = head.strip()
    tree = walk.git_tree(root, _git)
    tracked = None if tree.tracked is None or tree.unlisted else frozenset(tree.tracked)
    if tracked is None or tree.status_failed:
        return TreeState(commit=commit, is_git=True, tracked=tracked, status_failed=True)
    dirty = {rel for rel in tree.changed if rel not in skipped}
    dirty |= {rel for rel in tree.untracked if rel in walked and rel not in skipped}
    for rel in walked:
        # A submodule's `.git` pointer file is walked and belongs to no commit.
        if rel in skipped or PurePosixPath(rel).name == ".git":
            continue
        if rel in tree.uncompared or (rel not in tracked and rel not in inputs):
            dirty.add(rel)
    return TreeState(commit=commit, is_git=True, dirty=tuple(sorted(dirty)), tracked=tracked)


def machine_scan(
    path: str | Path,
    *,
    mode: str = "self-assessment",
    policy: Policy | None = None,
    evaluation_report: str | None = None,
) -> MachineScan:
    """The workbench's scan of `path` (see the module docstring). `evaluation_report` is an
    `aisafe evaluate` report read as `audit --evaluation-report` reads it: in auditor mode
    the only evaluation that counts. Raises on a missing path and on a policy error."""
    from aisafe.audit import AuditOptions, scan

    policy = policy or load_policy()
    options = AuditOptions(
        path=str(path),
        deep="python",
        mode=mode,
        evaluation_report=evaluation_report,
        workbench=True,
    )
    ctx, findings, unknown, rules = scan(options, policy)
    walked = {record.relpath: record for record in ctx.files}
    skipped = set(getattr(ctx.inventory, "own_output_skipped", None) or [])
    inputs = {str(getattr(report, "file", "")) for report in ctx.evaluation}
    inputs |= {str(row.get("file")) for row in ctx.inventory.review_records or []}
    state = tree_state(ctx.root, set(walked), skipped, inputs)
    not_walked: list[str] | None = None if state.is_git and state.tracked is None else []
    if state.tracked is not None:
        not_walked = sorted(p for p in state.tracked if p not in walked and p not in skipped)
    return MachineScan(
        root=ctx.root,
        mode=mode,
        ctx=ctx,
        findings=findings,
        unknown=unknown,
        rules=rules,
        state=state,
        policy=policy,
        walked=walked,
        tracked_not_walked=not_walked,
    )
