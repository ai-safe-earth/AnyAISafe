"""src/aisafe/discovery/walk.py
----------------------------
File enumeration for `aisafe audit`: gitignore-lite, size/binary/marker guards, language and
unit detection, plus the read-only git helpers (`git_meta`, `git_tree`, `file_age`).

Rules that hold here:

- `.env*` files are always enumerated, even when `.gitignore` excludes them. The
  matcher's `match()` carries that exception; `would_ignore()` is the raw answer and is
  what sets `FileRecord.gitignored`. Without this the highest-blast-radius credentials on
  a developer machine would be invisible while the report implied `.env*` was covered.
- Dotfiles and dotdirs are walked: host configs (`.claude/`, `.cursor/`, `.codex/`) live
  there. Only `SKIP_DIRS`, `--exclude` and the gitignore matcher prune.
- A file git tracks is part of the commit, so `.gitignore` never hides it: git itself does
  not ignore a tracked file. A tracked file under a `SKIP_DIRS` directory is read with
  `WalkOptions.read_tracked` (auditor mode), where a folder name is the audited team's
  claim; without it the directory stays pruned and one UNKNOWN row names the files. A file
  skipped as not text (a NUL byte anywhere in it, a UTF-16 or UTF-32 byte order mark, a
  Git LFS pointer whose real content was never fetched) gets one UNKNOWN row unless its
  suffix is on the known-binary list. When git fails inside a repository the list is not
  known: that is one UNKNOWN row, never the silence of "outside git", and one submodule
  that cannot be listed costs only its own files. A tracked file the walk never met and
  no row names (a sparse checkout, a submodule not checked out, a folder renamed by case
  only, a deleted file) gets one row too; on Windows spelling differs by case without
  being another file, so the comparison ignores case there.
- Outside git no commit lists what the walk stepped over, so the walk does: `unread_files`
  names every file left unread (marker, gitignore line, exclude, size limit, not text,
  symlink, read error) and `unread_dirs` every directory it did not go into. A directory
  is named and never walked, so a large `node_modules` costs one line. A cache
  (`CACHE_OWN_TYPES`) and version control data are left out, unless the cache holds a file
  of another type, which nothing but a person put there. The audit's own output has its
  own list. One UNKNOWN row counts both lists, the known-binary suffixes left out, and the
  workbench reads the lists themselves.
- A junction or a directory symlink is a link (`is_link`), not a folder of the tree: on
  Windows `os.path.islink` says False for a junction and `os.walk` goes through it, which
  read other folders' files as the tree's own and walked a loop.
- The walker never raises on an unreadable file or directory; it counts and reports
  once under UNKNOWN. Silence is never a pass.
- `subprocess` is used only for read-only `git` commands, never with `shell=True`, never
  with `check=True`, always with a timeout.
- The audit's own output is not audited. A `.json` that parses to a document with the
  schema marker and `"kind": "audit"` or `"kind": "inventory"` at its top level, a `.sarif`
  (or `.json`) whose first run opens with the property bag the SARIF renderer writes first
  (`aisg_schema` then `own_output_skipped`), and an html document or the assessment's
  markdown whose first line is `OWN_HTML_MARKER_LINE`, are skipped and named in
  `own_output_skipped`, so a report written into the tree does not reproduce every finding
  it lists on the next run. The same words nested inside another document skip nothing, and
  `audit.py` gives every skip outside `AUDIT_DIR` an UNKNOWN row. A baseline
  (`kind: audit-baseline`) is still scanned: an accepted reason that quotes the literal
  it accepts must show up. So is every other document of the schema family, the lint
  SARIF included: it carries the same `aisg_schema` marker but not the audit's second
  key. No `SKIP_DIRS` entry does this, so measure and probe reports placed next to the
  audit report are still discovered as evidence.
- The head every marker check reads is decoded the way `read_text` decodes the whole
  file: UTF-8 with the BOM stripped. A BOM before `OWN_HTML_MARKER_LINE` used to defeat
  `is_own_html`, so the html report fell through to the plain marker skip.
- A file over `max_size` is not read, and that is reported: the count, the limit and the
  first few paths go under UNKNOWN, and `oversize_skipped` receives every path so the
  caller can put the count on the inventory. Silence is never a pass.
- A file carrying the ignore marker in its first five lines is skipped, and the skip is
  named: `marker_skipped` receives every such path, so the caller can list it under
  UNKNOWN and an assessment can list it as unassessed scope. A marker is the tree's own
  claim about itself; in auditor mode (`WalkOptions.honour_marker=False`,
  `skip_own_output=False`) neither the marker nor the own-output heads skip anything, so
  the team being audited cannot hide a file with one comment line. On any other file the
  html marker line is that same ignore marker, never own output.
- Every git command goes through `run_git`, the one place that starts git: a repository's
  configuration names programs git would start, and the audited repository is not trusted.
  It takes git's absolute path from `PATH` alone (`git_program`), so a `git.exe` committed
  to the folder the audit runs from never starts, and it runs with `GIT_SAFE` and with
  `GIT_ALLOW_PROTOCOL` set (`git_env`). `git status` also blanks the filter drivers the
  repository can write (`status_args`) and never goes into a submodule by itself, because a
  submodule has its own configuration; `git_tree` reads each one in turn. A gitlink whose
  path leaves the tree is no submodule of it: git never runs there. A folder laid out like
  a bare repository is never taken for one (`safe.bareRepository=explicit`), so a folder a
  clone delivered cannot bring its own configuration. Git is not started at all when the
  repository's files name a path on another machine (`network_reference`): reading it
  would open a connection, and the audit promises none. The tree is then unknown.
- `.aisafe-audit/` (`AUDIT_DIR`) is never pruned by `.gitignore`, in either the directory
  or the file branch. The skill puts every artefact there and proposes the gitignore line
  for it, so the measure and probe reports the skill itself produces would otherwise stop
  being evidence the moment the line landed. As with `.env*`, `would_ignore()` stays raw
  and `FileRecord.gitignored` still says so. The pre-rename `.aisg-audit/`
  (`LEGACY_AUDIT_DIRS`) is exempt the same way, and the pre-rename ignore marker and
  html marker line are honoured: read, never written.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
import tempfile
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator

from aisafe.discovery.patterns import (
    AUDIT_DIR,
    CACHE_OWN_NAMES,
    CACHE_OWN_TYPES,
    ENV_FILE_RE,
    IGNORE_MARKER,
    LANG_BY_EXT,
    LEGACY_AUDIT_DIRS,
    LEGACY_IGNORE_MARKERS,
    LEGACY_OWN_HTML_MARKER_LINES,
    NOTHING_WRITTEN_DIRS,
    OWN_HTML_MARKER_LINE,
    SKIP_DIRS,
    UNIT_MANIFESTS,
)
from aisafe.evidence.model import SCHEMA_VERSION, Unit, UnknownCategory, UnknownItem

__all__ = [
    "DEFAULT_MAX_SIZE",
    "GIT_SAFE",
    "HEAD_BYTES",
    "PR_BODY",
    "WORKBENCH_INPUTS",
    "MARKER_LINES",
    "GIT_TIMEOUT",
    "ROOT_UNIT_ID",
    "WalkOptions",
    "FileRecord",
    "GitIgnore",
    "GitTree",
    "read_text",
    "has_ignore_marker",
    "is_own_report",
    "is_own_html",
    "unit_of",
    "walk",
    "git_env",
    "git_meta",
    "git_program",
    "git_tree",
    "file_age",
    "in_audit_dir",
    "is_link",
    "network_reference",
    "run_git",
    "status_args",
]

DEFAULT_MAX_SIZE = 2 * 1024 * 1024
HEAD_BYTES = 8 * 1024
MARKER_LINES = 5
GIT_TIMEOUT = 10.0
# What makes a git command safe on a repository nobody here trusts. Its `.git/config` can
# name a file-system monitor, a hooks directory and a signature program.
# `--no-optional-locks` keeps `git status` from rewriting the index. A replace ref shows
# another commit's content under the same commit id, so replace refs stay unread.
#
# A partial clone fetches a missing object through a transport the configuration names, and
# a transport can be a program: `alias.remote-<name>` with a URL `<name>::x`, or
# `remote.<name>.vcs`. A repository's own `protocol.<name>.allow` beats `protocol.allow`, so
# only the environment can close them: see `git_env`. `GIT_ALLOW_PROTOCOL` is a list and has
# no empty form, so `none` is a name the configuration can ask for too; the blank alias is
# what stops a helper called `none`.
#
# A folder holding HEAD, config, objects/ and refs/ reads to git as a bare repository, and
# a commit can deliver such a folder: `safe.bareRepository=explicit` keeps git from taking
# its `config` for the audited repository's. Only the command line can set that key.
GIT_SAFE: tuple[str, ...] = (
    "--no-optional-locks",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
    "-c",
    f"core.hooksPath={os.devnull}",
    "-c",
    "log.showSignature=false",
    "-c",
    "core.useReplaceRefs=false",
    "-c",
    "alias.remote-none=",
    "-c",
    "safe.bareRepository=explicit",
)
_NO_TRANSPORT = "none"
_GIT_NAME = "git.exe" if os.name == "nt" else "git"
# Hashing every tracked file against the commit takes longer than a question about refs.
_COMPARE_TIMEOUT = 60.0
# `git config --show-scope`: where the operator wrote a setting, not the repository.
_OPERATOR_SCOPES = frozenset({"system", "global"})
# `git -c` cannot override a key with `=` in it, so a filter driver is named only by these.
_FILTER_NAME_RE = re.compile(r"[A-Za-z0-9._-]+")
# The `lfs.` keys git-lfs writes into a repository itself. Any other can name a program
# (`lfs.extension.<name>.clean`, `lfs.customtransfer.<name>.path`) or a folder to write to
# (`lfs.storage`), and git-lfs starts for a file `.gitattributes` gives its filter.
_LFS_OWN_KEY_RE = re.compile(r"lfs\.(?:repositoryformatversion|.+\.(?:access|locksverify))")
_GITLINK_MODE = "160000"
_MAX_SUBMODULE_DEPTH = 8
# A value that starts with two slashes, either way round, is a path on another machine.
# `%(prefix)/` is git's own spelling of a folder, and what follows it can start one too.
_HOST_VALUE_RE = re.compile(r'\s*"?(?:%\(prefix\)/)?[/\\]{2}')
_CONFIG_HOST_RE = re.compile(r"([A-Za-z][A-Za-z0-9-]*)[ \t]*=[ \t]*(?:%\(prefix\)/)?[/\\]{2}")
_CONFIG_INCLUDE_RE = re.compile(r"\bpath[ \t]*=[ \t]*([^\r\n;#]+)", re.IGNORECASE)
# Remote addresses: git status never opens one, and no transport is allowed (`git_env`). A
# team's remote on a file share is ordinary.
_REMOTE_KEYS = frozenset({"url", "pushurl", "insteadof", "pushinsteadof"})
# git's C quoting (`unquote_c_style`), which reads an object alternate that starts with a
# quote: `"\057\057host/share"` is `//host/share`. A configuration value has fewer escapes,
# and no octal. `_C_SPACE` is C's `isspace`, which git's parsers use.
_C_ESCAPES = {
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "\\": "\\",
    '"': '"',
}
_CONFIG_ESCAPES = {"t": "\t", "b": "\b", "n": "\n", "\\": "\\", '"': '"'}
_OCTAL = "01234567"
_C_SPACE = " \t\n\v\f\r"
_GIT_FILE_LIMIT = 16 * 1024 * 1024
_MAX_GIT_FILES = 64
ROOT_UNIT_ID = "u0"
ROOT_UNIT_PATH = "."

_MANIFEST_LANG: dict[str, str] = {
    "pyproject.toml": "python",
    "setup.py": "python",
    "requirements.txt": "python",
    "package.json": "typescript",
    "go.mod": "go",
    "Cargo.toml": "rust",
    "pom.xml": "jvm",
    "build.gradle": "jvm",
    "Gemfile": "ruby",
    "*.csproj": "dotnet",
}
_NON_CODE_LANGS = frozenset({"config", "other"})
_SKIP_NAMES = frozenset(s for s in SKIP_DIRS if "/" not in s)
_SKIP_PATHS = frozenset(s for s in SKIP_DIRS if "/" in s)
_SHA_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")

# The toolchain's own JSON output (the audit's report or inventory, `aisafe attest`'s
# attestation): the exact quoted forms `json.dumps` writes, with optional whitespace
# after the colon. `"kind": "audit-baseline"` does not match the second one.
_OWN_SCHEMA_RE = re.compile(r'"schema":\s*"' + re.escape(SCHEMA_VERSION) + '"')
_OWN_KIND_RE = re.compile(r'"kind":\s*"(?:audit|inventory|attestation)"')
# The audit's own SARIF: `report.to_sarif` writes the run's property bag first, and its
# first two keys in this order. The lint SARIF carries `aisg_schema` too, so the marker
# alone would skip a document that is not ours.
_OWN_SARIF_RE = re.compile(
    r'"aisg_schema":\s*"' + re.escape(SCHEMA_VERSION) + r'",\s*"own_output_skipped":'
)
_OWN_REPORT_SUFFIXES = (".json", ".sarif")
# The files the toolchain writes the html marker line into: the html report and
# assessment.html, wherever `-o` puts them, and assessment.md (`assessment/cli.write_outputs`).
_OWN_HTML_SUFFIXES = (".html", ".htm")
_OWN_MARKDOWN_NAMES = frozenset({"assessment.md"})
# A byte order mark of UTF-16 or UTF-32: text the walk does not decode.
_WIDE_BOMS = (b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff")
# What git-lfs leaves in the tree when the real file was not fetched: never over this size.
_LFS_POINTER_HEADS = (
    b"version https://git-lfs.github.com/spec/v1",
    b"version https://hawser.github.com/spec/v1",
)
_LFS_POINTER_LIMIT = 1024
# The bit of a Windows reparse tag that says "this name stands for another one": a junction
# or a symlink. A cloud placeholder has a reparse tag too, and it is the file itself.
_REPARSE_NAME_SURROGATE = 0x20000000
# File types that are binary by nature, where a NUL byte says nothing. `.bin` and `.dat` are
# not here: either can hold anything.
_BINARY_SUFFIXES = frozenset(
    f".{suffix}"
    for suffix in (
        "7z avi bmp bz2 class db dll dylib eot exe flac gif gz ico jar jpeg jpg lib mkv mov mp3 "
        "mp4 npy npz o obj ogg onnx otf pdf pkl png pt pth pyc pyd rar safetensors so sqlite "
        "sqlite3 tar tgz tif tiff ttf wasm wav webm webp woff woff2 xz zip"
    ).split()
)
# What the skill writes under `AUDIT_DIR` that is neither a report nor a parsed input. Their
# words are not the audited system's: a reason or a pull request text that names a helpline
# would close AUD-1108. Unless the commit holds them, `WalkOptions.skip_untracked` leaves
# them unread, the way a gitignored file is unread.
PR_BODY = f"{AUDIT_DIR}/pr-body.md"
WORKBENCH_INPUTS: tuple[str, ...] = (f"{AUDIT_DIR}/audit-baseline.json", PR_BODY)
# The workbench documents: investigation records and their validation, skeptic passes,
# investigation plans, assessments, engagements, evidence requests, auditee responses, QA
# sign-offs, a person's sign-offs and bundle manifests. Their quotes would re-report every
# line they cite. A head match on the exact schema label and the kind that goes with it,
# like the audit report's.
_OWN_WORKBENCH: dict[str, str] = {
    name: name
    for name in (
        "investigation",
        "investigation-validation",
        "investigation-plan",
        "skeptic",
        "assessment",
        "engagement",
        "bundle",
        "evidence-requests",
        "auditee-response",
        "qa-signoff",
        "signoff",
    )
}
_OWN_WORKBENCH_RE = re.compile(
    r'"schema":\s*"aisg/('
    + "|".join(re.escape(k) for k in sorted(_OWN_WORKBENCH, key=len, reverse=True))
    + r')/1"'
)


# ---------------------------------------------------------------------------
# Options and records
# ---------------------------------------------------------------------------


@dataclass
class WalkOptions:
    exclude: tuple[str, ...] = ()
    include_ignored: bool = False
    max_size: int = DEFAULT_MAX_SIZE
    follow_symlinks: bool = False
    # A file-scoped run (`aisafe audit --only PATH`): the whole tree is still enumerated,
    # so gitignore, excludes, the marker and the size limit apply exactly as in a full
    # run and the units are the same; only the records handed on are filtered. A path
    # the walk never saw is one UNKNOWN row, never a silent no-op.
    only: tuple[str, ...] = ()
    # Files left unread and named as own output, unless the commit holds them.
    skip_untracked: tuple[str, ...] = ()
    # Auditor mode turns both off: the tree's own claims about itself skip nothing.
    honour_marker: bool = True
    skip_own_output: bool = True
    # Auditor mode turns this on: a `SKIP_DIRS` directory is walked for the files git
    # tracks in it, and only for those.
    read_tracked: bool = False


@dataclass
class FileRecord:
    """One enumerated file. `relpath` is POSIX and relative to the walk root."""

    path: Path
    relpath: str
    lang: str
    unit: str
    size: int
    gitignored: bool = False


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _norm_rel(relpath: str) -> str:
    rel = str(relpath).replace("\\", "/").strip("/")
    while rel.startswith("./"):
        rel = rel[2:]
    return "" if rel == "." else rel


def _clean_rel(rel: str) -> str:
    """`rel` with what UTF-8 cannot write replaced: a file name can hold a lone surrogate,
    and a report, a fingerprint or a rule that encodes it would stop for the whole tree."""
    return rel.encode("utf-8", "replace").decode("utf-8")


def _join(dir_rel: str, name: str) -> str:
    return _clean_rel(f"{dir_rel}/{name}" if dir_rel else name)


def _fold(rel: str) -> str:
    """`rel` for comparing with git's spelling: Windows does not tell `Build` from `build`."""
    return rel.casefold() if os.name == "nt" else rel


def _ancestors(rel: str) -> list[str]:
    parts = rel.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]


def is_link(path: str | os.PathLike[str]) -> bool:
    """`path` is a symlink or a Windows junction. Never raises: `os.path.islink` swallows
    OSError, and `Path.is_symlink` does not."""
    if os.path.islink(path):
        return True
    try:
        return bool(getattr(os.lstat(path), "st_reparse_tag", 0) & _REPARSE_NAME_SURROGATE)
    except (OSError, ValueError):
        return False


def _is_env_file(name: str) -> bool:
    return ENV_FILE_RE.match(name) is not None


def _lang_for(name: str) -> str:
    if _is_env_file(name) or name.lower() == "dockerfile":
        return "config"
    suffix = os.path.splitext(name)[1]
    return LANG_BY_EXT.get(suffix) or LANG_BY_EXT.get(suffix.lower()) or "other"


def _manifest_in(filenames: Sequence[str]) -> str | None:
    """The first `UNIT_MANIFESTS` entry present in a directory listing, else None."""
    names = set(filenames)
    for manifest in UNIT_MANIFESTS:
        if "*" in manifest:
            hits = sorted(n for n in names if fnmatch.fnmatchcase(n, manifest))
            if hits:
                return hits[0]
        elif manifest in names:
            return manifest
    return None


def _manifest_language(manifest_name: str) -> str:
    for pattern, lang in _MANIFEST_LANG.items():
        if fnmatch.fnmatchcase(manifest_name, pattern):
            return lang
    return "unknown"


# ---------------------------------------------------------------------------
# gitignore-lite
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Rule:
    base: str  # directory holding the ignore file, "" for the root
    regex: re.Pattern[str]
    negate: bool
    dir_only: bool


def _glob_to_regex(glob: str) -> str:
    """gitignore glob -> regex body. `*`/`?` stop at `/`; `**` crosses it."""
    out: list[str] = []
    i, n = 0, len(glob)
    while i < n:
        c = glob[i]
        if c == "*":
            if glob.startswith("**/", i):
                out.append("(?:.*/)?")
                i += 3
            elif glob.startswith("**", i):
                out.append(".*")
                i += 2
            else:
                out.append("[^/]*")
                i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            j = glob.find("]", i + 1)
            if j == -1:
                out.append(re.escape(c))
                i += 1
            else:
                body = glob[i + 1 : j]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = j + 1
        elif c == "\\" and i + 1 < n:
            out.append(re.escape(glob[i + 1]))
            i += 2
        else:
            out.append(re.escape(c))
            i += 1
    return "".join(out)


def _compile_rule(base: str, raw: str) -> _Rule | None:
    line = raw.rstrip("\r\n")
    if not line.strip() or line.lstrip().startswith("#"):
        return None
    line = re.sub(r"(?<!\\)\s+$", "", line)
    negate = False
    if line.startswith("!"):
        negate = True
        line = line[1:]
    elif line.startswith("\\!") or line.startswith("\\#"):
        line = line[1:]
    dir_only = line.endswith("/")
    line = line.rstrip("/")
    if not line:
        return None
    # A slash at the start or in the middle anchors the pattern to the ignore file's
    # directory; a bare name matches its basename at any depth below it.
    anchored = "/" in line
    prefix = "^" if anchored else "(?:^|.*/)"
    try:
        regex = re.compile(prefix + _glob_to_regex(line.lstrip("/")) + "$")
    except re.error:
        return None
    return _Rule(base, regex, negate, dir_only)


class GitIgnore:
    """Minimal `.gitignore` matcher: enough for pruning, not a git reimplementation.

    Supported: blank and comment lines, leading `/` anchoring, trailing `/` for
    directories, `*` (does not cross `/`), `**` (does), `?`, `[...]`, `!` negation with
    last-match-wins, nested ignore files via `add()`, and "an ignored directory ignores
    everything beneath it". Case-sensitive on every platform so results do not depend on
    where the audit runs.
    """

    def __init__(self) -> None:
        self._rules: list[_Rule] = []

    @classmethod
    def load(cls, dir: Path) -> GitIgnore:
        matcher = cls()
        text = read_text(Path(dir) / ".gitignore")
        if text:
            matcher.add("", text)
        return matcher

    def add(self, dir_relpath: str, text: str) -> None:
        base = _norm_rel(dir_relpath)
        for raw in text.splitlines():
            rule = _compile_rule(base, raw)
            if rule is not None:
                self._rules.append(rule)

    def __len__(self) -> int:
        return len(self._rules)

    def _matches(self, rel: str, is_dir: bool) -> bool:
        ignored = False
        for rule in self._rules:
            if rule.dir_only and not is_dir:
                continue
            if rule.base:
                if not rel.startswith(rule.base + "/"):
                    continue
                sub = rel[len(rule.base) + 1 :]
            else:
                sub = rel
            if rule.regex.match(sub):
                ignored = not rule.negate
        return ignored

    def would_ignore(self, relpath: str, is_dir: bool = False) -> bool:
        """Raw answer: would git ignore this path? No `.env*` exception."""
        rel = _norm_rel(relpath)
        if not rel:
            return False
        # git never re-includes a file whose parent directory is excluded.
        for ancestor in _ancestors(rel):
            if self._matches(ancestor, True):
                return True
        return self._matches(rel, is_dir)

    def match(self, relpath: str, is_dir: bool = False) -> bool:
        """
        `would_ignore` with the hard exceptions: a `.env*` file is never ignored, and
        neither is `AUDIT_DIR` (or a `LEGACY_AUDIT_DIRS` entry) or anything under it.
        """
        rel = _norm_rel(relpath)
        if not is_dir and _is_env_file(rel.rsplit("/", 1)[-1]):
            return False
        for audit_dir in (AUDIT_DIR, *LEGACY_AUDIT_DIRS):
            if rel == audit_dir or rel.startswith(audit_dir + "/"):
                return False
        return self.would_ignore(rel, is_dir)


# ---------------------------------------------------------------------------
# File reading
# ---------------------------------------------------------------------------


def read_text(path: Path, max_size: int | None = None) -> str | None:
    """Decode a file as UTF-8 (errors replaced, BOM stripped).

    Returns None when the file is larger than `max_size`, has a NUL byte in its first
    8 KiB, or cannot be read.
    """
    try:
        with open(path, "rb") as fh:
            if max_size is not None and os.fstat(fh.fileno()).st_size > max_size:
                return None
            head = fh.read(HEAD_BYTES)
            if b"\x00" in head:
                return None
            data = head + fh.read()
    except OSError:
        return None
    text = data.decode("utf-8", errors="replace")
    if text.startswith("\ufeff"):
        text = text[1:]
    return text


def has_ignore_marker(head: str) -> bool:
    """True when `IGNORE_MARKER` (or a `LEGACY_IGNORE_MARKERS` entry) appears in the first
    five lines."""
    markers = (IGNORE_MARKER, *LEGACY_IGNORE_MARKERS)
    return any(m in line for line in head.splitlines()[:MARKER_LINES] for m in markers)


def _own_head(name: str, head: str) -> bool:
    """The file's head carries the words of the toolchain's own JSON or SARIF: worth parsing."""
    lower = name.lower()
    if not lower.endswith(_OWN_REPORT_SUFFIXES):
        return False
    if _OWN_SARIF_RE.search(head):
        return True
    if not lower.endswith(".json"):
        return False
    workbench = _OWN_WORKBENCH_RE.search(head)
    if workbench is not None:
        kind = _OWN_WORKBENCH[workbench.group(1)]
        if re.search(r'"kind":\s*"' + re.escape(kind) + '"', head):
            return True
    return bool(_OWN_SCHEMA_RE.search(head)) and bool(_OWN_KIND_RE.search(head))


def _own_sarif(doc: dict[str, Any]) -> bool:
    runs = doc.get("runs")
    run = runs[0] if isinstance(runs, list) and runs else None
    bag = run.get("properties") if isinstance(run, dict) else None
    return (
        isinstance(bag, dict)
        and bag.get("aisg_schema") == SCHEMA_VERSION
        and "own_output_skipped" in bag
    )


def _own_json(doc: dict[str, Any]) -> bool:
    schema, kind = doc.get("schema"), doc.get("kind")
    if schema == SCHEMA_VERSION:
        return kind in ("audit", "inventory", "attestation")
    return isinstance(kind, str) and kind in _OWN_WORKBENCH and schema == f"aisg/{kind}/1"


def is_own_report(name: str, text: str) -> bool:
    """
    True when the whole file `text` is the audit's own output: a `.json` with the schema
    marker and `"kind": "audit"` (or `"kind": "inventory"`) at its top level, or a `.sarif`
    (or `.json`) whose first run holds the property bag `aisg_schema` then
    `own_output_skipped`. A baseline (`"kind": "audit-baseline"`) and every other document
    of the schema family stay scanned, and so does a document that only nests those words.
    """
    if not _own_head(name, text):
        return False
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        return False
    if not isinstance(doc, dict):
        return False
    return _own_sarif(doc) or (name.lower().endswith(".json") and _own_json(doc))


def is_own_html(head: str, name: str | None = None) -> bool:
    """
    True when the first line is exactly `OWN_HTML_MARKER_LINE` (or a
    `LEGACY_OWN_HTML_MARKER_LINES` entry): the audit's own html report.
    `has_ignore_marker` would drop it too, but silently; this names it.

    `name`, when given, must be a file the toolchain writes that line into. On a prompt or
    a configuration file the same line is a hand-placed ignore marker, which is reported.
    """
    if name is not None:
        lower = name.lower()
        if not lower.endswith(_OWN_HTML_SUFFIXES) and lower not in _OWN_MARKDOWN_NAMES:
            return False
    first = head.split("\n", 1)[0].rstrip("\r")
    return first == OWN_HTML_MARKER_LINE or first in LEGACY_OWN_HTML_MARKER_LINES


# ---------------------------------------------------------------------------
# Units
# ---------------------------------------------------------------------------


def unit_of(relpath: str, units: Sequence[Unit]) -> str:
    """Id of the nearest unit whose root is the file's directory or an ancestor of it.

    The repo root unit (`root == "."`) is the fallback and is always present.
    """
    rel = _norm_rel(relpath)
    best_id = ROOT_UNIT_ID
    best_len = -1
    for unit in units:
        root = "" if unit.root in ("", ROOT_UNIT_PATH) else unit.root
        if root and not (rel == root or rel.startswith(root + "/")):
            continue
        if len(root) > best_len:
            best_id, best_len = unit.id, len(root)
    return best_id


def _build_units(
    manifests: dict[str, str | None], langs_by_dir: Counter[tuple[str, str]]
) -> list[Unit]:
    """Number units u0.. in sorted root order; the repo root is always u0."""
    others = sorted(r for r in manifests if r != "")
    units: list[Unit] = []
    for index, root in enumerate(["", *others]):
        manifest = manifests.get(root)
        language = _manifest_language(manifest) if manifest else "unknown"
        units.append(
            Unit(
                id=f"u{index}",
                root=root or ROOT_UNIT_PATH,
                manifest=_join(root, manifest) if manifest else None,
                language=language,
            )
        )
    root_unit = units[0]
    if root_unit.manifest is None:
        votes: Counter[str] = Counter()
        for (unit_id, lang), count in langs_by_dir.items():
            if unit_id == ROOT_UNIT_ID and lang not in _NON_CODE_LANGS:
                votes[lang] += count
        if votes:
            top = max(votes.values())
            root_unit.language = sorted(lang for lang, c in votes.items() if c == top)[0]
    return units


# ---------------------------------------------------------------------------
# Walk
# ---------------------------------------------------------------------------


def _normalise_excludes(exclude: Sequence[str]) -> tuple[str, ...]:
    out: list[str] = []
    for entry in exclude:
        rel = _norm_rel(entry)
        if rel.endswith("/**"):
            rel = rel[:-3]
        if rel:
            out.append(rel)
    return tuple(out)


def _excluded(rel: str, exclude: tuple[str, ...]) -> bool:
    if not exclude:
        return False
    ancestors = _ancestors(rel)
    for entry in exclude:
        if rel == entry or rel.startswith(entry + "/"):
            return True
        if fnmatch.fnmatchcase(rel, entry):
            return True
        if any(fnmatch.fnmatchcase(a, entry) for a in ancestors):
            return True
    return False


def _skip_dir(name: str, rel: str) -> bool:
    if name in _SKIP_NAMES:
        return True
    return any(rel == p or rel.endswith("/" + p) for p in _SKIP_PATHS)


def _tracked(
    root: Path, unlisted: list[str] | None = None, network: list[str] | None = None
) -> frozenset[str] | None:
    """The files git tracks under `root`, submodules included, relative to it; empty outside
    git. None when git fails inside a repository, which must not read as outside git.
    `unlisted`, when given, receives the submodules git could not list: the rest stands.
    `network` receives the submodule files that name a path on another machine."""
    tree = git_tree(root, compare=False)
    if network is not None:
        network.extend(tree.network)
    if tree.tracked is None:
        inside = any((folder / ".git").exists() for folder in (root, *root.parents))
        return None if inside else frozenset()
    if unlisted is not None:
        unlisted.extend(sorted(tree.unlisted))
    return frozenset(tree.tracked)


def _not_text(data: bytes) -> bool:
    """The walk will not read `data` as UTF-8: a NUL byte anywhere, a byte order mark of a
    wide encoding (UTF-16 needs no NUL when every character is outside Latin), or a Git LFS
    pointer standing in for a file that was never fetched."""
    if b"\x00" in data or data.startswith(_WIDE_BOMS):
        return True
    return len(data) <= _LFS_POINTER_LIMIT and data.startswith(_LFS_POINTER_HEADS)


def _looks_like_text(name: str, head: bytes) -> bool:
    """A file not read as text the walk should say it did not read: a wide text encoding, a
    code or text file type, or any type that is not binary by nature. A prompt can start
    with a stray NUL or be BOM-less UTF-16, whatever its name says."""
    if head.startswith(_WIDE_BOMS) or _lang_for(name) != "other":
        return True
    return Path(name).suffix.lower() not in _BINARY_SUFFIXES


def _walk(top: str, onerror: Any = None, followlinks: bool = False) -> Iterator[Any]:
    """`os.walk(top, topdown=True)`, except that a link is never followed to learn whether it
    is a folder: `os.walk` stats the target of every link it meets, and a link to another
    machine would make that a network connection. A link is listed with the files, and the
    caller decides; `followlinks` keeps the old behaviour. Prune `dirnames` in place, as with
    `os.walk`."""
    stack = [top]
    while stack:
        folder = stack.pop()
        try:
            with os.scandir(folder) as listing:
                entries = list(listing)
        except OSError as err:
            if onerror is not None:
                onerror(err)
            continue
        dirnames: list[str] = []
        filenames: list[str] = []
        for entry in entries:
            try:
                is_folder = entry.is_dir(follow_symlinks=followlinks)
            except OSError:
                is_folder = False
            (dirnames if is_folder else filenames).append(entry.name)
        yield folder, dirnames, filenames
        stack.extend(os.path.join(folder, name) for name in reversed(dirnames))


def _holds_foreign_file(name: str, folder: str) -> bool:
    """The cache `folder`, called `name`, holds a file of a type the cache does not write.
    Version control data has no such test and is never listed."""
    own = CACHE_OWN_TYPES.get(name)
    if own is None:
        return False
    for _dirpath, _dirnames, filenames in _walk(folder):
        for filename in filenames:
            if filename in CACHE_OWN_NAMES:
                continue
            if os.path.splitext(filename)[1].lower() not in own:
                return True
    return False


def in_audit_dir(rel: str) -> bool:
    """`rel` lies under `AUDIT_DIR`, or the pre-rename one."""
    return rel.startswith((AUDIT_DIR + "/", *(d + "/" for d in LEGACY_AUDIT_DIRS)))


def _worth_parsing(name: str, rel: str, head: str, size: int) -> bool:
    """The head names the toolchain, or a workbench document written with its keys sorted
    may put `schema` past the head: under the audit directory every `.json` is parsed."""
    if _own_head(name, head):
        return True
    return name.lower().endswith(".json") and in_audit_dir(rel) and size > HEAD_BYTES


@dataclass
class _Pending:
    path: Path
    relpath: str
    lang: str
    size: int
    gitignored: bool


def walk(
    root: Path,
    options: WalkOptions | None = None,
    *,
    own_output_skipped: list[str] | None = None,
    oversize_skipped: list[str] | None = None,
    marker_skipped: list[str] | None = None,
    unread_files: list[str] | None = None,
    unread_dirs: list[str] | None = None,
) -> tuple[list[FileRecord], list[Unit], list[UnknownItem]]:
    """
    Enumerate `root`. Never raises on an unreadable entry; see the module docstring.

    `own_output_skipped`, when given, receives the POSIX relpath of every file skipped as
    the audit's own report (`is_own_report`, `is_own_html`), sorted, so the caller can put
    the list in the inventory; those files get no UNKNOWN row here, `audit.py` adds one for
    a skip outside `AUDIT_DIR`.

    `oversize_skipped`, when given, receives the POSIX relpath of every file over
    `options.max_size`. Those files always get one UNKNOWN row (count, limit, first few
    paths) whether or not the sink is passed; the sink is for the inventory's count.

    `marker_skipped`, when given, receives the POSIX relpath of every file skipped for the
    ignore marker, sorted. With `honour_marker=False` no file is skipped for it.

    `unread_files` and `unread_dirs`, when given, receive the POSIX relpath of every file
    left unread and every directory not gone into, sorted (see the module docstring). The
    audit's own output is in `own_output_skipped` instead, and version control data and a
    cache holding only its own file types in neither.
    """
    opts = options or WalkOptions()
    root = Path(root).resolve()
    exclude = _normalise_excludes(opts.exclude)
    ignore = GitIgnore.load(root)
    unlisted: list[str] = []
    network: list[str] = []
    listing = _tracked(root, unlisted, network)
    tracked = listing or frozenset()
    outside_git = listing is not None and not tracked
    tracked_dirs = frozenset(a for rel in tracked for a in _ancestors(rel))
    pending: list[_Pending] = []
    manifests: dict[str, str | None] = {"": None}
    symlinks = 0
    unreadable = 0
    ignored_dirs: list[str] = []
    oversize: list[str] = []
    not_text: list[str] = []
    # `SKIP_DIRS` directories kept open for their tracked files, and the ones left pruned.
    opened: set[str] = set()
    pruned: list[str] = []
    not_read_files: list[str] = []
    not_read_dirs: list[str] = []
    # Files the walk met and can answer for, and the folders it said it left out. A tracked
    # file in neither was never seen. A gitignored file is not answered for: `.gitignore`
    # does not hide a tracked file, so it only applies here when git spells the name
    # differently.
    met: set[str] = set()
    left_out: list[str] = []
    # Every `.git` below the root the walk meets: `git status` opens them (`git_tree`).
    dotgits: list[Path] = []

    def _onerror(err: OSError) -> None:
        nonlocal unreadable
        unreadable += 1
        if err.filename:
            not_read_dirs.append(_clean_rel(_norm_rel(os.path.relpath(err.filename, root))) or ".")

    def _not_entered(name: str, rel: str, folder: str) -> None:
        if name not in NOTHING_WRITTEN_DIRS or (outside_git and _holds_foreign_file(name, folder)):
            not_read_dirs.append(rel)

    for dirpath, dirnames, filenames in _walk(
        root, onerror=_onerror, followlinks=opts.follow_symlinks
    ):
        dir_rel = _clean_rel(_norm_rel(os.path.relpath(dirpath, root)))
        if dir_rel and ".gitignore" in filenames:
            text = read_text(Path(dirpath) / ".gitignore")
            if text:
                ignore.add(dir_rel, text)
        manifest = _manifest_in(filenames)
        if manifest is not None:
            manifests[dir_rel] = manifest

        keep: list[str] = []
        if dir_rel and (".git" in dirnames or ".git" in filenames):
            dotgits.append(Path(dirpath) / ".git")
        for name in sorted(dirnames):
            rel = _join(dir_rel, name)
            folder = os.path.join(dirpath, name)
            if not opts.follow_symlinks and is_link(folder):
                symlinks += 1
                not_read_files.append(rel)
                met.add(rel)
                continue
            if _excluded(rel, exclude):
                left_out.append(rel)
                _not_entered(name, rel, folder)
                continue
            if _skip_dir(name, rel) or dir_rel in opened:
                if rel in tracked_dirs and opts.read_tracked:
                    opened.add(rel)
                    keep.append(name)
                elif rel in tracked_dirs:
                    pruned.append(rel)
                _not_entered(name, rel, folder)
                continue
            if not opts.include_ignored and ignore.match(rel, is_dir=True):
                ignored_dirs.append(rel)
                # Its tracked files are the commit's; the rest stays ignored below.
                if rel not in tracked_dirs:
                    _not_entered(name, rel, folder)
                    continue
            keep.append(name)
        dirnames[:] = keep

        for name in filenames:
            rel = _join(dir_rel, name)
            full = Path(dirpath) / name
            met.add(rel)
            if not opts.follow_symlinks and is_link(full):
                symlinks += 1
                not_read_files.append(rel)
                continue
            if _excluded(rel, exclude) or (dir_rel in opened and rel not in tracked):
                not_read_files.append(rel)
                continue
            if rel in opts.skip_untracked and rel not in tracked:
                if own_output_skipped is not None:
                    own_output_skipped.append(rel)
                continue
            gitignored = rel not in tracked and ignore.would_ignore(rel, is_dir=False)
            if gitignored and not opts.include_ignored and ignore.match(rel, is_dir=False):
                not_read_files.append(rel)
                met.discard(rel)
                continue
            try:
                size = full.stat().st_size
                if size > opts.max_size:
                    oversize.append(rel)
                    not_read_files.append(rel)
                    continue
                with open(full, "rb") as fh:
                    data = fh.read()
            except OSError:
                unreadable += 1
                not_read_files.append(rel)
                continue
            head = data[:HEAD_BYTES]
            if _not_text(data):
                not_read_files.append(rel)
                if _looks_like_text(name, head):
                    not_text.append(rel)
                continue
            # `utf-8-sig`: the same text `read_text` returns. A BOM left in place put
            # three bytes before the html marker line and defeated `is_own_html`.
            text_head = head.decode("utf-8-sig", errors="replace")
            # The html report carries the marker on line 1; name it before the marker
            # check drops it without a trace.
            own = is_own_html(text_head, name)
            if opts.skip_own_output and not own and _worth_parsing(name, rel, text_head, size):
                own = is_own_report(name, read_text(full) or "")
            if opts.skip_own_output and own:
                if own_output_skipped is not None:
                    own_output_skipped.append(rel)
                continue
            if opts.honour_marker and has_ignore_marker(text_head):
                if marker_skipped is not None:
                    marker_skipped.append(rel)
                not_read_files.append(rel)
                continue
            pending.append(_Pending(full, rel, _lang_for(name), size, gitignored))

    pending.sort(key=lambda p: p.relpath)
    only = tuple(_norm_rel(str(item)) for item in opts.only if str(item).strip())
    only_missing: list[str] = []
    if only:
        seen_rel = {item.relpath for item in pending}
        only_missing = [rel for rel in only if rel not in seen_rel]
        wanted = set(only)
        pending = [item for item in pending if item.relpath in wanted]
    # Provisional unit ids are needed for the root-language vote, so assign in two steps.
    provisional = _build_units(manifests, Counter())
    votes: Counter[tuple[str, str]] = Counter()
    assigned: list[str] = []
    for item in pending:
        unit_id = unit_of(item.relpath, provisional)
        assigned.append(unit_id)
        votes[(unit_id, item.lang)] += 1
    units = _build_units(manifests, votes)
    records = [
        FileRecord(
            path=item.path,
            relpath=item.relpath,
            lang=item.lang,
            unit=unit_id,
            size=item.size,
            gitignored=item.gitignored,
        )
        for item, unit_id in zip(pending, assigned)
    ]

    unknown: list[UnknownItem] = []
    if symlinks:
        unknown.append(
            UnknownItem(
                category=UnknownCategory.RUNTIME,
                what="symlinks skipped",
                why=f"{symlinks} symlink(s) not followed",
                how_to_resolve="Re-run with follow_symlinks enabled, or audit the link targets directly.",
            )
        )
    if unreadable:
        unknown.append(
            UnknownItem(
                category=UnknownCategory.RUNTIME,
                what="unreadable files",
                why=f"{unreadable} file(s) or director(ies) could not be read",
                how_to_resolve="Check permissions on the target tree; unreadable paths were not audited.",
            )
        )
    if ignored_dirs:
        unknown.append(_ignored_dirs_item(ignored_dirs))
    for rel in only_missing:
        unknown.append(
            UnknownItem(
                category=UnknownCategory.RUNTIME,
                what="--only path not walked",
                why=(
                    f"{rel}: excluded, gitignored, over the size limit, carrying the ignore "
                    "marker, or not found"
                ),
                how_to_resolve=(
                    "Check the path against the walk's excludes and .gitignore; a file the "
                    "walk never saw was not audited."
                ),
                file=rel,
            )
        )
    if oversize:
        if oversize_skipped is not None:
            oversize_skipped.extend(sorted(oversize))
        unknown.append(_oversize_item(oversize, opts.max_size))
    if pruned:
        unknown.append(_tracked_skipped_item(tracked, pruned))
    if not_text:
        unknown.append(_not_text_item(not_text))
    if listing is None or unlisted:
        own = network_reference(root)
        sub = _shown(network) if network and own is None else None
        unknown.append(_not_listed_item(unlisted, own or sub, in_submodule=sub is not None))
    nested = {_host_in_git_files(dotgit) for dotgit in dotgits} - {None}
    nested_rels = sorted({_shown_rel(hit, root) for hit in nested if hit} - set(network))
    if nested_rels:
        unknown.append(_nested_network_item(nested_rels))
    lost = _lost_tracked(tracked, met, [*pruned, *left_out])
    if lost:
        unknown.append(_lost_tracked_item(lost))
    if outside_git:
        unread = [rel for rel in not_read_files if Path(rel).suffix.lower() not in _BINARY_SUFFIXES]
        if unread or not_read_dirs:
            unknown.append(_unread_item({*unread, *not_read_dirs}))
    # Filename visit order from os.walk is OS-dependent; sort so inventory/SARIF lists
    # match across Windows and Linux (same invariant as oversize_skipped and records).
    if own_output_skipped is not None:
        own_output_skipped[:] = sorted(own_output_skipped)
    if marker_skipped is not None:
        marker_skipped[:] = sorted(marker_skipped)
    if unread_files is not None:
        unread_files[:] = sorted(set(not_read_files))
    if unread_dirs is not None:
        unread_dirs[:] = sorted(set(not_read_dirs))
    return records, units, unknown


_IGNORED_DIRS_NAMED = 6
_OVERSIZE_NAMED = 3


def _oversize_item(oversize: list[str], limit: int) -> UnknownItem:
    """A file over `max_size` was never opened, so nothing in it was audited. A large
    file is exactly where a dumped conversation log, an eval corpus or a bundled config
    lives, so the skip is counted and named, never silent."""
    names = sorted(oversize)
    shown = ", ".join(names[:_OVERSIZE_NAMED])
    if len(names) > _OVERSIZE_NAMED:
        shown += f", +{len(names) - _OVERSIZE_NAMED} more"
    return UnknownItem(
        category=UnknownCategory.RUNTIME,
        what="oversize files skipped",
        why=f"{len(names)} file(s) over the {limit} byte limit not read: {shown}",
        how_to_resolve=(
            "Re-run with a larger size limit (WalkOptions.max_size), or audit those files directly."
        ),
    )


def _shown(paths: Sequence[str]) -> str:
    names = sorted(paths)
    shown = ", ".join(names[:_OVERSIZE_NAMED])
    if len(names) > _OVERSIZE_NAMED:
        shown += f", +{len(names) - _OVERSIZE_NAMED} more"
    return shown


def _tracked_skipped_item(tracked: frozenset[str], pruned: Sequence[str]) -> UnknownItem:
    """Files of the commit under a directory the walk prunes by name. A folder called
    `build` or `vendor` can hold the code that runs, so the skip is named."""
    prefixes = tuple(rel + "/" for rel in pruned)
    files = [rel for rel in tracked if rel.startswith(prefixes)]
    return UnknownItem(
        category=UnknownCategory.COVERAGE,
        what="tracked files in skipped directories",
        why=f"{len(files)} tracked file(s) in a skipped directory not read: {_shown(files)}",
        how_to_resolve=(
            "Move code and prompts the system runs out of these directories, or read them "
            "with --mode auditor, which reads every tracked file whatever its folder is called."
        ),
    )


def _not_text_item(paths: Sequence[str]) -> UnknownItem:
    """A NUL byte ends the read, and UTF-16 text is full of them; a byte order mark ends it
    too; a Git LFS pointer is a few lines standing for a file that was never fetched. A
    prompt saved or stored that way is still a prompt, so the skip is named."""
    return UnknownItem(
        category=UnknownCategory.COVERAGE,
        what="files not read as text",
        why=(
            f"{len(paths)} file(s) with a NUL byte (binary data, or UTF-16 or UTF-32 text), a "
            f"wide byte order mark, or a Git LFS pointer not read: {_shown(paths)}"
        ),
        how_to_resolve=(
            "Save text as UTF-8, fetch Git LFS files (`git lfs pull`), or audit those files "
            "directly."
        ),
    )


def _not_listed_item(
    unlisted: Sequence[str], network: str | None = None, *, in_submodule: bool = False
) -> UnknownItem:
    """`.gitignore` never hides a tracked file, but only git can say which are tracked. When
    it cannot, a committed file can stay hidden, so the walk says what it could not know.
    `in_submodule`: the file naming another machine is a submodule's, not the root's."""
    if network is not None:
        where = " in the submodule" if in_submodule else ""
        why = f"git was not started{where}: {network} names a path on another machine"
    elif unlisted:
        why = f"git could not list the files of {len(unlisted)} submodule(s): {_shown(unlisted)}"
    else:
        why = "git could not list the tracked files of this repository"
    return UnknownItem(
        category=UnknownCategory.COVERAGE,
        what="tracked files not listed",
        why=why + "; a .gitignore line or a folder name may have hidden a committed file",
        how_to_resolve=(
            "Take the network path out of the repository's git files, or audit a copy "
            "without `.git`."
            if network is not None
            else "Repair the repository (`git status` names the error) and re-run."
        ),
    )


def _nested_network_item(paths: Sequence[str]) -> UnknownItem:
    """A nested repository whose git files name a path on another machine: `git status`
    would open them, so it is not run (`git_tree`), and the tree's state is not known."""
    return UnknownItem(
        category=UnknownCategory.COVERAGE,
        what="tree state not compared",
        why=(
            f"git status was not run: {_shown(paths)} in a nested repository names a path on "
            "another machine, and git status opens it; whether the tree differs from its "
            "commit is not known"
        ),
        how_to_resolve=(
            "Take the network path out of the nested repository's git files, or audit a copy "
            "without them."
        ),
    )


def _lost_tracked(tracked: frozenset[str], met: set[str], left_out: Sequence[str]) -> list[str]:
    """The files of the commit the walk never met, in a folder it did not say it left out."""
    seen = {_fold(rel) for rel in met}
    folders = tuple(_fold(rel) + "/" for rel in left_out)
    return [rel for rel in tracked if _fold(rel) not in seen and not _fold(rel).startswith(folders)]


def _lost_tracked_item(paths: Sequence[str]) -> UnknownItem:
    """A file of the commit that is not on disk under its name was read by nobody, and git
    can call the tree unchanged all the same."""
    return UnknownItem(
        category=UnknownCategory.COVERAGE,
        what="tracked files not read",
        why=(
            f"{len(paths)} tracked file(s) or submodule(s) not found under their own name: "
            f"{_shown(paths)}"
        ),
        how_to_resolve=(
            "Check out the whole commit: leave the sparse checkout, run `git submodule update "
            "--init --recursive`, restore a deleted file, or put a folder's name back in the "
            "case the commit spells it."
        ),
    )


def _unread_item(paths: set[str]) -> UnknownItem:
    """Outside git no commit shows what the walk left out, so the walk says it once."""
    return UnknownItem(
        category=UnknownCategory.COVERAGE,
        what="files and folders not read",
        why=(
            f"{len(paths)} file(s) or folder(s) not read, and no commit lists them: "
            f"{_shown(sorted(paths))}"
        ),
        how_to_resolve=(
            "Check nothing the system runs is among them: a folder's name, a .gitignore line "
            "or an exclude says nothing about what it holds."
        ),
    )


def _ignored_dirs_item(ignored_dirs: list[str]) -> UnknownItem:
    """A `.gitignore`d directory is not walked, so nothing in it was audited. That is
    where logs, eval outputs and scratch data accumulate -- the files most likely to
    hold PII or the eval corpus -- so the pruning is reported, never silent."""
    names = sorted(ignored_dirs)
    shown = ", ".join(names[:_IGNORED_DIRS_NAMED])
    if len(names) > _IGNORED_DIRS_NAMED:
        shown += f", +{len(names) - _IGNORED_DIRS_NAMED} more"
    return UnknownItem(
        category=UnknownCategory.RUNTIME,
        what="gitignored directories skipped",
        why=f"{len(names)} gitignored director(ies) not walked: {shown}",
        how_to_resolve=(
            "Re-run with --include-ignored to audit them; logs/, evals/ and data "
            "directories are where PII and eval corpora accumulate."
        ),
    )


# ---------------------------------------------------------------------------
# git (read-only)
# ---------------------------------------------------------------------------


@lru_cache(maxsize=4)
def _git_on_path(path: str) -> str | None:
    for folder in path.split(os.pathsep):
        candidate = os.path.join(folder, _GIT_NAME)
        if os.path.isabs(folder) and os.path.isfile(candidate):
            return candidate
    return None


def git_program() -> str | None:
    """git's absolute path, found on `PATH` alone, or None. Started by a bare name, Windows
    looks in the current directory first, so a `git.exe` committed to the audited tree would
    run; `shutil.which` looks there too. A relative `PATH` entry is the same hole."""
    return _git_on_path(os.environ.get("PATH", os.defpath))


def git_env(protocols: str = _NO_TRANSPORT) -> dict[str, str]:
    """The environment of a git command. `GIT_ALLOW_PROTOCOL` beats every `protocol.*` key
    of a repository's configuration, so no missing object is ever fetched and no remote
    helper starts. Only `aisafe fleet`'s clone step names real transports."""
    return {**os.environ, "GIT_ALLOW_PROTOCOL": protocols}


def _config_text(text: str) -> str:
    """Git configuration with its line continuations and quotes taken out, so a value reads
    as git reads it. Coarse on purpose: a comment that looks like a value counts as one."""
    return re.sub(r"\\\r?\n", "", text).replace('"', "")


def _names_host(text: str) -> bool:
    return any(
        match.group(1).lower() not in _REMOTE_KEYS for match in _CONFIG_HOST_RE.finditer(text)
    )


def _link_target(path: Path) -> str | None:
    """What a link points at, without touching it. Windows writes a local target of a
    junction as `\\\\?\\C:\\...`, which is no path on another machine, and a remote one as
    `\\\\?\\UNC\\host\\share`."""
    try:
        target = os.readlink(path)
    except (OSError, ValueError):
        return None
    if target.startswith("\\\\?\\UNC\\"):
        return "\\\\" + target[len("\\\\?\\UNC\\") :]
    return target.removeprefix("\\\\?\\")


def _unquote_c(text: str, start: int) -> tuple[str, int] | None:
    """git's `unquote_c_style` on the quoted string at `text[start]`: its value and the index
    just past the closing quote, or None where git finds the quoting broken."""
    out: list[str] = []
    index = start + 1
    while index < len(text):
        char = text[index]
        index += 1
        if char == '"':
            return "".join(out), index
        if char == "\0":
            return None
        if char != "\\":
            out.append(char)
            continue
        code, index = text[index : index + 1], index + 1
        digits = code + text[index : index + 2]
        if code and code in _C_ESCAPES:
            out.append(_C_ESCAPES[code])
        elif code and code in "0123" and len(digits) == 3 and all(d in _OCTAL for d in digits):
            out.append(chr(int(digits, 8)))
            index += 2
        else:
            return None
    return None


def _alternate_entries(text: str) -> list[str] | None:
    """The entries of `objects/info/alternates` as git reads them (`parse_alt_odb_entry`):
    one a line and `#` a comment, but an entry that starts with a quote is C-unquoted, may
    run past its line, and git skips the one character after its closing quote. None when a
    quoted entry does not decode: git would read it as written, this counts it as a host."""
    entries: list[str] = []
    index = 0
    while index < len(text):
        if text[index] == '"':
            decoded = _unquote_c(text, index)
            if decoded is None:
                return None
            entries.append(decoded[0])
            index = decoded[1] + 1
            continue
        end = text.find("\n", index)
        end = len(text) if end < 0 else end
        if text[index] != "#":
            entries.append(text[index:end])
        index = end + 1
    return entries


def _config_entries(text: str) -> list[tuple[str, str, str | None]] | None:
    """A git configuration file parsed the way git parses it (`git_parse_source`): `(section,
    key, value)`, section and key lowercased (the subsection is dropped), each value with its
    quotes, escapes, comments and continuation lines resolved, None for a key without `=`.
    None at a line git rejects: git stops there."""
    text = text.replace("\r\n", "\n").removeprefix("\xef\xbb\xbf")  # BOM, read as latin-1
    entries: list[tuple[str, str, str | None]] = []
    section = ""
    index = 0
    comment = False
    while index < len(text):
        char = text[index]
        index += 1
        if char == "\n":
            comment = False
        elif comment or char in _C_SPACE:
            continue
        elif char in "#;":
            comment = True
        elif char == "[":
            header = _config_section(text, index)
            if header is None:
                return None
            section, index = header
        elif not (char.isascii() and char.isalpha()):
            return None
        else:
            start = index - 1
            while index < len(text) and _key_char(text[index]):
                index += 1
            key = text[start:index].lower()
            while text[index : index + 1] in (" ", "\t"):
                index += 1
            if text[index : index + 1] in ("", "\n"):
                entries.append((section, key, None))
                continue
            if text[index] != "=":
                return None
            value = _config_value(text, index + 1)
            if value is None:
                return None
            entries.append((section, key, value[0]))
            index = value[1]
    return entries


def _key_char(char: str) -> bool:
    return char.isascii() and (char.isalnum() or char == "-")


def _config_section(text: str, index: int) -> tuple[str, int] | None:
    """A `[section]` or `[section "subsection"]` header read from just past its `[`: the
    section's name, lowercased, and the index past its `]` (`get_base_var`)."""
    start = index
    while index < len(text):
        char = text[index]
        index += 1
        if char == "]":
            name = text[start : index - 1].lower()
            return (name, index) if name else None
        if char in _C_SPACE:
            if char == "\n":
                return None
            name = text[start : index - 1].lower()
            while text[index : index + 1] in tuple(_C_SPACE.replace("\n", "")):
                index += 1
            if text[index : index + 1] != '"':
                return None
            index += 1
            while index < len(text):
                char = text[index]
                index += 1
                if char == "\n":
                    return None
                if char == '"':
                    return (name, index + 1) if text[index : index + 1] == "]" else None
                if char == "\\":
                    if text[index : index + 1] in ("", "\n"):
                        return None
                    index += 1
            return None
        if not (_key_char(char) or char == "."):
            return None
    return None


def _config_value(text: str, index: int) -> tuple[str, int] | None:
    """A configuration value read from just past its `=` (`parse_value`): the value and the
    index past its line, or None at a line git rejects (an open quote, an unknown escape)."""
    out: list[str] = []
    trim: int | None = None
    quote = comment = False
    while True:
        char = text[index] if index < len(text) else "\n"
        index += 1
        if char == "\n":
            if quote:
                return None
            return "".join(out[:trim] if trim is not None else out), index
        if comment:
            continue
        if char in _C_SPACE and not quote:
            trim = len(out) if trim is None else trim
            if out:
                out.append(char)
            continue
        if char in ";#" and not quote:
            comment = True
            continue
        trim = None
        if char == "\\":
            code = text[index] if index < len(text) else "\n"
            index += 1
            if code == "\n":
                continue
            if code not in _CONFIG_ESCAPES:
                return None
            out.append(_CONFIG_ESCAPES[code])
        elif char == '"':
            quote = not quote
        else:
            out.append(char)


def _config_includes(path: Path, text: str) -> list[Path] | None:
    """The files a configuration file includes, or None when it names a path on another
    machine. Read twice: coarsely (`_config_text`), which can only count more, and as git
    parses it, which decodes what the coarse read cannot and finds an include path quoted
    around a `;`. A file git rejects counts as naming one: git has read the lines above the
    bad one, includes and all, before it stops."""
    coarse = _config_text(text)
    entries = _config_entries(text)
    if _names_host(coarse) or entries is None:
        return None
    for _section, key, value in entries:
        if value is not None and key not in _REMOTE_KEYS and _HOST_VALUE_RE.match(value):
            return None
    rels = [match.group(1).strip() for match in _CONFIG_INCLUDE_RE.finditer(coarse)]
    rels += [
        value
        for section, key, value in entries
        if key == "path" and section in ("include", "includeif") and value
    ]
    return [path.parent / rel for rel in dict.fromkeys(rels) if rel[:1] != "~"]


def _host_in_git_files(dotgit: Path) -> Path | None:
    """The file behind `dotgit` that names a path on another machine, or None. It follows
    what git would follow: the `.git` file, `commondir`, `config`, `config.worktree` and the
    files they include, and object alternates, each by its own syntax. A configuration value
    and a quoted alternate are decoded first, as git decodes them (`\\057` is `/`), and one
    that does not decode counts as naming a host."""
    queue: list[tuple[str, Path]] = [(".git", dotgit)]
    seen: set[Path] = set()
    while queue:
        kind, path = queue.pop()
        if path in seen:
            continue
        if len(seen) >= _MAX_GIT_FILES:
            return path  # more than a repository has: what is left cannot be taken as read
        seen.add(path)
        if is_link(path):
            target = _link_target(path)
            if target is not None and _HOST_VALUE_RE.match(target):
                return path
            if target is not None:
                queue.append((kind, path.parent / target))
            continue
        if kind == "folder" or (kind == ".git" and os.path.isdir(path)):
            queue += [
                ("commondir", path / "commondir"),
                ("config", path / "config"),
                ("config", path / "config.worktree"),
                ("alternates", path / "objects" / "info" / "alternates"),
            ]
            continue
        if not os.path.isfile(path):
            continue
        try:
            if os.path.getsize(path) > _GIT_FILE_LIMIT:
                return path
            text = path.read_bytes().decode("latin-1")
        except OSError:
            continue
        if kind == "config":
            includes = _config_includes(path, text)
            if includes is None:
                return path
            queue += [("config", include) for include in includes]
            continue
        # git reads a `gitdir:` line and `commondir` as written, quotes and backslashes
        # included; stripping them only counts more.
        lines = [
            (line.partition("gitdir:")[2] if kind == ".git" else line).strip().strip('"')
            for line in text.splitlines()
        ]
        if kind == "alternates":
            entries = _alternate_entries(text)
            if entries is None:
                return path
            values = [*entries, *lines]
            follow = [entry.split("\0")[0].strip() for entry in entries]
            nexts = [
                ("alternates", path.parents[1] / v / "info" / "alternates") for v in follow if v
            ]
        else:
            values = lines
            nexts = [("folder", path.parent / v) for v in lines if v and not v.startswith("#")]
        if any(_HOST_VALUE_RE.match(value) for value in values):
            return path
        queue += nexts
    return None


def network_reference(cwd: Path) -> str | None:
    """Which file of the repository around `cwd` names a path on another machine, or None.
    Git opens such a path while it starts, before any command, so a repository's own files
    could make the audit connect to a host: `include.path=//host/share/x`, a `gitdir:` line,
    `commondir`, or an object alternate. A value that starts `//` or `\\\\` is enough; remote
    addresses are not counted, because nothing here opens one."""
    start = Path(os.path.abspath(cwd))
    for folder in (start, *start.parents):
        if not os.path.lexists(folder / ".git"):
            continue
        found = _host_in_git_files(folder / ".git")
        if found is not None:
            return _shown_rel(found, folder)
    return None


def _shown_rel(path: Path, folder: Path) -> str:
    """`path` relative to `folder` when it lies inside it, its name otherwise."""
    path = Path(os.path.normpath(path))
    return path.relative_to(folder).as_posix() if folder in path.parents else path.name


def _host_on_the_way(path: Path, root: Path, depth: int = 0) -> Path | None:
    """The link between `root` and `path` whose target is on another machine, or None.
    Opening a path through a link opens the link's target first, so a link to a local folder
    is followed and the folders on its own way are checked too."""
    here = root
    for part in path.relative_to(root).parts:
        here = here / part
        target = _link_target(here) if is_link(here) else None
        if target is None:
            continue
        if _HOST_VALUE_RE.match(target) or depth >= _MAX_SUBMODULE_DEPTH:
            return here
        resolved = Path(os.path.abspath(here.parent / target))
        if _host_on_the_way(resolved, Path(resolved.anchor), depth + 1) is not None:
            return here
    return None


def _host_in_gitlink(root: Path, rel: str) -> Path | None:
    """The file of the submodule at `rel` that names a path on another machine, or None.
    The parent's `git status` reads every submodule's HEAD, so it opens what the submodule's
    `.git` names before a check inside the submodule could refuse it."""
    found = _host_on_the_way(root / rel, root)
    return found if found is not None else _host_in_git_files(root / rel / ".git")


def _nested_git_hosts(root: Path) -> list[str]:
    """The git files below `root` that name a path on another machine, relative to it.
    `git status` opens the `.git` of a folder it does not track to tell a nested repository
    from a folder, so one such file anywhere in the tree makes it connect. Links and `.git`
    folders are not entered."""
    found: set[str] = set()
    stack = [root]
    while stack:
        folder = stack.pop()
        try:
            with os.scandir(folder) as listing:
                entries = list(listing)
        except OSError:
            continue
        for entry in entries:
            path = Path(entry.path)
            if entry.name == ".git":
                hit = None if folder == root else _host_in_git_files(path)
                if hit is not None:
                    found.add(_shown_rel(hit, root))
                continue
            try:
                folder_like = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue
            if folder_like and not is_link(path):
                stack.append(path)
    return sorted(found)


def crosses_link(output: str) -> bool:
    """The file itself or a folder on its way is a symlink or a junction. Nothing but the
    path's own parts is compared, so an 8.3 short name or a drive letter's case is no link."""
    path = Path(os.path.abspath(output))
    return any(is_link(part) for part in (path, *path.parents))


def run_git(
    args: Sequence[str],
    cwd: Path,
    *,
    ok: tuple[int, ...] = (0,),
    env: Mapping[str, str] | None = None,
    timeout: float = GIT_TIMEOUT,
) -> bytes | None:
    """Run a read-only git command, the one way this package does: stdout when it exits with
    a code in `ok`, None on any failure, and None without starting git when the repository
    names a path on another machine (`network_reference`). `env` is added to `git_env()`."""
    program = git_program()
    if program is None or network_reference(cwd) is not None:
        return None
    try:
        proc = subprocess.run(
            [program, *GIT_SAFE, *args],
            cwd=str(cwd),
            env={**git_env(), **(env or {})},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    return proc.stdout if proc.returncode in ok else None


def _git(
    args: Sequence[str],
    cwd: Path,
    *,
    ok: tuple[int, ...] = (0,),
    env: Mapping[str, str] | None = None,
    timeout: float = GIT_TIMEOUT,
) -> str | None:
    """`run_git` with its stdout decoded."""
    out = run_git(args, cwd, ok=ok, env=env, timeout=timeout)
    return None if out is None else out.decode("utf-8", errors="replace")


def status_args(root: Path) -> list[str] | None:
    """The `git status` command for the repository at `root`: no filter driver the repository
    can write starts, and a submodule is compared by its commit only, because looking inside
    one starts a git that reads that submodule's own configuration (`git_tree` looks inside
    instead). The flag overrides `ignore = all` in `.gitmodules`. A blanked filter also means
    a filter cannot make a changed file read as unchanged. A driver only the operator wrote
    (system or global scope, where `git lfs install` puts its own) stays: it is what makes an
    LFS file equal its pointer, and a repository can only point at it. A driver the
    repository touches in any key, even to shadow the operator's, is blanked whole, and so is
    the `lfs` driver when the repository sets an `lfs.` key git-lfs does not write itself,
    because git-lfs reads those and they can start a program. None when the drivers cannot
    be listed or one cannot be overridden: git is then not run at all."""
    # `git config --get-regexp` exits 1 when nothing matches.
    listed = _git(
        ["config", "--show-scope", "-z", "--name-only", "--get-regexp", r"^(filter|lfs)\."],
        root,
        ok=(0, 1),
    )
    if listed is None:
        return None
    fields = listed.split("\0")
    drivers: set[str] = set()
    for scope, key in zip(fields[0::2], fields[1::2]):
        if scope in _OPERATOR_SCOPES:
            continue
        if key.startswith("filter."):
            drivers.add(key[len("filter.") :].rpartition(".")[0])
        elif not _LFS_OWN_KEY_RE.fullmatch(key):
            drivers.add("lfs")
    drivers.discard("")
    if not all(_FILTER_NAME_RE.fullmatch(driver) for driver in drivers):
        return None
    blank: list[str] = []
    for driver in sorted(drivers):
        for setting in ("clean=", "smudge=", "process=", "required=false"):
            blank.extend(("-c", f"filter.{driver}.{setting}"))
    return [*blank, "status", "--porcelain=v1", "--ignore-submodules=dirty"]


@dataclass
class GitTree:
    """What git says about a work tree, submodules included, with paths relative to it.

    `tracked`: the commit's files; a submodule that is not checked out stays as one path,
    so it reads as a tracked file nobody read. None when git could not list them.
    `unlisted`: checked-out submodules git could not list, and gitlinks that leave the tree;
    `tracked` holds the rest.
    `changed`: tracked paths that differ, and submodules at another commit. `untracked`:
    what `git status` lists as untracked. `uncompared`: tracked files `git status` does not
    look at (skip-worktree, assume-unchanged); a file a sparse checkout left off the disk
    is not one of them. `status_failed`: git could not say, so nothing here may be read as
    "no changes". `network`: the git files of submodules and nested repositories that name a
    path on another machine, relative to the root; `git status` opens them, so it was not
    run, and such a submodule was not listed either."""

    tracked: set[str] | None = field(default_factory=set)
    unlisted: set[str] = field(default_factory=set)
    changed: set[str] = field(default_factory=set)
    untracked: set[str] = field(default_factory=set)
    uncompared: set[str] = field(default_factory=set)
    status_failed: bool = False
    network: list[str] = field(default_factory=list)


def _leaves_tree(path: str) -> bool:
    """A path in the index that points out of the work tree."""
    rel = path.replace("\\", "/")
    return rel.startswith("/") or rel[1:2] == ":" or ".." in rel.split("/")


def git_tree(
    root: Path,
    run: Callable[..., str | None] | None = None,
    *,
    depth: int = 0,
    compare: bool = True,
    nested: bool = True,
) -> GitTree:
    """Read the work tree at `root`, then each checked-out submodule as its own repository.
    `run` is the command runner, `_git` by default. `compare=False` lists the files and asks
    nothing about differences. Before anything is compared, every submodule's `.git` and,
    with `nested`, every `.git` below `root` is checked for a path on another machine: one
    found means no `git status` runs anywhere in the tree."""
    git = run or _git
    tree = GitTree()
    root = Path(root)
    listed = git(["ls-files", "-v", "-s", "-z", "--", "."], root)
    if listed is None:
        tree.tracked = None
        tree.status_failed = True
    submodules: list[str] = []
    sparse: set[str] = set()
    for entry in (listed or "").split("\0"):
        head, tab, path = entry.partition("\t")
        if not tab:
            continue
        tag, _, rest = head.partition(" ")
        if rest.startswith(_GITLINK_MODE) and _leaves_tree(path):
            # A crafted index: never a place to run git. What it held stays unknown.
            tree.status_failed = True
            tree.unlisted.add(path)
            continue
        hit = _host_in_gitlink(root, path) if rest.startswith(_GITLINK_MODE) else None
        if hit is not None:
            # Checked before `.exists()`, which would follow a link to the other machine too.
            tree.status_failed = True
            tree.unlisted.add(path)
            tree.network.append(_shown_rel(hit, root))
            continue
        if rest.startswith(_GITLINK_MODE) and (root / path / ".git").exists():
            submodules.append(path)
        elif tree.tracked is not None:
            tree.tracked.add(path)
        if tag == "S" and not os.path.lexists(root / path):
            sparse.add(path)
        elif tag != "H":  # `git ls-files -v`: every other tag is a file status does not compare
            tree.uncompared.add(path)
    if compare and nested:
        tree.network += [rel for rel in _nested_git_hosts(root) if rel not in tree.network]
    if compare and tree.network:
        tree.status_failed = True
        compare = False
    if compare:
        _compare(root, git, tree)
        tree.changed -= sparse
    for rel in submodules:
        if depth >= _MAX_SUBMODULE_DEPTH:
            tree.status_failed = True
            tree.unlisted.add(rel)
            continue
        inner = git_tree(root / rel, run, depth=depth + 1, compare=compare, nested=False)
        tree.status_failed = tree.status_failed or inner.status_failed
        if inner.tracked is None:
            tree.unlisted.add(rel)
        elif tree.tracked is not None:
            tree.tracked |= {f"{rel}/{p}" for p in inner.tracked}
        tree.unlisted |= {f"{rel}/{p}" for p in inner.unlisted}
        tree.changed |= {f"{rel}/{p}" for p in inner.changed}
        tree.untracked |= {f"{rel}/{p}" for p in inner.untracked}
        tree.uncompared |= {f"{rel}/{p}" for p in inner.uncompared}
        tree.network += [f"{rel}/{p}" for p in inner.network]
    return tree


def _compare(root: Path, git: Callable[..., str | None], tree: GitTree) -> None:
    """Fold into `tree` what differs. `core.worktree` can point git at a clean copy, where
    every question below has a good answer about the wrong files, so a root that is not in
    git's work tree is a failure. The index's own stat data can lie (a same-size edit with
    its time put back), so the files are compared with the commit through a fresh index too."""
    args = status_args(root)
    if args is None:
        tree.status_failed = True
        return
    status = git([*args, "-z", "--untracked-files=all", "--", "."], root)
    prefix = (git(["rev-parse", "--show-prefix"], root) or "").strip()
    inside = git(["rev-parse", "--is-inside-work-tree"], root)
    fresh = None if status is None else _status_from_head(root, git, args)
    if fresh is None or (inside or "").strip() != "true":
        tree.status_failed = True
    _read_status(status or "", prefix, tree)
    _read_status(fresh or "", prefix, tree)


def _status_from_head(
    root: Path, git: Callable[..., str | None], args: Sequence[str]
) -> str | None:
    """`git status` against an index just read from HEAD: no stat data, so git reads every
    file. The index lies in a temporary folder, never in the audited tree."""
    with tempfile.TemporaryDirectory(prefix="aisafe-", ignore_cleanup_errors=True) as folder:
        env = {"GIT_INDEX_FILE": str(Path(folder) / "index")}
        if git(["read-tree", "HEAD"], root, env=env, timeout=_COMPARE_TIMEOUT) is None:
            return None
        return git(
            [*args, "-z", "--untracked-files=no", "--", "."],
            root,
            env=env,
            timeout=_COMPARE_TIMEOUT,
        )


def _read_status(status: str, prefix: str, tree: GitTree) -> None:
    """Fold `git status --porcelain=v1 -z` into `tree`. Its paths start at the repository's
    top, `prefix` is the walk root's place under it."""
    entries = status.split("\0")
    index = 0
    while index < len(entries):
        entry = entries[index]
        index += 1
        if len(entry) < 4:
            continue
        code, path = entry[:2], entry[3:]
        if code[0] in "RC":
            index += 1  # the rename's source path follows; the new path is what is walked
        rel = path[len(prefix) :] if prefix and path.startswith(prefix) else path
        (tree.untracked if code == "??" else tree.changed).add(rel)


def git_meta(root: Path) -> tuple[str | None, bool | None]:
    """(HEAD sha, dirty). `(None, False)` when git is absent or `root` is not a repo; dirty
    is None when git could not say, or was not started: unknown, never "no changes"."""
    out = _git(["rev-parse", "HEAD"], Path(root))
    if out is None:
        return None, None if network_reference(Path(root)) is not None else False
    sha = out.strip()
    if not _SHA_RE.match(sha):
        return None, False
    tree = git_tree(Path(root))
    if tree.status_failed:
        return sha, None
    return sha, bool(tree.changed or tree.untracked or tree.uncompared)


def file_age(path: Path, root: Path) -> tuple[datetime | None, str]:
    """When was this file last changed, and how do we know? Never raises.

    Sources, in order: `mtime` (stat), `git` (last commit touching the file), `unknown`.
    """
    path = Path(path)
    try:
        stamp = path.stat().st_mtime
        return datetime.fromtimestamp(stamp, tz=timezone.utc), "mtime"
    except (OSError, ValueError, OverflowError):
        pass
    try:
        rel = os.path.relpath(path, Path(root)).replace(os.sep, "/")
    except ValueError:
        return None, "unknown"
    out = _git(["log", "-1", "--format=%cI", "--", rel], Path(root))
    if out and out.strip():
        # git writes a UTC committer date as `...Z`; fromisoformat only accepts
        # that suffix from 3.11, so on 3.10 every UTC commit would fall to unknown.
        stamp = out.strip().splitlines()[0].replace("Z", "+00:00")
        try:
            when = datetime.fromisoformat(stamp)
        except ValueError:
            return None, "unknown"
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return when.astimezone(timezone.utc), "git"
    return None, "unknown"
