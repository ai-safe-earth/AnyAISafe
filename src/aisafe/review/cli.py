"""src/aisafe/review/cli.py
------------------------
`aisafe review`: write, complete and check the review record that binds a named person to
the exact prompts and code they read.

    aisafe review init [PATH] [--record FILE] [--force]
    aisafe review record [PATH] --reviewer NAME --purpose TEXT [--scope M1,M4]
                         [--affected TEXT] [--assisted-by TEXT] [--record FILE]
    aisafe review check [PATH] [--record FILE]

`init` discovers the artifacts a reviewer has to read (prompt files, files holding prompt
literals or assemblies, files carrying a person signal), hashes them and writes a skeleton
with the reviewer, the date, the scope and the purpose left to fill. `record` writes the
completed record for today with the hashes refreshed from a fresh discovery; the contextual
decisions and notes already in the file are carried over, because a person typed them.
`check` says which listed artifacts changed or went missing, whether the review is older
than the policy allows, and which discovered artifacts no record lists.

Exit codes: 0 nothing to report; 1 (`check`) at least one stale reason or uncovered
artifact; 2 a refusal or a failure (an existing file without --force, an empty or
verdict-shaped reviewer or purpose, a malformed record, discovery unavailable).

Discovery is the audit's own offline walk; nothing here calls a model or opens a socket.
The tree the command reads is the tree the audit reads: `[tool.aisafe-audit]` `exclude`
and `review-record` from pyproject.toml are the defaults. Output is ASCII and names
evidence, never a verdict.
"""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import yaml

from aisafe.evidence.artifacts import artifact_refs, sha256_of, short
from aisafe.policy import Policy, PolicyError, load_policy
from aisafe.review.records import (
    DEFAULT_RECORD_FILE,
    PLACEHOLDER,
    RECORD_CANDIDATES,
    dump_document,
    find_records,
    parse_review_document,
    record_document,
    relative_to_root,
    tool_name_problem,
)

__all__ = [
    "CONFIG_SECTION",
    "EXIT_FATAL",
    "EXIT_FINDINGS",
    "EXIT_INTERRUPTED",
    "EXIT_OK",
    "DiscoveryUnavailable",
    "build_parser",
    "discover_artifacts",
    "main",
    "today",
]

# The audit's pyproject table; `exclude` and `review-record` are shared with it so the
# record covers exactly the tree the audit reads.
CONFIG_SECTION = "aisafe-audit"
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_FATAL = 2
EXIT_INTERRUPTED = 130


class DiscoveryUnavailable(RuntimeError):
    """The walk or the discovery engine could not run. Nothing was listed in its place: a
    shorter artifact list would make `check` call a file covered that nobody saw."""


def today() -> date:
    """The date `record` writes and `check` ages against; a seam for tests."""
    return date.today()


def _note(text: str) -> None:
    print(text, file=sys.stderr)


def _plural(count: int) -> str:
    return "" if count == 1 else "s"


def _csv(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    items = [str(v) for v in value] if isinstance(value, (list, tuple)) else str(value).split(",")
    return tuple(item.strip() for item in items if item.strip())


def _config(root: Path) -> dict[str, Any]:
    """`[tool.aisafe-audit]` of the nearest pyproject above `root`, or {}."""
    from aisafe.devtools._config import load_tool_config

    return load_tool_config(CONFIG_SECTION, start=root)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def discover_artifacts(root: Path, exclude: Sequence[str] = ()) -> list[str]:
    """
    The files a reviewer has to read, as POSIX paths relative to `root`: every prompt file
    and every file holding a prompt literal or assembly (the inventory's `prompts`), and
    every file carrying a person signal (`person_signals`). Runs the audit's own walk and
    discovery so the record covers what the audit sees. Raises DiscoveryUnavailable when
    they cannot run.
    """
    try:
        from aisafe.discovery import discover, walk
    except ImportError as exc:
        raise DiscoveryUnavailable(f"discovery is not importable: {exc}") from exc
    try:
        files, units, _unknown = walk.walk(root, walk.WalkOptions(exclude=tuple(exclude)))
        result = discover.discover(root, files, units, discover.DiscoverOptions())
    except Exception as exc:  # broad on purpose: the command maps every failure to exit 2
        raise DiscoveryUnavailable(f"discovery failed: {type(exc).__name__}: {exc}") from exc
    inventory = result[0] if isinstance(result, tuple) else result
    paths: set[str] = set()
    for section in ("prompts", "person_signals"):
        for entry in getattr(inventory, section, None) or []:
            file = entry.get("file") if isinstance(entry, Mapping) else getattr(entry, "file", None)
            if isinstance(file, str) and file.strip() and file != ".":
                paths.add(file.replace("\\", "/"))
    # The record never lists itself.
    paths.difference_update(RECORD_CANDIDATES)
    return sorted(paths)


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------


def _root(path: str) -> Path:
    root = Path(path).expanduser()
    if not root.is_dir():
        raise NotADirectoryError(f"{root.as_posix()} is not a directory")
    return root.resolve()


def _target(root: Path, flag: str | None, configured: Any) -> Path:
    """
    Where `init` and `record` write. `--record` is taken as given (relative to the current
    directory, like `aisafe audit --review-record`); a pyproject `review-record` is
    relative to the audited root; otherwise the record file already present at the root,
    or `aisafe-review.yaml` there when none is.
    """
    if flag:
        return Path(flag).expanduser()
    if configured:
        given = Path(str(configured)).expanduser()
        return given if given.is_absolute() else root / given
    for name in RECORD_CANDIDATES:
        if (root / name).is_file():
            return root / name
    return root / DEFAULT_RECORD_FILE


def _write(target: Path, text: str) -> None:
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def _existing_reviews(target: Path, shown: str) -> list[dict[str, Any]]:
    """The raw `reviews` entries of the file about to be rewritten, so what a person typed
    (decisions, notes, units) is carried over. [] when there is nothing readable."""
    if not target.is_file():
        return []
    try:
        data = yaml.safe_load(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, yaml.YAMLError) as exc:
        _note(
            f"note: {shown} could not be read ({' '.join(str(exc).split())}); nothing carried over"
        )
        return []
    reviews = data.get("reviews") if isinstance(data, Mapping) else None
    if not isinstance(reviews, list):
        return []
    kept = [dict(entry) for entry in reviews if isinstance(entry, Mapping)]
    if len(kept) != len(reviews):
        _note(f"note: {len(reviews) - len(kept)} entries under reviews were not mappings; dropped")
    return kept


def _scope_from_flag(raw: str | None, policy: Policy) -> list[str]:
    ids = [mechanism.id for mechanism in policy.mechanisms]
    if raw is None:
        return ids
    chosen: list[str] = []
    unknown: list[str] = []
    for item in _csv(raw):
        mechanism_id = item.upper()
        if mechanism_id in ids:
            if mechanism_id not in chosen:
                chosen.append(mechanism_id)
        else:
            unknown.append(item)
    if unknown:
        raise ValueError(
            f"--scope names unknown mechanism ids {', '.join(unknown)}; valid ids are {', '.join(ids)}"
        )
    if not chosen:
        raise ValueError("--scope is empty; name at least one mechanism id or omit the flag")
    return sorted(chosen, key=ids.index)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    root = _root(args.path)
    policy = load_policy()
    config = _config(root)
    target = _target(root, args.record, config.get("review_record"))
    shown = relative_to_root(target, root)
    if target.exists() and not args.force:
        _note(f"refused: {shown} exists; pass --force to overwrite it")
        return EXIT_FATAL
    refs = artifact_refs(root, discover_artifacts(root, _csv(config.get("exclude"))))
    doc = record_document(
        reviewer=PLACEHOLDER,
        reviewed_at=None,
        scope=[],
        declared_purpose=PLACEHOLDER,
        artifacts=refs,
        policy_version=policy.version,
    )
    _write(target, dump_document(doc, header=True))
    print(
        f"wrote {shown}: {len(refs)} artifact{_plural(len(refs))}, reviewer {PLACEHOLDER}, "
        "reviewed_at null, scope []"
    )
    for ref in refs:
        print(f"  {ref.file}  sha256 {short(ref.sha256)}")
    if not refs:
        print(
            "  no prompt or person-signal artifacts were discovered; list the files you "
            "reviewed under artifacts by hand"
        )
    where = "" if args.path == "." else f" {args.path}"
    print(
        f'next: aisafe review record{where} --reviewer "NAME <role>" --purpose "TEXT" '
        "[--scope M1,M4]"
    )
    return EXIT_OK


def cmd_record(args: argparse.Namespace) -> int:
    root = _root(args.path)
    policy = load_policy()
    config = _config(root)
    target = _target(root, args.record, config.get("review_record"))
    shown = relative_to_root(target, root)
    scope = _scope_from_flag(args.scope, policy)
    existing = _existing_reviews(target, shown)
    previous: dict[str, Any] = existing[0] if existing else {}
    refs = artifact_refs(root, discover_artifacts(root, _csv(config.get("exclude"))))
    if not refs:
        _note(
            f"refused: no prompt or person-signal artifacts were discovered under "
            f"{root.as_posix()}; there is nothing to bind the review to"
        )
        return EXIT_FATAL
    units = previous.get("units")
    decisions = previous.get("decisions")
    problem = tool_name_problem(args.reviewer)
    if problem:
        _note(f"refused: {problem}")
        return EXIT_FATAL
    # Read once: the date written and the date printed are the same, even across midnight.
    when = today()
    doc = record_document(
        reviewer=args.reviewer,
        reviewed_at=when,
        scope=scope,
        declared_purpose=args.purpose,
        artifacts=refs,
        policy_version=policy.version,
        affected_population=(
            args.affected if args.affected is not None else previous.get("affected_population")
        ),
        assisted_by=(
            args.assisted_by if args.assisted_by is not None else previous.get("assisted_by")
        ),
        units=units if isinstance(units, list) else (),
        decisions=[d for d in decisions if isinstance(d, Mapping)]
        if isinstance(decisions, list)
        else (),
        notes=previous.get("notes"),
        extra_reviews=existing[1:],
    )
    # Validate before writing: the command never leaves a file the audit would reject.
    _records, errors, _version = parse_review_document(doc, shown, policy)
    if errors:
        for error in errors:
            _note(f"refused: {error}")
        return EXIT_FATAL
    _write(target, dump_document(doc, header=True))
    carried = [
        name
        for name, value in (
            ("decisions", doc["reviews"][0]["decisions"]),
            ("notes", doc["reviews"][0]["notes"]),
            ("units", doc["reviews"][0]["units"]),
        )
        if value
    ]
    print(
        f"wrote {shown}: reviewer {args.reviewer}, reviewed_at {when.isoformat()}, "
        f"scope {','.join(scope)}, {len(refs)} artifact{_plural(len(refs))}, "
        f"policy_version {policy.version}"
    )
    for ref in refs:
        print(f"  {ref.file}  sha256 {short(ref.sha256)}")
    if carried:
        print(f"  carried over from the previous record: {', '.join(carried)}")
    if len(existing) > 1:
        print(f"  {len(existing) - 1} further record{_plural(len(existing) - 1)} left as written")
    return EXIT_OK


def cmd_check(args: argparse.Namespace) -> int:
    root = _root(args.path)
    policy = load_policy()
    config = _config(root)
    override = args.record if args.record is not None else config.get("review_record")
    if override is not None and args.record is None and not Path(str(override)).is_absolute():
        override = root / str(override)
    review = find_records(root, None, override, policy)
    for error in review.errors:
        print(f"error: {error}")
    if review.found:
        print(
            f"{review.file}: {len(review.records)} record{_plural(len(review.records))}, "
            f"policy_version {review.policy_version or 'none'}"
        )
    elif not review.errors:
        print(
            f"no review record under {root.as_posix()} (looked for "
            f"{', '.join(RECORD_CANDIDATES)}); run `aisafe review init`"
        )
    now = today()
    stale = 0
    for record in review.records:
        reasons = record.is_stale(
            lambda relpath: sha256_of(root / relpath), now, policy.review_max_age_days
        )
        if record.policy_outdated(policy.version):
            reasons.append(
                f"policy_version {record.policy_version or 'none'} is older than the current "
                f"policy {policy.version}"
            )
        print(
            f"record {record.index + 1}: {record.reviewer}, reviewed_at {record.reviewed_at_iso}, "
            f"scope {','.join(record.scope) or '-'}, "
            f"{len(record.artifacts)} artifact{_plural(len(record.artifacts))}"
        )
        for reason in reasons:
            print(f"  stale: {reason}")
        stale += len(reasons)
    paths = discover_artifacts(root, _csv(config.get("exclude")))
    listed: set[str] = set()
    for record in review.records:
        listed |= record.artifact_paths
    uncovered = [path for path in paths if path not in listed]
    print(f"{len(paths)} artifact{_plural(len(paths))} discovered")
    for path in uncovered:
        print(f"uncovered: {path}")
    print(
        f"result: {stale} stale reason{_plural(stale)}, "
        f"{len(uncovered)} uncovered artifact{_plural(len(uncovered))}"
    )
    if review.errors:
        return EXIT_FATAL
    return EXIT_FINDINGS if stale or uncovered else EXIT_OK


_VERBS: dict[str, Callable[[argparse.Namespace], int]] = {
    "init": cmd_init,
    "record": cmd_record,
    "check": cmd_check,
}

_EPILOG = """
The record file is aisafe-review.yaml at PATH (also .aisafe/review.yaml or
.aisafe-audit/review.yaml when present), or the `review-record` of [tool.aisafe-audit] in
pyproject.toml, or --record FILE. The audit reads the same file.

Exit codes:
  0  nothing to report
  1  check: a listed artifact changed or is missing, the review is older than the policy
     allows, or a discovered artifact is listed in no record
  2  refused or failed: the file exists (init without --force), an empty or verdict-shaped
     reviewer or purpose, a malformed record, discovery unavailable

Examples:
  aisafe review init
  aisafe review record --reviewer "J. Doe <product owner>" --purpose "a language tutor for adults"
  aisafe review record . --scope M1,M4,M5 --assisted-by "an LLM reviewer" --reviewer "J. Doe" --purpose "..."
  aisafe review check
"""


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", nargs="?", default=".", help="root of the tree (default: .)")
    parser.add_argument(
        "--record",
        metavar="FILE",
        default=None,
        help="the record file to write or read (default: see below)",
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aisafe review",
        description=(
            "Write, complete and check the review record that binds a named person to the "
            "exact prompts and code they read."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EPILOG,
    )
    verbs = p.add_subparsers(dest="verb", metavar="{init,record,check}")
    init = verbs.add_parser(
        "init", help="write a skeleton listing every discovered artifact with its hash"
    )
    _add_common(init)
    init.add_argument("--force", action="store_true", help="overwrite an existing record file")
    record = verbs.add_parser(
        "record", help="write the completed record for today with refreshed hashes"
    )
    _add_common(record)
    record.add_argument(
        "--reviewer",
        required=True,
        metavar="NAME",
        help='the person who did the review, e.g. "J. Doe <product owner>"; never a tool',
    )
    record.add_argument(
        "--purpose",
        required=True,
        metavar="TEXT",
        help="what the system is for, in the operator's words",
    )
    record.add_argument(
        "--scope",
        metavar="IDS",
        default=None,
        help="mechanism ids considered, comma-separated (default: every mechanism)",
    )
    record.add_argument(
        "--affected",
        metavar="TEXT",
        default=None,
        help="who uses the system or is decided about (optional)",
    )
    record.add_argument(
        "--assisted-by",
        dest="assisted_by",
        metavar="TEXT",
        default=None,
        help="a tool or model that helped the reviewer; attribution only (optional)",
    )
    check = verbs.add_parser(
        "check", help="list stale reasons and uncovered artifacts; exit 1 when there are any"
    )
    _add_common(check)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.verb is None:
        parser.print_help()
        return EXIT_FATAL
    try:
        return _VERBS[args.verb](args)
    except KeyboardInterrupt:
        _note("interrupted")
        return EXIT_INTERRUPTED
    except DiscoveryUnavailable as exc:
        _note(f"error: {exc}")
        return EXIT_FATAL
    except PolicyError as exc:
        _note(f"error: {exc}")
        return EXIT_FATAL
    except ValueError as exc:
        _note(f"refused: {exc}")
        return EXIT_FATAL
    except (NotADirectoryError, FileNotFoundError) as exc:
        _note(f"error: {exc}")
        return EXIT_FATAL
    except OSError as exc:
        _note(f"error: could not write the record: {exc}")
        return EXIT_FATAL


if __name__ == "__main__":
    sys.exit(main())
