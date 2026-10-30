"""src/aisafe/investigation/cli.py
--------------------------------
`aisafe investigate`: the deterministic half of an investigation.

    aisafe investigate plan . -o .aisafe-audit/investigation-plan.json
    aisafe investigate cite app.py:17
    aisafe investigate validate .aisafe-audit/investigations/
    aisafe investigate digest .aisafe-audit/investigations/inv-crisis.json

`plan` writes the ranked queue of surfaces; `cite` prints a link's `file`, `line`, `quote`
and `sha256` exactly as `validate` will check them; `validate` checks records against the
tree; `digest` prints the hash a skeptic file binds to. None of them reasons about the
code: the reasoning is the investigator's, in the host agent, and enters only as records.

Exit codes: 0 done (validate: every record accepted), 1 a record rejected, 2 fatal.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Sequence

from aisafe.evidence.model import MODES, redact

__all__ = ["build_parser", "main"]

PROG = "aisafe investigate"
_CITE_RE = re.compile(r"^(?P<file>.+?):(?P<line>\d+)(?:-(?P<end>\d+))?$")


def _note(message: str) -> None:
    print(f"{PROG}: {message}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Plan an investigation of the surfaces of a tree, cite lines for a record, and "
            "validate investigation records against the tree. Deterministic; no model."
        ),
    )
    sub = parser.add_subparsers(dest="action", required=True, metavar="action")

    plan = sub.add_parser("plan", help="write the ranked queue of surfaces to investigate")
    plan.add_argument("path", nargs="?", default=".", help="the audited tree (default: .)")
    plan.add_argument("--budget", type=int, default=20, help="surfaces to queue (default: 20)")
    plan.add_argument("--format", choices=("terminal", "json"), default="terminal")
    plan.add_argument("-o", "--output", default=None, help="write the plan here (JSON)")
    plan.add_argument("--mode", choices=MODES, default="self-assessment")

    validate = sub.add_parser("validate", help="check investigation records against the tree")
    validate.add_argument("records", nargs="+", help="record files or directories")
    validate.add_argument("--target", default=".", help="the audited tree (default: .)")
    validate.add_argument("--format", choices=("terminal", "json"), default="terminal")
    validate.add_argument("-o", "--output", default=None, help="write the result here")
    validate.add_argument("--mode", choices=MODES, default="self-assessment")
    validate.add_argument(
        "--working-tree",
        action="store_true",
        help="check quotes against uncommitted files on disk (the result says so)",
    )

    cite = sub.add_parser("cite", help="print a citation (file, line, quote, sha256) for a record")
    cite.add_argument("location", help="FILE:LINE or FILE:LINE-END, relative to the target")
    cite.add_argument("--target", default=".", help="the audited tree (default: .)")
    cite.add_argument("--mode", choices=MODES, default="self-assessment")

    digest = sub.add_parser("digest", help="print the record_sha256 a skeptic file binds to")
    digest.add_argument("record", help="an investigation record")
    return parser


def _inside(path: Path, tree: Path) -> bool:
    try:
        path.resolve().relative_to(tree.resolve())
    except ValueError:
        return False
    return True


def _ascii(text: str) -> str:
    """What a console of any code page can print: non-ASCII as backslash escapes."""
    return text.encode("ascii", "backslashreplace").decode("ascii")


def _write(text: str, output: str | None) -> None:
    if output is None:
        sys.stdout.write(_ascii(text))
        sys.stdout.flush()
        return
    path = Path(output)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _plan(ns: argparse.Namespace) -> int:
    from aisafe.investigation.plan import build_plan, render_plan
    from aisafe.investigation.scan import machine_scan

    if ns.budget < 1:
        _note("--budget must be at least 1")
        return 2
    if ns.mode == "auditor" and ns.output and _inside(Path(ns.output), Path(ns.path)):
        _note("in auditor mode the audited tree is read-only; write the plan outside it")
        return 2
    scan = machine_scan(ns.path, mode=ns.mode)
    plan = build_plan(scan, budget=ns.budget)
    document = json.dumps(plan, indent=2, ensure_ascii=False) + "\n"
    if ns.output is not None:
        _write(document, ns.output)
        _note(f"plan written to {ns.output} ({plan['counts']['surfaces']} surfaces)")
        if ns.format == "terminal":
            sys.stdout.write(_ascii(render_plan(plan)))
        return 0
    _write(document if ns.format == "json" else render_plan(plan), None)
    return 0


def _validate(ns: argparse.Namespace) -> int:
    from aisafe.investigation.plan import build_plan
    from aisafe.investigation.scan import machine_scan
    from aisafe.investigation.validate import render_validation, validate_paths

    paths = [Path(p) for p in ns.records]
    for path in paths:
        if not path.exists():
            _note(f"no such file or directory: {path.as_posix()}")
            return 2
    scan = machine_scan(ns.target, mode=ns.mode)
    plan = build_plan(scan)
    run = validate_paths(
        paths,
        scan,
        working_tree=ns.working_tree,
        plan_surfaces={s["id"]: s for s in plan["surfaces"]},
    )
    if ns.format == "json":
        text = json.dumps(run.to_dict(), indent=2, ensure_ascii=False) + "\n"
    else:
        text = render_validation(run)
    _write(text, ns.output)
    if run.fatal:
        _note(run.fatal)
    return run.exit_code


def _cite(ns: argparse.Namespace) -> int:
    from aisafe.discovery import walk
    from aisafe.investigation.text import content_sha256, file_lines, normalise

    match = _CITE_RE.match(ns.location.replace("\\", "/"))
    if match is None:
        _note("give the location as FILE:LINE or FILE:LINE-END")
        return 2
    root = Path(ns.target).resolve()
    auditor = ns.mode == "auditor"
    files, _units, _unknown = walk.walk(
        root, walk.WalkOptions(honour_marker=not auditor, skip_own_output=not auditor)
    )
    walked = {record.relpath: record for record in files}
    relpath = match.group("file").strip("/")
    if relpath.startswith("./"):
        relpath = relpath[2:]
    record = walked.get(relpath)
    if record is None:
        _note(f"{relpath} is not a file the scan walks; a record cannot cite it")
        return 2
    lines = file_lines(record.path)
    line = int(match.group("line"))
    end = int(match.group("end")) if match.group("end") else None
    last = end or line
    if line < 1 or last < line or last > len(lines):
        _note(f"{relpath} has {len(lines)} lines")
        return 2
    quoted = [redact(text).rstrip() for text in lines[line - 1 : last]]
    if end is None:
        quote = normalise(quoted[0])
        if not quote:
            _note(f"{relpath}:{line} is blank; cite a line with text on it")
            return 2
    else:
        if not normalise(quoted[0]) or not normalise(quoted[-1]):
            _note("a range starts and ends on a line with text on it")
            return 2
        quote = "\n".join(normalise(text) for text in quoted)
    out = {"file": relpath, "line": line}
    if end is not None:
        out["end_line"] = end
    out["quote"] = quote
    out["sha256"] = content_sha256(record.path)
    sys.stdout.write(json.dumps(out) + "\n")
    return 0


def _digest(ns: argparse.Namespace) -> int:
    from aisafe.investigation.records import RecordError, load_json, record_digest

    try:
        raw = load_json(Path(ns.record))
    except RecordError as exc:
        _note(str(exc))
        return 2
    if not isinstance(raw, dict):
        _note("the record is not a JSON object")
        return 2
    sys.stdout.write(record_digest(raw) + "\n")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    ns = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if ns.action == "plan":
            return _plan(ns)
        if ns.action == "validate":
            return _validate(ns)
        if ns.action == "cite":
            return _cite(ns)
        return _digest(ns)
    except KeyboardInterrupt:
        _note("interrupted")
        return 130
    except Exception as exc:  # broad on purpose: every failure is exit 2 with one line
        _note(f"fatal: {type(exc).__name__}: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
