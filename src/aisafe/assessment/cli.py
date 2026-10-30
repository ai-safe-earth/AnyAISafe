"""src/aisafe/assessment/cli.py
-----------------------------
`aisafe assess PATH --investigations DIR`: write the assessment.

    aisafe assess . --investigations .aisafe-audit/investigations
    aisafe assess . --investigations .aisafe-audit/investigations --retest previous/assessment.json

Writes `assessment.json` (`aisg/assessment/1`, authoritative), `assessment.md` and
`assessment.html` into the output directory (default `.aisafe-audit/assessment/` under the
audited tree) and prints a summary. Only this command's output is called an assessment;
`aisafe audit` writes a scan report.

Exit codes: 0 every mechanism has no violation identified within the assessed scope and no
record was rejected; 1 otherwise; 2 fatal (no accepted investigation record, uncommitted
changes without --working-tree, unreadable input). Without investigation records there is
no assessment: the command never falls back to the scan.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from aisafe.evidence.model import MODES

__all__ = ["build_parser", "main"]

PROG = "aisafe assess"
DEFAULT_OUTPUT = ".aisafe-audit/assessment"


def _note(message: str) -> None:
    print(f"{PROG}: {message}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Merge the scan, the validated investigation records, the review records and the "
            "evaluation reports into an assessment with one outcome per mechanism. Never a "
            "certification."
        ),
    )
    parser.add_argument("path", nargs="?", default=".", help="the audited tree (default: .)")
    parser.add_argument(
        "--investigations",
        nargs="+",
        required=True,
        metavar="DIR",
        help="investigation record files or directories (required: no records, no assessment)",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=None,
        help=f"where the three files go (default: PATH/{DEFAULT_OUTPUT})",
    )
    parser.add_argument("--format", choices=("terminal", "json"), default="terminal")
    parser.add_argument(
        "--retest",
        default=None,
        metavar="ASSESSMENT",
        help="a previous assessment.json: re-run its records' verification steps on this commit",
    )
    parser.add_argument("--working-tree", action="store_true", help="assess uncommitted files")
    parser.add_argument("--mode", choices=MODES, default="self-assessment")
    parser.add_argument("--budget", type=int, default=20, help="surfaces the plan queues")
    return parser


def _inside(path: Path, tree: Path) -> bool:
    try:
        path.resolve().relative_to(tree.resolve())
    except ValueError:
        return False
    return True


def write_outputs(document: dict, output_dir: Path) -> list[Path]:
    from aisafe.assessment.render import render_html, render_markdown

    output_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, text in (
        ("assessment.json", json.dumps(document, indent=2, ensure_ascii=False) + "\n"),
        ("assessment.md", render_markdown(document)),
        ("assessment.html", render_html(document)),
    ):
        path = output_dir / name
        path.write_text(text, encoding="utf-8", newline="\n")
        paths.append(path)
    return paths


def main(argv: Sequence[str] | None = None) -> int:
    from aisafe.assessment.assess import run_assessment
    from aisafe.assessment.render import render_terminal

    parser = build_parser()
    ns = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if ns.budget < 1:
            _note("--budget must be at least 1")
            return 2
        run = run_assessment(
            ns.path,
            [Path(p) for p in ns.investigations],
            mode=ns.mode,
            working_tree=ns.working_tree,
            retest=Path(ns.retest) if ns.retest else None,
            budget=ns.budget,
        )
        if run.document is None:
            _note(f"no assessment: {run.fatal}")
            return 2
        output_dir = Path(ns.output_dir) if ns.output_dir else Path(ns.path) / DEFAULT_OUTPUT
        if ns.mode == "auditor" and _inside(output_dir, Path(ns.path)):
            _note("in auditor mode the audited tree is read-only; pass -o outside it")
            return 2
        written = write_outputs(run.document, output_dir)
        _note("assessment written: " + ", ".join(p.as_posix() for p in written))
        if ns.format == "json":
            sys.stdout.write(json.dumps(run.document, indent=2) + "\n")
        else:
            text = render_terminal(run.document)
            sys.stdout.write(text.encode("ascii", "backslashreplace").decode("ascii"))
        return run.exit_code
    except KeyboardInterrupt:
        _note("interrupted")
        return 130
    except Exception as exc:  # broad on purpose: every failure is exit 2 with one line
        _note(f"fatal: {type(exc).__name__}: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
