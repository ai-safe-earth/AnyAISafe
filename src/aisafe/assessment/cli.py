"""src/aisafe/assessment/cli.py
-----------------------------
`aisafe assess PATH --investigations DIR`: write the assessment.

    aisafe assess . --investigations .aisafe-audit/investigations
    aisafe assess . --investigations .aisafe-audit/investigations --retest previous/assessment.json
    aisafe assess ../acme --engagement ../acme-engagement --evaluation-report eval.json

Writes `assessment.json` (`aisg/assessment/1`, authoritative), `assessment.md`,
`assessment.html` and `bundle.json` (`aisg/bundle/1`: the sha256 of every input and output)
into the output directory and prints a summary. The default output directory is
`.aisafe-audit/assessment/` under the audited tree, or `assessment/` in the engagement
directory when `--engagement` is given. Only this command's output is called an
assessment; `aisafe audit` writes a scan report.

With `--engagement DIR` the mode comes from the engagement, the records default to
DIR/investigations, the legal profiles are read against the engagement's applicability
answers, and DIR/evidence-requests.json is updated (new requests added as `requested`,
existing ones kept as they are). In auditor mode the engagement is required and the
audited tree is read-only: every output goes outside it.

Exit codes: 0 every mechanism has no violation identified within the assessed scope and no
record was rejected; 1 otherwise; 2 fatal (no accepted investigation record, uncommitted
changes without --working-tree, an engagement that cannot be used, unreadable input).
Without investigation records there is no assessment: the command never falls back to the
scan. The legal section never changes the exit code.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from aisafe.discovery.walk import crosses_link
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
            "evaluation reports into an assessment with one outcome per mechanism, and, with "
            "an engagement, a separate legal section. Never a certification."
        ),
    )
    parser.add_argument("path", nargs="?", default=".", help="the audited tree (default: .)")
    parser.add_argument(
        "--investigations",
        nargs="+",
        default=None,
        metavar="DIR",
        help=(
            "investigation record files or directories (required without --engagement; "
            "default with it: DIR/investigations). No records, no assessment"
        ),
    )
    parser.add_argument(
        "--engagement",
        default=None,
        metavar="DIR",
        help="the engagement directory (`aisafe engagement init`); required in auditor mode",
    )
    parser.add_argument(
        "--evaluation-report",
        default=None,
        metavar="FILE",
        help="an `aisafe evaluate` report you ran; in auditor mode the only evaluation read",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=None,
        help=f"where the files go (default: PATH/{DEFAULT_OUTPUT}, or DIR/assessment)",
    )
    parser.add_argument("--format", choices=("terminal", "json"), default="terminal")
    parser.add_argument(
        "--retest",
        default=None,
        metavar="ASSESSMENT",
        help="a previous assessment.json: re-run its records' verification steps on this commit",
    )
    parser.add_argument("--working-tree", action="store_true", help="assess uncommitted files")
    parser.add_argument(
        "--mode",
        choices=MODES,
        default=None,
        help="self-assessment (default) or auditor; with --engagement, the engagement's mode",
    )
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
    from aisafe.engagement import model as eng_model
    from aisafe.engagement.bundle import build_bundle, hash_now

    parser = build_parser()
    ns = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if ns.budget < 1:
            _note("--budget must be at least 1")
            return 2
        engagement = None
        if ns.engagement:
            engagement = eng_model.load_engagement(Path(ns.engagement))
            if ns.mode is not None and ns.mode != engagement.mode:
                _note(f"--mode {ns.mode} contradicts the engagement's mode ({engagement.mode})")
                return 2
        mode = ns.mode or (engagement.mode if engagement is not None else "self-assessment")
        if ns.investigations:
            investigations = [Path(p) for p in ns.investigations]
        elif engagement is not None:
            investigations = [engagement.dir / eng_model.INVESTIGATIONS_DIR]
        else:
            _note("--investigations is required without --engagement")
            return 2
        output_dir = (
            Path(ns.output_dir)
            if ns.output_dir
            else (
                engagement.dir / eng_model.ASSESSMENT_DIR
                if engagement is not None
                else Path(ns.path) / DEFAULT_OUTPUT
            )
        )
        # `.aisafe-audit` can be a link the audited tree delivered.
        if crosses_link(str(output_dir)):
            _note(f"refused: the output {output_dir.as_posix()} goes through a link")
            return 2
        if mode == "auditor" and _inside(output_dir, Path(ns.path)):
            _note("in auditor mode the audited tree is read-only; pass -o outside it")
            return 2
        if ns.retest and (output_dir / "assessment.json").resolve() == Path(ns.retest).resolve():
            # The previous assessment is an input of the retest: it is never overwritten.
            _note("--retest names the assessment this run would overwrite; pass -o elsewhere")
            return 2
        run = run_assessment(
            ns.path,
            investigations,
            mode=mode,
            working_tree=ns.working_tree,
            retest=Path(ns.retest) if ns.retest else None,
            budget=ns.budget,
            engagement=engagement,
            evaluation_report=ns.evaluation_report,
        )
        if run.document is None:
            _note(f"no assessment: {run.fatal}")
            return 2
        inputs = hash_now(run.bundle_inputs)
        written = write_outputs(run.document, output_dir)
        outputs = [{"role": "assessment", "path": p.as_posix()} for p in written]
        if engagement is not None and run.requests is not None:
            requests_path = engagement.dir / eng_model.REQUESTS_FILE
            eng_model.write_json(requests_path, run.requests)
            outputs.append({"role": "evidence requests", "path": requests_path.as_posix()})
        bundle = build_bundle(
            bundle_dir=output_dir,
            document=run.document,
            inputs=inputs,
            outputs=outputs,
            engagement_dir=engagement.dir if engagement is not None else None,
        )
        bundle_path = output_dir / eng_model.BUNDLE_FILE
        eng_model.write_json(bundle_path, bundle)
        _note("assessment written: " + ", ".join(p.as_posix() for p in [*written, bundle_path]))
        if ns.format == "json":
            sys.stdout.write(json.dumps(run.document, indent=2) + "\n")
        else:
            text = render_terminal(run.document)
            sys.stdout.write(text.encode("ascii", "backslashreplace").decode("ascii"))
        return run.exit_code
    except eng_model.EngagementError as exc:
        _note(str(exc))
        return 2
    except KeyboardInterrupt:
        _note("interrupted")
        return 130
    except Exception as exc:  # broad on purpose: every failure is exit 2 with one line
        _note(f"fatal: {type(exc).__name__}: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
