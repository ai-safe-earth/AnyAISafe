"""src/aisafe/cli.py
-----------------
Single entry point for AnyAISafe.

    aisafe --version
    aisafe audit . --format json -o audit-report.json
    aisafe investigate plan . -o .aisafe-audit/investigation-plan.json
    aisafe assess . --investigations .aisafe-audit/investigations
    aisafe engagement init --engagement ../acme-engagement --target .
    aisafe review record --reviewer "J. Doe <product owner>" --purpose "a language tutor"
    aisafe evaluate http://localhost:8000/chat --families goodbye_pressure
    aisafe fleet fleet.yaml --jobs 4 --proposal
    aisafe skill install --host all

Eight commands: `audit` (the static scan of prompts and the code around them),
`investigate` (the plan of surfaces, and the mechanical check of the investigation records
a host coding agent writes), `assess` (the assessment built from the scan and the
validated records, with a separate legal section when an engagement is given),
`engagement` (the auditor's workspace: scope, authorisations, applicability answers,
evidence requests, auditee responses, QA sign-off), `review` (the record a named person
signs about what they read),
`evaluate` (fixed scenarios against an endpoint you are authorised to test, or held
transcripts), `fleet` (many repositories, one audit each) and `skill` (install the agent
skill). `probe` is a hidden
alias of `evaluate` kept for scripts written before the rename; it prints a note on
stderr and runs `evaluate`.

Each command is imported only when invoked, so `aisafe --help` pays for nothing it does
not run. Everything after the command is handed to the tool untouched, so its flags,
defaults and exit codes are unchanged:

    0  nothing counted
    1  findings (audit), a rejected record (investigate validate), a mechanism not
       closed or a rejected record (assess), an engagement with fields to fill in or a
       changed file (engagement status), stale or uncovered artifacts (review check),
       failed cases (evaluate), a repository not audited (fleet), a refused or drifted
       install (skill)
    2  fatal (bad args, unreadable input)

`audit` and `review` add 130 for an interrupted run.
"""

from __future__ import annotations

import argparse
import sys
from typing import Callable, Sequence

from aisafe import __version__

__all__ = ["COMMANDS", "main", "build_parser"]

_EPILOG = """
Commands:
  audit       Audit the prompts and code of a repository for profiling, manipulation,
              engineered attachment, deceptive identity and behavioural influence over
              the person using it; findings carry evidence and a policy decision
  investigate Plan the surfaces an investigation reads, cite lines, and validate the
              investigation records a host coding agent writes, against the tree
  assess      Merge the scan, the validated investigation records, the review records
              and the evaluation reports into an assessment: one outcome per mechanism,
              the scope read and the scope left out, and with an engagement a separate
              legal section; never a certification
  engagement  The auditor's workspace outside the audited tree: who audits whom, the
              scope, the written authorisations, the applicability answers, the evidence
              requested and received, the auditee's responses, the QA sign-off
  review      Write or check the review record: a named person, the artifacts they read
              (bound by content hash), the mechanisms considered, the declared purpose
  evaluate    Send fixed scenarios to an endpoint you are authorised to test, or read
              held transcripts, and report what each reply carried
  fleet       Audit every repository in a list, one subprocess each, and aggregate the
              counts
  skill       Install the packaged ai-safety-audit agent skill into host skill directories

Run `aisafe <command> --help` for a command's own options.

Examples:
  aisafe audit . --format json -o audit-report.json
  aisafe audit . --baseline audit-baseline.json --fail-on high
  aisafe investigate plan . -o .aisafe-audit/investigation-plan.json
  aisafe investigate validate .aisafe-audit/investigations/
  aisafe assess . --investigations .aisafe-audit/investigations
  aisafe engagement init --engagement ../acme-engagement --target . --auditor "A. Auditor"
  aisafe assess . --engagement ../acme-engagement --evaluation-report eval.json
  aisafe engagement status --engagement ../acme-engagement
  aisafe review init
  aisafe review record --reviewer "J. Doe <product owner>" --purpose "a language tutor for adults"
  aisafe evaluate http://localhost:8000/chat --response-path '$.response'
  aisafe evaluate --transcripts conversations.jsonl
  aisafe fleet fleet.yaml --jobs 4 --proposal
  aisafe skill install --host all

Nothing here calls a model, installs anything or publishes anything. A report lists
observations and the project's policy decision on each; it is never a certification, and
absence of a finding is not evidence of safety.
"""

_PROBE_NOTE = 'aisafe: "probe" is now "evaluate"; running `aisafe evaluate` with the same arguments'


def _audit(argv: Sequence[str]) -> int:
    from aisafe.audit import main as audit_main

    return audit_main(list(argv))


def _review(argv: Sequence[str]) -> int:
    from aisafe.review.cli import main as review_main

    return review_main(list(argv))


def _evaluate(argv: Sequence[str]) -> int:
    from aisafe.evaluation.scenarios import main as evaluate_main

    return evaluate_main(list(argv))


def _probe(argv: Sequence[str]) -> int:
    print(_PROBE_NOTE, file=sys.stderr)
    return _evaluate(argv)


def _assess(argv: Sequence[str]) -> int:
    from aisafe.assessment.cli import main as assess_main

    return assess_main(list(argv))


def _engagement(argv: Sequence[str]) -> int:
    from aisafe.engagement.cli import main as engagement_main

    return engagement_main(list(argv))


def _investigate(argv: Sequence[str]) -> int:
    from aisafe.investigation.cli import main as investigate_main

    return investigate_main(list(argv))


def _fleet(argv: Sequence[str]) -> int:
    from aisafe.devtools.fleet import main as fleet_main

    return fleet_main(list(argv))


def _skill(argv: Sequence[str]) -> int:
    from aisafe.devtools.skill import main as skill_main

    return skill_main(list(argv))


COMMANDS: dict[str, Callable[[Sequence[str]], int]] = {
    "audit": _audit,
    "review": _review,
    "evaluate": _evaluate,
    "investigate": _investigate,
    "assess": _assess,
    "engagement": _engagement,
    "fleet": _fleet,
    "skill": _skill,
    "probe": _probe,  # hidden alias of `evaluate`; not listed in the epilog
}

# The commands a person is shown: the help line, the error for a wrong name and the
# epilog all list these. The alias dispatches but is named nowhere.
PUBLIC_COMMANDS: tuple[str, ...] = (
    "audit",
    "investigate",
    "assess",
    "engagement",
    "review",
    "evaluate",
    "fleet",
    "skill",
)


def _command(name: str) -> str:
    """argparse `type` for the command: accept every key of COMMANDS, name only the public
    ones when refusing (an alias kept for old scripts is not a choice to offer)."""
    if name in COMMANDS:
        return name
    raise argparse.ArgumentTypeError(
        f"invalid choice: {name!r} (choose from {', '.join(PUBLIC_COMMANDS)})"
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aisafe",
        description=(
            "AnyAISafe: audit the prompts and algorithms of AI-enabled software for how "
            "they influence the person using it."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EPILOG,
    )
    p.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"aisafe {__version__}",
    )
    # `type` validates in place of `choices`, so the hidden alias appears in no usage
    # line, help line or error message; the Commands block of the epilog is the list a
    # person reads.
    p.add_argument(
        "command",
        type=_command,
        metavar="command",
        help="one of: " + ", ".join(PUBLIC_COMMANDS),
    )
    # REMAINDER hands the rest through verbatim, so each tool keeps its own
    # flags, help text and pyproject-sourced defaults.
    p.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="arguments passed through to the command",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        parser.print_help()
        return 2
    ns = parser.parse_args(argv)
    return COMMANDS[ns.command](ns.args)


if __name__ == "__main__":
    sys.exit(main())
