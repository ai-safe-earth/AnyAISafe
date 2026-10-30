"""src/aisafe/engagement/cli.py
----------------------------
`aisafe engagement`: the auditor's workspace for one engagement.

    aisafe engagement init --engagement ../acme-engagement --target . --auditor "A. Auditor" \\
        --organisation "Audit Org" --auditee "Acme Ltd"
    aisafe engagement status --engagement ../acme-engagement
    aisafe engagement receive --engagement ../acme-engagement --request ID --file protocol.pdf \\
        --by "A. Auditor"
    aisafe engagement insufficient --engagement ../acme-engagement --request ID \\
        --by "A. Auditor" --reason "the protocol does not name the crisis services"
    aisafe engagement respond --engagement ../acme-engagement --to M5 --by "B. Owner <CTO>" \\
        --text "..."
    aisafe engagement qa --engagement ../acme-engagement --by "C. Reviewer" --decision approved

`init` writes `engagement.json` with the names given and every other field empty: the
independence statement, the scope, the authorisations and the applicability answers are
written by a person, never prefilled. In auditor mode the engagement directory must be
outside the audited tree. `status` says what is still to fill in, the state of every
evidence request and received document, the auditee's responses, whether the last
assessment's bundle still matches, and the QA sign-offs.

The auditor decides. The auditee's evidence and responses are shown beside the outcome and
never change it; `receive`, `insufficient`, `respond` and `qa` record what a named person
did or said, on that person's instruction.

Exit codes: 0 done (status: complete and nothing changed); 1 status found something to
fill in, a changed document or a stale bundle; 2 fatal.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Sequence

from aisafe.engagement import model
from aisafe.evidence.model import MODES

__all__ = ["build_parser", "main"]

PROG = "aisafe engagement"


def _note(message: str) -> None:
    print(f"{PROG}: {message}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "The engagement directory of an assessment: who audits whom, the scope, the "
            "authorisations, the applicability answers, the evidence requested and received, "
            "the auditee's responses and the QA sign-off."
        ),
    )
    sub = parser.add_subparsers(dest="action", required=True, metavar="action")

    def add(name: str, help_text: str) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_text, description=help_text)
        p.add_argument(
            "--engagement", required=True, metavar="DIR", help="the engagement directory"
        )
        return p

    p = add("init", "write a new engagement.json with every answer empty")
    p.add_argument("--target", required=True, metavar="PATH", help="the audited tree")
    p.add_argument("--mode", choices=MODES, default="auditor")
    p.add_argument("--auditor", default=None, help="the auditor's name")
    p.add_argument("--organisation", default=None, help="the auditor's organisation")
    p.add_argument("--auditee", default=None, help="whose system is audited")

    p = add("status", "what is still to fill in, and the state of every file")
    p.add_argument("--format", choices=("terminal", "json"), default="terminal")

    p = add("receive", "record documents received for an evidence request (copied and hashed)")
    p.add_argument("--request", required=True, metavar="ID")
    p.add_argument("--file", required=True, nargs="+", metavar="FILE")
    p.add_argument("--by", required=True, help="who received them")
    p.add_argument("--note", default=None)

    p = add("insufficient", "mark an evidence request insufficient, with the reason")
    p.add_argument("--request", required=True, metavar="ID")
    p.add_argument("--by", required=True, help="who decided")
    p.add_argument("--reason", required=True)

    p = add("respond", "record the auditee's management response to a finding")
    p.add_argument(
        "--to",
        required=True,
        metavar="REF",
        help="a mechanism (M5), a record id, a finding fingerprint or profile/provision",
    )
    p.add_argument("--by", required=True, help="who responds, with their role")
    p.add_argument("--text", required=True)
    p.add_argument("--evidence", nargs="*", default=[], metavar="ID", help="evidence request ids")

    p = add("qa", "record a second auditor's sign-off, bound to the assessment's sha256")
    p.add_argument("--by", required=True, help="the second auditor")
    p.add_argument("--decision", required=True, choices=model.QA_DECISIONS)
    p.add_argument("--notes", default=None)
    p.add_argument(
        "--assessment",
        default=None,
        metavar="FILE",
        help=f"default: DIR/{model.ASSESSMENT_DIR}/assessment.json",
    )
    return parser


def _init(ns: argparse.Namespace) -> int:
    from aisafe.legal.profile import definition_questions, load_profiles

    directory = Path(ns.engagement)
    target = Path(ns.target)
    if not target.is_dir():
        _note(f"no such directory: {target.as_posix()}")
        return 2
    if (directory / model.ENGAGEMENT_FILE).exists():
        _note(f"{(directory / model.ENGAGEMENT_FILE).as_posix()} exists; init never overwrites it")
        return 2
    leftovers = [
        name
        for name in (
            model.REQUESTS_FILE,
            model.QA_FILE,
            model.ASSESSMENT_DIR,
            model.EVIDENCE_DIR,
            model.RESPONSES_DIR,
            model.INVESTIGATIONS_DIR,
        )
        if (directory / name).is_file()
        or ((directory / name).is_dir() and any((directory / name).iterdir()))
    ]
    if leftovers:
        # Another engagement's evidence or responses would be read as this one's.
        _note(
            f"{directory.as_posix()} already holds {', '.join(leftovers)}: start a new "
            "engagement in an empty directory"
        )
        return 2
    if model.inside(directory, target):
        # The engagement lives outside the audited tree, in either mode.
        _note("put the engagement directory outside the audited tree")
        return 2
    directory.mkdir(parents=True, exist_ok=True)
    for name in (model.INVESTIGATIONS_DIR, model.EVIDENCE_DIR, model.RESPONSES_DIR):
        (directory / name).mkdir(exist_ok=True)
    try:
        target_text = Path(os.path.relpath(target.resolve(), directory.resolve())).as_posix()
    except ValueError:  # another drive on Windows
        target_text = target.resolve().as_posix()

    def name(value: str | None) -> str | None:
        return value.strip() if value and value.strip() else None

    data = model.skeleton(
        target=target_text,
        mode=ns.mode,
        auditor=name(ns.auditor),
        organisation=name(ns.organisation),
        auditee=name(ns.auditee),
        definitions=definition_questions(load_profiles()),
    )
    model.write_json(directory / model.ENGAGEMENT_FILE, data)
    _note(f"wrote {(directory / model.ENGAGEMENT_FILE).as_posix()}")
    print(
        "Fill in engagement.json by hand: the independence statement, the scope (commits, "
        "deployment, configuration, environments), the written authorisations and the "
        "applicability answers. Then run `aisafe engagement status`."
    )
    return 0


def _status(ns: argparse.Namespace) -> int:
    from aisafe.engagement.bundle import verify_bundle
    from aisafe.legal.profile import definition_questions, load_profiles

    directory = Path(ns.engagement)
    eng = model.load_engagement(directory)
    profiles = load_profiles()
    questions = definition_questions(profiles)
    missing = model.missing_fields(eng.data, definitions=questions)
    requests = model.load_requests(directory)
    states = model.request_states(directory, requests)
    responses, response_problems = model.load_responses(directory)
    qa = model.load_qa(directory)
    assessment = directory / model.ASSESSMENT_DIR / "assessment.json"
    bundle = directory / model.ASSESSMENT_DIR / model.BUNDLE_FILE
    bundle_rows = verify_bundle(bundle) if bundle.is_file() else []
    current = model.file_sha256(assessment) if assessment.is_file() else None
    qa_view = model.qa_state(qa, current)
    signoffs = qa_view["signoffs"]
    authorisations = model.authorisation_states(directory, eng.data)
    selected = set(eng.answers.get("jurisdictions") or [])
    changed_docs = [
        doc for state in states.values() for doc in state["documents"] if doc["state"] != "intact"
    ]
    stale = [row for row in bundle_rows if row["state"] not in ("intact", "rewritten")]
    # Inputs the last assessment never read: a response or a document added since.
    bundled = {
        (bundle.parent / row["path"]).resolve() for row in bundle_rows if row["group"] == "inputs"
    }
    unread = []
    if current is not None:
        for response in responses:
            if (directory / response["file"]).resolve() not in bundled:
                unread.append(response["file"])
        for state in states.values():
            for doc in state["documents"]:
                if (directory / str(doc["path"])).resolve() not in bundled:
                    unread.append(str(doc["path"]))
    outstanding = [s for s in states.values() if s["active"] and s["status"] == "requested"]
    changed_auth = [a for a in authorisations if a["state"] in ("changed", "missing")]
    report: dict[str, Any] = {
        "engagement": eng.path.as_posix(),
        "sha256": eng.sha256,
        "mode": eng.mode,
        "auditor": eng.data.get("auditor"),
        "auditee": eng.data.get("auditee"),
        "target": (eng.data.get("scope") or {}).get("target"),
        "commits": eng.commits,
        "profiles": [
            {
                "id": p.id,
                "jurisdiction": p.jurisdiction,
                "selected": p.jurisdiction in selected,
                "legal_review": "reviewed" if p.reviewed else "not reviewed by a lawyer",
            }
            for p in profiles
        ],
        "to_fill_in": missing,
        "definition_questions": questions,
        "requests": list(states.values()),
        "changed_documents": changed_docs,
        "responses": [
            {"file": r["file"], "to": r["to"], "by": r["by"], "date": r.get("date")}
            for r in responses
        ],
        "response_problems": response_problems,
        "assessment": None
        if current is None
        else {"path": assessment.as_posix(), "sha256": current},
        "bundle": {"files": len(bundle_rows), "not_intact": stale} if bundle_rows else None,
        "not_in_last_assessment": unread,
        "outstanding_requests": [s["id"] for s in outstanding],
        "authorisations": authorisations,
        "qa": {
            "required": (eng.data.get("qa") or {}).get("required"),
            "signoffs": signoffs,
            "standing": qa_view["standing"],
        },
    }
    qa_required = bool((eng.data.get("qa") or {}).get("required"))
    # The latest sign-off of the current assessment stands; an earlier approval does not
    # outlive a later request for changes.
    qa_open = qa_required and qa_view["standing"] != "approved"
    exit_code = (
        1
        if (
            missing
            or changed_docs
            or stale
            or response_problems
            or qa_open
            or unread
            or outstanding
            or changed_auth
            or (current is not None and not bundle_rows)
        )
        else 0
    )
    if ns.format == "json":
        sys.stdout.write(json.dumps({**report, "exit_code": exit_code}, indent=2) + "\n")
        return exit_code
    lines = [
        f"engagement: {eng.path.as_posix()} ({eng.mode})",
        f"auditor: {(eng.data.get('auditor') or {}).get('name') or 'not named'}"
        f" ({(eng.data.get('auditor') or {}).get('organisation') or 'no organisation'})",
        f"auditee: {(eng.data.get('auditee') or {}).get('name') or 'not named'}",
        f"target: {report['target']}; commits in scope: {', '.join(eng.commits) or 'none'}",
        "legal profiles: "
        + ", ".join(
            f"{p['id']} ({'selected' if p['selected'] else 'not selected'}; {p['legal_review']})"
            for p in report["profiles"]
        ),
    ]
    if missing:
        lines.append(f"to fill in ({len(missing)}):")
        lines.extend(f"  - {item}" for item in missing)
        open_defs = [k for k in questions if any(k in m for m in missing)]
        for key in open_defs:
            lines.append(f"    {key}: {questions[key]}")
    else:
        lines.append("to fill in: nothing")
    counts: dict[str, int] = {}
    for state in states.values():
        counts[state["status"]] = counts.get(state["status"], 0) + 1
    lines.append(
        f"evidence requests: {len(states)}"
        + (" (" + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) + ")" if counts else "")
    )
    for state in states.values():
        flag = "" if state["active"] else " [no longer asked]"
        lines.append(f"  - {state['id']} [{state['status']}]{flag}: {state['detail']}")
    for doc in changed_docs:
        lines.append(f"  ! {doc['path']} is {doc['state']}: it no longer counts")
    lines.append(f"auditee responses: {len(responses)}")
    lines.extend(f"  ! {problem}" for problem in response_problems)
    lines.append(f"written authorisations: {len(authorisations)}")
    for auth in authorisations:
        if auth["state"] is not None:
            lines.append(f"  - {auth['what']}: document {auth['state']}")
    if current is None:
        lines.append("assessment: none yet")
    else:
        lines.append(f"assessment: {assessment.as_posix()} (sha256 {current[:12]})")
        if bundle_rows:
            lines.append(
                f"bundle: {len(bundle_rows)} file(s), "
                + (f"{len(stale)} changed or missing" if stale else "every file intact")
            )
            lines.extend(f"  ! {row['path']} is {row['state']}" for row in stale)
        else:
            lines.append("bundle: none: nothing vouches for the assessment's inputs")
        for rel in unread:
            lines.append(f"  ! {rel} came after the assessment: run aisafe assess again")
    lines.append(
        f"QA sign-off: {'required' if qa_required else 'optional'}; "
        + (
            "; ".join(
                f"{s['by']} {s['decision']} on {s['date']}"
                + ("" if s["current"] else " (for an earlier assessment)")
                for s in signoffs
            )
            or "none"
        )
        + (f"; standing: {qa_view['standing']}" if qa_view["standing"] else "")
    )
    text = "\n".join(lines) + "\n"
    sys.stdout.write(text.encode("ascii", "backslashreplace").decode("ascii"))
    return exit_code


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    ns = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if ns.action == "init":
            return _init(ns)
        if ns.action == "status":
            return _status(ns)
        directory = Path(ns.engagement)
        eng = model.load_engagement(directory)
        if ns.action == "receive":
            model.receive(directory, ns.request, [Path(f) for f in ns.file], by=ns.by, note=ns.note)
            _note(f"received {len(ns.file)} document(s) for {ns.request}")
            return 0
        if ns.action == "insufficient":
            model.mark_insufficient(directory, ns.request, by=ns.by, reason=ns.reason)
            _note(f"{ns.request} marked insufficient")
            return 0
        if ns.action == "respond":
            path = model.add_response(
                directory, to=ns.to, by=ns.by, text=ns.text, evidence=ns.evidence
            )
            _note(f"wrote {path.as_posix()}")
            return 0
        if ns.action == "qa":
            assessment = (
                Path(ns.assessment)
                if ns.assessment
                else directory / model.ASSESSMENT_DIR / "assessment.json"
            )
            model.add_signoff(
                directory,
                by=ns.by,
                decision=ns.decision,
                assessment=assessment,
                notes=ns.notes,
                auditor=(eng.data.get("auditor") or {}).get("name"),
            )
            _note(f"sign-off by {ns.by} recorded for {assessment.as_posix()}")
            return 0
    except model.EngagementError as exc:
        _note(str(exc))
        return 2
    except KeyboardInterrupt:
        _note("interrupted")
        return 130
    except Exception as exc:  # broad on purpose: every failure is exit 2 with one line
        _note(f"fatal: {type(exc).__name__}: {exc}")
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
