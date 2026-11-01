"""tests/unit/test_stage_b_leftovers.py
------------------------------------
Six small gaps of the workbench, closed: whose applicability answers these are, a response
that names nothing, `engagement authorise`, a retest of another target, the not-covered
list in the terminal, and a review record's scope in M8. In every one, nothing reads more
favourable than the evidence, and accountability has a name.
"""

from __future__ import annotations

import json
import re
import shutil
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from test_engagement import GIT, _fill, _git, _init, _record, _tree
from test_fixes_outcome import POLICY, _m, _plan_surface, _run

from aisafe.assessment.assess import _previous_problem, run_assessment
from aisafe.assessment.cli import main as assess_main
from aisafe.assessment.render import (
    _mechanism_blocks,
    render_html,
    render_markdown,
    render_terminal,
)
from aisafe.engagement import model
from aisafe.engagement.cli import main as eng_main

needs_git = pytest.mark.skipif(GIT is None, reason="git not on PATH")
NO_VIOLATION = "no_violation_identified_within_assessed_scope"
SHA = "a" * 64


def _assess(root: Path, eng: Path, **kw: Any) -> dict[str, Any]:
    run = run_assessment(
        root,
        [eng / model.INVESTIGATIONS_DIR],
        mode="auditor",
        engagement=model.load_engagement(eng),
        **kw,
    )
    assert run.document is not None, run.fatal
    return run.document


def _engagement(tmp_path: Path, **answers: Any) -> tuple[Path, str, Path]:
    root, commit = _tree(tmp_path)
    eng = _init(tmp_path, root)
    _fill(eng, commit, **answers)
    _record(root, commit, eng)
    return root, commit, eng


def _first_legal_lines(doc: dict[str, Any]) -> dict[str, str]:
    """The first line of the legal section, in each format that renders one."""
    terminal = render_terminal(doc).splitlines()
    heading = next(i for i, line in enumerate(terminal) if line.startswith("Legal profiles"))
    md = render_markdown(doc).split("## Legal profiles\n\n", 1)[1]
    html = render_html(doc).split("Legal profiles</h2>", 1)[1]
    return {
        "terminal": terminal[heading + 1],
        "markdown": md.splitlines()[0],
        "html": html.split("<li>", 1)[1].split("</li>", 1)[0],
    }


# ---------------------------------------------------------------------------
# 1. Whose applicability answers these are
# ---------------------------------------------------------------------------


@needs_git
def test_every_format_says_the_answers_are_the_auditors_own(tmp_path: Path) -> None:
    root, _, eng = _engagement(tmp_path)
    doc = _assess(root, eng)
    assert doc["legal"]["answers_source"]["state"] == "auditor"
    for line in _first_legal_lines(doc).values():
        assert "auditor" in line and "own" in line and "NOT" not in line


@needs_git
def test_answers_named_by_the_audited_team_are_said_on_the_first_line_and_not_refused(
    tmp_path: Path, capsys
) -> None:
    root, _, eng = _engagement(tmp_path, answered_by="B. Owner, CTO of the auditee")
    doc = _assess(root, eng)
    source = doc["legal"]["answers_source"]
    assert source == {
        "state": "not_auditor",
        "answered_by": "B. Owner, CTO of the auditee",
        "auditor": "T. Auditor",
    }
    for line in _first_legal_lines(doc).values():
        assert "NOT" in line and "B. Owner" in line and "T. Auditor" in line
    # The answers are still read: legitimate input, shown for what it is.
    assert doc["legal"]["answers"]["answered_by"] == "B. Owner, CTO of the auditee"
    capsys.readouterr()
    eng_main(["status", "--engagement", str(eng)])
    assert "NOT the auditor's own" in capsys.readouterr().out
    eng_main(["status", "--engagement", str(eng), "--format", "json"])
    assert json.loads(capsys.readouterr().out)["applicability_source"]["state"] == "not_auditor"


@pytest.mark.parametrize(
    ("mode", "by", "name", "state"),
    [
        ("auditor", "t.  auditor ", "T. Auditor", "auditor"),
        ("auditor", "T. Auditor (lead)", "T. Auditor", "not_auditor"),
        ("auditor", None, "T. Auditor", "unnamed"),
        ("auditor", "T. Auditor", None, "no_auditor"),
    ],
)
def test_only_the_same_name_reads_as_the_auditors_own(
    mode: str, by: str | None, name: str | None, state: str
) -> None:
    data = {"mode": mode, "applicability": {"answered_by": by}, "auditor": {"name": name}}
    assert model.answers_source(data)["state"] == state


def test_self_assessment_has_no_auditor_to_compare() -> None:
    data = {"mode": "self-assessment", "applicability": {"answered_by": "x"}, "auditor": {}}
    assert model.answers_source(data) is None


def test_the_terminal_filter_can_no_longer_hide_the_first_line() -> None:
    source = {"state": "not_auditor", "answered_by": "not covered: me", "auditor": "A"}
    doc = {"legal": {"note": "n", "answers": {}, "answers_source": source, "profiles": []}}
    assert "NOT the auditor's own" in render_terminal(doc)


# ---------------------------------------------------------------------------
# 2. A response that names nothing
# ---------------------------------------------------------------------------


@needs_git
def test_an_unmatched_response_is_flagged_in_every_format_and_in_status(
    tmp_path: Path, capsys
) -> None:
    root, _, eng = _engagement(tmp_path)
    # `respond` stays permissive: it cannot always know the ids.
    assert (
        eng_main(
            ["respond", "--engagement", str(eng), "--to", "M55", "--by", "B. Owner", "--text", "no"]
        )
        == 0
    )
    assert assess_main([str(root), "--engagement", str(eng)]) == 1
    doc = json.loads((eng / "assessment" / "assessment.json").read_text(encoding="utf-8"))
    assert doc["auditee"]["unmatched"] == ["responses/response-001.json"]
    needle = "response responses/response-001.json answers M55, which names nothing"
    auditee_md = render_markdown(doc).split("## Auditee inputs", 1)[1].split("## Remediation")[0]
    auditee_html = render_html(doc).split("Auditee inputs</h2>", 1)[1].split("Remediation</h2>")[0]
    assert needle in auditee_md and needle in auditee_html
    assert needle in render_terminal(doc)
    capsys.readouterr()
    assert eng_main(["status", "--engagement", str(eng), "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["unmatched_responses"] == [{"file": "responses/response-001.json", "to": "M55"}]
    eng_main(["status", "--engagement", str(eng)])
    assert "response-001.json answers M55, which names nothing" in capsys.readouterr().out


@needs_git
def test_a_bare_provision_id_of_one_profile_is_placed_beside_that_provision(tmp_path: Path) -> None:
    root, _, eng = _engagement(tmp_path)
    model.add_response(eng, to="bpc-22602-a", by="B. Owner", text="We answer this one.")
    doc = _assess(root, eng)
    assert doc["auditee"]["unmatched"] == []
    assert doc["auditee"]["responses"][0]["resolved_to"] == "us-ca-sb243/bpc-22602-a"
    legal = render_markdown(doc).split("## Legal profiles", 1)[1].split("## Machine inputs")[0]
    assert "We answer this one." in legal


@needs_git
def test_a_response_to_a_profile_the_engagement_did_not_select_stays_unmatched(
    tmp_path: Path,
) -> None:
    root, _, eng = _engagement(tmp_path, jurisdictions=["EU"])
    model.add_response(eng, to="bpc-22602-a", by="B. Owner", text="x")
    model.add_response(eng, to="us-ca-sb243/bpc-22602-a", by="B. Owner", text="y")
    assert len(_assess(root, eng)["auditee"]["unmatched"]) == 2


def test_a_bare_provision_id_two_profiles_hold_says_nothing_about_which() -> None:
    document = {
        "legal": {
            "profiles": [
                {"id": "one", "provisions": [{"id": "same"}, {"id": "only-one"}]},
                {"id": "two", "provisions": [{"id": "same"}]},
            ]
        }
    }
    responses = [{"file": "a", "to": "same"}, {"file": "b", "to": "only-one"}]
    assert model.place_responses(responses, document) == ["a"]
    assert "resolved_to" not in responses[0] and responses[1]["resolved_to"] == "one/only-one"


def test_a_record_carried_by_a_retest_is_a_record_the_response_can_name() -> None:
    document = {"remediation": {"carried_records": [{"id": "inv-old"}]}}
    assert model.place_responses([{"file": "a", "to": "inv-old"}], document) == []


def test_a_matched_response_to_a_record_is_placed_whatever_the_records_claim() -> None:
    response = {"id": "r", "to": "rec-1", "by": "b", "date": "d", "text": "beside the record"}
    doc = {
        "outcome": {"mechanisms": [{"id": "M1", "name": "n", "outcome": "inconclusive"}]},
        # Accepted, and in none of a mechanism's lists: an upheld, incomplete `establishes`.
        "machine": {"records": [{"id": "rec-1", "mechanism": "M1"}]},
        "auditee": {"responses": [response]},
    }
    assert model.place_responses([response], doc) == []
    assert any("beside the record" in line for line in _mechanism_blocks(doc)[0][1])


@needs_git
def test_status_with_no_assessment_says_it_cannot_tell(tmp_path: Path, capsys) -> None:
    root, commit = _tree(tmp_path)
    eng = _init(tmp_path, root)
    _fill(eng, commit)
    model.add_response(eng, to="anything", by="B. Owner", text="x")
    capsys.readouterr()
    eng_main(["status", "--engagement", str(eng), "--format", "json"])
    assert json.loads(capsys.readouterr().out)["unmatched_responses"] is None
    eng_main(["status", "--engagement", str(eng)])
    assert "which responses name something is unknown" in capsys.readouterr().out


@needs_git
def test_status_with_an_unreadable_assessment_is_not_a_clean_bill(tmp_path: Path, capsys) -> None:
    root, _, eng = _engagement(tmp_path)
    assert assess_main([str(root), "--engagement", str(eng)]) == 1
    model.add_response(eng, to="M6", by="B. Owner", text="x")
    (eng / "assessment" / "assessment.json").write_text("not json", encoding="utf-8")
    capsys.readouterr()
    assert eng_main(["status", "--engagement", str(eng)]) == 1
    assert "which responses name something is unknown" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# 3. `engagement authorise`
# ---------------------------------------------------------------------------


def _authorise(eng: Path, file: Path, *extra: str) -> int:
    return eng_main(
        [
            "authorise",
            "--engagement",
            str(eng),
            "--what",
            "authorisation to test the staging endpoint",
            "--by",
            "B. Owner <CTO>",
            "--date",
            "2026-10-29",
            "--file",
            str(file),
            *extra,
        ]
    )


@needs_git
def test_authorise_copies_hashes_and_adds_the_entry_beside_a_hand_written_one(
    tmp_path: Path,
) -> None:
    root, commit = _tree(tmp_path)
    eng = _init(tmp_path, root)
    _fill(eng, commit)
    signed = tmp_path / "signed.pdf"
    signed.write_bytes(b"signed by the CTO")
    assert (
        _authorise(eng, signed, "--endpoint", "https://test.example/chat", "--data", "synthetic")
        == 0
    )
    entries = model.load_engagement(eng).data["authorisations"]
    assert entries[0]["by"] == "the auditee's CTO"  # the hand-written one, untouched
    assert entries[1] == {
        "what": "authorisation to test the staging endpoint",
        "by": "B. Owner <CTO>",
        "date": "2026-10-29",
        "endpoint": "https://test.example/chat",
        "data": "synthetic",
        "document": {
            "path": "authorisations/signed.pdf",
            "sha256": model.file_sha256(signed),
        },
    }
    assert (eng / "authorisations" / "signed.pdf").read_bytes() == b"signed by the CTO"


@needs_git
def test_status_and_the_bundle_read_the_document_authorise_wrote(tmp_path: Path, capsys) -> None:
    root, _, eng = _engagement(tmp_path)
    signed = tmp_path / "signed.pdf"
    signed.write_bytes(b"signed")
    assert _authorise(eng, signed) == 0
    assert assess_main([str(root), "--engagement", str(eng)]) == 1
    bundle = json.loads((eng / "assessment" / "bundle.json").read_text(encoding="utf-8"))
    rows = [row for row in bundle["inputs"] if row["role"] == "written authorisation"]
    assert [row["sha256"] for row in rows] == [model.file_sha256(signed)]
    capsys.readouterr()
    eng_main(["status", "--engagement", str(eng)])
    assert "document intact" in capsys.readouterr().out
    (eng / "authorisations" / "signed.pdf").write_bytes(b"edited afterwards")
    assert eng_main(["status", "--engagement", str(eng)]) == 1
    assert "document changed" in capsys.readouterr().out


@needs_git
def test_status_says_when_an_authorisation_came_after_the_assessment(
    tmp_path: Path, capsys
) -> None:
    root, _, eng = _engagement(tmp_path)
    assert assess_main([str(root), "--engagement", str(eng)]) == 1
    signed = tmp_path / "signed.pdf"
    signed.write_bytes(b"signed")
    assert _authorise(eng, signed) == 0
    capsys.readouterr()
    assert eng_main(["status", "--engagement", str(eng)]) == 1
    assert "authorisations/signed.pdf came after the assessment" in capsys.readouterr().out


@needs_git
@pytest.mark.parametrize(
    ("over", "message"),
    [
        ({"--date": "29 October 2026"}, "ISO date"),
        ({"--by": "  "}, "--what and --by"),
        ({"--file": "no-such-file.pdf"}, "no such file"),
    ],
)
def test_authorise_refuses_what_names_nobody_or_nothing(
    tmp_path: Path, capsys, over: dict[str, str], message: str
) -> None:
    root, commit = _tree(tmp_path)
    eng = _init(tmp_path, root)
    _fill(eng, commit)
    signed = tmp_path / "signed.pdf"
    signed.write_bytes(b"signed")
    args = {
        "--what": "to test",
        "--by": "B. Owner",
        "--date": "2026-10-29",
        "--file": str(signed),
        **over,
    }
    flat = [item for pair in args.items() for item in pair]
    assert eng_main(["authorise", "--engagement", str(eng), *flat]) == 2
    assert message in capsys.readouterr().err
    assert len(model.load_engagement(eng).data["authorisations"]) == 1


@needs_git
def test_authorise_never_writes_over_another_document_or_repeats_an_entry(tmp_path: Path) -> None:
    root, commit = _tree(tmp_path)
    eng = _init(tmp_path, root)
    _fill(eng, commit)
    signed = tmp_path / "signed.pdf"
    signed.write_bytes(b"first")
    assert _authorise(eng, signed) == 0
    assert _authorise(eng, signed) == 2  # the same entry twice would count twice
    assert _authorise(eng, eng / "authorisations" / "signed.pdf", "--data", "more") == 0
    signed.write_bytes(b"another document, the same name")
    assert _authorise(eng, signed, "--data", "other") == 2
    assert (eng / "authorisations" / "signed.pdf").read_bytes() == b"first"


@needs_git
def test_init_refuses_another_engagements_authorisations(tmp_path: Path, capsys) -> None:
    root, _ = _tree(tmp_path)
    eng = tmp_path / "engagement"
    (eng / "authorisations").mkdir(parents=True)
    (eng / "authorisations" / "old.pdf").write_bytes(b"old")
    args = ["init", "--engagement", str(eng), "--target", str(root)]
    assert eng_main(args) == 2
    assert "authorisations" in capsys.readouterr().err


def _report(tmp_path: Path) -> str:
    path = tmp_path / "evaluation-report.json"
    path.write_text("{}", encoding="utf-8")
    return str(path)


NO_ENDPOINT = "no written authorisation names an endpoint"


@needs_git
def test_an_evaluation_report_with_no_endpoint_authorised_is_said_not_refused(
    tmp_path: Path,
) -> None:
    root, _, eng = _engagement(tmp_path)
    doc = _assess(root, eng, evaluation_report=_report(tmp_path))
    assert doc["engagement"]["evaluation_endpoint_named"] is False
    for text in (render_markdown(doc), render_html(doc), render_terminal(doc)):
        assert NO_ENDPOINT in text


@needs_git
def test_no_line_when_an_authorisation_names_the_endpoint(tmp_path: Path) -> None:
    root, _, eng = _engagement(tmp_path)
    signed = tmp_path / "signed.pdf"
    signed.write_bytes(b"signed")
    assert _authorise(eng, signed, "--endpoint", "https://test.example/chat") == 0
    doc = _assess(root, eng, evaluation_report=_report(tmp_path))
    assert doc["engagement"]["evaluation_endpoint_named"] is True
    assert NO_ENDPOINT not in render_markdown(doc)


@needs_git
def test_a_changed_document_names_no_endpoint(tmp_path: Path) -> None:
    root, _, eng = _engagement(tmp_path)
    signed = tmp_path / "signed.pdf"
    signed.write_bytes(b"signed")
    assert _authorise(eng, signed, "--endpoint", "https://test.example/chat") == 0
    (eng / "authorisations" / "signed.pdf").write_bytes(b"edited afterwards")
    doc = _assess(root, eng, evaluation_report=_report(tmp_path))
    assert doc["engagement"]["evaluation_endpoint_named"] is False


@needs_git
def test_a_hand_written_entry_naming_an_endpoint_still_counts(tmp_path: Path) -> None:
    root, _, eng = _engagement(tmp_path)
    path = eng / model.ENGAGEMENT_FILE
    data = json.loads(path.read_text(encoding="utf-8"))
    data["authorisations"][0]["endpoint"] = "https://test.example/chat"
    path.write_text(json.dumps(data), encoding="utf-8")
    doc = _assess(root, eng, evaluation_report=_report(tmp_path))
    assert doc["engagement"]["evaluation_endpoint_named"] is True


@needs_git
def test_without_an_evaluation_report_nothing_is_said_about_endpoints(tmp_path: Path) -> None:
    root, _, eng = _engagement(tmp_path)
    doc = _assess(root, eng)
    assert "evaluation_endpoint_named" not in doc["engagement"]
    assert NO_ENDPOINT not in render_markdown(doc)


# ---------------------------------------------------------------------------
# 4. A retest of another target
# ---------------------------------------------------------------------------


def _scope(eng: Path, *commits: str) -> None:
    path = eng / model.ENGAGEMENT_FILE
    data = json.loads(path.read_text(encoding="utf-8"))
    data["scope"]["commits"] = list(commits)
    path.write_text(json.dumps(data), encoding="utf-8")


def _commit(root: Path, name: str) -> str:
    (root / name).write_text("more\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", name)
    return _git(root, "rev-parse", "HEAD").strip()


def _previous(root: Path, eng: Path, tmp_path: Path) -> Path:
    out = tmp_path / "previous"
    assert assess_main([str(root), "--engagement", str(eng), "-o", str(out)]) == 1
    return out / "assessment.json"


def _edit(path: Path, change) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    change(data)
    path.write_text(json.dumps(data), encoding="utf-8")


@needs_git
def test_a_retest_prints_the_previous_mode_and_engagement_in_every_format(tmp_path: Path) -> None:
    root, commit, eng = _engagement(tmp_path)
    previous = _previous(root, eng, tmp_path)
    later = _commit(root, "later.txt")
    _scope(eng, commit, later)
    _record(root, later, eng)
    doc = _assess(root, eng, retest=previous)
    before = doc["remediation"]["previous"]
    assert before["mode"] == "auditor"
    assert before["engagement"]["auditor"]["name"] == "T. Auditor"
    line = "previous assessment: mode auditor; engagement: T. Auditor (Test Audit Ltd) for Partial"
    remediation_md = render_markdown(doc).split("## Remediation", 1)[1].split("## Inputs")[0]
    assert line in remediation_md
    assert line in render_html(doc).split("Remediation</h2>", 1)[1]
    assert line in render_terminal(doc)


@needs_git
@pytest.mark.parametrize(
    ("block", "key"),
    [("auditor", "name"), ("auditor", "organisation"), ("auditee", "name")],
)
def test_a_retest_of_another_auditor_or_auditee_is_refused(
    tmp_path: Path, block: str, key: str
) -> None:
    root, _, eng = _engagement(tmp_path)
    previous = _previous(root, eng, tmp_path)
    _edit(previous, lambda data: data["engagement"][block].update({key: "Somebody Else"}))
    run = run_assessment(
        root,
        [eng / model.INVESTIGATIONS_DIR],
        mode="auditor",
        engagement=model.load_engagement(eng),
        retest=previous,
    )
    assert run.document is None and f"another {block}" in run.fatal


@needs_git
def test_a_retest_with_no_engagement_in_the_previous_assessment_is_refused(tmp_path: Path) -> None:
    root, _, eng = _engagement(tmp_path)
    prev = {"mode": "auditor", "engagement": None}
    problem = _previous_problem(prev, "auditor", model.load_engagement(eng))
    assert problem is not None and "another auditor" in problem


@needs_git
def test_a_retest_of_a_commit_on_another_history_is_refused_with_exit_2(
    tmp_path: Path, capsys
) -> None:
    root, first, eng = _engagement(tmp_path)
    _git(root, "checkout", "-q", "-b", "side")
    side = _commit(root, "side.txt")
    _scope(eng, first, side)
    _record(root, side, eng)
    previous = _previous(root, eng, tmp_path)
    _git(root, "checkout", "-q", "-")
    other = _commit(root, "other.txt")
    _scope(eng, first, side, other)
    _record(root, other, eng)
    capsys.readouterr()
    args = [
        str(root),
        "--engagement",
        str(eng),
        "--retest",
        str(previous),
        "-o",
        str(tmp_path / "o"),
    ]
    assert assess_main(args) == 2
    assert "is not an ancestor of this commit" in capsys.readouterr().err


@needs_git
@pytest.mark.parametrize("commit", ["a" * 40, None, "not-a-commit", "--all"])
def test_when_git_cannot_say_the_retest_is_refused_and_says_so(
    tmp_path: Path, commit: str | None
) -> None:
    root, _, eng = _engagement(tmp_path)
    previous = _previous(root, eng, tmp_path)
    _edit(previous, lambda data: data["target"].update(commit=commit))
    run = run_assessment(
        root,
        [eng / model.INVESTIGATIONS_DIR],
        mode="auditor",
        engagement=model.load_engagement(eng),
        retest=previous,
    )
    assert run.document is None and "git cannot say" in run.fatal


@needs_git
def test_a_clone_in_another_folder_and_a_moved_engagement_can_retest(tmp_path: Path) -> None:
    root, commit, eng = _engagement(tmp_path)
    previous = _previous(root, eng, tmp_path)
    later = _commit(root, "later.txt")
    clone = tmp_path / "elsewhere" / "clone"
    _git(tmp_path, "clone", "-q", str(root), str(clone))
    moved = tmp_path / "moved-engagement"
    shutil.copytree(eng, moved)
    _edit(
        moved / model.ENGAGEMENT_FILE,
        lambda data: data["scope"].update(target="../elsewhere/clone", commits=[commit, later]),
    )
    _record(clone, later, moved)
    doc = _assess(clone, moved, retest=previous)
    assert doc["remediation"]["previous"]["commit"] == commit


def test_self_assessment_has_no_auditor_to_hold_a_retest_to() -> None:
    assert _previous_problem({"mode": "self-assessment"}, "self-assessment", None) is None


# ---------------------------------------------------------------------------
# 5. The not-covered list in the terminal
# ---------------------------------------------------------------------------


def _legal_doc(*counts: int) -> dict[str, Any]:
    profiles = [
        {"id": f"p{n}", "not_covered": [f"item {n}.{i}" for i in range(count)]}
        for n, count in enumerate(counts)
    ]
    return {"legal": {"note": "n", "answers": {}, "profiles": profiles}}


def test_the_terminal_counts_what_is_not_covered_past_three_items() -> None:
    lines = [ln for ln in render_terminal(_legal_doc(4)).splitlines() if "not covered" in ln]
    assert [ln.strip() for ln in lines] == ["not covered: 4 item(s), see assessment.md"]


@pytest.mark.parametrize("count", [1, 3])
def test_the_terminal_shows_three_items_or_fewer_on_one_line(count: int) -> None:
    lines = [ln for ln in render_terminal(_legal_doc(count)).splitlines() if "not covered" in ln]
    assert len(lines) == 1
    assert all(f"item 0.{i}" in lines[0] for i in range(count))


def test_a_profile_with_nothing_listed_adds_no_line() -> None:
    assert "not covered" not in render_terminal(_legal_doc(0))


def test_the_files_keep_every_item() -> None:
    doc = _legal_doc(4)
    assert render_markdown(doc).count("not covered: item") == 4
    assert render_html(doc).count("not covered: item") == 4


@needs_git
def test_the_terminal_says_what_each_shipped_profile_leaves_out(tmp_path: Path) -> None:
    root, _, eng = _engagement(tmp_path)
    lines = [ln for ln in render_terminal(_assess(root, eng)).splitlines() if "not covered:" in ln]
    assert len(lines) == 3  # one per profile


# ---------------------------------------------------------------------------
# 6. M8 and a review record's scope
# ---------------------------------------------------------------------------


def _row(file: str = "app.py", scope: tuple[str, ...] = ("M1",), **over: Any) -> dict[str, Any]:
    return {
        "file": "aisafe-review.yaml",
        "policy_version": POLICY.version,
        "reviewed_at": date.today().isoformat(),
        "stale": [],
        "artifact_files": [file],
        "units": [],
        "scope": list(scope),
        **over,
    }


def _hypotheses(*mechanisms: str) -> list[dict[str, Any]]:
    return [_plan_surface("s1", "prompt", "app.py", [(m, "any") for m in mechanisms])]


def test_a_record_scoped_to_m1_does_not_review_a_surface_that_carries_m5() -> None:
    m8 = _m(_run(surfaces=_hypotheses("M5"), review_records=[_row()]), "M8")
    assert m8.outcome == "inconclusive"
    assert [gap.kind for gap in m8.gaps] == ["surface_not_reviewed"]
    assert "app.py" in m8.gaps[0].detail and "in its scope" in m8.gaps[0].detail


def test_a_record_scoped_to_part_of_a_surfaces_mechanisms_does_not_bind_it() -> None:
    surfaces = _hypotheses("M1", "M5")
    assert _m(_run(surfaces=surfaces, review_records=[_row()]), "M8").outcome == "inconclusive"


def test_a_record_scoped_to_every_mechanism_of_the_surface_closes_m8() -> None:
    row = _row(scope=("M1", "M5", "M6"))
    m8 = _m(_run(surfaces=_hypotheses("M1", "M5"), review_records=[row]), "M8")
    assert m8.outcome == NO_VIOLATION


def test_a_surface_with_no_hypotheses_needs_only_the_file_binding() -> None:
    assert _m(_run(surfaces=_hypotheses(), review_records=[_row()]), "M8").outcome == NO_VIOLATION


def test_a_row_without_a_scope_binds_no_surface_with_hypotheses() -> None:
    row = _row()
    del row["scope"]
    assert _m(_run(surfaces=_hypotheses("M1"), review_records=[row]), "M8").outcome != NO_VIOLATION


def test_reference_and_docstring_state_the_scope_rule() -> None:
    from aisafe.assessment import outcome

    assert "`scope` holds every" in " ".join((outcome.__doc__ or "").split())
    reference = Path(__file__).parents[2] / "docs" / "REFERENCE.md"
    text = " ".join(reference.read_text(encoding="utf-8").split())
    assert re.search(r"scope. holds every mechanism", text)
