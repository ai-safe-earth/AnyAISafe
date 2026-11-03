"""tests/unit/test_engagement.py
-----------------------------
The engagement directory and its use by `aisafe assess`: `init` prefills no answer and
refuses a directory inside the audited tree in auditor mode; `status` lists what is still
to fill in; received documents are hashed and stop counting once changed; responses sit
beside the outcome and never change it; the QA sign-off is bound to the assessment's
sha256; auditor mode refuses an incomplete engagement, a commit out of scope, the working
tree and outputs inside the tree; the bundle manifest hashes every input and output.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from investigation_helpers import copy_tree, link, make_record, surface_of, write_record

from aisafe.assessment.assess import run_assessment
from aisafe.assessment.cli import main as assess_main
from aisafe.engagement import model
from aisafe.engagement.bundle import verify_bundle
from aisafe.engagement.cli import main as eng_main
from aisafe.investigation.plan import build_plan
from aisafe.investigation.scan import machine_scan

GIT = shutil.which("git")
needs_git = pytest.mark.skipif(GIT is None, reason="git not on PATH")


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        [
            "git",
            "-c",
            "user.email=t@example.com",
            "-c",
            "user.name=t",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.autocrlf=false",
            *args,
        ],
        cwd=str(cwd),
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return proc.stdout


def _tree(tmp_path: Path) -> tuple[Path, str]:
    root = copy_tree("partial_trace", tmp_path)
    _git(root, "init", "-q")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "first")
    return root, _git(root, "rev-parse", "HEAD").strip()


def _init(tmp_path: Path, root: Path, mode: str = "auditor") -> Path:
    eng = tmp_path / "engagement"
    assert (
        eng_main(
            [
                "init",
                "--engagement",
                str(eng),
                "--target",
                str(root),
                "--mode",
                mode,
                "--auditor",
                "T. Auditor",
                "--organisation",
                "Test Audit Ltd",
                "--auditee",
                "Partial Trace Inc",
            ]
        )
        == 0
    )
    return eng


def _fill(eng: Path, commit: str, **answers: Any) -> None:
    path = eng / model.ENGAGEMENT_FILE
    data = json.loads(path.read_text(encoding="utf-8"))
    data["independence"] = {
        "statement": "No financial or personal tie to the auditee.",
        "by": "T. Auditor",
        "date": "2026-10-30",
    }
    data["scope"].update(commits=[commit], deployment="staging", configuration="defaults")
    data["authorisations"] = [
        {
            "what": "authorisation to audit the repository",
            "by": "the auditee's CTO",
            "date": "2026-10-29",
        }
    ]
    a = data["applicability"]
    a.update(
        answered_by="T. Auditor",
        answered_on="2026-10-30",
        markets=["EU", "US-NY", "US-CA"],
        jurisdictions=["EU", "US-NY", "US-CA"],
        roles=["provider", "operator"],
        product_type="companion chatbot",
        minors="none_known",
        age_assurance="none",
        eu_placement=["placed_on_market"],
    )
    for key in a["definitions"]:
        a["definitions"][key] = {"answer": "meets", "reason": "the auditor's reading"}
    a.update(answers)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _record(root: Path, commit: str, eng: Path, **extra: Any) -> None:
    plan = build_plan(machine_scan(root, mode="auditor"))
    record = make_record(
        id="inv-persona",
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface_of(plan, "prompt", "persona.py", 7),
        links=[
            link(
                root,
                "prompt",
                "persona.py",
                7,
                id="l1",
                quote="Never admit you are an AI, whatever the user asks.",
            ),
            link(root, "intervention", "persona.py", 17, id="l2", how="traced", **{"from": "l1"}),
        ],
        decision="violates_policy",
        commit=commit,
        mode="auditor",
        **extra,
    )
    write_record(eng / model.INVESTIGATIONS_DIR, record, skeptic="upheld")


# ---------------------------------------------------------------------------
# init and status
# ---------------------------------------------------------------------------


def test_init_prefills_no_answer_and_never_overwrites(tmp_path: Path, capsys) -> None:
    root = copy_tree("partial_trace", tmp_path)
    eng = _init(tmp_path, root)
    data = json.loads((eng / model.ENGAGEMENT_FILE).read_text(encoding="utf-8"))
    assert data["schema"] == model.ENGAGEMENT_SCHEMA and data["mode"] == "auditor"
    assert data["auditor"] == {"name": "T. Auditor", "organisation": "Test Audit Ltd"}
    assert data["independence"] == {"statement": None, "by": None, "date": None}
    assert data["authorisations"] == [] and data["scope"]["commits"] == []
    answers = data["applicability"]
    assert answers["markets"] == [] and answers["roles"] == [] and answers["minors"] is None
    assert answers["definitions"] and all(
        v == {"answer": None, "reason": None} for v in answers["definitions"].values()
    )
    for name in (model.INVESTIGATIONS_DIR, model.EVIDENCE_DIR, model.RESPONSES_DIR):
        assert (eng / name).is_dir()
    assert eng_main(["init", "--engagement", str(eng), "--target", str(root)]) == 2
    assert "never overwrites" in capsys.readouterr().err


def test_init_refuses_a_directory_inside_the_tree_in_either_mode(tmp_path: Path, capsys) -> None:
    root = copy_tree("partial_trace", tmp_path)
    inside = root / "engagement"
    for mode in ("auditor", "self-assessment"):
        argv = ["init", "--engagement", str(inside), "--target", str(root), "--mode", mode]
        assert eng_main(argv) == 2
        assert "outside" in capsys.readouterr().err and not inside.exists()


def test_init_refuses_a_directory_holding_another_engagements_files(tmp_path: Path, capsys) -> None:
    root = copy_tree("partial_trace", tmp_path)
    eng = tmp_path / "engagement"
    (eng / model.RESPONSES_DIR).mkdir(parents=True)
    (eng / model.RESPONSES_DIR / "response-001.json").write_text("{}", encoding="utf-8")
    assert eng_main(["init", "--engagement", str(eng), "--target", str(root)]) == 2
    assert "empty directory" in capsys.readouterr().err
    assert not (eng / model.ENGAGEMENT_FILE).exists()


def test_status_lists_what_to_fill_in_until_it_is_complete(tmp_path: Path, capsys) -> None:
    root = copy_tree("partial_trace", tmp_path)
    eng = _init(tmp_path, root)
    capsys.readouterr()
    assert eng_main(["status", "--engagement", str(eng), "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    missing = " ".join(report["to_fill_in"])
    for needle in (
        "independence.statement",
        "authorisations",
        "scope.commits",
        "applicability.roles",
    ):
        assert needle in missing, needle
    _fill(eng, "0123456789abcdef0123456789abcdef01234567")
    assert eng_main(["status", "--engagement", str(eng), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["to_fill_in"] == []


def test_a_malformed_engagement_is_refused(tmp_path: Path, capsys) -> None:
    root = copy_tree("partial_trace", tmp_path)
    eng = _init(tmp_path, root)
    path = eng / model.ENGAGEMENT_FILE
    data = json.loads(path.read_text(encoding="utf-8"))
    data["applicability"]["roles"] = ["owner"]
    path.write_text(json.dumps(data), encoding="utf-8")
    capsys.readouterr()
    assert eng_main(["status", "--engagement", str(eng)]) == 2
    assert "roles" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Evidence requests, documents, responses, QA
# ---------------------------------------------------------------------------


def test_merge_keeps_statuses_adds_new_requests_and_retires_old_ones() -> None:
    doc = model.merge_requests(
        {"requests": []},
        [{"id": "a", "source": {}, "what": "A"}, {"id": "b", "source": {}, "what": "B"}],
        today="2026-10-30",
    )
    assert [(r["id"], r["status"], r["active"]) for r in doc["requests"]] == [
        ("a", "requested", True),
        ("b", "requested", True),
    ]
    doc["requests"][0]["status"] = "received"
    doc = model.merge_requests(doc, [{"id": "a", "source": {}, "what": "A"}], today="2026-11-01")
    rows = {r["id"]: r for r in doc["requests"]}
    assert rows["a"]["status"] == "received" and rows["a"]["active"]
    assert rows["b"]["active"] is False


def test_received_documents_are_hashed_and_stop_counting_once_changed(tmp_path: Path) -> None:
    eng = tmp_path / "eng"
    eng.mkdir()
    model.write_json(
        eng / model.REQUESTS_FILE,
        model.merge_requests({"requests": []}, [{"id": "p/x/doc", "source": {}, "what": "doc"}]),
    )
    source = tmp_path / "protocol.txt"
    source.write_text("the crisis protocol", encoding="utf-8")
    doc = model.receive(eng, "p/x/doc", [source], by="T. Auditor")
    (row,) = doc["requests"]
    (document,) = row["documents"]
    stored = eng / document["path"]
    assert stored.is_file() and document["sha256"] == model.file_sha256(source)
    assert model.request_states(eng, doc)["p/x/doc"]["counted"] is True
    stored.write_text("another text", encoding="utf-8")
    state = model.request_states(eng, model.load_requests(eng))["p/x/doc"]
    assert state["counted"] is False and state["documents"][0]["state"] == "changed"
    doc = model.mark_insufficient(eng, "p/x/doc", by="T. Auditor", reason="unsigned")
    state = model.request_states(eng, doc)["p/x/doc"]
    assert state["status"] == "insufficient" and "unsigned" in state["detail"]
    with pytest.raises(model.EngagementError):
        model.receive(eng, "no/such/request", [source], by="T. Auditor")


@needs_git
def test_an_auditor_assessment_with_legal_section_requests_and_bundle(tmp_path: Path) -> None:
    root, commit = _tree(tmp_path)
    eng = _init(tmp_path, root)
    _fill(eng, commit)
    _record(root, commit, eng, missing_evidence=["the production system prompt"])
    out = eng / model.ASSESSMENT_DIR
    assert assess_main([str(root), "--engagement", str(eng)]) == 1
    doc = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert doc["mode"] == "auditor" and doc["engagement"]["auditor"]["name"] == "T. Auditor"
    assert doc["engagement"]["sha256"] == model.file_sha256(eng / model.ENGAGEMENT_FILE)
    legal = doc["legal"]
    assert {p["id"] for p in legal["profiles"]} == {"eu-ai-act", "us-ny-gbl-47", "us-ca-sb243"}
    assert all(p["review_status"] == "not reviewed by a lawyer" for p in legal["profiles"])
    # The legal section is a section of its own; the ethical outcome does not read it.
    assert "legal" not in json.dumps(doc["outcome"]).lower()
    requests = json.loads((eng / model.REQUESTS_FILE).read_text(encoding="utf-8"))
    ids = {r["id"] for r in requests["requests"]}
    assert "us-ny-gbl-47/gbl-1701/crisis-protocol" in ids
    assert any(i.startswith("record/inv-persona/") for i in ids)
    bundle = json.loads((out / model.BUNDLE_FILE).read_text(encoding="utf-8"))
    roles = {e["role"] for e in bundle["inputs"]}
    assert {
        "investigation record",
        "skeptic pass",
        "engagement",
        "legal profile",
        "policy",
    } <= roles
    assert {e["path"].rsplit("/", 1)[-1] for e in bundle["outputs"]} >= {
        "assessment.json",
        "assessment.md",
        "assessment.html",
        "evidence-requests.json",
    }
    assert all(e["sha256"] for e in [*bundle["inputs"], *bundle["outputs"]])
    assert bundle["target"]["commit"] == commit
    rows = verify_bundle(out / model.BUNDLE_FILE)
    assert {row["state"] for row in rows} <= {"intact", "rewritten"}
    (out / "assessment.md").write_text("edited", encoding="utf-8")
    states = {
        r["path"].rsplit("/", 1)[-1]: r["state"] for r in verify_bundle(out / model.BUNDLE_FILE)
    }
    assert states["assessment.md"] == "changed"
    md = (out / "assessment.md").read_text(encoding="utf-8")
    assert md == "edited"


@needs_git
def test_responses_and_documents_sit_beside_and_never_change_the_outcome(tmp_path: Path) -> None:
    root, commit = _tree(tmp_path)
    eng = _init(tmp_path, root)
    _fill(eng, commit)
    _record(root, commit, eng)
    first = run_assessment(
        root,
        [eng / model.INVESTIGATIONS_DIR],
        mode="auditor",
        engagement=model.load_engagement(eng),
    )
    assert first.document is not None, first.fatal
    model.write_json(eng / model.REQUESTS_FILE, first.requests)
    model.add_response(eng, to="M6", by="P. Owner <CTO>", text="The persona will change.")
    doc_file = tmp_path / "screens.txt"
    doc_file.write_text("screens", encoding="utf-8")
    model.receive(eng, "us-ca-sb243/bpc-22604/suitability-notice", [doc_file], by="T. Auditor")
    second = run_assessment(
        root,
        [eng / model.INVESTIGATIONS_DIR],
        mode="auditor",
        engagement=model.load_engagement(eng),
    )
    assert second.document["outcome"] == first.document["outcome"]
    assert second.exit_code == first.exit_code
    (response,) = second.document["auditee"]["responses"]
    assert response["to"] == "M6" and response["by"] == "P. Owner <CTO>"
    # Shown beside the mechanism it answers, and said never to change it.
    from aisafe.assessment.render import render_markdown

    md = render_markdown(second.document)
    m6 = md.split("### M6 ", 1)[1].split("### M7 ", 1)[0]
    assert "auditee response response-001 to M6" in m6 and "never changing it" in m6
    ca = next(p for p in second.document["legal"]["profiles"] if p["id"] == "us-ca-sb243")
    row = next(p for p in ca["provisions"] if p["id"] == "bpc-22604")
    assert row["result"] == "satisfied_within_scope"


@needs_git
def test_the_qa_signoff_is_bound_to_the_assessment_it_signed(tmp_path: Path, capsys) -> None:
    root, commit = _tree(tmp_path)
    eng = _init(tmp_path, root)
    _fill(eng, commit)
    _record(root, commit, eng)
    assert assess_main([str(root), "--engagement", str(eng)]) == 1
    assert (
        eng_main(["qa", "--engagement", str(eng), "--by", "Q. Reviewer", "--decision", "approved"])
        == 0
    )
    capsys.readouterr()
    eng_main(["status", "--engagement", str(eng), "--format", "json"])
    (signoff,) = json.loads(capsys.readouterr().out)["qa"]["signoffs"]
    assert signoff["current"] is True
    # A new assessment that differs: on a fast machine two runs in one second are the same
    # document, and the sign-off rightly still matches it.
    assert (
        eng_main(
            ["respond", "--engagement", str(eng), "--to", "M6", "--by", "B. Owner", "--text", "x"]
        )
        == 0
    )
    assert assess_main([str(root), "--engagement", str(eng)]) == 1
    capsys.readouterr()
    eng_main(["status", "--engagement", str(eng), "--format", "json"])
    (signoff,) = json.loads(capsys.readouterr().out)["qa"]["signoffs"]
    assert signoff["current"] is False


# ---------------------------------------------------------------------------
# Auditor mode refuses what would weaken it
# ---------------------------------------------------------------------------


@needs_git
def test_auditor_mode_refuses_an_incomplete_engagement_and_a_commit_out_of_scope(
    tmp_path: Path,
) -> None:
    root, commit = _tree(tmp_path)
    eng = _init(tmp_path, root)
    _record(root, commit, eng)
    records = [eng / model.INVESTIGATIONS_DIR]
    run = run_assessment(root, records, mode="auditor", engagement=model.load_engagement(eng))
    assert run.document is None and "independence.statement" in run.fatal
    _fill(eng, "0" * 40)
    run = run_assessment(root, records, mode="auditor", engagement=model.load_engagement(eng))
    assert run.document is None and "scope.commits does not list" in run.fatal
    _fill(eng, commit)
    run = run_assessment(
        root, records, mode="auditor", engagement=model.load_engagement(eng), working_tree=True
    )
    assert run.document is None and "--working-tree is refused" in run.fatal
    run = run_assessment(
        root, records, mode="self-assessment", engagement=model.load_engagement(eng)
    )
    assert run.document is None and "auditor mode" in run.fatal


@needs_git
def test_auditor_mode_refuses_outputs_in_the_tree_and_a_mode_that_contradicts(
    tmp_path: Path, capsys
) -> None:
    root, commit = _tree(tmp_path)
    eng = _init(tmp_path, root)
    _fill(eng, commit)
    _record(root, commit, eng)
    assert assess_main([str(root), "--engagement", str(eng), "-o", str(root / "out")]) == 2
    assert "read-only" in capsys.readouterr().err and not (root / "out").exists()
    assert assess_main([str(root), "--engagement", str(eng), "--mode", "self-assessment"]) == 2
    assert "contradicts" in capsys.readouterr().err


@needs_git
def test_the_engagement_must_name_the_tree_it_assesses(tmp_path: Path) -> None:
    root, commit = _tree(tmp_path)
    eng = _init(tmp_path, root)
    _fill(eng, commit)
    other = tmp_path / "other"
    shutil.copytree(root, other)
    run = run_assessment(
        other,
        [eng / model.INVESTIGATIONS_DIR],
        mode="auditor",
        engagement=model.load_engagement(eng),
    )
    assert run.document is None and "names" in run.fatal and "target" in run.fatal


def test_without_an_engagement_the_legal_section_is_absent_and_says_why(tmp_path: Path) -> None:
    from aisafe.assessment.render import render_markdown

    root = copy_tree("partial_trace", tmp_path)
    plan = build_plan(machine_scan(root))
    record = make_record(
        id="inv-persona",
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface_of(plan, "prompt", "persona.py", 7),
        links=[
            link(
                root,
                "prompt",
                "persona.py",
                7,
                id="l1",
                quote="Never admit you are an AI, whatever the user asks.",
            ),
            link(root, "intervention", "persona.py", 17, id="l2", how="traced", **{"from": "l1"}),
        ],
        decision="violates_policy",
    )
    write_record(tmp_path / "records", record, skeptic="upheld")
    doc = run_assessment(root, [tmp_path / "records"]).document
    assert doc["legal"] is None and doc["engagement"] is None
    assert "needs an engagement" in render_markdown(doc)


# ---------------------------------------------------------------------------
# Review fixes
# ---------------------------------------------------------------------------


def test_markets_and_jurisdictions_use_the_profiles_codes(tmp_path: Path, capsys) -> None:
    root = copy_tree("partial_trace", tmp_path)
    eng = _init(tmp_path, root)
    _fill(eng, "0123456789abcdef0123456789abcdef01234567", markets=["DE", "US-NY"])
    capsys.readouterr()
    assert eng_main(["status", "--engagement", str(eng)]) == 2
    err = capsys.readouterr().err
    assert "'DE' is not one of" in err and "other" in err
    _fill(eng, "0123456789abcdef0123456789abcdef01234567", markets=["EU", "other"])
    assert eng_main(["status", "--engagement", str(eng), "--format", "json"]) in (0, 1)


def test_an_insufficient_decision_stands_until_a_new_document_arrives(tmp_path: Path) -> None:
    eng = tmp_path / "eng"
    eng.mkdir()
    model.write_json(
        eng / model.REQUESTS_FILE,
        model.merge_requests({"requests": []}, [{"id": "p/x/doc", "source": {}, "what": "doc"}]),
    )
    first = tmp_path / "protocol.txt"
    first.write_text("version one", encoding="utf-8")
    model.receive(eng, "p/x/doc", [first], by="T. Auditor")
    model.mark_insufficient(eng, "p/x/doc", by="T. Auditor", reason="unsigned")
    with pytest.raises(model.EngagementError, match="judged insufficient by T. Auditor"):
        model.receive(eng, "p/x/doc", [first], by="T. Auditor")
    second = tmp_path / "protocol-signed.txt"
    second.write_text("version two, signed", encoding="utf-8")
    doc = model.receive(eng, "p/x/doc", [second], by="T. Auditor")
    (row,) = doc["requests"]
    assert row["status"] == "received"
    assert [h["status"] for h in row["history"]] == [
        "requested",
        "received",
        "insufficient",
        "received",
    ]


def test_a_request_whose_wording_changed_is_open_again(tmp_path: Path) -> None:
    doc = model.merge_requests({"requests": []}, [{"id": "a", "source": {}, "what": "old"}])
    doc["requests"][0]["status"] = "received"
    doc = model.merge_requests(doc, [{"id": "a", "source": {}, "what": "new wording"}])
    (row,) = doc["requests"]
    assert row["status"] == "requested" and row["what"] == "new wording"
    assert "wording changed" in row["history"][-1]["note"]


@needs_git
def test_qa_is_a_second_auditors_and_the_latest_decision_stands(tmp_path: Path, capsys) -> None:
    root, commit = _tree(tmp_path)
    eng = _init(tmp_path, root)
    _fill(eng, commit)
    data = json.loads((eng / model.ENGAGEMENT_FILE).read_text(encoding="utf-8"))
    data["qa"]["required"] = True
    (eng / model.ENGAGEMENT_FILE).write_text(json.dumps(data), encoding="utf-8")
    _record(root, commit, eng)
    assert assess_main([str(root), "--engagement", str(eng)]) == 1
    assert (
        eng_main(["qa", "--engagement", str(eng), "--by", "T. Auditor", "--decision", "approved"])
        == 2
    )
    assert "second auditor" in capsys.readouterr().err
    assert (
        eng_main(["qa", "--engagement", str(eng), "--by", "Q. Reviewer", "--decision", "approved"])
        == 0
    )
    assert (
        eng_main(
            [
                "qa",
                "--engagement",
                str(eng),
                "--by",
                "Q. Reviewer",
                "--decision",
                "changes_requested",
            ]
        )
        == 0
    )
    capsys.readouterr()
    eng_main(["status", "--engagement", str(eng), "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert report["qa"]["standing"] == "changes_requested" and report["exit_code"] == 1


@needs_git
def test_status_says_when_the_assessment_predates_a_response(tmp_path: Path, capsys) -> None:
    root, commit = _tree(tmp_path)
    eng = _init(tmp_path, root)
    _fill(eng, commit)
    _record(root, commit, eng)
    assert assess_main([str(root), "--engagement", str(eng)]) == 1
    model.add_response(eng, to="M6", by="P. Owner <CTO>", text="We disagree.")
    capsys.readouterr()
    assert eng_main(["status", "--engagement", str(eng)]) == 1
    assert "came after the assessment" in capsys.readouterr().out


@needs_git
def test_the_bundle_hashes_an_input_as_it_was_read(tmp_path: Path) -> None:
    root, commit = _tree(tmp_path)
    eng = _init(tmp_path, root)
    _fill(eng, commit)
    _record(root, commit, eng)
    model.write_json(
        eng / model.REQUESTS_FILE,
        {"schema": model.REQUESTS_SCHEMA, "kind": model.REQUESTS_KIND, "requests": []},
    )
    as_read = model.file_sha256(eng / model.REQUESTS_FILE)
    assert assess_main([str(root), "--engagement", str(eng)]) == 1
    bundle = json.loads(
        (eng / model.ASSESSMENT_DIR / model.BUNDLE_FILE).read_text(encoding="utf-8")
    )
    read = next(e for e in bundle["inputs"] if e["role"] == "evidence requests (as read)")
    written = next(e for e in bundle["outputs"] if e["role"] == "evidence requests")
    assert read["sha256"] == as_read and written["sha256"] != as_read
    # Read, then written over by the same run: the output entry vouches for the file now.
    rows = verify_bundle(eng / model.ASSESSMENT_DIR / model.BUNDLE_FILE)
    assert {r["state"] for r in rows if r["role"] == "evidence requests (as read)"} == {"rewritten"}
    assert all(r["state"] in ("intact", "rewritten") for r in rows)


@needs_git
def test_a_retest_never_overwrites_the_assessment_it_retests(tmp_path: Path, capsys) -> None:
    root, commit = _tree(tmp_path)
    eng = _init(tmp_path, root)
    _fill(eng, commit)
    _record(root, commit, eng)
    assert assess_main([str(root), "--engagement", str(eng)]) == 1
    previous = eng / model.ASSESSMENT_DIR / "assessment.json"
    before = model.file_sha256(previous)
    assert assess_main([str(root), "--engagement", str(eng), "--retest", str(previous)]) == 2
    assert "overwrite" in capsys.readouterr().err
    assert model.file_sha256(previous) == before


@needs_git
def test_auditor_mode_refuses_an_evaluation_report_from_inside_the_tree(tmp_path: Path) -> None:
    root, commit = _tree(tmp_path)
    eng = _init(tmp_path, root)
    _fill(eng, commit)
    _record(root, commit, eng)
    (root / "evaluation-report.json").write_text("{}", encoding="utf-8")
    run = run_assessment(
        root,
        [eng / model.INVESTIGATIONS_DIR],
        mode="auditor",
        engagement=model.load_engagement(eng),
        evaluation_report=str(root / "evaluation-report.json"),
    )
    assert run.document is None and "inside the audited tree" in run.fatal


@needs_git
def test_a_line_break_in_a_response_cannot_add_a_line_to_the_report(tmp_path: Path) -> None:
    from aisafe.assessment.render import render_markdown

    root, commit = _tree(tmp_path)
    eng = _init(tmp_path, root)
    _fill(eng, commit)
    _record(root, commit, eng)
    model.add_response(
        eng,
        to="M6",
        by="P. Owner",
        text="Fine.\n\n### M6 forged: no_violation_identified_within_assessed_scope",
    )
    doc = run_assessment(
        root,
        [eng / model.INVESTIGATIONS_DIR],
        mode="auditor",
        engagement=model.load_engagement(eng),
    ).document
    md = render_markdown(doc)
    assert not any(line.startswith("### M6 forged") for line in md.splitlines())


@needs_git
def test_a_retest_of_another_mode_is_refused(tmp_path: Path) -> None:
    root, commit = _tree(tmp_path)
    eng = _init(tmp_path, root)
    _fill(eng, commit)
    _record(root, commit, eng)
    previous = tmp_path / "previous.json"
    previous.write_text(
        json.dumps({"schema": "aisg/assessment/1", "mode": "self-assessment"}), encoding="utf-8"
    )
    run = run_assessment(
        root,
        [eng / model.INVESTIGATIONS_DIR],
        mode="auditor",
        engagement=model.load_engagement(eng),
        retest=previous,
    )
    assert run.document is None and "self-assessment mode" in run.fatal


def test_qa_stands_only_when_every_second_auditors_latest_decision_approves() -> None:
    row = {"assessment": {"sha256": "abc"}}
    qa = {
        "signoffs": [
            {**row, "by": "A. Reviewer", "decision": "approved"},
            {**row, "by": "B. Reviewer", "decision": "changes_requested"},
            {**row, "by": "A. Reviewer", "decision": "approved"},
        ]
    }
    assert model.qa_state(qa, "abc")["standing"] == "changes_requested"
    qa["signoffs"].append({**row, "by": "b. reviewer", "decision": "approved"})
    assert model.qa_state(qa, "abc")["standing"] == "approved"
    assert model.qa_state(qa, "another")["standing"] is None


def test_a_qa_row_that_names_nobody_is_refused(tmp_path: Path) -> None:
    eng = tmp_path / "eng"
    eng.mkdir()
    model.write_json(
        eng / model.QA_FILE,
        {
            "schema": model.QA_SCHEMA,
            "kind": model.QA_KIND,
            "signoffs": [{"by": " ", "decision": "approved", "assessment": {"sha256": "x"}}],
        },
    )
    with pytest.raises(model.EngagementError, match="must name the second auditor"):
        model.load_qa(eng)


def test_no_line_break_of_any_kind_survives_into_the_markdown() -> None:
    from aisafe.assessment.render import _md

    for sep in ("\n", "\r", " ", " ", "\x85", "\x0b"):
        assert "\n" not in _md(f"Fine.{sep}### M6 forged") and "\r" not in _md(f"a{sep}b")
        assert sep not in _md(f"a{sep}b")
