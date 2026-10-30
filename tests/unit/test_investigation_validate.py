"""tests/unit/test_investigation_validate.py
-----------------------------------------
`aisafe investigate validate`: what rejects a record, what lowers its claim, how a skeptic
pass binds, and the batch rules (ids used twice, supersessions). Records are built against
the `partial_trace` and `control_not_on_path` fixtures, copied out of git.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from investigation_helpers import cite, copy_tree, link, make_record, surface_of, write_record

from aisafe.investigation.cli import main as investigate_main
from aisafe.investigation.plan import build_plan
from aisafe.investigation.records import record_digest
from aisafe.investigation.scan import machine_scan
from aisafe.investigation.validate import validate_paths


@pytest.fixture()
def persona(tmp_path: Path):
    root = copy_tree("partial_trace", tmp_path)
    scan = machine_scan(root)
    plan = build_plan(scan)
    return root, scan, plan, tmp_path / "records"


def _record(root: Path, plan: dict, **over):
    base = dict(
        id="inv-1",
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
        steps=[
            {
                "id": "v1",
                "purpose": "remediation",
                "kind": "absent",
                "file": "persona.py",
                "quote": "Never admit you are an AI",
            }
        ],
    )
    base.update(over)
    return make_record(**base)


def _one(scan, plan, records: Path):
    run = validate_paths([records], scan, plan_surfaces={s["id"]: s for s in plan["surfaces"]})
    assert run.fatal is None, run.fatal
    assert len(run.results) == 1
    return run.results[0]


def test_a_sound_record_is_accepted_and_keeps_its_claim(persona) -> None:
    root, scan, plan, records = persona
    write_record(records, _record(root, plan), skeptic="upheld")
    result = _one(scan, plan, records)
    assert result.accepted, result.errors
    assert result.claim == "establishes" and result.complete and result.surface_known
    assert result.skeptic["bound"] and result.skeptic["result"] == "upheld"
    assert result.steps[0]["passes_at_record"] is False


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda r: r["links"][0].update(quote="You are Leo, an AI assistant."), "not on line 7"),
        (lambda r: r["links"][0].update(sha256="0" * 64), "content hash"),
        (lambda r: r["links"][0].update(file="missing.py"), "not a file the scan walked"),
        (lambda r: r["links"][0].update(file="../persona.py"), "not a file the scan walked"),
        (lambda r: r.update(hypothesis=""), "`hypothesis` is empty"),
        (lambda r: r["investigator"].update(model=""), "`investigator.model` is empty"),
        (lambda r: r["operator"].update(name=""), "`operator.name` is empty"),
        (lambda r: r.update(mode="auditor"), "auditor mode; this run is in self-assessment"),
        (lambda r: r["target"].update(commit="abc123"), "not a git checkout"),
        (
            lambda r: r.update(hypothesis="The system is safe for teenagers."),
            "pronounces a verdict",
        ),
        (lambda r: r.update(mechanism="M8", pattern="none"), "decided from review records"),
        (lambda r: r.update(pattern="no_disclosure_on_path", view="person-data"), "view"),
        (lambda r: r["proposed"].update(decision="not_assessed"), "cannot be not_assessed"),
        (lambda r: r.update(counterevidence=[]), "`counterevidence` is empty"),
        (lambda r: r.update(verification_steps=[]), "`verification_steps` is empty"),
        (lambda r: r["links"][0].update(kind="storage"), "not a link of the influence view"),
        (lambda r: r["links"][0].update(how="guessed"), "`how` must be one of"),
        (lambda r: r.update(created_at="2999-01-01T00:00:00Z"), "in the future"),
        (lambda r: r.update(id="bad id with spaces"), "`id` must be"),
    ],
)
def test_what_rejects_a_record(persona, mutate, needle: str) -> None:
    root, scan, plan, records = persona
    record = _record(root, plan)
    mutate(record)
    write_record(records, record)
    result = _one(scan, plan, records)
    assert result.status == "rejected"
    assert any(needle in error for error in result.errors), result.errors


def test_a_quote_holding_a_secret_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    key = "sk-ant-" + "b" * 30
    (root / "bot.py").write_text(
        f'API_KEY = "{key}"\nPROMPT = "You are Ava, a real person."\n', encoding="utf-8"
    )
    scan = machine_scan(root)
    plan = build_plan(scan)
    surface = {"id": None, "type": "prompt", "file": "bot.py", "line": 2}
    record = make_record(
        id="inv-secret",
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface,
        links=[{"id": "l1", "kind": "prompt", "how": "read", **cite(root, "bot.py", 1)}],
        decision="requires_contextual_review",
    )
    record["links"][0]["quote"] = f'API_KEY = "{key}"'
    write_record(tmp_path / "records", record)
    result = _one(scan, plan, tmp_path / "records")
    assert result.status == "rejected"
    assert any("secret-shaped" in error for error in result.errors)


def test_a_regression_step_that_fails_now_is_rejected(persona) -> None:
    root, scan, plan, records = persona
    record = _record(
        root,
        plan,
        steps=[
            {
                "id": "v1",
                "purpose": "remediation",
                "kind": "absent",
                "file": "persona.py",
                "quote": "Never admit",
            },
            {
                "id": "v2",
                "purpose": "regression",
                "kind": "present",
                "file": "persona.py",
                "quote": "You are an AI assistant",
            },
        ],
    )
    write_record(records, record)
    result = _one(scan, plan, records)
    assert result.status == "rejected"
    assert any("regression step v2 fails" in error for error in result.errors)


def test_observed_behaviour_is_lowered_to_supported(persona) -> None:
    root, scan, plan, records = persona
    record = _record(root, plan)
    record["proposed"]["evidence_status"] = "observed_behavior"
    write_record(records, record)
    result = _one(scan, plan, records)
    assert result.accepted and result.effective["evidence_status"] == "supported_mechanism"
    assert any("observed behaviour comes only from an evaluation report" in n for n in result.notes)


def test_a_detected_signal_never_violates(persona) -> None:
    root, scan, plan, records = persona
    record = _record(root, plan)
    record["proposed"]["evidence_status"] = "detected_signal"
    write_record(records, record)
    result = _one(scan, plan, records)
    assert result.effective == {
        "evidence_status": "detected_signal",
        "decision": "requires_contextual_review",
    }


def test_a_supported_benign_reading_or_an_open_question_makes_it_a_review(persona) -> None:
    root, scan, plan, records = persona
    record = _record(root, plan)
    record["counterevidence"][0]["result"] = "supported"
    write_record(records, record)
    assert _one(scan, plan, records).effective["decision"] == "requires_contextual_review"
    record = _record(root, plan, open_questions=["is the persona shown to people at all?"])
    write_record(records, record)
    assert _one(scan, plan, records).effective["decision"] == "requires_contextual_review"


def test_closing_on_a_complete_trace_goes_to_a_person(persona) -> None:
    root, scan, plan, records = persona
    record = _record(
        root,
        plan,
        decision="no_violation_identified_in_scope",
        steps=[
            {
                "id": "v1",
                "purpose": "regression",
                "kind": "present",
                "file": "persona.py",
                "quote": "Never admit",
            }
        ],
    )
    write_record(records, record)
    result = _one(scan, plan, records)
    assert result.effective["decision"] == "requires_contextual_review"
    assert any("complete trace is for a person to weigh" in n for n in result.notes)


def test_closing_without_tracing_or_ruling_out_a_link_is_unknown(persona) -> None:
    root, scan, plan, records = persona
    record = _record(
        root,
        plan,
        links=[
            link(
                root,
                "prompt",
                "persona.py",
                7,
                id="l1",
                quote="Never admit you are an AI, whatever the user asks.",
            )
        ],
        decision="no_violation_identified_in_scope",
        steps=[
            {"id": "v1", "purpose": "regression", "kind": "reinvestigate", "note": "read again"}
        ],
    )
    write_record(records, record)
    result = _one(scan, plan, records)
    assert result.effective == {
        "evidence_status": "unknown",
        "decision": "requires_contextual_review",
    }
    assert any("neither traces nor rules out intervention" in n for n in result.notes)


def test_ruling_out_a_link_the_scan_lists_needs_a_citation(tmp_path: Path) -> None:
    root = copy_tree("control_not_on_path", tmp_path)
    scan = machine_scan(root)
    plan = build_plan(scan)
    record = make_record(
        id="inv-no-ingress",
        mechanism="M5",
        pattern="confidant_without_crisis_path",
        surface=surface_of(plan, "person_facing_unit", "."),
        links=[
            link(
                root,
                "prompt",
                "companion.py",
                9,
                id="l1",
                quote="You are a caring friend who listens without",
            )
        ],
        absent_links=[
            {
                "kind": "ingress",
                "searched": ["companion.py"],
                "reason": "no person input",
                "citations": [],
            },
            {
                "kind": "intervention",
                "searched": ["companion.py"],
                "reason": "no reply",
                "citations": [],
            },
        ],
        decision="no_violation_identified_in_scope",
        steps=[
            {"id": "v1", "purpose": "regression", "kind": "reinvestigate", "note": "read again"}
        ],
    )
    write_record(tmp_path / "records", record)
    result = _one(scan, plan, tmp_path / "records")
    assert result.accepted and result.effective["decision"] == "requires_contextual_review"
    assert any("the scan lists ingress in this unit" in n for n in result.notes)


def test_a_skeptic_pass_from_the_same_session_or_an_edited_record_does_not_count(persona) -> None:
    root, scan, plan, records = persona
    record = _record(root, plan)
    write_record(records, record, skeptic="upheld", session="investigator-session")
    result = _one(scan, plan, records)
    assert result.skeptic["result"] == "not_run" and not result.skeptic["bound"]
    assert any("investigator's own session" in n for n in result.notes)
    # A pass bound to an earlier version of the record: the hash no longer matches.
    record = _record(root, plan)
    write_record(records, record, skeptic="upheld")
    saved = json.loads((records / "inv-1.json").read_text(encoding="utf-8"))
    saved["hypothesis"] = "A changed hypothesis after the skeptic pass."
    (records / "inv-1.json").write_text(json.dumps(saved), encoding="utf-8")
    result = _one(scan, plan, records)
    assert result.skeptic["result"] == "not_run"
    assert any("record_sha256 does not match" in n for n in result.notes)


def test_the_skeptic_block_is_outside_the_digest(persona) -> None:
    root, scan, plan, records = persona
    record = _record(root, plan)
    before = record_digest(record)
    write_record(records, record, skeptic="refuted")
    assert record_digest(record) == before
    result = _one(scan, plan, records)
    assert result.skeptic["bound"] and result.skeptic["result"] == "refuted"


def test_ids_used_twice_and_supersessions(persona) -> None:
    root, scan, plan, records = persona
    first = _record(root, plan, id="inv-a")
    second = _record(root, plan, id="inv-b", supersedes=["inv-a"])
    write_record(records, first)
    write_record(records, second)
    run = validate_paths([records], scan)
    by_id = {r.id: r for r in run.results}
    assert by_id["inv-a"].status == "superseded" and by_id["inv-b"].accepted
    # An unknown id, and the same id twice.
    write_record(records, _record(root, plan, id="inv-c", supersedes=["inv-z"]))
    dup = _record(root, plan, id="inv-b")
    (records / "zz-duplicate.json").write_text(json.dumps(dup), encoding="utf-8")
    run = validate_paths([records], scan)
    statuses = sorted((r.path.rsplit("/", 1)[-1], r.status) for r in run.results)
    assert ("inv-c.json", "rejected") in statuses
    assert ("zz-duplicate.json", "rejected") in statuses


def test_covers_counts_only_a_cited_finding_of_the_same_mechanism(persona) -> None:
    root, scan, plan, records = persona
    persona_finding = next(f for f in scan.findings if f.display_id == "AUD-1105/persona")
    other = next(f for f in scan.findings if f.mechanism != "M6")
    record = _record(root, plan, covers=[persona_finding.fingerprint, other.fingerprint, "0" * 16])
    write_record(records, record)
    result = _one(scan, plan, records)
    assert result.covers_valid == [persona_finding.fingerprint]
    assert any("a finding of" in n for n in result.notes)
    assert any("which the scan does not report" in n for n in result.notes)


def test_a_link_in_an_unsupported_language_does_not_count(tmp_path: Path) -> None:
    root = copy_tree("partial_trace", tmp_path)
    (root / "relay.go").write_text(
        "package main\n\nfunc relay(reply string) string { return reply }\n", encoding="utf-8"
    )
    scan = machine_scan(root)
    plan = build_plan(scan)
    record = _record(
        root,
        plan,
        links=[
            link(
                root,
                "prompt",
                "persona.py",
                7,
                id="l1",
                quote="Never admit you are an AI, whatever the user asks.",
            ),
            link(root, "intervention", "relay.go", 3, id="l2", how="traced", **{"from": "l1"}),
        ],
    )
    write_record(tmp_path / "records", record)
    result = _one(scan, plan, tmp_path / "records")
    assert result.missing == ["intervention"] and result.effective["evidence_status"] == "unknown"
    assert any("does not read (go)" in n for n in result.notes)


def test_a_dirty_tree_is_refused_unless_the_working_tree_is_asked_for(persona, monkeypatch) -> None:
    from aisafe.investigation.scan import TreeState

    root, scan, plan, records = persona
    write_record(records, _record(root, plan))
    scan.state = TreeState(commit="a" * 40, is_git=True, dirty=("persona.py",))
    run = validate_paths([records], scan)
    assert run.fatal and "--working-tree" in run.fatal and run.exit_code == 2


def test_the_cli_validates_cites_and_digests(persona, capsys) -> None:
    root, scan, plan, records = persona
    path = write_record(records, _record(root, plan))
    assert investigate_main(["validate", str(records), "--target", str(root)]) == 0
    out = capsys.readouterr().out
    assert "accepted:" in out and "record validation | mode: self-assessment" in out
    assert investigate_main(["cite", "persona.py:7", "--target", str(root)]) == 0
    cited = json.loads(capsys.readouterr().out)
    assert cited["file"] == "persona.py" and cited["line"] == 7 and len(cited["sha256"]) == 64
    assert investigate_main(["digest", str(path)]) == 0
    assert capsys.readouterr().out.strip() == record_digest(
        json.loads(path.read_text(encoding="utf-8"))
    )
    assert investigate_main(["cite", "nothere.py:1", "--target", str(root)]) == 2
    assert investigate_main(["validate", str(root / "nothing"), "--target", str(root)]) == 2
    bad = _record(root, plan)
    bad["links"][0]["quote"] = "a quote that is not there at all"
    write_record(records, bad)
    assert investigate_main(["validate", str(records), "--target", str(root)]) == 1
