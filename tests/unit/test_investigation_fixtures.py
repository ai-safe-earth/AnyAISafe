"""tests/unit/test_investigation_fixtures.py
-----------------------------------------
The nine investigation fixtures under `tests/fixtures/investigate/`, each with the record an
investigator would write and what validation and the assessment make of it:

- a harmful flow spanning three files (and the same chain without its `via` hops);
- a benign lookalike closed by ruling out the objective;
- effective anonymisation before transmission, closed by the control on the path;
- the same anonymisation bypassed by a debug branch that ships the raw message;
- a crisis check imported and never called, which the scan takes for a control;
- a prompt fetched at run time, which leaves the mechanism inconclusive;
- an attachment instruction the lexical rules miss and the investigation establishes;
- a renamed outreach job (a scheduler and a send under other names) the rules miss;
- a partial trace, never presented as complete.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from investigation_helpers import copy_tree, link, make_record, surface_of, write_record
from test_evidence_model import make_finding

from aisafe.assessment.assess import run_assessment
from aisafe.assessment.render import render_markdown
from aisafe.investigation.plan import build_plan
from aisafe.investigation.scan import machine_scan
from aisafe.investigation.validate import validate_paths
from aisafe.reporting.report import _chain_text


def _setup(name: str, tmp_path: Path):
    root = copy_tree(name, tmp_path)
    scan = machine_scan(root)
    plan = build_plan(scan)
    return root, scan, plan


def _validate(scan, plan, records_dir: Path):
    run = validate_paths([records_dir], scan, plan_surfaces={s["id"]: s for s in plan["surfaces"]})
    assert run.fatal is None, run.fatal
    return {r.id: r for r in run.results}


def _outcome(root: Path, records_dir: Path, mechanism: str) -> dict:
    run = run_assessment(root, [records_dir])
    assert run.document is not None, run.fatal
    return next(m for m in run.document["outcome"]["mechanisms"] if m["id"] == mechanism)


# ---------------------------------------------------------------------------
# 1. A harmful flow across files
# ---------------------------------------------------------------------------


def _multi_file_record(root: Path, plan: dict, *, with_via: bool) -> dict:
    prompt_via = [
        {
            **link(root, "prompt", "prompting.py", 9, id="h1"),
            "step": "build_prompt reads the profile",
        }
    ]
    call_via = [
        {
            **link(root, "prompt", "chat.py", 13, id="h2"),
            "step": "the handler passes the built prompt as system=",
        }
    ]
    for hop in prompt_via + call_via:
        for key in ("id", "kind", "how"):
            hop.pop(key)
    return make_record(
        id="inv-m1-binding",
        mechanism="M1",
        pattern="binding",
        surface=surface_of(plan, "prompt", "prompting.py", 10),
        links=[
            link(root, "person_data", "profiles.py", 12, id="l1"),
            link(
                root,
                "prompt",
                "prompting.py",
                10,
                id="l2",
                how="traced",
                **{"from": "l1"},
                via=prompt_via if with_via else [],
            ),
            link(
                root,
                "intervention",
                "chat.py",
                14,
                id="l3",
                how="traced",
                **{"from": "l2"},
                via=call_via if with_via else [],
            ),
        ],
        decision="violates_policy",
        steps=[
            {
                "id": "v1",
                "purpose": "remediation",
                "kind": "absent",
                "file": "prompting.py",
                "quote": "Recent moods:",
            }
        ],
    )


def test_a_flow_across_three_files_is_established_with_its_via_hops(tmp_path: Path) -> None:
    root, scan, plan = _setup("multi_file_flow", tmp_path)
    records = tmp_path / "records"
    write_record(records, _multi_file_record(root, plan, with_via=True), skeptic="upheld")
    result = _validate(scan, plan, records)["inv-m1-binding"]
    assert result.accepted, result.errors
    assert result.complete and result.connected and result.claim == "establishes"
    assert result.effective == {
        "evidence_status": "supported_mechanism",
        "decision": "violates_policy",
    }
    assert _outcome(root, records, "M1")["outcome"] == "violations_identified"


def test_the_same_links_without_via_hops_do_not_form_a_chain(tmp_path: Path) -> None:
    root, scan, plan = _setup("multi_file_flow", tmp_path)
    records = tmp_path / "records"
    write_record(records, _multi_file_record(root, plan, with_via=False))
    result = _validate(scan, plan, records)["inv-m1-binding"]
    assert result.accepted and not result.connected and not result.complete
    assert result.effective == {
        "evidence_status": "unknown",
        "decision": "requires_contextual_review",
    }
    assert any("crosses files with no `via` hop" in note for note in result.notes)


# ---------------------------------------------------------------------------
# 2. A benign lookalike
# ---------------------------------------------------------------------------


def test_a_requested_tone_analysis_closes_when_the_objective_is_ruled_out(tmp_path: Path) -> None:
    root, scan, plan = _setup("benign_lookalike", tmp_path)
    assert not [f for f in scan.findings if f.id == "AUD-1102"]  # the scan is silent here
    records = tmp_path / "records"
    record = make_record(
        id="inv-m2-tone",
        mechanism="M2",
        pattern="inference_for_influence",
        surface=surface_of(plan, "prompt", "assistant.py", 7),
        links=[
            link(
                root,
                "inference",
                "assistant.py",
                8,
                id="l1",
                quote="analyze its emotional tone and suggest a kinder wording.",
            ),
            link(root, "intervention", "assistant.py", 18, id="l2", how="traced", **{"from": "l1"}),
        ],
        absent_links=[
            {
                "kind": "objective",
                "searched": ["assistant.py", "the reply path"],
                "reason": "the tone goes back to the person as the rewrite they asked for; nothing stores it or uses it to shape a pitch",
                "citations": [],
            }
        ],
        decision="no_violation_identified_in_scope",
        steps=[
            {
                "id": "v1",
                "purpose": "regression",
                "kind": "present",
                "file": "assistant.py",
                "quote": "Only answer the question they asked.",
            }
        ],
    )
    write_record(records, record, skeptic="upheld")
    result = _validate(scan, plan, records)["inv-m2-tone"]
    assert result.accepted, result.errors
    assert result.claim == "closes" and result.ruled_out == ["objective"]
    mech = _outcome(root, records, "M2")
    # Closed on the one surface investigated, and the outcome says how far that goes: the
    # assembly that carries the same hypothesis is normal priority, so it is no gap, and it
    # is counted in "1 of 2".
    assert mech["closing"] == ["inv-m2-tone"] and mech["gaps"] == []
    assert mech["outcome"] == "no_violation_identified_within_assessed_scope"
    assert mech["closed_on"] == {"closed": 1, "of": 2}


# ---------------------------------------------------------------------------
# 3 and 4. Anonymisation before transmission, and a branch that bypasses it
# ---------------------------------------------------------------------------


def test_anonymisation_on_the_path_closes_the_transmission(tmp_path: Path) -> None:
    root, scan, plan = _setup("sanitised_transmission", tmp_path)
    records = tmp_path / "records"
    record = make_record(
        id="inv-m1-telemetry",
        mechanism="M1",
        pattern="transmission",
        view="person-data",
        surface=surface_of(plan, "external_destination", "telemetry.py"),
        links=[
            link(root, "collection", "chat.py", 15, id="l1"),
            link(
                root,
                "transformation",
                "telemetry.py",
                10,
                id="l2",
                how="traced",
                **{"from": "l1"},
                via=[
                    {
                        k: v
                        for k, v in link(root, "collection", "chat.py", 16, id="x").items()
                        if k not in ("id", "kind", "how")
                    }
                    | {"step": "the handler calls record_turn"}
                ],
            ),
            link(root, "transmission", "telemetry.py", 15, id="l3", how="traced", **{"from": "l2"}),
        ],
        controls=[
            {
                "name": "anonymisation",
                "location": {
                    k: v
                    for k, v in link(root, "transformation", "telemetry.py", 14, id="c").items()
                    if k not in ("id", "kind", "how")
                },
                "on_path": "yes",
                # The transmission link it sits on, in the same file.
                "link": "l3",
                "reason": "record_turn sends only the anonymised event and has no other branch",
            }
        ],
        decision="no_violation_identified_in_scope",
        steps=[
            {
                "id": "v1",
                "purpose": "regression",
                "kind": "present",
                "file": "telemetry.py",
                "quote": "event = anonymise(user_id, text)",
            }
        ],
    )
    write_record(records, record, skeptic="upheld")
    result = _validate(scan, plan, records)["inv-m1-telemetry"]
    assert result.accepted, result.errors
    assert result.control_on_path and result.claim == "closes"
    # The same control with no link of the chain to sit on closes nothing.
    del record["controls"][0]["link"]
    write_record(records, record, skeptic="upheld")
    bare = _validate(scan, plan, records)["inv-m1-telemetry"]
    assert not bare.control_on_path and bare.claim == "review"


def test_a_debug_branch_that_ships_the_raw_message_establishes_the_transmission(
    tmp_path: Path,
) -> None:
    root, scan, plan = _setup("logging_bypass", tmp_path)
    records = tmp_path / "records"
    via = [
        {
            k: v
            for k, v in link(root, "collection", "chat.py", 16, id="x").items()
            if k not in ("id", "kind", "how")
        }
        | {"step": "the handler calls record_turn"}
    ]
    bypass = make_record(
        id="inv-m1-trace",
        mechanism="M1",
        pattern="transmission",
        view="person-data",
        surface=surface_of(plan, "external_destination", "telemetry.py"),
        links=[
            link(root, "collection", "chat.py", 15, id="l1"),
            link(
                root,
                "transmission",
                "telemetry.py",
                20,
                id="l2",
                how="traced",
                **{"from": "l1"},
                via=via,
            ),
        ],
        controls=[
            {
                "name": "anonymisation",
                "location": None,
                "on_path": "no",
                "searched": ["telemetry.py", "chat.py"],
                "reason": "the debug branch posts the user id and the raw message before anonymise runs",
            }
        ],
        decision="violates_policy",
        steps=[
            {
                "id": "v1",
                "purpose": "remediation",
                "kind": "absent",
                "file": "telemetry.py",
                "quote": '"message": text',
            }
        ],
    )
    write_record(records, bypass, skeptic="upheld")
    result = _validate(scan, plan, records)["inv-m1-trace"]
    assert result.accepted, result.errors
    assert result.claim == "establishes" and result.complete
    assert _outcome(root, records, "M1")["outcome"] == "violations_identified"


def test_a_closing_claim_that_misses_the_bypass_is_refuted_and_stays_inconclusive(
    tmp_path: Path,
) -> None:
    root, scan, plan = _setup("logging_bypass", tmp_path)
    records = tmp_path / "records"
    via = [
        {
            k: v
            for k, v in link(root, "collection", "chat.py", 16, id="x").items()
            if k not in ("id", "kind", "how")
        }
        | {"step": "the handler calls record_turn"}
    ]
    closing = make_record(
        id="inv-m1-closing",
        mechanism="M1",
        pattern="transmission",
        view="person-data",
        surface=surface_of(plan, "external_destination", "telemetry.py"),
        links=[
            link(root, "collection", "chat.py", 15, id="l1"),
            link(
                root,
                "transmission",
                "telemetry.py",
                22,
                id="l2",
                how="traced",
                **{"from": "l1"},
                via=via,
            ),
        ],
        controls=[
            {
                "name": "anonymisation",
                "location": {
                    k: v
                    for k, v in link(root, "transformation", "telemetry.py", 21, id="c").items()
                    if k not in ("id", "kind", "how")
                },
                "on_path": "yes",
                "link": "l2",
                "reason": "the event is anonymised before analytics.track",
            }
        ],
        decision="no_violation_identified_in_scope",
        steps=[
            {
                "id": "v1",
                "purpose": "regression",
                "kind": "present",
                "file": "telemetry.py",
                "quote": "event = anonymise(user_id, text)",
            }
        ],
    )
    write_record(records, closing, skeptic="refuted")
    mech = _outcome(root, records, "M1")
    assert mech["outcome"] == "inconclusive"
    assert any(gap["kind"] == "skeptic_refuted" for gap in mech["gaps"])


# ---------------------------------------------------------------------------
# 5. A control imported and never called
# ---------------------------------------------------------------------------


def _crisis_links(root: Path) -> list[dict]:
    return [
        link(root, "ingress", "companion.py", 15, id="l1"),
        link(
            root,
            "prompt",
            "companion.py",
            9,
            id="l2",
            how="traced",
            quote="You are a caring friend who listens without",
            **{"from": "l1"},
        ),
        link(root, "intervention", "companion.py", 20, id="l3", how="traced", **{"from": "l2"}),
    ]


def test_an_imported_crisis_check_is_not_a_crisis_path(tmp_path: Path) -> None:
    root, scan, plan = _setup("control_not_on_path", tmp_path)
    # The scan takes the crisis words in safety.py for a control and reports nothing.
    assert not [f for f in scan.findings if f.id == "AUD-1108"]
    records = tmp_path / "records"
    record = make_record(
        id="inv-m5-crisis",
        mechanism="M5",
        pattern="confidant_without_crisis_path",
        surface=surface_of(plan, "person_facing_unit", "."),
        links=_crisis_links(root),
        controls=[
            {
                "name": "crisis_path",
                "location": None,
                "on_path": "no",
                "searched": ["companion.py", "safety.py", "every caller of crisis_check"],
                "reason": "crisis_check is imported and never called; the reply returns as the model wrote it",
            }
        ],
        decision="violates_policy",
        steps=[
            {
                "id": "v1",
                "purpose": "remediation",
                "kind": "evaluation",
                "family": "crisis_disclosure",
            }
        ],
    )
    write_record(records, record, skeptic="upheld")
    result = _validate(scan, plan, records)["inv-m5-crisis"]
    assert result.accepted, result.errors
    assert result.claim == "establishes"
    assert _outcome(root, records, "M5")["outcome"] == "violations_identified"


def test_a_remediation_step_the_tree_already_passes_is_rejected(tmp_path: Path) -> None:
    root, scan, plan = _setup("control_not_on_path", tmp_path)
    records = tmp_path / "records"
    record = make_record(
        id="inv-m5-step",
        mechanism="M5",
        pattern="confidant_without_crisis_path",
        surface=surface_of(plan, "person_facing_unit", "."),
        links=_crisis_links(root),
        controls=[
            {"name": "crisis_path", "location": None, "on_path": "no", "reason": "never called"}
        ],
        decision="violates_policy",
        # The scan already reports no AUD-1108 here, so this step tests nothing.
        steps=[{"id": "v1", "purpose": "remediation", "kind": "no_finding", "rule": "AUD-1108"}],
    )
    write_record(records, record)
    result = _validate(scan, plan, records)["inv-m5-step"]
    assert result.status == "rejected"
    assert any("already passes" in error for error in result.errors)


# ---------------------------------------------------------------------------
# 6. A prompt fetched at run time
# ---------------------------------------------------------------------------


def test_a_prompt_fetched_at_run_time_leaves_the_mechanism_inconclusive(tmp_path: Path) -> None:
    root, scan, plan = _setup("runtime_prompt", tmp_path)
    records = tmp_path / "records"
    record = make_record(
        id="inv-m6-remote",
        mechanism="M6",
        pattern="concealment_instruction",
        surface=surface_of(plan, "remote_prompt", "bot.py", 13),
        links=[
            link(root, "prompt", "bot.py", 13, id="l1", how="read"),
            link(root, "intervention", "bot.py", 15, id="l2", how="traced", **{"from": "l1"}),
        ],
        decision="no_violation_identified_in_scope",
        absent_links=[],
        steps=[
            {
                "id": "v1",
                "purpose": "regression",
                "kind": "reinvestigate",
                "note": "read the served prompt",
            }
        ],
    )
    write_record(records, record, skeptic="upheld")
    result = _validate(scan, plan, records)["inv-m6-remote"]
    assert result.accepted, result.errors
    # The scan lists the line as a prompt fetched at run time: the link is runtime-only.
    assert result.links[0]["established_by"] == "runtime-only" and result.runtime == ["prompt"]
    assert result.effective["evidence_status"] == "unknown" and result.claim == "review"
    mech = _outcome(root, records, "M6")
    assert mech["outcome"] == "inconclusive"
    assert {gap["kind"] for gap in mech["gaps"]} >= {"runtime_only", "record_at_review"}


# ---------------------------------------------------------------------------
# 7. A semantic finding the lexical rules miss
# ---------------------------------------------------------------------------


def test_an_attachment_instruction_without_trigger_words_is_established(tmp_path: Path) -> None:
    root, scan, plan = _setup("semantic_miss", tmp_path)
    assert not [f for f in scan.findings if f.mechanism == "M5" and f.id == "AUD-1109"]
    records = tmp_path / "records"
    load = {
        k: v
        for k, v in link(root, "prompt", "app.py", 8, id="x").items()
        if k not in ("id", "kind", "how")
    }
    record = make_record(
        id="inv-m5-attach",
        mechanism="M5",
        pattern="attachment_instruction",
        surface=surface_of(plan, "prompt", "prompts/companion.md", 1),
        links=[
            {
                "id": "l1",
                "kind": "objective",
                "how": "read",
                **{
                    k: v
                    for k, v in link(root, "objective", "prompts/companion.md", 5, id="y").items()
                    if k in ("file", "line", "sha256")
                },
                "end_line": 6,
                "quote": "tell them the evening will feel empty without your\ntalks and that you will be waiting here",
            },
            link(
                root,
                "prompt",
                "app.py",
                8,
                id="l2",
                how="traced",
                **{"from": "l1"},
                via=[load | {"step": "the handler loads the prompt file as its system prompt"}],
            ),
            link(root, "intervention", "app.py", 15, id="l3", how="traced", **{"from": "l2"}),
        ],
        decision="violates_policy",
        steps=[
            {
                "id": "v1",
                "purpose": "remediation",
                "kind": "absent",
                "file": "prompts/companion.md",
                "quote": "will feel empty without your",
            }
        ],
    )
    write_record(records, record, skeptic="upheld")
    result = _validate(scan, plan, records)["inv-m5-attach"]
    assert result.accepted, result.errors
    assert result.claim == "establishes"
    assert _outcome(root, records, "M5")["outcome"] == "violations_identified"


# ---------------------------------------------------------------------------
# 8. A renamed mechanism
# ---------------------------------------------------------------------------


def test_a_renamed_outreach_job_is_found_by_investigation(tmp_path: Path) -> None:
    root, scan, plan = _setup("renamed_mechanism", tmp_path)
    # A schedule is detected, the send under another name is not: no outreach finding.
    assert not [f for f in scan.findings if f.display_id.startswith("AUD-1104/outreach")]
    records = tmp_path / "records"
    record = make_record(
        id="inv-m4-pulse",
        mechanism="M4",
        pattern="outreach",
        surface=surface_of(plan, "scheduler_sender", "jobs.py", 19),
        links=[link(root, "intervention", "jobs.py", 16, id="l1", how="traced")],
        controls=[
            {
                "name": "person_set_schedule",
                "location": None,
                "on_path": "no",
                "searched": ["jobs.py", "push.py", "app.py"],
                "reason": "the job runs every six hours for everyone away two days; nothing reads a time the person chose",
            }
        ],
        decision="violates_policy",
        steps=[
            {
                "id": "v1",
                "purpose": "remediation",
                "kind": "absent",
                "file": "jobs.py",
                "quote": "Juno has been thinking about you",
            }
        ],
    )
    write_record(records, record, skeptic="upheld")
    result = _validate(scan, plan, records)["inv-m4-pulse"]
    assert result.accepted, result.errors
    assert result.claim == "establishes"
    assert _outcome(root, records, "M4")["outcome"] == "violations_identified"


# ---------------------------------------------------------------------------
# 9. A partial trace
# ---------------------------------------------------------------------------


def test_a_partial_trace_is_never_presented_as_complete(tmp_path: Path) -> None:
    root, scan, plan = _setup("partial_trace", tmp_path)
    records = tmp_path / "records"
    record = make_record(
        id="inv-m6-partial",
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
            )
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
    write_record(records, record, skeptic="upheld")
    result = _validate(scan, plan, records)["inv-m6-partial"]
    assert result.accepted, result.errors
    assert not result.complete and result.missing == ["intervention"]
    assert result.effective == {
        "evidence_status": "unknown",
        "decision": "requires_contextual_review",
    }
    # As a chain on a finding, the record's links read as a partial trace.
    finding = make_finding("AUD-1105", sub="persona", flow=result.flow())
    assert finding.trace_complete is False
    assert _chain_text(finding).endswith(
        "[partial trace for M6/concealment_instruction: intervention not established]"
    )
    run = run_assessment(root, [records])
    text = render_markdown(run.document)
    line = next(row for row in text.splitlines() if "inv-m6-partial" in row and "trace" in row)
    assert "trace partial" in line and "trace complete" not in line


@pytest.mark.parametrize(
    "name",
    [
        "multi_file_flow",
        "benign_lookalike",
        "sanitised_transmission",
        "logging_bypass",
        "control_not_on_path",
        "runtime_prompt",
        "semantic_miss",
        "renamed_mechanism",
        "partial_trace",
    ],
)
def test_every_fixture_plans_deterministically(name: str, tmp_path: Path) -> None:
    first = build_plan(machine_scan(copy_tree(name, tmp_path / "a")))
    second = build_plan(machine_scan(copy_tree(name, tmp_path / "b")))
    assert first["plan_sha256"] == second["plan_sha256"]
    assert [s["id"] for s in first["surfaces"]] == [s["id"] for s in second["surfaces"]]
