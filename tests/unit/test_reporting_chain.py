"""tests/unit/test_reporting_chain.py
----------------------------------
The chain line of a finding: a call and its reply are two `intervention` sites established
the same way, and the line names the step once; links established differently, or of
different kinds, stay separate; the JSON keeps every site. The status measures the chain
against the finding's policy pattern: complete, partial (naming each required link it lacks)
or lexical co-occurrence only, and a partial trace is never shown complete.
"""

from __future__ import annotations

import json

from test_evidence_model import make_finding

from aisafe.evidence.model import Flow, FlowLink
from aisafe.reporting.report import _chain_text


def _flow(*links: tuple[str, int, str]) -> Flow:
    return Flow(
        links=[FlowLink(kind, "app.py", line, f"line {line}", by) for kind, line, by in links]
    )


def test_two_intervention_sites_render_as_one_step() -> None:
    finding = make_finding(
        flow=_flow(
            ("objective", 3, "declared"),
            ("prompt", 12, "ast"),
            ("intervention", 20, "ast"),
            ("intervention", 24, "ast"),
        )
    )
    assert _chain_text(finding) == (
        "chain: objective (declared) -> prompt (ast) -> intervention (ast) "
        "[trace complete for M4/objective]"
    )
    # Every site stays in the serialised flow.
    links = json.loads(json.dumps(finding.to_dict()))["flow"]["links"]
    assert [link["line"] for link in links] == [3, 12, 20, 24]


def test_links_established_differently_stay_separate() -> None:
    finding = make_finding(
        flow=_flow(
            ("prompt", 12, "ast"), ("intervention", 20, "ast"), ("intervention", 30, "co-located")
        )
    )
    assert _chain_text(finding) == (
        "chain: prompt (ast) -> intervention (ast) -> intervention (co-located) "
        "[partial trace for M4/objective: objective not established]"
    )


def test_a_partial_trace_is_never_shown_complete() -> None:
    # Every present link is supported, but the pattern needs an objective link.
    partial = make_finding(flow=_flow(("prompt", 12, "ast"), ("intervention", 20, "ast")))
    assert partial.links_supported is True and partial.trace_complete is False
    text = _chain_text(partial)
    assert text.endswith("[partial trace for M4/objective: objective not established]")
    assert "complete" not in text
    # A required link that is present but only co-located is named with its status.
    weak = make_finding(flow=_flow(("objective", 3, "co-located"), ("intervention", 20, "ast")))
    assert _chain_text(weak).endswith("[partial trace for M4/objective: objective is co-located]")


def test_a_runtime_only_link_leaves_the_trace_partial() -> None:
    finding = make_finding(
        flow=_flow(("objective", 3, "declared"), ("intervention", 20, "runtime-only"))
    )
    assert _chain_text(finding) == (
        "chain: objective (declared) -> intervention (runtime-only) "
        "[partial trace for M4/objective: intervention is runtime-only]"
    )


def test_a_chain_of_co_located_links_has_no_trace() -> None:
    finding = make_finding(
        flow=_flow(("prompt", 12, "co-located"), ("intervention", 20, "co-located"))
    )
    assert _chain_text(finding) == (
        "chain: prompt (co-located) -> intervention (co-located) [lexical co-occurrence only; "
        "no trace for M4/objective: objective not established, intervention is co-located]"
    )


def test_a_person_data_trace_names_its_own_pattern() -> None:
    flow = Flow(
        links=[
            FlowLink("collection", "app.py", 3, "text = req.json", "investigated", record="r"),
            FlowLink("storage", "store.py", 8, "db.save(mood)", "investigated", record="r"),
        ],
        view="person-data",
    )
    finding = make_finding("AUD-1101", sub="store", flow=flow)
    assert _chain_text(finding) == (
        "chain: collection (investigated) -> storage (investigated) [trace complete for M1/storage]"
    )


def test_a_rule_with_no_pattern_says_no_trace_is_defined() -> None:
    finding = make_finding(
        "AUD-1107", sub="missing", flow=_flow(("prompt", 12, "ast"), ("intervention", 20, "ast"))
    )
    assert _chain_text(finding) == (
        "chain: prompt (ast) -> intervention (ast) "
        "[links supported; no trace is defined for this rule]"
    )


def test_no_flow_still_names_what_the_trace_needs() -> None:
    none = "chain: none drawn [no trace for M4/objective: objective not established, "
    none += "intervention not established]"
    assert _chain_text(make_finding()) == none
    assert _chain_text(make_finding(flow=Flow())) == none
    # A rule with no pattern and no chain prints no chain line.
    assert _chain_text(make_finding("AUD-1107", sub="missing")) is None
