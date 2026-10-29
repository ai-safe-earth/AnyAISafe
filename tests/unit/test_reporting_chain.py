"""tests/unit/test_reporting_chain.py
----------------------------------
The chain line of a finding: a call and its reply are two `intervention` sites established
the same way, and the line names the step once; links established differently, or of
different kinds, stay separate; the JSON keeps every site.
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
        flow=_flow(("prompt", 12, "ast"), ("intervention", 20, "ast"), ("intervention", 24, "ast"))
    )
    assert _chain_text(finding) == "chain: prompt (ast) -> intervention (ast) [established]"
    # Every site stays in the serialised flow.
    links = json.loads(json.dumps(finding.to_dict()))["flow"]["links"]
    assert [link["line"] for link in links] == [12, 20, 24]


def test_links_established_differently_stay_separate() -> None:
    finding = make_finding(
        flow=_flow(
            ("prompt", 12, "ast"), ("intervention", 20, "ast"), ("intervention", 30, "co-located")
        )
    )
    assert _chain_text(finding) == (
        "chain: prompt (ast) -> intervention (ast) -> intervention (co-located) "
        "[not established: a co-located link is lexical co-occurrence]"
    )


def test_no_flow_means_no_chain_line() -> None:
    assert _chain_text(make_finding()) is None
    assert _chain_text(make_finding(flow=Flow())) is None
