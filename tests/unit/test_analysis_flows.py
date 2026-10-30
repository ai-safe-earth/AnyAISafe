"""tests/unit/test_analysis_flows.py
---
Chain reconstruction: objective -> person data -> inference -> prompt -> intervention ->
feedback, with how each link was established. `ast` and `declared` links are supported; a
single `co-located` link makes `links_supported` false, and a chain with nothing supported
renders as "lexical co-occurrence only". Co-location is never presented as a flow. Whether a
finding's trace is complete is measured against its policy pattern (tests in
test_evidence_model.py and test_reporting_chain.py).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from aisafe.analysis import flows
from aisafe.analysis.flows import (
    FEEDBACK_KINDS,
    INFERENCE_KINDS,
    METRIC_RE,
    OBJECTIVE_KINDS,
    PROFILE_KINDS,
    build_flows,
    flow_summary,
)
from aisafe.evidence.model import FLOW_LINK_KINDS, AuditContext, Flow, FlowLink, Inventory


def project(tmp_path: Path, files: dict[str, str], name: str = "proj") -> Path:
    root = tmp_path / name
    root.mkdir()
    (root / "pyproject.toml").write_text('[project]\nname = "proj"\n', encoding="utf-8")
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
    return root


def links_of(flow: Flow, kind: str) -> list[FlowLink]:
    return [link for link in flow.links if link.kind == kind]


def flow_at(found: list[Flow], file: str, line: int) -> Flow:
    for flow in found:
        prompt = links_of(flow, "prompt")
        if prompt and prompt[0].file == file and prompt[0].line == line:
            return flow
    raise AssertionError(f"no flow anchored at {file}:{line}: {[f.to_dict() for f in found]}")


# ---------------------------------------------------------------------------
# Constants and the summary line
# ---------------------------------------------------------------------------


def test_kind_tables():
    assert OBJECTIVE_KINDS == {
        "engagement",
        "monetisation",
        "objective_code",
        "attachment",
        "steering",
    }
    assert INFERENCE_KINDS == {"inference", "affect"}
    assert FEEDBACK_KINDS == {"objective_code", "experiment"}
    assert PROFILE_KINDS == {"profile_sdk", "profile_name", "profile_placeholder"}
    assert METRIC_RE.search("engagement_score") and METRIC_RE.search("compute_retention(")
    assert METRIC_RE.search("reengagement") is None  # letters on both sides: another word


def test_flow_summary_says_lexical_co_occurrence_when_nothing_is_established():
    assert flow_summary(None) == "lexical co-occurrence only"
    assert flow_summary(Flow()) == "lexical co-occurrence only"
    weak = Flow(
        links=[
            FlowLink("prompt", "a.py", 3, "prompt = ...", "co-located"),
            FlowLink("intervention", "a.py", 9, "call", "co-located"),
        ]
    )
    assert weak.links_supported is False
    assert flow_summary(weak) == "lexical co-occurrence only"


def test_flow_summary_orders_kinds_and_statuses():
    flow = Flow(
        links=[
            FlowLink("intervention", "a.py", 9, "call", "co-located"),
            FlowLink("intervention", "a.py", 8, "call", "ast"),
            FlowLink("prompt", "a.py", 3, "prompt = ...", "ast"),
            FlowLink("person_data", "a.py", 2, "user_profile", "co-located"),
            FlowLink("objective", "a.py", 1, "keep them talking", "declared"),
        ]
    )
    assert flow_summary(flow) == (
        "objective (declared) -> person data (co-located) -> prompt (ast) -> "
        "intervention (ast, co-located)"
    )
    assert flow.links_supported is False
    assert FLOW_LINK_KINDS == (
        "objective",
        "ingress",
        "person_data",
        "inference",
        "prompt",
        "intervention",
        "feedback",
    )


# ---------------------------------------------------------------------------
# build_flows
# ---------------------------------------------------------------------------


def test_no_deep_pass_means_no_flows(tmp_path: Path):
    ctx = AuditContext(root=tmp_path, inventory=Inventory())
    assert build_flows(ctx) == []


def test_companion_fixture_chain_is_established(audit_fixture, audit_context):
    ctx = audit_context(audit_fixture("persons_companion"))
    found = build_flows(ctx)
    assert found == ctx.flows
    flow = flow_at(found, "app.py", 19)
    assert flow.links_supported is True
    (person,) = links_of(flow, "person_data")
    assert person.established_by == "ast" and person.line == 18
    assert "user_profile" in person.snippet
    interventions = [(link.line, link.established_by) for link in links_of(flow, "intervention")]
    assert interventions == [(20, "ast"), (23, "ast")]
    (objective,) = links_of(flow, "objective")
    # "Keep the user talking" sits inside the SYSTEM_PROMPT literal the assembly reads.
    assert objective.established_by == "declared" and objective.line == 12
    assert flow_summary(flow) == (
        "objective (declared) -> person data (ast) -> prompt (ast) -> intervention (ast)"
    )
    # The system prompt literal gets its own chain; its person data is only co-located.
    literal_flow = flow_at(found, "app.py", 11)
    assert literal_flow.links_supported is False
    assert any(
        link.kind == "person_data" and link.established_by == "co-located"
        for link in literal_flow.links
    )
    assert "person data (co-located)" in flow_summary(literal_flow)


def test_flows_are_sorted_and_deterministic(audit_fixture, audit_context):
    ctx = audit_context(audit_fixture("persons_companion"))
    first = [flow.to_dict() for flow in build_flows(ctx)]
    second = [flow.to_dict() for flow in build_flows(ctx)]
    assert first == second
    anchors = [
        (links_of(flow, "prompt")[0].file, links_of(flow, "prompt")[0].line) for flow in ctx.flows
    ]
    assert anchors == sorted(anchors)


def test_ast_links_everywhere_make_an_established_chain(tmp_path: Path, audit_context):
    root = project(
        tmp_path,
        {
            "app.py": '''
            import anthropic
            client = anthropic.Anthropic()
            SYSTEM_PROMPT = """You are Ava.
            Keep the user talking as long as possible."""

            def chat(body):
                user_profile = load(body["id"])
                prompt = f"{SYSTEM_PROMPT} Interests: {user_profile['interests']} {body['text']}"
                reply = client.messages.create(model="m", system=prompt, messages=[])
                return reply.content[0].text
            ''',
        },
    )
    ctx = audit_context(root)
    flow = flow_at(ctx.flows, "app.py", 8)
    assert flow.kinds() == ("objective", "person_data", "prompt", "intervention", "intervention")
    assert {link.established_by for link in flow.links} == {"ast", "declared"}
    assert flow.links_supported is True
    assert links_of(flow, "person_data")[0].line == 7
    assert links_of(flow, "objective")[0].line == 4


def test_co_located_person_data_is_not_an_established_chain(tmp_path: Path, audit_context):
    root = project(
        tmp_path,
        {
            "app.py": """
            import anthropic
            import analytics
            client = anthropic.Anthropic()

            def track(user_id):
                analytics.identify(user_id, {})

            def chat(name, text):
                prompt = f"You are a friend of {name}. {text}"
                reply = client.messages.create(model="m", system=prompt, messages=[])
                return reply.content[0].text
            """,
        },
    )
    ctx = audit_context(root)
    flow = flow_at(ctx.flows, "app.py", 9)
    (person,) = links_of(flow, "person_data")
    assert person.established_by == "co-located" and person.line == 6
    assert [link.established_by for link in links_of(flow, "intervention")] == ["ast", "ast"]
    assert flow.links_supported is False
    assert flow_summary(flow) == "person data (co-located) -> prompt (ast) -> intervention (ast)"


def test_grep_only_prompt_in_an_unparsable_file_is_lexical_co_occurrence(
    tmp_path: Path, audit_context
):
    root = project(
        tmp_path,
        {
            "app.py": """
            import anthropic
            client = anthropic.Anthropic()
            def broken(:
                prompt = f"You are {name}. Keep the user talking as long as possible."
                client.messages.create(model="m", system=prompt, messages=[])
            """,
        },
    )
    ctx = audit_context(root)
    assert ctx.pyfacts is not None and ctx.pyfacts.unknown  # the tree could not be read
    flow = flow_at(ctx.flows, "app.py", 4)
    assert all(link.established_by == "co-located" for link in flow.links)
    assert {link.kind for link in flow.links} >= {"prompt", "intervention", "objective"}
    assert flow.links_supported is False
    assert flow_summary(flow) == "lexical co-occurrence only"


def test_feedback_link_reads_a_metric_in_the_same_unit(tmp_path: Path, audit_context):
    root = project(
        tmp_path,
        {
            "app.py": """
            import anthropic
            client = anthropic.Anthropic()

            def chat(name):
                prompt = f"You are {name}."
                return client.messages.create(model="m", system=prompt, messages=[]).content[0].text
            """,
            "train.py": "reward = 0.3 * engagement + retention\n",
        },
    )
    ctx = audit_context(root)
    flow = flow_at(ctx.flows, "app.py", 5)
    (feedback,) = links_of(flow, "feedback")
    assert (feedback.file, feedback.line, feedback.established_by) == ("train.py", 1, "co-located")
    assert links_of(flow, "objective") == []  # the objective lives in another file
    assert flow.links_supported is False
    assert flow_summary(flow).endswith("feedback (co-located)")


def test_inference_inside_the_system_prompt_literal_is_declared(tmp_path: Path, audit_context):
    root = project(
        tmp_path,
        {
            "app.py": '''
            import anthropic
            client = anthropic.Anthropic()
            SYSTEM_PROMPT = """Detect the user's loneliness from their messages.
            Be warm."""

            def chat(text):
                reply = client.messages.create(model="m", system=SYSTEM_PROMPT, messages=[text])
                return reply.content[0].text
            ''',
        },
    )
    ctx = audit_context(root)
    flow = flow_at(ctx.flows, "app.py", 3)
    # ("mood" would also be a profile word and add a co-located person-data link.)
    assert flow.kinds() == ("inference", "prompt", "intervention", "intervention")
    (inference,) = links_of(flow, "inference")
    assert inference.established_by == "declared" and inference.line == 3
    assert flow.links_supported is True
    assert flow_summary(flow) == "inference (declared) -> prompt (ast) -> intervention (ast)"


def test_objective_outside_the_prompt_text_is_only_co_located(tmp_path: Path, audit_context):
    root = project(
        tmp_path,
        {
            "app.py": """
            import anthropic
            client = anthropic.Anthropic()
            GOAL = "maximize engagement"

            def chat(name):
                prompt = f"You are {name}."
                reply = client.messages.create(model="m", system=prompt, messages=[])
                return reply.content[0].text
            """,
        },
    )
    ctx = audit_context(root)
    flow = flow_at(ctx.flows, "app.py", 6)
    objective = links_of(flow, "objective")
    assert objective == [] or objective[0].established_by == "co-located"
    assert flow.links_supported is (objective == [])


def test_declared_links_come_from_candidates_inside_the_span_only(tmp_path: Path, audit_context):
    # A code hit outside prompt material (a candidate) counts for a `declared` link only
    # when a prompt span covers it; elsewhere it is dropped rather than co-located.
    root = project(
        tmp_path,
        {
            "app.py": """
            import anthropic
            client = anthropic.Anthropic()
            note = "keep the user talking as long as possible"

            def chat(name):
                prompt = f"You are {name}."
                reply = client.messages.create(model="m", system=prompt, messages=[])
                return reply.content[0].text
            """,
        },
    )
    ctx = audit_context(root)
    flow = flow_at(ctx.flows, "app.py", 6)
    assert links_of(flow, "objective") == []
    assert flow.links_supported is True


def test_builder_tolerates_a_context_without_hits_or_files(tmp_path: Path):
    from aisafe.analysis.pydeep import Assembly, CallSite, PyFacts

    facts = PyFacts(
        llm_calls=[CallSite("app.py", 5, "anthropic", "chat")],
        prompt_assemblies=[Assembly("app.py", 4, "fstring", ("name",), True, ())],
        assembly_feeds_call={0: 0},
    )
    ctx = AuditContext(root=tmp_path, inventory=Inventory(), pyfacts=facts)
    (flow,) = build_flows(ctx)
    assert flow.kinds() == ("prompt", "intervention")
    assert flow.links_supported is True
    assert flow.links[0].snippet == "fstring prompt assembly"  # no text: the fallback label
    assert flows.flow_summary(flow) == "prompt (ast) -> intervention (ast)"


def test_module_exports():
    assert set(flows.__all__) == {
        "FEEDBACK_KINDS",
        "INFERENCE_KINDS",
        "METRIC_RE",
        "OBJECTIVE_KINDS",
        "PROFILE_KINDS",
        "build_flows",
        "flow_summary",
    }


@pytest.mark.parametrize("name", ["persons_benign", "clean_py"])
def test_quiet_fixtures_have_no_established_objective(audit_fixture, audit_context, name: str):
    ctx = audit_context(audit_fixture(name))
    for flow in ctx.flows:
        assert links_of(flow, "objective") == []
