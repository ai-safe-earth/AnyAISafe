"""tests/unit/test_policy.py
-------------------------
The ethical policy: the packaged copies equal the sources under `policy/`, the loader
validates the shape, the evidence model's enums spell the policy's keys, every rule the
policy lists is registered and every registered rule is listed under exactly one
mechanism, each mechanism's patterns name the links a trace needs, and the charter keeps
the hypothesis apart from the commitment.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from aisafe.evidence.model import (
    FLOW_ESTABLISHED_BY,
    LINK_KINDS_BY_VIEW,
    SUPPORTED_LINK_STATUSES,
    ControlStatus,
    Decision,
    EvidenceStatus,
    Severity,
)
from aisafe.policy import (
    POLICY_VERSION,
    Policy,
    PolicyError,
    charter_path,
    load_policy,
    policy_path,
)

REPO = Path(__file__).resolve().parents[2]
SOURCE_YAML = REPO / "policy" / "mechanisms.yaml"
SOURCE_CHARTER = REPO / "policy" / "charter.md"


def test_packaged_copies_equal_the_sources() -> None:
    assert policy_path().read_bytes() == SOURCE_YAML.read_bytes()
    assert charter_path().read_bytes() == SOURCE_CHARTER.read_bytes()


def test_policy_loads_with_eight_mechanisms_in_order() -> None:
    policy = load_policy()
    assert isinstance(policy, Policy)
    assert policy.version == POLICY_VERSION
    assert [m.id for m in policy.mechanisms] == [f"M{i}" for i in range(1, 9)]
    for mechanism in policy.mechanisms:
        assert mechanism.name and mechanism.prohibited and mechanism.distinct_from
        assert mechanism.rules


def test_enum_values_match_the_policy_vocabulary() -> None:
    policy = load_policy()
    assert {e.value for e in EvidenceStatus} == set(policy.evidence_statuses)
    assert {d.value for d in Decision} == set(policy.decisions)
    assert {c.value for c in ControlStatus} == set(policy.control_statuses)
    assert {s.value for s in Severity} == set(policy.severity_criteria)


def test_link_vocabulary_matches_the_evidence_model() -> None:
    policy = load_policy()
    assert policy.version == "1.1.0"
    assert tuple(policy.link_statuses) == FLOW_ESTABLISHED_BY
    assert tuple(policy.supported_link_statuses) == SUPPORTED_LINK_STATUSES
    assert {view: tuple(kinds) for view, kinds in policy.link_kinds.items()} == (LINK_KINDS_BY_VIEW)


def test_every_mechanism_but_the_review_one_has_patterns() -> None:
    policy = load_policy()
    for mechanism in policy.mechanisms:
        if mechanism.id == "M8":
            assert mechanism.patterns == ()  # the review rules trace nothing
            continue
        assert mechanism.patterns, mechanism.id
        for pattern in mechanism.patterns:
            assert pattern.mechanism == mechanism.id
            assert pattern.links and set(pattern.links) <= set(policy.link_kinds[pattern.view])
            assert all(rule.split("/", 1)[0] in mechanism.rules for rule in pattern.rules)
            assert pattern.display_id == f"{mechanism.id}/{pattern.id}"


def test_pattern_of_takes_the_sub_finding_before_its_rule() -> None:
    policy = load_policy()
    assert policy.pattern_of("AUD-1101").id == "binding"
    assert policy.pattern_of("AUD-1101/sensitive").id == "binding"
    assert policy.pattern_of("AUD-1101/store").id == "storage"
    assert policy.pattern_of("AUD-1101/store").view == "person-data"
    assert policy.pattern_of("AUD-1104/outreach").id == "outreach"
    assert policy.pattern_of("AUD-1104/vulnerable").id == "objective"  # falls back to the rule
    assert policy.pattern_of("AUD-1108").absent_control == "crisis_path"
    assert policy.pattern_of("AUD-1105/no-disclosure").absent_control == "ai_disclosure"
    assert policy.pattern_of("AUD-1105/persona").id == "concealment_instruction"
    assert policy.pattern_of("AUD-1110/affiliate").id == "affiliate"
    assert policy.pattern_of("AUD-1107/missing") is None
    assert policy.pattern_of("AUD-1106/none") is None
    assert policy.pattern_of("AUD-999") is None
    crisis = policy.pattern_by_id("M5", "confidant_without_crisis_path")
    assert crisis.links == ("ingress", "prompt", "intervention")
    assert policy.pattern_by_id("M5", "nothing") is None
    assert policy.pattern_by_id("M9", "binding") is None


def _mutated(tmp_path: Path, change) -> Path:
    data = yaml.safe_load(SOURCE_YAML.read_text(encoding="utf-8"))
    change(data)
    out = tmp_path / "mutated.yaml"
    out.write_text(yaml.safe_dump(data), encoding="utf-8")
    return out


def _m1_patterns(data: dict) -> list:
    return data["mechanisms"][0]["patterns"]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: _m1_patterns(d)[0].update(view="audit"), "unknown view"),
        (lambda d: _m1_patterns(d)[0].update(links=["collection"]), "outside the influence"),
        (lambda d: _m1_patterns(d)[0].update(links=[]), "requires no link"),
        (lambda d: _m1_patterns(d)[0].update(rules=["AUD-1104"]), "not a rule of M1"),
        (lambda d: _m1_patterns(d)[1]["rules"].append("AUD-1101"), "named by two patterns"),
        (lambda d: _m1_patterns(d)[1].update(id="binding"), "twice"),
        (lambda d: d.update(supported_link_statuses=["guessed"]), "supported_link_statuses"),
        (lambda d: d.update(link_kinds={}), "link_kinds"),
    ],
    ids=[
        "unknown-view",
        "kind-outside-view",
        "no-link",
        "foreign-rule",
        "rule-in-two-patterns",
        "duplicate-id",
        "unsupported-status",
        "no-kinds",
    ],
)
def test_malformed_patterns_are_policy_errors(tmp_path: Path, change, message) -> None:
    with pytest.raises(PolicyError, match=message):
        load_policy(_mutated(tmp_path, change))


def test_order_of_and_mechanism_of() -> None:
    policy = load_policy()
    assert policy.order_of("AUD-1101") == 1
    assert policy.order_of("AUD-1104/vulnerable") == 4
    assert policy.order_of("AUD-1109") == 5
    assert policy.order_of("AUD-1108") == 5
    assert policy.order_of("AUD-1110") == 7
    assert policy.order_of("AUD-1107") == 8
    assert policy.order_of("AUD-301") == 99
    assert policy.mechanism_of("AUD-1105").id == "M6"
    assert policy.mechanism_of("AUD-999") is None


def test_every_registered_rule_sits_under_exactly_one_mechanism() -> None:
    from aisafe.rules import ALL_RULES, MISSING_RULE_MODULES

    assert MISSING_RULE_MODULES == []
    policy = load_policy()
    listed = [rule_id for m in policy.mechanisms for rule_id in m.rules]
    assert len(listed) == len(set(listed))
    registered = {rule.id for rule in ALL_RULES}
    assert set(listed) == registered


def test_not_automatic_exemptions_name_the_five_the_charter_names() -> None:
    text = " ".join(load_policy().not_automatic_exemptions).lower()
    for word in ("disclosure", "consent", "adult", "fiction", "human"):
        assert word in text, word


def test_charter_separates_hypothesis_from_commitment() -> None:
    charter = SOURCE_CHARTER.read_text(encoding="utf-8")
    assert "## 1. The working hypothesis" in charter
    assert "## 2. The normative commitment" in charter
    assert charter.index("working hypothesis") < charter.index("normative commitment")
    assert "Legal permissibility does not establish ethical acceptability" in charter
    assert "not automatic exemptions" in charter


def test_malformed_policy_is_a_policy_error(tmp_path: Path) -> None:
    bad = tmp_path / "p.yaml"
    bad.write_text("schema: aisg/1\nkind: policy\nversion: '1'\n", encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(bad)
    data = yaml.safe_load(SOURCE_YAML.read_text(encoding="utf-8"))
    data["mechanisms"][0]["rules"].append(data["mechanisms"][1]["rules"][0])
    dup = tmp_path / "dup.yaml"
    dup.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(PolicyError, match="two mechanisms"):
        load_policy(dup)
