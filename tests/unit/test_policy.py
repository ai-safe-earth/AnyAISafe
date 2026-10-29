"""tests/unit/test_policy.py
-------------------------
The ethical policy: the packaged copies equal the sources under `policy/`, the loader
validates the shape, the evidence model's enums spell the policy's keys, every rule the
policy lists is registered and every registered rule is listed under exactly one
mechanism, and the charter keeps the hypothesis apart from the commitment.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from aisafe.evidence.model import ControlStatus, Decision, EvidenceStatus, Severity
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
