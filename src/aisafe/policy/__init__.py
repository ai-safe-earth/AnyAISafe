"""src/aisafe/policy/__init__.py
-----------------------------
The ethical policy the auditor applies, read from the packaged `mechanisms.yaml` (the
machine-readable half of `charter.md`). `/policy/` at the repository root holds the
source copies; a test pins the packaged files identical to them.

    from aisafe.policy import load_policy, POLICY_VERSION
    policy = load_policy()
    policy.mechanism_of("AUD-1104").name   # "Optimisation of attention, ..."
    policy.order_of("AUD-1104")            # 4

Nothing here is detection logic. The policy says what the eight mechanisms are, what
distinguishes each from ordinary behaviour, which vocabulary a finding may use for its
evidence status, its decision and a control's status, and how severity is read. The rules
in `aisafe.rules` name the mechanism they serve; the evidence model's enums must spell the
same values as the YAML keys (a test pins that too), so a policy change that renames a
decision is caught before a report carries it.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

__all__ = [
    "POLICY_KIND",
    "POLICY_VERSION",
    "Mechanism",
    "Policy",
    "PolicyError",
    "charter_path",
    "load_policy",
    "policy_path",
]

POLICY_KIND = "policy"
_SCHEMA = "aisg/1"
_UNPLACED = 99


class PolicyError(Exception):
    """The policy file cannot be used. One line; the CLI maps it to exit 2."""


@dataclass(frozen=True)
class Mechanism:
    """One prohibited mechanism. `rules` are the detection rule ids that serve it."""

    id: str
    name: str
    prohibited: str
    distinct_from: str
    rules: tuple[str, ...]


@dataclass(frozen=True)
class Policy:
    version: str
    adopted: str
    charter: str
    evidence_statuses: dict[str, str]
    decisions: dict[str, str]
    control_statuses: dict[str, str]
    not_automatic_exemptions: tuple[str, ...]
    severity_criteria: dict[str, str]
    review_max_age_days: int
    evaluation_max_age_days: int
    mechanisms: tuple[Mechanism, ...]

    def mechanism_of(self, rule_id: str) -> Mechanism | None:
        """The mechanism a rule id (or a sub-finding id `AUD-1104/x`) serves, else None."""
        parent = str(rule_id).split("/", 1)[0]
        for mechanism in self.mechanisms:
            if parent in mechanism.rules:
                return mechanism
        return None

    def order_of(self, rule_id: str) -> int:
        """1-based position of the rule's mechanism in the policy; 99 when unplaced.

        This is the `priority` a finding carries: a grouping order, never a severity and
        never the number inside the rule id.
        """
        parent = str(rule_id).split("/", 1)[0]
        for index, mechanism in enumerate(self.mechanisms, 1):
            if parent in mechanism.rules:
                return index
        return _UNPLACED

    def mechanism_by_id(self, mechanism_id: str) -> Mechanism | None:
        for mechanism in self.mechanisms:
            if mechanism.id == mechanism_id:
                return mechanism
        return None

    def to_dict(self) -> dict[str, Any]:
        """The `policy` block of a report: version, charter, adopted."""
        return {"version": self.version, "charter": self.charter, "adopted": self.adopted}


def policy_path() -> Path:
    """Filesystem path of the packaged `mechanisms.yaml`."""
    return Path(str(resources.files(__package__) / "mechanisms.yaml"))


def charter_path() -> Path:
    """Filesystem path of the packaged `charter.md`."""
    return Path(str(resources.files(__package__) / "charter.md"))


def _text(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"policy: {where} must be a non-empty string")
    return " ".join(value.split())


def _mapping(value: Any, where: str) -> dict[str, str]:
    if not isinstance(value, dict) or not value:
        raise PolicyError(f"policy: {where} must be a non-empty mapping")
    return {str(key): _text(text, f"{where}.{key}") for key, text in value.items()}


def _int(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PolicyError(f"policy: {where} must be a positive integer")
    return value


def _parse(data: Any, source: str) -> Policy:
    if not isinstance(data, dict):
        raise PolicyError(f"policy: {source} is not a mapping")
    if data.get("schema") != _SCHEMA or data.get("kind") != POLICY_KIND:
        raise PolicyError(f"policy: {source} is not an {_SCHEMA} {POLICY_KIND} document")
    raw_mechanisms = data.get("mechanisms")
    if not isinstance(raw_mechanisms, list) or not raw_mechanisms:
        raise PolicyError(f"policy: {source} lists no mechanisms")
    mechanisms: list[Mechanism] = []
    seen_ids: set[str] = set()
    seen_rules: set[str] = set()
    for index, entry in enumerate(raw_mechanisms):
        if not isinstance(entry, dict):
            raise PolicyError(f"policy: mechanisms[{index}] is not a mapping")
        mechanism_id = _text(entry.get("id"), f"mechanisms[{index}].id")
        if mechanism_id in seen_ids:
            raise PolicyError(f"policy: mechanism id {mechanism_id} appears twice")
        seen_ids.add(mechanism_id)
        rules = entry.get("rules")
        if not isinstance(rules, list) or not rules:
            raise PolicyError(f"policy: mechanism {mechanism_id} names no rules")
        rule_ids = tuple(_text(rule, f"mechanisms[{index}].rules") for rule in rules)
        for rule_id in rule_ids:
            if rule_id in seen_rules:
                raise PolicyError(f"policy: rule {rule_id} is listed under two mechanisms")
            seen_rules.add(rule_id)
        mechanisms.append(
            Mechanism(
                id=mechanism_id,
                name=_text(entry.get("name"), f"mechanisms[{index}].name"),
                prohibited=_text(entry.get("prohibited"), f"mechanisms[{index}].prohibited"),
                distinct_from=_text(
                    entry.get("distinct_from"), f"mechanisms[{index}].distinct_from"
                ),
                rules=rule_ids,
            )
        )
    exemptions = data.get("not_automatic_exemptions")
    if not isinstance(exemptions, list) or not exemptions:
        raise PolicyError(f"policy: {source} lists no not_automatic_exemptions")
    return Policy(
        version=_text(str(data.get("version", "")), "version"),
        adopted=str(data.get("adopted", "")),
        charter=_text(data.get("charter"), "charter"),
        evidence_statuses=_mapping(data.get("evidence_statuses"), "evidence_statuses"),
        decisions=_mapping(data.get("decisions"), "decisions"),
        control_statuses=_mapping(data.get("control_statuses"), "control_statuses"),
        not_automatic_exemptions=tuple(_text(e, "not_automatic_exemptions") for e in exemptions),
        severity_criteria=_mapping(data.get("severity_criteria"), "severity_criteria"),
        review_max_age_days=_int(data.get("review_max_age_days"), "review_max_age_days"),
        evaluation_max_age_days=_int(
            data.get("evaluation_max_age_days"), "evaluation_max_age_days"
        ),
        mechanisms=tuple(mechanisms),
    )


def _read(path: Path) -> Policy:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"policy: {path.as_posix()}: {exc.strerror or exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy: {path.as_posix()}: invalid YAML ({exc})") from exc
    return _parse(data, path.as_posix())


@lru_cache(maxsize=1)
def _packaged() -> Policy:
    return _read(policy_path())


def load_policy(path: Path | str | None = None) -> Policy:
    """The policy. Without `path`, the packaged one (read once per process)."""
    if path is None:
        return _packaged()
    return _read(Path(path))


POLICY_VERSION: str = _packaged().version
