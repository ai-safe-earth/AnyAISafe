"""src/aisafe/policy/__init__.py
-----------------------------
The ethical policy the auditor applies, read from the packaged `mechanisms.yaml` (the
machine-readable half of `charter.md`). `/policy/` at the repository root holds the
source copies; a test pins the packaged files identical to them.

    from aisafe.policy import load_policy, POLICY_VERSION
    policy = load_policy()
    policy.mechanism_of("AUD-1104").name   # "Optimisation of attention, ..."
    policy.order_of("AUD-1104")            # 4
    policy.pattern_of("AUD-1105/persona")  # Pattern(id="concealment_instruction", ...)

Nothing here is detection logic. The policy says what the eight mechanisms are, what
distinguishes each from ordinary behaviour, which vocabulary a finding may use for its
evidence status, its decision and a control's status, how severity is read, and which links
a trace of each part of a mechanism (its `patterns`) needs before it is complete. The rules
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
    "Pattern",
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
class Pattern:
    """One part of a mechanism and the links a trace of it needs before it is complete.

    `absent_control` names a control whose absence on the path is the mechanism (a crisis
    path, an AI disclosure, a schedule the person set): a trace of the pattern establishes
    it only when the control is shown missing there, and closes it only when the control is
    shown on that path. `rules` are the rule ids (`AUD-1105`) and sub-finding ids
    (`AUD-1105/persona`) whose findings take this pattern; a bare rule id covers its subs
    that no other pattern names.
    """

    id: str
    mechanism: str
    view: str
    links: tuple[str, ...]
    absent_control: str | None
    rules: tuple[str, ...]

    @property
    def display_id(self) -> str:
        """`M4/objective`: the mechanism and the pattern, as the renderers name it."""
        return f"{self.mechanism}/{self.id}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "mechanism": self.mechanism,
            "view": self.view,
            "links": list(self.links),
            "absent_control": self.absent_control,
            "rules": list(self.rules),
        }


@dataclass(frozen=True)
class Mechanism:
    """One prohibited mechanism. `rules` are the detection rule ids that serve it;
    `patterns` are its parts and the links a trace of each needs."""

    id: str
    name: str
    prohibited: str
    distinct_from: str
    rules: tuple[str, ...]
    patterns: tuple[Pattern, ...] = ()

    def pattern(self, pattern_id: str) -> Pattern | None:
        for pattern in self.patterns:
            if pattern.id == pattern_id:
                return pattern
        return None


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
    link_statuses: dict[str, str]
    supported_link_statuses: tuple[str, ...]
    link_kinds: dict[str, tuple[str, ...]]

    def pattern_of(self, display_id: str) -> Pattern | None:
        """The pattern a finding of `display_id` (`AUD-1105/persona`) takes: the pattern
        that names the sub-finding, else the one that names its rule; None when neither
        does (a rule with no trace, such as the review rules of M8)."""
        display_id = str(display_id)
        parent = display_id.split("/", 1)[0]
        fallback: Pattern | None = None
        for mechanism in self.mechanisms:
            for pattern in mechanism.patterns:
                if display_id in pattern.rules:
                    return pattern
                if parent in pattern.rules and fallback is None:
                    fallback = pattern
        return fallback

    def pattern_by_id(self, mechanism_id: str, pattern_id: str) -> Pattern | None:
        mechanism = self.mechanism_by_id(mechanism_id)
        return None if mechanism is None else mechanism.pattern(pattern_id)

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


def _names(value: Any, where: str) -> tuple[str, ...]:
    """A list of distinct non-empty names (an empty list is allowed)."""
    if not isinstance(value, list):
        raise PolicyError(f"policy: {where} must be a list")
    names = tuple(_text(item, where) for item in value)
    if len(set(names)) != len(names):
        raise PolicyError(f"policy: {where} names an entry twice")
    return names


def _link_kinds(value: Any) -> dict[str, tuple[str, ...]]:
    if not isinstance(value, dict) or not value:
        raise PolicyError("policy: link_kinds must be a non-empty mapping")
    out = {str(view): _names(kinds, f"link_kinds.{view}") for view, kinds in value.items()}
    if not all(out.values()):
        raise PolicyError("policy: every view in link_kinds needs at least one kind")
    return out


def _patterns(
    raw: Any,
    mechanism_id: str,
    rule_ids: tuple[str, ...],
    link_kinds: dict[str, tuple[str, ...]],
    seen_rules: set[str],
) -> tuple[Pattern, ...]:
    """A mechanism's patterns, each checked against the views, the link kinds and the
    rules the mechanism lists; a rule or sub-finding id belongs to one pattern at most."""
    where = f"mechanism {mechanism_id} patterns"
    if not isinstance(raw, list):
        raise PolicyError(f"policy: {where} must be a list")
    out: list[Pattern] = []
    ids: set[str] = set()
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise PolicyError(f"policy: {where}[{index}] is not a mapping")
        pattern_id = _text(entry.get("id"), f"{where}[{index}].id")
        if pattern_id in ids:
            raise PolicyError(f"policy: {where} lists pattern {pattern_id} twice")
        ids.add(pattern_id)
        view = _text(entry.get("view"), f"{where}.{pattern_id}.view")
        if view not in link_kinds:
            raise PolicyError(f"policy: {where}.{pattern_id} has an unknown view {view!r}")
        links = _names(entry.get("links"), f"{where}.{pattern_id}.links")
        if not links:
            raise PolicyError(f"policy: {where}.{pattern_id} requires no link")
        unknown = [kind for kind in links if kind not in link_kinds[view]]
        if unknown:
            raise PolicyError(
                f"policy: {where}.{pattern_id} names link kinds outside the {view} view: "
                + ", ".join(unknown)
            )
        absent = entry.get("absent_control")
        absent_control = None if absent is None else _text(absent, f"{where}.{pattern_id}")
        rules = _names(entry.get("rules", []), f"{where}.{pattern_id}.rules")
        for rule in rules:
            if rule.split("/", 1)[0] not in rule_ids:
                raise PolicyError(
                    f"policy: {where}.{pattern_id} names {rule}, which is not a rule of "
                    f"{mechanism_id}"
                )
            if rule in seen_rules:
                raise PolicyError(f"policy: {rule} is named by two patterns")
            seen_rules.add(rule)
        out.append(Pattern(pattern_id, mechanism_id, view, links, absent_control, rules))
    return tuple(out)


def _parse(data: Any, source: str) -> Policy:
    if not isinstance(data, dict):
        raise PolicyError(f"policy: {source} is not a mapping")
    if data.get("schema") != _SCHEMA or data.get("kind") != POLICY_KIND:
        raise PolicyError(f"policy: {source} is not an {_SCHEMA} {POLICY_KIND} document")
    link_statuses = _mapping(data.get("link_statuses"), "link_statuses")
    supported = _names(data.get("supported_link_statuses"), "supported_link_statuses")
    if not supported or any(status not in link_statuses for status in supported):
        raise PolicyError("policy: supported_link_statuses must name link_statuses")
    link_kinds = _link_kinds(data.get("link_kinds"))
    seen_pattern_rules: set[str] = set()
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
                patterns=_patterns(
                    entry.get("patterns", []),
                    mechanism_id,
                    rule_ids,
                    link_kinds,
                    seen_pattern_rules,
                ),
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
        link_statuses=link_statuses,
        supported_link_statuses=supported,
        link_kinds=link_kinds,
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
