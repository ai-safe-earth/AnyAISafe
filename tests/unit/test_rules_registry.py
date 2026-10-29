"""
tests/unit/test_rules_registry.py
---------------------------------
Registry-level pins for the `aisafe audit` rules: every module present, exactly the ten
focused ids, every rule under one policy mechanism with `priority` equal to the
mechanism's order (never the number in the id), a version and a change log, metadata
complete and honest (references in the grammar, a remediation that says what it removes,
at least one alternative that is not aisafe, failure modes), precision UNMEASURED (never
guessed), every rule silent on an empty context, and the vocabulary modules marked so the
self-audit does not read them as prompts.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aisafe.evidence.model import (
    REMOVES,
    AuditContext,
    Decision,
    EvidenceStatus,
    Inventory,
    Tier,
    UnknownCategory,
    UnknownItem,
)
from aisafe.policy import load_policy
from aisafe.reporting.report import BANNED_PHRASES
from aisafe.rules import (
    ALL_RULES,
    MIN_PRECISION,
    MISSING_RULE_MODULES,
    AuditRule,
    coverage_table,
    default_rules,
    experimental_rules,
    is_demoted,
    rule_by_id,
    rules_of_mechanism,
    run_rules,
    select_rules,
)

RULE_ID = re.compile(r"^AUD-11(?:0[1-9]|10)$")
EXPECTED_IDS = {f"AUD-{n}" for n in range(1101, 1111)}
REFERENCE_RE = re.compile(
    r"^(LLM(0[1-9]|10)|EU:Art\.\d+(\(\d+\))?(\([a-h]\))?|GDPR:Art\.\d+|DSA:Art\.\d+"
    r"|US-[A-Z]{2}:([A-Z]{2}\d+|GBL-Art\.\d+)|NIST:[A-Z]+-\d+\.\d+)$"
)
# The one word the design bans outright, assembled from fragments so this file does not
# carry it as a contiguous literal (the self-audit scans tests too).
BANNED_WORD_RE = re.compile(r"\bcl" + r"ean\b", re.IGNORECASE)
COMPLETION_CLAIMS = ("resolves the finding", "guarantees", "certif")

SRC = Path(__file__).resolve().parents[2] / "src" / "aisafe"
VOCABULARY_MODULES = sorted(p.relative_to(SRC).as_posix() for p in (SRC / "rules").glob("*.py")) + [
    "discovery/vocabulary.py",
    "analysis/checks.py",
]


def _empty_context(tmp_path: Path) -> AuditContext:
    return AuditContext(root=tmp_path, inventory=Inventory())


# ---------------------------------------------------------------------------
# Self-vocabulary: the rule modules must not audit themselves
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("relpath", VOCABULARY_MODULES)
def test_vocabulary_modules_carry_the_ignore_marker(relpath: str) -> None:
    from aisafe.discovery.patterns import IGNORE_MARKER

    head = (SRC / relpath).read_text(encoding="utf-8").splitlines()[:5]
    assert IGNORE_MARKER in head, f"{relpath} lacks the ignore-file marker in its first five lines"


def test_walk_skips_every_marked_rule_module() -> None:
    from aisafe.discovery.walk import walk

    files, _units, _unknown = walk(SRC / "rules")
    seen = {record.relpath for record in files}
    marked = {Path(p).name for p in VOCABULARY_MODULES if p.startswith("rules/")}
    assert marked
    assert not (seen & marked), f"walk() still yields marked modules: {sorted(seen & marked)}"


# ---------------------------------------------------------------------------
# Registry shape
# ---------------------------------------------------------------------------


def test_every_rule_module_is_present() -> None:
    assert MISSING_RULE_MODULES == []
    assert len(ALL_RULES) == len(EXPECTED_IDS)


def test_rule_ids_are_unique_well_formed_and_complete() -> None:
    ids = [rule.id for rule in ALL_RULES]
    assert len(ids) == len(set(ids)), "duplicate rule id"
    for rule_id in ids:
        assert RULE_ID.match(rule_id), rule_id
    assert set(ids) == EXPECTED_IDS


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_priority_is_the_mechanism_order_not_the_id(rule: type[AuditRule]) -> None:
    policy = load_policy()
    instance = rule()
    assert instance.priority == policy.order_of(rule.id)
    assert 1 <= instance.priority <= len(policy.mechanisms)
    assert instance.priority != 11
    assert rule.mechanism_id() == policy.mechanism_of(rule.id).id


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_rule_is_versioned_and_documents_its_changes(rule: type[AuditRule]) -> None:
    assert isinstance(rule.version, int) and rule.version >= 1
    if rule.id in {f"AUD-{n}" for n in range(1101, 1109)}:
        assert rule.version >= 2, f"{rule.id} changed semantics in the pivot; bump version"
    if rule.version > 1:
        assert rule.changed, f"{rule.id} v{rule.version} lists no changes"
        assert all(line.isascii() and line.strip() for line in rule.changed)


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_rule_metadata_is_complete(rule: type[AuditRule]) -> None:
    assert issubclass(rule, AuditRule)
    assert rule.title.strip()
    assert rule.references, f"{rule.id} has no references"
    for reference in rule.references:
        assert REFERENCE_RE.match(reference), (rule.id, reference)
    assert rule.tier in tuple(Tier)
    rec = rule.recommendation
    assert rec.summary.strip()
    assert len(rec.alternatives) >= 3, f"{rule.id} needs at least three alternatives"
    assert any("aisafe" not in alt.lower() for alt in rec.alternatives), (
        f"{rule.id}: at least one alternative must not point at aisafe"
    )
    assert rec.removes, f"{rule.id}: the remediation must say what it removes"
    assert set(rec.removes) <= set(REMOVES)
    assert rule.known_failure_modes, f"{rule.id} admits no failure mode"
    assert rule.default_evidence_status in tuple(EvidenceStatus)
    assert rule.default_decision in tuple(Decision)


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_measured_precision_is_unmeasured(rule: type[AuditRule]) -> None:
    # UNMEASURED is the literal None; a number here must come from a labelled corpus.
    assert rule.measured_precision is None
    assert not is_demoted(rule)
    assert not rule.experimental()
    assert MIN_PRECISION == 0.80


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_rule_prose_is_ascii_without_verdict_or_completion_language(
    rule: type[AuditRule],
) -> None:
    rec = rule.recommendation
    texts = [rule.title, rec.summary, *rec.alternatives, *rule.known_failure_modes, *rule.changed]
    for text in texts:
        assert text.isascii(), (rule.id, text)
        lowered = text.lower()
        for phrase in BANNED_PHRASES:
            assert phrase not in lowered, (rule.id, phrase)
        assert not BANNED_WORD_RE.search(text), (rule.id, text)
        for claim in COMPLETION_CLAIMS:
            assert claim not in lowered, (rule.id, claim)


def test_default_and_experimental_partition_the_registry() -> None:
    assert default_rules() == list(ALL_RULES)
    assert experimental_rules() == []
    for rule in ALL_RULES:
        assert rule_by_id(rule.id) is rule
    assert rule_by_id("AUD-000") is None
    assert rule_by_id("AUD-301") is None


def test_rules_of_mechanism_follows_the_policy() -> None:
    policy = load_policy()
    for mechanism in policy.mechanisms:
        rules = rules_of_mechanism(mechanism.id)
        assert {r.id for r in rules} == set(mechanism.rules), mechanism.id
    assert rules_of_mechanism("M99") == []


def test_select_rules_notes_unknown_ids_without_raising() -> None:
    rules, notes = select_rules(["AUD-1104", "AUD-999", "AUD-1104"])
    assert [r.id for r in rules] == ["AUD-1104"]
    assert notes == ["unknown rule id AUD-999"]
    everything, no_notes = select_rules(None)
    assert everything == default_rules()
    assert no_notes == []


# ---------------------------------------------------------------------------
# Evaluation safety
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_rule_is_silent_on_an_empty_context(rule: type[AuditRule], tmp_path: Path) -> None:
    instance = rule()
    assert instance.evaluate(_empty_context(tmp_path)) == []


def test_run_rules_on_empty_context_yields_nothing(tmp_path: Path) -> None:
    findings, unknown = run_rules(ALL_RULES, _empty_context(tmp_path))
    assert findings == []
    assert unknown == []


def test_rule_exception_becomes_an_unknown_item(tmp_path: Path) -> None:
    class Broken(AuditRule):
        id = "AUD-9999"
        title = "broken on purpose"

        def evaluate(self, ctx: AuditContext):
            raise RuntimeError("boom")

    findings, unknown = run_rules([Broken], _empty_context(tmp_path))
    assert findings == []
    assert len(unknown) == 1
    item = unknown[0]
    assert isinstance(item, UnknownItem)
    assert item.category is UnknownCategory.RUNTIME
    assert item.what == "rule AUD-9999"
    assert "RuntimeError: boom" in item.why
    assert item.rule_ids == ("AUD-9999",)


def test_companion_findings_carry_policy_and_rule_versions(audit_fixture, audit_context) -> None:
    ctx = audit_context(audit_fixture("persons_companion"))
    findings, unknown = run_rules(ALL_RULES, ctx)
    assert findings, "persons_companion must produce findings"
    policy = load_policy()
    for finding in findings:
        assert finding.policy_version == policy.version
        assert finding.rule_version >= 1
        assert finding.mechanism == policy.mechanism_of(finding.id).id
        assert finding.priority == policy.order_of(finding.id)
        assert finding.artifacts or finding.basis.value == "absence"
    assert all(item.category is not UnknownCategory.RUNTIME for item in unknown), (
        "no rule may crash on the reference fixture"
    )
    # Sorted by severity first, then mechanism order: never by rule id.
    ranks = [(-f.severity.rank(), f.priority) for f in findings]
    assert ranks == sorted(ranks)


# ---------------------------------------------------------------------------
# Coverage table
# ---------------------------------------------------------------------------


def test_coverage_table_marks_not_assessed_without_a_surface(tmp_path: Path) -> None:
    policy = load_policy()
    rows = coverage_table(policy, ALL_RULES, [], _empty_context(tmp_path))
    assert [row["id"] for row in rows] == [m.id for m in policy.mechanisms]
    assert {row["decision"] for row in rows} == {Decision.NOT_ASSESSED.value}
    assert all(row["findings"] == 0 for row in rows)


def test_coverage_table_reads_the_strongest_decision(audit_fixture, audit_context) -> None:
    policy = load_policy()
    ctx = audit_context(audit_fixture("persons_companion"))
    findings, _ = run_rules(ALL_RULES, ctx)
    rows = {row["id"]: row for row in coverage_table(policy, ALL_RULES, findings, ctx)}
    assert rows["M4"]["findings"] >= 1
    assert rows["M4"]["decision"] == Decision.VIOLATES.value
    quiet = [row for row in rows.values() if row["findings"] == 0]
    assert all(row["decision"] == Decision.NO_VIOLATION.value for row in quiet)
    assert all(row["surfaces"] >= 1 for row in rows.values())
