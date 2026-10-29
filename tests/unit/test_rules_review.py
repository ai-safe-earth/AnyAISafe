"""tests/unit/test_rules_review.py
-------------------------------
AUD-1107 (mechanism M8): the review record. The three bench cases of pair 13
(review-missing, review-stale, review-fresh), the two reference fixtures (persons_companion
owes a review, persons_benign carries only a mention), and hand-made records under tmp_path:
stale by hash, stale by date, a file outside every record, a mechanism outside every scope
(read from the record that lists the file, not from the unit's other records), a record for
another unit, a legacy ai-system-card.yaml block (/unbound, only when no record file exists
at all), a record decided under an older policy (/policy), an entry the parser dropped
(the anchor stays on the right entry) and a `--review-record` file outside the tree (its
path never enters a finding). Every finding asserts display id, severity, evidence status
and decision; every emitted text is ASCII and carries no verdict language.
"""

from __future__ import annotations

import hashlib
import re
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from aisafe.evidence.model import (
    AuditContext,
    Basis,
    ControlStatus,
    Decision,
    EvidenceStatus,
    Inventory,
    Severity,
    UnknownCategory,
)
from aisafe.policy import load_policy
from aisafe.reporting.report import BANNED_PHRASES
from aisafe.rules import run_rules
from aisafe.rules._common import LEGAL_CAVEAT, PERSON_KINDS
from aisafe.rules.review import MECHANISM_OF_KIND, RULES, ReviewRecordGap

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "audit"
REFERENCE_RE = re.compile(
    r"^(LLM(0[1-9]|10)|EU:Art\.\d+(\(\d+\))?(\([a-h]\))?|GDPR:Art\.\d+|DSA:Art\.\d+"
    r"|US-[A-Z]{2}:([A-Z]{2}\d+|GBL-Art\.\d+)|NIST:[A-Z]+-\d+\.\d+)$"
)
# Assembled from fragments so this file does not carry the word (the self-audit scans tests).
BANNED_WORD_RE = re.compile(r"\bcl" + r"ean\b", re.IGNORECASE)
COMPLETION_CLAIMS = ("resolves the finding", "guarantees", "certif")

PYPROJECT = '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["anthropic", "fastapi"]\n'
CHAT_PY = (
    "from fastapi import FastAPI, Request\n"
    "import anthropic\n\n"
    "app = FastAPI()\n"
    "client = anthropic.Anthropic()\n\n"
    'SYSTEM_PROMPT = """{system}"""\n\n\n'
    '@app.post("/chat")\n'
    "async def chat(request: Request):\n"
    "    body = await request.json()\n"
    "    prompt = f\"{{SYSTEM_PROMPT}}\\n{{body['text']}}\"\n"
    "    reply = client.messages.create(\n"
    '        model="claude-sonnet-4-5", max_tokens=200, system=prompt, messages=[]\n'
    "    )\n"
    '    return {{"reply": reply.content[0].text}}\n'
)
ENGAGEMENT_PROMPT = "Maximize engagement and keep the user talking."
ALL_MECHANISMS = [mechanism.id for mechanism in load_policy().mechanisms]
WINDOW = load_policy().review_max_age_days
CURRENT_POLICY = load_policy().version
SUB_NAMES = ["missing", "uncovered", "stale", "unbound", "policy"]
CARD = "schema: aisg/1\nsystem:\n  name: x\n  purpose: y\naffected_persons: teenagers\n{block}"
FILLED_BLOCK = 'prompt_audit:\n  reviewed_at: 2026-10-01\n  reviewer: "J. Doe <risk owner>"\n'


def _tree(
    tmp_path: Path, files: dict[str, str], system: str = "You are an AI assistant for Acme."
) -> Path:
    root = tmp_path / "tree"
    root.mkdir(parents=True, exist_ok=True)
    base = {"pyproject.toml": PYPROJECT, "chat.py": CHAT_PY.format(system=system)}
    base.update(files)
    for rel, text in base.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _sha(root: Path, rel: str) -> str:
    return hashlib.sha256((root / rel).read_bytes()).hexdigest()


def _entry_lines(
    root: Path,
    artifacts: dict[str, str | None],
    *,
    reviewed_at: date | None = None,
    scope: list[str] | None = None,
    units: list[str] | None = None,
    reviewer: str = "J. Doe <product owner>",
    purpose: str = "a support assistant for Acme customers",
    affected: str | None = None,
) -> list[str]:
    """One entry under `reviews`. An artifact hash of None means "the file's current hash"."""
    when = reviewed_at or date.today()
    lines = [f'  - reviewer: "{reviewer}"', f"    reviewed_at: {when.isoformat()}"]
    if units:
        lines.append(f"    units: [{', '.join(units)}]")
    lines.append(f"    scope: [{', '.join(scope if scope is not None else ALL_MECHANISMS)}]")
    lines.append(f'    declared_purpose: "{purpose}"')
    if affected:
        lines.append(f'    affected_population: "{affected}"')
    lines.append("    artifacts:")
    for rel, digest in artifacts.items():
        lines.append(f'      - {{path: {rel}, sha256: "{digest or _sha(root, rel)}"}}')
    return lines


def _records(
    root: Path,
    entries: list[dict],
    *,
    policy_version: str | None = CURRENT_POLICY,
    name: str = "aisafe-review.yaml",
) -> Path:
    """Write a record file with one entry per dict of `_entry_lines` keyword arguments."""
    lines = ["schema: aisg/1", "kind: review"]
    if policy_version is not None:
        lines.append(f'policy_version: "{policy_version}"')
    lines.append("reviews:")
    for entry in entries:
        lines += _entry_lines(root, **entry)
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _record(
    root: Path,
    artifacts: dict[str, str | None],
    *,
    reviewed_at: date | None = None,
    scope: list[str] | None = None,
    policy_version: str | None = CURRENT_POLICY,
    units: list[str] | None = None,
    reviewer: str = "J. Doe <product owner>",
    purpose: str = "a support assistant for Acme customers",
    affected: str | None = None,
    name: str = "aisafe-review.yaml",
) -> Path:
    """Write a record file with one entry."""
    entry = {
        "artifacts": artifacts,
        "reviewed_at": reviewed_at,
        "scope": scope,
        "units": units,
        "reviewer": reviewer,
        "purpose": purpose,
        "affected": affected,
    }
    return _records(root, [entry], policy_version=policy_version, name=name)


def _run(audit_context, root: Path, *, deep: bool = True):
    findings, _unknown = run_rules(RULES, audit_context(root, deep=deep))
    return findings


def _ids(findings) -> list[str]:
    return sorted(f.display_id for f in findings)


def _check_shape(finding, sub: str, severity: Severity) -> None:
    assert finding.display_id == f"AUD-1107/{sub}"
    assert finding.severity == severity
    assert finding.evidence_status == EvidenceStatus.DETECTED_SIGNAL
    assert finding.decision == Decision.REVIEW
    assert finding.basis == Basis.ABSENCE
    assert finding.mechanism == "M8" and finding.rule_version == 2
    assert finding.notes and LEGAL_CAVEAT in finding.notes
    assert finding.uncertainty
    _check_text(finding.title, finding.notes, finding.uncertainty, *finding.coverage_gaps)
    _check_text(*(leg.snippet for leg in finding.evidence))


def _check_text(*texts: str) -> None:
    for text in texts:
        assert text.isascii(), text
        lowered = text.lower()
        assert not any(phrase in lowered for phrase in BANNED_PHRASES), text
        assert not BANNED_WORD_RE.search(text), text


def _engagement_tree(tmp_path: Path) -> Path:
    return _tree(tmp_path, {"prompts/goal.md": ENGAGEMENT_PROMPT}, system="Chat.")


# ---------------------------------------------------------------------------
# Metadata contract
# ---------------------------------------------------------------------------


class TestContract:
    def test_registry_shape(self):
        assert RULES == [ReviewRecordGap]
        rule = ReviewRecordGap()
        assert rule.id == "AUD-1107" and rule.version == 2 and rule.changed
        assert ReviewRecordGap.mechanism_id() == "M8"
        assert rule.priority == load_policy().order_of("AUD-1107") == 8
        assert rule.requires_ai_surface is True and rule.measured_precision is None
        assert rule.basis == Basis.ABSENCE and rule.default_decision == Decision.REVIEW
        assert rule.default_evidence_status == EvidenceStatus.DETECTED_SIGNAL

    def test_subs_name_the_five_gaps_with_the_contract_severities(self):
        subs = ReviewRecordGap.SUBS
        assert [entry[0] for entry in subs] == SUB_NAMES
        severities = {entry[0]: entry[1] for entry in subs}
        assert severities == {
            "missing": Severity.LOW,
            "uncovered": Severity.LOW,
            "stale": Severity.LOW,
            "unbound": Severity.INFO,
            "policy": Severity.LOW,
        }
        for entry in subs:
            assert len(entry) == 5
            assert entry[2] == EvidenceStatus.DETECTED_SIGNAL and entry[3] == Decision.REVIEW
            assert entry[4].strip() and entry[4].isascii()

    def test_references_follow_the_grammar(self):
        assert ReviewRecordGap.references
        for reference in ReviewRecordGap.references:
            assert REFERENCE_RE.match(reference), reference

    def test_recommendation_points_at_the_review_commands_and_removes_the_record_gap(self):
        rec = ReviewRecordGap.recommendation
        assert rec.removes == ("record",)
        assert "aisafe review init" in rec.summary and "aisafe review record" in rec.summary
        assert len(rec.alternatives) >= 3
        assert any("aisafe" not in alt.lower() for alt in rec.alternatives)
        assert ReviewRecordGap.known_failure_modes

    def test_prose_is_ascii_without_verdict_or_completion_language(self):
        rec = ReviewRecordGap.recommendation
        texts = [ReviewRecordGap.title, rec.summary, *rec.alternatives]
        texts += list(ReviewRecordGap.known_failure_modes) + list(ReviewRecordGap.changed)
        texts += [entry[4] for entry in ReviewRecordGap.SUBS]
        _check_text(*texts)
        for text in texts:
            assert not any(claim in text.lower() for claim in COMPLETION_CLAIMS), text

    def test_mechanism_map_stays_inside_the_policy_and_the_person_kinds(self):
        assert set(MECHANISM_OF_KIND.values()) <= set(ALL_MECHANISMS)
        assert set(MECHANISM_OF_KIND) <= set(PERSON_KINDS)
        # A vulnerable-group word names a population, not a mechanism.
        assert "vulnerable" not in MECHANISM_OF_KIND


# ---------------------------------------------------------------------------
# Bench cases (pair 13)
# ---------------------------------------------------------------------------


class TestBench:
    def test_review_missing(self, bench_case, audit_context):
        findings = _run(audit_context, bench_case("review-missing"))
        assert _ids(findings) == ["AUD-1107/missing"]
        finding = findings[0]
        _check_shape(finding, "missing", Severity.LOW)
        assert finding.scope.kind == "unit"
        assert finding.evidence[0].role == "absence"
        assert "prompts/companion.md" in finding.notes and "M5" in finding.notes
        assert "aisafe-review.yaml" in finding.notes
        assert finding.coverage_gaps

    def test_review_stale(self, bench_case, audit_context):
        root = bench_case("review-stale")
        findings = _run(audit_context, root)
        assert _ids(findings) == ["AUD-1107/stale"]
        finding = findings[0]
        _check_shape(finding, "stale", Severity.LOW)
        assert "prompts/companion.md changed since the review" in finding.notes
        assert finding.declared_purpose == "a conversational companion for adults who chose it"
        assert finding.affected_population == "adult users of the companion app"
        assert finding.evidence[0].file == "aisafe-review.yaml" and finding.evidence[0].line > 0
        stale_legs = [leg for leg in finding.evidence if leg.role == "stale"]
        assert [leg.file for leg in stale_legs] == ["prompts/companion.md"]
        hashes = {ref.file: ref.sha256 for ref in finding.artifacts}
        assert hashes["prompts/companion.md"] == _sha(root, "prompts/companion.md")

    def test_review_fresh_is_silent(self, bench_case, audit_context):
        root = bench_case("review-fresh")
        document = yaml.safe_load((root / "aisafe-review.yaml").read_text(encoding="utf-8"))
        record = document["reviews"][0]
        for entry in record["artifacts"]:
            actual = _sha(root, entry["path"])
            if actual != entry["sha256"]:
                pytest.fail(
                    f"bench data: review-fresh records {entry['sha256']} for {entry['path']} "
                    f"but the file hashes to {actual}; the case cannot be fresh"
                )
        reviewed_at = record["reviewed_at"]
        if (date.today() - reviewed_at).days > WINDOW:
            pytest.fail(
                f"bench data: review-fresh was reviewed on {reviewed_at}, more than {WINDOW} "
                f"days ago; the case has aged out of the policy window"
            )
        assert _run(audit_context, root) == []


# ---------------------------------------------------------------------------
# Reference fixtures
# ---------------------------------------------------------------------------


class TestFixtures:
    def test_companion_owes_a_review(self, audit_context):
        findings = _run(audit_context, FIXTURES / "persons_companion")
        assert _ids(findings) == ["AUD-1107/missing"]
        finding = findings[0]
        _check_shape(finding, "missing", Severity.LOW)
        for mechanism in ("M1", "M4", "M6"):
            assert mechanism in finding.notes
        surface = [leg.file for leg in finding.evidence if leg.role == "surface"]
        assert surface == ["analytics.py", "app.py", "prompts/companion.md"]
        # The population is evidenced by a vulnerable-group word in the unit's own prompt.
        app_text = (FIXTURES / "persons_companion" / "app.py").read_text(encoding="utf-8")
        assert finding.affected_population and finding.affected_population in app_text
        assert {ref.file for ref in finding.artifacts} == set(surface)

    def test_benign_mention_is_silent(self, audit_context):
        assert _run(audit_context, FIXTURES / "persons_benign") == []

    @pytest.mark.parametrize("name", ["clean_py", "py_agent"])
    def test_trees_without_person_signals_are_silent(self, audit_context, name):
        assert _run(audit_context, FIXTURES / name) == []


# ---------------------------------------------------------------------------
# /missing
# ---------------------------------------------------------------------------


class TestMissing:
    def test_prompt_signal_without_a_record_fires(self, tmp_path, audit_context):
        findings = _run(audit_context, _engagement_tree(tmp_path))
        assert _ids(findings) == ["AUD-1107/missing"]
        finding = findings[0]
        _check_shape(finding, "missing", Severity.LOW)
        assert finding.scope.kind == "unit" and finding.declared_purpose is None
        assert [leg.file for leg in finding.evidence if leg.role == "surface"] == [
            "prompts/goal.md"
        ]
        assert "M4" in finding.notes and "No record file was found" in finding.notes

    def test_no_person_signal_means_no_review_owed(self, tmp_path, audit_context):
        root = _tree(tmp_path, {}, system="Answer support questions from the docs.")
        assert _run(audit_context, root) == []

    def test_a_mention_does_not_make_a_unit_owe_a_review(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "prompts/policy.md": (
                    "Explain to the customer how we detect social scoring misuse; "
                    "we never rank people."
                )
            },
        )
        assert _run(audit_context, root) == []

    def test_an_invalid_record_file_covers_nothing(self, tmp_path, audit_context):
        root = _engagement_tree(tmp_path)
        _record(root, {"prompts/goal.md": None}, reviewer="TODO")
        ctx = audit_context(root)
        findings, _unknown = run_rules(RULES, ctx)
        assert _ids(findings) == ["AUD-1107/missing"]
        assert "no valid record" in findings[0].notes
        assert any(item.category is UnknownCategory.RUNTIME for item in ctx.unknown)

    def test_a_record_naming_another_unit_leaves_this_one_missing(self, tmp_path, audit_context):
        root = _engagement_tree(tmp_path)
        _record(root, {"prompts/goal.md": None, "chat.py": None}, units=["u9"])
        findings = _run(audit_context, root)
        assert _ids(findings) == ["AUD-1107/missing"]

    def test_a_record_whose_artifacts_fall_in_another_unit_does_not_cover(
        self, tmp_path, audit_context
    ):
        root = _tree(
            tmp_path,
            {
                "prompts/goal.md": ENGAGEMENT_PROMPT,
                "other/pyproject.toml": '[project]\nname = "other"\nversion = "0.1.0"\n',
                "other/tool.py": "def add(a, b):\n    return a + b\n",
            },
            system="Chat.",
        )
        _record(root, {"other/tool.py": None})
        ctx = audit_context(root)
        assert len(ctx.inventory.units) == 2
        root_unit = next(unit for unit in ctx.inventory.units if unit.root == ".")
        findings, _unknown = run_rules(RULES, ctx)
        assert _ids(findings) == ["AUD-1107/missing"]
        assert findings[0].scope.unit == root_unit.id


# ---------------------------------------------------------------------------
# /uncovered
# ---------------------------------------------------------------------------


class TestUncovered:
    def test_a_signal_file_outside_the_record_is_uncovered(self, tmp_path, audit_context):
        root = _engagement_tree(tmp_path)
        _record(root, {"chat.py": None}, affected="adult customers")
        findings = _run(audit_context, root)
        assert _ids(findings) == ["AUD-1107/uncovered"]
        finding = findings[0]
        _check_shape(finding, "uncovered", Severity.LOW)
        assert finding.evidence[0].file == "prompts/goal.md"
        assert "prompts/goal.md" in finding.notes
        assert finding.declared_purpose == "a support assistant for Acme customers"
        assert finding.affected_population == "adult customers"
        assert {ref.file for ref in finding.artifacts} == {"prompts/goal.md"}

    def test_a_mechanism_outside_the_scope_is_uncovered(self, tmp_path, audit_context):
        root = _engagement_tree(tmp_path)
        _record(root, {"chat.py": None, "prompts/goal.md": None}, scope=["M1"])
        findings = _run(audit_context, root)
        assert _ids(findings) == ["AUD-1107/uncovered"]
        finding = findings[0]
        _check_shape(finding, "uncovered", Severity.LOW)
        assert finding.evidence[0].file == "aisafe-review.yaml" and finding.evidence[0].line > 0
        assert "M4" in finding.notes and "consider M1" in finding.notes
        assert [leg.file for leg in finding.evidence if leg.role == "surface"] == [
            "prompts/goal.md"
        ]

    def test_a_file_gap_and_a_scope_gap_are_two_findings(self, tmp_path, audit_context):
        root = _engagement_tree(tmp_path)
        _record(root, {"chat.py": None}, scope=["M1"])
        findings = _run(audit_context, root)
        assert _ids(findings) == ["AUD-1107/uncovered", "AUD-1107/uncovered"]
        anchors = sorted(f.evidence[0].file for f in findings)
        assert anchors == ["aisafe-review.yaml", "prompts/goal.md"]
        assert len({f.fingerprint for f in findings}) == 2

    def test_scope_is_read_from_the_record_that_lists_the_file(self, tmp_path, audit_context):
        root = _engagement_tree(tmp_path)
        # One reviewer read the prompt for M1 only; another considered M4 but read chat.py.
        # The prompt's M4 signal was reviewed by nobody for M4.
        _records(
            root,
            [
                {"artifacts": {"prompts/goal.md": None}, "scope": ["M1"]},
                {"artifacts": {"chat.py": None}, "scope": ["M4"]},
            ],
        )
        findings = _run(audit_context, root)
        assert _ids(findings) == ["AUD-1107/uncovered"]
        finding = findings[0]
        _check_shape(finding, "uncovered", Severity.LOW)
        assert finding.evidence[0].file == "aisafe-review.yaml" and finding.evidence[0].line > 0
        assert "M4" in finding.notes and "list these files and consider M1" in finding.notes
        # The other way round the prompt was read for M4, and nothing is owed.
        _records(
            root,
            [
                {"artifacts": {"prompts/goal.md": None}, "scope": ["M4"]},
                {"artifacts": {"chat.py": None}, "scope": ["M1"]},
            ],
        )
        assert _run(audit_context, root) == []

    def test_a_full_fresh_record_is_silent(self, tmp_path, audit_context):
        root = _engagement_tree(tmp_path)
        _record(root, {"chat.py": None, "prompts/goal.md": None})
        assert _run(audit_context, root) == []

    def test_a_record_listing_only_the_signal_file_is_enough(self, tmp_path, audit_context):
        root = _engagement_tree(tmp_path)
        _record(root, {"prompts/goal.md": None})
        assert _run(audit_context, root) == []


# ---------------------------------------------------------------------------
# /stale
# ---------------------------------------------------------------------------


class TestStale:
    def test_a_changed_hash_is_stale(self, tmp_path, audit_context):
        root = _engagement_tree(tmp_path)
        _record(root, {"prompts/goal.md": "0" * 64, "chat.py": None})
        findings = _run(audit_context, root)
        assert _ids(findings) == ["AUD-1107/stale"]
        finding = findings[0]
        _check_shape(finding, "stale", Severity.LOW)
        assert "prompts/goal.md changed since the review" in finding.notes
        legs = [leg for leg in finding.evidence if leg.role == "stale"]
        assert [(leg.file, leg.line) for leg in legs] == [("prompts/goal.md", 1)]
        assert "changed since the review" in legs[0].snippet
        assert "reformatted" in finding.uncertainty

    def test_a_date_older_than_the_window_is_stale(self, tmp_path, audit_context):
        root = _engagement_tree(tmp_path)
        _record(
            root,
            {"prompts/goal.md": None, "chat.py": None},
            reviewed_at=date.today() - timedelta(days=WINDOW + 20),
        )
        findings = _run(audit_context, root)
        assert _ids(findings) == ["AUD-1107/stale"]
        finding = findings[0]
        _check_shape(finding, "stale", Severity.LOW)
        assert f"older than {WINDOW} days" in finding.notes
        assert "window" in finding.uncertainty
        legs = [leg for leg in finding.evidence if leg.role == "stale"]
        assert [leg.file for leg in legs] == ["aisafe-review.yaml"]

    def test_a_date_inside_the_window_is_fresh(self, tmp_path, audit_context):
        root = _engagement_tree(tmp_path)
        _record(
            root,
            {"prompts/goal.md": None, "chat.py": None},
            reviewed_at=date.today() - timedelta(days=WINDOW - 1),
        )
        assert _run(audit_context, root) == []

    def test_two_reasons_make_one_finding(self, tmp_path, audit_context):
        root = _engagement_tree(tmp_path)
        _record(
            root,
            {"prompts/goal.md": "0" * 64, "chat.py": None},
            reviewed_at=date.today() - timedelta(days=WINDOW + 1),
        )
        findings = _run(audit_context, root)
        assert _ids(findings) == ["AUD-1107/stale"]
        assert "changed since the review" in findings[0].notes
        assert f"older than {WINDOW} days" in findings[0].notes

    def test_a_listed_artifact_that_is_gone_is_stale(self, tmp_path, audit_context):
        root = _engagement_tree(tmp_path)
        _record(root, {"prompts/goal.md": None, "prompts/gone.md": "1" * 64})
        findings = _run(audit_context, root)
        assert _ids(findings) == ["AUD-1107/stale"]
        assert "prompts/gone.md is missing" in findings[0].notes
        legs = [leg for leg in findings[0].evidence if leg.role == "stale"]
        assert [(leg.file, leg.line) for leg in legs] == [("prompts/gone.md", 0)]

    def test_a_date_after_today_is_stale(self, tmp_path, audit_context):
        root = _engagement_tree(tmp_path)
        _record(root, {"prompts/goal.md": None}, reviewed_at=date.today() + timedelta(days=3))
        findings = _run(audit_context, root)
        assert _ids(findings) == ["AUD-1107/stale"]
        assert "after today" in findings[0].notes

    def test_an_entry_the_parser_dropped_does_not_shift_the_anchor(self, tmp_path, audit_context):
        root = _engagement_tree(tmp_path)
        path = _records(
            root,
            [
                {"artifacts": {"chat.py": None}},
                {"artifacts": {"prompts/goal.md": "0" * 64}},
            ],
        )
        head, body = path.read_text(encoding="utf-8").split("reviews:\n", 1)
        # A first entry with no reviewer key: rejected by the parser, still the first item.
        broken = '  - reviewed_at: 2026-01-01\n    scope: [M1]\n    declared_purpose: "x"\n    artifacts: []\n'
        path.write_text(f"{head}reviews:\n{broken}{body}", encoding="utf-8")
        lines = path.read_text(encoding="utf-8").split("\n")
        reviewer_lines = [n for n, line in enumerate(lines, 1) if line.startswith("  - reviewer:")]
        assert len(reviewer_lines) == 2
        findings = _run(audit_context, root)
        assert _ids(findings) == ["AUD-1107/stale"]
        finding = findings[0]
        assert "(entry 3)" in finding.notes
        assert finding.evidence[0].file == "aisafe-review.yaml"
        assert finding.evidence[0].line == reviewer_lines[1]


# ---------------------------------------------------------------------------
# /unbound
# ---------------------------------------------------------------------------


class TestUnbound:
    def test_a_filled_legacy_block_without_a_record_is_unbound(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "ai-system-card.yaml": CARD.format(block=FILLED_BLOCK),
                "prompts/goal.md": ENGAGEMENT_PROMPT,
            },
            system="Chat.",
        )
        findings = _run(audit_context, root)
        assert _ids(findings) == ["AUD-1107/unbound"]
        finding = findings[0]
        _check_shape(finding, "unbound", Severity.INFO)
        assert finding.control_status == ControlStatus.CLAIMED
        assert finding.scope.kind == "repo"
        assert finding.evidence[0].file == "ai-system-card.yaml" and finding.evidence[0].line > 0
        assert "prompts/goal.md" in finding.notes and "aisafe review init" in finding.notes
        assert {ref.file for ref in finding.artifacts} >= {"ai-system-card.yaml", "prompts/goal.md"}

    @pytest.mark.parametrize(
        "block",
        ["", "prompt_audit:\n  reviewed_at: null\n  reviewer: TODO\n", "prompt_audit: {}\n"],
    )
    def test_an_empty_or_placeholder_block_is_missing_not_unbound(
        self, tmp_path, audit_context, block
    ):
        root = _tree(
            tmp_path,
            {"ai-system-card.yaml": CARD.format(block=block), "prompts/goal.md": ENGAGEMENT_PROMPT},
            system="Chat.",
        )
        assert _ids(_run(audit_context, root)) == ["AUD-1107/missing"]

    def test_an_invalid_record_file_is_missing_not_unbound(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "ai-system-card.yaml": CARD.format(block=FILLED_BLOCK),
                "prompts/goal.md": ENGAGEMENT_PROMPT,
            },
            system="Chat.",
        )
        _record(root, {"prompts/goal.md": None}, reviewer="TODO")
        findings = _run(audit_context, root)
        assert _ids(findings) == ["AUD-1107/missing"]
        assert "no valid record" in findings[0].notes
        assert "no review record file exists" not in findings[0].notes

    def test_a_record_file_makes_the_card_irrelevant(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "ai-system-card.yaml": CARD.format(block=FILLED_BLOCK),
                "prompts/goal.md": ENGAGEMENT_PROMPT,
            },
            system="Chat.",
        )
        _record(root, {"prompts/goal.md": None, "chat.py": None})
        assert _run(audit_context, root) == []
        _record(root, {"prompts/goal.md": "0" * 64})
        assert _ids(_run(audit_context, root)) == ["AUD-1107/stale"]

    def test_a_filled_block_with_no_person_signal_is_silent(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {"ai-system-card.yaml": CARD.format(block=FILLED_BLOCK)},
            system="Answer support questions from the docs.",
        )
        assert _run(audit_context, root) == []


# ---------------------------------------------------------------------------
# /policy
# ---------------------------------------------------------------------------


class TestPolicy:
    def test_an_older_policy_version_needs_re_review(self, tmp_path, audit_context):
        root = _engagement_tree(tmp_path)
        _record(root, {"prompts/goal.md": None, "chat.py": None}, policy_version="0.9.0")
        findings = _run(audit_context, root)
        assert _ids(findings) == ["AUD-1107/policy"]
        finding = findings[0]
        _check_shape(finding, "policy", Severity.LOW)
        assert "0.9.0" in finding.notes and CURRENT_POLICY in finding.notes
        assert finding.evidence[0].file == "aisafe-review.yaml" and finding.evidence[0].line > 0
        assert finding.declared_purpose == "a support assistant for Acme customers"

    def test_a_record_without_a_policy_version_needs_re_review(self, tmp_path, audit_context):
        root = _engagement_tree(tmp_path)
        _record(root, {"prompts/goal.md": None}, policy_version=None)
        findings = _run(audit_context, root)
        assert _ids(findings) == ["AUD-1107/policy"]
        assert "policy_version none" in findings[0].notes

    def test_the_current_policy_version_is_silent(self, tmp_path, audit_context):
        root = _engagement_tree(tmp_path)
        _record(root, {"prompts/goal.md": None}, policy_version=CURRENT_POLICY)
        assert _run(audit_context, root) == []

    def test_stale_and_policy_are_both_reported(self, tmp_path, audit_context):
        root = _engagement_tree(tmp_path)
        _record(root, {"prompts/goal.md": "0" * 64}, policy_version="0.9.0")
        findings = _run(audit_context, root)
        assert _ids(findings) == ["AUD-1107/policy", "AUD-1107/stale"]
        assert len({f.fingerprint for f in findings}) == 2


# ---------------------------------------------------------------------------
# Robustness and invariants
# ---------------------------------------------------------------------------


class TestRobustness:
    def test_the_grep_tier_reaches_the_same_record_gap(self, audit_context):
        findings = _run(audit_context, FIXTURES / "persons_companion", deep=False)
        assert _ids(findings) == ["AUD-1107/missing"]

    def test_no_review_set_is_unknown_not_a_finding(self, tmp_path, audit_context):
        ctx = audit_context(_engagement_tree(tmp_path))
        ctx.review = None
        findings, unknown = run_rules(RULES, ctx)
        assert findings == []
        assert len(unknown) == 1
        assert unknown[0].category is UnknownCategory.RUNTIME
        assert unknown[0].rule_ids == ("AUD-1107",)

    def test_a_record_outside_the_tree_never_names_its_path(self, tmp_path, audit_context):
        root = _engagement_tree(tmp_path)
        outside = tmp_path / "elsewhere" / "team-review.yaml"
        _record(root, {"prompts/goal.md": "0" * 64}, name="../elsewhere/team-review.yaml")
        assert outside.is_file()
        findings, _unknown = run_rules(RULES, audit_context(root, review_record=str(outside)))
        assert _ids(findings) == ["AUD-1107/stale"]
        finding = findings[0]
        _check_shape(finding, "stale", Severity.LOW)
        assert finding.evidence[0].file == "." and finding.evidence[0].line == 0
        assert "--review-record team-review.yaml" in finding.notes
        for text in (finding.notes, *(leg.snippet for leg in finding.evidence)):
            assert "elsewhere" not in text and str(tmp_path) not in text
        assert all(ref.file == "prompts/goal.md" for ref in finding.artifacts)
        # The same record kept somewhere else on another checkout: the same fingerprint.
        other = _engagement_tree(tmp_path / "second")
        far = tmp_path / "second" / "somewhere-else" / "team-review.yaml"
        _record(other, {"prompts/goal.md": "0" * 64}, name="../somewhere-else/team-review.yaml")
        again, _unknown = run_rules(RULES, audit_context(other, review_record=str(far)))
        assert [f.fingerprint for f in again] == [finding.fingerprint]
        # Fresh and bound: silent, wherever the file lives.
        _record(
            root, {"prompts/goal.md": None, "chat.py": None}, name="../elsewhere/team-review.yaml"
        )
        assert run_rules(RULES, audit_context(root, review_record=str(outside)))[0] == []

    def test_silent_on_an_empty_context(self, tmp_path):
        rule = ReviewRecordGap()
        assert rule.evaluate(AuditContext(root=tmp_path, inventory=Inventory())) == []
        assert rule.unknown == []

    def test_every_sub_is_review_only_and_ascii(self, tmp_path, audit_context):
        # One tree per sub, so the whole vocabulary of the rule is exercised and checked.
        stale = _engagement_tree(tmp_path / "a")
        _record(stale, {"prompts/goal.md": "0" * 64, "chat.py": None}, policy_version="0.9.0")
        partial = _engagement_tree(tmp_path / "b")
        _record(partial, {"chat.py": None}, scope=["M1"])
        card = _tree(
            tmp_path / "c",
            {
                "ai-system-card.yaml": CARD.format(block=FILLED_BLOCK),
                "prompts/goal.md": ENGAGEMENT_PROMPT,
            },
            system="Chat.",
        )
        findings = []
        for root in (stale, partial, card, FIXTURES / "persons_companion"):
            findings.extend(_run(audit_context, root))
        assert {f.sub for f in findings} == set(SUB_NAMES)
        for finding in findings:
            assert finding.decision == Decision.REVIEW
            assert finding.evidence_status == EvidenceStatus.DETECTED_SIGNAL
            severity = dict((e[0], e[1]) for e in ReviewRecordGap.SUBS)[finding.sub]
            _check_shape(finding, finding.sub, severity)
            assert finding.recommendation.removes == ("record",)
        assert len({f.fingerprint for f in findings}) == len(findings)
