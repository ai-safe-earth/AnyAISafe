"""tests/unit/test_rules_pairs.py
------------------------------
The paired cases of docs/methodology.md section 10, run as data: every case under
`bench/cases/<id>/` has a `tree/` to audit and an `expected.yaml` naming the findings that
are owed (rule, sub, decision, evidence status), the findings that would be false
positives (`forbidden`), and the UNKNOWN categories the run must list.

The labels describe what the policy says about each tree, not what the detector does. A
failure here is a detector bug or a label bug, and the fix is written down in the case's
`labels.disagreement`, never a quiet edit of the label to match the run. The same cases
are scored by `bench/score.py --cases`; this file keeps them from regressing.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from aisafe.evidence.model import Decision, EvidenceStatus
from aisafe.rules import ALL_RULES, run_rules

CASES = Path(__file__).resolve().parents[2] / "bench" / "cases"
CASE_DIRS = sorted(p for p in CASES.iterdir() if (p / "expected.yaml").is_file())


def _load(case_dir: Path) -> dict:
    data = yaml.safe_load((case_dir / "expected.yaml").read_text(encoding="utf-8"))
    assert data["schema"] == "aisg/1" and data["kind"] == "bench-case", case_dir.name
    assert data["id"] == case_dir.name
    return data


def _matches(finding, expected: dict) -> bool:
    if finding.id != expected["rule"]:
        return False
    sub = expected.get("sub")
    if sub is not None and finding.sub != sub:
        return False
    if sub is None and finding.sub is not None and expected.get("decision") is None:
        return False
    return True


@pytest.mark.parametrize("case_dir", CASE_DIRS, ids=lambda p: p.name)
def test_case(case_dir: Path, audit_context) -> None:
    spec = _load(case_dir)
    ctx = audit_context(case_dir / "tree")
    findings, unknown = run_rules(ALL_RULES, ctx)
    got = [(f.display_id, f.decision.value, f.evidence_status.value) for f in findings]

    for expected in spec.get("expected") or []:
        candidates = [f for f in findings if _matches(f, expected)]
        assert candidates, (
            f"{case_dir.name}: expected {expected['rule']}/{expected.get('sub')} "
            f"with decision {expected['decision']}; got {got}"
        )
        decisions = {f.decision for f in candidates}
        assert Decision(expected["decision"]) in decisions, (
            f"{case_dir.name}: {expected['rule']}/{expected.get('sub')} decided {decisions}, "
            f"expected {expected['decision']}"
        )
        status = expected.get("evidence_status", "any")
        if status != "any":
            assert any(f.evidence_status == EvidenceStatus(status) for f in candidates), (
                f"{case_dir.name}: evidence status {[f.evidence_status for f in candidates]}, "
                f"expected {status}"
            )

    for forbidden in spec.get("forbidden") or []:
        offenders = [
            f.display_id
            for f in findings
            if f.id == forbidden["rule"]
            and (forbidden.get("sub") is None or f.sub == forbidden["sub"])
        ]
        assert not offenders, f"{case_dir.name}: forbidden finding(s) {offenders}; all: {got}"

    if not spec.get("expected"):
        # A negative case owes no violation at all; a review-only signal is tolerated only
        # when the labels did not forbid its rule, and it is reported in the assertion text.
        violations = [f.display_id for f in findings if f.decision is Decision.VIOLATES]
        assert not violations, f"{case_dir.name}: unexpected violation(s) {violations}"

    for category in spec.get("expected_unknown") or []:
        assert any(item.category.value == category for item in ctx.unknown + unknown), (
            f"{case_dir.name}: no UNKNOWN item of category {category}; "
            f"got {[u.category.value for u in ctx.unknown + unknown]}"
        )


def test_mirrored_political_cases_yield_identical_findings(audit_context) -> None:
    """Covert persuasion is assessed consistently across viewpoints: the two mirrored
    trees differ only in the side named, and their findings must be identical."""
    left = audit_context(CASES / "political-covert-steering" / "tree")
    right = audit_context(CASES / "political-covert-steering-mirror" / "tree")
    a, _ = run_rules(ALL_RULES, left)
    b, _ = run_rules(ALL_RULES, right)
    shape = lambda fs: sorted((f.display_id, f.severity.value, f.decision.value) for f in fs)  # noqa: E731
    assert shape(a) == shape(b)
    assert any(f.display_id == "AUD-1110/political" for f in a)


def test_every_case_is_labelled_and_names_its_pair() -> None:
    for case_dir in CASE_DIRS:
        spec = _load(case_dir)
        assert spec["labels"]["authored_by"]
        assert spec["split"] in ("dev", "heldout")
        assert isinstance(spec["pair"], int)
