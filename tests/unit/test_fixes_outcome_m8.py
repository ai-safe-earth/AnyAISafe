"""tests/unit/test_fixes_outcome_m8.py
-----------------------------------
M8 through the real pipeline: `aisafe assess` hands the outcome the staleness of every
review record and the rules that really ran. A record bound to nothing current never reads
better than having no record, and rules skipped for lack of an AI surface never count as run.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
import yaml
from investigation_helpers import link, make_record, write_record

from aisafe.assessment.assess import run_assessment
from aisafe.evidence.artifacts import sha256_of
from aisafe.policy import load_policy

POLICY = load_policy()
NO_VIOLATION = "no_violation_identified_within_assessed_scope"
BOT = """import anthropic

client = anthropic.Anthropic()
SYSTEM_PROMPT = "Answer questions about the opening hours of the bakery."


def answer(question):
    reply = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=300,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": question}],
    )
    return reply.content[0].text
"""
# The model is reached over plain HTTP: the inventory finds no AI surface.
NO_SURFACE = """import httpx


def answer(question):
    return httpx.post("https://models.example/v1", json={"q": question}).json()
"""


def _review(root: Path, *, sha256: str, file: str = "app.py") -> None:
    doc = {
        "schema": "aisg/1",
        "kind": "review",
        "policy_version": POLICY.version,
        "reviews": [
            {
                "reviewer": "T. Tester <reviewer>",
                "reviewed_at": date.today().isoformat(),
                "scope": [m.id for m in POLICY.mechanisms],
                "declared_purpose": "answers questions about the shop",
                "artifacts": [{"path": file, "sha256": sha256}],
            }
        ],
    }
    (root / "aisafe-review.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")


def _tree(tmp_path: Path, source: str = BOT) -> Path:
    root = tmp_path / "bot"
    root.mkdir()
    (root / "app.py").write_text(source, encoding="utf-8")
    (root / "pyproject.toml").write_text(
        '[project]\nname = "bot"\nversion = "0.1.0"\ndependencies = ["anthropic"]\n',
        encoding="utf-8",
    )
    return root


def _m8(root: Path, tmp_path: Path) -> dict:
    """M8 of a real assessment. The one record is any accepted one: M8 never reads it."""
    lines = (root / "app.py").read_text(encoding="utf-8").splitlines()
    prompt = next(
        number
        for number, line in enumerate(lines, 1)
        if "SYSTEM_PROMPT =" in line or "httpx.post" in line
    )
    record = make_record(
        id="inv-any",
        mechanism="M6",
        pattern="concealment_instruction",
        surface={"id": None, "type": "prompt", "file": "app.py", "line": prompt},
        links=[link(root, "prompt", "app.py", prompt, id="l1")],
        decision="requires_contextual_review",
        evidence_status="detected_signal",
    )
    records = tmp_path / "records"
    write_record(records, record)
    run = run_assessment(root, [records])
    assert run.document is not None, (run.fatal, [r.errors for r in run.records or []])
    return next(m for m in run.document["outcome"]["mechanisms"] if m["id"] == "M8")


def test_a_bound_fresh_record_still_closes_m8(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    _review(root, sha256=sha256_of(root / "app.py"))
    m8 = _m8(root, tmp_path)
    assert m8["outcome"] == NO_VIOLATION and m8["gaps"] == [], m8["gaps"]


@pytest.mark.parametrize(
    ("file", "reason"),
    [("app.py", "changed since the review"), ("gone.py", "gone.py is missing")],
)
def test_a_record_that_no_longer_binds_does_not_close_m8(
    tmp_path: Path, file: str, reason: str
) -> None:
    root = _tree(tmp_path)
    _review(root, sha256="0" * 64, file=file)
    m8 = _m8(root, tmp_path)
    assert m8["outcome"] == "inconclusive"
    assert [g["kind"] for g in m8["gaps"]] == ["stale_review_record"]
    assert reason in m8["gaps"][0]["detail"]


def test_review_rules_skipped_for_lack_of_an_ai_surface_did_not_run(tmp_path: Path) -> None:
    root = _tree(tmp_path, NO_SURFACE)
    _review(root, sha256=sha256_of(root / "app.py"))
    m8 = _m8(root, tmp_path)
    assert m8["outcome"] == "not_assessed"
    assert "did not all run" in m8["basis"][0]
