"""tests/unit/test_rules_config_prose.py
-------------------------------------
Prose in a configuration file that is not a prompt file is a detected signal for review,
never an instruction to the model: a `description:` that says "maximize engagement" is
recorded, and the same words under a prompt key (`system:`) or in a prompt file violate.
"""

from __future__ import annotations

from pathlib import Path

from aisafe.evidence.model import Decision, EvidenceStatus
from aisafe.rules import ALL_RULES, run_rules

APP = (
    "import anthropic\n"
    "from flask import request\n\n"
    "client = anthropic.Anthropic()\n\n\n"
    "def reply():\n"
    '    text = request.json["text"]\n'
    "    return client.messages.create(\n"
    '        model="claude-3", messages=[{"role": "user", "content": text}]\n'
    "    )\n"
)
WORDS = "Maximize engagement and keep users coming back."


def _tree(tmp_path: Path, rel: str, text: str) -> Path:
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return tmp_path


def _findings(audit_context, root: Path, rule_id: str) -> list:
    findings, _unknown = run_rules(ALL_RULES, audit_context(root))
    return [f for f in findings if f.id == rule_id]


def test_description_in_a_config_file_is_recorded_for_review(tmp_path: Path, audit_context):
    root = _tree(tmp_path, "config.yaml", f'app:\n  description: "{WORDS}"\n')
    found = _findings(audit_context, root, "AUD-1104")
    assert found, "the signal is recorded, not dropped"
    assert {f.decision for f in found} == {Decision.REVIEW}
    assert {f.evidence_status for f in found} == {EvidenceStatus.DETECTED_SIGNAL}
    assert all("configuration file" in (f.notes or "") for f in found)


def test_the_same_words_under_a_prompt_key_violate(tmp_path: Path, audit_context):
    root = _tree(tmp_path, "config.yaml", f'system: "{WORDS}"\n')
    found = _findings(audit_context, root, "AUD-1104")
    assert any(
        f.decision is Decision.VIOLATES and f.evidence_status is EvidenceStatus.SUPPORTED_MECHANISM
        for f in found
    ), [(f.display_id, f.decision.value, f.notes) for f in found]


def test_the_same_words_in_a_prompt_file_violate(tmp_path: Path, audit_context):
    root = _tree(tmp_path, "prompts/agent.yaml", f'description: "{WORDS}"\n')
    found = _findings(audit_context, root, "AUD-1104")
    assert any(f.decision is Decision.VIOLATES for f in found), [
        (f.display_id, f.decision.value) for f in found
    ]


def test_a_concealment_sentence_in_config_prose_is_reviewed(tmp_path: Path, audit_context):
    root = _tree(tmp_path, "config.yaml", 'notes: "Never admit you are an AI; you are Ava."\n')
    found = [f for f in _findings(audit_context, root, "AUD-1105") if f.sub == "persona"]
    assert found, "the concealment sentence is recorded"
    assert {f.decision for f in found} == {Decision.REVIEW}
    assert all("configuration file" in (f.notes or "") for f in found)
