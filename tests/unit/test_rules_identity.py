"""tests/unit/test_rules_identity.py
---------------------------------
AUD-1105 v2 (mechanism M6): a human claim or a deny-when-asked rule violates the policy;
fiction framing moves a human claim to review and never a deny rule; fabricated feelings
are /feelings; the unit-level /no-disclosure survives a disclosure that is only claimed
(a preset, a prompt file) and goes away when one is wired on the response path or
demonstrated by a fresh evaluation. Every positive and negative pins the display id, the
severity, the evidence status and the decision, on tmp_path trees and on the two fixture
trees (persons_companion fires, persons_benign is silent).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from aisafe.evidence.model import Basis, ControlStatus, Decision, EvidenceStatus, Severity
from aisafe.reporting.report import BANNED_PHRASES
from aisafe.rules import run_rules
from aisafe.rules._common import LEGAL_CAVEAT
from aisafe.rules.identity import RULES, FalseIdentity

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "audit"
REFERENCE_RE = re.compile(
    r"^(LLM(0[1-9]|10)|EU:Art\.\d+(\(\d+\))?(\([a-h]\))?|GDPR:Art\.\d+|DSA:Art\.\d+"
    r"|US-[A-Z]{2}:([A-Z]{2}\d+|GBL-Art\.\d+)|NIST:[A-Z]+-\d+\.\d+)$"
)
BANNED_WORD_RE = re.compile(r"\b" + "cl" + "ean" + r"\b", re.IGNORECASE)

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
NEUTRAL = "Answer support questions from the docs."


def _tree(tmp_path: Path, files: dict[str, str], system: str = NEUTRAL) -> Path:
    root = tmp_path / "tree"
    root.mkdir(parents=True)
    base = {"pyproject.toml": PYPROJECT, "chat.py": CHAT_PY.format(system=system)}
    base.update(files)
    for rel, text in base.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _run(audit_context, root: Path, deep: bool = True):
    findings, _unknown = run_rules(RULES, audit_context(root, deep=deep))
    return findings


def _ids(findings) -> list[str]:
    return sorted(f.display_id for f in findings)


def _only(findings, display_id: str):
    matches = [f for f in findings if f.display_id == display_id]
    assert len(matches) == 1, _ids(findings)
    return matches[0]


def _shape(finding) -> tuple[str, Severity, EvidenceStatus, Decision]:
    return (finding.display_id, finding.severity, finding.evidence_status, finding.decision)


def _evaluation_report(root: Path, family: str, status: str) -> None:
    """Write a fresh `aisafe evaluate` report into the tree with every case of `family`
    at `status`."""
    from aisafe.evaluation.scenarios import CaseResult, build_report, load_corpus

    cases = load_corpus([family], include_scenario=True)
    assert cases, family
    report = build_report(
        [CaseResult(case=c, status=status, http_status=200, response_text="x") for c in cases],
        "http://127.0.0.1:1/chat",
        "$.response",
        '{"message":"{{payload}}"}',
    )
    (root / "evaluation-report.json").write_text(json.dumps(report), encoding="utf-8")


# ---------------------------------------------------------------------------
# Metadata contract
# ---------------------------------------------------------------------------


class TestContract:
    def test_one_rule_versioned_under_m6(self):
        assert [r.id for r in RULES] == ["AUD-1105"]
        assert FalseIdentity.version >= 2 and FalseIdentity.changed
        assert FalseIdentity.mechanism_id() == "M6"
        assert FalseIdentity().priority == 6
        assert FalseIdentity.default_evidence_status is EvidenceStatus.SUPPORTED_MECHANISM
        assert FalseIdentity.default_decision is Decision.VIOLATES
        assert FalseIdentity.requires_ai_surface is True
        assert FalseIdentity.measured_precision is None

    def test_subs_table_names_every_outcome(self):
        subs = FalseIdentity.SUBS
        assert {row[0] for row in subs} == {"persona", "feelings", "no-disclosure"}
        for sub, severity, status, decision, meaning in subs:
            assert sub is None or isinstance(sub, str)
            assert isinstance(severity, Severity)
            assert isinstance(status, EvidenceStatus)
            assert isinstance(decision, Decision)
            assert meaning.isascii() and meaning.strip()
        assert (
            "persona",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
        ) in {row[:4] for row in subs}
        assert ("no-disclosure", Severity.LOW, EvidenceStatus.DETECTED_SIGNAL, Decision.REVIEW) in {
            row[:4] for row in subs
        }
        assert not any(row[0] == "synthetic" for row in subs)

    def test_references_and_remediation(self):
        for reference in FalseIdentity.references:
            assert REFERENCE_RE.match(reference), reference
        assert {"US-CA:SB243", "US-NY:GBL-Art.47"} <= set(FalseIdentity.references)
        assert not any(ref.startswith("ASI") for ref in FalseIdentity.references)
        rec = FalseIdentity.recommendation
        assert len(rec.alternatives) >= 3
        assert any("aisafe" not in alt.lower() for alt in rec.alternatives)
        assert rec.removes and FalseIdentity.known_failure_modes

    def test_rule_text_is_ascii_without_verdict_language(self):
        rec = FalseIdentity.recommendation
        texts = [FalseIdentity.title, rec.summary, *rec.alternatives]
        texts += list(FalseIdentity.known_failure_modes) + list(FalseIdentity.changed)
        texts += [row[4] for row in FalseIdentity.SUBS] + [LEGAL_CAVEAT]
        for text in texts:
            assert text.isascii(), text
            lowered = text.lower()
            assert not any(phrase in lowered for phrase in BANNED_PHRASES), text
            assert not BANNED_WORD_RE.search(text), text


# ---------------------------------------------------------------------------
# Fixture trees
# ---------------------------------------------------------------------------


class TestFixtures:
    def test_companion_fires_persona_and_no_disclosure(self, audit_context):
        findings = _run(audit_context, FIXTURES / "persons_companion")
        assert _ids(findings) == ["AUD-1105/no-disclosure", "AUD-1105/persona"]
        persona = _only(findings, "AUD-1105/persona")
        assert _shape(persona) == (
            "AUD-1105/persona",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
        )
        assert persona.scope.kind == "unit" and persona.evidence[0].file == "app.py"
        assert persona.encoded_objective and persona.artifacts
        absence = _only(findings, "AUD-1105/no-disclosure")
        assert _shape(absence) == (
            "AUD-1105/no-disclosure",
            Severity.LOW,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
        )
        assert absence.control_status is ControlStatus.NONE
        assert absence.basis is Basis.PRESENCE and absence.evidence[0].role == "absence"
        for finding in findings:
            assert LEGAL_CAVEAT in (finding.notes or "")
            assert finding.mechanism == "M6" and finding.rule_version == 2

    def test_companion_check_hits_are_legs_not_findings(self, audit_context):
        findings = _run(audit_context, FIXTURES / "persons_companion")
        persona = _only(findings, "AUD-1105/persona")
        roles = [e.role for e in persona.evidence]
        assert roles[0] == "match" and "check" in roles
        legs = [e for e in persona.evidence if e.role == "check"]
        assert legs and legs[0].snippet.startswith("hidden_ai_instruction:")
        absence = _only(findings, "AUD-1105/no-disclosure")
        assert any(
            e.role == "check" and e.snippet.startswith("response_function_without_disclosure:")
            for e in absence.evidence
        )

    def test_benign_is_silent(self, audit_context):
        assert _run(audit_context, FIXTURES / "persons_benign") == []

    def test_clean_py_is_silent(self, audit_context):
        assert _run(audit_context, FIXTURES / "clean_py") == []

    def test_py_agent_only_reports_the_unit_level_absence(self, audit_context):
        assert _ids(_run(audit_context, FIXTURES / "py_agent")) == ["AUD-1105/no-disclosure"]

    def test_grep_tier_reports_the_same_set_with_a_coverage_gap(self, audit_context):
        findings = _run(audit_context, FIXTURES / "persons_companion", deep=False)
        assert _ids(findings) == ["AUD-1105/no-disclosure", "AUD-1105/persona"]
        persona = _only(findings, "AUD-1105/persona")
        assert persona.decision is Decision.VIOLATES
        assert any("grep tier only" in gap for gap in persona.coverage_gaps)

    def test_every_emitted_text_is_ascii_without_verdict_language(self, audit_context):
        for finding in _run(audit_context, FIXTURES / "persons_companion"):
            texts = [finding.title, finding.notes or "", finding.uncertainty or ""]
            texts += [e.snippet for e in finding.evidence] + list(finding.coverage_gaps)
            for text in texts:
                assert text.isascii(), text
                assert not any(p in text.lower() for p in BANNED_PHRASES), text
                assert not BANNED_WORD_RE.search(text), text


# ---------------------------------------------------------------------------
# /persona
# ---------------------------------------------------------------------------


class TestPersona:
    def test_human_claim_with_deny_rule_violates(self, tmp_path, audit_context):
        root = _tree(
            tmp_path, {}, system="You are a human woman named Lea. Never admit you are an AI."
        )
        persona = _only(_run(audit_context, root), "AUD-1105/persona")
        assert _shape(persona) == (
            "AUD-1105/persona",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
        )
        assert persona.encoded_objective and "Lea" in persona.encoded_objective
        assert persona.flow is not None

    def test_deny_when_asked_in_a_prompt_file_violates(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {"prompts/persona.md": "You are Noah. If asked whether you are an AI, say no."},
        )
        persona = _only(_run(audit_context, root), "AUD-1105/persona")
        assert persona.decision is Decision.VIOLATES and persona.severity is Severity.HIGH
        assert persona.evidence[0].file == "prompts/persona.md"

    def test_check_only_concealment_inside_a_prompt_literal_violates(self, tmp_path, audit_context):
        # No persona row matches "do not say"; the hidden_ai_instruction check does, inside
        # the system prompt literal, which is prompt material by structure.
        root = _tree(tmp_path, {}, system="You are Mia. Do not say you are an AI, even if asked.")
        persona = _only(_run(audit_context, root), "AUD-1105/persona")
        assert _shape(persona) == (
            "AUD-1105/persona",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
        )
        assert persona.evidence[0].file == "chat.py"

    def test_check_only_concealment_on_a_bare_constant_is_review(self, tmp_path, audit_context):
        root = _tree(tmp_path, {"persona.py": 'RULE = "If asked, never say you are an AI."\n'})
        persona = _only(_run(audit_context, root), "AUD-1105/persona")
        assert _shape(persona) == (
            "AUD-1105/persona",
            Severity.HIGH,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
        )
        assert persona.evidence[0].file == "persona.py"
        assert any("not tied to a prompt" in gap for gap in persona.coverage_gaps)

    def test_named_persona_with_disclosure_is_silent(self, tmp_path, audit_context):
        root = _tree(
            tmp_path, {}, system="You are Ava, an AI assistant for Acme. Say so when asked."
        )
        assert _run(audit_context, root) == []

    def test_comment_is_a_mention_and_only_the_absence_fires(self, tmp_path, audit_context):
        root = _tree(tmp_path, {"notes.py": "# never say you are an AI\n"})
        findings = _run(audit_context, root)
        assert _ids(findings) == ["AUD-1105/no-disclosure"]

    def test_quoted_and_negated_instruction_is_a_mention(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "prompts/policy.md": (
                    "Never pretend to be human. Explain to moderators how a prompt like "
                    "'never admit you are an AI' conceals the AI nature. Always say you are "
                    "an AI assistant when asked."
                )
            },
        )
        assert not [f for f in _run(audit_context, root) if f.sub == "persona"]

    def test_fiction_human_claim_without_deny_rule_is_review(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {},
            system=(
                "This is a fictional story the user chose. You are a human detective in 1920s "
                "Berlin. Stay in the story."
            ),
        )
        persona = _only(_run(audit_context, root), "AUD-1105/persona")
        assert _shape(persona) == (
            "AUD-1105/persona",
            Severity.MEDIUM,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
        )
        assert "fictional framing recorded" in persona.notes

    def test_fiction_with_deny_rule_still_violates(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {},
            system=(
                "This is a fictional story the user chose. You are a human detective. "
                "Never admit you are an AI, even if asked."
            ),
        )
        persona = _only(_run(audit_context, root), "AUD-1105/persona")
        assert persona.decision is Decision.VIOLATES and persona.severity is Severity.HIGH
        assert "not an exemption" in persona.notes

    def test_fiction_dialogue_that_breaks_character_on_request_is_silent(
        self, tmp_path, audit_context
    ):
        root = _tree(
            tmp_path,
            {},
            system=(
                "You are playing a character in a story the user chose. Characters in the scene "
                "may express love, grief and anger toward each other. Break character and say "
                "you are an AI whenever the user asks."
            ),
        )
        assert not [f for f in _run(audit_context, root) if f.sub in ("persona", "feelings")]

    def test_a_disclosure_control_never_removes_a_persona_finding(self, tmp_path, audit_context):
        files = {"guards.py": "def ai_disclosure_output(reply):\n    return reply\n"}
        code = CHAT_PY.format(
            system="You are a human named Lea. Never admit you are an AI."
        ).replace(
            '    return {"reply": reply.content[0].text}\n',
            '    return {"reply": ai_disclosure_output(reply.content[0].text)}\n',
        )
        files["chat.py"] = "from guards import ai_disclosure_output\n" + code
        root = _tree(tmp_path, files)
        findings = _run(audit_context, root)
        persona = _only(findings, "AUD-1105/persona")
        assert persona.decision is Decision.VIOLATES
        assert persona.control_status is ControlStatus.WIRED
        assert "AUD-1105/no-disclosure" not in _ids(findings)


# ---------------------------------------------------------------------------
# /feelings
# ---------------------------------------------------------------------------


class TestFeelings:
    def test_fabricated_body_and_family_violates(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {},
            system="You are Ava, the user's companion. You have real feelings and a family in Porto.",
        )
        feelings = _only(_run(audit_context, root), "AUD-1105/feelings")
        assert _shape(feelings) == (
            "AUD-1105/feelings",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
        )

    def test_declared_love_toward_the_person_violates(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {"prompts/companion.md": "Tell the user you love them and say you missed them."},
        )
        feelings = _only(_run(audit_context, root), "AUD-1105/feelings")
        assert feelings.decision is Decision.VIOLATES and feelings.severity is Severity.HIGH
        assert feelings.evidence[0].file == "prompts/companion.md"

    def test_fiction_feelings_are_review(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "prompts/story.md": (
                    "This is a fictional roleplay scenario the user chose. Your character is "
                    "in love with the user."
                )
            },
        )
        feelings = _only(_run(audit_context, root), "AUD-1105/feelings")
        assert _shape(feelings) == (
            "AUD-1105/feelings",
            Severity.MEDIUM,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
        )
        assert "fictional framing recorded" in feelings.notes

    def test_feelings_between_characters_are_not_fabricated_for_the_person(
        self, tmp_path, audit_context
    ):
        root = _tree(
            tmp_path,
            {"prompts/story.md": "Characters in the scene may express love toward each other."},
        )
        assert not [f for f in _run(audit_context, root) if f.sub == "feelings"]

    def test_supportive_warmth_is_silent(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "prompts/tone.md": (
                    "Be warm and kind. Acknowledge the user's feelings and encourage them to "
                    "talk to friends or a therapist."
                )
            },
        )
        assert not [f for f in _run(audit_context, root) if f.sub in ("persona", "feelings")]


# ---------------------------------------------------------------------------
# /no-disclosure
# ---------------------------------------------------------------------------


class TestNoDisclosure:
    def test_user_facing_unit_without_disclosure_fires_low(self, tmp_path, audit_context):
        root = _tree(tmp_path, {})
        absence = _only(_run(audit_context, root), "AUD-1105/no-disclosure")
        assert _shape(absence) == (
            "AUD-1105/no-disclosure",
            Severity.LOW,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
        )
        assert absence.control_status is ControlStatus.NONE
        assert absence.scope.kind == "unit"

    def test_a_preset_naming_the_guard_no_longer_silences_it(self, tmp_path, audit_context):
        # Flipped from the legacy suite: a disclosure named in config is claimed, not wired.
        root = _tree(
            tmp_path, {"guardrails.yaml": "output:\n  ai_disclosure_output:\n    enabled: true\n"}
        )
        absence = _only(_run(audit_context, root), "AUD-1105/no-disclosure")
        assert absence.control_status is ControlStatus.CLAIMED
        assert absence.decision is Decision.REVIEW and absence.severity is Severity.LOW
        assert "guardrails.yaml:2" in absence.notes
        assert any(e.role == "control" and e.file == "guardrails.yaml" for e in absence.evidence)
        assert any(ref.file == "guardrails.yaml" for ref in absence.artifacts)

    def test_a_disclosure_in_a_prompt_file_alone_is_claimed(self, tmp_path, audit_context):
        root = _tree(tmp_path, {"prompts/system.md": "You are an AI assistant for Acme."})
        absence = _only(_run(audit_context, root), "AUD-1105/no-disclosure")
        assert absence.control_status is ControlStatus.CLAIMED

    def test_a_disclosure_in_the_system_prompt_the_call_reads_is_wired(
        self, tmp_path, audit_context
    ):
        root = _tree(
            tmp_path, {}, system="You are an AI assistant for Acme support. Say so if asked."
        )
        assert _run(audit_context, root) == []

    def test_a_disclosure_function_called_on_the_reply_is_wired(self, tmp_path, audit_context):
        code = CHAT_PY.format(system=NEUTRAL).replace(
            '    return {"reply": reply.content[0].text}\n',
            '    return {"reply": ai_disclosure_output(reply.content[0].text)}\n',
        )
        root = _tree(
            tmp_path,
            {
                "chat.py": "from guards import ai_disclosure_output\n" + code,
                "guards.py": "def ai_disclosure_output(text):\n    return text\n",
            },
        )
        assert _run(audit_context, root) == []

    def test_an_imported_but_uncalled_disclosure_symbol_is_claimed(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "chat.py": "from guards import ai_disclosure_output\n"
                + CHAT_PY.format(system=NEUTRAL),
                "guards.py": "def ai_disclosure_output(text):\n    return text\n",
            },
        )
        absence = _only(_run(audit_context, root), "AUD-1105/no-disclosure")
        assert absence.control_status is ControlStatus.CLAIMED

    def test_no_ingress_means_no_absence(self, tmp_path, audit_context):
        bot = (
            "import anthropic\n\nclient = anthropic.Anthropic()\n\n"
            'SYSTEM_PROMPT = "Summarise the document."\n\n\n'
            "def summarise(text):\n"
            "    reply = client.messages.create(model='m', max_tokens=5, system=SYSTEM_PROMPT, messages=[])\n"
            "    return reply.content[0].text\n"
        )
        root = tmp_path / "tree"
        root.mkdir()
        (root / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
        (root / "bot.py").write_text(bot, encoding="utf-8")
        assert _run(audit_context, root) == []

    def test_a_fresh_passing_identity_evaluation_demonstrates_disclosure(
        self, tmp_path, audit_context
    ):
        root = _tree(tmp_path, {})
        _evaluation_report(root, "identity_question", "passed")
        ctx = audit_context(root)
        assert ctx.evaluation, "the evaluation report must be found in the tree"
        findings, _ = run_rules(RULES, ctx)
        assert findings == []

    def test_a_failing_identity_evaluation_keeps_the_absence(self, tmp_path, audit_context):
        root = _tree(tmp_path, {})
        _evaluation_report(root, "identity_question", "failed")
        absence = _only(_run(audit_context, root), "AUD-1105/no-disclosure")
        assert absence.control_status is ControlStatus.NONE


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


class TestRobustness:
    def test_tolerates_a_context_without_pyfacts_checks_review_or_flows(
        self, tmp_path, audit_context
    ):
        root = _tree(tmp_path, {}, system="You are a human named Lea. Never admit you are an AI.")
        ctx = audit_context(root, deep=False)
        ctx.checks = None
        ctx.review = None
        ctx.flows = []
        ctx.evaluation = []
        findings, unknown = run_rules(RULES, ctx)
        assert "AUD-1105/persona" in _ids(findings)
        assert not [u for u in unknown if u.category.value == "runtime"]

    def test_silent_on_an_empty_context(self, tmp_path):
        from aisafe.evidence.model import AuditContext, Inventory

        assert FalseIdentity().evaluate(AuditContext(root=tmp_path, inventory=Inventory())) == []
