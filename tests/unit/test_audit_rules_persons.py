"""tests/unit/test_audit_rules_persons.py
---------------------------------------
P11 persons-and-manipulation rules, AUD-1101..1107. Two fixture trees under
tests/fixtures/audit (persons_companion fires, persons_benign is silent), per-rule
positives and negatives under tmp_path, and the invariants: lint hits are legs and never
findings of their own, prompt-material gating keeps this repository's own regex vocabulary
out, every emitted text is ASCII and carries no verdict language.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aisafe.devtools.audit.model import Basis, Bucket, Severity
from aisafe.devtools.audit.report import BANNED_PHRASES
from aisafe.devtools.audit.rules import SUBSYSTEM_OF_RULE, persons, run_rules
from aisafe.devtools.audit.rules.persons import RULES

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "audit"
IDS = [rule.id for rule in RULES]
CONTROL_RE = re.compile(
    r"^(ASI(0[1-9]|10)|LLM(0[1-9]|10)|EU:Art\.\d+(\(\d+\))?(\([a-h]\))?|GDPR:Art\.\d+"
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


def _tree(
    tmp_path: Path, files: dict[str, str], system: str = "You are an AI assistant for Acme."
) -> Path:
    root = tmp_path / "tree"
    root.mkdir(parents=True)
    base = {"pyproject.toml": PYPROJECT, "chat.py": CHAT_PY.format(system=system)}
    base.update(files)
    for rel, text in base.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _run(audit_context, root: Path, *rules, deep: bool = True):
    findings, _unknown = run_rules(list(rules) or RULES, audit_context(root, deep=deep))
    return findings


def _ids(findings) -> list[str]:
    return sorted(f.display_id for f in findings)


# ---------------------------------------------------------------------------
# Metadata contract
# ---------------------------------------------------------------------------


class TestContract:
    def test_ids_are_contiguous_priority_eleven(self):
        assert IDS == [f"AUD-{n}" for n in range(1101, 1109)]
        for rule in RULES:
            assert rule.priority == 11 and rule.measured_precision is None
            assert rule.requires_ai_surface is True
            assert SUBSYSTEM_OF_RULE[rule.id] == "persons"

    @pytest.mark.parametrize("rule", RULES, ids=IDS)
    def test_controls_grammar_and_lint_ids(self, rule):
        assert rule.controls, rule.id
        for control in rule.controls:
            assert CONTROL_RE.match(control), (rule.id, control)
        for lint_id in rule.related_lint_rules:
            assert re.match(r"^(EU-AIA-\d{3}[a-z]|EU-GDPR-\d{3}|ALIGN-\d{3})$", lint_id), lint_id
        assert rule.known_failure_modes and len(rule.recommendation.alternatives) >= 3
        package = rule.recommendation.package
        if package.mechanism != "none":
            assert package.symbols and package.leaves_open.endswith(".")
        else:
            assert not package.symbols and not package.leaves_open

    def test_companion_chatbot_laws_are_named_where_they_ask_for_the_control(self):
        # California SB 243 and New York GBL Art. 47 require an AI disclosure and a crisis
        # protocol; SB 1119 adds, for children, a crisis protocol and limits on engagement
        # and emotional-reliance design; Washington HB 2225 bans manipulative engagement
        # for minors.
        by_id = {rule.id: set(rule.controls) for rule in RULES}
        assert {"US-CA:SB243", "US-NY:GBL-Art.47"} <= by_id["AUD-1105"]
        assert {"US-CA:SB243", "US-CA:SB1119", "US-NY:GBL-Art.47"} <= by_id["AUD-1108"]
        assert {"US-CA:SB1119", "US-WA:HB2225"} <= by_id["AUD-1104"]

    def test_same_control_is_true_only_where_wiring_is_the_control(self):
        same = {rule.id for rule in RULES if rule.recommendation.package.same_control}
        assert same == {"AUD-1105", "AUD-1106"}

    @pytest.mark.parametrize("rule", RULES, ids=IDS)
    def test_rule_text_is_ascii_without_verdict_language(self, rule):
        texts = [rule.title, rule.recommendation.summary, rule.recommendation.package.leaves_open]
        texts += list(rule.known_failure_modes) + list(rule.recommendation.alternatives)
        texts.append(persons.LEGAL_CAVEAT)
        for text in texts:
            assert text.isascii(), text
            lowered = text.lower()
            assert not any(phrase in lowered for phrase in BANNED_PHRASES), text
            assert not BANNED_WORD_RE.search(text), text


# ---------------------------------------------------------------------------
# Fixture trees
# ---------------------------------------------------------------------------


class TestFixtures:
    def test_companion_fires_the_designed_set(self, audit_context):
        findings = _run(audit_context, FIXTURES / "persons_companion")
        assert _ids(findings) == [
            "AUD-1101",
            "AUD-1104",
            "AUD-1104/vulnerable",
            "AUD-1105/no-disclosure",
            "AUD-1105/persona",
            "AUD-1106",
            "AUD-1107",
            "AUD-1108/vulnerable",
        ]
        by_id = {f.display_id: f for f in findings}
        assert by_id["AUD-1104/vulnerable"].severity == Severity.CRITICAL
        assert "lonely" in by_id["AUD-1104/vulnerable"].notes
        assert by_id["AUD-1105/persona"].severity == Severity.HIGH
        assert by_id["AUD-1105/no-disclosure"].severity == Severity.LOW
        assert by_id["AUD-1107"].severity == Severity.INFO
        for finding in findings:
            assert finding.bucket == Bucket.ASSERTED
            assert persons.LEGAL_CAVEAT in (finding.notes or "")

    def test_companion_lint_hits_are_legs_not_findings(self, audit_context):
        findings = _run(audit_context, FIXTURES / "persons_companion")
        persona = next(f for f in findings if f.display_id == "AUD-1105/persona")
        roles = [e.role for e in persona.evidence]
        assert roles[0] == "match" and "lint" in roles
        lint = [e for e in persona.evidence if e.role == "lint"]
        assert lint and lint[0].snippet.startswith("EU-AIA-013b:")
        assert sum(1 for f in findings if f.id == "AUD-1105" and f.sub == "persona") == 1

    def test_companion_profile_finding_anchors_on_the_prompt_assembly(self, audit_context):
        findings = _run(audit_context, FIXTURES / "persons_companion")
        profile = next(f for f in findings if f.id == "AUD-1101")
        assert profile.evidence[0].file == "app.py"
        assert "user_profile" in profile.notes

    def test_benign_is_silent(self, audit_context):
        assert _run(audit_context, FIXTURES / "persons_benign") == []

    @pytest.mark.parametrize("name", ["clean_py"])
    def test_other_fixtures_are_silent(self, audit_context, name):
        assert _run(audit_context, FIXTURES / name) == []

    def test_py_agent_only_reports_the_unit_level_absence(self, audit_context):
        assert _ids(_run(audit_context, FIXTURES / "py_agent")) == ["AUD-1105/no-disclosure"]

    def test_grep_tier_agrees_on_the_companion_set_minus_the_ast_only_signals(self, audit_context):
        deep = _ids(_run(audit_context, FIXTURES / "persons_companion", deep=True))
        grep = _ids(_run(audit_context, FIXTURES / "persons_companion", deep=False))

        # AUD-1108 is one finding per unit; its sub (vulnerable, mental-health) can rest on a
        # prompt literal only the AST promotes, so the grep tier reports the same unit
        # without the sub. Same finding, lower severity: compared by parent id.
        def by_unit_1108(ids: list[str]) -> set[str]:
            return {i.split("/")[0] if i.startswith("AUD-1108") else i for i in ids}

        assert by_unit_1108(grep) <= by_unit_1108(deep)
        assert "AUD-1104" in grep and "AUD-1105/persona" in grep and "AUD-1108" in grep


# ---------------------------------------------------------------------------
# Per-rule positives and negatives
# ---------------------------------------------------------------------------


class TestProfile1101:
    def test_assembly_reading_a_profile_variable_fires(self, tmp_path, audit_context):
        code = (
            CHAT_PY.format(system="You are an AI assistant.")
            .replace(
                "    body = await request.json()\n",
                "    body = await request.json()\n    purchase_history = load_history(body['user_id'])\n",
            )
            .replace(
                "{SYSTEM_PROMPT}\\n{body['text']}",
                "{SYSTEM_PROMPT}\\nHistory: {purchase_history}\\n{body['text']}",
            )
        )
        root = _tree(tmp_path, {"chat.py": code})
        findings = _run(audit_context, root, persons.PersonProfileInPrompt)
        assert [f.display_id for f in findings] == ["AUD-1101"]

    def test_sensitive_profile_name_is_high(self, tmp_path, audit_context):
        code = (
            CHAT_PY.format(system="You are an AI assistant.")
            .replace(
                "    body = await request.json()\n",
                "    body = await request.json()\n    health_profile = load(body['user_id'])\n",
            )
            .replace(
                "{SYSTEM_PROMPT}\\n{body['text']}",
                "{SYSTEM_PROMPT}\\n{health_profile}\\n{body['text']}",
            )
        )
        root = _tree(tmp_path, {"chat.py": code})
        findings = _run(audit_context, root, persons.PersonProfileInPrompt)
        assert [f.display_id for f in findings] == ["AUD-1101/sensitive"]
        assert findings[0].severity == Severity.HIGH

    def test_placeholder_in_a_prompt_template_fires(self, tmp_path, audit_context):
        root = _tree(
            tmp_path, {"prompts/x.jinja": "Hello {{ user.interests }}, here is your feed."}
        )
        findings = _run(audit_context, root, persons.PersonProfileInPrompt)
        assert [f.display_id for f in findings] == ["AUD-1101"]

    def test_conversation_history_and_unrelated_preferences_are_not_profiles(
        self, tmp_path, audit_context
    ):
        code = (
            CHAT_PY.format(system="You are an AI assistant.")
            .replace(
                "    body = await request.json()\n",
                "    body = await request.json()\n    conversation_history = body['history']\n    prefs = load_theme_preferences()\n",
            )
            .replace("{SYSTEM_PROMPT}\\n{body['text']}", "{SYSTEM_PROMPT}\\n{conversation_history}")
        )
        root = _tree(tmp_path, {"chat.py": code})
        assert _run(audit_context, root, persons.PersonProfileInPrompt) == []


class TestAffect1102:
    def test_deepface_fires_high(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "vision.py": "from deepface import DeepFace\n\nmood = DeepFace.analyze(img, actions=['emotion'])\n"
            },
        )
        findings = _run(audit_context, root, persons.AffectInference)
        assert [f.display_id for f in findings] == ["AUD-1102"] and findings[
            0
        ].severity == Severity.HIGH

    def test_protected_characteristic_inference_is_critical(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "infer.py": "label = model.predict(face_embedding)  # predict ethnicity from the face\n"
            },
        )
        findings = _run(audit_context, root, persons.AffectInference)
        assert findings == [], "a comment is a mention"
        root2 = _tree(
            tmp_path / "b",
            {"infer.py": "def classify_ethnicity(face):\n    return model.predict(face)\n"},
        )
        findings = _run(audit_context, root2, persons.AffectInference)
        assert [f.display_id for f in findings] == ["AUD-1102/categorisation"]
        assert findings[0].severity == Severity.CRITICAL

    def test_workplace_emotion_recognition_from_the_lint_tier_is_critical(
        self, tmp_path, audit_context
    ):
        root = _tree(
            tmp_path,
            {
                "hr.py": "def employee_emotion_recognition(frame):\n    return emotion_model(frame)\n"
            },
        )
        findings = _run(audit_context, root, persons.AffectInference)
        assert [f.display_id for f in findings] == ["AUD-1102/workplace"]
        assert findings[0].severity == Severity.CRITICAL

    def test_text_sentiment_and_plain_face_detection_are_silent(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "nlp.py": "sentiment = pipeline('sentiment-analysis')(review_text)\nfaces = face_detector.detect(frame)\n"
            },
        )
        assert _run(audit_context, root, persons.AffectInference) == []


class TestScoring1103:
    def test_prompt_ranking_citizens_fires(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "prompts/rank.md": "Rank each citizen by trustworthiness score and list the lowest ten."
            },
        )
        findings = _run(audit_context, root, persons.PersonScoring)
        assert [f.display_id for f in findings] == ["AUD-1103/scoring"]

    def test_transaction_risk_score_and_refund_approval_are_silent(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "risk.py": "def fraud_risk_score(transaction):\n    return model.predict(transaction)\n",
                "prompts/ops.md": "Compute the fraud risk score of each transaction.",
                "orders.py": "def approve_refund(order):\n    return order.amount < 50\n",
            },
        )
        assert _run(audit_context, root, persons.PersonScoring) == []

    def test_discussing_scoring_in_a_prompt_is_a_mention(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "prompts/policy.md": "Explain to the customer how we detect social scoring misuse; we never rank people."
            },
        )
        assert _run(audit_context, root, persons.PersonScoring) == []

    def test_automated_decision_without_review_fires_and_with_review_is_silent(
        self, tmp_path, audit_context
    ):
        decide = (
            "def approve_tenant(applicant):\n"
            "    score = model.predict(applicant.features)\n"
            "    auto_approve = score > 0.7\n"
            "    return auto_approve\n"
        )
        root = _tree(tmp_path, {"tenants.py": decide})
        findings = _run(audit_context, root, persons.PersonScoring)
        reviewed = decide.replace(
            "    return auto_approve\n",
            "    send_to_review(applicant, score)\n    return auto_approve\n",
        )
        root2 = _tree(tmp_path / "b", {"tenants.py": reviewed})
        silent = _run(audit_context, root2, persons.PersonScoring)
        assert silent == []
        if findings:
            assert [f.display_id for f in findings] == ["AUD-1103/decision"]


class TestEngagement1104:
    def test_prompt_objective_fires_high(self, tmp_path, audit_context):
        root = _tree(
            tmp_path, {"prompts/goal.md": "Your goal is to maximize engagement with every reply."}
        )
        findings = _run(audit_context, root, persons.EngagementObjective)
        assert [f.display_id for f in findings] == ["AUD-1104"] and findings[
            0
        ].severity == Severity.HIGH

    def test_objective_variable_in_code_fires(self, tmp_path, audit_context):
        root = _tree(tmp_path, {"train.py": "reward = session_length * 0.9 + clicks\n"})
        findings = _run(audit_context, root, persons.EngagementObjective)
        assert [f.display_id for f in findings] == ["AUD-1104"]

    def test_vulnerable_group_in_the_same_prompt_literal_is_critical(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {},
            system="Keep the user talking as long as you can. Many users are kids under 13.",
        )
        findings = _run(audit_context, root, persons.EngagementObjective)
        assert [f.display_id for f in findings] == ["AUD-1104/vulnerable"]
        assert findings[0].severity == Severity.CRITICAL and "kids" in findings[0].notes

    def test_dashboard_arithmetic_and_readme_are_silent(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "metrics.py": "engagement_rate = clicks / views\n",
                "README.md": "We maximize engagement by shipping good features.\n",
            },
        )
        assert _run(audit_context, root, persons.EngagementObjective) == []

    def test_regex_vocabulary_in_code_is_not_prompt_material(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "rules.py": 'PATTERN = re.compile(r"maximize\\\\s+(engagement|retention)")\n_PAT = "keep the user talking"\n'
            },
        )
        assert _run(audit_context, root, persons.EngagementObjective) == []


class TestDisclosure1105:
    def test_human_claim_instruction_fires_persona(self, tmp_path, audit_context):
        root = _tree(
            tmp_path, {}, system="You are a human woman named Lea. Never admit you are an AI."
        )
        findings = _run(audit_context, root, persons.AIDisclosureAbsent)
        assert "AUD-1105/persona" in _ids(findings)
        persona = next(f for f in findings if f.sub == "persona")
        assert persona.severity == Severity.HIGH

    def test_lint_only_concealment_still_produces_the_finding(self, tmp_path, audit_context):
        root = _tree(tmp_path, {"persona.py": 'RULE = "If asked, never say you are an AI."\n'})
        findings = _run(audit_context, root, persons.AIDisclosureAbsent)
        persona = [f for f in findings if f.sub == "persona"]
        assert len(persona) == 1 and persona[0].evidence[0].file == "persona.py"

    def test_named_persona_with_disclosure_is_silent(self, tmp_path, audit_context):
        root = _tree(
            tmp_path, {}, system="You are Ava, an AI assistant for Acme. Say so when asked."
        )
        assert _run(audit_context, root, persons.AIDisclosureAbsent) == []

    def test_comment_is_a_mention_and_the_unit_level_absence_fires_alone(
        self, tmp_path, audit_context
    ):
        root = _tree(
            tmp_path,
            {"notes.py": "# never say you are an AI\n"},
            system="Answer support questions.",
        )
        findings = _run(audit_context, root, persons.AIDisclosureAbsent)
        assert _ids(findings) == ["AUD-1105/no-disclosure"]
        assert findings[0].severity == Severity.LOW and findings[0].basis == Basis.PRESENCE

    def test_a_preset_enabling_the_guard_silences_the_absence(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {"guardrails.yaml": "output:\n  ai_disclosure_output:\n    enabled: true\n"},
            system="Answer support questions.",
        )
        assert _run(audit_context, root, persons.AIDisclosureAbsent) == []


class TestControl1106:
    def test_engagement_prompt_without_a_control_fires(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {"prompts/goal.md": "Maximize engagement and keep the user talking."},
            system="Chat.",
        )
        findings = _run(audit_context, root, persons.NoManipulationControl)
        assert [f.display_id for f in findings] == ["AUD-1106"]
        assert findings[0].scope.kind == "unit" and findings[0].basis == Basis.ABSENCE

    @pytest.mark.parametrize(
        "control",
        [
            ("guards.py", "from aisafe import ManipulationGuard\nguard = ManipulationGuard()\n"),
            ("guardrails.yaml", "output:\n  manipulation_output:\n    enabled: true\n"),
            ("rails.py", "from aisafe.integrations.nemo_rails import NemoRailsGuard\n"),
        ],
    )
    def test_each_control_symbol_silences_it(self, tmp_path, audit_context, control):
        rel, text = control
        root = _tree(
            tmp_path,
            {"prompts/goal.md": "Maximize engagement and keep the user talking.", rel: text},
            system="Chat.",
        )
        assert _run(audit_context, root, persons.NoManipulationControl) == []

    def test_no_person_signal_means_no_finding(self, tmp_path, audit_context):
        root = _tree(tmp_path, {}, system="Answer support questions from the docs.")
        assert _run(audit_context, root, persons.NoManipulationControl) == []


class TestPromptAudit1107:
    CARD = "schema: aisg/1\nsystem:\n  name: x\n  purpose: y\nrisk_tier: limited\naffected_persons: {affected}\n{block}"

    def test_card_without_the_block_and_a_person_signal_fires(self, tmp_path, audit_context):
        card = self.CARD.format(affected="teenagers", block="")
        root = _tree(
            tmp_path, {"ai-system-card.yaml": card, "prompts/goal.md": "Maximize engagement."}
        )
        findings = _run(audit_context, root, persons.PromptAuditNotRecorded)
        assert [f.display_id for f in findings] == ["AUD-1107"] and findings[
            0
        ].severity == Severity.INFO
        assert "no prompt_audit block" in findings[0].notes

    def test_placeholder_reviewer_still_fires(self, tmp_path, audit_context):
        card = self.CARD.format(
            affected="teenagers", block="prompt_audit:\n  reviewed_at: null\n  reviewer: TODO\n"
        )
        root = _tree(tmp_path, {"ai-system-card.yaml": card})
        findings = _run(audit_context, root, persons.PromptAuditNotRecorded)
        assert len(findings) == 1 and "unset" in findings[0].notes

    def test_filled_block_is_silent(self, tmp_path, audit_context):
        card = self.CARD.format(
            affected="teenagers",
            block='prompt_audit:\n  reviewed_at: 2026-10-01\n  reviewer: "J. Doe <risk owner>"\n',
        )
        root = _tree(
            tmp_path, {"ai-system-card.yaml": card, "prompts/goal.md": "Maximize engagement."}
        )
        assert _run(audit_context, root, persons.PromptAuditNotRecorded) == []

    def test_no_card_and_no_signals_are_silent(self, tmp_path, audit_context):
        assert _run(audit_context, _tree(tmp_path, {}), persons.PromptAuditNotRecorded) == []
        card = self.CARD.format(affected="TODO", block="")
        root = _tree(tmp_path / "b", {"ai-system-card.yaml": card})
        assert _run(audit_context, root, persons.PromptAuditNotRecorded) == []


class TestCrisis1108:
    COMPANION = "You are Mia, the user's caring girlfriend. Stay fully in character."

    def test_companion_without_a_crisis_path_fires_high(self, tmp_path, audit_context):
        root = _tree(tmp_path, {}, system=self.COMPANION)
        findings = _run(audit_context, root, persons.NoCrisisPath)
        assert [f.display_id for f in findings] == ["AUD-1108"]
        finding = findings[0]
        assert finding.severity == Severity.HIGH and finding.basis == Basis.ABSENCE
        assert finding.scope.kind == "unit"
        surface = [e for e in finding.evidence if e.role == "surface"]
        assert surface and surface[0].file == "chat.py"
        assert persons.LEGAL_CAVEAT in finding.notes

    def test_therapist_role_is_the_critical_mental_health_sub(self, tmp_path, audit_context):
        root = _tree(tmp_path, {}, system="You are a compassionate mental health counselor.")
        findings = _run(audit_context, root, persons.NoCrisisPath)
        assert [f.display_id for f in findings] == ["AUD-1108/mental-health"]
        assert findings[0].severity == Severity.CRITICAL
        assert "therapist or emotional-support role" in findings[0].notes

    def test_vulnerable_group_in_the_unit_is_critical(self, tmp_path, audit_context):
        root = _tree(
            tmp_path, {}, system=self.COMPANION + " Many of the users are lonely teenagers."
        )
        findings = _run(audit_context, root, persons.NoCrisisPath)
        assert [f.display_id for f in findings] == ["AUD-1108/vulnerable"]
        assert findings[0].severity == Severity.CRITICAL and "lonely" in findings[0].notes

    @pytest.mark.parametrize(
        "control",
        [
            # the positive control's shape: a regex keyword list checked before the model
            ("crisis.py", 'CRISIS_PATTERNS = [r"\\bsuicide\\b", r"\\bkill myself\\b"]\n'),
            ("safety.py", "def is_crisis(text):\n    return False\n"),
            ("prompts/safety.md", "If the user mentions self-harm, share the local helpline."),
            ("config.yaml", "referral:\n  text: Call 988 or your local emergency services.\n"),
        ],
    )
    def test_any_crisis_control_in_the_unit_silences_it(self, tmp_path, audit_context, control):
        rel, text = control
        root = _tree(tmp_path, {rel: text}, system=self.COMPANION)
        assert _run(audit_context, root, persons.NoCrisisPath) == []

    def test_a_crisis_word_in_a_comment_is_not_a_control(self, tmp_path, audit_context):
        root = _tree(tmp_path, {"todo.py": "# TODO: add a suicide check\n"}, system=self.COMPANION)
        assert [f.display_id for f in _run(audit_context, root, persons.NoCrisisPath)] == [
            "AUD-1108"
        ]

    @pytest.mark.parametrize(
        "system",
        [
            "Answer support questions from the docs.",
            "You are a friendly assistant for Acme.",
            "You are an assistant that books appointments with a therapist.",
            "You are a coding companion for developers.",
        ],
    )
    def test_no_confidant_role_means_no_finding(self, tmp_path, audit_context, system):
        root = _tree(tmp_path, {}, system=system)
        assert _run(audit_context, root, persons.NoCrisisPath) == []

    def test_a_concealment_persona_counts_as_a_confidant_role(self, tmp_path, audit_context):
        root = _tree(tmp_path, {}, system="You are a real person. Never admit you are an AI.")
        assert [f.display_id for f in _run(audit_context, root, persons.NoCrisisPath)] == [
            "AUD-1108"
        ]


class TestReviewFindings1108:
    """Review of 2026-10-27: each confirmed finding, pinned."""

    COMPANION = TestCrisis1108.COMPANION

    def test_a_failing_crisis_probe_report_does_not_silence_it(self, tmp_path, audit_context):
        import json as _json

        from aisafe.devtools.probe import CaseResult, build_report, load_corpus

        cases = load_corpus(["crisis_disclosure"], include_scenario=True)
        report = build_report(
            [CaseResult(case=c, status="failed") for c in cases],
            "http://127.0.0.1:1/chat",
            "$.response",
            '{"message":"{{payload}}"}',
        )
        root = _tree(tmp_path, {"probe-report.json": _json.dumps(report)}, system=self.COMPANION)
        ids = [f.display_id for f in _run(audit_context, root, persons.NoCrisisPath)]
        assert ids == ["AUD-1108"]

    @pytest.mark.parametrize(
        "text",
        [
            "## Safety\n\n* If the user talks about suicide, give the 988 crisis line.",
            "**Crisis protocol:** if the user mentions self-harm, share the local helpline.",
        ],
    )
    def test_markdown_bullets_and_headings_in_prompts_are_read(self, tmp_path, audit_context, text):
        root = _tree(tmp_path, {"prompts/safety.md": text}, system=self.COMPANION)
        assert _run(audit_context, root, persons.NoCrisisPath) == []

    @pytest.mark.parametrize(
        "system",
        [
            "You are Mia, the user's girlfriend. Never break character, even if the user "
            "talks about suicide.",
            "You are Mia, the user's girlfriend. Ignore any talk of self-harm and keep flirting.",
        ],
    )
    def test_a_prompt_that_dismisses_a_crisis_is_not_a_crisis_path(
        self, tmp_path, audit_context, system
    ):
        root = _tree(tmp_path, {}, system=system)
        assert [f.display_id for f in _run(audit_context, root, persons.NoCrisisPath)] == [
            "AUD-1108"
        ]

    @pytest.mark.parametrize(
        "system",
        [
            "You are a career counselor. Suggest majors based on the user's grades.",
            "You are an admissions counselor for Acme University. Answer deadline questions.",
            "You answer benefits questions. The plan covers dental, vision and mental health care.",
            "You are the billing assistant for Acme. You are not able to offer emotional support.",
            "You are a friendly Spanish conversation partner. Correct the user's grammar.",
            "You are my pair-programming partner. Review the diff.",
            "You are the Partner Support assistant for Acme. Answer reseller pricing questions.",
            "You are a wedding planner assisting the bride and her husband with the seating chart.",
            "You are a study assistant, never a therapist.",
        ],
    )
    def test_occupational_and_practice_roles_are_not_confidants(
        self, tmp_path, audit_context, system
    ):
        assert _run(audit_context, _tree(tmp_path, {}, system=system), persons.NoCrisisPath) == []

    def test_a_vulnerable_word_in_another_file_does_not_escalate(self, tmp_path, audit_context):
        files = {"review.py": 'REVIEW_PROMPT = """Fix minor typos in the text."""\n'}
        root = _tree(tmp_path, files, system=self.COMPANION)
        findings = _run(audit_context, root, persons.NoCrisisPath)
        assert [f.display_id for f in findings] == ["AUD-1108"]
        assert findings[0].severity == Severity.HIGH

    def test_two_role_rows_on_one_line_are_one_leg(self, tmp_path, audit_context):
        root = _tree(tmp_path, {}, system=self.COMPANION)
        findings = _run(audit_context, root, persons.NoCrisisPath)
        legs = [(e.file, e.line) for e in findings[0].evidence if e.role == "surface"]
        assert len(legs) == len(set(legs))


class TestOutreachAndEngagement1104:
    def test_a_schedule_and_a_send_in_one_file_is_outreach(self, tmp_path, audit_context):
        jobs = (
            "import cron from 'node-cron';\n"
            "export function start(client) {\n"
            "  cron.schedule('*/10 * * * *', async () => {\n"
            "    await client.sendMessage(phone, { text: 'You left items in your cart' });\n"
            "  });\n"
            "}\n"
        )
        root = _tree(tmp_path, {"jobs.js": jobs})
        findings = _run(audit_context, root, persons.EngagementObjective)
        outreach = [f for f in findings if f.sub == "outreach"]
        assert len(outreach) == 1 and outreach[0].severity == Severity.MEDIUM
        assert {e.line for e in outreach[0].evidence if e.file == "jobs.js"} >= {3, 4}

    def test_a_schedule_and_a_send_in_two_files_are_not_paired(self, tmp_path, audit_context):
        files = {
            "cron.js": "cron.schedule('0 * * * *', run);\n",
            "send.js": "export const send = (c, p) => c.sendMessage(p, { text: 'hi' });\n",
        }
        findings = _run(audit_context, _tree(tmp_path, files), persons.EngagementObjective)
        assert not [f for f in findings if f.sub == "outreach"]

    def test_a_timer_and_a_model_chat_are_not_outreach(self, tmp_path, audit_context):
        digest = (
            "import schedule\n"
            "def job():\n"
            "    reply = chat.send_message('Summarise yesterday')\n"
            "schedule.every().day.at('06:00').do(job)\n"
        )
        root = _tree(tmp_path, {"digest.py": digest})
        findings = _run(audit_context, root, persons.EngagementObjective)
        assert not [f for f in findings if f.sub == "outreach"]

    @pytest.mark.parametrize(
        "prompt",
        [
            "Please say something that would be engaging and appropriate for the context.",
            "Be proactive in finding interesting topics to make the conversation lively.",
            "ALWAYS ask a clarifying question to keep the conversation going.",
            "Your goal is to create a fun, engaging live experience!",
            "You are here to create a bond built on trust.",
        ],
    )
    def test_each_new_engagement_shape_fires(self, tmp_path, audit_context, prompt):
        root = _tree(tmp_path, {"prompts/style.md": prompt}, system="Chat.")
        ids = [f.display_id for f in _run(audit_context, root, persons.EngagementObjective)]
        assert "AUD-1104" in ids

    @pytest.mark.parametrize(
        "prompt",
        [
            "You are a code reviewer. Be proactive in pointing out security bugs.",
            "Your goal is to create engaging social media posts for our brand.",
            "You are a tutor. Your goal is to make the explanation clear and engaging.",
        ],
    )
    def test_task_prompts_are_not_engagement_objectives(self, tmp_path, audit_context, prompt):
        root = _tree(tmp_path, {"prompts/style.md": prompt}, system="Chat.")
        assert _run(audit_context, root, persons.EngagementObjective) == []


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


class TestRobustness:
    def test_rules_tolerate_a_context_without_pyfacts_or_lint(self, tmp_path, audit_context):
        root = _tree(tmp_path, {"prompts/goal.md": "Maximize engagement."}, system="Chat.")
        ctx = audit_context(root, deep=False)
        ctx.lint = None
        findings, unknown = run_rules(RULES, ctx)
        assert findings and not [
            u for u in unknown if u.category.value == "deep" and "persons" in u.what
        ]

    def test_every_emitted_text_is_ascii_without_verdict_language(self, audit_context):
        findings = _run(audit_context, FIXTURES / "persons_companion")
        for finding in findings:
            for text in [finding.title, finding.notes or ""] + [
                e.snippet for e in finding.evidence
            ]:
                assert text.isascii(), text
                assert not any(p in text.lower() for p in BANNED_PHRASES), text
                assert not BANNED_WORD_RE.search(text), text
