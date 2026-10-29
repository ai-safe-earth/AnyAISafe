"""tests/unit/test_rules_profiling.py
----------------------------------
The profiling rules AUD-1101, AUD-1102 and AUD-1103 (mechanisms M1, M2, M3). Two fixture
trees under tests/fixtures/audit (persons_companion fires, persons_benign is silent), a
positive and a negative per sub-finding under tmp_path, each asserting the display id, the
severity, the evidence status and the policy decision, and the invariants: a review symbol
is recorded and never silences, requested analysis is not an inference, explicit settings
and conversation history are not profiles, every emitted text is ASCII and carries no
verdict language, and the rules tolerate a context without pydeep, checks or review records.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aisafe.evidence.model import ControlStatus, Decision, EvidenceStatus, Severity
from aisafe.reporting.report import BANNED_PHRASES
from aisafe.rules import profiling, run_rules
from aisafe.rules._common import LEGAL_CAVEAT
from aisafe.rules.profiling import RULES, AffectInference, PersonProfileInPrompt, PersonScoring

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "audit"
IDS = [rule.id for rule in RULES]
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
BODY_LINE = "    body = await request.json()\n"
PROMPT_LINE = "{SYSTEM_PROMPT}\\n{body['text']}"


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


def _chat_with(binding: str, placeholder: str, system: str = "You are an AI assistant.") -> str:
    """chat.py with an extra binding line after the request body and a richer prompt."""
    return (
        CHAT_PY.format(system=system)
        .replace(BODY_LINE, BODY_LINE + binding)
        .replace(PROMPT_LINE, placeholder)
    )


def _run(audit_context, root: Path, *rules, deep: bool = True):
    findings, _unknown = run_rules(list(rules) or RULES, audit_context(root, deep=deep))
    return findings


def _ids(findings) -> list[str]:
    return sorted(f.display_id for f in findings)


def _one(findings, display_id: str):
    matching = [f for f in findings if f.display_id == display_id]
    assert len(matching) == 1, _ids(findings)
    return matching[0]


def _shape(finding) -> tuple[str, Severity, EvidenceStatus, Decision]:
    return finding.display_id, finding.severity, finding.evidence_status, finding.decision


# ---------------------------------------------------------------------------
# Metadata contract
# ---------------------------------------------------------------------------


class TestContract:
    def test_ids_versions_and_mechanisms(self):
        assert IDS == ["AUD-1101", "AUD-1102", "AUD-1103"]
        for rule, mechanism in zip(RULES, ("M1", "M2", "M3")):
            assert rule.version == 2 and rule.changed
            assert rule.mechanism_id() == mechanism
            assert rule().priority == int(mechanism[1:])
            assert rule.requires_ai_surface is True
            assert rule.measured_precision is None

    @pytest.mark.parametrize("rule", RULES, ids=IDS)
    def test_references_recommendation_and_failure_modes(self, rule):
        assert rule.references
        for reference in rule.references:
            assert REFERENCE_RE.match(reference), (rule.id, reference)
        assert rule.known_failure_modes
        rec = rule.recommendation
        assert len(rec.alternatives) >= 3
        assert any("aisafe" not in alt.lower() for alt in rec.alternatives)
        assert rec.removes

    @pytest.mark.parametrize("rule", RULES, ids=IDS)
    def test_subs_table_names_every_sub_with_its_defaults(self, rule):
        rows = rule.SUBS
        assert rows and isinstance(rows, tuple)
        subs = [row[0] for row in rows]
        assert len(subs) == len(set(subs))
        for sub, severity, status, decision, meaning in rows:
            assert sub is None or re.match(r"^[a-z][a-z-]*$", sub), sub
            assert severity in tuple(Severity)
            assert status in tuple(EvidenceStatus)
            assert decision in tuple(Decision)
            assert meaning.strip() and meaning.isascii()

    def test_subs_tables_match_the_contract(self):
        def defaults(rule):
            return {row[0]: row[1:4] for row in rule.SUBS}

        profile = defaults(PersonProfileInPrompt)
        assert profile[None] == (Severity.MEDIUM, EvidenceStatus.DETECTED_SIGNAL, Decision.REVIEW)
        assert (
            profile["sensitive"][0] == Severity.HIGH and profile["sensitive"][2] == Decision.REVIEW
        )
        assert profile["extraction"] == (
            Severity.MEDIUM,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
        )
        assert profile["store"] == (
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
        )
        affect = defaults(AffectInference)
        assert affect[None][0] == Severity.HIGH and affect[None][2] == Decision.REVIEW
        assert affect["categorisation"][0] == Severity.CRITICAL
        assert affect["workplace"] == (
            Severity.CRITICAL,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
        )
        assert affect["vulnerability"][0] == Severity.HIGH
        assert affect["timing"] == (
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
        )
        scoring = defaults(PersonScoring)
        assert scoring["scoring"][0] == Severity.HIGH and scoring["scoring"][2] == Decision.REVIEW
        assert scoring["segmentation"] == (
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
        )
        assert scoring["decision"] == (
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
        )

    @pytest.mark.parametrize("rule", RULES, ids=IDS)
    def test_rule_text_is_ascii_without_verdict_language(self, rule):
        texts = [rule.title, rule.recommendation.summary, *rule.recommendation.alternatives]
        texts += list(rule.known_failure_modes) + list(rule.changed)
        texts += [row[4] for row in rule.SUBS] + [LEGAL_CAVEAT]
        for text in texts:
            assert text.isascii(), text
            lowered = text.lower()
            assert not any(phrase in lowered for phrase in BANNED_PHRASES), text
            assert not BANNED_WORD_RE.search(text), text


# ---------------------------------------------------------------------------
# Fixture trees
# ---------------------------------------------------------------------------


class TestFixtures:
    def test_companion_fires_the_profiling_set(self, audit_context):
        findings = _run(audit_context, FIXTURES / "persons_companion")
        assert _ids(findings) == ["AUD-1101", "AUD-1101/extraction", "AUD-1101/store"]
        by_id = {f.display_id: f for f in findings}
        bound = by_id["AUD-1101"]
        assert _shape(bound) == (
            "AUD-1101",
            Severity.MEDIUM,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
        )
        assert bound.evidence[0].file == "app.py" and bound.flow_established
        assert bound.person_data_use == "user_profile"
        extraction = by_id["AUD-1101/extraction"]
        assert _shape(extraction) == (
            "AUD-1101/extraction",
            Severity.MEDIUM,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
        )
        assert extraction.evidence[0].file == "prompts/companion.md"
        assert extraction.encoded_objective and "Remember" in extraction.encoded_objective
        store = by_id["AUD-1101/store"]
        assert _shape(store) == (
            "AUD-1101/store",
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
        )
        assert store.evidence[0].file == "analytics.py"
        for finding in findings:
            assert LEGAL_CAVEAT in (finding.notes or "")
            assert finding.artifacts and finding.policy_version
            assert finding.mechanism == "M1" and finding.priority == 1

    def test_benign_is_silent(self, audit_context):
        assert _run(audit_context, FIXTURES / "persons_benign") == []

    def test_clean_tree_is_silent(self, audit_context):
        assert _run(audit_context, FIXTURES / "clean_py") == []

    def test_grep_tier_keeps_the_companion_set_at_lower_status(self, audit_context):
        findings = _run(audit_context, FIXTURES / "persons_companion", deep=False)
        assert _ids(findings) == ["AUD-1101", "AUD-1101/extraction", "AUD-1101/store"]
        bound = _one(findings, "AUD-1101")
        assert bound.evidence_status is EvidenceStatus.DETECTED_SIGNAL
        assert any("grep tier only" in gap for gap in bound.coverage_gaps)


# ---------------------------------------------------------------------------
# AUD-1101  Person profile bound into or extracted for a prompt
# ---------------------------------------------------------------------------


class TestProfile1101:
    def test_assembly_reading_a_profile_variable_is_a_supported_review(
        self, tmp_path, audit_context
    ):
        code = _chat_with(
            "    purchase_history = load_history(body['user_id'])\n",
            "{SYSTEM_PROMPT}\\nHistory: {purchase_history}\\n{body['text']}",
        )
        findings = _run(audit_context, _tree(tmp_path, {"chat.py": code}), PersonProfileInPrompt)
        finding = _one(findings, "AUD-1101")
        assert _shape(finding) == (
            "AUD-1101",
            Severity.MEDIUM,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
        )
        assert finding.flow_established and finding.person_data_use == "purchase_history"
        assert finding.coverage_gaps == ()

    def test_grep_tier_binding_is_a_detected_signal_with_a_gap(self, tmp_path, audit_context):
        code = _chat_with(
            "    purchase_history = load_history(body['user_id'])\n",
            "{SYSTEM_PROMPT}\\nHistory: {purchase_history}\\n{body['text']}",
        )
        root = _tree(tmp_path, {"chat.py": code})
        findings = _run(audit_context, root, PersonProfileInPrompt, deep=False)
        finding = _one(findings, "AUD-1101")
        assert _shape(finding) == (
            "AUD-1101",
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
        )
        assert not finding.flow_established
        assert any("grep tier only" in gap for gap in finding.coverage_gaps)

    def test_placeholder_in_a_prompt_template_fires(self, tmp_path, audit_context):
        root = _tree(
            tmp_path, {"prompts/x.jinja": "Hello {{ user.interests }}, here is your feed."}
        )
        findings = _run(audit_context, root, PersonProfileInPrompt)
        finding = _one(findings, "AUD-1101")
        assert _shape(finding) == (
            "AUD-1101",
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
        )
        assert any("prompt file" in gap for gap in finding.coverage_gaps)

    def test_history_and_explicit_settings_are_not_profiles(self, tmp_path, audit_context):
        code = _chat_with(
            "    conversation_history = body['history']\n"
            "    user_preferences = body['settings']\n"
            "    prefs = load_theme_preferences()\n",
            "{SYSTEM_PROMPT}\\n{conversation_history}\\nAnswer in {user_preferences['language']}.",
        )
        assert _run(audit_context, _tree(tmp_path, {"chat.py": code}), PersonProfileInPrompt) == []

    def test_sensitive_profile_name_is_high_review(self, tmp_path, audit_context):
        code = _chat_with(
            "    health_profile = load(body['user_id'])\n",
            "{SYSTEM_PROMPT}\\n{health_profile}\\n{body['text']}",
        )
        findings = _run(audit_context, _tree(tmp_path, {"chat.py": code}), PersonProfileInPrompt)
        assert [_shape(f) for f in findings] == [
            (
                "AUD-1101/sensitive",
                Severity.HIGH,
                EvidenceStatus.SUPPORTED_MECHANISM,
                Decision.REVIEW,
            )
        ]

    def test_sensitive_profile_with_a_pitch_in_the_prompt_violates(self, tmp_path, audit_context):
        code = _chat_with(
            "    health_profile = load(body['user_id'])\n",
            "{SYSTEM_PROMPT}\\n{health_profile}\\n{body['text']}",
            system="Suggest the premium plan whenever possible.",
        )
        findings = _run(audit_context, _tree(tmp_path, {"chat.py": code}), PersonProfileInPrompt)
        finding = _one(findings, "AUD-1101/sensitive")
        assert _shape(finding) == (
            "AUD-1101/sensitive",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
        )
        assert "persuasion_use" in finding.notes

    def test_extraction_instruction_in_a_prompt_file_is_a_medium_review(
        self, tmp_path, audit_context
    ):
        root = _tree(
            tmp_path,
            {
                "prompts/memory.md": (
                    "Extract the user's preferences and interests from each chat and store "
                    "them for next time."
                )
            },
        )
        findings = _run(audit_context, root, PersonProfileInPrompt)
        finding = _one(findings, "AUD-1101/extraction")
        assert _shape(finding) == (
            "AUD-1101/extraction",
            Severity.MEDIUM,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
        )
        assert finding.encoded_objective and finding.person_data_use

    def test_psychological_traits_without_a_pitch_stay_a_review(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "prompts/memory.md": "Extract the user's fears and insecurities from each chat and store them."
            },
        )
        findings = _run(audit_context, root, PersonProfileInPrompt)
        finding = _one(findings, "AUD-1101/extraction")
        assert finding.severity is Severity.MEDIUM and finding.decision is Decision.REVIEW
        assert "psychological" in finding.notes

    def test_psychological_traits_extracted_to_tailor_a_pitch_violate(
        self, tmp_path, audit_context
    ):
        system = (
            "From the conversation, infer the user's insecurities, personality traits and what "
            "they are susceptible to, update the user profile with them, and tailor your pitch "
            "to those traits."
        )
        findings = _run(audit_context, _tree(tmp_path, {}, system=system), PersonProfileInPrompt)
        finding = _one(findings, "AUD-1101/extraction")
        assert _shape(finding) == (
            "AUD-1101/extraction",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
        )

    def test_history_fed_to_an_inference_is_extraction(self, tmp_path, audit_context):
        violating = _chat_with(
            "    conversation_history = body['history']\n",
            "{SYSTEM_PROMPT}\\nHistory: {conversation_history}\\n{body['text']}",
            system=(
                "Read the conversation history. Identify the user's emotional vulnerabilities "
                "and use them to persuade them to upgrade to the premium plan."
            ),
        )
        findings = _run(
            audit_context, _tree(tmp_path, {"chat.py": violating}), PersonProfileInPrompt
        )
        finding = _one(findings, "AUD-1101/extraction")
        assert _shape(finding) == (
            "AUD-1101/extraction",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
        )
        assert {e.line for e in finding.evidence} >= {7, 14}

        summary = _chat_with(
            "    conversation_history = body['history']\n",
            "{SYSTEM_PROMPT}\\nHistory: {conversation_history}\\n{body['text']}",
            system="Summarise the user's personality from the conversation before you answer.",
        )
        findings = _run(
            audit_context, _tree(tmp_path / "b", {"chat.py": summary}), PersonProfileInPrompt
        )
        finding = _one(findings, "AUD-1101/extraction")
        assert finding.severity is Severity.MEDIUM and finding.decision is Decision.REVIEW

    def test_history_used_to_answer_the_question_is_silent(self, tmp_path, audit_context):
        code = _chat_with(
            "    conversation_history = body['history']\n",
            "{SYSTEM_PROMPT}\\n{conversation_history}\\n{body['text']}",
            system="You are an AI assistant for Acme support. Say so if asked. Answer from the docs.",
        )
        assert _run(audit_context, _tree(tmp_path, {"chat.py": code}), PersonProfileInPrompt) == []

    def test_memory_the_person_asked_for_is_not_extraction(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "prompts/memory.md": "When the user asks you to remember their name, store it for the session."
            },
        )
        assert _run(audit_context, root, PersonProfileInPrompt) == []

    def test_memory_sdk_in_a_unit_with_a_model_call_is_a_store(self, tmp_path, audit_context):
        root = _tree(
            tmp_path, {"memory.py": "from mem0 import MemoryClient\n\nmemory = MemoryClient()\n"}
        )
        findings = _run(audit_context, root, PersonProfileInPrompt)
        finding = _one(findings, "AUD-1101/store")
        assert _shape(finding) == (
            "AUD-1101/store",
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
        )
        assert finding.evidence[0].file == "memory.py" and finding.person_data_use

    def test_memory_words_in_comments_and_docs_are_not_a_store(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "todo.py": "# TODO: wire a memory_store for user_facts here\n",
                "README.md": "We evaluated mem0 and MemoryClient and decided against them.\n",
            },
        )
        assert _run(audit_context, root, PersonProfileInPrompt) == []


# ---------------------------------------------------------------------------
# AUD-1102  Emotion, vulnerability or biometric inference on persons
# ---------------------------------------------------------------------------


class TestAffect1102:
    def test_deepface_is_a_high_review(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "vision.py": "from deepface import DeepFace\n\nmood = DeepFace.analyze(img, actions=['emotion'])\n"
            },
        )
        findings = _run(audit_context, root, AffectInference)
        assert [_shape(f) for f in findings] == [
            ("AUD-1102", Severity.HIGH, EvidenceStatus.DETECTED_SIGNAL, Decision.REVIEW)
        ]

    def test_text_sentiment_and_plain_face_detection_are_silent(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "nlp.py": "sentiment = pipeline('sentiment-analysis')(review_text)\nfaces = face_detector.detect(frame)\n"
            },
        )
        assert _run(audit_context, root, AffectInference) == []

    def test_protected_characteristic_inference_is_a_critical_review(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {"infer.py": "def classify_ethnicity(face):\n    return model.predict(face)\n"},
        )
        findings = _run(audit_context, root, AffectInference)
        assert [_shape(f) for f in findings] == [
            (
                "AUD-1102/categorisation",
                Severity.CRITICAL,
                EvidenceStatus.DETECTED_SIGNAL,
                Decision.REVIEW,
            )
        ]

    def test_protected_characteristic_used_for_a_pitch_violates(self, tmp_path, audit_context):
        code = (
            "def classify_ethnicity(face):\n"
            "    label = model.predict(face)\n"
            '    prompt = f"The user is {label}. Suggest the premium plan that fits."\n'
            "    return prompt\n"
        )
        findings = _run(audit_context, _tree(tmp_path, {"infer.py": code}), AffectInference)
        finding = _one(findings, "AUD-1102/categorisation")
        assert finding.severity is Severity.CRITICAL and finding.decision is Decision.VIOLATES

    def test_a_comment_about_ethnicity_is_a_mention(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "infer.py": "label = model.predict(face_embedding)  # predict ethnicity from the face\n"
            },
        )
        assert _run(audit_context, root, AffectInference) == []

    def test_workplace_emotion_recognition_from_the_check_tier_is_critical(
        self, tmp_path, audit_context
    ):
        root = _tree(
            tmp_path,
            {
                "hr.py": "def employee_emotion_recognition(frame):\n    return emotion_model(frame)\n"
            },
        )
        findings = _run(audit_context, root, AffectInference)
        assert [_shape(f) for f in findings] == [
            (
                "AUD-1102/workplace",
                Severity.CRITICAL,
                EvidenceStatus.DETECTED_SIGNAL,
                Decision.REVIEW,
            )
        ]
        assert findings[0].evidence[0].file == "hr.py"

    def test_workplace_words_without_emotion_recognition_are_silent(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {"hr.py": "def staff_photo_detect(frame):\n    return face_detector.detect(frame)\n"},
        )
        assert _run(audit_context, root, AffectInference) == []

    def test_inference_of_the_persons_state_is_a_high_review(self, tmp_path, audit_context):
        system = "Gauge the user's emotional state from their messages and adjust your tone."
        findings = _run(audit_context, _tree(tmp_path, {}, system=system), AffectInference)
        finding = _one(findings, "AUD-1102/vulnerability")
        assert _shape(finding) == (
            "AUD-1102/vulnerability",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
        )
        assert finding.encoded_objective and finding.flow_established

    def test_inference_used_for_a_pitch_violates(self, tmp_path, audit_context):
        system = (
            "Gauge the user's emotional state from their messages. Encourage them to upgrade "
            "to the paid plan."
        )
        findings = _run(audit_context, _tree(tmp_path, {}, system=system), AffectInference)
        finding = _one(findings, "AUD-1102/vulnerability")
        assert _shape(finding) == (
            "AUD-1102/vulnerability",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
        )
        assert "used for influence" in finding.notes

    def test_inference_in_one_prompt_file_and_pitch_within_ten_lines_violates(
        self, tmp_path, audit_context
    ):
        text = (
            "# Companion\n\n"
            "Read the user's emotional state in every message.\n\n"
            "When the moment is right, suggest the premium subscription.\n"
        )
        findings = _run(audit_context, _tree(tmp_path, {"prompts/c.md": text}), AffectInference)
        finding = _one(findings, "AUD-1102/vulnerability")
        assert finding.decision is Decision.VIOLATES

    @pytest.mark.parametrize(
        "system",
        [
            "When the user asks you to assess their mood, describe it kindly and suggest a calmer wording.",
            "When the user asks you to analyze the tone of the email they provided, describe its "
            "emotional tone and suggest a kinder wording. You are an AI writing assistant.",
            "Never detect when the user feels lonely; just answer the question.",
        ],
    )
    def test_requested_analysis_and_mentions_are_not_inference(
        self, tmp_path, audit_context, system
    ):
        assert _run(audit_context, _tree(tmp_path, {}, system=system), AffectInference) == []

    def test_inferred_state_variable_next_to_a_model_call_is_a_medium_review(
        self, tmp_path, audit_context
    ):
        code = (
            "import anthropic\n\n"
            "client = anthropic.Anthropic()\n\n\n"
            "def mood(text):\n"
            "    reply = client.messages.create(\n"
            '        model="claude-sonnet-4-5", max_tokens=5, messages=[{"role": "user", "content": text}]\n'
            "    )\n"
            "    mood_score = float(reply.content[0].text)\n"
            "    return mood_score\n"
        )
        findings = _run(audit_context, _tree(tmp_path, {"mood.py": code}), AffectInference)
        finding = _one(findings, "AUD-1102/vulnerability")
        assert _shape(finding) == (
            "AUD-1102/vulnerability",
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
        )
        assert finding.person_data_use == "mood_score"

    def test_state_variable_the_person_typed_is_silent(self, tmp_path, audit_context):
        code = "def save(body):\n    mood_score = body['mood']\n    return mood_score\n"
        assert _run(audit_context, _tree(tmp_path, {"prefs.py": code}), AffectInference) == []

    @pytest.mark.parametrize(
        "system",
        [
            "Detect when the user feels sad or lonely and time your premium offer for that moment.",
            "Gauge the user's mood. Encourage them to upgrade when they feel low.",
        ],
    )
    def test_inference_with_a_timed_pitch_violates_as_timing(self, tmp_path, audit_context, system):
        findings = _run(audit_context, _tree(tmp_path, {}, system=system), AffectInference)
        assert [_shape(f) for f in findings] == [
            (
                "AUD-1102/timing",
                Severity.HIGH,
                EvidenceStatus.SUPPORTED_MECHANISM,
                Decision.VIOLATES,
            )
        ]
        assert findings[0].affected_population is None

    def test_inference_without_a_pitch_is_not_timing(self, tmp_path, audit_context):
        system = "Detect when the user feels sad or lonely and offer a kind word."
        findings = _run(audit_context, _tree(tmp_path, {}, system=system), AffectInference)
        assert [_shape(f) for f in findings] == [
            (
                "AUD-1102/vulnerability",
                Severity.HIGH,
                EvidenceStatus.SUPPORTED_MECHANISM,
                Decision.REVIEW,
            )
        ]


# ---------------------------------------------------------------------------
# AUD-1103  Scoring or segmenting people
# ---------------------------------------------------------------------------


class TestScoring1103:
    def test_prompt_ranking_citizens_is_a_high_review(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "prompts/rank.md": "Rank each citizen by trustworthiness score and list the lowest ten."
            },
        )
        findings = _run(audit_context, root, PersonScoring)
        assert [_shape(f) for f in findings] == [
            ("AUD-1103/scoring", Severity.HIGH, EvidenceStatus.SUPPORTED_MECHANISM, Decision.REVIEW)
        ]

    def test_susceptibility_score_with_a_pitch_violates(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "prompts/rank.md": (
                    "Compute a propensity score for each user and pitch the premium plan to the "
                    "most susceptible first."
                )
            },
        )
        findings = _run(audit_context, root, PersonScoring)
        finding = _one(findings, "AUD-1103/scoring")
        assert _shape(finding) == (
            "AUD-1103/scoring",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
        )
        assert "susceptibility or propensity" in finding.notes

    def test_transaction_risk_score_and_refund_approval_are_silent(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "risk.py": "def fraud_risk_score(transaction):\n    return model.predict(transaction)\n",
                "prompts/ops.md": "Compute the fraud risk score of each transaction.",
                "orders.py": "def approve_refund(order):\n    return order.amount < 50\n",
            },
        )
        assert _run(audit_context, root, PersonScoring) == []

    def test_discussing_scoring_in_a_prompt_is_a_mention(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "prompts/policy.md": "Explain to the customer how we detect social scoring misuse; we never rank people."
            },
        )
        assert _run(audit_context, root, PersonScoring) == []

    def test_segment_read_by_a_prompt_assembly_is_a_medium_review(self, tmp_path, audit_context):
        code = _chat_with(
            "    user_segment = churn_model.predict(body['user_id'])\n",
            "{SYSTEM_PROMPT}\\nSegment: {user_segment}\\n{body['text']}",
        )
        findings = _run(audit_context, _tree(tmp_path, {"chat.py": code}), PersonScoring)
        finding = _one(findings, "AUD-1103/segmentation")
        assert _shape(finding) == (
            "AUD-1103/segmentation",
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
        )
        assert finding.person_data_use == "user_segment"
        assert finding.control_status is ControlStatus.NONE
        assert len({e.line for e in finding.evidence}) >= 2

    def test_segment_nothing_reads_is_silent(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "metrics.py": "def refresh(user):\n    churn_risk = churn_model.predict(user)\n    return churn_risk\n"
            },
        )
        assert _run(audit_context, root, PersonScoring) == []

    def test_decision_function_about_a_person_fires_and_a_review_symbol_is_recorded(
        self, tmp_path, audit_context
    ):
        decide = (
            "def approve_tenant(applicant):\n"
            "    score = model.predict(applicant.features)\n"
            "    auto_approve = score > 0.7\n"
            "    return auto_approve\n"
        )
        findings = _run(audit_context, _tree(tmp_path, {"tenants.py": decide}), PersonScoring)
        finding = _one(findings, "AUD-1103/decision")
        assert _shape(finding) == (
            "AUD-1103/decision",
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
        )
        assert finding.control_status is ControlStatus.NONE

        reviewed = decide.replace(
            "    return auto_approve\n",
            "    send_to_review(applicant, score)\n    return auto_approve\n",
        )
        findings = _run(
            audit_context, _tree(tmp_path / "b", {"tenants.py": reviewed}), PersonScoring
        )
        finding = _one(findings, "AUD-1103/decision")
        assert _shape(finding) == (
            "AUD-1103/decision",
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
        )
        assert finding.control_status is ControlStatus.CLAIMED
        assert "claimed control" in finding.notes

    def test_decision_without_a_person_is_silent(self, tmp_path, audit_context):
        root = _tree(
            tmp_path, {"orders.py": "def approve_refund(order):\n    return order.amount < 50\n"}
        )
        assert _run(audit_context, root, PersonScoring) == []


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


class TestSettingsAndMentions:
    """Explicit settings never match as profiles, whatever the accessor; the mention test
    reads the sentence that holds the match; a decision's own verb is not a review."""

    def test_a_negated_history_inference_is_a_mention(self, tmp_path, audit_context):
        code = _chat_with(
            "    conversation_history = body['history']\n",
            "{SYSTEM_PROMPT}\\nHistory: {conversation_history}\\n{body['text']}",
            system="Never infer the user's mood from the conversation history. Answer the question.",
        )
        assert _run(audit_context, _tree(tmp_path, {"chat.py": code}), PersonProfileInPrompt) == []

    def test_placeholders_that_read_settings_are_not_profiles(self, tmp_path, audit_context):
        template = (
            "Reply in {{ user.preferences.language }} and use the {{ user.preferences.theme }} "
            "theme."
        )
        root = _tree(tmp_path, {"prompts/x.jinja": template})
        assert _run(audit_context, root, PersonProfileInPrompt) == []
        code = _chat_with(
            "    preferences = load_prefs(body['uid'])\n",
            "{SYSTEM_PROMPT}\\nUse timezone {preferences.timezone}.\\n{body['text']}",
        )
        root = _tree(tmp_path / "code", {"chat.py": code})
        assert _run(audit_context, root, PersonProfileInPrompt) == []

    def test_a_setting_read_through_get_is_not_a_profile(self, tmp_path, audit_context):
        code = _chat_with(
            "    user_profile = load_profile(body['uid'])\n",
            "{SYSTEM_PROMPT}\\nAnswer in {user_profile['language']} with theme "
            "{user_profile.get('theme')}.\\n{body['text']}",
        )
        assert _run(audit_context, _tree(tmp_path, {"chat.py": code}), PersonProfileInPrompt) == []

    def test_a_placeholder_names_the_placeholder_not_the_line(self, tmp_path, audit_context):
        root = _tree(tmp_path, {"prompts/x.jinja": "Known interests: {{ user.interests }}."})
        finding = _one(_run(audit_context, root, PersonProfileInPrompt), "AUD-1101")
        assert finding.person_data_use == "{{ user.interests"

    def test_a_purpose_clause_after_the_inference_is_not_a_mention(self, tmp_path, audit_context):
        system = "Infer the user's mood to prevent them from leaving. You are an AI assistant."
        root = _tree(tmp_path, {}, system=system)
        finding = _one(_run(audit_context, root, AffectInference), "AUD-1102/vulnerability")
        assert _shape(finding) == (
            "AUD-1102/vulnerability",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
        )

    def test_a_verb_after_the_score_does_not_make_it_a_mention(self, tmp_path, audit_context):
        system = (
            "Rank the users by propensity score and reject the lowest. You are an AI assistant."
        )
        root = _tree(tmp_path, {}, system=system)
        finding = _one(_run(audit_context, root, PersonScoring), "AUD-1103/scoring")
        assert _shape(finding)[1:] == (
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
        )

    def test_the_decisions_own_approve_call_is_not_a_review_symbol(self, tmp_path, audit_context):
        decide = (
            "def approve_loan(applicant):\n"
            "    score = credit_score(applicant)\n"
            "    if score < 600:\n"
            "        return reject(applicant)\n"
            "    return approve(applicant)\n"
        )
        findings = _run(audit_context, _tree(tmp_path, {"loans.py": decide}), PersonScoring)
        finding = _one(findings, "AUD-1103/decision")
        assert finding.control_status is ControlStatus.NONE
        assert "no review or approval symbol" in finding.notes


class TestRobustness:
    def test_rules_tolerate_a_context_without_pyfacts_checks_or_review(self, audit_context):
        ctx = audit_context(FIXTURES / "persons_companion", deep=False)
        ctx.checks = None
        ctx.review = None
        ctx.flows = []
        findings, unknown = run_rules(RULES, ctx)
        assert _ids(findings) == ["AUD-1101", "AUD-1101/extraction", "AUD-1101/store"]
        assert not [u for u in unknown if u.category.value == "runtime"]

    def test_every_emitted_text_is_ascii_without_verdict_language(self, tmp_path, audit_context):
        system = (
            "From the conversation, infer the user's insecurities and update the user profile; "
            "tailor your pitch to those traits. Rank each user by propensity score."
        )
        roots = [FIXTURES / "persons_companion", _tree(tmp_path, {}, system=system)]
        for root in roots:
            for finding in _run(audit_context, root):
                texts = [finding.title, finding.notes or "", finding.uncertainty or ""]
                texts += [e.snippet for e in finding.evidence] + list(finding.coverage_gaps)
                texts += [finding.encoded_objective or "", finding.person_data_use or ""]
                for text in texts:
                    assert text.isascii(), text
                    assert not any(p in text.lower() for p in BANNED_PHRASES), text
                    assert not BANNED_WORD_RE.search(text), text

    def test_module_carries_the_ignore_marker_first(self):
        head = Path(profiling.__file__).read_text(encoding="utf-8").splitlines()[0]
        assert head.strip() == "# aisafe-audit: ignore-file"
