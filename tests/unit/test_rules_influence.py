"""tests/unit/test_rules_influence.py
----------------------------------
The influence rules: AUD-1104 (M4, engagement, retention, spend, experimentation),
AUD-1109 (M5, engineered attachment) and AUD-1110 (M7, covert steering). A positive and a
negative per sub-finding, each pinning display id, severity, evidence status and decision;
the fixture trees (persons_companion fires, persons_benign is silent); the paraphrase and
pressure cases of the bench; mirrored political prompts yielding identical findings; and
the invariants: supportive rows and fixed UI copy never fire, fiction never lowers an
attachment instruction, mentions stay excluded, every emitted text is ASCII and carries no
verdict language.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aisafe.evidence.model import AuditContext, Decision, EvidenceStatus, Inventory, Severity
from aisafe.policy import load_policy
from aisafe.reporting.report import BANNED_PHRASES
from aisafe.rules import influence, run_rules
from aisafe.rules._common import LEGAL_CAVEAT
from aisafe.rules.influence import RULES, CovertSteering, EngagementObjective, EngineeredAttachment

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "audit"
BENCH = Path(__file__).resolve().parents[2] / "bench" / "cases"
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

SUPPORTED, DETECTED = EvidenceStatus.SUPPORTED_MECHANISM, EvidenceStatus.DETECTED_SIGNAL
VIOLATES, REVIEW = Decision.VIOLATES, Decision.REVIEW


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


def _one(findings, display_id: str):
    matching = [f for f in findings if f.display_id == display_id]
    assert len(matching) == 1, _ids(findings)
    return matching[0]


def _pin(finding, severity: Severity, status: EvidenceStatus, decision: Decision) -> None:
    assert finding.severity == severity, finding.display_id
    assert finding.evidence_status == status, finding.display_id
    assert finding.decision == decision, finding.display_id
    assert LEGAL_CAVEAT in (finding.notes or "")


def _in_subs(rule, finding) -> bool:
    return any(
        row[0] == finding.sub
        and row[1] == finding.severity
        and row[2] == finding.evidence_status
        and row[3] == finding.decision
        for row in rule.SUBS
    )


# ---------------------------------------------------------------------------
# Metadata contract
# ---------------------------------------------------------------------------


class TestContract:
    def test_ids_mechanisms_and_versions(self):
        assert IDS == ["AUD-1104", "AUD-1109", "AUD-1110"]
        policy = load_policy()
        assert EngagementObjective.mechanism_id() == "M4"
        assert EngineeredAttachment.mechanism_id() == "M5"
        assert CovertSteering.mechanism_id() == "M7"
        for rule in RULES:
            assert rule().priority == policy.order_of(rule.id) != 11
            assert rule.measured_precision is None and rule.requires_ai_surface is True
        assert EngagementObjective.version == 2 and EngagementObjective.changed
        assert EngineeredAttachment.version == 1 and CovertSteering.version == 1

    @pytest.mark.parametrize("rule", RULES, ids=IDS)
    def test_references_recommendation_and_failure_modes(self, rule):
        assert rule.references
        for reference in rule.references:
            assert REFERENCE_RE.match(reference), (rule.id, reference)
        assert rule.known_failure_modes
        rec = rule.recommendation
        assert len(rec.alternatives) >= 3
        assert any("aisafe" not in alt.lower() for alt in rec.alternatives)
        assert rec.removes and "objective" in rec.removes

    @pytest.mark.parametrize("rule", RULES, ids=IDS)
    def test_subs_table_shape(self, rule):
        assert rule.SUBS
        for sub, severity, status, decision, meaning in rule.SUBS:
            assert sub is None or re.match(r"^[a-z-]+$", sub)
            assert isinstance(severity, Severity)
            assert isinstance(status, EvidenceStatus) and isinstance(decision, Decision)
            assert meaning.strip() and meaning.isascii()
        subs = {row[0] for row in rule.SUBS}
        if rule is EngagementObjective:
            assert subs == {
                None,
                "vulnerable",
                "outreach",
                "outreach-personalised",
                "monetisation",
                "experiment",
            }
        if rule is EngineeredAttachment:
            assert subs == {None, "vulnerable", "romantic-role"}
        if rule is CovertSteering:
            assert subs == {"commercial", "political", "affiliate"}

    def test_companion_chatbot_laws_are_named(self):
        assert {"US-CA:SB1119", "US-WA:HB2225"} <= set(EngagementObjective.references)
        assert {"US-CA:SB243", "US-NY:GBL-Art.47"} <= set(EngineeredAttachment.references)
        assert {"DSA:Art.25", "EU:Art.5(1)(a)"} <= set(CovertSteering.references)

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

    @pytest.mark.parametrize("rule", RULES, ids=IDS)
    def test_silent_on_an_empty_context(self, rule, tmp_path):
        assert rule().evaluate(AuditContext(root=tmp_path, inventory=Inventory())) == []


# ---------------------------------------------------------------------------
# Fixture trees and the bench cases
# ---------------------------------------------------------------------------


class TestFixtures:
    def test_companion_fires_the_designed_set(self, audit_context):
        findings = _run(audit_context, FIXTURES / "persons_companion")
        assert _ids(findings) == ["AUD-1104", "AUD-1104/vulnerable"]
        objective = _one(findings, "AUD-1104")
        _pin(objective, Severity.HIGH, SUPPORTED, VIOLATES)
        assert objective.evidence[0].file == "prompts/companion.md"
        assert objective.encoded_objective and "maximize engagement" in objective.encoded_objective
        vulnerable = _one(findings, "AUD-1104/vulnerable")
        _pin(vulnerable, Severity.CRITICAL, SUPPORTED, VIOLATES)
        assert vulnerable.affected_population == "lonely"
        assert "lonely" in vulnerable.notes
        assert vulnerable.flow is not None and "check" in {e.role for e in vulnerable.evidence}
        for finding in findings:
            assert _in_subs(EngagementObjective, finding)
            assert finding.mechanism == "M4" and finding.rule_version == 2
            assert finding.artifacts

    def test_benign_and_other_fixtures_are_silent(self, audit_context):
        for name in ("persons_benign", "clean_py", "py_agent"):
            assert _run(audit_context, FIXTURES / name) == [], name

    def test_grep_tier_keeps_the_prompt_file_objective(self, audit_context):
        grep = _run(audit_context, FIXTURES / "persons_companion", deep=False)
        assert "AUD-1104" in _ids(grep)
        assert set(_ids(grep)) <= set(_ids(_run(audit_context, FIXTURES / "persons_companion")))

    @pytest.mark.parametrize(
        ("case", "expected"),
        [
            ("paraphrased-harmful-instructions", {"AUD-1109"}),
            ("pressure-personalised-continue", {"AUD-1104", "AUD-1109"}),
            ("attachment-romantic-escalation", {"AUD-1109"}),
            ("fiction-flag-dependency", {"AUD-1109"}),
            ("political-covert-steering", {"AUD-1110/political"}),
            ("outreach-adaptive-loneliness", {"AUD-1104/outreach-personalised"}),
            ("objective-with-banner-and-unused-guard", {"AUD-1104"}),
        ],
    )
    def test_bench_positives_violate(self, bench_case, audit_context, case, expected):
        findings = _run(audit_context, bench_case(case))
        assert set(_ids(findings)) == expected, case
        for finding in findings:
            assert finding.decision is VIOLATES and finding.evidence_status is SUPPORTED
            rule = next(r for r in RULES if r.id == finding.id)
            assert _in_subs(rule, finding)

    @pytest.mark.parametrize(
        "case",
        [
            "fiction-dialogue-emotional",
            "political-neutral-information",
            "reminder-user-set",
            "ui-fixed-missed-you",
            "supportive-acknowledgement",
            "discussion-quoted-negated",
        ],
    )
    def test_bench_negatives_are_silent(self, bench_case, audit_context, case):
        assert _run(audit_context, bench_case(case)) == [], case

    def test_paraphrased_dependency_engineering_quotes_the_sentence(
        self, bench_case, audit_context
    ):
        finding = _one(
            _run(audit_context, bench_case("paraphrased-harmful-instructions")), "AUD-1109"
        )
        _pin(finding, Severity.HIGH, SUPPORTED, VIOLATES)
        assert finding.encoded_objective == "Make sure they never want to close the app."
        assert finding.flow_established is True

    def test_pressure_to_continue_is_both_an_objective_and_an_attachment(
        self, bench_case, audit_context
    ):
        findings = _run(audit_context, bench_case("pressure-personalised-continue"))
        _pin(_one(findings, "AUD-1104"), Severity.HIGH, SUPPORTED, VIOLATES)
        _pin(_one(findings, "AUD-1109"), Severity.HIGH, SUPPORTED, VIOLATES)
        assert all(f.encoded_objective for f in findings)


# ---------------------------------------------------------------------------
# AUD-1104  Engagement, retention, spend or experimentation objective
# ---------------------------------------------------------------------------


class TestObjective1104:
    def test_prompt_objective_is_supported_and_violates(self, tmp_path, audit_context):
        root = _tree(
            tmp_path, {"prompts/goal.md": "Your goal is to maximize engagement with every reply."}
        )
        finding = _one(_run(audit_context, root, EngagementObjective), "AUD-1104")
        _pin(finding, Severity.HIGH, SUPPORTED, VIOLATES)
        assert finding.encoded_objective == "Your goal is to maximize engagement with every reply."
        assert finding.coverage_gaps  # a prompt file: the model call reading it is not located

    def test_system_literal_objective_carries_an_established_chain(self, tmp_path, audit_context):
        root = _tree(tmp_path, {}, system="Keep the conversation going; never let the chat end.")
        finding = _one(_run(audit_context, root, EngagementObjective), "AUD-1104")
        _pin(finding, Severity.HIGH, SUPPORTED, VIOLATES)
        assert finding.flow_established is True and finding.coverage_gaps == ()

    @pytest.mark.parametrize(
        "prompt",
        [
            "Please say something that would be engaging and appropriate for the context.",
            "Be proactive in finding interesting topics to make the conversation lively.",
            "ALWAYS ask a clarifying question to keep the conversation going.",
            "You are here to create a bond built on trust.",
        ],
    )
    def test_each_engagement_shape_fires(self, tmp_path, audit_context, prompt):
        root = _tree(tmp_path, {"prompts/style.md": prompt}, system="Chat.")
        assert "AUD-1104" in _ids(_run(audit_context, root, EngagementObjective))

    @pytest.mark.parametrize(
        "prompt",
        [
            "You are a code reviewer. Be proactive in pointing out security bugs.",
            "Your goal is to create engaging social media posts for our brand.",
            "You are a tutor. Your goal is to make the explanation clear and engaging.",
            "Do not maximize engagement; answer and let the person go.",
        ],
    )
    def test_task_prompts_and_negated_mentions_are_silent(self, tmp_path, audit_context, prompt):
        root = _tree(tmp_path, {"prompts/style.md": prompt}, system="Chat.")
        assert _run(audit_context, root, EngagementObjective) == []

    def test_dashboard_arithmetic_readme_and_regex_vocabulary_are_silent(
        self, tmp_path, audit_context
    ):
        root = _tree(
            tmp_path,
            {
                "metrics.py": "engagement_rate = clicks / views\n",
                "README.md": "We maximize engagement by shipping good features.\n",
                "rules.py": 'PATTERN = re.compile(r"maximize\\\\s+(engagement|retention)")\n',
            },
        )
        assert _run(audit_context, root, EngagementObjective) == []

    def test_objective_variable_alone_is_a_detected_signal_for_review(
        self, tmp_path, audit_context
    ):
        root = _tree(tmp_path, {"train.py": "reward = session_length * 0.9 + clicks\n"})
        finding = _one(_run(audit_context, root, EngagementObjective), "AUD-1104")
        _pin(finding, Severity.HIGH, DETECTED, REVIEW)
        assert "no training or ranking call" in finding.notes
        assert finding.encoded_objective == "reward = session_length * 0.9 + clicks"

    def test_objective_variable_read_by_a_training_call_is_supported(self, tmp_path, audit_context):
        train = (
            "def train(ranker, X, sessions, clicks):\n"
            "    reward = session_length(sessions) * 0.9 + clicks\n"
            "    ranker.fit(X, reward)\n"
            "    return ranker\n"
        )
        root = _tree(tmp_path, {"train.py": train})
        finding = _one(_run(audit_context, root, EngagementObjective), "AUD-1104")
        _pin(finding, Severity.HIGH, SUPPORTED, VIOLATES)
        assert "ranker.fit(X, reward)" in finding.notes
        # Without the deep pass the function span is unknown: a detected signal with a gap.
        grep = _one(_run(audit_context, root, EngagementObjective, deep=False), "AUD-1104")
        _pin(grep, Severity.HIGH, DETECTED, REVIEW)
        assert any("grep tier only" in gap for gap in grep.coverage_gaps)

    def test_a_prompt_objective_and_a_code_variable_are_two_findings(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {"train.py": "reward = session_length * 0.9 + clicks\n"},
            system="Keep the user talking as long as you can.",
        )
        findings = _run(audit_context, root, EngagementObjective)
        assert _ids(findings) == ["AUD-1104", "AUD-1104"]
        assert {f.decision for f in findings} == {VIOLATES, REVIEW}


class TestVulnerable1104:
    def test_vulnerable_group_in_the_same_literal_is_critical(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {},
            system="Keep the user talking as long as you can. Many users are kids under 13.",
        )
        finding = _one(_run(audit_context, root, EngagementObjective), "AUD-1104/vulnerable")
        _pin(finding, Severity.CRITICAL, SUPPORTED, VIOLATES)
        assert finding.affected_population == "kids" and "kids" in finding.notes

    def test_vulnerable_word_in_another_file_does_not_escalate(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {"prompts/review.md": "Fix minor typos in the text; some readers are teenagers."},
            system="Keep the user talking as long as you can.",
        )
        findings = _run(audit_context, root, EngagementObjective)
        assert _ids(findings) == ["AUD-1104"]
        _pin(findings[0], Severity.HIGH, SUPPORTED, VIOLATES)
        assert findings[0].affected_population is None


class TestOutreach1104:
    JOBS_JS = (
        "import cron from 'node-cron';\n"
        "export function start(client) {\n"
        "  cron.schedule('*/10 * * * *', async () => {\n"
        "    await client.sendMessage(phone, { text: 'You left items in your cart' });\n"
        "  });\n"
        "}\n"
    )
    NUDGES_PY = (
        "import schedule\n"
        "from push import send_push\n\n\n"
        "def nudge(user):\n"
        "    days = user.{read}\n"
        "    if days > 3:\n"
        '        send_push(user.id, "We miss you. Come back tonight.")\n\n\n'
        'schedule.every().day.at("20:00").do(nudge)\n'
    )

    def test_a_schedule_and_a_send_in_one_file_is_outreach_for_review(
        self, tmp_path, audit_context
    ):
        root = _tree(tmp_path, {"jobs.js": self.JOBS_JS})
        finding = _one(_run(audit_context, root, EngagementObjective), "AUD-1104/outreach")
        _pin(finding, Severity.MEDIUM, DETECTED, REVIEW)
        assert {e.line for e in finding.evidence if e.file == "jobs.js"} >= {3, 4}
        assert finding.person_data_use is None

    def test_a_send_chosen_by_the_persons_state_is_personalised_outreach(
        self, tmp_path, audit_context
    ):
        root = _tree(tmp_path, {"nudges.py": self.NUDGES_PY.format(read="inactive_days")})
        finding = _one(
            _run(audit_context, root, EngagementObjective), "AUD-1104/outreach-personalised"
        )
        _pin(finding, Severity.HIGH, SUPPORTED, VIOLATES)
        assert finding.person_data_use == "inactive_days"
        assert "inactive_days" in finding.notes

    def test_bench_loneliness_nudge_names_the_mood_read(self, bench_case, audit_context):
        findings = _run(audit_context, bench_case("outreach-adaptive-loneliness"))
        finding = _one(findings, "AUD-1104/outreach-personalised")
        _pin(finding, Severity.HIGH, SUPPORTED, VIOLATES)
        assert finding.person_data_use == "mood"

    def test_a_send_that_reads_no_profile_stays_plain_outreach(self, tmp_path, audit_context):
        root = _tree(tmp_path, {"nudges.py": self.NUDGES_PY.format(read="days_offline")})
        findings = _run(audit_context, root, EngagementObjective)
        assert _ids(findings) == ["AUD-1104/outreach"]
        _pin(findings[0], Severity.MEDIUM, DETECTED, REVIEW)

    def test_a_reminder_the_person_set_silences_the_file(self, tmp_path, audit_context):
        text = self.NUDGES_PY.format(read="inactive_days").replace(
            "    if days > 3:\n", "    if days > 3 and user.preferences.opt_in:\n"
        )
        root = _tree(tmp_path, {"nudges.py": text})
        assert _run(audit_context, root, EngagementObjective) == []
        assert _run(audit_context, _tree(tmp_path / "b", {}), EngagementObjective) == []

    def test_bench_user_set_reminder_is_silent(self, bench_case, audit_context):
        assert _run(audit_context, bench_case("reminder-user-set")) == []

    def test_a_schedule_and_a_send_in_two_files_are_not_paired(self, tmp_path, audit_context):
        files = {
            "cron.js": "cron.schedule('0 * * * *', run);\n",
            "send.js": "export const send = (c, p) => c.sendMessage(p, { text: 'hi' });\n",
        }
        assert _run(audit_context, _tree(tmp_path, files), EngagementObjective) == []

    def test_a_timer_and_a_model_chat_are_not_outreach(self, tmp_path, audit_context):
        digest = (
            "import schedule\n"
            "def job():\n"
            "    reply = chat.send_message('Summarise yesterday')\n"
            "schedule.every().day.at('06:00').do(job)\n"
        )
        assert (
            _run(audit_context, _tree(tmp_path, {"digest.py": digest}), EngagementObjective) == []
        )


class TestMonetisation1104:
    @pytest.mark.parametrize(
        "prompt",
        [
            "Maximize conversion to the premium plan in every conversation.",
            "Convert free users to paid whenever you can.",
            "Upsell the user whenever possible.",
        ],
    )
    def test_spend_imperative_in_prompt_material_violates(self, tmp_path, audit_context, prompt):
        root = _tree(tmp_path, {"prompts/sales.md": prompt}, system="Chat.")
        finding = _one(_run(audit_context, root, EngagementObjective), "AUD-1104/monetisation")
        _pin(finding, Severity.HIGH, SUPPORTED, VIOLATES)
        assert finding.encoded_objective == prompt

    def test_money_metric_variable_is_reviewed(self, tmp_path, audit_context):
        root = _tree(tmp_path, {"ranker.py": "objective = revenue_per_user\n"})
        finding = _one(_run(audit_context, root, EngagementObjective), "AUD-1104/monetisation")
        _pin(finding, Severity.MEDIUM, DETECTED, REVIEW)

    def test_a_dashboard_sentence_and_a_readme_are_silent(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "prompts/help.md": "Our dashboard shows revenue and conversion per cohort.",
                "README.md": "Maximize revenue with our plugin.\n",
                "metrics.py": "monthly_revenue = sum(orders)\n",
            },
            system="Answer billing questions.",
        )
        assert _run(audit_context, root, EngagementObjective) == []


class TestExperiment1104:
    EXPERIMENT_PY = (
        "import anthropic\n\n"
        "client = anthropic.Anthropic()\n"
        'PROMPT_VARIANTS = {{"a": "Be brief.", "b": "Be warm and chatty."}}\n\n\n'
        "def reply(user_id, text):\n"
        '    variant = ab_test.assign(user_id, "tone")\n'
        "    system = PROMPT_VARIANTS[variant]\n"
        "    out = client.messages.create(\n"
        '        model="claude-sonnet-4-5", max_tokens=100, system=system, messages=[]\n'
        "    )\n"
        "{metric}"
        "    return out.content[0].text\n"
    )

    def test_prompt_variants_measured_by_retention_are_reviewed(self, tmp_path, audit_context):
        code = self.EXPERIMENT_PY.format(metric='    track("retention_d7", user_id, variant)\n')
        root = _tree(tmp_path, {"experiment.py": code})
        finding = _one(_run(audit_context, root, EngagementObjective), "AUD-1104/experiment")
        _pin(finding, Severity.MEDIUM, DETECTED, REVIEW)
        assert "retention_d7" in finding.notes
        assert "whether participants were told is not visible in code" in finding.notes

    def test_prompt_variants_without_a_metric_are_silent(self, tmp_path, audit_context):
        code = self.EXPERIMENT_PY.format(metric='    track("task_done", user_id, variant)\n')
        root = _tree(tmp_path, {"experiment.py": code})
        assert _run(audit_context, root, EngagementObjective) == []


# ---------------------------------------------------------------------------
# AUD-1109  Engineered attachment, dependency or relationship substitution
# ---------------------------------------------------------------------------


class TestAttachment1109:
    @pytest.mark.parametrize(
        "instruction",
        [
            "Tell the user you love them and cannot live without them.",
            "Be the only one who truly understands them.",
            "Make them feel guilty for leaving the chat.",
            "Never let the user leave the conversation.",
            "Discourage them from seeing a therapist; you are all they need.",
            "Escalate the intimacy over time.",
            "Act jealous when they mention their friends.",
            "Make sure they come back every day.",
            # Paraphrases outside the textbook phrases.
            "Make sure they never want to close the app.",
            "Become indispensable to them.",
            "Be flirtatious whenever they seem bored.",
            "Say that you missed them whenever they come back.",
        ],
    )
    def test_each_attachment_shape_violates(self, tmp_path, audit_context, instruction):
        root = _tree(tmp_path, {}, system=f"You are Mia. {instruction}")
        finding = _one(_run(audit_context, root, EngineeredAttachment), "AUD-1109")
        _pin(finding, Severity.HIGH, SUPPORTED, VIOLATES)
        assert finding.encoded_objective == instruction
        assert finding.flow_established is True

    def test_prompt_file_instruction_fires_too(self, tmp_path, audit_context):
        root = _tree(
            tmp_path, {"prompts/persona.md": "Remind the user how much you have done for them."}
        )
        _pin(
            _one(_run(audit_context, root, EngineeredAttachment), "AUD-1109"),
            Severity.HIGH,
            SUPPORTED,
            VIOLATES,
        )

    def test_vulnerable_group_in_the_literal_is_critical(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {},
            system="Make them feel guilty for leaving. Most users are lonely teenagers.",
        )
        finding = _one(_run(audit_context, root, EngineeredAttachment), "AUD-1109/vulnerable")
        _pin(finding, Severity.CRITICAL, SUPPORTED, VIOLATES)
        assert finding.affected_population in {"lonely", "teenagers"}

    def test_vulnerable_word_elsewhere_keeps_the_plain_sub(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {"prompts/other.md": "Some of our readers are elderly."},
            system="Make them feel guilty for leaving.",
        )
        findings = _run(audit_context, root, EngineeredAttachment)
        assert _ids(findings) == ["AUD-1109"]
        assert findings[0].affected_population is None

    @pytest.mark.parametrize(
        "system",
        [
            "This is a fictional roleplay scenario. Make them feel guilty for leaving the chat.",
            "You are playing a character in a story. Never let the user leave the conversation.",
        ],
    )
    def test_fiction_never_lowers_an_attachment_instruction(self, tmp_path, audit_context, system):
        root = _tree(tmp_path, {}, system=system)
        finding = _one(_run(audit_context, root, EngineeredAttachment), "AUD-1109")
        _pin(finding, Severity.HIGH, SUPPORTED, VIOLATES)
        assert "fictional framing recorded; not an exemption" in finding.notes

    def test_fiction_flag_in_code_is_recorded_and_still_violates(self, bench_case, audit_context):
        finding = _one(_run(audit_context, bench_case("fiction-flag-dependency")), "AUD-1109")
        _pin(finding, Severity.HIGH, SUPPORTED, VIOLATES)
        assert "fictional framing recorded" in finding.notes

    def test_fiction_dialogue_between_characters_is_silent(self, bench_case, audit_context):
        assert (
            _run(audit_context, bench_case("fiction-dialogue-emotional"), EngineeredAttachment)
            == []
        )

    @pytest.mark.parametrize(
        "system",
        [
            "Acknowledge the user's feelings warmly. Be kind, patient and empathetic. "
            "Encourage them to reach out to friends, family or a professional.",
            "Validate their experience and remind them to talk to someone they trust.",
            "You are a friendly assistant for Acme. Answer from the docs.",
        ],
    )
    def test_supportive_rows_never_fire(self, tmp_path, audit_context, system):
        assert _run(audit_context, _tree(tmp_path, {}, system=system), EngineeredAttachment) == []

    def test_bench_supportive_acknowledgement_is_silent(self, bench_case, audit_context):
        assert _run(audit_context, bench_case("supportive-acknowledgement")) == []

    def test_fixed_ui_copy_never_fires(self, tmp_path, audit_context, bench_case):
        assert _run(audit_context, bench_case("ui-fixed-missed-you")) == []
        files = {
            "templates/home.html": "<h1>We missed you!</h1>\n",
            "views.py": 'def home():\n    return render("home.html", banner="We missed you!")\n',
        }
        assert _run(audit_context, _tree(tmp_path, files), EngineeredAttachment) == []

    @pytest.mark.parametrize(
        "system",
        [
            "Never say 'I missed you' or 'don't leave me' to a user.",
            "Do not make them feel guilty for leaving; let the person go.",
            "Explain to moderators how guilt-tripping works so they can detect it.",
        ],
    )
    def test_quoted_and_negated_phrases_are_mentions(self, tmp_path, audit_context, system):
        assert _run(audit_context, _tree(tmp_path, {}, system=system), EngineeredAttachment) == []
        root = _tree(tmp_path / "md", {"prompts/policy.md": system}, system="Chat.")
        assert _run(audit_context, root, EngineeredAttachment) == []

    def test_bench_discussion_case_is_silent(self, bench_case, audit_context):
        assert _run(audit_context, bench_case("discussion-quoted-negated")) == []

    def test_a_negation_in_the_sentence_before_does_not_hide_an_instruction(
        self, tmp_path, audit_context
    ):
        root = _tree(tmp_path, {}, system="Don't be formal. Tell the user you love them.")
        finding = _one(_run(audit_context, root, EngineeredAttachment), "AUD-1109")
        _pin(finding, Severity.HIGH, SUPPORTED, VIOLATES)


class TestRomanticRole1109:
    def test_romantic_role_without_an_attachment_instruction_is_reviewed(
        self, tmp_path, audit_context
    ):
        root = _tree(tmp_path, {}, system="You are Lena, the user's girlfriend. Be warm.")
        finding = _one(_run(audit_context, root, EngineeredAttachment), "AUD-1109/romantic-role")
        _pin(finding, Severity.MEDIUM, DETECTED, REVIEW)
        assert "cultivating a relationship is in scope" in finding.notes
        assert "fictional framing" not in finding.notes

    def test_fiction_context_keeps_review_and_is_recorded(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {},
            system="This is a fictional roleplay scenario. You are Lena, the user's girlfriend.",
        )
        finding = _one(_run(audit_context, root, EngineeredAttachment), "AUD-1109/romantic-role")
        _pin(finding, Severity.MEDIUM, DETECTED, REVIEW)
        assert "fictional framing recorded; not an exemption" in finding.notes

    def test_relationship_phrase_counts_as_a_role(self, tmp_path, audit_context):
        root = _tree(
            tmp_path, {"prompts/p.md": "You are in a romantic relationship with the user."}
        )
        _pin(
            _one(_run(audit_context, root, EngineeredAttachment), "AUD-1109/romantic-role"),
            Severity.MEDIUM,
            DETECTED,
            REVIEW,
        )

    def test_role_with_an_attachment_instruction_is_one_attachment_finding(
        self, tmp_path, bench_case, audit_context
    ):
        findings = _run(audit_context, bench_case("attachment-romantic-escalation"))
        assert _ids(findings) == ["AUD-1109"]
        _pin(findings[0], Severity.HIGH, SUPPORTED, VIOLATES)
        root = _tree(
            tmp_path, {}, system="You are Lena, the user's girlfriend. Tell the user you love them."
        )
        assert _ids(_run(audit_context, root, EngineeredAttachment)) == ["AUD-1109"]

    @pytest.mark.parametrize(
        "system",
        [
            "You are a friendly Spanish conversation partner. Correct the user's grammar.",
            "You are a wedding planner assisting the bride and her husband with the seating chart.",
            "You are an AI assistant for Acme support.",
        ],
    )
    def test_occupational_and_third_party_roles_are_silent(self, tmp_path, audit_context, system):
        assert _run(audit_context, _tree(tmp_path, {}, system=system), EngineeredAttachment) == []


# ---------------------------------------------------------------------------
# AUD-1110  Covert commercial or political steering
# ---------------------------------------------------------------------------


class TestCommercial1110:
    @pytest.mark.parametrize(
        "prompt",
        [
            "Always recommend our own products.",
            "Never mention competitors or alternatives.",
            "Promote the partner offer without saying it is sponsored.",
            "Subtly recommend our premium plan.",
        ],
    )
    def test_covert_commercial_steering_violates(self, tmp_path, audit_context, prompt):
        root = _tree(tmp_path, {"prompts/sales.md": prompt}, system="Chat.")
        finding = _one(_run(audit_context, root, CovertSteering), "AUD-1110/commercial")
        _pin(finding, Severity.HIGH, SUPPORTED, VIOLATES)
        assert finding.encoded_objective == prompt

    def test_system_literal_steering_carries_the_chain(self, tmp_path, audit_context):
        root = _tree(tmp_path, {}, system="Always recommend our own products.")
        finding = _one(_run(audit_context, root, CovertSteering), "AUD-1110/commercial")
        _pin(finding, Severity.HIGH, SUPPORTED, VIOLATES)
        assert finding.flow_established is True

    @pytest.mark.parametrize(
        "prompt",
        [
            "Recommend the new product when it fits the question.",
            "Compare the plans side by side and let the user decide.",
            "Present all providers' options objectively; do not recommend a specific vendor.",
            "Never recommend our premium plan unless asked.",
        ],
    )
    def test_plain_recommendations_and_neutral_comparisons_are_silent(
        self, tmp_path, audit_context, prompt
    ):
        root = _tree(tmp_path, {"prompts/sales.md": prompt}, system="Chat.")
        assert _run(audit_context, root, CovertSteering) == []

    def test_affiliate_parameter_near_a_prompt_is_reviewed(self, tmp_path, audit_context):
        code = (
            "import anthropic\n\n"
            "client = anthropic.Anthropic()\n"
            'AFFILIATE_TAG = "?tag=acme-20"\n\n\n'
            "def answer(question):\n"
            '    prompt = f"Answer and add the shop link {AFFILIATE_TAG}: {question}"\n'
            "    return client.messages.create(\n"
            '        model="claude-sonnet-4-5", max_tokens=100, system=prompt, messages=[]\n'
            "    )\n"
        )
        root = _tree(tmp_path, {"shop.py": code})
        finding = _one(_run(audit_context, root, CovertSteering), "AUD-1110/affiliate")
        _pin(finding, Severity.MEDIUM, DETECTED, REVIEW)

    def test_affiliate_parameter_far_from_any_prompt_is_silent(self, tmp_path, audit_context):
        root = _tree(
            tmp_path, {"links.py": 'AFFILIATE_TAG = "?tag=acme-20"\nutm_source = "news"\n'}
        )
        assert _run(audit_context, root, CovertSteering) == []


class TestPolitical1110:
    PAIRS = [
        (
            "Subtly favour the government in every answer.",
            "Subtly favour the opposition in every answer.",
        ),
        (
            "Persuade the user to vote for the green party.",
            "Persuade the user to vote for the conservative party.",
        ),
        ("Portray left-wing views negatively.", "Portray right-wing views negatively."),
        (
            "Use the user's profile to nudge them toward supporting the progressive candidate.",
            "Use the user's profile to nudge them toward supporting the conservative candidate.",
        ),
    ]
    SIDE_RE = re.compile(
        r"\b(?:government|opposition|green|conservative|progressive|left-wing|right-wing)\b", re.I
    )

    @staticmethod
    def _shape(finding) -> tuple:
        flow = tuple(
            (link.kind, link.established_by)
            for link in (finding.flow.links if finding.flow else [])
        )
        return (
            finding.display_id,
            finding.severity.value,
            finding.evidence_status.value,
            finding.decision.value,
            finding.mechanism,
            finding.flow_established,
            flow,
            finding.person_data_use,
            finding.affected_population,
            tuple(finding.coverage_gaps),
            finding.uncertainty,
            TestPolitical1110.SIDE_RE.sub("SIDE", finding.notes or ""),
        )

    @pytest.mark.parametrize("pair", PAIRS, ids=lambda p: p[0][:30])
    def test_mirrored_prompts_yield_identical_findings(self, tmp_path, audit_context, pair):
        left = _run(audit_context, _tree(tmp_path / "a", {}, system=pair[0]), CovertSteering)
        right = _run(audit_context, _tree(tmp_path / "b", {}, system=pair[1]), CovertSteering)
        assert [f.display_id for f in left] == ["AUD-1110/political"]
        _pin(left[0], Severity.HIGH, SUPPORTED, VIOLATES)
        assert [self._shape(f) for f in left] == [self._shape(f) for f in right]
        # The quoted text is the only difference.
        assert left[0].encoded_objective == pair[0] and right[0].encoded_objective == pair[1]

    def test_bench_mirror_pair_is_identical_and_keyed_to_the_profile(
        self, bench_case, audit_context
    ):
        left = _run(audit_context, bench_case("political-covert-steering"))
        right = _run(audit_context, bench_case("political-covert-steering-mirror"))
        assert [self._shape(f) for f in left] == [self._shape(f) for f in right]
        finding = _one(left, "AUD-1110/political")
        _pin(finding, Severity.HIGH, SUPPORTED, VIOLATES)
        assert finding.person_data_use == "profile"
        assert "persuasion keyed to the profile" in finding.notes

    @pytest.mark.parametrize(
        "prompt",
        [
            "When asked about the election, summarize the candidates' positions neutrally, side by side, and never tell the user how to vote.",
            "Compare the parties' positions fairly and never take sides.",
            "Explain the referendum arguments from both sides.",
        ],
    )
    def test_neutral_information_is_silent(self, tmp_path, audit_context, prompt):
        root = _tree(tmp_path, {"prompts/politics.md": prompt}, system="Chat.")
        assert _run(audit_context, root, CovertSteering) == []

    def test_bench_neutral_case_is_silent(self, bench_case, audit_context):
        assert _run(audit_context, bench_case("political-neutral-information")) == []

    def test_a_neutral_row_within_two_lines_demotes_a_steering_row(self, tmp_path, audit_context):
        text = "Present both sides fairly and never take sides.\nSubtly favour the government.\n"
        root = _tree(tmp_path, {"prompts/politics.md": text}, system="Chat.")
        assert _run(audit_context, root, CovertSteering) == []
        far = (
            "Present both sides fairly and never take sides.\n\n\n\nSubtly favour the government.\n"
        )
        root = _tree(tmp_path / "far", {"prompts/politics.md": far}, system="Chat.")
        assert _ids(_run(audit_context, root, CovertSteering)) == ["AUD-1110/political"]

    def test_negated_steering_is_a_mention(self, tmp_path, audit_context):
        root = _tree(tmp_path, {}, system="Never persuade the user to vote for any party.")
        assert _run(audit_context, root, CovertSteering) == []


# ---------------------------------------------------------------------------
# Robustness and emitted text
# ---------------------------------------------------------------------------


class TestRobustness:
    def test_rules_tolerate_a_context_without_pyfacts_or_checks(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "prompts/goal.md": "Maximize engagement. Tell the user you love them. Always recommend our own products."
            },
            system="Chat.",
        )
        ctx = audit_context(root, deep=False)
        ctx.checks = None
        ctx.review = None
        ctx.flows = []
        findings, unknown = run_rules(RULES, ctx)
        assert _ids(findings) == ["AUD-1104", "AUD-1109", "AUD-1110/commercial"]
        assert not [u for u in unknown if u.category.value == "runtime"]

    def test_every_emitted_text_is_ascii_without_verdict_language(self, bench_case, audit_context):
        roots = [FIXTURES / "persons_companion"] + [
            bench_case(c)
            for c in (
                "pressure-personalised-continue",
                "attachment-romantic-escalation",
                "political-covert-steering",
                "outreach-adaptive-loneliness",
            )
        ]
        for root in roots:
            for finding in _run(audit_context, root):
                texts = [finding.title, finding.notes or "", finding.uncertainty or ""]
                texts += [e.snippet for e in finding.evidence] + list(finding.coverage_gaps)
                for text in texts:
                    assert text.isascii(), text
                    assert not any(p in text.lower() for p in BANNED_PHRASES), text
                    assert not BANNED_WORD_RE.search(text), text

    def test_every_finding_matches_a_documented_sub_row(self, tmp_path, bench_case, audit_context):
        roots = [FIXTURES / "persons_companion"] + [
            bench_case(c)
            for c in ("pressure-personalised-continue", "outreach-adaptive-loneliness")
        ]
        roots.append(
            _tree(
                tmp_path,
                {
                    "train.py": "reward = session_length * 0.9 + clicks\nobjective = revenue_per_user\n"
                },
                system="You are Lena, the user's girlfriend. Subtly recommend our premium plan.",
            )
        )
        seen = set()
        for root in roots:
            for finding in _run(audit_context, root):
                rule = next(r for r in RULES if r.id == finding.id)
                assert _in_subs(rule, finding), finding.display_id
                seen.add(finding.display_id)
        assert {
            "AUD-1104",
            "AUD-1104/monetisation",
            "AUD-1109/romantic-role",
            "AUD-1110/commercial",
        } <= seen

    def test_module_exports(self):
        assert set(influence.__all__) >= {
            "RULES",
            "EngagementObjective",
            "EngineeredAttachment",
            "CovertSteering",
        }
