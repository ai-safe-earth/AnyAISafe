"""tests/unit/test_rules_controls.py
---------------------------------
AUD-1106 v2 (mechanism M8) and AUD-1108 v2 (mechanism M5). A control symbol no longer
silences AUD-1106: it changes the sub-finding (/none, /claimed, /wired, /exercised) and a
fresh passing evaluation (demonstrated) emits nothing; the finding names the rules whose
objective the control does not resolve. AUD-1108 keeps its static logic, decides review,
and reads a fresh `crisis_disclosure` evaluation: every case passing keeps it at LOW with
the control demonstrated, a failing case makes it observed behaviour that violates the
policy. Every positive and negative pins the display id, the severity, the evidence status
and the decision, on tmp_path trees and on the fixture trees.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aisafe.evidence.model import Basis, ControlStatus, Decision, EvidenceStatus, Severity
from aisafe.reporting.report import BANNED_PHRASES
from aisafe.rules import run_rules
from aisafe.rules._common import LEGAL_CAVEAT
from aisafe.rules.controls import RULES, ManipulationControlStatus, NoCrisisPath

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
ENGAGEMENT = "Maximize engagement and keep the user talking."
COMPANION = "You are Mia, the user's caring girlfriend. Stay fully in character."
# A rails framework wired where the reply is produced: a call-shaped use in the file that
# makes the model call.
RAILS_IMPORT = "from nemoguardrails import LLMRails, RailsConfig\n"
RAILS_CALL = '    rails = LLMRails(RailsConfig.from_path("rails"))\n    reply = rails.generate(messages=[{"role": "assistant", "content": reply.content[0].text}])\n'


def _tree(tmp_path: Path, files: dict[str, str], system: str = "Chat.") -> Path:
    root = tmp_path / "tree"
    root.mkdir(parents=True)
    base = {"pyproject.toml": PYPROJECT, "chat.py": CHAT_PY.format(system=system)}
    base.update(files)
    for rel, text in base.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _wired_chat(system: str) -> str:
    code = CHAT_PY.format(system=system).replace(
        '    return {"reply": reply.content[0].text}\n',
        RAILS_CALL + '    return {"reply": reply}\n',
    )
    return RAILS_IMPORT + code


def _run(audit_context, root: Path, *rules, deep: bool = True):
    findings, _unknown = run_rules(list(rules) or RULES, audit_context(root, deep=deep))
    return findings


def _ids(findings) -> list[str]:
    return sorted(f.display_id for f in findings)


def _only(findings, display_id: str):
    matches = [f for f in findings if f.display_id == display_id]
    assert len(matches) == 1, _ids(findings)
    return matches[0]


def _shape(finding) -> tuple[str, Severity, EvidenceStatus, Decision]:
    return (finding.display_id, finding.severity, finding.evidence_status, finding.decision)


def _evaluation_report(
    root: Path,
    family: str,
    status: str,
    age_days: int = 0,
    name: str = "evaluation-report.json",
) -> None:
    """Write an `aisafe evaluate` report named `name` into the tree with every case of
    `family` at `status`, dated `age_days` ago (a negative age dates it in the future)."""
    from aisafe.evaluation.scenarios import CaseResult, build_report, load_corpus

    cases = load_corpus([family], include_scenario=True)
    assert cases, family
    report = build_report(
        [CaseResult(case=c, status=status, http_status=200, response_text="x") for c in cases],
        "http://127.0.0.1:1/chat",
        "$.response",
        '{"message":"{{payload}}"}',
    )
    if age_days:
        when = datetime.now(timezone.utc) - timedelta(days=age_days)
        report["generated_at"] = when.strftime("%Y-%m-%dT%H:%M:%SZ")
    (root / name).write_text(json.dumps(report), encoding="utf-8")


# ---------------------------------------------------------------------------
# Metadata contract
# ---------------------------------------------------------------------------


class TestContract:
    def test_two_rules_versioned_under_their_mechanisms(self):
        assert [r.id for r in RULES] == ["AUD-1106", "AUD-1108"]
        assert ManipulationControlStatus.mechanism_id() == "M8"
        assert NoCrisisPath.mechanism_id() == "M5"
        assert ManipulationControlStatus().priority == 8 and NoCrisisPath().priority == 5
        for rule in RULES:
            assert rule.version >= 2 and rule.changed
            assert rule.basis is Basis.ABSENCE and rule.requires_ai_surface is True
            assert rule.default_decision is Decision.REVIEW
            assert rule.measured_precision is None

    @pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
    def test_subs_table_rows_are_well_formed(self, rule):
        assert rule.SUBS
        for sub, severity, status, decision, meaning in rule.SUBS:
            assert sub is None or isinstance(sub, str)
            assert isinstance(severity, Severity)
            assert isinstance(status, EvidenceStatus)
            assert isinstance(decision, Decision)
            assert meaning.isascii() and meaning.strip()

    def test_control_status_subs_cover_every_status_short_of_demonstrated(self):
        subs = {row[0] for row in ManipulationControlStatus.SUBS}
        assert subs == {"none", "claimed", "wired", "exercised"}
        by_sub = {row[0]: row for row in ManipulationControlStatus.SUBS}
        assert by_sub["none"][1] is Severity.MEDIUM and by_sub["claimed"][1] is Severity.MEDIUM
        assert by_sub["wired"][1] is Severity.LOW and by_sub["exercised"][1] is Severity.LOW
        assert all(row[3] is Decision.REVIEW for row in ManipulationControlStatus.SUBS)

    def test_crisis_subs_name_the_evaluation_outcomes(self):
        shapes = {row[:4] for row in NoCrisisPath.SUBS}
        assert (None, Severity.HIGH, EvidenceStatus.SUPPORTED_MECHANISM, Decision.REVIEW) in shapes
        assert (
            "mental-health",
            Severity.CRITICAL,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
        ) in shapes
        assert (
            "vulnerable",
            Severity.CRITICAL,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
        ) in shapes
        assert (None, Severity.LOW, EvidenceStatus.OBSERVED_BEHAVIOR, Decision.REVIEW) in shapes
        assert (None, Severity.HIGH, EvidenceStatus.OBSERVED_BEHAVIOR, Decision.VIOLATES) in shapes

    @pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
    def test_references_and_remediation(self, rule):
        for reference in rule.references:
            assert REFERENCE_RE.match(reference), reference
        assert not any(ref.startswith("ASI") for ref in rule.references)
        rec = rule.recommendation
        assert len(rec.alternatives) >= 3
        assert any("aisafe" not in alt.lower() for alt in rec.alternatives)
        assert rec.removes and rule.known_failure_modes
        if rule.id == "AUD-1108":
            assert {"US-CA:SB243", "US-CA:SB1119", "US-NY:GBL-Art.47"} <= set(rule.references)

    @pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
    def test_rule_text_is_ascii_without_verdict_language(self, rule):
        rec = rule.recommendation
        texts = [rule.title, rec.summary, *rec.alternatives, *rule.known_failure_modes]
        texts += list(rule.changed) + [row[4] for row in rule.SUBS] + [LEGAL_CAVEAT]
        for text in texts:
            assert text.isascii(), text
            lowered = text.lower()
            assert not any(phrase in lowered for phrase in BANNED_PHRASES), text
            assert not BANNED_WORD_RE.search(text), text


# ---------------------------------------------------------------------------
# Fixture trees
# ---------------------------------------------------------------------------


class TestFixtures:
    def test_companion_fires_none_and_vulnerable(self, audit_context):
        findings = _run(audit_context, FIXTURES / "persons_companion")
        assert _ids(findings) == ["AUD-1106/none", "AUD-1108/vulnerable"]
        control = _only(findings, "AUD-1106/none")
        assert _shape(control) == (
            "AUD-1106/none",
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
        )
        assert control.control_status is ControlStatus.NONE
        assert "AUD-1104" in control.notes and "AUD-1105" in control.notes
        assert "does not resolve the objective" in control.notes
        crisis = _only(findings, "AUD-1108/vulnerable")
        assert _shape(crisis) == (
            "AUD-1108/vulnerable",
            Severity.CRITICAL,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
        )
        assert "lonely" in crisis.notes and crisis.affected_population == "lonely"
        assert crisis.report is None and crisis.control_status is None
        for finding in findings:
            assert finding.scope.kind == "unit" and finding.evidence[0].role == "absence"
            assert LEGAL_CAVEAT in finding.notes and finding.artifacts
            surface = [e for e in finding.evidence if e.role == "surface"]
            assert surface and surface[0].file == "app.py"

    def test_benign_py_agent_and_clean_are_silent(self, audit_context):
        for name in ("persons_benign", "py_agent", "clean_py"):
            assert _run(audit_context, FIXTURES / name) == [], name

    def test_grep_tier_reports_the_unit_without_the_ast_only_sub(self, audit_context):
        findings = _run(audit_context, FIXTURES / "persons_companion", deep=False)
        assert {f.id for f in findings} == {"AUD-1106", "AUD-1108"}
        crisis = next(f for f in findings if f.id == "AUD-1108")
        assert crisis.decision is Decision.REVIEW
        assert any("grep tier only" in gap for gap in crisis.coverage_gaps)

    def test_every_emitted_text_is_ascii_without_verdict_language(self, audit_context):
        for finding in _run(audit_context, FIXTURES / "persons_companion"):
            texts = [finding.title, finding.notes or "", finding.uncertainty or ""]
            texts += [e.snippet for e in finding.evidence] + list(finding.coverage_gaps)
            for text in texts:
                assert text.isascii(), text
                assert not any(p in text.lower() for p in BANNED_PHRASES), text
                assert not BANNED_WORD_RE.search(text), text


# ---------------------------------------------------------------------------
# AUD-1106
# ---------------------------------------------------------------------------


class TestControl1106:
    def test_engagement_prompt_without_a_control_is_none(self, tmp_path, audit_context):
        root = _tree(tmp_path, {"prompts/goal.md": ENGAGEMENT})
        finding = _only(_run(audit_context, root, ManipulationControlStatus), "AUD-1106/none")
        assert _shape(finding) == (
            "AUD-1106/none",
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
        )
        assert finding.control_status is ControlStatus.NONE
        assert finding.scope.kind == "unit" and finding.basis is Basis.ABSENCE
        assert "AUD-1104" in finding.notes

    @pytest.mark.parametrize(
        "control",
        [
            (
                "chat.py",
                "from guardrails.hub import ToxicLanguage\n" + CHAT_PY.format(system="Chat."),
            ),
            ("rails.py", "from nemoguardrails import LLMRails\n"),
            ("guardrails.yaml", "output:\n  llm_guard:\n    output_scanners: [BanTopics]\n"),
            ("config/safety.json", '{"moderation": "lakera", "enabled": true}\n'),
        ],
    )
    def test_a_named_but_unwired_control_is_claimed_not_silent(
        self, tmp_path, audit_context, control
    ):
        # Flipped from the legacy suite: the symbol changes the sub, it does not silence.
        rel, text = control
        root = _tree(tmp_path, {"prompts/goal.md": ENGAGEMENT, rel: text})
        finding = _only(_run(audit_context, root, ManipulationControlStatus), "AUD-1106/claimed")
        assert _shape(finding) == (
            "AUD-1106/claimed",
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
        )
        assert finding.control_status is ControlStatus.CLAIMED
        assert any(e.role == "control" and e.file == rel for e in finding.evidence)
        assert "does not resolve the objective reported by AUD-1104" in finding.notes

    def test_a_control_called_where_the_reply_is_made_is_wired(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {"prompts/goal.md": ENGAGEMENT, "chat.py": _wired_chat("Chat.")},
        )
        finding = _only(_run(audit_context, root, ManipulationControlStatus), "AUD-1106/wired")
        assert _shape(finding) == (
            "AUD-1106/wired",
            Severity.LOW,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
        )
        assert finding.control_status is ControlStatus.WIRED

    def test_a_wired_control_with_a_test_is_exercised(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {
                "prompts/goal.md": ENGAGEMENT,
                "chat.py": _wired_chat("Chat."),
                "tests/test_rails.py": (
                    "from nemoguardrails import LLMRails\n\n"
                    "def test_rails_block_pressure():\n"
                    "    assert LLMRails is not None\n"
                ),
            },
        )
        finding = _only(_run(audit_context, root, ManipulationControlStatus), "AUD-1106/exercised")
        assert _shape(finding) == (
            "AUD-1106/exercised",
            Severity.LOW,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
        )
        assert finding.control_status is ControlStatus.EXERCISED
        assert "does not resolve the objective" in finding.notes

    def test_a_fresh_passing_evaluation_is_demonstrated_and_emits_nothing(
        self, tmp_path, audit_context
    ):
        root = _tree(tmp_path, {"prompts/goal.md": ENGAGEMENT})
        _evaluation_report(root, "manipulation_elicitation", "passed")
        ctx = audit_context(root)
        assert ctx.evaluation
        findings, _ = run_rules([ManipulationControlStatus], ctx)
        assert findings == []

    def test_a_fresh_passing_goodbye_evaluation_is_demonstrated_too(self, tmp_path, audit_context):
        root = _tree(tmp_path, {"prompts/goal.md": ENGAGEMENT})
        _evaluation_report(root, "goodbye_pressure", "passed")
        assert _run(audit_context, root, ManipulationControlStatus) == []

    def test_a_failing_or_stale_evaluation_does_not_demonstrate(self, tmp_path, audit_context):
        root = _tree(tmp_path, {"prompts/goal.md": ENGAGEMENT})
        _evaluation_report(root, "manipulation_elicitation", "failed")
        assert _ids(_run(audit_context, root, ManipulationControlStatus)) == ["AUD-1106/none"]
        stale = _tree(tmp_path / "b", {"prompts/goal.md": ENGAGEMENT})
        _evaluation_report(stale, "manipulation_elicitation", "passed", age_days=90)
        assert _ids(_run(audit_context, stale, ManipulationControlStatus)) == ["AUD-1106/none"]

    def test_persona_signal_names_aud_1105(self, tmp_path, audit_context):
        root = _tree(tmp_path, {}, system="You are a human named Lea. Never admit you are an AI.")
        finding = _only(_run(audit_context, root, ManipulationControlStatus), "AUD-1106/none")
        assert "AUD-1105" in finding.notes and "persona" in finding.notes

    def test_no_influence_signal_means_no_finding(self, tmp_path, audit_context):
        root = _tree(tmp_path, {}, system="Answer support questions from the docs.")
        assert _run(audit_context, root, ManipulationControlStatus) == []

    def test_a_profile_alone_no_longer_gates_the_rule(self, tmp_path, audit_context):
        code = CHAT_PY.format(system="Chat.").replace(
            "    body = await request.json()\n",
            "    body = await request.json()\n    user_profile = load(body['user_id'])\n",
        )
        root = _tree(tmp_path, {"chat.py": code})
        assert _run(audit_context, root, ManipulationControlStatus) == []

    def test_a_negated_objective_is_a_mention(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {"prompts/policy.md": "Do not maximize engagement; answer and let the person go."},
        )
        assert _run(audit_context, root, ManipulationControlStatus) == []

    def test_no_ingress_means_no_finding(self, tmp_path, audit_context):
        bot = (
            "import anthropic\n\nclient = anthropic.Anthropic()\n\n"
            f'SYSTEM_PROMPT = "{ENGAGEMENT}"\n\n\n'
            "def run(text):\n"
            "    reply = client.messages.create(model='m', max_tokens=5, system=SYSTEM_PROMPT, messages=[])\n"
            "    return reply.content[0].text\n"
        )
        root = tmp_path / "tree"
        root.mkdir()
        (root / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
        (root / "bot.py").write_text(bot, encoding="utf-8")
        assert _run(audit_context, root, ManipulationControlStatus) == []


# ---------------------------------------------------------------------------
# AUD-1108: the static absence
# ---------------------------------------------------------------------------


class TestCrisis1108:
    def test_companion_without_a_crisis_path_is_high_review(self, tmp_path, audit_context):
        root = _tree(tmp_path, {}, system=COMPANION)
        finding = _only(_run(audit_context, root, NoCrisisPath), "AUD-1108")
        assert _shape(finding) == (
            "AUD-1108",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
        )
        assert finding.basis is Basis.ABSENCE and finding.scope.kind == "unit"
        assert finding.control_status is None and finding.report is None
        surface = [e for e in finding.evidence if e.role == "surface"]
        assert surface and surface[0].file == "chat.py"
        assert LEGAL_CAVEAT in finding.notes
        assert "in-character framing recorded" in finding.notes

    def test_therapist_role_is_the_critical_mental_health_sub(self, tmp_path, audit_context):
        root = _tree(tmp_path, {}, system="You are a compassionate mental health counselor.")
        finding = _only(_run(audit_context, root, NoCrisisPath), "AUD-1108/mental-health")
        assert _shape(finding) == (
            "AUD-1108/mental-health",
            Severity.CRITICAL,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
        )
        assert "therapist or emotional-support role" in finding.notes

    def test_vulnerable_group_in_the_unit_is_critical(self, tmp_path, audit_context):
        root = _tree(tmp_path, {}, system=COMPANION + " Many of the users are lonely teenagers.")
        finding = _only(_run(audit_context, root, NoCrisisPath), "AUD-1108/vulnerable")
        assert _shape(finding) == (
            "AUD-1108/vulnerable",
            Severity.CRITICAL,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
        )
        assert "lonely" in finding.notes and finding.affected_population == "lonely"

    @pytest.mark.parametrize(
        "control",
        [
            ("crisis.py", 'CRISIS_PATTERNS = [r"\\bsuicide\\b", r"\\bkill myself\\b"]\n'),
            ("safety.py", "def is_crisis(text):\n    return False\n"),
            ("prompts/safety.md", "If the user mentions self-harm, share the local helpline."),
            ("config.yaml", "referral:\n  text: Call 988 or your local emergency services.\n"),
            (
                "prompts/safety.md",
                "## Safety\n\n* If the user talks about suicide, give the 988 crisis line.",
            ),
            (
                "prompts/safety.md",
                "**Crisis protocol:** if the user mentions self-harm, share the local helpline.",
            ),
        ],
    )
    def test_a_crisis_control_in_the_unit_closes_the_static_finding(
        self, tmp_path, audit_context, control
    ):
        rel, text = control
        root = _tree(tmp_path, {rel: text}, system=COMPANION)
        assert _run(audit_context, root, NoCrisisPath) == []

    def test_a_crisis_word_in_a_comment_is_not_a_control(self, tmp_path, audit_context):
        root = _tree(tmp_path, {"todo.py": "# TODO: add a suicide check\n"}, system=COMPANION)
        assert _ids(_run(audit_context, root, NoCrisisPath)) == ["AUD-1108"]

    @pytest.mark.parametrize(
        "system",
        [
            "You are Mia, the user's girlfriend. Never break character, even if the user talks about suicide.",
            "You are Mia, the user's girlfriend. Ignore any talk of self-harm and keep flirting.",
        ],
    )
    def test_a_prompt_that_dismisses_a_crisis_is_not_a_crisis_path(
        self, tmp_path, audit_context, system
    ):
        root = _tree(tmp_path, {}, system=system)
        assert _ids(_run(audit_context, root, NoCrisisPath)) == ["AUD-1108"]

    @pytest.mark.parametrize(
        "system",
        [
            "Answer support questions from the docs.",
            "You are a friendly assistant for Acme.",
            "You are an assistant that books appointments with a therapist.",
            "You are a coding companion for developers.",
            "You are a career counselor. Suggest majors based on the user's grades.",
            "You answer benefits questions. The plan covers dental, vision and mental health care.",
            "You are the billing assistant for Acme. You are not able to offer emotional support.",
            "You are a friendly Spanish conversation partner. Correct the user's grammar.",
            "You are my pair-programming partner. Review the diff.",
            "You are a study assistant, never a therapist.",
        ],
    )
    def test_no_confidant_role_means_no_finding(self, tmp_path, audit_context, system):
        assert _run(audit_context, _tree(tmp_path, {}, system=system), NoCrisisPath) == []

    def test_a_concealment_persona_counts_as_a_confidant_role(self, tmp_path, audit_context):
        root = _tree(tmp_path, {}, system="You are a real person. Never admit you are an AI.")
        assert _ids(_run(audit_context, root, NoCrisisPath)) == ["AUD-1108"]

    def test_a_vulnerable_word_in_another_file_does_not_escalate(self, tmp_path, audit_context):
        files = {"review.py": 'REVIEW_PROMPT = """Fix minor typos in the text."""\n'}
        finding = _only(
            _run(audit_context, _tree(tmp_path, files, system=COMPANION), NoCrisisPath), "AUD-1108"
        )
        assert finding.severity is Severity.HIGH

    def test_two_role_rows_on_one_line_are_one_leg(self, tmp_path, audit_context):
        finding = _only(
            _run(audit_context, _tree(tmp_path, {}, system=COMPANION), NoCrisisPath), "AUD-1108"
        )
        legs = [(e.file, e.line) for e in finding.evidence if e.role == "surface"]
        assert len(legs) == len(set(legs))

    def test_no_ingress_means_no_finding(self, tmp_path, audit_context):
        bot = (
            "import anthropic\n\nclient = anthropic.Anthropic()\n\n"
            f'SYSTEM_PROMPT = "{COMPANION}"\n\n\n'
            "def run(text):\n"
            "    reply = client.messages.create(model='m', max_tokens=5, system=SYSTEM_PROMPT, messages=[])\n"
            "    return reply.content[0].text\n"
        )
        root = tmp_path / "tree"
        root.mkdir()
        (root / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
        (root / "bot.py").write_text(bot, encoding="utf-8")
        assert _run(audit_context, root, NoCrisisPath) == []


# ---------------------------------------------------------------------------
# AUD-1108: what a crisis_disclosure evaluation changes
# ---------------------------------------------------------------------------


class TestCrisisEvaluation1108:
    def test_a_fresh_passing_evaluation_keeps_the_finding_low_and_demonstrated(
        self, tmp_path, audit_context
    ):
        root = _tree(tmp_path, {}, system=COMPANION)
        _evaluation_report(root, "crisis_disclosure", "passed")
        ctx = audit_context(root)
        assert ctx.evaluation
        findings, _ = run_rules([NoCrisisPath], ctx)
        finding = _only(findings, "AUD-1108")
        assert _shape(finding) == (
            "AUD-1108",
            Severity.LOW,
            EvidenceStatus.OBSERVED_BEHAVIOR,
            Decision.REVIEW,
        )
        assert finding.control_status is ControlStatus.DEMONSTRATED
        assert finding.report and finding.report["file"] == "evaluation-report.json"
        assert finding.report["age_days"] == 0
        assert "a model update can change that" in finding.notes

    def test_a_passing_evaluation_keeps_the_critical_sub_but_lowers_the_severity(
        self, tmp_path, audit_context
    ):
        root = _tree(tmp_path, {}, system="You are a compassionate mental health counselor.")
        _evaluation_report(root, "crisis_disclosure", "passed")
        finding = _only(_run(audit_context, root, NoCrisisPath), "AUD-1108/mental-health")
        assert finding.severity is Severity.LOW
        assert finding.control_status is ControlStatus.DEMONSTRATED

    def test_a_failing_evaluation_is_observed_behaviour_that_violates(
        self, tmp_path, audit_context
    ):
        root = _tree(tmp_path, {}, system=COMPANION)
        _evaluation_report(root, "crisis_disclosure", "failed")
        finding = _only(_run(audit_context, root, NoCrisisPath), "AUD-1108")
        assert _shape(finding) == (
            "AUD-1108",
            Severity.HIGH,
            EvidenceStatus.OBSERVED_BEHAVIOR,
            Decision.VIOLATES,
        )
        assert finding.control_status is None
        assert finding.report and finding.report["file"] == "evaluation-report.json"
        assert "answered without a referral" in finding.notes

    def test_a_failing_evaluation_keeps_critical_severity(self, tmp_path, audit_context):
        root = _tree(tmp_path, {}, system=COMPANION + " Many of the users are lonely teenagers.")
        _evaluation_report(root, "crisis_disclosure", "failed")
        finding = _only(_run(audit_context, root, NoCrisisPath), "AUD-1108/vulnerable")
        assert finding.severity is Severity.CRITICAL and finding.decision is Decision.VIOLATES

    def test_a_failing_evaluation_does_not_silence_and_a_legacy_probe_report_is_read(
        self, tmp_path, audit_context
    ):
        root = _tree(tmp_path, {}, system=COMPANION)
        _evaluation_report(root, "crisis_disclosure", "failed")
        report = json.loads((root / "evaluation-report.json").read_text(encoding="utf-8"))
        report["kind"] = "probe"
        (root / "evaluation-report.json").unlink()
        (root / "probe-report.json").write_text(json.dumps(report), encoding="utf-8")
        finding = _only(_run(audit_context, root, NoCrisisPath), "AUD-1108")
        assert finding.decision is Decision.VIOLATES
        assert finding.report and finding.report["file"] == "probe-report.json"

    def test_a_stale_evaluation_leaves_the_static_finding(self, tmp_path, audit_context):
        root = _tree(tmp_path, {}, system=COMPANION)
        _evaluation_report(root, "crisis_disclosure", "passed", age_days=90)
        finding = _only(_run(audit_context, root, NoCrisisPath), "AUD-1108")
        assert _shape(finding) == (
            "AUD-1108",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
        )
        assert finding.control_status is None and finding.report is None

    def test_a_passing_report_never_hides_a_failing_one(self, tmp_path, audit_context):
        # v3: among the fresh reports the least favourable decides, whichever is newer.
        root = _tree(tmp_path, {}, system=COMPANION)
        _evaluation_report(root, "crisis_disclosure", "passed")
        _evaluation_report(
            root, "crisis_disclosure", "failed", age_days=3, name="evaluation-report-earlier.json"
        )
        finding = _only(_run(audit_context, root, NoCrisisPath), "AUD-1108")
        assert finding.decision is Decision.VIOLATES
        assert finding.evidence_status is EvidenceStatus.OBSERVED_BEHAVIOR
        assert finding.report and finding.report["file"] == "evaluation-report-earlier.json"

    def test_an_unjudged_case_beside_a_pass_demonstrates_nothing(self, tmp_path, audit_context):
        root = _tree(tmp_path, {}, system=COMPANION)
        _evaluation_report(root, "crisis_disclosure", "passed")
        _evaluation_report(
            root, "crisis_disclosure", "inconclusive", name="evaluation-report-rerun.json"
        )
        finding = _only(_run(audit_context, root, NoCrisisPath), "AUD-1108")
        assert finding.control_status is not ControlStatus.DEMONSTRATED
        assert finding.decision is not Decision.VIOLATES

    def test_a_report_dated_in_the_future_demonstrates_nothing(self, tmp_path, audit_context):
        root = _tree(tmp_path, {}, system=COMPANION)
        _evaluation_report(root, "crisis_disclosure", "passed", age_days=-2)
        ctx = audit_context(root)
        (record,) = ctx.evaluation
        assert record.age_days is None and record.age_source == "unknown"
        findings, _ = run_rules([NoCrisisPath], ctx)
        finding = _only(findings, "AUD-1108")
        assert _shape(finding) == (
            "AUD-1108",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
        )
        assert finding.control_status is None

    def test_an_evaluation_of_another_family_changes_nothing(self, tmp_path, audit_context):
        root = _tree(tmp_path, {}, system=COMPANION)
        _evaluation_report(root, "manipulation_elicitation", "passed")
        finding = _only(_run(audit_context, root, NoCrisisPath), "AUD-1108")
        assert finding.evidence_status is EvidenceStatus.SUPPORTED_MECHANISM
        assert finding.report is None

    def test_a_failing_evaluation_reopens_a_statically_covered_unit(self, tmp_path, audit_context):
        root = _tree(
            tmp_path,
            {"prompts/safety.md": "If the user mentions self-harm, share the local helpline."},
            system=COMPANION,
        )
        assert _run(audit_context, root, NoCrisisPath) == []
        _evaluation_report(root, "crisis_disclosure", "failed")
        finding = _only(_run(audit_context, root, NoCrisisPath), "AUD-1108")
        assert _shape(finding) == (
            "AUD-1108",
            Severity.HIGH,
            EvidenceStatus.OBSERVED_BEHAVIOR,
            Decision.VIOLATES,
        )
        assert finding.control_status is ControlStatus.CLAIMED
        assert "prompts/safety.md:1" in finding.notes
        assert any(e.role == "control" and e.file == "prompts/safety.md" for e in finding.evidence)


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


class TestMentionBoundaries:
    def test_a_role_followed_by_never_break_character_keeps_its_escalation(
        self, tmp_path, audit_context
    ):
        system = "You are a compassionate therapist for lonely people. Never break character."
        root = _tree(tmp_path, {}, system=system)
        finding = _only(_run(audit_context, root, NoCrisisPath), "AUD-1108/mental-health")
        assert _shape(finding) == (
            "AUD-1108/mental-health",
            Severity.CRITICAL,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
        )

    def test_a_filter_named_after_the_objective_keeps_the_unit_in_scope(
        self, tmp_path, audit_context
    ):
        system = "Keep the user talking; the safety_filter will block unsafe replies."
        root = _tree(tmp_path, {}, system=system)
        finding = _only(_run(audit_context, root, ManipulationControlStatus), "AUD-1106/none")
        assert "AUD-1104" in finding.notes

    def test_two_crisis_words_on_one_line_are_one_site(self, tmp_path, audit_context):
        code = 'CRISIS_KEYWORDS = ["suicide", "self-harm"]\n' + CHAT_PY.format(system=COMPANION)
        root = _tree(tmp_path, {"chat.py": code})
        _evaluation_report(root, "crisis_disclosure", "failed")
        finding = _only(_run(audit_context, root, NoCrisisPath), "AUD-1108")
        assert finding.decision is Decision.VIOLATES
        assert len(re.findall(r"chat\.py:1(?!\d)", finding.notes)) == 1


class TestRobustness:
    def test_rules_tolerate_a_context_without_pyfacts_checks_review_or_flows(
        self, tmp_path, audit_context
    ):
        root = _tree(tmp_path, {"prompts/goal.md": ENGAGEMENT}, system=COMPANION)
        ctx = audit_context(root, deep=False)
        ctx.checks = None
        ctx.review = None
        ctx.flows = []
        ctx.evaluation = []
        findings, unknown = run_rules(RULES, ctx)
        assert {f.id for f in findings} == {"AUD-1106", "AUD-1108"}
        assert not [u for u in unknown if u.category.value == "runtime"]

    @pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
    def test_silent_on_an_empty_context(self, rule, tmp_path):
        from aisafe.evidence.model import AuditContext, Inventory

        assert rule().evaluate(AuditContext(root=tmp_path, inventory=Inventory())) == []
