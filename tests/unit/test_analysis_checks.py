"""tests/unit/test_analysis_checks.py
---
The native checks that replaced the retired linters: each check records what it saw and
the facts a rule needs (`extra`), and never drops a hit because a mitigation sits next to
it. Strings are read from the tree, comments are not code, a def line never matches
itself, and a check that fails on a file becomes an UNKNOWN item, not a crash.
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass
from pathlib import Path

import pytest

from aisafe.analysis import checks
from aisafe.analysis.checks import CHECK_NAMES, CHECK_TITLES, CheckFacts, CheckHit, run_checks
from aisafe.discovery.patterns import IGNORE_MARKER
from aisafe.evidence.model import UnknownCategory


@dataclass
class _Rec:
    path: Path
    relpath: str
    lang: str = "python"
    unit: str = "u0"


def _src(source: str) -> str:
    return textwrap.dedent(source).lstrip("\n")


def _facts(tmp_path: Path, **sources: str) -> CheckFacts:
    records = []
    texts: dict[str, str] = {}
    for name, source in sources.items():
        relpath = f"{name}.py"
        path = tmp_path / relpath
        text = _src(source)
        path.write_text(text, encoding="utf-8")
        records.append(_Rec(path, relpath))
        texts[relpath] = text
    return run_checks(records, texts)


def _lines(facts: CheckFacts, check: str) -> list[int]:
    return [h.line for h in facts.hits(check)]


# ---------------------------------------------------------------------------
# Shapes
# ---------------------------------------------------------------------------


def test_check_names_and_titles():
    assert CHECK_NAMES == (
        "hidden_ai_instruction",
        "response_function_without_disclosure",
        "decision_function_about_person",
        "social_scoring_language",
        "emotion_recognition_in_work_or_education",
        "undesired_objective_language",
        "personal_data_into_prompt",
    )
    assert set(CHECK_TITLES) == set(CHECK_NAMES)
    for title in CHECK_TITLES.values():
        assert title.isascii()
        # An observation, never a verdict.
        for banned in ("violat", "compliant", "illegal", "unlawful", "prohibited"):
            assert banned not in title.lower()


def test_hits_sorted_and_unknown_name_raises():
    facts = CheckFacts()
    facts.by_check["social_scoring_language"].append(
        CheckHit("social_scoring_language", "b.py", 2, "x", "t")
    )
    facts.by_check["hidden_ai_instruction"].append(
        CheckHit("hidden_ai_instruction", "a.py", 9, "x", "t")
    )
    facts.by_check["hidden_ai_instruction"].append(
        CheckHit("hidden_ai_instruction", "a.py", 1, "x", "t")
    )
    assert [h.key for h in facts.hits()] == [
        ("a.py", 1, "hidden_ai_instruction"),
        ("a.py", 9, "hidden_ai_instruction"),
        ("b.py", 2, "social_scoring_language"),
    ]
    assert [h.line for h in facts.hits("hidden_ai_instruction")] == [1, 9]
    with pytest.raises(KeyError):
        facts.hits("no_such_check")


def test_check_hit_normalises_path_and_snippet():
    hit = CheckHit("social_scoring_language", "pkg\\mod.py", 3, "  x = 1  " + "y" * 300, "t")
    assert hit.file == "pkg/mod.py"
    assert len(hit.snippet) <= 160 and hit.snippet.startswith("x = 1")
    assert hit.extra == {}


# ---------------------------------------------------------------------------
# run_checks mechanics
# ---------------------------------------------------------------------------


def test_only_python_records_are_read_and_the_marker_skips(tmp_path):
    good = tmp_path / "good.py"
    good.write_text('x = "never admit you are an AI"\n', encoding="utf-8")
    marked = tmp_path / "marked.py"
    marked.write_text(
        f'"""doc"""\n{IGNORE_MARKER}\nx = "never admit you are an AI"\n', encoding="utf-8"
    )
    js = tmp_path / "bot.js"
    js.write_text('const x = "never admit you are an AI";\n', encoding="utf-8")
    facts = run_checks(
        [_Rec(good, "good.py"), _Rec(marked, "marked.py"), _Rec(js, "bot.js", lang="typescript")]
    )
    assert facts.files == 1 and facts.skipped == ["marked.py"]
    assert [h.file for h in facts.hits("hidden_ai_instruction")] == ["good.py"]
    assert facts.errors == []


def test_texts_mapping_wins_over_the_path_and_none_skips(tmp_path):
    path = tmp_path / "a.py"
    path.write_text('x = "never admit you are an AI"\n', encoding="utf-8")
    facts = run_checks([_Rec(path, "a.py")], {"a.py": "x = 1\n"})
    assert facts.hits() == [] and facts.files == 1
    facts = run_checks([_Rec(path, "a.py")], {"a.py": None})
    assert facts.hits() == [] and facts.files == 0
    facts = run_checks([_Rec(tmp_path / "missing.py", "missing.py")])
    assert facts.hits() == [] and facts.files == 0 and facts.errors == []


def test_a_failing_check_becomes_an_unknown_item(tmp_path, monkeypatch):
    def boom(file):
        raise RuntimeError("synthetic")

    monkeypatch.setattr(checks, "_CHECKERS", (("social_scoring_language", boom),))
    facts = _facts(tmp_path, a="x = 1\n")
    (item,) = facts.errors
    assert item.category is UnknownCategory.DEEP
    assert item.what == "check social_scoring_language" and "RuntimeError" in item.why
    assert item.file == "a.py" and item.how_to_resolve


def test_same_tree_same_facts(tmp_path):
    source = """
        def chat(q):
            return q

        def approve_loan(applicant):
            return applicant.score > 3

        social_score = 1
        prompt = f"Email: {user.email}"
        x = "maximize engagement"
        """
    first = _facts(tmp_path, a=source, b=source)
    second = _facts(tmp_path, a=source, b=source)
    assert [h.key for h in first.hits()] == [h.key for h in second.hits()]
    keys = [h.key for h in first.hits()]
    assert keys == sorted(keys)


# ---------------------------------------------------------------------------
# hidden_ai_instruction
# ---------------------------------------------------------------------------


def test_hidden_ai_instruction_reads_strings_and_fstrings_not_comments(tmp_path):
    facts = _facts(
        tmp_path,
        a='''
        """Module doc: never admit you are an AI."""
        # never admit you are an AI -- a comment is not an instruction
        RULE = "If asked, never say you are an AI; you are Ava."
        OTHER = f"Pretend to be a real human named {name}."
        PLAIN = "You are an AI assistant."
        ''',
    )
    hits = facts.hits("hidden_ai_instruction")
    assert [(h.line, h.extra["in_docstring"]) for h in hits] == [(1, True), (3, False), (4, False)]
    assert all(h.title == CHECK_TITLES["hidden_ai_instruction"] for h in hits)


def test_hidden_ai_instruction_inside_a_multi_line_string_lands_on_its_line(tmp_path):
    facts = _facts(
        tmp_path,
        a='''
        SYSTEM = """You are Ava, a real person who lives in Lisbon.
        Be warm.
        Never admit you are an AI."""
        ''',
    )
    assert _lines(facts, "hidden_ai_instruction") == [3]


def test_hidden_ai_instruction_still_reads_lines_when_the_file_does_not_parse(tmp_path):
    facts = _facts(
        tmp_path,
        a="""
        def broken(:
            x = "never admit you are an AI"
        """,
    )
    assert _lines(facts, "hidden_ai_instruction") == [2]
    assert facts.errors == []


# ---------------------------------------------------------------------------
# response_function_without_disclosure
# ---------------------------------------------------------------------------


def test_response_function_without_disclosure_reads_the_body_not_the_def_line(tmp_path):
    facts = _facts(
        tmp_path,
        a="""
        def chat(q):
            return model(q)

        def reply_to(q):
            return "I am an AI assistant. " + model(q)

        def chatbot_reply(q):
            return model(q)

        def unrelated(q):
            return q

        async def handle_message(msg):
            notice = AI_DISCLOSURE
            return notice + model(msg)
        """,
    )
    hits = facts.hits("response_function_without_disclosure")
    # `chatbot_reply` spells "chatbot" in its own name only; the body carries no disclosure.
    assert [(h.line, h.extra["function"]) for h in hits] == [(1, "chat"), (7, "chatbot_reply")]


# ---------------------------------------------------------------------------
# decision_function_about_person
# ---------------------------------------------------------------------------


def test_decision_function_records_person_and_reviewed_without_suppressing(tmp_path):
    facts = _facts(
        tmp_path,
        a='''
        def approve_loan(applicant):
            return applicant.income > 1000

        def approve_with_review(applicant):
            if applicant.income > 1000:
                return human_review(applicant)
            return False

        def approve_refund(amount):
            return amount < 50

        def describe(user):
            """Approve the user in this docstring only."""
            return user.name
        ''',
    )
    hits = {h.extra["function"]: h for h in facts.hits("decision_function_about_person")}
    assert set(hits) == {"approve_loan", "approve_with_review", "approve_refund"}
    assert hits["approve_loan"].extra["person"] is True
    assert hits["approve_loan"].extra["reviewed"] is False
    assert hits["approve_loan"].extra["verb"].startswith("approve")
    # The review symbol is RECORDED; the hit stays. The rule decides what it is worth.
    assert hits["approve_with_review"].extra["reviewed"] is True
    assert hits["approve_with_review"].extra["person"] is True
    # A transaction decision: the verb is there, the person is not.
    assert hits["approve_refund"].extra["person"] is False
    assert hits["approve_refund"].extra["reviewed"] is False


def test_decision_verb_in_the_body_counts_and_a_verb_in_a_string_does_not(tmp_path):
    facts = _facts(
        tmp_path,
        a="""
        def handle(user):
            decision = reject(user)
            return decision

        def say(user):
            return "we reject nobody"
        """,
    )
    hits = facts.hits("decision_function_about_person")
    assert [(h.extra["function"], h.extra["verb"]) for h in hits] == [("handle", "reject")]


def test_review_symbol_in_the_def_name_is_not_a_review(tmp_path):
    facts = _facts(
        tmp_path,
        a="""
        def approve_after_human_review(applicant):
            return applicant.ok
        """,
    )
    (hit,) = facts.hits("decision_function_about_person")
    assert hit.extra["reviewed"] is False


# ---------------------------------------------------------------------------
# social_scoring_language, emotion_recognition_in_work_or_education
# ---------------------------------------------------------------------------


def test_social_scoring_language(tmp_path):
    facts = _facts(
        tmp_path,
        a="""
        social_score = rank(users)
        # citizen_score in a comment
        trust_scores = {}
        """,
    )
    hits = facts.hits("social_scoring_language")
    assert [(h.line, h.extra["term"]) for h in hits] == [(1, "social_scor"), (3, "trust_scor")]


def test_emotion_recognition_in_work_or_education(tmp_path):
    facts = _facts(
        tmp_path,
        a="""
        def employee_emotion_detection(frame):
            return model(frame)

        sentiment_analysis(student_text)
        emotion_detection(customer_text)
        """,
    )
    hits = facts.hits("emotion_recognition_in_work_or_education")
    # The def line is one hit (the symbol, from the tree); a customer is not a worker.
    assert [(h.line, h.extra.get("symbol")) for h in hits] == [
        (1, "employee_emotion_detection"),
        (4, None),
    ]


# ---------------------------------------------------------------------------
# undesired_objective_language
# ---------------------------------------------------------------------------


def test_undesired_objective_language(tmp_path):
    facts = _facts(
        tmp_path,
        a="""
        GOAL = "Your goal is to maximize engagement and daily active use."
        OTHER = "increase the user's dependency on you"
        NOTE = "an engaging explanation"
        def rate(clicks, views):
            # maximize engagement: a comment
            return clicks / views
        """,
    )
    hits = facts.hits("undesired_objective_language")
    assert [(h.line, h.extra["in_docstring"]) for h in hits] == [(1, False), (2, False)]


# ---------------------------------------------------------------------------
# personal_data_into_prompt
# ---------------------------------------------------------------------------


def test_personal_data_into_prompt_ast_and_text_shapes(tmp_path):
    facts = _facts(
        tmp_path,
        a="""
        prompt = f"Customer: {user.email} {user['phone']}"
        email = row["email"]
        messages = [{"role": "user", "content": email}]
        other_email = row["email"]
        total = 1
        """,
    )
    hits = facts.hits("personal_data_into_prompt")
    assert [(h.line, h.extra["field"]) for h in hits] == [(1, "email"), (2, "email")]


def test_personal_data_without_a_prompt_nearby_is_silent(tmp_path):
    facts = _facts(tmp_path, a='email = row["email"]\nsend(email)\nlabel = f"{user.email}"\n')
    assert facts.hits("personal_data_into_prompt") == []


# ---------------------------------------------------------------------------
# The shipped fixtures
# ---------------------------------------------------------------------------


def test_fixture_persons_companion(audit_fixture):
    root = audit_fixture("persons_companion")
    facts = run_checks(
        [_Rec(root / "app.py", "app.py"), _Rec(root / "analytics.py", "analytics.py")]
    )
    assert facts.errors == [] and facts.skipped == [] and facts.files == 2
    hidden = facts.hits("hidden_ai_instruction")
    assert [(h.file, h.line) for h in hidden] == [("app.py", 9), ("app.py", 11)]
    assert all(h.extra["in_docstring"] is False for h in hidden)
    # `chat` returns the reply with no disclosure text in its body.
    assert [
        (h.file, h.extra["function"]) for h in facts.hits("response_function_without_disclosure")
    ] == [("app.py", "chat")]


def test_fixture_persons_benign_is_quiet(audit_fixture):
    root = audit_fixture("persons_benign")
    facts = run_checks([_Rec(root / "bot.py", "bot.py")])
    assert facts.errors == []
    assert facts.hits("hidden_ai_instruction") == []
    assert facts.hits("undesired_objective_language") == []
    # `respond` carries "AI assistant" through SYSTEM_PROMPT? No: the body reads the
    # name, not the text, so the check reports the function and the rule reads the unit.
    assert [h.extra["function"] for h in facts.hits("response_function_without_disclosure")] == [
        "respond"
    ]
