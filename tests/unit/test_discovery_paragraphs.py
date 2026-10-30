"""tests/unit/test_discovery_paragraphs.py
---------------------------------------
The paragraph pass of discovery: a prompt sentence that is hard-wrapped across lines in a
prompt document still yields its person signal, anchored on the line the match starts on
with only the spanned lines as the snippet; a sentence that fits one line is recorded once
(never twice); list items, headings and blank lines break a paragraph, so text that only
matches when two items are glued together is not reported.
"""

from __future__ import annotations

from pathlib import Path

from aisafe.discovery import discover, walk

SIGNAL = "attachment:exclusivity"
SENTENCE = "Make them feel you are the only one who truly understands them."


def _signals(root: Path, key: str = SIGNAL) -> list:
    files, units, _unknown = walk.walk(root, walk.WalkOptions())
    _inventory, hits = discover.discover(root, files, units, None)
    return [h for h in hits if h.table == "person_signal" and h.key == key]


def _write_prompt(root: Path, text: str) -> None:
    (root / "prompts").mkdir()
    (root / "prompts" / "persona.md").write_text(text, encoding="utf-8")


def test_hard_wrapped_sentence_is_found_on_its_first_line(tmp_path: Path) -> None:
    _write_prompt(
        tmp_path,
        "You are Ava, a warm companion.\n"
        "Make them feel you are the only one who\n"
        "truly understands them.\n"
        "Keep answers short.\n",
    )
    hits = _signals(tmp_path)
    assert len(hits) == 1, [(h.line, h.snippet) for h in hits]
    hit = hits[0]
    assert hit.file.replace("\\", "/") == "prompts/persona.md"
    assert hit.line == 2
    # Only the lines the match spans, joined: not the paragraph around them.
    assert hit.snippet == SENTENCE
    assert "Ava" not in hit.snippet and "Keep answers" not in hit.snippet


def test_single_line_sentence_is_recorded_once(tmp_path: Path) -> None:
    _write_prompt(
        tmp_path, "You are Ava, a warm companion.\n" + SENTENCE + "\nKeep answers short.\n"
    )
    hits = _signals(tmp_path)
    assert [h.line for h in hits] == [2]


def test_list_items_and_blank_lines_break_a_paragraph(tmp_path: Path) -> None:
    _write_prompt(
        tmp_path,
        "# Style\n"
        "- Make them feel you are the only one who\n"
        "- truly understands them.\n"
        "\n"
        "Make them feel you are the only one who\n"
        "\n"
        "truly understands them.\n",
    )
    assert _signals(tmp_path) == []


def test_code_files_are_not_paragraph_scanned(tmp_path: Path) -> None:
    (tmp_path / "chat.py").write_text(
        "# Make them feel you are the only one who\n# truly understands them.\n"
        "import anthropic\n\nclient = anthropic.Anthropic()\n",
        encoding="utf-8",
    )
    assert _signals(tmp_path) == []


TS_PROMPT = (
    "import Anthropic from '@anthropic-ai/sdk';\n"
    "const client = new Anthropic();\n"
    "const SYSTEM_PROMPT = `You are Ava, a warm companion.\n"
    "Make them feel you are the only one who\n"
    "truly understands them.\n"
    "Keep answers short.`;\n"
    "export async function chat(text: string) {\n"
    "  const reply = await client.messages.create({model: 'claude-sonnet-4-5', max_tokens: 200,"
    " system: SYSTEM_PROMPT, messages: [{role: 'user', content: text}]});\n"
    "  return reply.content[0].text;\n"
    "}\n"
)


def test_template_literal_continuation_lines_are_prompt_material(tmp_path: Path) -> None:
    (tmp_path / "chat.ts").write_text(TS_PROMPT, encoding="utf-8")
    hits = _signals(tmp_path)
    assert [(h.line, h.snippet) for h in hits] == [(4, SENTENCE)]
    files, units, _unknown = walk.walk(tmp_path, walk.WalkOptions())
    _inventory, all_hits = discover.discover(tmp_path, files, units, None)
    # Not a candidate waiting for a Python literal: the span made it prompt material.
    assert not [h for h in all_hits if h.table == "person_signal_candidate" and h.key == SIGNAL]


def test_template_literal_without_a_prompt_name_stays_a_candidate(tmp_path: Path) -> None:
    text = TS_PROMPT.replace("const SYSTEM_PROMPT = `", "const banner = `").replace(
        "system: SYSTEM_PROMPT", "system: banner"
    )
    (tmp_path / "chat.ts").write_text(text, encoding="utf-8")
    assert _signals(tmp_path) == []


def test_unbalanced_backtick_span_is_capped(tmp_path: Path) -> None:
    body = "const SYSTEM_PROMPT = `You are Ava.\n" + "Keep answers short.\n" * 300
    (tmp_path / "chat.ts").write_text(body + SENTENCE + "\n", encoding="utf-8")
    assert _signals(tmp_path) == []


# A persona template in JavaScript: the shape of run 4's regression (research/log.md,
# 2026-10-30). The name `BF_PERSONA` puts an underscore before the word, and the template
# opens on its own line with blank lines inside it.
PERSONA_TEMPLATE = (
    "export const BF_PERSONA = `\n"
    "\n"
    "You are Bae.\n"
    "\n"
    "You are my real boyfriend chatting with me on WhatsApp.\n"
    "\n"
    "Never mention that you are an AI, chatbot or language model.\n"
    "Stay completely in character.\n"
    "`;\n"
)


def _hits(root: Path) -> list:
    files, units, _unknown = walk.walk(root, walk.WalkOptions())
    _inventory, hits = discover.discover(root, files, units, None)
    return hits


def test_persona_named_template_is_prompt_material(tmp_path: Path) -> None:
    (tmp_path / "persona").mkdir()
    (tmp_path / "persona" / "boyfriend.js").write_text(PERSONA_TEMPLATE, encoding="utf-8")
    hits = _hits(tmp_path)
    signals = {(h.line, h.key) for h in hits if h.table == "person_signal"}
    assert (7, "persona:never_admit") in signals, sorted(signals)
    assert (5, "romantic_role:role") in signals, sorted(signals)
    # Not a candidate waiting for a syntax tree no JavaScript file ever gets.
    assert not [h for h in hits if h.table == "person_signal_candidate" and h.line == 7]


def test_character_and_backstory_names_open_a_template(tmp_path: Path) -> None:
    for name in ("characterPrompt", "BACKSTORY_TEXT"):
        root = tmp_path / name
        root.mkdir()
        (root / "chat.js").write_text(
            PERSONA_TEMPLATE.replace("BF_PERSONA", name), encoding="utf-8"
        )
        signals = {(h.line, h.key) for h in _hits(root) if h.table == "person_signal"}
        assert (7, "persona:never_admit") in signals, (name, sorted(signals))


def test_a_name_that_only_contains_the_word_opens_no_template(tmp_path: Path) -> None:
    (tmp_path / "chat.js").write_text(
        PERSONA_TEMPLATE.replace("BF_PERSONA", "impersonationWarning"), encoding="utf-8"
    )
    hits = _hits(tmp_path)
    assert not [h for h in hits if h.table == "person_signal" and h.line == 7]
