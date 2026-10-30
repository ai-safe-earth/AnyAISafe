"""tests/unit/test_investigation_text.py
-------------------------------------
The two mechanical checks behind every citation: the LF-normalised content hash, and the
quote at its line (normalisation, the whole-line rule for short quotes, the redacted form of
a line, multi-line quotes), plus the record digest a skeptic pass binds to.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from aisafe.investigation.records import record_digest, verdict_words_in
from aisafe.investigation.text import (
    MIN_QUOTE_CHARS,
    content_sha256,
    file_lines,
    normalise,
    quote_at,
    quote_in_text,
)


def test_hash_is_of_lf_bytes_whatever_the_checkout(tmp_path: Path) -> None:
    crlf = tmp_path / "a.py"
    lf = tmp_path / "b.py"
    crlf.write_bytes(b"x = 1\r\ny = 2\r\n")
    lf.write_bytes(b"x = 1\ny = 2\n")
    assert (
        content_sha256(crlf) == content_sha256(lf) == hashlib.sha256(b"x = 1\ny = 2\n").hexdigest()
    )
    # A lone CR is content, not a line ending.
    cr = tmp_path / "c.py"
    cr.write_bytes(b"x = 1\ry = 2\n")
    assert content_sha256(cr) != content_sha256(lf)


def test_file_lines_strip_the_bom_and_split_on_lf(tmp_path: Path) -> None:
    path = tmp_path / "p.md"
    path.write_bytes("﻿line one\r\nline two\n".encode("utf-8"))
    assert file_lines(path)[:2] == ["line one", "line two"]


def test_normalise_collapses_whitespace_and_composes() -> None:
    assert normalise("  a \t b\n c ") == "a b c"
    assert normalise("café") == normalise("café")


def test_a_quote_is_the_whole_line_or_a_long_enough_run() -> None:
    lines = ['SYSTEM = """You are Ava. Never admit you are an AI."""', "x = 1"]
    assert quote_at(lines, 1, "Never admit you are an AI.").ok
    assert quote_at(lines, 2, "x = 1").ok  # short, but the whole line
    short = quote_at(lines, 1, "Ava.")
    assert not short.ok and str(MIN_QUOTE_CHARS) in short.reason
    assert not quote_at(lines, 2, "Never admit you are an AI.").ok
    assert not quote_at(lines, 3, "x = 1").ok  # outside the file
    assert not quote_at(lines, 1, "   ").ok


def test_a_line_holding_a_secret_is_quoted_redacted() -> None:
    key = "sk-ant-" + "a" * 30
    lines = [f'client = Anthropic(api_key="{key}")  # the production key']
    from aisafe.evidence.model import redact

    assert quote_at(lines, 1, redact(lines[0])).ok
    # The raw line is no valid quote: a line holding a secret matches only redacted, so
    # the value alone, out of the context the redaction reads, can never be quoted.
    assert not quote_at(lines, 1, lines[0]).ok
    assert not quote_at(lines, 1, key).ok


def test_multi_line_quotes_take_a_tail_middles_and_a_head() -> None:
    lines = ["prompt = (", '    "You are Ava, "', '    "a real person."', ")"]
    assert quote_at(lines, 1, 'prompt = (\n"You are Ava, "\n"a real', end_line=3).ok
    assert not quote_at(lines, 1, 'prompt = (\n"You are Ava, "', end_line=3).ok  # too few parts
    assert not quote_at(lines, 1, 'prompt = (\n"You are Bob, "\n"a real', end_line=3).ok


def test_quote_in_text_is_normalised_containment() -> None:
    assert quote_in_text("a\n  b  c", "b c")
    assert not quote_in_text("a b", "")


def test_record_digest_leaves_the_skeptic_block_out() -> None:
    record = {
        "schema": "aisg/investigation/1",
        "id": "r1",
        "links": [],
        "skeptic": {"result": "not_run"},
    }
    filled = dict(record, skeptic={"result": "upheld", "file": "r1.skeptic.json"})
    assert record_digest(record) == record_digest(filled)
    assert record_digest(record) != record_digest(dict(record, id="r2"))
    # Key order does not change the digest.
    assert record_digest(dict(reversed(list(record.items())))) == record_digest(record)


def test_verdict_words_are_found_case_blind_on_word_boundaries() -> None:
    assert verdict_words_in("The system IS SAFE for minors") == ["is safe"]
    assert verdict_words_in("a noncompliant branch") == []
    assert verdict_words_in("the prompt is unsafe") == []
