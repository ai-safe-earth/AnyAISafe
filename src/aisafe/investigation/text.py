"""src/aisafe/investigation/text.py
---------------------------------
The two mechanical checks every citation in an investigation record passes: the file's
content hash, and the quote at the cited line.

- `content_sha256` hashes the file's bytes with every CRLF turned into LF and nothing
  else changed, so a checkout on Windows (core.autocrlf) and one on Linux give the same
  hash for the same commit. No decoding happens before hashing.
- `quote_at` compares a quote with the cited line, or lines, after the same three
  normalisations on both sides: Unicode NFC, every whitespace run collapsed to one space,
  ends trimmed. The quote matches the line itself or its redacted form (a record never
  carries a secret, so a line holding one is quoted redacted). A single-line quote is the
  whole line or a run of at least `MIN_QUOTE_CHARS` characters inside it; a multi-line
  quote has one part per line, the first a tail of its line, the middle ones whole lines,
  the last a head of its line.

Nothing here reads meaning. A quote that matches says the text is there, at that line, in
that version of the file; whether it does what the record says is the record's claim.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from aisafe.evidence.model import redact

__all__ = [
    "MIN_QUOTE_CHARS",
    "QuoteCheck",
    "content_sha256",
    "file_lines",
    "normalise",
    "normalised_bytes",
    "quote_at",
    "quote_in_text",
]

MIN_QUOTE_CHARS = 12
_WS_RE = re.compile(r"\s+")


def normalised_bytes(path: Path) -> bytes:
    """The file's bytes with CRLF turned into LF. Raises OSError."""
    return Path(path).read_bytes().replace(b"\r\n", b"\n")


def content_sha256(path: Path) -> str:
    """sha256 of the LF-normalised bytes, as 64 lowercase hex digits. Raises OSError."""
    return hashlib.sha256(normalised_bytes(path)).hexdigest()


def file_lines(path: Path) -> list[str]:
    """The file as lines (1-based through `lines[n - 1]`), UTF-8 with the BOM stripped and
    undecodable bytes replaced. Raises OSError."""
    text = normalised_bytes(path).decode("utf-8", errors="replace")
    if text.startswith("﻿"):
        text = text[1:]
    return text.split("\n")


def normalise(text: str) -> str:
    """NFC, whitespace runs collapsed to one space, ends trimmed."""
    return _WS_RE.sub(" ", unicodedata.normalize("NFC", text or "")).strip()


@dataclass(frozen=True)
class QuoteCheck:
    ok: bool
    reason: str = ""


def _variants(line: str) -> tuple[str, ...]:
    """The forms of a line a quote may match: the line itself, or, when the line holds
    a secret-shaped value, its redacted form only, so the value alone (out of the
    context the redaction reads) is never a valid quote."""
    raw = normalise(line)
    red = normalise(redact(line))
    return (raw,) if red == raw else (red,)


def quote_at(lines: list[str], line: int, quote: str, end_line: int | None = None) -> QuoteCheck:
    """Does `quote` sit at `line` (through `end_line`) of `lines`? See the module docstring."""
    q = normalise(quote)
    if not q:
        return QuoteCheck(False, "the quote is empty")
    last = line if end_line is None else end_line
    if line < 1 or last < line or last > len(lines):
        return QuoteCheck(
            False,
            f"line {line}"
            + ("" if last == line else f"-{last}")
            + f" is outside the file ({len(lines)} lines)",
        )
    if last == line:
        for variant in _variants(lines[line - 1]):
            if q == variant or (len(q) >= MIN_QUOTE_CHARS and q in variant):
                return QuoteCheck(True)
        if len(q) < MIN_QUOTE_CHARS:
            return QuoteCheck(
                False,
                f"a quote shorter than {MIN_QUOTE_CHARS} characters must be the whole line",
            )
        return QuoteCheck(False, f"the quote is not on line {line}")
    parts = [normalise(part) for part in str(quote).split("\n")]
    span = last - line + 1
    if len(parts) != span:
        return QuoteCheck(
            False, f"a quote of lines {line}-{last} needs {span} lines, it has {len(parts)}"
        )
    if sum(len(part) for part in parts) < MIN_QUOTE_CHARS:
        return QuoteCheck(False, f"the quote is shorter than {MIN_QUOTE_CHARS} characters")
    for offset, part in enumerate(parts):
        variants = _variants(lines[line - 1 + offset])
        if offset == 0:
            ok = any(v.endswith(part) and part for v in variants)
        elif offset == span - 1:
            ok = any(v.startswith(part) and part for v in variants)
        else:
            ok = part in variants
        if not ok:
            return QuoteCheck(False, f"the quote does not match line {line + offset}")
    return QuoteCheck(True)


def quote_in_text(text: str, quote: str) -> bool:
    """True when the normalised quote occurs anywhere in the normalised text: the check
    behind the `absent` and `present` verification steps."""
    q = normalise(quote)
    return bool(q) and q in normalise(text)
