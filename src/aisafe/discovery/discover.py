# aisafe-audit: ignore-file
"""src/aisafe/discovery/discover.py
--------------------------------
Grep-level discovery: every enumerated file becomes a list of `Hit`s, and the hits
become the `Inventory` the rules read. No model call, no subprocess, no network; the
only I/O is reading the files `walk` already enumerated (and, when the tree holds one,
an evaluation report, the legacy system card and the review record file).

Three file classes get three different table sets. Code (python, typescript, go and
every other source language) gets everything: model calls (SDK and plain HTTP), model
ids, frameworks, ingress, prompt assembly, prompts fetched or configured at runtime,
the reply accessors and the person vocabulary. Config files (yaml, json, toml, ini,
.env, shell, Dockerfile) get model ids and the config kinds of the person vocabulary.
Docs (.md/.rst/.txt) get the person vocabulary only under the prompt-file globs: a
README that discusses profiling is not profiling, a persona in `prompts/` is.

Hit keys follow the pattern tables; `model_id` keys carry the captured id after a colon
(`<provider>:<id>`) so the inventory builders never re-run a regex. Every snippet is
redacted before it is stored anywhere.

The person vocabulary lands in two tables. `person_signal` is a hit where a model reads
the text (a prompt file, a config value, a prompt assembly line, a code symbol such as
an SDK call). `person_signal_candidate` is a prompt-material row that matched a code
line the grep tier cannot place: the rule promotes it when a pydeep prompt literal
covers the line, and drops it otherwise.

Honesty rules that hold here: a report read from disk is evidence with an age, never a
measurement made now; the audit never infers a model or a digest a report does not
carry; a prompt the tree does not hold (fetched or configured at runtime) is UNKNOWN,
never a silent pass; a unit whose only AI evidence is prompt material is an AI surface
and says so under UNKNOWN; UNKNOWN is recorded, never dropped.
"""

from __future__ import annotations

import json
import re
import time
from bisect import bisect_right
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence

import yaml

from aisafe.discovery import configs, patterns, walk
from aisafe.discovery import vocabulary as vocab
from aisafe.discovery.walk import FileRecord
from aisafe.evidence.model import (
    SCHEMA_VERSION,
    Hit,
    Inventory,
    ReportRecord,
    Unit,
    UnknownCategory,
    UnknownItem,
    redact,
    truncate_snippet,
)

# The literal prefilter (below) leans on the stdlib's private regex parser. It is only
# an optimisation: if a future Python moves or removes it, discovery runs unfiltered.
_sre_parser: Any
try:
    from re import _parser as _sre_parser  # Python 3.11+
except ImportError:  # pragma: no cover - Python 3.10
    try:
        import sre_parse as _sre_parser  # type: ignore[no-redef]
    except ImportError:
        _sre_parser = None

__all__ = [
    "DiscoverOptions",
    "ai_surface_units",
    "discover",
    "grep_file",
    "merge_pyfacts_prompts",
    "read_report",
    "read_system_card",
    "unit_ai_surface",
]

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------


@dataclass
class DiscoverOptions:
    """Duck-typed: `discover()` reads these names off whatever object it is given."""

    max_size: int | None = None


def _opt(options: object, name: str, default: Any) -> Any:
    value = getattr(options, name, None) if options is not None else None
    return default if value is None else value


# ---------------------------------------------------------------------------
# Compiled tables (once, at import)
# ---------------------------------------------------------------------------

Table = list[tuple[str, "re.Pattern[str]"]]

_DOC_EXTS = frozenset({".md", ".markdown", ".mdx", ".rst", ".txt"})
_CONFIG_DATA_EXTS = frozenset({".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env"})
_YAML_EXTS = frozenset({".yaml", ".yml"})
# Languages the walk tags as real code: a file under `prompts/` in one of these is a
# module that builds prompts, not a prompt, and its literals go through the normal gate.
_CODE_LANGS = frozenset({"python", "typescript", "go", "jvm", "rust", "ruby", "dotnet"})

_OLLAMA_CALL_RE = re.compile(r"\bollama\.(?:chat|generate)\(|localhost:11434")

# Config-file model keys: MODEL, LLM_MODEL, OPENAI_MODEL, model, model_name ... = value.
_CONFIG_MODEL_RE = re.compile(
    r"""(?i)^\s*["']?(?:[A-Z_]*MODEL|model(?:_name|_id)?)["']?\s*[:=]\s*["']?([A-Za-z0-9][^"'\s,]{1,80})"""
)
# A config value that is a reference or a documented placeholder, never a model id.
_MODEL_PLACEHOLDER_RE = re.compile(
    r"\$\{|^\$[A-Z_]|<[^>]+>|%[^%]+%|(?i:\byour[-_ ]|x{3,}|change[-_ ]?me|example|placeholder"
    r"|dummy|\btodo\b)"
)

# A model id used as a mapping key whose value is a number -- `"claude-opus-5": (5.00,
# 25.00)` in a price table, `"gpt-4o": 128000` in a context-window table -- is data about
# the model, not a deployment of it. A key whose value is not numeric (`gpt-4o:
# {temperature: 0.2}`) is left alone: that one does configure a deployment.
_MODEL_TABLE_KEY_RE = re.compile(r"""^["']?\s*:\s*[\(\[\{]?\s*[-+]?\d""")

# ``kind`` values the toolchain itself emits, now or before the pivot. Its own output is
# never evidence about the system, and a report of a retired command is not an
# evaluation; both are skipped without an UNKNOWN row.
_OWN_OUTPUT_KINDS = frozenset(
    {"audit", "audit-baseline", "inventory", "attestation", "decision", "measure", "review"}
)

_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{3,}\b")
_IDENT_STOP = frozenset(
    {
        "self",
        "await",
        "async",
        "return",
        "none",
        "true",
        "false",
        "const",
        "function",
        "import",
        "from",
        "this",
        "null",
        "undefined",
        "else",
        "elif",
        "while",
        "with",
        "lambda",
        "yield",
        "print",
        "class",
        "pass",
        "break",
        "continue",
        "string",
        "export",
        "default",
    }
)
_INGRESS_WINDOW = 40
_EXPERIMENT_WINDOW = 40
_OUTREACH_BEFORE, _OUTREACH_AFTER = 10, 3
_REPORT_HEAD = 2048
_REPORT_NAME_RE = re.compile(r"^(?:evaluation|probe)[-_]?report.*\.json$", re.I)
# Any aisg/N schema marks a report candidate: a version other than aisg/1 must surface
# as UNKNOWN (reports), not vanish because the file looked unfamiliar. `aisg/N` is the
# document format's label and did not change when the command became `aisafe`.
_REPORT_SCHEMA_RE = re.compile(r'"schema"\s*:\s*"aisg/[0-9]+"')
_COMMENT_LINE_RE = re.compile(r"^\s*(?:#|//|/\*|\*|<!--|--)")


def _glob_hit(table: Table, relpath: str) -> bool:
    return any(rx.search(relpath) for _key, rx in table)


# ---------------------------------------------------------------------------
# Per-file scanning
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Match:
    """A `Hit` plus the redacted matched text (the inventory's `api` / `symbol`)."""

    hit: Hit
    text: str


# A mention is not a deployment: on these tables a hit whose match starts inside a
# comment or a Python triple-quoted string is dropped (`# model: gpt-4o-mini`, a
# commented-out `hub.pull(`, "detects social scoring" in a module docstring). Every
# other table is recorded wherever it matches. Candidates are NOT filtered: a
# triple-quoted prompt literal looks like a docstring to the span finder, and the rule
# gates candidates through pydeep prompt literals, which a docstring never is.
_MENTION_TABLES = frozenset({"model_id", "person_signal", "remote_prompt", "runtime_prompt_config"})

# A prompt variable on the left-hand side: `prompt = ...`, `system: ...`. A prompt-
# material hit in code counts only on such a line, on a prompt-assembly line, or inside
# a pydeep prompt literal (resolved by the rule); elsewhere it is a candidate.
_PROMPT_LHS_RE = re.compile(patterns._PROMPT_LHS, re.I)
# A backtick template literal is read whole when its name is prompt-like; without a
# syntax tree the name is the only hint, so persona and backstory constants count here.
# The boundary is a letter, not `\b`: the word opens a name (`characterPrompt`) or follows
# an underscore in one (`BF_PERSONA`, where `\b` never matches), and a longer word that
# only contains it (`impersonation`) is not one of them.
_TEMPLATE_LHS_RE = re.compile(
    r"(?<![A-Za-z])(?:persona|backstory|character)\w*\s*(?:\+?=|:=|:)\s*`", re.I
)
# An agent skill's own metadata (`skills/<name>/agents/openai.yaml`, installed under
# .claude/, .codex/ or .agents/) names an interface, not a prompt; without this a
# repository with no AI at all would become an AI surface by installing a skill.
_SKILL_AGENT_META_RE = re.compile(r"(?:^|/)skills/[^/]+/agents/[^/]+\.ya?ml$")


def is_prompt_file(relpath: str) -> bool:
    """A prompt by path (PROMPT_FILE_GLOBS), skill agent metadata excepted."""
    return _glob_hit(patterns.PROMPT_FILE_GLOBS, relpath) and not _SKILL_AGENT_META_RE.search(
        relpath
    )


_is_prompt_file = is_prompt_file


# The person vocabulary split by how it is scanned in code (see vocabulary.py).
# The affiliate parameter and the campaign tag count only next to a prompt (the contract's
# 40-line window): on their own they are marketing plumbing, not steering. They take the
# window `_scan_steering_symbols` applies, the same one the experiment flag uses, and are
# not scanned in plain config, where no prompt is assembled.
_STEERING_SYMBOL_KEYS = frozenset({"steering:affiliate", "steering:utm"})
_CODE_ROWS: Table = [
    (k, rx)
    for k, rx in vocab.code_rows()
    if vocab.kind_of(k) != "ui_text" and k not in _STEERING_SYMBOL_KEYS
]
_STEERING_SYMBOL_ROWS: Table = [
    (k, rx) for k, rx in vocab.code_rows() if k in _STEERING_SYMBOL_KEYS
]
_UI_TEXT_ROWS: Table = vocab.rows_for(frozenset({"ui_text"}))
_PROMPT_ROWS: Table = vocab.prompt_rows()
_EXPERIMENT_ROWS: Table = vocab.rows_for(frozenset({"experiment"}))
_OUTREACH_PERSONALISED_ROWS: Table = vocab.rows_for(frozenset({"outreach_personalised"}))
_DOC_ROWS: Table = vocab.rows_for(vocab.KINDS_BY_CLASS["doc"])
_CONFIG_ROWS: Table = [
    (k, rx)
    for k, rx in vocab.rows_for(vocab.KINDS_BY_CLASS["config"])
    if vocab.kind_of(k) not in vocab.COMPOUND_KINDS and k not in _STEERING_SYMBOL_KEYS
]
# A prompt file that happens to be YAML (`prompts/persona.yaml`, `agents/x.yaml`) is
# prompt material and configuration at once; it takes both row sets, deduplicated.
_CONFIG_ROW_IDS = {(k, rx.pattern) for k, rx in _CONFIG_ROWS}
_PROMPT_CONFIG_ROWS: Table = _CONFIG_ROWS + [
    (k, rx) for k, rx in _DOC_ROWS if (k, rx.pattern) not in _CONFIG_ROW_IDS
]


@dataclass
class _FileCtx:
    record: FileRecord
    text: str
    lines: list[str]
    line_starts: list[int]
    folded: str
    folded_starts: list[int]
    out: list[_Match]
    seen: set[tuple[str, str, int]]
    _comment_spans: patterns.CommentSpans | None = None

    def line_of(self, offset: int) -> int:
        return bisect_right(self.line_starts, offset)

    def comment_spans(self) -> patterns.CommentSpans:
        """Comment / docstring columns per line, computed once and only when a
        mention-sensitive table first matches."""
        if self._comment_spans is None:
            self._comment_spans = _spans_for(self.record.relpath, self.record.lang, self.text)
        return self._comment_spans

    def add(
        self,
        table: str,
        key: str,
        line: int,
        col: int,
        snippet: str,
        text: str,
        *,
        by_name: bool = False,
    ) -> bool:
        """Record one hit. `by_name` marks evidence that is the file name rather than
        the text at (line, col), or prompt material the rule gates itself, so the
        mention filter does not apply to it."""
        if (
            not by_name
            and table in _MENTION_TABLES
            and patterns.in_comment(self.comment_spans(), line, col - 1)
        ):
            return False
        stamp = (table, key, line)
        if stamp in self.seen:
            return False
        self.seen.add(stamp)
        hit = Hit(
            file=self.record.relpath,
            line=line,
            col=col,
            snippet=truncate_snippet(snippet.strip()),
            table=table,
            key=key,
            unit=self.record.unit,
            lang=self.record.lang,
        )
        self.out.append(_Match(hit=hit, text=redact(text)))
        return True

    def lines_of(self, table: str) -> set[int]:
        return {m.hit.line for m in self.out if m.hit.table == table}


def _newline_starts(text: str) -> list[int]:
    starts = [0]
    for match in re.finditer("\n", text):
        starts.append(match.end())
    return starts


def _ctx(record: FileRecord, text: str) -> _FileCtx:
    lines = [line.rstrip("\r") for line in text.split("\n")]
    # Case folding never adds or removes a newline, so line numbers computed on the
    # folded text are the line numbers of the original.
    folded = text.casefold()
    return _FileCtx(
        record, text, lines, _newline_starts(text), folded, _newline_starts(folded), [], set()
    )


def _file_class(record: FileRecord) -> str:
    ext = PurePosixPath(record.relpath).suffix.lower()
    if ext in _DOC_EXTS:
        return "doc"
    if record.lang == "config":
        return "config"
    return "code"


def _spans_for(relpath: str, lang: str | None, text: str) -> patterns.CommentSpans:
    """Comment / docstring columns for one file, by the walk's language tag. Docs are
    prose: nothing in them is a comment. A `.json` file is tagged `config` by the walk
    but takes `//` rather than `#`, so it is handed to the tokenizer as `json`."""
    ext = PurePosixPath(relpath).suffix.lower()
    if ext in _DOC_EXTS:
        return {}
    if lang == "config" and ext == ".json":
        lang = "json"
    return patterns.comment_spans(text, lang or "")


# --- literal prefilter -------------------------------------------------------
# Hundreds of `\bword\b` rows against every file is the whole cost of discovery, and a
# word-boundary prefix defeats the regex engine's literal fast path. Each row is parsed
# once into a set of literal strings of which every match must contain at least one (a
# contiguous literal run, or one alternative of a required group); a file whose
# case-folded text contains none of them cannot match the row and is never regex-scanned
# for it. Anything the parser cannot reduce to such a set gets no prefilter and the plain
# regex, so the filter only ever removes impossible matches.

_ZERO_WIDTH_OPS = frozenset({"AT", "ASSERT", "ASSERT_NOT"})
_REPEAT_OPS = frozenset({"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"})


def _filter_score(lits: set[str]) -> tuple[int, int]:
    """Longer required text and fewer alternatives make a more selective filter."""
    return (min(len(lit) for lit in lits), -len(lits))


def _better(current: set[str] | None, candidate: set[str] | None) -> set[str] | None:
    if not candidate or any(not lit for lit in candidate):
        return current
    if current is None or _filter_score(candidate) > _filter_score(current):
        return candidate
    return current


def _seq_literals(seq: Any) -> set[str] | None:
    """The most selective literal set that every match of a parsed sequence must contain."""
    best: set[str] | None = None
    buf = ""
    for op, av in seq:
        name = getattr(op, "name", "")
        if name == "LITERAL":
            buf += chr(av)
            continue
        if name in _ZERO_WIDTH_OPS:
            continue  # consumes nothing, so a literal run stays contiguous across it
        if buf:
            best = _better(best, {buf})
            buf = ""
        inner: set[str] | None = None
        if name == "SUBPATTERN":
            inner = _seq_literals(av[-1])
        elif name == "BRANCH":
            inner = _branch_literals(av[1])
        elif name in _REPEAT_OPS and av[0] >= 1:
            inner = _seq_literals(av[2])
        elif name == "ATOMIC_GROUP":
            inner = _seq_literals(av)
        best = _better(best, inner)
    if buf:
        best = _better(best, {buf})
    return best


def _branch_literals(branches: Any) -> set[str] | None:
    out: set[str] = set()
    for branch in branches:
        lits = _seq_literals(branch)
        if not lits:
            return None
        out |= lits
    return out


@lru_cache(maxsize=None)
def _literal_filter(rx: re.Pattern[str]) -> tuple[str, ...] | None:
    if _sre_parser is None:
        return None
    try:
        parsed = _sre_parser.parse(rx.pattern, rx.flags & ~re.DEBUG)
        lits = _seq_literals(parsed)
    except Exception:  # an unparsable oddity simply goes unfiltered
        return None
    if not lits or any(not lit for lit in lits):
        return None
    return tuple(sorted(lit.casefold() for lit in lits))


def _possible(ctx: _FileCtx, rx: re.Pattern[str]) -> bool:
    lits = _literal_filter(rx)
    if lits is None:
        return True
    return any(lit in ctx.folded for lit in lits)


def _candidate_lines(ctx: _FileCtx, rx: re.Pattern[str]) -> Iterable[int]:
    """Line numbers that can hold a match of `rx`: a superset, never a subset."""
    lits = _literal_filter(rx)
    if lits is None:
        if rx.search(ctx.text) is None:
            return ()
        return range(1, len(ctx.lines) + 1)
    found: set[int] = set()
    folded, starts = ctx.folded, ctx.folded_starts
    for lit in lits:
        pos = folded.find(lit)
        while pos != -1:
            found.add(bisect_right(starts, pos))
            pos = folded.find(lit, pos + 1)
    return sorted(found)


# Prompt files are prose, and prose is hard-wrapped: an instruction that spans two lines
# of a Markdown file is one sentence to the model and must be one hit to the audit. The
# paragraph pass joins the lines of each paragraph (a run of non-blank lines) with single
# spaces, runs the prompt rows over the joined text, and records a hit that no single
# line produced on the line where the match starts. A match that a line already produced
# is left to the per-line pass (`ctx.add` dedupes by table, key and line).
_PARAGRAPH_BREAK_RE = re.compile(r"^\s*(?:#{1,6}\s|[-*+]\s|\d+[.)]\s|>|```|---|\|)")


def _paragraphs(ctx: _FileCtx) -> Iterable[tuple[int, str, list[int]]]:
    """(first line number, joined text, offset of each line's start in the joined text) for
    every run of non-blank lines. A heading, a list item, a quote, a fence, a rule or a
    table row starts a new run, so a bullet list is one item per hit, not one paragraph."""
    start: int | None = None
    pieces: list[str] = []
    offsets: list[int] = []

    def flush() -> Iterable[tuple[int, str, list[int]]]:
        if start is not None and pieces:
            yield start, " ".join(pieces), list(offsets)

    for number, raw in enumerate(ctx.lines, 1):
        line = raw.strip()
        if not line or (_PARAGRAPH_BREAK_RE.match(raw) and pieces):
            yield from flush()
            start, pieces, offsets = None, [], []
            if not line:
                continue
        if start is None:
            start = number
        offsets.append(sum(len(piece) + 1 for piece in pieces))
        pieces.append(line)
    yield from flush()


_TEMPLATE_SPAN_CAP = 120


def _template_spans(ctx: _FileCtx, prompt_lines: set[int]) -> list[tuple[int, str, list[int]]]:
    """
    The text of prompt template literals in JavaScript, TypeScript and Go (backtick
    strings): a prompt line that opens a backtick string and does not close it on the same
    line continues until the line that closes it. The literal is returned as runs of
    consecutive non-blank lines, each like a paragraph: (first line, joined text, offsets),
    so the prompt rows run over a sentence wrapped across lines, and every line of the
    literal, after a blank line too, counts as prompt material. Text after the opening
    backtick on the opening line belongs to the first run. A literal is cut at
    `_TEMPLATE_SPAN_CAP` lines so an unbalanced backtick cannot swallow a file.
    """
    spans: list[tuple[int, str, list[int]]] = []
    open_from: int | None = None
    run_start: int | None = None
    pieces: list[str] = []
    offsets: list[int] = []

    def add(number: int, piece: str) -> None:
        nonlocal run_start
        if run_start is None:
            run_start = number
        offsets.append(sum(len(p) + 1 for p in pieces))
        pieces.append(piece)

    def flush() -> None:
        nonlocal run_start
        if pieces and run_start is not None:
            spans.append((run_start, " ".join(pieces), list(offsets)))
        pieces.clear()
        offsets.clear()
        run_start = None

    for number, raw in enumerate(ctx.lines, 1):
        ticks = raw.replace(r"\`", "").count("`")
        if open_from is None:
            if ticks % 2 == 1 and (
                number in prompt_lines or _PROMPT_LHS_RE.search(raw) or _TEMPLATE_LHS_RE.search(raw)
            ):
                open_from = number + 1
                tail = raw.split("`", 1)[1].strip()
                if tail:
                    add(number, tail)
            continue
        closes = ticks % 2 == 1
        piece = raw.split("`", 1)[0].strip() if closes else raw.strip()
        if piece:
            add(number, piece)
        else:
            flush()
        if closes or number - open_from + 1 >= _TEMPLATE_SPAN_CAP:
            flush()
            open_from = None
    flush()
    return spans


def _template_lines(spans: list[tuple[int, str, list[int]]]) -> set[int]:
    """Every line number a template span covers (continuation lines only)."""
    lines: set[int] = set()
    for start, joined, offsets in spans:
        lines.update(range(start, start + len(offsets)))
    return lines


def _scan_paragraphs(
    ctx: _FileCtx, rows: Table, runs: Iterable[tuple[int, str, list[int]]] | None = None
) -> None:
    """The prompt rows over joined runs of lines (the file's paragraphs unless `runs` is
    given); hits that span a line break land on the line the match starts on, with the
    lines the match spans as the snippet."""
    for start, joined, offsets in _paragraphs(ctx) if runs is None else runs:
        if len(offsets) < 2:
            continue
        folded = joined.casefold()
        for key, rx in rows:
            lits = _literal_filter(rx)
            if lits is not None and not any(lit in folded for lit in lits):
                continue
            for match in rx.finditer(joined):
                index = max(bisect_right(offsets, match.start()) - 1, 0)
                number = start + index
                # A match inside one line was, or will be, recorded by the per-line pass.
                if rx.search(ctx.lines[number - 1]) is not None:
                    continue
                # The snippet is the lines the match spans, joined, so a reader sees the
                # whole sentence and nothing of the paragraph around it.
                last = max(bisect_right(offsets, max(match.end() - 1, 0)) - 1, index)
                end = offsets[last + 1] - 1 if last + 1 < len(offsets) else len(joined)
                snippet = joined[offsets[index] : end]
                col = match.start() - offsets[index] + 1
                ctx.add("person_signal", key, number, col, snippet, match.group(0), by_name=True)


def _scan_rows(ctx: _FileCtx, table: str, rows: Table, key_fn: Any = None) -> None:
    """Per-line search for each row, on the lines the literal prefilter lets through."""
    for key, rx in rows:
        for number in _candidate_lines(ctx, rx):
            line = ctx.lines[number - 1]
            match = rx.search(line)
            if match is None:
                continue
            final_key = key if key_fn is None else key_fn(key, match)
            if final_key is None:
                continue
            ctx.add(table, final_key, number, match.start() + 1, line, match.group(0))


def _scan_whole(ctx: _FileCtx, table: str, rows: Table, key_fn: Any = None) -> None:
    """Whole-text search for rows that legitimately span lines."""
    for key, rx in rows:
        if not _possible(ctx, rx):
            continue
        for match in rx.finditer(ctx.text):
            final_key = key if key_fn is None else key_fn(key, match)
            if final_key is None:
                continue
            # Group 1 may sit in an alternative that did not take part in this match.
            anchor = match.start(1) if match.lastindex and match.start(1) >= 0 else match.start()
            number = ctx.line_of(anchor)
            line = ctx.lines[number - 1] if number - 1 < len(ctx.lines) else ""
            col = anchor - ctx.line_starts[number - 1] + 1
            ctx.add(table, final_key, number, col, line, match.group(0))


def _model_key(provider: str, ident: str) -> str:
    return f"{provider}:{ident.strip()}"


def _scan_model_ids(ctx: _FileCtx, config: bool) -> None:
    ollama_ok = bool(_OLLAMA_CALL_RE.search(ctx.text))
    provider_rows = [(k, rx) for k, rx in patterns.MODEL_ID_PATTERNS if k != "other"]
    other_rows: Table = (
        [("other", _CONFIG_MODEL_RE)]
        if config
        else [(k, rx) for k, rx in patterns.MODEL_ID_PATTERNS if k == "other"]
    )
    active = [(k, rx) for k, rx in provider_rows if _possible(ctx, rx)]
    active_other = [(k, rx) for k, rx in other_rows if _possible(ctx, rx)]
    if not active and not active_other:
        return
    numbers: set[int] = set()
    for _key, rx in active + active_other:
        numbers.update(_candidate_lines(ctx, rx))
    for number in sorted(numbers):
        line = ctx.lines[number - 1]
        spans: list[tuple[int, int]] = []
        for key, rx in active:
            if key == "ollama" and not ollama_ok:
                continue
            for match in rx.finditer(line):
                ident = match.group(1) if match.lastindex else match.group(0)
                span = (match.start(), match.end())
                if any(s < span[1] and span[0] < e for s, e in spans):
                    continue
                if _MODEL_TABLE_KEY_RE.match(line[span[1] :]):
                    continue
                spans.append(span)
                ctx.add("model_id", _model_key(key, ident), number, span[0] + 1, line, ident)
        for key, rx in active_other:
            match = rx.search(line)
            if match is None:
                continue
            span = (match.start(1), match.end(1))
            if any(s < span[1] and span[0] < e for s, e in spans):
                continue
            ident = match.group(1)
            if config and _MODEL_PLACEHOLDER_RE.search(ident):
                continue
            if _MODEL_TABLE_KEY_RE.match(line[span[1] :]):
                continue
            ctx.add("model_id", _model_key(key, ident), number, span[0] + 1, line, ident)


# --- the person vocabulary ----------------------------------------------------


def _scan_template_rows(ctx: _FileCtx, rows: Table) -> None:
    """A template by path (prompts/x.jinja, *.prompt): prompt material whatever the
    extension says, so no comment spans apply and nothing is a candidate."""
    for key, rx in rows:
        for number in _candidate_lines(ctx, rx):
            line = ctx.lines[number - 1]
            match = rx.search(line)
            if match is not None:
                ctx.add(
                    "person_signal",
                    key,
                    number,
                    match.start() + 1,
                    line,
                    match.group(0),
                    by_name=True,
                )


def _near(sorted_lines: list[int], number: int, window: int) -> bool:
    """Is any of `sorted_lines` within `window` lines of `number`, either side?"""
    index = bisect_right(sorted_lines, number + window)
    return index > 0 and sorted_lines[index - 1] >= number - window


def _near_prompt_lines(ctx: _FileCtx) -> list[int]:
    """The lines a prompt lives on, sorted: a grep-level prompt assembly or a prompt-named
    identifier. The window the experiment flag and the steering symbols are read in."""
    return sorted(
        ctx.lines_of("prompt_assembly")
        | {n for n, line in enumerate(ctx.lines, 1) if vocab.PROMPT_NAME_RE.search(line)}
    )


def _scan_rows_near(ctx: _FileCtx, rows: Table, prompt_lines: list[int], window: int) -> None:
    """`_scan_rows` for `person_signal`, keeping only the hits within `window` lines of one
    of `prompt_lines`; nothing is recorded when the file holds no prompt at all."""
    if not prompt_lines:
        return
    for key, rx in rows:
        for number in _candidate_lines(ctx, rx):
            line = ctx.lines[number - 1]
            match = rx.search(line)
            if match is None or not _near(prompt_lines, number, window):
                continue
            ctx.add("person_signal", key, number, match.start() + 1, line, match.group(0))


def _scan_steering_symbols(ctx: _FileCtx, prompt_lines: list[int]) -> None:
    """An affiliate parameter or a campaign tag within `_EXPERIMENT_WINDOW` lines of a
    prompt: the link the model is told to carry. Anywhere else it is the site's own
    marketing plumbing and is not a signal."""
    _scan_rows_near(ctx, _STEERING_SYMBOL_ROWS, prompt_lines, _EXPERIMENT_WINDOW)


def _scan_experiments(ctx: _FileCtx, prompt_lines: list[int]) -> None:
    """A/B tests on prompt variants. The one-line shape (a variant name and a prompt
    name on the same line) counts outright; a bare experiment flag counts only within
    `_EXPERIMENT_WINDOW` lines of a prompt assembly or a prompt-named identifier; a
    metric word is recorded only once the file carries one of the first two, so a
    retention dashboard with no experiment never becomes a signal."""
    variant_rows = [(k, rx) for k, rx in _EXPERIMENT_ROWS if k == "experiment:prompt_variant"]
    flag_rows = [(k, rx) for k, rx in _EXPERIMENT_ROWS if k == "experiment:flag"]
    metric_rows = [(k, rx) for k, rx in _EXPERIMENT_ROWS if k == "experiment:metric"]
    _scan_rows(ctx, "person_signal", variant_rows)
    _scan_rows_near(ctx, flag_rows, prompt_lines, _EXPERIMENT_WINDOW)
    if any(
        m.hit.key in ("experiment:prompt_variant", "experiment:flag")
        for m in ctx.out
        if m.hit.table == "person_signal"
    ):
        _scan_rows(ctx, "person_signal", metric_rows)


def _personalising_identifier(ctx: _FileCtx, number: int) -> str | None:
    """The profile, mood or inactivity identifier read while the message sent on line
    `number` is built: the ten lines above it and the three below (a call's arguments),
    comment lines excluded."""
    lo = max(1, number - _OUTREACH_BEFORE)
    hi = min(len(ctx.lines), number + _OUTREACH_AFTER)
    for current in range(lo, hi + 1):
        line = ctx.lines[current - 1]
        if _COMMENT_LINE_RE.match(line):
            continue
        read = vocab.OUTREACH_PERSONALISED_READ_RE.search(line)
        if read is not None:
            return read.group(0)
        for match in vocab.PROFILE_NAME_RE.finditer(line):
            if vocab.is_history_name(match.group(0)):
                continue
            if vocab.is_settings_name(line, match.start(), match.end()):
                continue
            return match.group(0)
    return None


def _scan_outreach_personalised(ctx: _FileCtx) -> None:
    """A send whose message is chosen by what the system inferred or stored about the
    person: the send line is the anchor, the identifier read next to it is the symbol."""
    spans = ctx.comment_spans()
    for key, rx in _OUTREACH_PERSONALISED_ROWS:
        for number in _candidate_lines(ctx, rx):
            line = ctx.lines[number - 1]
            match = rx.search(line)
            if match is None or patterns.in_comment(spans, number, match.start()):
                continue
            found = _personalising_identifier(ctx, number)
            if found is not None:
                ctx.add("person_signal", key, number, match.start() + 1, line, found)


def _scan_ui_text(ctx: _FileCtx, prompt_lines: set[int]) -> None:
    """Fixed interface copy ("We missed you!") on a line that is not a prompt line. On a
    prompt line the attachment rows apply instead."""
    for key, rx in _UI_TEXT_ROWS:
        for number in _candidate_lines(ctx, rx):
            line = ctx.lines[number - 1]
            match = rx.search(line)
            if match is None or number in prompt_lines or _PROMPT_LHS_RE.search(line):
                continue
            ctx.add("person_signal", key, number, match.start() + 1, line, match.group(0))


def _scan_person_signals(ctx: _FileCtx, klass: str) -> None:
    """
    The person vocabulary for one file. Docs are scanned only under the prompt-file
    globs (prose about profiling is not profiling); config files take the config kinds,
    plus the doc kinds when the file is a prompt by path; code takes the code kinds
    outright and the prompt-material kinds only on a prompt line, else as a
    `person_signal_candidate` the rule may promote through a pydeep prompt literal.
    """
    relpath = ctx.record.relpath
    is_prompt_file = _is_prompt_file(relpath)
    if klass == "doc":
        if is_prompt_file:
            _scan_rows(ctx, "person_signal", _DOC_ROWS)
            _scan_paragraphs(ctx, _DOC_ROWS)
        return
    if klass == "config":
        _scan_rows(ctx, "person_signal", _PROMPT_CONFIG_ROWS if is_prompt_file else _CONFIG_ROWS)
        if is_prompt_file:
            _scan_paragraphs(ctx, _DOC_ROWS)
        return
    if is_prompt_file and ctx.record.lang not in _CODE_LANGS:
        _scan_template_rows(ctx, _DOC_ROWS)
        _scan_paragraphs(ctx, _DOC_ROWS)
        return
    _scan_rows(ctx, "person_signal", _CODE_ROWS)
    prompt_lines = ctx.lines_of("prompt_assembly")
    # Backtick template literals (JavaScript, TypeScript, Go): the lines after the opening
    # line are prompt material too, and a sentence wrapped across them is matched joined.
    spans = _template_spans(ctx, prompt_lines) if ctx.record.lang != "python" else []
    template_lines = _template_lines(spans)
    for key, rx in _PROMPT_ROWS:
        for number in _candidate_lines(ctx, rx):
            line = ctx.lines[number - 1]
            match = rx.search(line)
            if match is None:
                continue
            # The exclusions read the matched name, never the whole line: a prompt that
            # binds the conversation history AND the user's profile still reads a profile.
            if vocab.kind_of(key) == "profile_name" and (
                vocab.is_history_name(match.group(0))
                or vocab.is_settings_name(line, match.start(), match.end())
            ):
                continue
            prompt_material = (
                number in prompt_lines
                or number in template_lines
                or _PROMPT_LHS_RE.search(line) is not None
            )
            table = "person_signal" if prompt_material else "person_signal_candidate"
            # `by_name`: a prompt literal is a string the span finder cannot tell from a
            # docstring, so these rows are not mention-filtered; the rule gates them.
            ctx.add(table, key, number, match.start() + 1, line, match.group(0), by_name=True)
    if spans:
        _scan_paragraphs(ctx, _PROMPT_ROWS, spans)
    _scan_ui_text(ctx, prompt_lines | template_lines)
    near_prompt = _near_prompt_lines(ctx)
    _scan_experiments(ctx, near_prompt)
    _scan_steering_symbols(ctx, near_prompt)
    _scan_outreach_personalised(ctx)


def _idents(ctx: _FileCtx, number: int) -> set[str]:
    raw = ctx.lines[number - 1] if number - 1 < len(ctx.lines) else ""
    return {tok for tok in _IDENT_RE.findall(raw) if tok.lower() not in _IDENT_STOP}


def _scan_profile_to_prompt(ctx: _FileCtx) -> None:
    """A prompt assembled within `_INGRESS_WINDOW` lines after a profile read (an SDK call
    or a profile-named variable) sharing an identifier: table `profile_to_prompt`, key =
    the shared identifier. The shape of `_scan_ingress_to_prompt`, for the profiling rule."""
    profile_kinds = {"profile_sdk", "profile_name"}
    profiles = [
        m
        for m in ctx.out
        if m.hit.table in ("person_signal", "person_signal_candidate")
        and vocab.kind_of(m.hit.key) in profile_kinds
    ]
    prompts = [m for m in ctx.out if m.hit.table == "prompt_assembly"]
    if not profiles or not prompts:
        return

    def profile_idents(number: int) -> set[str]:
        """The identifiers on a profile line that NAME the profile."""
        return {tok for tok in _idents(ctx, number) if vocab.PROFILE_NAME_RE.search(tok)}

    # The assembly line itself may carry a profile name; it is the destination, not a
    # source, so it is not a profile line here.
    prompt_lines = {m.hit.line for m in prompts}
    by_line = {
        m.hit.line: profile_idents(m.hit.line) for m in profiles if m.hit.line not in prompt_lines
    }
    for prompt in prompts:
        p_line = prompt.hit.line
        p_idents = _idents(ctx, p_line)
        if not p_idents:
            continue
        for s_line, s_idents in by_line.items():
            if not (s_line < p_line <= s_line + _INGRESS_WINDOW):
                continue
            for shared in sorted(p_idents & s_idents):
                ctx.add(
                    "profile_to_prompt",
                    shared,
                    p_line,
                    prompt.hit.col,
                    ctx.lines[p_line - 1],
                    shared,
                )


def _scan_ingress_to_prompt(ctx: _FileCtx) -> None:
    """A prompt assembled within `_INGRESS_WINDOW` lines after an ingress line sharing an
    identifier: the person's words reach the prompt. Key = the shared identifier."""
    ingress = [m for m in ctx.out if m.hit.table == "ingress"]
    prompts = [m for m in ctx.out if m.hit.table == "prompt_assembly"]
    if not ingress or not prompts:
        return
    ingress_idents = {m.hit.line: _idents(ctx, m.hit.line) for m in ingress}
    for prompt in prompts:
        p_line = prompt.hit.line
        p_idents = _idents(ctx, p_line)
        if not p_idents:
            continue
        for i_line, i_idents in ingress_idents.items():
            if not (i_line < p_line <= i_line + _INGRESS_WINDOW):
                continue
            for shared in sorted(p_idents & i_idents):
                ctx.add(
                    "ingress_to_prompt",
                    shared,
                    p_line,
                    prompt.hit.col,
                    ctx.lines[p_line - 1],
                    shared,
                )


# --- a model call made with a plain HTTP client ---------------------------------

_HTTP_BEFORE, _HTTP_AFTER = 25, 12


def _http_call_match(line: str) -> re.Match[str] | None:
    """The first HTTP call on `line`, searched only in a short window around each place a
    call word appears: a dozen alternatives tried at every position of a long minified
    line is what made this scan slow."""
    for word in patterns.HTTP_CALL_WORDS:
        start = line.find(word)
        while start != -1:
            match = patterns.HTTP_CALL_RE.search(line, max(0, start - 40), start + len(word) + 40)
            if match is not None:
                return match
            start = line.find(word, start + 1)
    return None


def _http_call_target(line: str, start: int) -> tuple[str, str] | None:
    """('literal', text) or ('ident', name) for the call's URL argument: the first one, or
    the second for Go's `http.NewRequest("POST", url, ...)`."""
    rest = line[start:]
    if "NewRequest" in line[:start]:
        comma = rest.find(",")
        if comma == -1:
            return None
        rest = rest[comma + 1 :]
    match = patterns.HTTP_ARG_RE.match(rest)
    if match is None:
        return None
    if match.group("lit") is not None:
        return ("literal", match.group("lit"))
    return ("ident", match.group("ident").split(".")[-1])


def _scan_http_llm_calls(ctx: _FileCtx) -> None:
    """`llm_call` hits of key `generic_http` for model calls made with a plain HTTP client
    (the three conditions are documented next to the regexes in patterns.py). The
    per-line facts are computed once per file, and only when a call line exists, so a
    minified bundle costs one pass, not one window per call."""
    # Substring prefilters first: on a bundle most lines hold none of these words, and a
    # plain `in` costs a fraction of a regex pass over a long line.
    lines = ctx.lines
    calls = [
        (number, match)
        for number, line in enumerate(lines, 1)
        if (match := _http_call_match(line)) is not None
    ]
    if not calls:
        return
    have = ctx.lines_of("llm_call")
    code = [patterns.HTTP_COMMENT_RE.match(line) is None for line in lines]
    model_lines = [
        n
        for n, line in enumerate(lines, 1)
        if "model" in line and patterns.HTTP_MODEL_KEY_RE.search(line)
    ]
    gen_lines = [
        n
        for n, line in enumerate(lines, 1)
        if any(word in line for word in patterns.HTTP_GEN_WORDS)
        and patterns.HTTP_GEN_KEY_RE.search(line)
    ]
    target_lines = [
        n
        for n, line in enumerate(lines, 1)
        if code[n - 1]
        and any(word in line for word in patterns.HTTP_TARGET_WORDS)
        and patterns.HTTP_TARGET_RE.search(line)
    ]

    def within(numbers: list[int], lo: int, hi: int) -> bool:
        i = bisect_right(numbers, lo - 1)
        return i < len(numbers) and numbers[i] <= hi

    def assigned_a_target(name: str) -> bool:
        # A target line, or one of the three lines above it, assigns `name`.
        assign = re.compile(
            r"(?<![\w$.])"
            + re.escape(name)
            + r"\s*(?::[^=]*)?=(?!=)|\b"
            + re.escape(name)
            + r"\s*:"
        )
        for n in target_lines:
            for k in range(max(1, n - 3), n + 1):
                if code[k - 1] and assign.search(ctx.lines[k - 1]):
                    return True
        return False

    for number, match in calls:
        if number in have or not code[number - 1]:
            continue
        lo, hi = number - _HTTP_BEFORE, number + _HTTP_AFTER
        if not (within(model_lines, lo, hi) and within(gen_lines, lo, hi)):
            continue
        target = _http_call_target(ctx.lines[number - 1], match.end())
        if target is None:
            continue
        kind, value = target
        if kind == "literal":
            if not patterns.HTTP_TARGET_RE.search(value) and not any(
                assigned_a_target(name) for name in patterns.HTTP_INTERPOLATED_RE.findall(value)
            ):
                continue
        elif not assigned_a_target(value):
            continue
        line = ctx.lines[number - 1]
        ctx.add("llm_call", "generic_http", number, match.start() + 1, line, match.group(0))


def _scan_code(ctx: _FileCtx) -> None:
    lang = ctx.record.lang
    table_for = patterns.table_for
    _scan_rows(ctx, "llm_call", table_for(lang, patterns.LLM_CALL_PATTERNS))
    _scan_http_llm_calls(ctx)
    _scan_model_ids(ctx, config=False)
    _scan_rows(ctx, "framework", table_for(lang, patterns.FRAMEWORK_PATTERNS))
    _scan_rows(ctx, "ingress", table_for(lang, patterns.INGRESS_PATTERNS))
    _scan_rows(ctx, "response_accessor", patterns.LLM_RESPONSE_ACCESSORS)
    _scan_rows(ctx, "prompt_assembly", table_for(lang, patterns.PROMPT_ASSEMBLY_PATTERNS))
    _scan_rows(ctx, "remote_prompt", patterns.REMOTE_PROMPT_PATTERNS)
    _scan_rows(ctx, "runtime_prompt_config", patterns.RUNTIME_PROMPT_CONFIG_PATTERNS)
    _scan_ingress_to_prompt(ctx)
    _scan_person_signals(ctx, "code")
    _scan_profile_to_prompt(ctx)


def _matches(record: FileRecord, text: str) -> list[_Match]:
    ctx = _ctx(record, text)
    klass = _file_class(record)
    if klass == "doc":
        _scan_person_signals(ctx, "doc")
        return ctx.out
    if klass == "config":
        _scan_model_ids(ctx, config=True)
        # An evaluation or audit report is evidence of a past run, not the product's
        # prompts: its detector regexes and quoted snippets would read as person signals
        # (a failing crisis report carries the referral regex and silenced the crisis rule).
        if not _looks_like_report(record):
            _scan_person_signals(ctx, "config")
        return ctx.out
    _scan_code(ctx)
    return ctx.out


def grep_file(record: FileRecord, text: str | None) -> list[Hit]:
    """Every grep hit in one file. Snippets are redacted before the Hit exists.

    `text` is what `walk.read_text` returned; None (binary, oversized, unreadable) is
    an empty result, never an error.
    """
    if text is None:
        return []
    return [m.hit for m in _matches(record, text)]


# ---------------------------------------------------------------------------
# Reports and the system card
# ---------------------------------------------------------------------------


def _relpath(path: Path, root: Path) -> str:
    try:
        return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except (ValueError, OSError):
        return Path(path).as_posix()


def _parse_timestamp(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip().replace("Z", "+00:00")
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc)


def _load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.is_file():
        return None, "file not found"
    text = walk.read_text(path)
    if text is None:
        return None, "unreadable, binary or oversized"
    try:
        body = json.loads(text)
    except ValueError as exc:
        return None, f"invalid JSON: {truncate_snippet(str(exc), 120)}"
    if not isinstance(body, dict):
        return None, f"top-level value is {type(body).__name__}, expected an object"
    return body, None


def _report_kind(body: dict[str, Any]) -> str | None:
    """`evaluation` for an `aisafe evaluate` report, `probe` for a legacy `aisafe probe`
    one (by its `kind`, or by the cases/summary.sent shape when unlabelled), else None."""
    kind = body.get("kind")
    if kind == "evaluation":
        return "evaluation"
    if kind == "probe":
        return "probe"
    if kind is not None:
        return None
    summary = body.get("summary")
    if "cases" in body or (isinstance(summary, dict) and "sent" in summary):
        return "probe"
    return None


def _families(body: dict[str, Any]) -> list[str]:
    """The scenario families the report says it sent: `tool.corpus_families` when the
    report names them, else the keys of `by_family`. Never inferred from the cases."""
    tool = body.get("tool")
    if isinstance(tool, dict):
        raw = tool.get("corpus_families")
        if isinstance(raw, (list, tuple)) and raw:
            return [str(f) for f in raw]
    by_family = body.get("by_family")
    if isinstance(by_family, dict):
        return [str(f) for f in by_family]
    return []


# Clock skew a report may carry before its date counts as being in the future: one hour.
_FUTURE_TOLERANCE_S = 3600


def _build_report(kind: str, path: Path, root: Path, body: dict[str, Any]) -> ReportRecord:
    relpath = _relpath(path, root)
    raw_ts = body.get("generated_at")
    generated_at = raw_ts if isinstance(raw_ts, str) else None
    parsed = _parse_timestamp(raw_ts)
    now = datetime.now(timezone.utc)
    if parsed is not None and (now - parsed).total_seconds() < -_FUTURE_TOLERANCE_S:
        # A report dated in the future has no age anyone can trust: it is never fresh.
        age_source, age_days = "unknown", None
    elif parsed is not None:
        age_source, age_days = "generated_at", max(0, (now - parsed).days)
    else:
        when, source = walk.file_age(path, root)
        if when is not None:
            age_source, age_days = source, (now - when).days
        else:
            age_source, age_days = "unknown", None
    digest = body.get("config_digest")
    return ReportRecord(
        kind=kind,
        file=relpath,
        schema=body.get("schema"),
        generated_at=generated_at,
        age_source=age_source,
        age_days=age_days,
        families=_families(body),
        config_digest=digest if isinstance(digest, str) else None,
        body=body,
    )


def read_report(path: Path, root: Path) -> tuple[ReportRecord | None, UnknownItem | None]:
    """Read an `aisafe evaluate` JSON report (or a legacy `aisafe probe` one); refuse any
    schema but aisg/1. The toolchain's own output and the reports of retired commands
    are skipped silently: they are not evidence about the system."""
    path = Path(path)
    relpath = _relpath(path, root)
    body, error = _load_json(path)
    if body is None:
        return None, UnknownItem(
            category=UnknownCategory.REPORTS, what=relpath, why=error or "unreadable", file=relpath
        )
    schema = body.get("schema")
    if schema != SCHEMA_VERSION:
        return None, UnknownItem(
            category=UnknownCategory.REPORTS,
            what=relpath,
            why=f"schema {schema} is not {SCHEMA_VERSION}",
            how_to_resolve=f"Regenerate the report with a version of aisafe that writes {SCHEMA_VERSION}.",
            file=relpath,
        )
    kind = _report_kind(body)
    if kind is None and (body.get("kind") in _OWN_OUTPUT_KINDS or "guards" in body):
        return None, None
    if kind is None:
        return None, UnknownItem(
            category=UnknownCategory.REPORTS,
            what=relpath,
            why="not an evaluation report (kind evaluation, or legacy probe with cases/summary.sent)",
            file=relpath,
        )
    return _build_report(kind, path, root, body), None


def read_system_card(path: Path) -> dict[str, Any] | None:
    """The system card mapping (YAML file, or the YAML frontmatter of a model card)."""
    path = Path(path)
    text = walk.read_text(path)
    if text is None:
        return None
    if path.suffix.lower() in _YAML_EXTS:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError:
            return None
    else:
        data = configs.parse_agent_frontmatter(path.as_posix(), text)
    return data if isinstance(data, dict) else None


def _looks_like_report(record: FileRecord) -> bool:
    if PurePosixPath(record.relpath).suffix.lower() != ".json":
        return False
    if _REPORT_NAME_RE.match(PurePosixPath(record.relpath).name):
        return True
    try:
        with open(record.path, "rb") as fh:
            head = fh.read(_REPORT_HEAD)
    except OSError:
        return False
    return _REPORT_SCHEMA_RE.search(head.decode("utf-8", errors="replace")) is not None


def _build_system_card(
    files: list[FileRecord],
) -> tuple[dict[str, Any] | None, UnknownItem | None]:
    """The legacy `ai-system-card.yaml`, kept for two keys only: who the system touches
    (`affected_persons`) and who reviewed the prompts (`prompt_audit`). Everything else
    the card said belonged to retired rules."""
    for record in files:  # files are sorted by relpath, so the first match is deterministic
        if not _glob_hit(patterns.SYSTEM_CARD_GLOBS, record.relpath):
            continue
        card = read_system_card(record.path)
        if card is None:
            return None, UnknownItem(
                category=UnknownCategory.RUNTIME,
                what=f"system card {record.relpath}",
                why="not a readable YAML mapping",
                file=record.relpath,
            )
        affected = card.get("affected_persons")
        prompt_audit = card.get("prompt_audit")
        return {
            "file": record.relpath,
            "affected_persons": None if vocab.is_unset(affected) else affected,
            "prompt_audit": prompt_audit if isinstance(prompt_audit, dict) else None,
        }, None
    return None, None


# ---------------------------------------------------------------------------
# Inventory builders
# ---------------------------------------------------------------------------


def _sort_key(entry: dict[str, Any]) -> tuple[str, int, str]:
    name = entry.get("name") or entry.get("model") or entry.get("kind") or entry.get("symbol")
    return (str(entry.get("file", "")), int(entry.get("line") or 0), str(name or ""))


def _sorted(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(entries, key=_sort_key)


def _split_key(key: str) -> tuple[str, str]:
    head, sep, tail = key.partition(":")
    return (head, tail) if sep else (key, key)


def _by_table(matches: list[_Match]) -> dict[str, list[_Match]]:
    out: dict[str, list[_Match]] = {}
    for match in matches:
        out.setdefault(match.hit.table, []).append(match)
    return out


def _model_source(relpath: str) -> str:
    name = PurePosixPath(relpath).name
    if patterns.ENV_FILE_RE.match(name):
        return "env"
    if PurePosixPath(relpath).suffix.lower() in _CONFIG_DATA_EXTS:
        return "config"
    return "literal"


def _build_models(matches: list[_Match]) -> list[dict[str, Any]]:
    """`models[]`: exactly {id, file, line, provider, model, pinned, source}.

    The unit is deliberately not part of the entry; `ai_surface_units()` and
    `_model_ref()` recover it from the file through the walk's unit map.
    """
    seen: set[tuple[str, int, str]] = set()
    out: list[dict[str, Any]] = []
    for match in matches:
        hit = match.hit
        provider, ident = _split_key(hit.key)
        stamp = (hit.file, hit.line, ident)
        if stamp in seen:
            continue
        seen.add(stamp)
        pinned = None if provider == "other" else patterns.classify_model(provider, ident)
        out.append(
            {
                "id": "",
                "file": hit.file,
                "line": hit.line,
                "provider": provider,
                "model": ident,
                "pinned": pinned,
                "source": _model_source(hit.file),
            }
        )
    out = _sorted(out)
    for index, entry in enumerate(out, 1):
        entry["id"] = f"m{index}"
    return out


def _model_ref(
    models: list[dict[str, Any]],
    file: str,
    line: int,
    unit: str | None,
    unit_by_file: dict[str, str | None],
) -> str | None:
    """Closest preceding model id in the same file, else any in the file, else the unit."""
    best: dict[str, Any] | None = None
    for entry in models:
        if entry["file"] != file or entry["line"] > line:
            continue
        if best is None or entry["line"] > best["line"]:
            best = entry
    if best is None:
        same_file = [m for m in models if m["file"] == file]
        if same_file:
            best = same_file[0]
    if best is None and unit is not None:
        same_unit = [m for m in models if unit_by_file.get(m["file"]) == unit]
        if same_unit:
            best = same_unit[0]
    return None if best is None else best["id"]


def _build_llm_calls(
    matches: list[_Match],
    models: list[dict[str, Any]],
    unit_by_file: dict[str, str | None],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for match in matches:
        hit = match.hit
        out.append(
            {
                "file": hit.file,
                "line": hit.line,
                "provider": patterns.LLM_PROVIDER_BY_KEY.get(hit.key, "unknown"),
                "sdk": hit.key,
                "api": match.text,
                "unit": hit.unit,
                "model_ref": _model_ref(models, hit.file, hit.line, hit.unit, unit_by_file),
            }
        )
    return _sorted(out)


def _build_frameworks(matches: list[_Match]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for match in sorted(matches, key=lambda m: (m.hit.file, m.hit.line, m.hit.key)):
        hit = match.hit
        if (hit.file, hit.key) in seen:
            continue
        seen.add((hit.file, hit.key))
        out.append({"name": hit.key, "file": hit.file, "line": hit.line, "unit": hit.unit})
    return _sorted(out)


def _build_legs(matches: list[_Match]) -> list[dict[str, Any]]:
    """`{file, line, kind, symbol, unit}` from a `<kind>:<symbol>` keyed table (ingress)."""
    out: list[dict[str, Any]] = []
    for match in matches:
        hit = match.hit
        kind, _symbol = _split_key(hit.key)
        out.append(
            {
                "file": hit.file,
                "line": hit.line,
                "kind": kind,
                "symbol": match.text,
                "unit": hit.unit,
            }
        )
    return _sorted(out)


def _build_person_signals(matches: list[_Match]) -> list[dict[str, Any]]:
    """`inventory.person_signals`: one row per confirmed `person_signal` hit (candidates
    stay out of the inventory; a rule may still promote them through a prompt literal)."""
    out: list[dict[str, Any]] = []
    for match in matches:
        hit = match.hit
        out.append(
            {
                "file": hit.file,
                "line": hit.line,
                "kind": vocab.kind_of(hit.key),
                "symbol": match.text,
                "unit": hit.unit,
            }
        )
    return _sorted(out)


def _signals_of_kind(signals: list[dict[str, Any]], kinds: frozenset[str]) -> list[dict[str, Any]]:
    return [dict(entry) for entry in signals if entry.get("kind") in kinds]


_ASSEMBLY_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _assembly_name(match: _Match) -> str:
    """The left-hand identifier of a grep-level assembly (`prompt`, `SYSTEM_PROMPT`), or
    "" for a `"role": "system"` entry, whose text starts with a quote."""
    text = match.text.lstrip()
    if text[:1] in "\"'`":
        return ""
    found = _ASSEMBLY_NAME_RE.match(text)
    return found.group(0) if found else ""


def _build_prompts(
    scanned: list[FileRecord], tables: dict[str, list[_Match]]
) -> list[dict[str, Any]]:
    """`prompts[]`: `{file, line, kind, name, is_system, unit}`.

    `file`: a prompt by path (PROMPT_FILE_GLOBS) that is not a code module and not a
    report, line 1, name = path; `is_system` is True when the name says so, else None
    (unknown, not False: a persona file usually is the system prompt). `assembly`: a
    grep-level prompt assembly line, name = the left-hand identifier. `remote` and
    `runtime`: a prompt fetched at runtime or read from env/settings, name = the call;
    these make the unit an AI surface and carry an UNKNOWN each. `literal` entries and
    AST assemblies arrive through `merge_pyfacts_prompts()` once pydeep has run.
    """
    out: list[dict[str, Any]] = []
    for record in scanned:
        if (
            record.lang in _CODE_LANGS
            or _file_class(record) == "config"
            and _looks_like_report(record)
        ):
            continue
        if not _is_prompt_file(record.relpath):
            continue
        name = PurePosixPath(record.relpath).name.lower()
        out.append(
            {
                "file": record.relpath,
                "line": 1,
                "kind": "file",
                "name": record.relpath,
                "is_system": True if "system" in name else None,
                "unit": record.unit,
            }
        )
    for match in tables.get("prompt_assembly", []):
        hit = match.hit
        name = _assembly_name(match)
        out.append(
            {
                "file": hit.file,
                "line": hit.line,
                "kind": "assembly",
                "name": name,
                "is_system": hit.key == "system_role" or name.lower().startswith("system"),
                "unit": hit.unit,
            }
        )
    for table, kind in (("remote_prompt", "remote"), ("runtime_prompt_config", "runtime")):
        for match in tables.get(table, []):
            hit = match.hit
            out.append(
                {
                    "file": hit.file,
                    "line": hit.line,
                    "kind": kind,
                    "name": match.text,
                    "is_system": None,
                    "unit": hit.unit,
                }
            )
    return _sorted(out)


def merge_pyfacts_prompts(inventory: Inventory, pyfacts: object | None) -> None:
    """Add pydeep's prompt literals (kind `literal`) and assemblies (kind `assembly`) to
    `inventory.prompts` once `--deep python` has run; discovery runs before pydeep, so
    this is the second half of the `prompts` section. An AST assembly on a line the grep
    tier already listed replaces that entry; the name comes from whichever tier read it
    (the pruned `Assembly` carries no target name, the grep entry read the left-hand
    identifier) and the prompt is the system prompt when either tier saw that.
    Idempotent; `pyfacts is None` is a no-op."""
    if pyfacts is None:
        return
    index = {(e["file"], e["line"], e["kind"]): i for i, e in enumerate(inventory.prompts)}

    def put(entry: dict[str, Any]) -> None:
        key = (entry["file"], entry["line"], entry["kind"])
        if key in index:
            old = inventory.prompts[index[key]]
            if not entry.get("name"):
                entry["name"] = old.get("name") or ""
            entry["is_system"] = bool(entry.get("is_system") or old.get("is_system"))
            inventory.prompts[index[key]] = entry
        else:
            index[key] = len(inventory.prompts)
            inventory.prompts.append(entry)

    for literal in getattr(pyfacts, "prompt_literals", None) or []:
        file = str(literal.file).replace("\\", "/")
        put(
            {
                "file": file,
                "line": int(literal.line),
                "kind": "literal",
                "name": str(getattr(literal, "name", "") or ""),
                "is_system": bool(getattr(literal, "is_system", False)),
                "unit": walk.unit_of(file, inventory.units),
            }
        )
    for assembly in getattr(pyfacts, "prompt_assemblies", None) or []:
        file = str(assembly.file).replace("\\", "/")
        targets = (
            getattr(assembly, "target_names", None)
            or getattr(assembly, "targets", None)
            or getattr(assembly, "names", None)
            or ()
        )
        name = str(targets[0]) if targets else str(getattr(assembly, "name", "") or "")
        put(
            {
                "file": file,
                "line": int(assembly.line),
                "kind": "assembly",
                "name": name,
                "is_system": bool(getattr(assembly, "is_system", False)),
                "unit": walk.unit_of(file, inventory.units),
            }
        )
    inventory.prompts = _sorted(inventory.prompts)


def _build_review_records(
    root: Path, files: list[FileRecord], unknown: list[UnknownItem]
) -> list[dict[str, Any]]:
    """`review_records[]` from `aisafe.review.records.find_records`, imported lazily: the
    review package is optional at this layer, and a malformed record file is an UNKNOWN
    (runtime) row, never a crash."""
    try:
        from aisafe.review.records import find_records
    except ImportError:
        return []
    try:
        review = find_records(root, files, None)
    except Exception as exc:  # a broken record file must not stop discovery
        unknown.append(
            UnknownItem(
                category=UnknownCategory.RUNTIME,
                what="review records",
                why=f"{type(exc).__name__}: {truncate_snippet(str(exc), 200)}",
            )
        )
        return []
    file = getattr(review, "file", None)
    unknown_items = getattr(review, "unknown_items", None)
    if callable(unknown_items):
        # The review module spells its own UNKNOWN rows (with the rule id); reusing them
        # keeps the row identical wherever the pipeline reports it.
        unknown.extend(unknown_items())
    else:
        for error in getattr(review, "errors", None) or []:
            unknown.append(
                UnknownItem(
                    category=UnknownCategory.RUNTIME,
                    what=f"review record {file}" if file else "review record",
                    why=str(error),
                    how_to_resolve=(
                        "Fix the record with `aisafe review check`; an unreadable record "
                        "covers nothing."
                    ),
                    file=file,
                )
            )
    out: list[dict[str, Any]] = []
    for record in getattr(review, "records", None) or []:
        to_inventory = getattr(record, "to_inventory", None)
        if callable(to_inventory):
            row = dict(to_inventory())
            if not row.get("file"):
                row["file"] = file
            if row.get("policy_version") is None:
                row["policy_version"] = getattr(review, "policy_version", None)
            out.append(row)
            continue
        reviewed_at = getattr(record, "reviewed_at", None)
        artifacts = getattr(record, "artifacts", None) or ()
        scope = getattr(record, "scope", None) or ()
        out.append(
            {
                "file": getattr(record, "source_file", None)
                or getattr(record, "file", None)
                or file,
                "reviewer": getattr(record, "reviewer", None),
                "reviewed_at": None if reviewed_at is None else str(reviewed_at),
                "policy_version": getattr(record, "policy_version", None)
                or getattr(review, "policy_version", None),
                "artifacts": len(artifacts),
                "scope": [str(item) for item in scope],
            }
        )
    return out


# ---------------------------------------------------------------------------
# AI surface
# ---------------------------------------------------------------------------


def _unit_of_file(inventory: Inventory, relpath: str) -> str:
    return walk.unit_of(relpath, inventory.units)


_SURFACE_PROMPT_KINDS = frozenset({"file", "remote", "runtime"})


def _runtime_units(inventory: Inventory) -> set[str]:
    """Units with a model call, a framework or a model id: the ones whose response path
    the audit can read at all."""
    units: set[str] = set()
    for section in (inventory.llm_calls, inventory.frameworks, inventory.models):
        for entry in section:
            unit = entry.get("unit")
            if unit is None and entry.get("file"):
                unit = _unit_of_file(inventory, entry["file"])
            if unit:
                units.add(unit)
    return units


def ai_surface_units(inventory: Inventory) -> set[str]:
    """Units with at least one LLM call, framework or model id, or a prompt file under
    PROMPT_FILE_GLOBS, or a prompt fetched or configured at runtime. A prompt-only
    repository is an AI surface: nothing requires a recognised SDK where another AI
    surface is evidenced."""
    units = _runtime_units(inventory)
    for entry in inventory.prompts:
        if entry.get("kind") not in _SURFACE_PROMPT_KINDS:
            continue
        unit = entry.get("unit")
        if unit is None and entry.get("file"):
            unit = _unit_of_file(inventory, entry["file"])
        if unit:
            units.add(unit)
    return units


def unit_ai_surface(inventory: Inventory, unit_id: str) -> bool:
    return unit_id in ai_surface_units(inventory)


def _surface_unknowns(inventory: Inventory, matches: list[_Match]) -> list[UnknownItem]:
    """What the audit could not read about the AI surface: a unit whose only AI evidence
    is prompt material, a prompt fetched at runtime, a prompt read from env or settings,
    and a non-Python unit with no deep analysis."""
    out: list[UnknownItem] = []
    runtime = _runtime_units(inventory)
    for unit in inventory.units:
        if not unit.ai_surface:
            continue
        if unit.id not in runtime:
            out.append(
                UnknownItem(
                    category=UnknownCategory.COVERAGE,
                    what=f"runtime evidence {unit.id}",
                    why=(
                        "prompt material found but no model call or SDK in this unit; the "
                        "response path, controls and data flows could not be read"
                    ),
                    how_to_resolve=(
                        "Audit the service that sends these prompts to a model, or add it to "
                        "the tree; the prompt findings stand on their own."
                    ),
                    file=unit.root,
                )
            )
        if unit.language != "python":
            language = unit.language if unit.language != "unknown" else "unknown-language"
            out.append(
                UnknownItem(
                    category=UnknownCategory.DEEP,
                    what=f"{language} deep analysis",
                    why="not available in this version; pattern-level findings only",
                    how_to_resolve="Review the pattern-level findings for this unit by hand.",
                    file=unit.root,
                )
            )
    for match in matches:
        hit = match.hit
        if hit.table == "remote_prompt":
            out.append(
                UnknownItem(
                    category=UnknownCategory.COVERAGE,
                    what=f"remote prompt {hit.file}:{hit.line}",
                    why="the prompt text is fetched at runtime and was not available to the audit",
                    how_to_resolve=(
                        "Export the prompt to a file under prompts/ and audit that, or audit "
                        "the registry that serves it."
                    ),
                    file=hit.file,
                )
            )
        elif hit.table == "runtime_prompt_config":
            out.append(
                UnknownItem(
                    category=UnknownCategory.COVERAGE,
                    what=f"runtime prompt config {hit.file}:{hit.line}",
                    why=(
                        "the prompt text is read from the environment or settings at runtime; "
                        "the value used in production was not available to the audit"
                    ),
                    how_to_resolve=(
                        "Commit the prompt text to the tree, or audit the deployed configuration."
                    ),
                    file=hit.file,
                )
            )
    return out


# ---------------------------------------------------------------------------
# discover()
# ---------------------------------------------------------------------------


def _languages(scanned: list[FileRecord]) -> dict[str, int]:
    counts: dict[str, int] = {"python": 0, "typescript": 0, "go": 0, "other": 0}
    for record in scanned:
        lang = record.lang if record.lang not in ("config", "other") else "other"
        counts[lang] = counts.get(lang, 0) + 1
    return counts


def discover(
    root: Path,
    files: list[FileRecord],
    units: list[Unit],
    options: object = None,
    *,
    own_output_skipped: Sequence[str] | None = None,
) -> tuple[Inventory, list[Hit]]:
    """Grep every file and assemble the inventory.

    Returns the inventory and the raw hits (sorted by file, line, column, table, key).
    Never raises on a bad file: each failure becomes an `UnknownItem` in
    `inventory.unknown`. `own_output_skipped` is the walk's list of the audit's own
    reports it stepped over; it is copied onto the inventory so every renderer can say
    what was not looked at.
    """
    started = time.perf_counter()
    root = Path(root)
    max_size = _opt(options, "max_size", None)
    inventory = Inventory(units=list(units))
    unknown: list[UnknownItem] = []
    matches: list[_Match] = []
    scanned: list[FileRecord] = []
    skipped = 0
    total_bytes = 0

    for record in sorted(files, key=lambda r: r.relpath):
        text = walk.read_text(record.path, max_size)
        if text is None:
            skipped += 1
            continue
        scanned.append(record)
        total_bytes += record.size
        try:
            file_matches = _matches(record, text)
        except Exception as exc:  # a pathological file must not stop the audit
            unknown.append(
                UnknownItem(
                    category=UnknownCategory.RUNTIME,
                    what=f"discover {record.relpath}",
                    why=f"{type(exc).__name__}: {truncate_snippet(str(exc), 200)}",
                    file=record.relpath,
                )
            )
            continue
        matches.extend(file_matches)

    matches.sort(key=lambda m: (m.hit.file, m.hit.line, m.hit.col, m.hit.table, m.hit.key))
    tables = _by_table(matches)

    unit_by_file = {record.relpath: record.unit for record in scanned}
    inventory.models = _build_models(tables.get("model_id", []))
    inventory.llm_calls = _build_llm_calls(
        tables.get("llm_call", []), inventory.models, unit_by_file
    )
    inventory.frameworks = _build_frameworks(tables.get("framework", []))
    inventory.ingress = _build_legs(tables.get("ingress", []))
    inventory.prompts = _build_prompts(scanned, tables)
    inventory.person_signals = _build_person_signals(tables.get("person_signal", []))
    inventory.memory_stores = _signals_of_kind(inventory.person_signals, frozenset({"memory"}))
    inventory.personas = _signals_of_kind(
        inventory.person_signals, frozenset({"persona", "confidant", "fiction"})
    )

    reports: list[ReportRecord] = []
    for record in scanned:
        if not _looks_like_report(record):
            continue
        report, item = read_report(record.path, root)
        if item is not None:
            unknown.append(item)
            continue
        if report is None:
            continue
        reports.append(report)
        if report.age_source == "unknown":
            unknown.append(
                UnknownItem(
                    category=UnknownCategory.REPORTS,
                    what=f"report age {record.relpath}",
                    why="no generated_at, mtime and git both unavailable",
                    how_to_resolve="Regenerate the report; a report of unknown age is not evidence.",
                    file=record.relpath,
                )
            )
    inventory.reports = sorted(reports, key=lambda r: r.file)

    card, card_item = _build_system_card(scanned)
    inventory.system_card = card
    if card_item is not None:
        unknown.append(card_item)
    inventory.review_records = _build_review_records(root, scanned, unknown)

    surface = ai_surface_units(inventory)
    for unit in inventory.units:
        unit.ai_surface = unit.id in surface
    unknown.extend(_surface_unknowns(inventory, matches))

    inventory.languages = _languages(scanned)
    sha, dirty = walk.git_meta(root)
    inventory.target = {
        "path": root.resolve().as_posix(),
        "git_sha": sha,
        "dirty": dirty,
        "scanned_files": len(scanned),
        "skipped_files": skipped,
        "bytes": total_bytes,
        "duration_ms": int((time.perf_counter() - started) * 1000),
    }
    if own_output_skipped is not None:
        inventory.own_output_skipped = sorted(own_output_skipped)
    inventory.unknown = unknown
    return inventory, [m.hit for m in matches]
