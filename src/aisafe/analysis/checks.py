# aisafe-audit: ignore-file
"""src/aisafe/analysis/checks.py
------------------------------
Native checks over the walked Python files: the shapes the retired EU AI Act linter and
misalignment checker looked for that the person-facing rules still consume. Python AST
plus text, no external framework, deterministic.

A check hit is evidence, never a finding of its own: the rules attach hits as `role: check`
legs, and a hit alone may anchor a finding exactly as a lint hit could. Every hit carries
what was seen, where, and the facts the rule needs to decide (`extra`); a check never drops
a hit because a mitigation sits next to it. `decision_function_about_person` records
`reviewed: True` instead of staying silent, because the rule, not the check, decides what a
review symbol is worth.

This module spells the phrases it looks for, so it carries the ignore marker on its first
line: the audit would otherwise read its own tables as the practice.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from aisafe.discovery import vocabulary as vocab
from aisafe.discovery.patterns import IGNORE_MARKER, LEGACY_IGNORE_MARKERS
from aisafe.evidence.model import UnknownCategory, UnknownItem, truncate_snippet

__all__ = [
    "CHECK_NAMES",
    "CHECK_TITLES",
    "CheckFacts",
    "CheckHit",
    "run_checks",
]

CHECK_NAMES: tuple[str, ...] = (
    "hidden_ai_instruction",
    "response_function_without_disclosure",
    "decision_function_about_person",
    "social_scoring_language",
    "emotion_recognition_in_work_or_education",
    "undesired_objective_language",
    "personal_data_into_prompt",
)

# What each hit says. Plain observations: the policy decision belongs to the rule.
CHECK_TITLES: dict[str, str] = {
    "hidden_ai_instruction": "a string instructs the model to hide or deny that it is an AI",
    "response_function_without_disclosure": "a response function carries no disclosure text",
    "decision_function_about_person": "a function decides with person and review flags recorded",
    "social_scoring_language": "social, citizen or trust scoring language",
    "emotion_recognition_in_work_or_education": (
        "emotion recognition named next to workplace or education words"
    ),
    "undesired_objective_language": "engagement, dependency or manipulation objective language",
    "personal_data_into_prompt": "a personal data field bound next to a prompt",
}

_MARKER_LINES = 5
_MARKERS: tuple[str, ...] = (IGNORE_MARKER, *LEGACY_IGNORE_MARKERS)
_PARSE_ERRORS = (SyntaxError, RecursionError, MemoryError, ValueError)

# ---------------------------------------------------------------------------
# Vocabulary of the checks (ported from EU-AIA-013b/013a/014a/005a/005c, ALIGN-008 and
# EU-GDPR-001, with whitespace made flexible and the obvious synonyms added)
# ---------------------------------------------------------------------------

_AI_NOUN = r"(?:an?\s+)?(?:AI|bot|chatbot|language\s+model|LLM|machine|program|assistant)"
HIDE_AI_RE = re.compile(
    r"\byou\s+are\s+a\s+(?:real\s+)?human\b"
    r"|\bpretend\s+(?:to\s+be|you\s+are|that\s+you\s+are)\s+(?:a\s+)?(?:real\s+)?human\b"
    r"|\bnever\s+(?:say|admit|reveal|mention|disclose|acknowledge)\s+(?:that\s+)?you(?:'re|\s+are)\s+"
    + _AI_NOUN
    + r"\b|\b(?:do\s+not|don'?t)\s+(?:tell|say|reveal|mention|admit|disclose)\s+(?:that\s+)?"
    r"you(?:'re|\s+are)\s+" + _AI_NOUN + r"\b"
    r"|\bdeny\s+(?:being|that\s+you\s+are)\s+" + _AI_NOUN + r"\b",
    re.I,
)

RESPONSE_FN_RE = re.compile(
    r"^(?:chat|respond|reply|generate_response|handle_message|send_response)", re.I
)
DISCLOSURE_TEXT_RE = re.compile(
    r"AI\s+system|generated\s+by\s+(?:an\s+)?AI|automated|chatbot|virtual\s+assistant|disclosure",
    re.I,
)

DECISION_VERB_RE = re.compile(
    r"\b(?:approve|reject|deny|hire|fire|terminate|accept|grant|disqualify|eligib\w*|score"
    r"|rank|flag_for_action|auto_decision|automated_decision)\w*\b",
    re.I,
)
# The review symbols the retired linter knew that the vocabulary's REVIEW_RE does not spell.
REVIEW_EXTRA_RE = re.compile(r"\b(?:human_oversight|requires_approval)\b", re.I)
# The approval symbols moved to the vocabulary; spelled here too so the check reads the same
# set while the vocabulary is being extended.
_APPROVAL_FALLBACK_RE = re.compile(
    r"\brequire_approval\b|\bapproval_callback\b|\bhuman_in_the_loop\b|\bHumanInTheLoop\b"
    r"|\binterrupt_before\b|\binterrupt_after\b|\bconfirm\(|\bask_user\b|\brequest_confirmation\b"
    r"|\bneeds_approval\b|\bapprove\(|\bpause_for_approval\b"
)

SOCIAL_SCORING_RE = re.compile(
    r"social[_\s]scor|citizen[_\s]scor|trust[_\s]scor|behaviou?r[_\s]scor|reputation[_\s]scor"
    r"|citizen[_\s]rank|social[_\s]credit",
    re.I,
)

EMOTION_RE = re.compile(
    r"emotion[_\s]*(?:detect|recogni|analys|classif)|sentiment[_\s]*analys|affect[_\s]*recogni"
    r"|facial[_\s]*expression",
    re.I,
)
WORK_EDU_RE = re.compile(
    r"employee|worker|staff|student|pupil|classroom|workplace|office|hr_", re.I
)

UNDESIRED_OBJECTIVE_RE = re.compile(
    r"\bmaximi[sz]e\s+(?:(?:the\s+)?user'?s?\s+)?(?:engagement|retention|dependency|dependence"
    r"|addiction|clicks?|watch.?time|session\s+(?:time|length))\b"
    r"|\bincrease\s+(?:(?:the\s+)?user'?s?\s+)?(?:dependency|dependence|addiction|reliance)\b"
    r"|\bmanipulate\s+(?:the\s+)?(?:users?|behaviou?r|outcomes?|people)\s+without\b",
    re.I,
)

PII_FIELD_RE = re.compile(
    r"(?:\w*_)?(?:email|phone|ssn|passport|date_of_birth|dob|credit_card|iban|address"
    r"|full_name|first_name|last_name|personal_data|user_data)\w*",
    re.I,
)
_PII_ASSIGN_RE = re.compile(
    r"(?:^|[\s(,])(" + PII_FIELD_RE.pattern + r")\s*(?::[^=\n]*)?=(?!=)", re.I
)
PROMPT_WORD_RE = re.compile(
    r"\b(?:messages?|prompt\w*|content|user_message|input|system\w*|instructions?)\b", re.I
)


# ---------------------------------------------------------------------------
# Products
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CheckHit:
    """One observation of a check. `extra` holds the facts a rule reads to decide
    (`person`, `reviewed`, `function`, `field`, `in_docstring`); it never changes whether the
    hit exists."""

    check: str
    file: str
    line: int
    snippet: str
    title: str
    extra: dict[str, Any] = field(default_factory=dict, hash=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "file", str(self.file).replace("\\", "/"))
        object.__setattr__(self, "snippet", truncate_snippet(self.snippet))

    @property
    def key(self) -> tuple[str, int, str]:
        return (self.file, self.line, self.check)


@dataclass
class CheckFacts:
    """The hits of every check, the files skipped by the ignore marker, and the checks that
    failed (as UNKNOWN items, never as a crash)."""

    by_check: dict[str, list[CheckHit]] = field(
        default_factory=lambda: {name: [] for name in CHECK_NAMES}
    )
    skipped: list[str] = field(default_factory=list)
    errors: list[UnknownItem] = field(default_factory=list)
    files: int = 0

    def hits(self, *names: str) -> list[CheckHit]:
        """Hits of the named checks (all when none is named), sorted by (file, line, check).
        An unknown name raises: a misspelt check is a bug, not an absence of evidence."""
        wanted = names or CHECK_NAMES
        out: list[CheckHit] = []
        for name in wanted:
            if name not in self.by_check:
                raise KeyError(f"unknown check {name!r}; known: {', '.join(CHECK_NAMES)}")
            out.extend(self.by_check[name])
        return sorted(out, key=lambda h: h.key)


# ---------------------------------------------------------------------------
# Per-file view
# ---------------------------------------------------------------------------


def _cut_comment(line: str) -> str:
    """The line up to a `#` that sits outside quotes."""
    if "#" not in line:
        return line
    quote: str | None = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote is not None:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "#":
            return line[:i]
        i += 1
    return line


def _is_comment_line(line: str) -> bool:
    return line.lstrip().startswith("#")


def _string_spans(node: ast.AST) -> list[tuple[int, int, int, int]]:
    """(line, col, end_line, end_col) of a string's source text, in bytes as the tree gives
    them. For an f-string only its constant parts are spanned when the tree places them
    (Python 3.12+), so a name inside `{...}` stays visible as code; older trees give the
    parts their parent's span, and then the whole f-string is spanned once."""
    whole = (
        getattr(node, "lineno", 0),
        getattr(node, "col_offset", 0),
        getattr(node, "end_lineno", None) or getattr(node, "lineno", 0),
        getattr(node, "end_col_offset", None),
    )
    if whole[3] is None or not whole[0]:
        return []
    if not isinstance(node, ast.JoinedStr):
        return [whole]
    spans: list[tuple[int, int, int, int]] = []
    for value in node.values:
        if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
            continue
        span = (
            value.lineno,
            value.col_offset,
            value.end_lineno or value.lineno,
            value.end_col_offset,
        )
        if span[3] is None or span == whole:
            return [whole]
        spans.append(span)
    return spans


def _blank(view: list[bytearray], span: tuple[int, int, int, int]) -> None:
    """Overwrite a span of the byte view with spaces, line by line."""
    line, col, end_line, end_col = span
    for number in range(line, end_line + 1):
        if not 1 <= number <= len(view):
            continue
        raw = view[number - 1]
        start = col if number == line else 0
        stop = end_col if number == end_line else len(raw)
        start, stop = max(0, min(start, len(raw))), max(0, min(stop, len(raw)))
        if stop > start:
            raw[start:stop] = b" " * (stop - start)


class _File:
    """One Python file as the checks read it: lines, the tree when it parses, the string
    constants with their parents, which constants are docstrings, and a code-only view of
    the lines (every string blanked) for the checks that must not read prose as code. The
    tree is walked once; the derived views are built on first use and kept."""

    def __init__(self, relpath: str, text: str) -> None:
        self.relpath = relpath
        self.text = text
        self.lines = text.splitlines()
        self.tree: ast.Module | None = None
        try:
            self.tree = ast.parse(text, filename=relpath)
        except _PARSE_ERRORS:
            self.tree = None
        self.parent: dict[ast.AST, ast.AST] = {}
        self.docstrings: set[int] = set()
        self._functions: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        self._strings: list[tuple[ast.AST, str, bool]] = []
        self._code_lines: list[tuple[int, str]] | None = None
        self._code_view: list[str] | None = None
        if self.tree is None:
            return
        # One breadth-first walk: a def is met before its docstring constant and an
        # f-string before its parts, so each constant is classified as it comes.
        for node in ast.walk(self.tree):
            for child in ast.iter_child_nodes(node):
                self.parent[child] = node
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                body = getattr(node, "body", None) or []
                first = body[0] if body else None
                if (
                    isinstance(first, ast.Expr)
                    and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)
                ):
                    self.docstrings.add(id(first.value))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._functions.append(node)
            if isinstance(node, ast.JoinedStr):
                parts = [
                    value.value
                    if isinstance(value, ast.Constant) and isinstance(value.value, str)
                    else "{...}"
                    for value in node.values
                ]
                self._strings.append((node, "".join(parts), False))
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if not isinstance(self.parent.get(node), ast.JoinedStr):
                    self._strings.append((node, node.value, id(node) in self.docstrings))

    def line(self, number: int) -> str:
        if 1 <= number <= len(self.lines):
            return self.lines[number - 1]
        return ""

    def code_lines(self) -> list[tuple[int, str]]:
        """(number, line) for every line that is not a comment, with inline comments cut."""
        if self._code_lines is None:
            self._code_lines = [
                (number, _cut_comment(raw))
                for number, raw in enumerate(self.lines, 1)
                if not _is_comment_line(raw)
            ]
        return self._code_lines

    def strings(self) -> list[tuple[ast.AST, str, bool]]:
        """(node, text, is_docstring) for every string constant and f-string. An f-string
        is read as one text with `{...}` for each formatted value, and its constant parts are
        not listed again on their own."""
        return self._strings

    def functions(self) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
        return self._functions

    def code_view(self) -> list[str]:
        """The lines with every string literal blanked from the tree's own spans, so a
        person noun or a decision verb inside a docstring or a prompt is never read as
        code. Empty when the file does not parse."""
        if self._code_view is None:
            if self.tree is None:
                self._code_view = []
            else:
                view = [bytearray(line.encode("utf-8")) for line in self.lines]
                for node, _text, _doc in self._strings:
                    for span in _string_spans(node):
                        _blank(view, span)
                self._code_view = [bytes(raw).decode("utf-8", errors="replace") for raw in view]
        return self._code_view

    def source(self, node: ast.AST) -> str:
        end = getattr(node, "end_lineno", None) or node.lineno
        return "\n".join(self.lines[node.lineno - 1 : end])

    def body(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
        """The function's body as written, strings included, without the `def` line: a
        symbol in the function's own name (`def approve(`, `def chatbot_reply(`) must never
        read as a control or a disclosure the function applies."""
        if not node.body:
            return ""
        first = node.body[0]
        end = getattr(node, "end_lineno", None) or node.lineno
        lines = list(self.lines[first.lineno - 1 : end])
        if lines:
            head = lines[0].encode("utf-8")
            lines[0] = head[getattr(first, "col_offset", 0) :].decode("utf-8", errors="replace")
        return "\n".join(lines)

    def code_of(self, node: ast.AST) -> list[str]:
        """A node's lines in the code-only view, inline comments cut, comment lines gone."""
        end = getattr(node, "end_lineno", None) or node.lineno
        return [
            _cut_comment(line)
            for line in self.code_view()[node.lineno - 1 : end]
            if not _is_comment_line(line)
        ]

    def signature(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
        """The `def` line(s) up to the body, in the code-only view, so a person noun in a
        parameter is read as part of the decision and one in a docstring is not."""
        body_start = node.body[0].lineno if node.body else node.lineno + 1
        end = max(node.lineno, body_start - 1)
        return " ".join(self.code_view()[node.lineno - 1 : end])


def _string_line(node: ast.AST, text: str, start: int) -> int:
    """The physical line of a match at `start` inside a (possibly multi-line) constant."""
    return int(getattr(node, "lineno", 1)) + text[:start].count("\n")


def _excerpt(text: str, match: re.Match[str], margin: int = 60) -> str:
    lo = max(0, match.start() - margin)
    hi = min(len(text), match.end() + margin)
    return text[lo:hi]


# ---------------------------------------------------------------------------
# The checks. Each returns hits for one file; `_Emitter` dedupes by line per check.
# ---------------------------------------------------------------------------


class _Emitter:
    def __init__(self, check: str, file: str) -> None:
        self.check = check
        self.file = file
        self.title = CHECK_TITLES[check]
        self.hits: list[CheckHit] = []
        self.lines: set[int] = set()

    def add(self, line: int, snippet: str, **extra: Any) -> None:
        if line in self.lines:
            return
        self.lines.add(line)
        self.hits.append(CheckHit(self.check, self.file, line, snippet, self.title, dict(extra)))


def _strings_and_lines(
    file: _File, check: str, rx: re.Pattern[str], *, want_docstring_flag: bool = True
) -> list[CheckHit]:
    """The shared shape of a phrase check: every string constant (AST, f-strings whole),
    then every non-comment text line (which also covers a file that does not parse)."""
    out = _Emitter(check, file.relpath)
    for node, text, is_doc in file.strings():
        for match in rx.finditer(text):
            extra = {"in_docstring": is_doc} if want_docstring_flag else {}
            out.add(_string_line(node, text, match.start()), _excerpt(text, match), **extra)
    for number, line in file.code_lines():
        match = rx.search(line)
        if match is not None:
            out.add(number, line.strip(), in_docstring=False)
    return out.hits


def _check_hidden_ai_instruction(file: _File) -> list[CheckHit]:
    return _strings_and_lines(file, "hidden_ai_instruction", HIDE_AI_RE)


def _check_undesired_objective_language(file: _File) -> list[CheckHit]:
    return _strings_and_lines(file, "undesired_objective_language", UNDESIRED_OBJECTIVE_RE)


def _check_social_scoring_language(file: _File) -> list[CheckHit]:
    out = _Emitter("social_scoring_language", file.relpath)
    for number, line in file.code_lines():
        match = SOCIAL_SCORING_RE.search(line)
        if match is not None:
            out.add(number, line.strip(), term=match.group(0))
    return out.hits


def _check_emotion_recognition(file: _File) -> list[CheckHit]:
    out = _Emitter("emotion_recognition_in_work_or_education", file.relpath)
    if file.tree is not None:
        for node in ast.walk(file.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = node.name
                if EMOTION_RE.search(name) and WORK_EDU_RE.search(name):
                    out.add(node.lineno, file.line(node.lineno).strip(), symbol=name)
    for number, line in file.code_lines():
        if EMOTION_RE.search(line) and WORK_EDU_RE.search(line):
            out.add(number, line.strip())
    return out.hits


def _disclosure_present(source: str) -> bool:
    if DISCLOSURE_TEXT_RE.search(source):
        return True
    return any(rx.search(source) for _key, rx in vocab.DISCLOSURE_SYMBOLS)


def _check_response_function_without_disclosure(file: _File) -> list[CheckHit]:
    out = _Emitter("response_function_without_disclosure", file.relpath)
    for node in file.functions():
        if not RESPONSE_FN_RE.match(node.name):
            continue
        if _disclosure_present(file.body(node)):
            continue
        out.add(node.lineno, file.line(node.lineno).strip(), function=node.name)
    return out.hits


def _review_present(source: str) -> bool:
    approval = getattr(vocab, "APPROVAL_SYMBOLS", None) or _APPROVAL_FALLBACK_RE
    return bool(
        vocab.REVIEW_RE.search(source) or REVIEW_EXTRA_RE.search(source) or approval.search(source)
    )


def _check_decision_function_about_person(file: _File) -> list[CheckHit]:
    """A function with a decision verb in its name or in its code (strings and comments
    blanked through the tree's own spans, so a verb in a docstring or a prompt does not
    count). `person` says whether a PERSON_NOUN sits in the signature or on a code line;
    `reviewed` whether a review or approval symbol appears in the function's body, strings
    included (a config key names a control too) but never its own name. Neither flag removes
    the hit: the rule reads them."""
    out = _Emitter("decision_function_about_person", file.relpath)
    for node in file.functions():
        verb: str | None = None
        name_match = DECISION_VERB_RE.search(node.name)
        if name_match is not None:
            verb = name_match.group(0)
        code = file.code_of(node)
        if verb is None:
            for line in code:
                match = DECISION_VERB_RE.search(line)
                if match is not None:
                    verb = match.group(0)
                    break
        if verb is None:
            continue
        person = bool(vocab.PERSON_NOUN.search(file.signature(node))) or any(
            vocab.PERSON_NOUN.search(line) for line in code
        )
        out.add(
            node.lineno,
            file.line(node.lineno).strip(),
            function=node.name,
            verb=verb,
            person=person,
            reviewed=_review_present(file.body(node)),
        )
    return out.hits


def _pii_names(node: ast.AST) -> list[str]:
    """Identifiers an expression reads that name a personal data field: plain names,
    attributes (`user.email`) and string keys (`user["phone"]`)."""
    out: list[str] = []
    for sub in ast.walk(node):
        token: str | None = None
        if isinstance(sub, ast.Name):
            token = sub.id
        elif isinstance(sub, ast.Attribute):
            token = sub.attr
        elif isinstance(sub, ast.Subscript) and isinstance(sub.slice, ast.Constant):
            token = str(sub.slice.value) if isinstance(sub.slice.value, str) else None
        if token and PII_FIELD_RE.fullmatch(token) and token not in out:
            out.append(token)
    return out


def _is_assembly(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return any(
            isinstance(s, ast.JoinedStr)
            or (isinstance(s, ast.Constant) and isinstance(s.value, str))
            for s in (node.left, node.right)
        )
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return node.func.attr == "format"
    return False


def _check_personal_data_into_prompt(file: _File) -> list[CheckHit]:
    """A personal data field read into a prompt. AST: a string assembly that reads a field
    named like personal data, on a statement whose first line names a prompt. Text: a line
    assigning such a field with a prompt word on the same or the next line."""
    out = _Emitter("personal_data_into_prompt", file.relpath)
    if file.tree is not None:
        for node in ast.walk(file.tree):
            if not _is_assembly(node):
                continue
            fields = _pii_names(node)
            if not fields:
                continue
            statement = node
            while statement in file.parent and not isinstance(statement, ast.stmt):
                statement = file.parent[statement]
            head = file.line(getattr(statement, "lineno", node.lineno))
            if not PROMPT_WORD_RE.search(_cut_comment(head)):
                continue
            out.add(node.lineno, head.strip(), field=fields[0])
    code = dict(file.code_lines())
    for number, line in code.items():
        match = _PII_ASSIGN_RE.search(line)
        if match is None:
            continue
        window = line[match.end() :] + "\n" + code.get(number + 1, "")
        if PROMPT_WORD_RE.search(window):
            out.add(number, line.strip(), field=match.group(1))
    return out.hits


_CHECKERS: tuple[tuple[str, Callable[[_File], list[CheckHit]]], ...] = (
    ("hidden_ai_instruction", _check_hidden_ai_instruction),
    ("response_function_without_disclosure", _check_response_function_without_disclosure),
    ("decision_function_about_person", _check_decision_function_about_person),
    ("social_scoring_language", _check_social_scoring_language),
    ("emotion_recognition_in_work_or_education", _check_emotion_recognition),
    ("undesired_objective_language", _check_undesired_objective_language),
    ("personal_data_into_prompt", _check_personal_data_into_prompt),
)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _has_marker(text: str) -> bool:
    head = text.splitlines()[:_MARKER_LINES]
    return any(any(marker in line for marker in _MARKERS) for line in head)


def _read(record: Any) -> str | None:
    path = getattr(record, "path", None)
    if path is None:
        return None
    try:
        # `utf-8-sig`: a byte-order mark is not Python source and must not become a
        # parse failure that silences the tree pass.
        return Path(path).read_text(encoding="utf-8-sig", errors="replace")
    except (OSError, TypeError, ValueError):
        return None


def run_checks(
    records: Iterable[Any],
    texts: Mapping[str, str | None] | None = None,
    *,
    honour_marker: bool = True,
) -> CheckFacts:
    """Run every check over the Python records (`lang == "python"`).

    `texts` maps a relpath to its decoded text, or None when the walk could not read it;
    a record missing from the mapping is read from its path. A file whose first five lines
    carry the ignore marker is skipped and listed (never in auditor mode,
    `honour_marker=False`). Files are visited in path order and hits
    are sorted, so the same tree gives the same facts. Never raises: a check that fails on a
    file becomes an UNKNOWN item.
    """
    texts = texts or {}
    facts = CheckFacts()
    ordered = sorted(
        (r for r in records if getattr(r, "lang", None) == "python"),
        key=lambda r: str(getattr(r, "relpath", "")),
    )
    for record in ordered:
        relpath = str(record.relpath).replace("\\", "/")
        text = texts[relpath] if relpath in texts else _read(record)
        if text is None:
            continue
        if honour_marker and _has_marker(text):
            facts.skipped.append(relpath)
            continue
        facts.files += 1
        file = _File(relpath, text)
        for name, check in _CHECKERS:
            try:
                facts.by_check[name].extend(check(file))
            except Exception as exc:  # one bad check on one file must not sink the run
                facts.errors.append(
                    UnknownItem(
                        category=UnknownCategory.DEEP,
                        what=f"check {name}",
                        why=f"{type(exc).__name__}: {exc}",
                        how_to_resolve="report the file; the other checks and the grep tier still apply",
                        file=relpath,
                    )
                )
    for name in CHECK_NAMES:
        facts.by_check[name].sort(key=lambda h: h.key)
    return facts
