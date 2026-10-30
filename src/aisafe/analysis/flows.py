"""src/aisafe/analysis/flows.py
-----------------------------
Chain reconstruction. For every prompt in a Python unit, how far the audit can follow

    objective -> person data -> inference -> prompt -> intervention -> feedback

and how each link was established: `ast` (the syntax tree connects it: a name the prompt
reads, the call the prompt feeds, the return that carries the reply), `declared` (it sits
inside the prompt text the chain reads) or `co-located` (the same file, window or unit, which
is lexical co-occurrence and never a flow). `Flow.links_supported` is True when every present
link is supported; whether a finding's trace is complete depends on the links its policy
pattern requires (`Finding.trace_complete`). The scan never builds `investigated` links: only
an assessment adds them, from validated investigation records.

The rules copy the flow whose prompt link is nearest to their signal onto the finding; the
renderers print the chain with each link's status, and "lexical co-occurrence only" when
nothing is established. Nothing here decides anything: a flow says what connects to what,
and how well that was seen.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from aisafe.discovery import vocabulary as vocab
from aisafe.evidence.model import (
    FLOW_ESTABLISHED_BY,
    FLOW_LINK_KINDS,
    AuditContext,
    Flow,
    FlowLink,
)

__all__ = [
    "FEEDBACK_KINDS",
    "INFERENCE_KINDS",
    "METRIC_RE",
    "OBJECTIVE_KINDS",
    "PROFILE_KINDS",
    "build_flows",
    "flow_summary",
]

# Which person-signal kinds feed which link.
OBJECTIVE_KINDS = frozenset(
    {"engagement", "monetisation", "objective_code", "attachment", "steering"}
)
INFERENCE_KINDS = frozenset({"inference", "affect"})
FEEDBACK_KINDS = frozenset({"objective_code", "experiment"})
PROFILE_KINDS = frozenset({"profile_sdk", "profile_name", "profile_placeholder"})

# A feedback signal has to read a metric; an objective variable that names none is an
# objective, not a loop. The boundaries are letters, not `\b`: metrics live in snake_case
# identifiers (`engagement_score`, `compute_retention(`), where `\b` never matches.
METRIC_RE = re.compile(
    r"(?<![A-Za-z])(?:engagement|retention|session_(?:length|time)|dwell(?:_time)?|conversion"
    r"|revenue|arpu|ltv|churn|dau|streaks?|watch_time|time_on_app)(?![A-Za-z])",
    re.I,
)
_IMPORT_LINE_RE = re.compile(r"^\s*(?:from\s+\S+\s+import\b|import\s+\S+)")
_STATUS_ORDER = FLOW_ESTABLISHED_BY


def _posix(path: Any) -> str:
    return str(path).replace("\\", "/")


def _is_python(file: str, lang: str | None) -> bool:
    return lang == "python" or file.endswith((".py", ".pyi"))


def _is_profile_name(name: str) -> bool:
    """A profile-named identifier: not a transcript, not an explicit setting."""
    if not vocab.PROFILE_NAME_RE.search(name) or vocab.is_history_name(name):
        return False
    settings = getattr(vocab, "SETTINGS_EXCLUDE", None)
    return not (settings is not None and settings.search(name))


def _binding_re(name: str) -> re.Pattern[str]:
    escaped = re.escape(name)
    return re.compile(
        rf"(?:^|[\s(,]){escaped}\s*(?::[^=\n]*)?=(?!=)|\bfor\s+{escaped}\s+in\b"
        rf"|\bdef\s+\w+\([^)]*\b{escaped}\b|\bas\s+{escaped}\b"
    )


def _assigns_re(name: str) -> re.Pattern[str]:
    return re.compile(rf"^\s*(?:self\.)?{re.escape(name)}\s*(?::[^=\n]*)?=(?!=)")


def _ident_re(name: str) -> re.Pattern[str]:
    return re.compile(rf"\b{re.escape(name)}\b")


@dataclass(frozen=True)
class _Sig:
    file: str
    line: int
    kind: str
    key: str
    snippet: str
    unit: str | None
    candidate: bool  # a code hit outside prompt material; counts only inside a prompt span


@dataclass(frozen=True)
class _Span:
    file: str
    line: int
    end_line: int

    def covers(self, line: int) -> bool:
        return self.line <= line <= max(self.line, self.end_line)


class _Builder:
    """One run's view: the pydeep facts, the grep hits by file, the texts, and the links."""

    def __init__(self, ctx: AuditContext, text_of: Callable[[str], str | None]) -> None:
        self.ctx = ctx
        self.text_of = text_of
        pyfacts = ctx.pyfacts
        self.assemblies = list(getattr(pyfacts, "prompt_assemblies", None) or [])
        self.literals = list(getattr(pyfacts, "prompt_literals", None) or [])
        self.calls = list(getattr(pyfacts, "llm_calls", None) or [])
        self.replies = list(getattr(pyfacts, "reply_returns", None) or [])
        self.feeds: dict[int, int] = dict(getattr(pyfacts, "assembly_feeds_call", None) or {})
        self.literal_feeds: dict[int, int] = dict(
            getattr(pyfacts, "literal_feeds_call", None) or {}
        )
        self.signals: dict[str, list[_Sig]] = {}
        self.profile_to_prompt: dict[str, list[Any]] = {}
        self.grep_calls: dict[str, list[Any]] = {}
        self.grep_prompts: dict[str, list[Any]] = {}
        for hit in getattr(ctx, "hits", None) or []:
            file = _posix(hit.file)
            if hit.table in ("person_signal", "person_signal_candidate"):
                self.signals.setdefault(file, []).append(
                    _Sig(
                        file,
                        int(hit.line),
                        vocab.kind_of(hit.key),
                        hit.key,
                        hit.snippet,
                        hit.unit,
                        hit.table == "person_signal_candidate",
                    )
                )
            elif hit.table == "profile_to_prompt":
                self.profile_to_prompt.setdefault(file, []).append(hit)
            elif hit.table == "llm_call":
                self.grep_calls.setdefault(file, []).append(hit)
            elif hit.table == "prompt_assembly" and _is_python(file, getattr(hit, "lang", None)):
                self.grep_prompts.setdefault(file, []).append(hit)
        for sigs in self.signals.values():
            sigs.sort(key=lambda s: (s.line, s.kind, s.key))
        self.unit_by_file: dict[str, str | None] = {}
        for record in getattr(ctx, "files", None) or []:
            relpath = getattr(record, "relpath", None)
            if relpath is not None:
                self.unit_by_file[_posix(relpath)] = getattr(record, "unit", None)
        self._lines: dict[str, list[str]] = {}

    # -- text ------------------------------------------------------------------
    def lines(self, file: str) -> list[str]:
        if file not in self._lines:
            text = self.text_of(file)
            self._lines[file] = text.split("\n") if text else []
        return self._lines[file]

    def line(self, file: str, number: int, fallback: str = "") -> str:
        lines = self.lines(file)
        if 1 <= number <= len(lines):
            return lines[number - 1].rstrip("\r").strip() or fallback
        return fallback

    def unit(self, file: str) -> str | None:
        if file in self.unit_by_file:
            return self.unit_by_file[file]
        for sig in self.signals.get(file, []):
            if sig.unit is not None:
                return sig.unit
        return None

    def link(self, kind: str, file: str, line: int, by: str, fallback: str = "") -> FlowLink:
        return FlowLink(kind, file, line, self.line(file, line, fallback or "(no text)"), by)

    # -- shared pieces -----------------------------------------------------------
    def nearest(self, sigs: list[_Sig], line: int) -> _Sig:
        return min(sigs, key=lambda s: (abs(s.line - line), s.line, s.kind, s.key))

    def signal_link(
        self, kind: str, kinds: frozenset[str], file: str, spans: list[_Span], anchor: int
    ) -> list[FlowLink]:
        """One link of `kind` from the signals of `kinds` in `file`: `declared` when the
        signal sits inside one of the prompt spans the anchor reads, else `co-located`.
        A candidate (a code hit outside prompt material) counts only inside a span."""
        sigs = [s for s in self.signals.get(file, []) if s.kind in kinds]
        if not sigs:
            return []
        declared = [s for s in sigs if any(span.covers(s.line) for span in spans)]
        if declared:
            sig = self.nearest(declared, anchor)
            return [self.link(kind, file, sig.line, "declared", sig.snippet)]
        plain = [s for s in sigs if not s.candidate]
        if not plain:
            return []
        sig = self.nearest(plain, anchor)
        return [self.link(kind, file, sig.line, "co-located", sig.snippet)]

    def feedback_link(self, file: str, anchor: int) -> list[FlowLink]:
        """An objective variable or an experiment reading a metric, in the same unit."""
        unit = self.unit(file)
        found: list[_Sig] = []
        for other, sigs in self.signals.items():
            for sig in sigs:
                if sig.kind not in FEEDBACK_KINDS:
                    continue
                same_unit = unit is not None and sig.unit == unit
                if not (same_unit or other == file):
                    continue
                text = self.line(other, sig.line, sig.snippet)
                if METRIC_RE.search(text) or METRIC_RE.search(sig.snippet):
                    found.append(sig)
        if not found:
            return []
        local = [s for s in found if s.file == file]
        sig = self.nearest(local, anchor) if local else min(found, key=lambda s: (s.file, s.line))
        return [self.link("feedback", sig.file, sig.line, "co-located", sig.snippet)]

    def binding_line(self, file: str, name: str, before: int) -> int:
        """The nearest line above `before` that binds `name`, else `before` itself."""
        rx = _binding_re(name)
        lines = self.lines(file)
        for number in range(min(before - 1, len(lines)), 0, -1):
            if rx.search(lines[number - 1]):
                return number
        return before

    def profile_line_for(self, file: str, key: str, before: int) -> int:
        """The nearest profile signal line above `before` whose text names `key`."""
        rx = _ident_re(key)
        best = 0
        for sig in self.signals.get(file, []):
            if (
                sig.kind in PROFILE_KINDS
                and sig.line < before
                and rx.search(self.line(file, sig.line))
            ):
                best = max(best, sig.line)
        return best or before

    def profile_colocated(self, file: str, anchor: int, spans: list[_Span]) -> list[FlowLink]:
        """The person data link when the syntax tree does not connect one: a placeholder
        inside the prompt text (`declared`), a profile-to-prompt grep hit on the prompt line,
        or the nearest profile signal in the file (both `co-located`)."""
        placeholders = [
            s
            for s in self.signals.get(file, [])
            if s.kind == "profile_placeholder" and any(span.covers(s.line) for span in spans)
        ]
        if placeholders:
            sig = self.nearest(placeholders, anchor)
            return [self.link("person_data", file, sig.line, "declared", sig.snippet)]
        for hit in self.profile_to_prompt.get(file, []):
            if any(span.covers(int(hit.line)) for span in spans):
                source = self.profile_line_for(file, hit.key, int(hit.line))
                return [self.link("person_data", file, source, "co-located", hit.key)]
        profiles = [s for s in self.signals.get(file, []) if s.kind in PROFILE_KINDS]
        if not profiles:
            return []
        sig = self.nearest(profiles, anchor)
        return [self.link("person_data", file, sig.line, "co-located", sig.snippet)]

    def reply_for(self, call: Any) -> Any | None:
        """The reply site in the same file and function as `call`, the first after it."""
        file = _posix(call.file)
        same = [
            r
            for r in self.replies
            if _posix(r.file) == file and getattr(r, "function", None) == call.function
        ]
        if not same:
            return None
        after = [r for r in same if r.line >= call.line]
        return min(after or same, key=lambda r: r.line)

    def call_links(self, index: int | None) -> list[FlowLink]:
        """`ast` intervention links for a fed call: the call, and its reply when one leaves
        the same function."""
        if index is None or not (0 <= index < len(self.calls)):
            return []
        call = self.calls[index]
        file = _posix(call.file)
        links = [self.link("intervention", file, call.line, "ast", f"{call.provider} call")]
        reply = self.reply_for(call)
        if reply is not None:
            links.append(
                self.link("intervention", _posix(reply.file), reply.line, "ast", reply.name)
            )
        return links

    def nearest_call_link(self, file: str, anchor: int) -> list[FlowLink]:
        """The nearest model call in the file, `co-located`: pydeep sites first, then grep
        hits that are calls rather than import lines."""
        sites = [c for c in self.calls if _posix(c.file) == file]
        if sites:
            call = min(sites, key=lambda c: (abs(c.line - anchor), c.line))
            return [
                self.link("intervention", file, call.line, "co-located", f"{call.provider} call")
            ]
        hits = [
            h
            for h in self.grep_calls.get(file, [])
            if not _IMPORT_LINE_RE.match(self.line(file, int(h.line), h.snippet))
        ]
        if not hits:
            return []
        hit = min(hits, key=lambda h: (abs(int(h.line) - anchor), int(h.line)))
        return [self.link("intervention", file, int(hit.line), "co-located", hit.snippet)]

    # -- anchors -----------------------------------------------------------------
    def literals_read_by(self, file: str, names: tuple[str, ...]) -> list[tuple[int, Any]]:
        return [
            (j, lit)
            for j, lit in enumerate(self.literals)
            if _posix(lit.file) == file and lit.name in names
        ]

    def flow_for_assembly(self, index: int, assembly: Any) -> Flow:
        file = _posix(assembly.file)
        span = _Span(file, assembly.line, getattr(assembly, "end_line", 0) or assembly.line)
        read = self.literals_read_by(file, tuple(assembly.source_names))
        spans = [span] + [_Span(file, lit.line, lit.end_line) for _j, lit in read]
        links = [
            self.link("prompt", file, assembly.line, "ast", f"{assembly.kind} prompt assembly")
        ]
        links += self.person_data_for_assembly(assembly, file, span, spans)
        fed = self.call_links(self.feeds.get(index))
        links += fed or self.nearest_call_link(file, assembly.line)
        links += self.signal_link("objective", OBJECTIVE_KINDS, file, spans, assembly.line)
        links += self.signal_link("inference", INFERENCE_KINDS, file, spans, assembly.line)
        links += self.feedback_link(file, assembly.line)
        return Flow(links=links)

    def person_data_for_assembly(
        self, assembly: Any, file: str, span: _Span, spans: list[_Span]
    ) -> list[FlowLink]:
        names = [n for n in assembly.source_names if _is_profile_name(n)]
        if names:
            line = self.binding_line(file, names[0], assembly.line)
            return [self.link("person_data", file, line, "ast", names[0])]
        # A profile SDK call bound to a name the assembly reads: the read is in the tree,
        # the binding is a plain assignment on the SDK line.
        for sig in self.signals.get(file, []):
            if sig.kind != "profile_sdk":
                continue
            text = self.line(file, sig.line)
            if any(_assigns_re(n).match(text) for n in assembly.source_names):
                return [self.link("person_data", file, sig.line, "ast", sig.snippet)]
        return self.profile_colocated(file, assembly.line, spans)

    def flow_for_literal(self, index: int, literal: Any) -> Flow:
        file = _posix(literal.file)
        span = _Span(file, literal.line, literal.end_line)
        links = [self.link("prompt", file, literal.line, "ast", f"{literal.name} prompt literal")]
        links += self.profile_colocated(file, literal.line, [span])
        fed = self.call_links(self.literal_feeds.get(index))
        if not fed:
            # The literal reaches the model through an assembly that reads it.
            for i, assembly in enumerate(self.assemblies):
                if _posix(assembly.file) == file and literal.name in assembly.source_names:
                    fed = self.call_links(self.feeds.get(i))
                    if fed:
                        break
        links += fed or self.nearest_call_link(file, literal.line)
        links += self.signal_link("objective", OBJECTIVE_KINDS, file, [span], literal.line)
        links += self.signal_link("inference", INFERENCE_KINDS, file, [span], literal.line)
        links += self.feedback_link(file, literal.line)
        return Flow(links=links)

    def flow_for_grep(self, file: str, line: int, snippet: str) -> Flow:
        """A prompt the grep tier saw in a Python file the syntax tree could not read: every
        link is co-located, so the chain reads as lexical co-occurrence only."""
        span = _Span(file, line, line)
        links = [self.link("prompt", file, line, "co-located", snippet)]
        links += self.profile_colocated(file, line, [span])
        links += self.nearest_call_link(file, line)
        links += self.signal_link("objective", OBJECTIVE_KINDS, file, [], line)
        links += self.signal_link("inference", INFERENCE_KINDS, file, [], line)
        links += self.feedback_link(file, line)
        return Flow(links=links)

    def build(self) -> list[Flow]:
        flows: list[tuple[tuple[str, int, int], Flow]] = []
        anchored: set[str] = set()
        assembly_lines: set[tuple[str, int]] = set()
        for index, assembly in enumerate(self.assemblies):
            file = _posix(assembly.file)
            anchored.add(file)
            assembly_lines.add((file, assembly.line))
            flows.append(((file, assembly.line, 0), self.flow_for_assembly(index, assembly)))
        for index, literal in enumerate(self.literals):
            file = _posix(literal.file)
            anchored.add(file)
            # An f-string assigned to a prompt name is recorded as both a literal (for its
            # span) and an assembly (for its names); the assembly's flow is the richer one.
            if literal.is_system and (file, literal.line) not in assembly_lines:
                flows.append(((file, literal.line, 1), self.flow_for_literal(index, literal)))
        for file, hits in sorted(self.grep_prompts.items()):
            if file in anchored:
                continue
            seen: set[int] = set()
            for hit in sorted(hits, key=lambda h: int(h.line)):
                line = int(hit.line)
                if line in seen:
                    continue
                seen.add(line)
                flows.append(((file, line, 2), self.flow_for_grep(file, line, hit.snippet)))
        flows.sort(key=lambda item: item[0])
        return [flow for _key, flow in flows]


def build_flows(ctx: AuditContext) -> list[Flow]:
    """The reconstructed chains of a run, one per prompt assembly, system prompt literal,
    or (in a Python file the syntax tree could not read) grep-level prompt line. Empty when
    the deep pass did not run (`ctx.pyfacts is None`)."""
    if getattr(ctx, "pyfacts", None) is None:
        return []
    # Local import: the rules package imports every rule module, and the rules read
    # `ctx.flows`; importing it at module level would tie the two together at load time.
    from aisafe.rules import file_text

    return _Builder(ctx, lambda relpath: file_text(ctx, relpath)).build()


def flow_summary(flow: Flow | None) -> str:
    """The chain as the renderers print it: each present kind with how it was established,
    e.g. "objective (declared) -> person data (ast) -> prompt (ast) -> intervention
    (co-located)"; "lexical co-occurrence only" when no link is supported."""
    links = list(getattr(flow, "links", None) or [])
    if not links or not any(link.supported for link in links):
        return "lexical co-occurrence only"
    parts: list[str] = []
    for kind in FLOW_LINK_KINDS:
        statuses = sorted(
            {link.established_by for link in links if link.kind == kind}, key=_STATUS_ORDER.index
        )
        if statuses:
            parts.append(f"{kind.replace('_', ' ')} ({', '.join(statuses)})")
    return " -> ".join(parts)
