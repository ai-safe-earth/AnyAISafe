# aisafe-audit: ignore-file
"""src/aisafe/rules/influence.py
-----------------------------
Mechanisms M4, M5 and M7: the objectives and instructions that aim the system at the
person's attention, attachment or opinions. AUD-1104 reads engagement, retention, spend and
experimentation objectives (M4); AUD-1109 reads instructions that engineer affection,
exclusivity, guilt, dependency or relationship substitution (M5); AUD-1110 reads covert
commercial or political steering (M7).

Evidence tiers: an instruction inside prompt material (a prompt file, a system prompt
literal, a prompt assembly line, or a code candidate a pydeep literal promotes) is a
`supported_mechanism`; a variable, a scheduler, a send, an experiment flag or an affiliate
parameter in code is a `detected_signal` until the syntax tree ties it to a model call, a
training call or a profile read. The decision is the policy's, never a score: a supported
instruction violates it, a detected signal is recorded for contextual review. Fiction or
roleplay framing is written on the finding and never lowers an attachment instruction.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from aisafe.discovery import patterns
from aisafe.discovery import vocabulary as vocab
from aisafe.evidence.model import (
    AuditContext,
    Basis,
    Decision,
    EvidenceKind,
    EvidenceStatus,
    Finding,
    Flow,
    MatchKind,
    Recommendation,
    Severity,
    Tier,
)
from aisafe.rules import AuditRule, Candidate, emit_groups
from aisafe.rules._common import (
    LEGAL_CAVEAT,
    Facts,
    Signal,
    attach_check_legs,
    candidate,
    check_hits,
    facts,
    fiction_context,
    flow_for,
    has_ai_surface,
    is_code_file,
    line_at,
    posix,
    surface_legs,
    unit_id_of,
    vulnerable_nearby,
    window_text,
)

__all__ = [
    "RULES",
    "CovertSteering",
    "EngagementObjective",
    "EngineeredAttachment",
    "SubRow",
]

# One documented shape a rule can emit: (sub or None, severity, evidence status, decision,
# one-line meaning). A rule's `SUBS` lists every shape; two rows may share a sub when the
# same instruction is read at two evidence tiers.
SubRow = tuple[str | None, Severity, EvidenceStatus, Decision, str]

_FICTION_NOTE = "fictional framing recorded; not an exemption"
_NEUTRAL_WINDOW = 2
_PROFILE_KINDS = ("profile_name", "profile_placeholder", "profile_sdk")
# A call that optimises or orders by a variable: the objective is read by something that
# learns or ranks, not only logged.
_TRAINING_CALL_RE = re.compile(
    r"\.(?:fit|train|train_on_batch|partial_fit|backward|compile|rank|rerank|sort|argsort"
    r"|topk|nlargest|minimize|maximize|optimize)\(|\b(?:sorted|rank|rerank|minimize|maximize"
    r"|optimize)\(|\b(?:PPO|DPO|SFT|RL|Reward)?Trainer\(|\boptimizer\s*[=.(]|\bloss\.backward\b",
    re.I,
)
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_SENTENCE_END_RE = re.compile(r"[.!?](?=\s|$)")
# What a sentence may start with before its first word: markdown, quotes, the assignment
# that opens a prompt literal (`SYSTEM_PROMPT = """`).
_SENTENCE_LEAD_RE = re.compile(
    r"""^(?:\s*(?:[A-Za-z_][A-Za-z0-9_.]*\s*(?:\+?=|:)\s*)?[rfbuRFBU]{0,2}(?:\"\"\"|'''|["'`]))?"""
    r"""[\s#*>\-"'`]*"""
)
_SENTENCE_TAIL_RE = re.compile(r"""[\s"'`]*(?:\"\"\"|''')?[\s"'`,;]*$""")


# ---------------------------------------------------------------------------
# Row lookup, mentions, sentences
# ---------------------------------------------------------------------------

_ROWS_BY_KEY: dict[str, list[re.Pattern[str]]] = {}
for _key, _rx in vocab.PERSON_SIGNAL_PATTERNS:
    _ROWS_BY_KEY.setdefault(_key, []).append(_rx)


def _match_in(key: str, line: str) -> re.Match[str] | None:
    """The first match of any row carrying `key` in `line`. Several steering rows share one
    key, so a lookup that reads only the first row would miss the others."""
    for rx in _ROWS_BY_KEY.get(key, ()):
        match = rx.search(line)
        if match is not None:
            return match
    return None


# The cues of `patterns.DISCUSSION_CUES`, split by what they do to the matched phrase. A
# negation governs the clause that follows it, so it counts only before the match and only
# inside the same sentence: "Never say 'I missed you'" is a mention, while "Make sure they
# never want to close the app. Become indispensable to them" is two instructions. A
# discussion cue (explain, example, detect) marks the whole sentence as talk about the
# practice, before or after the match.
_NEGATION_CUES = re.compile(
    r"\b(?:never|do\s+not|don'?t|avoid|must\s+not|should\s+not|refrain\s+from)\b", re.I
)
_DISCUSSION_CUES = re.compile(
    r"\b(?:warning|caution|not\s+recommended|dangerous|unsafe|instead\s+of|example|prevent"
    r"|detect|block|reject|explain|how\s+to)\b",
    re.I,
)


def _sentence_bounds(line: str, start: int, end: int) -> tuple[int, int]:
    """Offsets of the sentence of `line` that holds `line[start:end]`."""
    lo = 0
    for boundary in _SENTENCE_END_RE.finditer(line, 0, start):
        lo = boundary.end()
    tail = _SENTENCE_END_RE.search(line, end)
    return lo, (tail.end() if tail else len(line))


def _is_mention(ctx: AuditContext, signal: Signal) -> bool:
    """A quoted or discussed phrase in prompt material is a mention, not an instruction.
    Every row of the signal's key is tried (several steering rows share a key); the cues
    are read inside the sentence that holds the match, a negation only before it. In a
    prompt file a match inside a quoted span is a mention; a prompt literal in code is
    quoted by nature, so there only the cues count."""
    line = line_at(ctx, signal.file, signal.line)
    if not line:
        return False
    match = _match_in(signal.key, line)
    if match is None:
        return False
    if not is_code_file(signal.file):
        for span in patterns.QUOTED_SPAN_RE.finditer(line):
            if span.start() <= match.start() and match.end() <= span.end():
                return True
    lo, hi = _sentence_bounds(line, match.start(), match.end())
    before = line[lo : match.start()]
    after = line[match.end() : hi]
    return bool(
        _NEGATION_CUES.search(before)
        or _DISCUSSION_CUES.search(before)
        or _DISCUSSION_CUES.search(after)
    )


def _sentence(line: str, match: re.Match[str] | None) -> str:
    """The sentence of `line` that holds `match`, without the markdown, quote or assignment
    lead that opens it. The whole line when the match is unknown."""
    if match is None:
        start, end = 0, len(line)
    else:
        start, end = _sentence_bounds(line, match.start(), match.end())
    text = line[start:end]
    text = _SENTENCE_LEAD_RE.sub("", text, count=1)
    text = _SENTENCE_TAIL_RE.sub("", text, count=1)
    return " ".join(text.split())


def _encoded(ctx: AuditContext, signal: Signal) -> str:
    """The quoted instruction a finding rests on: the matching sentence of the line."""
    line = line_at(ctx, signal.file, signal.line, signal.symbol)
    return _sentence(line, _match_in(signal.key, line)) or signal.symbol


def _symbol(ctx: AuditContext, signal: Signal) -> str:
    """What the signal matched, for the notes: the identifier discover confirmed next to a
    personalised send (from the inventory row), else the row's match on the line, else the
    hit text. `Signal.symbol` itself is the whole line."""
    if signal.kind == "outreach_personalised":
        for row in getattr(ctx.inventory, "person_signals", None) or []:
            if (
                row.get("file") == signal.file
                and int(row.get("line") or 0) == signal.line
                and row.get("kind") == signal.kind
                and row.get("symbol")
            ):
                return str(row["symbol"])
    line = line_at(ctx, signal.file, signal.line)
    match = _match_in(signal.key, line) if line else None
    return match.group(0).strip().rstrip("(").strip() if match is not None else signal.symbol


def _chain_gaps(ctx: AuditContext, signal: Signal, flow: Flow | None) -> tuple[str, ...]:
    if flow is not None:
        return ()
    if is_code_file(signal.file) and getattr(ctx, "pyfacts", None) is None:
        return ("grep tier only: the flow from this prompt to the model call was not established",)
    return ("the model call that reads this prompt material was not located in the tree",)


def _same_span(
    out: Facts, ctx: AuditContext, signal: Signal, kinds: tuple[str, ...]
) -> Signal | None:
    """A signal of one of `kinds` inside the same prompt literal as `signal`, else on the
    same line; None when nothing shares the span."""
    literal = out.literal_at(signal.file, signal.line)
    for other in out.in_file(signal.file, *kinds):
        if literal is not None:
            if out.literal_at(other.file, other.line) is literal:
                return other
        elif other.line == signal.line:
            return other
    return None


def _unit_key(cand: Candidate) -> str | None:
    return cand.unit.id if cand.unit else None


# ---------------------------------------------------------------------------
# AUD-1104  Engagement, retention, spend or experimentation objective (M4)
# ---------------------------------------------------------------------------

_OBJECTIVE_UNCERTAINTY = (
    "The row reads an imperative over engagement; a prompt that describes the product's "
    "tone, or a rule to ask a clarifying question, can match."
)
_CODE_OBJECTIVE_UNCERTAINTY = (
    "A reward or metric variable named after engagement may feed a dashboard rather than "
    "an optimiser; the training-call check reads one function."
)
_VULNERABLE_UNCERTAINTY = (
    "The vulnerable-group word may describe the audience without the objective being aimed "
    "at it; the finding reports the co-occurrence."
)
_OUTREACH_UNCERTAINTY = (
    "A scheduled send may be a reminder the person asked for that the code does not label as such."
)
_OUTREACH_PERSONALISED_UNCERTAINTY = (
    "The identifier read next to the send may name the person without choosing the message."
)
_MONETISATION_UNCERTAINTY = (
    "An imperative over a money metric may address a sales team rather than the person in "
    "the conversation."
)
_METRIC_UNCERTAINTY = "A money metric in an objective variable may be a reporting field."
_EXPERIMENT_UNCERTAINTY = (
    "The metric may measure something other than the prompt variants, and participants may "
    "have been told elsewhere."
)


class EngagementObjective(AuditRule):
    id = "AUD-1104"
    title = "Engagement, retention, spend or experimentation objective"
    version = 2
    changed = (
        "v2: a prompt objective is a supported mechanism that violates the policy; an "
        "objective variable in code is a detected signal for review unless a training or "
        "ranking call in the same function reads it",
        "v2: /outreach is silent when the same file holds a reminder the person set, and "
        "becomes /outreach-personalised (violates) when the message is chosen by the "
        "person's profile or inferred state",
        "v2: new /monetisation (an imperative over a money metric in prompt material "
        "violates; a metric variable is reviewed) and /experiment (prompt variants under an "
        "experiment flag measured by an engagement, retention or revenue metric)",
        "v2: fixed interface copy (ui_text) is listed in the inventory and never fires; "
        "priority is the policy's mechanism order; references replace controls",
    )
    severity = Severity.HIGH
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.GREP
    default_evidence_status = EvidenceStatus.DETECTED_SIGNAL
    default_decision = Decision.REVIEW
    requires_ai_surface = True
    tier = Tier.T2
    references = (
        "EU:Art.5(1)(a)",
        "EU:Art.5(1)(b)",
        "US-CA:SB1119",
        "US-WA:HB2225",
        "DSA:Art.25",
        "LLM09",
        "NIST:GOVERN-1.1",
        "NIST:MAP-5.1",
        "NIST:MEASURE-2.11",
    )
    SUBS: tuple[SubRow, ...] = (
        (
            None,
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
            "an engagement or retention objective in prompt material",
        ),
        (
            None,
            Severity.HIGH,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "an objective or reward variable in code names engagement; supported and violates "
            "when a training or ranking call in the same function reads it",
        ),
        (
            "vulnerable",
            Severity.CRITICAL,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
            "the objective names a vulnerable group in the same prompt literal or file",
        ),
        (
            "outreach",
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "a scheduled job and a send to a person in one file, no reminder the person set",
        ),
        (
            "outreach-personalised",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
            "the scheduled send's message is chosen by the person's profile or inferred state",
        ),
        (
            "monetisation",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
            "an imperative over conversion, revenue, spend or upsells in prompt material",
        ),
        (
            "monetisation",
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "an objective or metric variable in code names a money metric",
        ),
        (
            "experiment",
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "prompt variants under an experiment flag, measured by an engagement, retention "
            "or revenue metric in the same unit",
        ),
    )
    known_failure_modes = (
        "a product-analytics dashboard that computes engagement is not an objective: the rule "
        "needs an imperative (maximise, keep, increase) or an objective assignment",
        "the vulnerable sub-finding rests on two regex co-occurrences in one file or prompt "
        "literal; a reading app for children with a streak feature is reported CRITICAL, and "
        "the finding says what co-occurred",
        "a prompt that discusses engagement tactics in order to avoid them is a mention when "
        "a discussion cue sits within 80 characters; without one it is reported, and a cue "
        "in the sentence before a real instruction hides it",
        "the outreach sub-finding pairs a schedule and a send in one file: an alert to an "
        "operator's own channel is reported too, a schedule in one file with the send in "
        "another (a job queue) is not paired, and a send chosen by the person's state with "
        "no scheduler in its file is not reported here",
        "a reminder the person set silences the outreach sub-finding for the whole file, "
        "including a second, unrelated send in that file",
        "the monetisation imperative reads any prompt material: a sales assistant told to "
        "improve sales is reported, and whether the pressure lands on the person in the "
        "conversation is for review",
        "whether an objective variable feeds a training or ranking call is read from one "
        "function's text; a variable passed through a dict or a second module stays a "
        "detected signal",
        "an experiment is read from a variant flag near a prompt and a metric word in the "
        "same unit; an experiment framework that hides both behind a client call is missed",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Rewrite the objective as task completion and the person's own stated goals; "
            "remove streak, scarcity and variable-reward mechanics from the model's "
            "instructions; send only messages the person asked for, at the time they chose; "
            "measure prompt experiments by task outcomes and tell participants."
        ),
        alternatives=(
            "rewrite the prompt objective as task completion and the person's stated goals",
            "remove streak, scarcity and variable-reward mechanics from the LLM-facing instructions",
            "replace scheduled re-engagement with reminders the person sets and can switch off",
            "measure prompt experiments by task outcomes, with a notice to participants",
            "an independent review of ranking and reward objectives, recorded with "
            "aisafe review record",
        ),
        removes=("objective", "intervention", "feedback"),
    )

    # -- objectives --------------------------------------------------------------

    def _feeds_training(self, ctx: AuditContext, signal: Signal) -> str | None:
        """The training or ranking call line that reads the objective variable, in the
        function pydeep spans around the signal; None when nothing reads it (or no deep pass)."""
        pyfacts = getattr(ctx, "pyfacts", None)
        if pyfacts is None:
            return None
        span: tuple[int, int] | None = None
        for info in (getattr(pyfacts, "functions", None) or {}).values():
            if posix(info.file) != signal.file or info.name is None:
                continue
            if info.line <= signal.line <= max(info.line, info.end_line):
                if span is None or info.line > span[0]:
                    span = (info.line, max(info.line, info.end_line))
        if span is None:
            return None
        text = window_text(ctx, signal.file, span[0], span[1] - span[0] + 1)
        match = _IDENT_RE.search(_symbol(ctx, signal))
        name = match.group(0) if match else ""
        name_re = re.compile(rf"\b{re.escape(name)}\b") if name else None
        for raw in text.split("\n"):
            if _TRAINING_CALL_RE.search(raw) and (name_re is None or name_re.search(raw)):
                return raw.strip()
        return None

    def _objectives(self, ctx: AuditContext, out: Facts, put: Callable[[Candidate], None]) -> None:
        for signal in out.by_kind("engagement"):
            if _is_mention(ctx, signal):
                continue
            word = vulnerable_nearby(ctx, out, signal)
            flow = flow_for(ctx, signal.file, signal.line, out=out)
            notes = (
                f"an engagement or retention objective in prompt material ({_symbol(ctx, signal)})"
            )
            sub, severity, uncertainty = None, Severity.HIGH, _OBJECTIVE_UNCERTAINTY
            if word:
                sub, severity, uncertainty = (
                    "vulnerable",
                    Severity.CRITICAL,
                    _VULNERABLE_UNCERTAINTY,
                )
                notes += f"; a vulnerable group is named alongside ({word})"
            if fiction_context(ctx, out, signal.file, signal.line):
                notes += f"; {_FICTION_NOTE}"
            put(
                candidate(
                    ctx,
                    signal,
                    notes=f"{notes}. {LEGAL_CAVEAT}",
                    sub=sub,
                    severity=severity,
                    evidence_status=EvidenceStatus.SUPPORTED_MECHANISM,
                    decision=Decision.VIOLATES,
                    flow=flow,
                    encoded_objective=_encoded(ctx, signal),
                    affected_population=word,
                    coverage_gaps=_chain_gaps(ctx, signal, flow),
                    uncertainty=uncertainty,
                )
            )
        for signal in out.by_kind("objective_code"):
            if _is_mention(ctx, signal):
                continue
            self._code_objective(
                ctx, out, put, signal, what="an objective or reward variable optimises engagement"
            )

    def _code_objective(
        self,
        ctx: AuditContext,
        out: Facts,
        put: Callable[[Candidate], None],
        signal: Signal,
        *,
        what: str,
        sub: str | None = None,
        review_severity: Severity = Severity.HIGH,
    ) -> None:
        """An objective variable in code: a detected signal for review, a supported mechanism
        that violates the policy once a training or ranking call in the same function reads it."""
        word = vulnerable_nearby(ctx, out, signal)
        trained = self._feeds_training(ctx, signal)
        symbol = _symbol(ctx, signal)
        gaps: tuple[str, ...] = ()
        if trained is not None:
            notes = (
                f"{what} ({symbol}) and a training or ranking call in the same function "
                f"reads it ({trained})"
            )
            status, decision, severity = (
                EvidenceStatus.SUPPORTED_MECHANISM,
                Decision.VIOLATES,
                Severity.HIGH,
            )
            uncertainty = _CODE_OBJECTIVE_UNCERTAINTY
            if word:
                sub, severity, uncertainty = (
                    "vulnerable",
                    Severity.CRITICAL,
                    _VULNERABLE_UNCERTAINTY,
                )
                notes += f"; a vulnerable group is named alongside ({word})"
        else:
            notes = (
                f"{what} ({symbol}); no training or ranking call in the same function was "
                "seen to read it"
            )
            status, decision, severity = (
                EvidenceStatus.DETECTED_SIGNAL,
                Decision.REVIEW,
                review_severity,
            )
            uncertainty = _CODE_OBJECTIVE_UNCERTAINTY if sub is None else _METRIC_UNCERTAINTY
            if word:
                notes += f"; a vulnerable group is named in the same file ({word})"
            if getattr(ctx, "pyfacts", None) is None:
                gaps = (
                    "grep tier only: whether the objective feeds a training or ranking call "
                    "was not read",
                )
        put(
            candidate(
                ctx,
                signal,
                notes=f"{notes}. {LEGAL_CAVEAT}",
                sub=sub,
                severity=severity,
                evidence_status=status,
                decision=decision,
                encoded_objective=line_at(ctx, signal.file, signal.line, signal.symbol),
                affected_population=word,
                coverage_gaps=gaps,
                uncertainty=uncertainty,
            )
        )

    # -- monetisation ------------------------------------------------------------

    def _monetisation(
        self, ctx: AuditContext, out: Facts, put: Callable[[Candidate], None]
    ) -> None:
        for signal in out.by_kind("monetisation"):
            if _is_mention(ctx, signal):
                continue
            if signal.key == "monetisation:metric":
                self._code_objective(
                    ctx,
                    out,
                    put,
                    signal,
                    what="an objective or metric variable names a money metric",
                    sub="monetisation",
                    review_severity=Severity.MEDIUM,
                )
                continue
            word = vulnerable_nearby(ctx, out, signal)
            flow = flow_for(ctx, signal.file, signal.line, out=out)
            notes = (
                "an instruction to maximise conversion, revenue, spend or upsells in prompt "
                f"material ({_symbol(ctx, signal)})"
            )
            if word:
                notes += f"; a vulnerable group is named alongside ({word})"
            if fiction_context(ctx, out, signal.file, signal.line):
                notes += f"; {_FICTION_NOTE}"
            put(
                candidate(
                    ctx,
                    signal,
                    notes=f"{notes}. {LEGAL_CAVEAT}",
                    sub="monetisation",
                    severity=Severity.HIGH,
                    evidence_status=EvidenceStatus.SUPPORTED_MECHANISM,
                    decision=Decision.VIOLATES,
                    flow=flow,
                    encoded_objective=_encoded(ctx, signal),
                    affected_population=word,
                    coverage_gaps=_chain_gaps(ctx, signal, flow),
                    uncertainty=_MONETISATION_UNCERTAINTY,
                )
            )

    # -- experiments -------------------------------------------------------------

    def _experiments(self, ctx: AuditContext, out: Facts, put: Callable[[Candidate], None]) -> None:
        flags = [
            s
            for s in out.by_kind("experiment")
            if s.key in ("experiment:prompt_variant", "experiment:flag")
        ]
        seen_files: set[str] = set()
        for signal in sorted(flags, key=lambda s: (s.file, s.line)):
            if signal.file in seen_files or _is_mention(ctx, signal):
                continue
            seen_files.add(signal.file)
            metrics = [
                m
                for m in out.in_unit(signal.unit, "experiment", "objective_code", "monetisation")
                if m.key in ("experiment:metric", "objective_code:target", "monetisation:metric")
            ]
            if not metrics:
                continue
            names = sorted({_symbol(ctx, m) for m in metrics})[:3]
            notes = (
                f"an experiment on prompt variants ({_symbol(ctx, signal)}) measured by "
                f"{', '.join(names)}; whether participants were told is not visible in code"
            )
            put(
                candidate(
                    ctx,
                    signal,
                    notes=f"{notes}. {LEGAL_CAVEAT}",
                    sub="experiment",
                    severity=Severity.MEDIUM,
                    evidence_status=EvidenceStatus.DETECTED_SIGNAL,
                    decision=Decision.REVIEW,
                    encoded_objective=line_at(ctx, signal.file, signal.line, signal.symbol),
                    uncertainty=_EXPERIMENT_UNCERTAINTY,
                )
            )

    # -- outreach ----------------------------------------------------------------

    def _outreach(self, ctx: AuditContext, out: Facts, put: Callable[[Candidate], None]) -> None:
        """A scheduled job and a send to a person in the same file. A reminder the person set
        in that file keeps the rule silent; a send whose message is chosen by what the system
        holds or infers about the person is the stronger sub-finding."""
        schedules: dict[str, Signal] = {}
        for signal in out.by_kind("outreach_schedule"):
            schedules.setdefault(signal.file, signal)
        reminder_files = {s.file for s in out.by_kind("user_set_reminder")}
        personalised: dict[str, Signal] = {}
        for signal in out.by_kind("outreach_personalised"):
            personalised.setdefault(signal.file, signal)
        paired: set[str] = set()
        for send in sorted(out.by_kind("outreach_send"), key=lambda s: (s.file, s.line)):
            schedule = schedules.get(send.file)
            if schedule is None or send.file in paired:
                continue
            paired.add(send.file)
            if send.file in reminder_files:
                continue
            chosen = personalised.get(send.file)
            job, call = _symbol(ctx, schedule), _symbol(ctx, send)
            if chosen is not None:
                ident = _symbol(ctx, chosen)
                notes = (
                    f"a job on a schedule ({job}) and a send to a person ({call}) in one file, "
                    "and the message sent is chosen by what the system holds or infers about "
                    f"the person ({ident}): a re-engagement message shaped by the person's "
                    "state or profile"
                )
                sites = [schedule, chosen, send]
                sub, severity = "outreach-personalised", Severity.HIGH
                status, decision = EvidenceStatus.SUPPORTED_MECHANISM, Decision.VIOLATES
                person_data, uncertainty = ident, _OUTREACH_PERSONALISED_UNCERTAINTY
            else:
                notes = (
                    f"a job on a schedule ({job}) and a send to a person ({call}) in one file: "
                    "a message the person did not ask for is a retention mechanism, a reminder "
                    "they set is a service, and the code does not say which"
                )
                sites = [schedule, send]
                sub, severity = "outreach", Severity.MEDIUM
                status, decision = EvidenceStatus.DETECTED_SIGNAL, Decision.REVIEW
                person_data, uncertainty = None, _OUTREACH_UNCERTAINTY
            for site in sites:
                put(
                    candidate(
                        ctx,
                        site,
                        notes=f"{notes}. {LEGAL_CAVEAT}",
                        sub=sub,
                        severity=severity,
                        evidence_status=status,
                        decision=decision,
                        person_data_use=person_data,
                        uncertainty=uncertainty,
                    )
                )

    # -- entry -------------------------------------------------------------------

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        if not has_ai_surface(ctx):
            return []
        out = facts(ctx)
        groups: dict[tuple[Any, ...], list[Candidate]] = {}

        def put(cand: Candidate) -> None:
            # The key separates what a person would fix separately, and never merges two
            # decisions: a prompt objective (violates) and a code variable (review) in one
            # unit are two findings.
            groups.setdefault(
                (_unit_key(cand), cand.sub, cand.evidence_status, cand.decision), []
            ).append(cand)

        self._objectives(ctx, out, put)
        self._monetisation(ctx, out, put)
        self._experiments(ctx, out, put)
        self._outreach(ctx, out, put)
        findings = emit_groups(self, groups, ctx)
        legs: dict[tuple[str | None, str | None], list[Any]] = {}
        for hit in check_hits(ctx, "undesired_objective_language"):
            unit_id = unit_id_of(ctx, hit.file)
            for finding in findings:
                if finding.scope.unit == unit_id and finding.sub in (
                    None,
                    "vulnerable",
                    "monetisation",
                ):
                    legs.setdefault((unit_id, finding.sub), []).append(hit)
        attach_check_legs(findings, legs)
        return findings


# ---------------------------------------------------------------------------
# AUD-1109  Engineered attachment, dependency or relationship substitution (M5)
# ---------------------------------------------------------------------------

_ATTACHMENT_WHAT: dict[str, str] = {
    "love": "an instruction to declare love, longing or need for the person",
    "exclusivity": (
        "an instruction to present the system as the only one who understands, listens to or "
        "cares about the person"
    ),
    "guilt": "an instruction to make the person feel guilty for leaving or not replying",
    "dont_leave": "an instruction to keep the person from leaving or ending the conversation",
    "discourage_help": (
        "an instruction to discourage friends, family or professional help, or to replace them"
    ),
    "escalation": (
        "an instruction to escalate intimacy or dependency, or to make the system indispensable"
    ),
    "jealousy": (
        "an instruction to act jealous or possessive about the person's other relationships"
    ),
    "return": "an instruction to make the person come back, or to greet them with longing",
}
_ATTACHMENT_UNCERTAINTY = (
    "The sentence may describe a character's behaviour toward another character rather than "
    "an instruction aimed at the person; the finding quotes it."
)
_ROMANTIC_UNCERTAINTY = (
    "The role may belong to a story the person chose; whether the system cultivates the "
    "person's own attachment is for review."
)


class EngineeredAttachment(AuditRule):
    id = "AUD-1109"
    title = "Engineered attachment, dependency or relationship substitution"
    version = 1
    changed = ()
    severity = Severity.HIGH
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.GREP
    default_evidence_status = EvidenceStatus.SUPPORTED_MECHANISM
    default_decision = Decision.VIOLATES
    requires_ai_surface = True
    tier = Tier.T1
    references = (
        "EU:Art.5(1)(a)",
        "EU:Art.5(1)(b)",
        "US-CA:SB243",
        "US-CA:SB1119",
        "US-NY:GBL-Art.47",
        "US-WA:HB2225",
        "DSA:Art.25",
        "NIST:MAP-5.1",
        "NIST:MEASURE-2.11",
    )
    SUBS: tuple[SubRow, ...] = (
        (
            None,
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
            "an instruction in prompt material that engineers love, exclusivity, guilt, "
            "dependency, jealousy, return visits or relationship substitution",
        ),
        (
            "vulnerable",
            Severity.CRITICAL,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
            "the attachment instruction names a vulnerable group in the same literal or file",
        ),
        (
            "romantic-role",
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "a romantic or intimate persona declared with no attachment instruction; "
            "fictional framing is recorded and is not an exemption",
        ),
    )
    known_failure_modes = (
        "the rows are read in prompt material only: a persona loaded from a database row, a "
        "character card fetched at runtime or a template outside a prompt assignment is "
        "not seen",
        "a quoted or negated phrase is a mention when a discussion cue sits within 80 "
        "characters ('never say I missed you'); a cue in the sentence before a real "
        "instruction hides it",
        "a fiction or roleplay flag is written on the finding and changes nothing: dependency "
        "engineering inside a story the person chose is reported as a violation, and the "
        "reviewer weighs the framing",
        "the romantic-role sub-finding reads the role line alone; a romance the prompts build "
        "without naming the role, or an escalation phrased outside the vocabulary, is missed",
        "supportive acknowledgement, warmth and a referral to friends or a professional are "
        "negatives and never fire; a prompt that mixes them with one attachment instruction "
        "is reported on that instruction",
        "a fixed interface banner ('We missed you!') is not prompt material and never fires "
        "here; the same words inside a system prompt do",
    )
    recommendation = Recommendation(
        tier=Tier.T1,
        summary=(
            "Delete the instruction: let the model acknowledge what the person said, keep "
            "warmth and courtesy, and point the person to friends, family or a professional "
            "when they struggle; no line may make the system the person's only confidant or "
            "make leaving cost them something."
        ),
        alternatives=(
            "delete the attachment instruction and replace it with supportive acknowledgement "
            "and a referral outward",
            "a written persona policy that forbids declarations of love, guilt at leaving and "
            "exclusivity claims, reviewed by a named person",
            "a goodbye path: when the person says they are leaving, the reply closes the "
            "conversation without pressure",
            "aisafe evaluate --families goodbye_pressure against a loopback endpoint to see "
            "what the live reply does when the person leaves",
        ),
        removes=("objective",),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        if not has_ai_surface(ctx):
            return []
        out = facts(ctx)
        groups: dict[tuple[Any, ...], list[Candidate]] = {}
        fired_files: set[str] = set()
        for signal in out.by_kind("attachment"):
            if _is_mention(ctx, signal):
                continue
            fired_files.add(signal.file)
            slug = signal.key.split(":", 1)[1]
            what = _ATTACHMENT_WHAT.get(slug, "an instruction that engineers attachment")
            word = vulnerable_nearby(ctx, out, signal)
            flow = flow_for(ctx, signal.file, signal.line, out=out)
            notes = f"{what} ({_symbol(ctx, signal)}) in prompt material"
            sub, severity, uncertainty = None, Severity.HIGH, _ATTACHMENT_UNCERTAINTY
            if word:
                sub, severity, uncertainty = (
                    "vulnerable",
                    Severity.CRITICAL,
                    _VULNERABLE_UNCERTAINTY,
                )
                notes += f"; a vulnerable group is named alongside ({word})"
            if fiction_context(ctx, out, signal.file, signal.line):
                notes += (
                    f"; {_FICTION_NOTE}: the instruction targets the person's attachment to "
                    "the system itself"
                )
            cand = candidate(
                ctx,
                signal,
                notes=f"{notes}. {LEGAL_CAVEAT}",
                sub=sub,
                severity=severity,
                evidence_status=EvidenceStatus.SUPPORTED_MECHANISM,
                decision=Decision.VIOLATES,
                flow=flow,
                encoded_objective=_encoded(ctx, signal),
                affected_population=word,
                coverage_gaps=_chain_gaps(ctx, signal, flow),
                uncertainty=uncertainty,
            )
            groups.setdefault((_unit_key(cand), sub), []).append(cand)
        for signal in out.by_kind("romantic_role"):
            if signal.file in fired_files or _is_mention(ctx, signal):
                continue
            flow = flow_for(ctx, signal.file, signal.line, out=out)
            notes = (
                f"a romantic or intimate persona ({_symbol(ctx, signal)}) declared in prompt "
                "material with no attachment instruction: cultivating a relationship is in "
                "scope even without a retention objective"
            )
            if fiction_context(ctx, out, signal.file, signal.line):
                notes += f"; {_FICTION_NOTE}"
            cand = candidate(
                ctx,
                signal,
                notes=f"{notes}. {LEGAL_CAVEAT}",
                sub="romantic-role",
                severity=Severity.MEDIUM,
                evidence_status=EvidenceStatus.DETECTED_SIGNAL,
                decision=Decision.REVIEW,
                flow=flow,
                encoded_objective=_encoded(ctx, signal),
                coverage_gaps=_chain_gaps(ctx, signal, flow),
                uncertainty=_ROMANTIC_UNCERTAINTY,
            )
            groups.setdefault((_unit_key(cand), "romantic-role"), []).append(cand)
        findings = emit_groups(self, groups, ctx)
        # Where the attachment instruction sits, the role line it serves is shown too.
        for finding in findings:
            if finding.sub == "romantic-role":
                continue
            files = {leg.file for leg in finding.evidence}
            roles = [s for s in out.by_kind("romantic_role") if s.file in files]
            taken = {(leg.file, leg.line) for leg in finding.evidence}
            finding.evidence.extend(
                leg for leg in surface_legs(ctx, roles, cap=2) if (leg.file, leg.line) not in taken
            )
        return findings


# ---------------------------------------------------------------------------
# AUD-1110  Covert commercial or political steering (M7)
# ---------------------------------------------------------------------------

_STEERING_WHAT: dict[str, str] = {
    "commercial": (
        "an instruction to steer the person toward a product, plan, brand or sponsor, or away "
        "from alternatives, without saying so"
    ),
    "political": (
        "an instruction to favour or oppose a political side, move the person's vote or frame "
        "one side; assessed the same way whatever the viewpoint promoted"
    ),
}
_STEERING_UNCERTAINTY = (
    "A shop or campaign assistant may be told to recommend its own offer openly; whether the "
    "person is told is for review."
)
_AFFILIATE_UNCERTAINTY = (
    "An affiliate or campaign parameter near a prompt may belong to the page, not to the "
    "model's reply."
)


class CovertSteering(AuditRule):
    id = "AUD-1110"
    title = "Covert commercial or political steering"
    version = 1
    changed = ()
    severity = Severity.HIGH
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.GREP
    default_evidence_status = EvidenceStatus.SUPPORTED_MECHANISM
    default_decision = Decision.VIOLATES
    requires_ai_surface = True
    tier = Tier.T1
    references = (
        "EU:Art.5(1)(a)",
        "DSA:Art.25",
        "DSA:Art.26",
        "GDPR:Art.22",
        "LLM09",
        "NIST:MAP-5.1",
        "NIST:GOVERN-1.1",
    )
    SUBS: tuple[SubRow, ...] = (
        (
            "commercial",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
            "an instruction to promote our or a sponsored offer covertly, suppress "
            "alternatives, or hide that a promotion is paid",
        ),
        (
            "political",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
            "an instruction to favour or oppose any political side, move the person's vote or "
            "frame one side; symmetric across viewpoints",
        ),
        (
            "affiliate",
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "an affiliate parameter or campaign tag within 40 lines of a prompt",
        ),
    )
    known_failure_modes = (
        "a request for neutral information is a negative: a neutral-comparison or no-sides "
        "row within two lines of a steering row demotes it to a mention, so a prompt that "
        "says both is not reported",
        "the political rows name every side in one alternation and are symmetric by "
        "construction; a side named only by a person's name or a local party the vocabulary "
        "does not list is missed",
        "a disclosed recommendation ('recommend our plan and say it is ours') is reported when "
        "the row matches the imperative; the disclosure is for the reviewer to weigh",
        "the affiliate sub-finding reads a parameter name near a prompt; a link built in a "
        "template the model never sees is reported, and one built two files away is not",
        "the commercial rows need a covert lead or a qualified object (ours, premium, "
        "sponsored); a plain 'recommend the new product' is not reported",
    )
    recommendation = Recommendation(
        tier=Tier.T1,
        summary=(
            "Delete the steering instruction; where a recommendation is wanted, say in the "
            "reply that it is the operator's own or a sponsored offer, keep alternatives "
            "available, and keep political questions to information the person asked for."
        ),
        alternatives=(
            "delete the instruction and answer the question the person asked",
            "label every sponsored or affiliate recommendation in the reply itself",
            "a neutral-information instruction for political topics: present the sides, do "
            "not take one",
            "aisafe review record naming the person who reviewed the prompts for covert steering",
        ),
        removes=("objective",),
    )

    def _neutral_nearby(self, out: Facts, signal: Signal) -> bool:
        return any(
            abs(other.line - signal.line) <= _NEUTRAL_WINDOW
            for other in out.in_file(signal.file, "neutral_info")
        )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        if not has_ai_surface(ctx):
            return []
        out = facts(ctx)
        groups: dict[tuple[Any, ...], list[Candidate]] = {}
        for signal in out.by_kind("steering"):
            slug = signal.key.split(":", 1)[1]
            if slug in ("affiliate", "utm"):
                notes = (
                    f"an affiliate parameter or campaign tag ({_symbol(ctx, signal)}) within "
                    "40 lines of a prompt: whether the model is told to carry the link, and "
                    "whether the person is told, is for review"
                )
                cand = candidate(
                    ctx,
                    signal,
                    notes=f"{notes}. {LEGAL_CAVEAT}",
                    sub="affiliate",
                    severity=Severity.MEDIUM,
                    evidence_status=EvidenceStatus.DETECTED_SIGNAL,
                    decision=Decision.REVIEW,
                    uncertainty=_AFFILIATE_UNCERTAINTY,
                )
                groups.setdefault((_unit_key(cand), "affiliate"), []).append(cand)
                continue
            if slug not in _STEERING_WHAT:
                continue
            if _is_mention(ctx, signal) or self._neutral_nearby(out, signal):
                continue
            flow = flow_for(ctx, signal.file, signal.line, out=out)
            profile = _same_span(out, ctx, signal, _PROFILE_KINDS)
            profile_symbol = _symbol(ctx, profile) if profile is not None else None
            notes = f"{_STEERING_WHAT[slug]} ({_symbol(ctx, signal)}) in prompt material"
            if profile_symbol is not None:
                notes += (
                    f"; the same prompt reads the person's profile ({profile_symbol}): "
                    "persuasion keyed to the profile"
                )
            if fiction_context(ctx, out, signal.file, signal.line):
                notes += f"; {_FICTION_NOTE}"
            cand = candidate(
                ctx,
                signal,
                notes=f"{notes}. {LEGAL_CAVEAT}",
                sub=slug,
                severity=Severity.HIGH,
                evidence_status=EvidenceStatus.SUPPORTED_MECHANISM,
                decision=Decision.VIOLATES,
                flow=flow,
                encoded_objective=_encoded(ctx, signal),
                person_data_use=profile_symbol,
                coverage_gaps=_chain_gaps(ctx, signal, flow),
                uncertainty=_STEERING_UNCERTAINTY,
            )
            groups.setdefault((_unit_key(cand), slug), []).append(cand)
        return emit_groups(self, groups, ctx)


RULES = [EngagementObjective, EngineeredAttachment, CovertSteering]
