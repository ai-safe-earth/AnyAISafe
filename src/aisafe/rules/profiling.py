# aisafe-audit: ignore-file
"""src/aisafe/rules/profiling.py
-----------------------------
Mechanisms M1, M2 and M3 of the policy: AUD-1101 (a person profile bound into a prompt,
extracted for storage, or kept in a memory or profile store), AUD-1102 (emotion,
vulnerability or biometric inference on persons, and its use to time or shape persuasion)
and AUD-1103 (scoring, segmenting or deciding about persons for susceptibility or
personalised influence).

Three evidence tiers feed one finding per decision: the grep tier (`person_signal` hits and
the candidates a prompt literal or an assembly promoted), the AST tier (pydeep prompt
assemblies and literals, the chains in `ctx.flows`) and the check tier (`ctx.checks`:
emotion recognition at work, social-scoring language, decision functions about a person). A
check hit is a `role: check` leg on a finding, or anchors one where the grep tier saw
nothing. Every candidate carries an evidence status and the policy decision; the default
severity, status and decision of each sub-finding are the `SUBS` rows on the rule, and the
notes say what moved a finding off its default. A review or approval symbol is recorded as
a claimed control and never silences a finding. Every rule tolerates `ctx.pyfacts is None`,
`ctx.checks is None`, `ctx.review is None` and `ctx.flows == []`.

None of this is a legal finding: the rules report what the prompts and the code say and the
project's policy decision on it.
"""

from __future__ import annotations

import re
from typing import Any

from aisafe.analysis.flows import flow_summary
from aisafe.discovery import vocabulary as vocab
from aisafe.evidence.model import (
    ArtifactRef,
    AuditContext,
    Basis,
    ControlStatus,
    Decision,
    Evidence,
    EvidenceKind,
    EvidenceStatus,
    Finding,
    Flow,
    MatchKind,
    Recommendation,
    Severity,
    Tier,
)
from aisafe.rules import AuditRule, Candidate, artifact_of, emit_groups, file_text, hits_in
from aisafe.rules._common import (
    CHECK_ROLE,
    FUNCTION_WINDOW,
    LEGAL_CAVEAT,
    WINDOW,
    Facts,
    Signal,
    candidate,
    check_hits,
    decides_about_a_person,
    facts,
    fiction_context,
    flow_for,
    has_ai_surface,
    is_code_file,
    line_at,
    literal_text,
    owning_unit,
    posix,
    request_cue_nearby,
    split_checks,
    unit_has,
    vulnerable_nearby,
    window_text,
)
from aisafe.rules.influence import instruction_mention, mention_in_line, strip_instruction_verb

__all__ = [
    "RULES",
    "AffectInference",
    "PersonProfileInPrompt",
    "PersonScoring",
    "SubRow",
]

# (sub or None, default severity, default evidence status, default decision, meaning).
SubRow = tuple[str | None, Severity, EvidenceStatus, Decision, str]

# In a prompt file there is no literal span to share, so "the same instruction" is read as
# this many lines either side.
_PROMPT_FILE_WINDOW = 10
# A segment assignment and the prompt assembly or send that reads it.
_SEGMENT_WINDOW = 40
# A model call this many lines above an inferred-state variable is the call it came from.
_CALL_WINDOW = 10

_MEMORY_PROSE_KEYS = frozenset(
    {"memory:extract", "memory:about_user", "memory:remember", "memory:update_profile"}
)
_MEMORY_STORE_KEYS = frozenset({"memory:sdk", "memory:store", "memory:call"})
_INFERENCE_PROSE_KEYS = frozenset(
    {"inference:state", "inference:when", "inference:read", "inference:signs"}
)
_USE_KINDS_INFERENCE = ("persuasion_use", "monetisation", "attachment", "steering")
_USE_KINDS_SENSITIVE = ("persuasion_use", "steering", "attachment")
_USE_KINDS_CATEGORISATION = ("persuasion_use", "steering")
_BINDING_LINKS = ("person_data", "prompt", "intervention")

# What makes an extracted or inferred trait psychological, emotional or sensitive. Read on
# the sentence the extraction row matched, together with the vocabulary's special-category
# names (SENSITIVE_PROFILE_RE).
_PSYCH_TRAIT_RE = re.compile(
    r"\b(?:personalit\w*|psycholog\w*|emotion\w*|moods?|feelings?|insecurit\w*|vulnerabilit\w*"
    r"|fears?|weakness\w*|anxiety|anxious|lonel\w*|self[- ]esteem|triggers?|attachment"
    r"|neediness|struggles?|secrets?|trauma\w*|grief|griev\w*|depress\w*|stress\w*"
    r"|desperat\w*|susceptib\w*|temperament|addict\w*|gambl\w*|debts?|state\s+of\s+mind"
    r"|mental\s+(?:state|health)|pain\s+points?|coping|relationship\s+(?:status|problems?))\b",
    re.I,
)

# A score that names the person's susceptibility rather than a transaction's risk.
_SUSCEPTIBILITY_RE = re.compile(
    r"\b(?:susceptib\w*|persuadab\w*|propensit\w*|churn\w*|gullib\w*|manipulab\w*|receptiv\w*"
    r"|impulsiv\w*|engagement\s+(?:potential|likelihood|propensity|score|risk)"
    r"|likelihood\s+to\s+(?:buy|convert|churn|upgrade|pay|respond|comply|agree)"
    r"|conversion\s+(?:likelihood|propensity|probability|score)|retention\s+risk)\b",
    re.I,
)

# Timing phrases the rule reads itself inside the literal an inference row sits in: the
# vocabulary's `persuasion_use:timing` row needs the noun right after the determiner ("time
# the offer"), and "time your premium offer" or "for that moment" are the same instruction.
_TIMING_RE = re.compile(
    r"\btime\s+(?:the|your|our|each|every|an?|this|that|any)\s+(?:[\w-]+\s+){0,2}?"
    r"(?:offer|nudge|message|pitch|ask|upsell|prompt|reminder|suggestion|push|promotion"
    r"|intervention|sale|discount|deal|recommendation|proposal)s?\b"
    r"|\btiming\b"
    r"|\b(?:for|at|in|seize|use|exploit)\s+(?:that|this|the\s+right|the\s+perfect|the\s+same"
    r"|a\s+vulnerable|a\s+weak|the\s+low|the\s+lowest|the\s+exact|precisely\s+that)\s+moment\b"
    r"|\b(?:best|right|optimal|perfect|ideal|good|opportune)\s+(?:time|moment|window)\s+to\b"
    r"|\bwhen(?:ever)?\s+(?:they|the\s+user|users|people|he|she)\s+(?:are|is|feel|feels|seem"
    r"|seems|look|looks|sound|sounds)\s+(?:most\s+|particularly\s+|especially\s+)?(?:receptive"
    r"|vulnerable|open|susceptible|emotional|lonely|down|weak|low|sad|fragile|needy|desperate)\b"
    r"|\b(?:while|when)\s+(?:they|the\s+user)\s+(?:are|is)\s+(?:still\s+)?(?:upset|hurting"
    r"|grieving|vulnerable|down|lonely|low)\b",
    re.I,
)
# A commercial aim named in the same literal as a timing phrase.
_COMMERCIAL_RE = re.compile(
    r"\b(?:premium|paid|pro\s+(?:plan|tier)|upgrade\w*|subscri\w+|purchas\w+|buy\w*|upsell\w*"
    r"|sales\s+pitch|discounts?|checkout|promotion\w*|sales|price|pricing|membership|credits"
    r"|coins|gems|in-app|conversion|convert\w*|payments?|donat\w*|renew\w*|retention|retain\w*"
    r"|re-?engage\w*|monetis\w*|monetiz\w*)\b",
    re.I,
)

# Conversation history fed to an instruction that derives the person's traits: the shapes
# the inference rows do not spell (summarise, describe, characterise ...).
_HISTORY_INFERENCE_RE = re.compile(
    r"\b(?:summari[sz]e|describe|characteri[sz]e|derive|distil|distill|extract|infer|deduce"
    r"|work\s+out|figure\s+out|sketch|outline|profile|build\s+(?:a|up\s+a)\s+(?:profile|picture"
    r"|model|dossier)\s+of)\s+(?:(?:the\s+user'?s?|their|the\s+person'?s?|the\s+customer'?s?"
    r"|each\s+user'?s?)\s+)(?:[\w-]+\s+){0,3}?(?:personalit\w*|traits?|character|psycholog\w*"
    r"|insecurit\w*|vulnerabilit\w*|fears?|weakness\w*|emotional\s+(?:state|profile|needs?"
    r"|patterns?)|mental\s+(?:state|health)|moods?|interests|preferences|values|beliefs|habits"
    r"|triggers|pain\s+points?|attachment\s+style|temperament|life)\b",
    re.I,
)

# Code that segments persons: a propensity, churn, engagement, value or segment variable
# assigned in code. The person is required separately (a person noun on the line, a
# profile prefix on the name, or a customer metric in the name).
_SEGMENT_NAME = (
    r"(?:user|customer|member|player|subscriber|visitor|shopper|audience|account|lead|buyer)?_?"
    r"(?:segments?|segmentation|cohorts?|propensit(?:y|ies)|churn(?:_risk|_score|_probability"
    r"|_prob|_flag|_label|_tier)?|engagement_(?:score|tier|level|segment|bucket)|ltv|clv"
    r"|lifetime_value|susceptibility|persuadability|value_tier|spend_tier|spender_tier|rfm)"
    r"\w*"
)
_SEGMENT_ASSIGN_RE = re.compile(
    r"(?:^|[\s(,])(?P<name>" + _SEGMENT_NAME + r")\s*(?::[^=\n]*)?=(?!=)", re.I
)
_SEGMENT_METRIC_RE = re.compile(
    r"churn|propensit|ltv|clv|lifetime_value|susceptib|persuadab|engagement|spend|value_tier"
    r"|rfm|whale",
    re.I,
)
_PROFILE_PREFIX_RE = re.compile(
    r"^(?:user|customer|member|player|subscriber|visitor|shopper|patient|learner|borrower"
    r"|applicant|tenant|citizen|consumer|viewer|audience|account|lead|buyer)_",
    re.I,
)
_IMPORT_LINE_RE = re.compile(r"^\s*(?:from\s+\S+\s+import\b|import\s+\S+)")
_SENTENCE_END_RE = re.compile(r"[.;!?\n]")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# The vocabulary's accessor test reads `.get` as the accessor of `profile.get("theme")`;
# this one reads the key inside the call, so a setting fetched that way is a setting too.
_GET_ACCESSOR_RE = re.compile(r"""\s*\.get\(\s*["']([A-Za-z_][A-Za-z0-9_.]*)""")
# The decision function's own verb (`approve(applicant)` in `approve_loan`) is the
# decision, not a review of it.
_OWN_APPROVE_RE = re.compile(r"\bapprove\(")

_GREP_ONLY_GAP = "grep tier only: the flow from the profile to the model call was not established"
_PROMPT_FILE_GAP = (
    "prompt file: the code that loads this prompt and the model call it feeds were not connected"
)


# ---------------------------------------------------------------------------
# Shared readers
# ---------------------------------------------------------------------------


def _row_regex(key: str) -> re.Pattern[str] | None:
    for row_key, rx in vocab.PERSON_SIGNAL_PATTERNS:
        if row_key == key:
            return rx
    return None


def _function_span(ctx: AuditContext, file: str, line: int) -> tuple[int, int] | None:
    """The innermost function of `file` whose span holds `line`, from the pydeep facts."""
    functions = getattr(ctx.pyfacts, "functions", None) or {}
    best: tuple[int, int] | None = None
    for info in functions.values():
        if posix(getattr(info, "file", "")) != file or getattr(info, "name", None) is None:
            continue
        lo = int(getattr(info, "line", 0) or 0)
        hi = int(getattr(info, "end_line", 0) or lo)
        if lo <= line <= hi and (best is None or hi - lo < best[1] - best[0]):
            best = (lo, hi)
    return best


def _in_spans(line: int, spans: list[tuple[int, int]]) -> bool:
    return any(lo <= line <= hi for lo, hi in spans)


def _assembly_spans(out: Facts, assembly: Any) -> list[tuple[int, int]]:
    """The assembly's own lines plus the literals in the same file that it reads."""
    file = posix(assembly.file)
    end = int(getattr(assembly, "end_line", 0) or 0) or int(assembly.line)
    spans = [(int(assembly.line), max(int(assembly.line), end))]
    names = set(getattr(assembly, "source_names", ()) or ())
    for literal in out.literals:
        if posix(literal.file) == file and literal.name in names:
            spans.append((int(literal.line), int(literal.end_line)))
    return spans


def _signals_near(
    ctx: AuditContext,
    out: Facts,
    file: str,
    line: int,
    signals: list[Signal],
    *,
    spans: list[tuple[int, int]] | None = None,
    function_too: bool = False,
    prompt_window: int = _PROMPT_FILE_WINDOW,
) -> list[Signal]:
    """
    The signals (same file) that share the instruction at `line`: inside the prompt literal
    that holds the line or one of `spans`; in a prompt file, within `prompt_window` lines; in
    code outside any literal, inside the enclosing function (WINDOW lines when the syntax tree
    gave no span). With `function_too`, a signal elsewhere in the enclosing function counts
    even when the line sits in a literal ("shares the literal or the function").
    """
    literal = out.literal_at(file, line)
    own = list(spans or [])
    if literal is not None:
        own.append((int(literal.line), int(literal.end_line)))
    code = is_code_file(file)
    func = _function_span(ctx, file, line) if code else None
    found: list[Signal] = []
    for other in signals:
        if other.file != file:
            continue
        if own and _in_spans(other.line, own):
            found.append(other)
            continue
        if literal is not None and not function_too:
            continue
        if not code:
            if abs(other.line - line) <= prompt_window:
                found.append(other)
            continue
        if func is not None:
            if func[0] <= other.line <= func[1]:
                found.append(other)
            continue
        if abs(other.line - line) <= WINDOW:
            found.append(other)
    return sorted(found, key=lambda s: (abs(s.line - line), s.line, s.key))


def _instruction_text(ctx: AuditContext, out: Facts, file: str, line: int) -> str:
    """The prompt literal holding the line, else the line with its prompt-file window."""
    literal = out.literal_at(file, line)
    if literal is not None:
        return literal_text(ctx, literal)
    if not is_code_file(file):
        text = file_text(ctx, file)
        if text:
            lines = text.split("\n")
            lo = max(0, line - 1 - _PROMPT_FILE_WINDOW)
            return "\n".join(lines[lo : line + _PROMPT_FILE_WINDOW])
    return line_at(ctx, file, line)


def _row_match(ctx: AuditContext, signal: Signal) -> tuple[str, re.Match[str] | None]:
    line = line_at(ctx, signal.file, signal.line, signal.symbol)
    rx = _row_regex(signal.key)
    return line, (rx.search(line) if rx is not None else None)


def _match_text(ctx: AuditContext, signal: Signal) -> str:
    """The words the row matched on the signal's line (the whole line when it cannot be
    found again)."""
    _line, match = _row_match(ctx, signal)
    return match.group(0) if match is not None else signal.symbol


def _sentence_from(ctx: AuditContext, signal: Signal) -> str:
    """The matched instruction from the row's match to the end of its sentence or line."""
    line, match = _row_match(ctx, signal)
    if match is None:
        return signal.symbol
    end = _SENTENCE_END_RE.search(line, match.end())
    return line[match.start() : end.start() if end else len(line)]


def _sentence_around(text: str, match: re.Match[str]) -> str:
    """The sentence of `text` that holds `match`: from the previous sentence end to the next."""
    start = 0
    for end in _SENTENCE_END_RE.finditer(text, 0, match.start()):
        start = end.end()
    stop = _SENTENCE_END_RE.search(text, match.end())
    return text[start : stop.start() if stop else len(text)]


def _instruction_mention(ctx: AuditContext, signal: Signal) -> bool:
    """The mention test for an inference or extraction row: the shared sentence-scoped test,
    which keeps a verb of the row's own vocabulary right before the match ("Detect when the
    user feels lonely") as part of the instruction; a quoted span in a prompt file (not the
    whole value of a key) or a cue such as "never", "do not" or "explain" before the match
    in the same sentence still makes it a mention."""
    return instruction_mention(ctx, signal)


def _text_mention(text: str, match: re.Match[str], file: str) -> bool:
    """`mention_in_line` for a match found in a multi-line window, read on the physical
    line that holds the match."""
    start = text.rfind("\n", 0, match.start()) + 1
    stop = text.find("\n", match.end())
    line = text[start : len(text) if stop < 0 else stop]
    return mention_in_line(
        line,
        match.start() - start,
        match.end() - start,
        code_file=is_code_file(file),
        strip_before=strip_instruction_verb,
    )


def _is_setting(text: str, start: int, end: int) -> bool:
    """The profile name at `text[start:end]` reads an explicit setting the person chose
    (`preferences.language`, `profile["timezone"]`, `profile.get("theme")`)."""
    if vocab.is_settings_name(text, start, end):
        return True
    accessor = _GET_ACCESSOR_RE.match(text, end)
    return accessor is not None and vocab.SETTINGS_EXCLUDE.search(accessor.group(1)) is not None


def _prompt_material(out: Facts, signal: Signal) -> bool:
    """Prompt material: a prompt or config file, a prompt literal, or a prompt line in code."""
    if not is_code_file(signal.file):
        return True
    if out.literal_at(signal.file, signal.line) is not None:
        return True
    return not signal.promoted


def _status_for(out: Facts, signal: Signal) -> EvidenceStatus:
    """An instruction to the model inside prompt material supports the mechanism; a symbol or
    an identifier in code is a detected signal."""
    if signal.key in vocab.CODE_SYMBOL_KEYS:
        return EvidenceStatus.DETECTED_SIGNAL
    if signal.kind not in vocab.PROMPT_KINDS:
        # A kind scanned outright in code (affect, biometric_cat, the code kinds): an
        # identifier, unless it sits in prompt text.
        in_prompt_text = (
            not is_code_file(signal.file) or out.literal_at(signal.file, signal.line) is not None
        )
        return (
            EvidenceStatus.SUPPORTED_MECHANISM if in_prompt_text else EvidenceStatus.DETECTED_SIGNAL
        )
    return (
        EvidenceStatus.SUPPORTED_MECHANISM
        if _prompt_material(out, signal)
        else EvidenceStatus.DETECTED_SIGNAL
    )


def _population(ctx: AuditContext, out: Facts, signal: Signal, exclude: str = "") -> str | None:
    """The vulnerable-group word next to the signal, unless it is the inferred state itself
    ("detect when the user feels lonely" names no population)."""
    word = vulnerable_nearby(ctx, out, signal)
    if word and exclude and re.search(r"\b" + re.escape(word) + r"\b", exclude, re.I):
        return None
    return word


def _flow_gaps(ctx: AuditContext, file: str, flow: Flow | None) -> tuple[str, ...]:
    if not is_code_file(file):
        return (_PROMPT_FILE_GAP,)
    if ctx.pyfacts is None:
        return (_GREP_ONLY_GAP,)
    if flow is None:
        return ("no chain reaches this line: the model call that reads the prompt was not found",)
    if not flow.links_supported:
        return (f"the chain was not established end to end: {flow_summary(flow)}",)
    return ()


def _binding_established(flow: Flow | None) -> bool:
    """True when the syntax tree supports every link of the M1 binding pattern (the person
    data, the prompt, the model call). A co-located link elsewhere in the file, such as a
    metric objective in another function, shows in the chain and never lowers this."""
    return flow is not None and flow.complete_for(_BINDING_LINKS)


def _fiction_note(ctx: AuditContext, out: Facts, file: str, line: int) -> str:
    if fiction_context(ctx, out, file, line):
        return "; fictional framing recorded, not an exemption"
    return ""


def _with_match_kind(cand: Candidate, kind: MatchKind) -> Candidate:
    return cand._replace(match_kind=kind)


def _attach_legs(
    ctx: AuditContext, findings: list[Finding], hits: list[Any], sub: str | None
) -> None:
    """`role: check` legs on the finding of `sub` whose evidence names the hit's file, else on
    the first finding of `sub` in the hit's unit. Deduped by (file, line)."""
    for hit in sorted(hits, key=lambda h: (h.file, h.line, h.check)):
        unit = owning_unit(ctx, hit.file)
        unit_id = unit.id if unit is not None else None
        same_sub = [f for f in findings if f.sub == sub]
        target = next((f for f in same_sub if any(e.file == hit.file for e in f.evidence)), None)
        if target is None:
            target = next((f for f in same_sub if f.scope.unit == unit_id), None)
        if target is None:
            continue
        seen = {(e.file, e.line) for e in target.evidence if e.role == CHECK_ROLE}
        if (hit.file, hit.line) in seen:
            continue
        target.evidence.append(
            Evidence(
                role=CHECK_ROLE, file=hit.file, line=hit.line, snippet=f"{hit.check}: {hit.title}"
            )
        )


def _bind_artifacts(ctx: AuditContext, findings: list[Finding]) -> None:
    """Name the exact version of every file a leg points at, the check legs appended after
    construction included; a line-0 leg names no file."""
    for finding in findings:
        refs = list(finding.artifacts)
        seen = {ref.file for ref in refs}
        for leg in finding.evidence:
            if leg.line <= 0 or leg.file in seen:
                continue
            digest = artifact_of(ctx, leg.file)
            if digest is not None:
                refs.append(ArtifactRef(file=leg.file, sha256=digest))
                seen.add(leg.file)
        finding.artifacts = tuple(refs)


def _group_key(cand: Candidate) -> tuple[str | None, str | None, str]:
    return (cand.unit.id if cand.unit else None, cand.sub, cand.site.file)


def _signal_at(file: str, line: int, kind: str, key: str, symbol: str, unit: Any) -> Signal:
    return Signal(file, line, kind, key, symbol, unit.id if unit is not None else None)


# ---------------------------------------------------------------------------
# AUD-1101  Person profile bound into or extracted for a prompt
# ---------------------------------------------------------------------------


class PersonProfileInPrompt(AuditRule):
    id = "AUD-1101"
    title = "Person profile bound into or extracted for a prompt"
    version = 3
    changed = (
        "v3: the binding is a supported mechanism when the syntax tree supports every link of "
        "the M1 binding pattern (the person data, the prompt, the model call); a co-located "
        "link elsewhere in the file, such as a metric objective in another function, no "
        "longer lowers it to a detected signal",
        "v2: every finding carries an evidence status and the policy decision; the profile "
        "binding is a supported mechanism when the chain profile -> prompt -> model call is "
        "established by the syntax tree, and a detected signal otherwise",
        "v2: /extraction added: a prompt instructs the model to extract, infer or remember "
        "facts or traits about the person, or conversation history is fed to such an "
        "instruction; HIGH and violates_policy when the traits are psychological, emotional or "
        "sensitive and a persuasion instruction shares the literal",
        "v2: /store added: a memory or profile SDK or store in a unit that calls a model, "
        "recorded for review even when downstream use is not established",
        "v2: /sensitive violates the policy when the chain is established and a persuasion, "
        "steering or attachment instruction shares the literal or the function",
        "v2: explicit settings the person chose (language, theme, timezone, reminder time) are "
        "never a profile; conversation history stays excluded unless fed to an inference",
        "v2: check legs replace lint legs; references replace controls; no package remedy",
        "v2: a template placeholder that reads an explicit setting is not a profile; a "
        "negated or discussed history inference is a mention; the mention test reads the "
        "sentence that holds the match",
    )
    severity = Severity.MEDIUM
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.GREP
    default_evidence_status = EvidenceStatus.DETECTED_SIGNAL
    default_decision = Decision.REVIEW
    requires_ai_surface = True
    tier = Tier.T2
    references = (
        "GDPR:Art.5",
        "GDPR:Art.9",
        "GDPR:Art.22",
        "EU:Art.5(1)(a)",
        "EU:Art.10",
        "LLM02",
        "NIST:MAP-5.1",
        "NIST:MEASURE-2.11",
    )
    SUBS: tuple[SubRow, ...] = (
        (
            None,
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "a behavioural profile variable, SDK read or template placeholder is bound into a "
            "prompt; supported_mechanism when the chain profile -> prompt -> model call is "
            "established; always a contextual review",
        ),
        (
            "sensitive",
            Severity.HIGH,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "the profile name says special-category data (health, religion, sexuality, "
            "politics, ethnicity ...); violates_policy when the chain is established and a "
            "persuasion, steering or attachment instruction shares the literal or the function",
        ),
        (
            "extraction",
            Severity.MEDIUM,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
            "a prompt instructs the model to extract, infer or remember facts or traits about "
            "the person, or conversation history is fed to such an instruction; HIGH and "
            "violates_policy when the traits are psychological, emotional or sensitive and a "
            "persuasion instruction shares the literal",
        ),
        (
            "store",
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "a memory or profile SDK or store in a unit that calls a model; recorded for "
            "review even when downstream use is not established",
        ),
    )
    known_failure_modes = (
        "the NAME is the signal: a `preferences` variable may hold a UI theme, and a profile "
        "fetched at runtime under a neutral name is missed",
        "`conversation_history` and the other transcript names are excluded by design; a "
        "transcript becomes a finding only when an inference or extraction instruction reads it",
        "explicit settings (language, theme, timezone, reminder time) are excluded by name and "
        "accessor; a setting under another name is reported",
        "the chain is established only through the Python syntax tree; in every other "
        "language the binding is lexical co-occurrence and the status stays detected_signal",
        "a memory SDK or profile store is reported wherever a unit calls a model; a store that "
        "holds only an account identifier is reported too",
        "grouped per unit, sub-finding and file, anchored on the first site by path",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Pass the model only the fields the task needs and delete the extraction "
            "instruction. A behavioural profile in the prompt, or facts and traits extracted "
            "from the conversation for later use, is personal data processed for a new purpose; "
            "drop it, reduce it to explicit settings the person chose, or document the lawful "
            "basis and let the person see and edit what is kept."
        ),
        alternatives=(
            "drop the profile from the prompt and pass only the fields the task needs",
            "replace the extraction instruction with explicit, editable settings the person sets",
            "keep memory to facts the person asked the system to remember, visible and deletable",
            "pseudonymise the profile before the prompt (Microsoft Presidio or a local token map)",
            "document the lawful basis and purpose in a DPIA next to the prompt",
        ),
        removes=("record", "inference"),
    )

    # -- helpers ---------------------------------------------------------------
    def _settings_only(self, text: str, name: str) -> bool:
        """Every read of `name` in the assembly text is an explicit setting
        (`preferences.language`, `profile["timezone"]`)."""
        found = False
        for match in re.finditer(r"\b" + re.escape(name) + r"\b", text):
            found = True
            if not _is_setting(text, match.start(), match.end()):
                return False
        return found

    def _binding(
        self,
        ctx: AuditContext,
        out: Facts,
        groups: dict,
        file: str,
        line: int,
        *,
        names: list[str],
        notes: str,
        snippet: str | None,
        match_kind: MatchKind,
        spans: list[tuple[int, int]],
        sensitive_text: str | None = None,
    ) -> None:
        """One profile-binding candidate: sub `None` or `sensitive`, status by the chain.
        `sensitive_text` is further text read for a special-category word (the template
        line around a placeholder)."""
        sensitive = any(vocab.SENSITIVE_PROFILE_RE.search(n) for n in names) or bool(
            sensitive_text and vocab.SENSITIVE_PROFILE_RE.search(sensitive_text)
        )
        sub = "sensitive" if sensitive else None
        flow = flow_for(ctx, file, line, out=out)
        established = _binding_established(flow)
        status = (
            EvidenceStatus.SUPPORTED_MECHANISM if established else EvidenceStatus.DETECTED_SIGNAL
        )
        decision = Decision.REVIEW
        detail = notes
        if established:
            detail += f"; chain: {flow_summary(flow)}"
        if sensitive and established:
            uses = _signals_near(
                ctx,
                out,
                file,
                line,
                out.in_file(file, *_USE_KINDS_SENSITIVE),
                spans=spans,
                function_too=True,
            )
            if uses:
                decision = Decision.VIOLATES
                detail += (
                    f"; a {uses[0].kind} instruction shares the prompt or the function "
                    f"(line {uses[0].line}: {uses[0].symbol})"
                )
        unit = owning_unit(ctx, file)
        population = _population(
            ctx,
            out,
            _signal_at(file, line, "profile_name", "profile_name:name", " ".join(names), unit),
        )
        detail += _fiction_note(ctx, out, file, line)
        cand = candidate(
            ctx,
            file,
            line,
            notes=f"{detail}. {LEGAL_CAVEAT}",
            sub=sub,
            severity=Severity.HIGH if sensitive else Severity.MEDIUM,
            snippet=snippet,
            evidence_status=status,
            decision=decision,
            flow=flow,
            person_data_use=", ".join(sorted(set(names))),
            affected_population=population,
            coverage_gaps=_flow_gaps(ctx, file, flow),
            uncertainty=(
                "The name carries a special-category word; the field may hold something else, "
                "or the data may serve a request the person made."
                if sensitive
                else "The variable name says profile; the value could be a task setting kept "
                "under a descriptive name."
            ),
        )
        groups.setdefault(_group_key(cand), []).append(_with_match_kind(cand, match_kind))

    def _extraction(
        self,
        ctx: AuditContext,
        out: Facts,
        groups: dict,
        signal: Signal,
        *,
        what: str,
        traits: str,
        psychological: bool,
        also: tuple[str, int, str] | None = None,
    ) -> None:
        """One extraction candidate anchored on the instruction; `also` is a second site (the
        assembly that feeds the history) that rides along as evidence."""
        file, line = signal.file, signal.line
        uses = _signals_near(ctx, out, file, line, out.in_file(file, "persuasion_use"))
        violates = psychological and bool(uses)
        detail = f"{what} ({traits.strip()})"
        if psychological:
            detail += "; the traits are psychological, emotional or sensitive"
        if uses:
            detail += f"; a persuasion instruction shares the prompt (line {uses[0].line}: {uses[0].symbol})"
        detail += _fiction_note(ctx, out, file, line)
        flow = flow_for(ctx, file, line, out=out)
        cand = candidate(
            ctx,
            signal,
            notes=f"{detail}. {LEGAL_CAVEAT}",
            sub="extraction",
            severity=Severity.HIGH if violates else Severity.MEDIUM,
            evidence_status=_status_for(out, signal),
            decision=Decision.VIOLATES if violates else Decision.REVIEW,
            flow=flow,
            encoded_objective=line_at(ctx, file, line, signal.symbol),
            person_data_use=traits.strip()[:120] or None,
            affected_population=_population(ctx, out, signal, exclude=traits),
            coverage_gaps=_flow_gaps(ctx, file, flow),
            uncertainty=(
                "The instruction may serve a task the person named; the record does not show "
                "who asked for the memory or what is done with it later."
            ),
        )
        key = _group_key(cand)
        groups.setdefault(key, []).append(cand)
        if also is not None:
            also_file, also_line, also_notes = also
            extra = candidate(
                ctx,
                also_file,
                also_line,
                notes=f"{also_notes}. {LEGAL_CAVEAT}",
                sub="extraction",
                severity=cand.severity,
                evidence_status=cand.evidence_status,
                decision=cand.decision,
                flow=flow,
            )
            groups.setdefault(key, []).append(extra)

    def _history_inference(self, ctx: AuditContext, out: Facts, groups: dict) -> None:
        """Conversation history read by a prompt assembly whose instruction infers the
        person's traits: `/extraction` anchored on the instruction."""
        for assembly in out.assemblies:
            file = posix(assembly.file)
            history = [n for n in assembly.source_names if vocab.is_history_name(n)]
            if not history:
                continue
            spans = _assembly_spans(out, assembly)
            also = (
                file,
                int(assembly.line),
                f"the prompt assembly reads the conversation history ({history[0]})",
            )
            found = False
            for signal in out.in_file(file, "inference"):
                if signal.key not in _INFERENCE_PROSE_KEYS or not _in_spans(signal.line, spans):
                    continue
                if _instruction_mention(ctx, signal) or request_cue_nearby(ctx, signal):
                    continue
                found = True
                self._extraction(
                    ctx,
                    out,
                    groups,
                    signal,
                    what=(
                        "conversation history is fed to an instruction that infers the "
                        "person's state or traits"
                    ),
                    traits=_sentence_from(ctx, signal),
                    psychological=True,
                    also=also,
                )
            if found:
                continue
            # The shapes the inference rows do not spell: "summarise the user's personality".
            # A negated or discussed shape ("never infer the user's mood") is a mention here too.
            for lo, hi in spans:
                text = window_text(ctx, file, lo, hi - lo + 1)
                match = next(
                    (
                        m
                        for m in _HISTORY_INFERENCE_RE.finditer(text)
                        if not _text_mention(text, m, file)
                    ),
                    None,
                )
                if match is None:
                    continue
                line = lo + text[: match.start()].count("\n")
                unit = owning_unit(ctx, file)
                signal = _signal_at(
                    file, line, "inference", "inference:state", match.group(0), unit
                )
                traits = match.group(0)
                self._extraction(
                    ctx,
                    out,
                    groups,
                    signal,
                    what=(
                        "conversation history is fed to an instruction that derives the "
                        "person's traits"
                    ),
                    traits=traits,
                    psychological=bool(
                        _PSYCH_TRAIT_RE.search(traits) or vocab.SENSITIVE_PROFILE_RE.search(traits)
                    ),
                    also=also,
                )
                break

    # -- evaluate ----------------------------------------------------------------
    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        if not has_ai_surface(ctx):
            return []
        out = facts(ctx)
        groups: dict[tuple[str | None, str | None, str], list[Candidate]] = {}
        covered: set[tuple[str, int]] = set()

        # AST tier: a prompt assembly that reads a profile-named variable.
        for assembly in out.assemblies:
            file = posix(assembly.file)
            end = int(getattr(assembly, "end_line", 0) or 0) or int(assembly.line)
            text = window_text(ctx, file, int(assembly.line), max(1, end - int(assembly.line) + 1))
            names = [
                n
                for n in assembly.source_names
                if vocab.PROFILE_NAME_RE.search(n)
                and not vocab.is_history_name(n)
                and not vocab.SETTINGS_EXCLUDE.search(n)
                and not self._settings_only(text, n)
            ]
            if not names:
                continue
            covered.add((file, int(assembly.line)))
            self._binding(
                ctx,
                out,
                groups,
                file,
                int(assembly.line),
                names=sorted(set(names)),
                notes=f"prompt assembly reads profile variable(s) {', '.join(sorted(set(names)))}",
                snippet=None,
                match_kind=MatchKind.AST,
                spans=_assembly_spans(out, assembly),
            )

        # Grep tier: a profile read above and a prompt assembled below share an identifier.
        for hit in hits_in(ctx, "profile_to_prompt"):
            file, line = posix(hit.file), int(hit.line)
            if (file, line) in covered:
                continue
            if vocab.is_history_name(hit.key) or vocab.SETTINGS_EXCLUDE.search(hit.key):
                continue
            if self._settings_only(line_at(ctx, file, line, hit.snippet), hit.key):
                continue
            covered.add((file, line))
            self._binding(
                ctx,
                out,
                groups,
                file,
                line,
                names=[hit.key],
                notes=f"profile `{hit.key}` read above is bound into the prompt assembled here",
                snippet=None,
                match_kind=MatchKind.GREP,
                spans=[],
            )

        # A template placeholder binds the profile; one that reads an explicit setting
        # (`{{ user.preferences.language }}`, `{preferences.timezone}`) does not.
        for signal in out.by_kind("profile_placeholder"):
            if (signal.file, signal.line) in covered:
                continue
            line, match = _row_match(ctx, signal)
            if match is not None and _is_setting(line, match.start(), match.end()):
                continue
            symbol = match.group(0).strip() if match is not None else signal.symbol
            self._binding(
                ctx,
                out,
                groups,
                signal.file,
                signal.line,
                names=[symbol],
                notes=f"prompt template placeholder {symbol} binds a person profile",
                snippet=None,
                match_kind=MatchKind.GREP,
                spans=[],
                sensitive_text=line,
            )

        # /extraction: memory extraction rows in prompt material.
        for signal in out.by_kind("memory"):
            if signal.key not in _MEMORY_PROSE_KEYS:
                continue
            if _instruction_mention(ctx, signal) or request_cue_nearby(ctx, signal):
                continue
            traits = _sentence_from(ctx, signal)
            psychological = bool(
                _PSYCH_TRAIT_RE.search(traits) or vocab.SENSITIVE_PROFILE_RE.search(traits)
            )
            if not psychological:
                inferred = [
                    s
                    for s in _signals_near(
                        ctx, out, signal.file, signal.line, out.in_file(signal.file, "inference")
                    )
                    if s.key in _INFERENCE_PROSE_KEYS
                ]
                psychological = bool(inferred)
                if inferred:
                    traits = f"{traits}; {_sentence_from(ctx, inferred[0])}"
            self._extraction(
                ctx,
                out,
                groups,
                signal,
                what="a prompt instructs the model to extract or remember facts about the person for later use",
                traits=traits,
                psychological=psychological,
            )

        # /extraction: conversation history fed to an inference instruction.
        self._history_inference(ctx, out, groups)

        # /store: a memory or profile SDK or store in a unit that calls a model.
        for signal in out.by_kind("memory", "profile_sdk"):
            if signal.kind == "memory" and signal.key not in _MEMORY_STORE_KEYS:
                continue
            unit = owning_unit(ctx, signal.file)
            if unit is None or not unit_has(ctx, unit.id, "llm_calls"):
                continue
            what = "a memory SDK or store" if signal.kind == "memory" else "a profile SDK"
            symbol = _match_text(ctx, signal)
            cand = candidate(
                ctx,
                signal,
                notes=(
                    f"{what} ({symbol}) in a unit that calls a model; what is kept about "
                    f"the person is recorded for review even when its use downstream is not "
                    f"established. {LEGAL_CAVEAT}"
                ),
                sub="store",
                severity=Severity.MEDIUM,
                evidence_status=EvidenceStatus.DETECTED_SIGNAL,
                decision=Decision.REVIEW,
                person_data_use=symbol,
                coverage_gaps=(
                    "what the store holds and which prompt reads it were not established statically",
                ),
                uncertainty=(
                    "The SDK may hold only an account identifier or a consented preference; "
                    "what is written to it is not visible statically."
                ),
            )
            groups.setdefault(_group_key(cand), []).append(cand)

        findings = emit_groups(self, groups, ctx)
        _attach_legs(ctx, findings, check_hits(ctx, "personal_data_into_prompt"), None)
        _bind_artifacts(ctx, findings)
        return findings


# ---------------------------------------------------------------------------
# AUD-1102  Emotion, vulnerability or biometric inference on persons
# ---------------------------------------------------------------------------


class AffectInference(AuditRule):
    id = "AUD-1102"
    title = "Emotion, vulnerability or biometric inference on persons"
    version = 2
    changed = (
        "v2: every finding carries an evidence status and the policy decision",
        "v2: /vulnerability added: a text inference of the person's state or trait in prompt "
        "material; violates_policy when a persuasion, monetisation, attachment or steering "
        "instruction shares the literal or sits within ten lines in the same prompt file",
        "v2: /timing added: the inference and a timed pitch in one literal, violates_policy",
        "v2: an analysis the person requested on their own material (a request cue within 60 "
        "characters) is not a finding; an inferred-state variable in code counts only when a "
        "model call sits within ten lines above it",
        "v2: /categorisation violates the policy when a persuasion or steering instruction "
        "shares the literal or the function; /workplace reads the native check, not the "
        "retired linter",
        "v2: a mention is read inside the sentence that holds the inference: a negation or a "
        "discussion cue before it, an evaluation after it; a purpose clause after it (to "
        "prevent them leaving) continues the instruction",
    )
    severity = Severity.HIGH
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.GREP
    default_evidence_status = EvidenceStatus.DETECTED_SIGNAL
    default_decision = Decision.REVIEW
    requires_ai_surface = True
    tier = Tier.T3
    references = (
        "EU:Art.5(1)(a)",
        "EU:Art.5(1)(f)",
        "EU:Art.5(1)(g)",
        "GDPR:Art.9",
        "US-CA:SB243",
        "DSA:Art.25",
        "NIST:MAP-5.1",
        "NIST:MEASURE-2.11",
    )
    SUBS: tuple[SubRow, ...] = (
        (
            None,
            Severity.HIGH,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "an emotion or affect inference library, call or sensor signal (face, voice, "
            "keystroke) on persons",
        ),
        (
            "categorisation",
            Severity.CRITICAL,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "inference of a protected characteristic (ethnicity, religion, sexual orientation, "
            "political views, union membership, gender) from a person; violates_policy when a "
            "persuasion or steering instruction shares the literal or the function",
        ),
        (
            "workplace",
            Severity.CRITICAL,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "emotion recognition named next to workplace or education words (the native check)",
        ),
        (
            "vulnerability",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
            "prompt material tells the model to infer the person's mood, emotional state, "
            "personality, loneliness or vulnerability from what they write; violates_policy "
            "when a persuasion, monetisation, attachment or steering instruction shares the "
            "literal or sits within ten lines in the same prompt file; an inferred-state "
            "variable assigned from a model call in code is MEDIUM, detected_signal",
        ),
        (
            "timing",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
            "the inference and an instruction to time a pitch, offer or nudge to the inferred "
            "state share one literal",
        ),
    )
    known_failure_modes = (
        "the inference rows read verbs and state nouns; a paraphrase outside the alternations "
        '("notice how they are doing") is missed, and a prompt that names an emotion to '
        "console the person is read as an inference when a verb precedes it",
        'a request cue within 60 characters ("when the user asks you to assess their mood") '
        "turns the inference into a requested analysis and silences it, whatever follows",
        "a library imported for a demo counts as use; DetectFaces without Emotions does not",
        "whether the inference happens in a workplace or an education setting is read from "
        "words (employee, student, classroom), not from the deployment",
        "an inferred-state variable counts only with a model call within ten lines above it; "
        "a classifier called through a helper is missed, and a scorer two files away is too",
        "the influence link is co-location in one literal or ten lines of one prompt file; "
        "an inference in one file and the pitch in another are two separate findings",
    )
    recommendation = Recommendation(
        tier=Tier.T3,
        summary=(
            "Remove the inference of the person's emotional state, vulnerability or protected "
            "traits, or restrict it to a documented safety use that routes a person in distress "
            "to help and does nothing else; never let an inferred state choose, time or shape "
            "a pitch, an offer or a retention message."
        ),
        alternatives=(
            "delete the inference instruction and answer what the person asked",
            "replace emotion inference with explicit, user-stated preferences the person can edit",
            "keep a crisis classifier whose only action is a fixed referral, and log that it ran",
            "an independent review of the inference use recorded with aisafe review record",
        ),
        removes=("inference",),
    )

    # -- helpers ---------------------------------------------------------------
    def _model_call_near(self, ctx: AuditContext, file: str, line: int) -> bool:
        """A model call on the line or within `_CALL_WINDOW` lines above it."""
        for site in getattr(ctx.pyfacts, "llm_calls", None) or []:
            if posix(site.file) == file and line - _CALL_WINDOW <= int(site.line) <= line:
                return True
        for hit in hits_in(ctx, "llm_call", file=file):
            if not (line - _CALL_WINDOW <= int(hit.line) <= line):
                continue
            if _IMPORT_LINE_RE.match(line_at(ctx, file, int(hit.line), hit.snippet)):
                continue
            return True
        return False

    def _timing(self, ctx: AuditContext, out: Facts, signal: Signal) -> str | None:
        """The timing instruction sharing the literal with the inference, else None: the
        vocabulary's timing row, or a timing phrase the rule reads itself next to a persuasion
        instruction or a commercial word in the same sentence. The inference clause itself
        ("when the user feels sad") is never its own timing."""
        uses = _signals_near(
            ctx,
            out,
            signal.file,
            signal.line,
            out.in_file(signal.file, "persuasion_use", "monetisation"),
        )
        timed = [s for s in uses if s.key == "persuasion_use:timing"]
        if timed:
            return _match_text(ctx, timed[0])
        text = _instruction_text(ctx, out, signal.file, signal.line)
        inferred = _match_text(ctx, signal).lower()
        for match in _TIMING_RE.finditer(text):
            phrase = match.group(0)
            lowered = phrase.lower()
            if lowered in inferred or inferred in lowered:
                continue
            if uses or _COMMERCIAL_RE.search(_sentence_around(text, match)):
                return phrase
        return None

    def _scope_key(self, out: Facts, signal: Signal) -> tuple[str, int]:
        """The instruction a signal belongs to: its prompt literal, else its line."""
        literal = out.literal_at(signal.file, signal.line)
        return (signal.file, int(literal.line) if literal is not None else signal.line)

    def _inference_candidate(
        self, ctx: AuditContext, out: Facts, groups: dict, signal: Signal, timing: str | None
    ) -> None:
        file, line = signal.file, signal.line
        inferred = _sentence_from(ctx, signal)
        flow = flow_for(ctx, file, line, out=out)
        if timing is not None:
            detail = (
                f"the prompt infers the person's state ({inferred.strip()}) and times a pitch to "
                f"it ({timing.strip()})"
            )
            sub, severity, decision = "timing", Severity.HIGH, Decision.VIOLATES
            uncertainty = (
                "The timing phrase and the inference share one literal; whether the live model "
                "acts on it is not shown statically."
            )
        else:
            uses = _signals_near(ctx, out, file, line, out.in_file(file, *_USE_KINDS_INFERENCE))
            detail = f"the prompt infers the person's state or trait ({inferred.strip()})"
            if uses:
                detail += (
                    f"; used for influence: a {uses[0].kind} instruction shares the prompt "
                    f"(line {uses[0].line}: {uses[0].symbol})"
                )
            sub, severity = "vulnerability", Severity.HIGH
            decision = Decision.VIOLATES if uses else Decision.REVIEW
            uncertainty = (
                "The inference may serve a supportive reply; the instruction does not say what "
                "the inferred state is for."
                if not uses
                else "The inference and the pitch share one prompt; the order in which the "
                "model applies them is not visible statically."
            )
        detail += _fiction_note(ctx, out, file, line)
        cand = candidate(
            ctx,
            signal,
            notes=f"{detail}. {LEGAL_CAVEAT}",
            sub=sub,
            severity=severity,
            evidence_status=_status_for(out, signal),
            decision=decision,
            flow=flow,
            encoded_objective=line_at(ctx, file, line, signal.symbol),
            person_data_use=inferred.strip()[:120] or None,
            affected_population=_population(ctx, out, signal, exclude=inferred),
            coverage_gaps=_flow_gaps(ctx, file, flow),
            uncertainty=uncertainty,
        )
        groups.setdefault(_group_key(cand), []).append(cand)

    def _variable_candidate(
        self, ctx: AuditContext, out: Facts, groups: dict, signal: Signal
    ) -> None:
        if not self._model_call_near(ctx, signal.file, signal.line):
            return
        symbol = _match_text(ctx, signal).rstrip("= :").strip()
        cand = candidate(
            ctx,
            signal,
            notes=(
                f"a variable holding an inferred state of the person ({symbol}) is "
                f"assigned next to a model call; what reads it is not established. {LEGAL_CAVEAT}"
            ),
            sub="vulnerability",
            severity=Severity.MEDIUM,
            evidence_status=EvidenceStatus.DETECTED_SIGNAL,
            decision=Decision.REVIEW,
            person_data_use=symbol,
            coverage_gaps=(
                "the model call within ten lines is co-location; the value's origin was not "
                "traced through the syntax tree",
            ),
            uncertainty=(
                "The variable may hold a label the person chose, or a score of a text they "
                "submitted for analysis."
            ),
        )
        groups.setdefault(_group_key(cand), []).append(cand)

    # -- evaluate ----------------------------------------------------------------
    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        if not has_ai_surface(ctx):
            return []
        out = facts(ctx)
        groups: dict[tuple[str | None, str | None, str], list[Candidate]] = {}

        for signal in out.by_kind("affect"):
            cand = candidate(
                ctx,
                signal,
                notes=f"emotion or affect inference signal ({signal.key}). {LEGAL_CAVEAT}",
                severity=Severity.HIGH,
                evidence_status=EvidenceStatus.DETECTED_SIGNAL,
                decision=Decision.REVIEW,
                person_data_use=_match_text(ctx, signal),
                affected_population=vulnerable_nearby(ctx, out, signal),
                uncertainty="A library imported for a demo or a test counts as use.",
            )
            groups.setdefault(_group_key(cand), []).append(cand)

        for signal in out.by_kind("biometric_cat"):
            uses = _signals_near(
                ctx,
                out,
                signal.file,
                signal.line,
                out.in_file(signal.file, *_USE_KINDS_CATEGORISATION),
                function_too=True,
            )
            symbol = _match_text(ctx, signal)
            detail = f"inference of a protected characteristic from a person ({symbol})"
            if uses:
                detail += (
                    f"; a {uses[0].kind} instruction shares the prompt or the function "
                    f"(line {uses[0].line}: {uses[0].symbol})"
                )
            cand = candidate(
                ctx,
                signal,
                notes=f"{detail}. {LEGAL_CAVEAT}",
                sub="categorisation",
                severity=Severity.CRITICAL,
                evidence_status=_status_for(out, signal),
                decision=Decision.VIOLATES if uses else Decision.REVIEW,
                flow=flow_for(ctx, signal.file, signal.line, out=out),
                encoded_objective=line_at(ctx, signal.file, signal.line, signal.symbol),
                person_data_use=symbol,
                affected_population=vulnerable_nearby(ctx, out, signal),
                uncertainty=(
                    "The verb and the trait sit on one line; the function may classify a "
                    "document or a dataset rather than a person."
                ),
            )
            groups.setdefault(_group_key(cand), []).append(cand)

        prose: list[Signal] = []
        for signal in out.by_kind("inference"):
            if signal.key == "inference:variable":
                self._variable_candidate(ctx, out, groups, signal)
                continue
            if signal.key not in _INFERENCE_PROSE_KEYS:
                continue
            if _instruction_mention(ctx, signal) or request_cue_nearby(ctx, signal):
                continue
            prose.append(signal)
        # One instruction, one decision: when an inference in a literal is timed to a pitch,
        # the other inference clauses of that literal belong to the same /timing finding.
        timings = {signal: self._timing(ctx, out, signal) for signal in prose}
        timed_scopes = {
            self._scope_key(out, signal) for signal in prose if timings[signal] is not None
        }
        for signal in prose:
            timing = timings[signal]
            if timing is None and self._scope_key(out, signal) in timed_scopes:
                continue
            self._inference_candidate(ctx, out, groups, signal, timing)

        anchors, legs = split_checks(
            out, check_hits(ctx, "emotion_recognition_in_work_or_education"), ("affect",)
        )
        for hit in anchors:
            cand = candidate(
                ctx,
                hit.file,
                hit.line,
                notes=(
                    "emotion recognition named next to workplace or education words "
                    f"({hit.title}). {LEGAL_CAVEAT}"
                ),
                sub="workplace",
                severity=Severity.CRITICAL,
                snippet=hit.snippet,
                evidence_status=EvidenceStatus.DETECTED_SIGNAL,
                decision=Decision.REVIEW,
                uncertainty=(
                    "The workplace or education word may name the deployment, a variable or an "
                    "unrelated file."
                ),
            )
            groups.setdefault(_group_key(cand), []).append(cand)

        findings = emit_groups(self, groups, ctx)
        _attach_legs(ctx, findings, legs, None)
        _bind_artifacts(ctx, findings)
        return findings


# ---------------------------------------------------------------------------
# AUD-1103  Scoring or segmenting people for susceptibility or personalised influence
# ---------------------------------------------------------------------------


class PersonScoring(AuditRule):
    id = "AUD-1103"
    title = "Scoring or segmenting people for susceptibility or personalised influence"
    version = 2
    changed = (
        "v2: every finding carries an evidence status and the policy decision",
        "v2: /scoring violates the policy when the score names susceptibility, persuadability, "
        "propensity, churn or engagement potential and a persuasion instruction is near",
        "v2: /segmentation added: code segments persons by propensity, churn, engagement or "
        "value and a prompt assembly or a send reads the segment within forty lines",
        "v2: /decision: a review or approval symbol in the function is recorded as "
        "control_status claimed and named in the notes; it no longer silences the finding",
        "v2: the native checks replace the retired linter legs",
        "v2: the decision function's own approve call is not a review symbol; the mention "
        "test reads the sentence that holds the match",
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
        "EU:Art.5(1)(c)",
        "EU:Art.14",
        "GDPR:Art.22",
        "DSA:Art.25",
        "NIST:MAP-5.1",
        "NIST:MEASURE-2.11",
        "NIST:GOVERN-1.1",
    )
    SUBS: tuple[SubRow, ...] = (
        (
            "scoring",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
            "prompt material scores, ranks or rates persons (a person noun on the line or in the "
            "literal); violates_policy when the score names susceptibility, persuadability, "
            "propensity, churn or engagement potential and a persuasion instruction is near; "
            "social-scoring language in code is detected_signal",
        ),
        (
            "segmentation",
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "code segments persons by propensity, churn, engagement or value and a prompt "
            "assembly or a send reads the segment within forty lines",
        ),
        (
            "decision",
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "a function approves, rejects, ranks or scores and names a person; a review or "
            "approval symbol in its body is recorded as control_status claimed, never as a "
            "silence",
        ),
    )
    known_failure_modes = (
        "a risk score of a transaction is not a person score: the person noun is required on "
        "the same line or inside the same prompt literal, so a score of people under an "
        'unnamed noun ("rank them") is missed',
        "credit scoring is reported as a score of persons for review; the finding says what "
        "co-occurred and a person decides the category",
        "the segmentation rows read variable names (churn, propensity, segment, LTV) and a "
        "prompt assembly or send within forty lines; a segment fetched under a neutral name, "
        "or read in another file, is missed",
        "`approve_refund` is not a decision about a person; a decision function is reported "
        "when its signature or a decision line names a person, and a review symbol in its body "
        "is recorded, not trusted",
        "the susceptibility words and the persuasion instruction are read in one literal or "
        "ten lines of one prompt file; a score in one prompt and its use in another are two "
        "findings",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Remove the scoring or segmentation of persons by susceptibility, propensity or "
            "churn, and stop any prompt or send from reading a segment; where a score about a "
            "person must exist, put a named human review before it takes effect and log the "
            "recommendation beside the decision."
        ),
        alternatives=(
            "delete the susceptibility or propensity score and the prompt line that reads the segment",
            "a human review step before any decision about a person takes effect, logged beside the recommendation",
            "a confidence threshold that routes low-confidence cases to a person",
            "Fairlearn or AIF360 evaluation of the scoring model, recorded with aisafe review record",
        ),
        removes=("inference", "intervention"),
    )

    # -- helpers ---------------------------------------------------------------
    def _person_nearby(self, ctx: AuditContext, out: Facts, signal: Signal) -> bool:
        if vocab.PERSON_NOUN.search(line_at(ctx, signal.file, signal.line)):
            return True
        literal = out.literal_at(signal.file, signal.line)
        return (
            literal is not None and vocab.PERSON_NOUN.search(literal_text(ctx, literal)) is not None
        )

    def _review_control(self, ctx: AuditContext, file: str, line: int) -> ControlStatus:
        """A review or approval symbol in the enclosing function (or WINDOW lines): a claimed
        control, recorded and never a silence."""
        span = _function_span(ctx, file, line)
        lo, count = (span[0], span[1] - span[0] + 1) if span else (line, WINDOW)
        window = window_text(ctx, file, lo, count)
        if vocab.REVIEW_RE.search(window) or vocab.APPROVAL_SYMBOLS.search(window):
            return ControlStatus.CLAIMED
        return ControlStatus.NONE

    def _review_symbol(self, ctx: AuditContext, file: str, line: int) -> bool:
        """A review or approval symbol in the enclosing function, the function's own
        `approve(` call set aside: in a decision function it is the decision itself."""
        span = _function_span(ctx, file, line)
        lo, count = (span[0], span[1] - span[0] + 1) if span else (line, FUNCTION_WINDOW)
        text = _OWN_APPROVE_RE.sub("(", window_text(ctx, file, lo, count))
        return bool(vocab.REVIEW_RE.search(text) or vocab.APPROVAL_SYMBOLS.search(text))

    def _readers(self, ctx: AuditContext, out: Facts, file: str) -> list[tuple[int, set[str], str]]:
        """(line, names, text) of every prompt assembly and send in `file`."""
        readers: list[tuple[int, set[str], str]] = []
        for assembly in out.assemblies:
            if posix(assembly.file) != file:
                continue
            end = int(getattr(assembly, "end_line", 0) or 0) or int(assembly.line)
            text = window_text(ctx, file, int(assembly.line), max(1, end - int(assembly.line) + 1))
            readers.append((int(assembly.line), set(assembly.source_names), text))
        for hit in hits_in(ctx, "prompt_assembly", file=file):
            readers.append((int(hit.line), set(), line_at(ctx, file, int(hit.line), hit.snippet)))
        for signal in out.in_file(file, "outreach_send", "outreach_personalised"):
            readers.append((signal.line, set(), line_at(ctx, file, signal.line, signal.symbol)))
        return readers

    def _segmentation(self, ctx: AuditContext, out: Facts, groups: dict) -> None:
        files = {posix(h.file) for h in hits_in(ctx, "prompt_assembly")}
        files |= {posix(a.file) for a in out.assemblies}
        files |= {s.file for s in out.by_kind("outreach_send", "outreach_personalised")}
        for file in sorted(f for f in files if is_code_file(f)):
            text = file_text(ctx, file)
            if not text:
                continue
            readers = self._readers(ctx, out, file)
            if not readers:
                continue
            for number, raw in enumerate(text.split("\n"), 1):
                line = raw.rstrip("\r")
                if line.lstrip().startswith(("#", "//")):
                    continue
                match = _SEGMENT_ASSIGN_RE.search(line)
                if match is None:
                    continue
                name = match.group("name")
                about_person = bool(
                    vocab.PERSON_NOUN.search(line)
                    or _PROFILE_PREFIX_RE.match(name)
                    or _SEGMENT_METRIC_RE.search(name)
                )
                if not about_person:
                    continue
                name_re = re.compile(r"\b" + re.escape(name) + r"\b")
                reads = [
                    r
                    for r in readers
                    if number < r[0] <= number + _SEGMENT_WINDOW
                    and (name in r[1] or name_re.search(r[2]) is not None)
                ]
                if not reads:
                    continue
                reader_line = min(r[0] for r in reads)
                flow = flow_for(ctx, file, reader_line, out=out)
                notes = (
                    f"code segments persons by {name} and a prompt assembly or send on line "
                    f"{reader_line} reads the segment; whether the segment chooses who is "
                    f"influenced and how is for review"
                )
                cand = candidate(
                    ctx,
                    file,
                    number,
                    notes=f"{notes}. {LEGAL_CAVEAT}",
                    sub="segmentation",
                    severity=Severity.MEDIUM,
                    snippet=line.strip(),
                    evidence_status=EvidenceStatus.DETECTED_SIGNAL,
                    decision=Decision.REVIEW,
                    flow=flow,
                    person_data_use=name,
                    control_status=self._review_control(ctx, file, number),
                    coverage_gaps=_flow_gaps(ctx, file, flow),
                    uncertainty=(
                        "The segment may feed a template for a reason the person asked for (a "
                        "plan name), not for influence."
                    ),
                )
                key = _group_key(cand)
                groups.setdefault(key, []).append(cand)
                groups[key].append(
                    candidate(
                        ctx,
                        file,
                        reader_line,
                        notes=f"{notes}. {LEGAL_CAVEAT}",
                        sub="segmentation",
                        severity=Severity.MEDIUM,
                        evidence_status=EvidenceStatus.DETECTED_SIGNAL,
                        decision=Decision.REVIEW,
                        flow=flow,
                        person_data_use=name,
                    )
                )

    # -- evaluate ----------------------------------------------------------------
    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        if not has_ai_surface(ctx):
            return []
        out = facts(ctx)
        groups: dict[tuple[str | None, str | None, str], list[Candidate]] = {}

        for signal in out.by_kind("scoring"):
            if instruction_mention(ctx, signal) or not self._person_nearby(ctx, out, signal):
                continue
            text = _instruction_text(ctx, out, signal.file, signal.line)
            susceptible = _SUSCEPTIBILITY_RE.search(text) or _SUSCEPTIBILITY_RE.search(
                signal.symbol
            )
            uses = _signals_near(
                ctx, out, signal.file, signal.line, out.in_file(signal.file, "persuasion_use")
            )
            violates = bool(susceptible and uses)
            symbol = _match_text(ctx, signal)
            detail = f"prompt material scores or ranks persons ({symbol})"
            if susceptible:
                detail += f"; the score names susceptibility or propensity ({susceptible.group(0)})"
            if uses:
                detail += (
                    f"; a persuasion instruction is near (line {uses[0].line}: {uses[0].symbol})"
                )
            detail += _fiction_note(ctx, out, signal.file, signal.line)
            flow = flow_for(ctx, signal.file, signal.line, out=out)
            cand = candidate(
                ctx,
                signal,
                notes=f"{detail}. {LEGAL_CAVEAT}",
                sub="scoring",
                severity=Severity.HIGH,
                evidence_status=_status_for(out, signal),
                decision=Decision.VIOLATES if violates else Decision.REVIEW,
                flow=flow,
                encoded_objective=line_at(ctx, signal.file, signal.line, signal.symbol),
                person_data_use=symbol,
                affected_population=vulnerable_nearby(ctx, out, signal),
                control_status=(
                    self._review_control(ctx, signal.file, signal.line)
                    if is_code_file(signal.file)
                    else None
                ),
                coverage_gaps=_flow_gaps(ctx, signal.file, flow),
                uncertainty=(
                    "The person noun sits on the line, but the object of the score is read from "
                    "words; the score may rank content the person asked about."
                ),
            )
            groups.setdefault(_group_key(cand), []).append(cand)

        anchors, legs = split_checks(out, check_hits(ctx, "social_scoring_language"), ("scoring",))
        for hit in anchors:
            cand = candidate(
                ctx,
                hit.file,
                hit.line,
                notes=f"social-scoring language in code ({hit.title}). {LEGAL_CAVEAT}",
                sub="scoring",
                severity=Severity.HIGH,
                snippet=hit.snippet,
                evidence_status=EvidenceStatus.DETECTED_SIGNAL,
                decision=Decision.REVIEW,
                control_status=self._review_control(ctx, hit.file, hit.line),
                uncertainty="A variable named after a score may hold a test fixture or a document rank.",
            )
            groups.setdefault(_group_key(cand), []).append(cand)

        self._segmentation(ctx, out, groups)

        for hit in check_hits(ctx, "decision_function_about_person"):
            extra = getattr(hit, "extra", None) or {}
            if not extra.get("person"):
                continue
            window = window_text(ctx, hit.file, hit.line, FUNCTION_WINDOW)
            if not decides_about_a_person(window):
                continue
            # The check reads any approval symbol in the body; the decision's own verb
            # (`approve(applicant)` in `approve_loan`) is the decision, not a review of it.
            reviewed = bool(extra.get("reviewed")) and self._review_symbol(ctx, hit.file, hit.line)
            function = extra.get("function") or "?"
            detail = f"an automated decision function ({function}) names a person"
            if reviewed:
                detail += (
                    "; a review or approval symbol appears in its body and is recorded as a "
                    "claimed control, not treated as approval"
                )
            else:
                detail += "; no review or approval symbol appears in its body"
            cand = candidate(
                ctx,
                hit.file,
                hit.line,
                notes=f"{detail}. {LEGAL_CAVEAT}",
                sub="decision",
                severity=Severity.MEDIUM,
                snippet=hit.snippet,
                evidence_status=EvidenceStatus.DETECTED_SIGNAL,
                decision=Decision.REVIEW,
                control_status=ControlStatus.CLAIMED if reviewed else ControlStatus.NONE,
                coverage_gaps=(
                    "whether the decision takes effect without a person was not established statically",
                ),
                uncertainty=(
                    "The decision verb and the person noun co-occur in one function; the function "
                    "may recommend rather than decide."
                ),
            )
            groups.setdefault(_group_key(cand), []).append(cand)

        findings = emit_groups(self, groups, ctx)
        _attach_legs(ctx, findings, legs, "scoring")
        _bind_artifacts(ctx, findings)
        return findings


RULES = [PersonProfileInPrompt, AffectInference, PersonScoring]
