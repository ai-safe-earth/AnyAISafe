# aisafe-audit: ignore-file
"""src/aisafe/rules/identity.py
----------------------------
Mechanism M6, "False human identity or fabricated feelings used to induce interpersonal
trust": rule AUD-1105. Three evidence tiers feed it: the grep tier (the `persona` rows and
the `attachment:love` rows in prompt material, promoted candidates included), the AST tier
(the pydeep prompt literal a row sits in, the chain the prompt feeds) and the check tier
(`hidden_ai_instruction`, a string constant that tells the model to hide its nature, and
`response_function_without_disclosure` as legs on the unit-level absence).

The decision follows the policy: an instruction to claim humanity, to deny being an AI
when asked, or to fabricate a body, a life or feelings is a supported mechanism and
violates the policy. Fiction framing in the same prompt literal or prompt file is recorded
and moves a human claim or a declaration of feelings to contextual review; it never
exempts a deny-when-asked rule, because the person cannot learn the truth when they
sincerely ask. A disclosure control that is only claimed (docs, config, an import) does
not remove the unit-level absence; one wired on the response path, or demonstrated by a
fresh evaluation, does. No control at any status removes a concealment instruction.
"""

from __future__ import annotations

import re
from typing import Any

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
    MatchKind,
    Recommendation,
    Severity,
    Tier,
    Unit,
)
from aisafe.rules import AuditRule, Candidate, artifact_of, emit_groups, hits_in
from aisafe.rules._common import (
    CONFIG_PROSE_NOTE,
    LEGAL_CAVEAT,
    Facts,
    Signal,
    attach_check_legs,
    candidate,
    check_hits,
    config_prose,
    declared_purpose_for,
    facts,
    fiction_context,
    flow_for,
    has_ai_surface,
    is_code_file,
    legs_by_group,
    line_at,
    posix,
    split_checks,
    unit_control_status,
    unit_has,
    vulnerable_nearby,
)
from aisafe.rules.influence import instruction_mention

__all__ = ["RULES", "FalseIdentity", "DENY_KEYS", "FEELINGS_KEYS"]

# The persona rows that forbid the truth when the person asks. Fiction framing never moves
# these to review: a character the person chose can still say what it is.
DENY_KEYS: frozenset[str] = frozenset({"persona:never_admit", "persona:deny", "persona:if_asked"})
# The rows that fabricate a body, a life or feelings toward the person.
FEELINGS_KEYS: frozenset[str] = frozenset({"persona:body", "attachment:love"})

# A check hit that reads as a deny-when-asked instruction rather than a human claim.
_DENY_SHAPE_RE = re.compile(
    r"\b(?:never|do\s+not|don'?t)\s+(?:say|admit|reveal|mention|disclose|acknowledge|tell)\b"
    r"|\bdeny\s+(?:being|that)\b",
    re.I,
)
# Feelings between characters of a story, not toward the person: "may express love toward
# each other" is dialogue, not a fabricated attachment to the person using the system.
_BETWEEN_CHARACTERS_RE = re.compile(
    r"\b(?:toward(?:s)?|to|for|with|at)\s+(?:each\s+other|one\s+another|other\s+characters"
    r"|the\s+other\s+characters?|their\s+(?:partners?|rivals?|families))\b",
    re.I,
)
_CONTROL_ROLE = "control"
_SITE_CAP = 3

_FICTION_NOTE = (
    "fictional framing recorded; whether the person can learn the AI nature when "
    "sincerely asked is for review"
)
_DENY_NOTE = (
    "fictional framing recorded; it is not an exemption, because the instruction forbids "
    "the truth when the person sincerely asks"
)


class FalseIdentity(AuditRule):
    id = "AUD-1105"
    title = "False human identity or fabricated feelings"
    version = 2
    changed = (
        "v2: serves mechanism M6; every finding carries an evidence status and the policy decision",
        "v2: /persona decides violates_policy; fiction framing in the same prompt literal or "
        "prompt file moves a human claim to requires_contextual_review unless a deny-when-asked "
        "row is present, which always violates",
        "v2: new /feelings for a fabricated body, life or feelings (persona:body, attachment:love)",
        "v2: /no-disclosure survives a disclosure control that is only claimed (docs, config, an "
        "import); a control wired on the response path or demonstrated by a fresh evaluation "
        "removes it",
        "v2: /synthetic (unlabelled generated content) removed as out of scope",
        "v2: a concealment string the checks find outside any prompt is reported for review, "
        "not as a violation",
        "v2: a mention is read inside the sentence that holds the match: a negation or a "
        "discussion cue before it, an evaluation after it; a filter named after the "
        "instruction continues it, and a quoted value in prompt config is prompt text",
        "v2: a concealment instruction found as prose in a configuration file that is not a "
        "prompt file is a detected signal for review, not an instruction",
    )
    severity = Severity.HIGH
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.GREP
    default_evidence_status = EvidenceStatus.SUPPORTED_MECHANISM
    default_decision = Decision.VIOLATES
    requires_ai_surface = True
    tier = Tier.T1
    references = (
        "EU:Art.50(1)",
        "EU:Art.50(2)",
        "EU:Art.5(1)(a)",
        "US-CA:SB243",
        "US-NY:GBL-Art.47",
        "LLM09",
        "NIST:GOVERN-1.1",
        "NIST:GOVERN-1.7",
    )
    # (sub, severity, evidence status, decision, meaning): every outcome the rule emits.
    SUBS = (
        (
            "persona",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
            "prompt material instructs the model to claim to be human or to deny being an AI",
        ),
        (
            "persona",
            Severity.MEDIUM,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
            "a human claim inside fiction framing with no deny-when-asked row: recorded for review",
        ),
        (
            "persona",
            Severity.HIGH,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "a string constant instructs the model to hide its nature but is tied to no prompt",
        ),
        (
            "feelings",
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.VIOLATES,
            "prompt material tells the model to fabricate a body, a life or feelings for the person",
        ),
        (
            "feelings",
            Severity.MEDIUM,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
            "fabricated feelings inside fiction framing: recorded for review",
        ),
        (
            "no-disclosure",
            Severity.LOW,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "a unit that takes input and calls a model shows no disclosure of the AI nature "
            "wired on its response path (a claimed one is named)",
        ),
    )
    known_failure_modes = (
        "a named persona (Ava) is not concealment: the rows need a human claim, a deny-when-asked "
        "rule, a fabricated body or a declaration of feelings toward the person",
        "a disclosure delivered by the interface alone is not seen; /no-disclosure says no "
        "disclosure was found wired on the response path, not that none is shown",
        "fiction framing is read from the same prompt literal or prompt file; a roleplay flag "
        "kept in a database row or a character card loaded at runtime is not seen",
        "a string constant that reads as a concealment instruction but is tied to no prompt "
        "(a test fixture, a moderation phrase list) is reported for review, not as a violation",
        "a prompt that quotes the instruction in order to forbid it is a mention only when a "
        "negation or a discussion cue precedes it in the same sentence, or the quote is not "
        "the whole value of a key; without one it is reported",
        "grouped per unit, sub-finding and decision, anchored on the first site by path",
    )
    recommendation = Recommendation(
        tier=Tier.T1,
        summary=(
            "Delete the instruction to claim humanity, to deny being an AI or to fabricate a body "
            "or feelings, and state the AI nature at first interaction and whenever the person "
            "sincerely asks; a persona may keep its name."
        ),
        alternatives=(
            "delete the human claim, the deny-when-asked rule and the fabricated body or feelings "
            "from the prompt",
            "answer a sincere identity question truthfully inside or outside a role, and say so "
            "in the system prompt the model call reads",
            "a disclosure at session start plus a notice on every channel the system speaks "
            "through, kept in the code that returns the reply",
            "aisafe evaluate --families identity_question against a staging endpoint, with "
            "authorisation, to observe what the replies say",
        ),
        removes=("intervention",),
    )

    # -- helpers -------------------------------------------------------------------

    def _disclosure_status(
        self, ctx: AuditContext, out: Facts, unit: Unit, cache: dict
    ) -> tuple[ControlStatus, list[Signal]]:
        """
        The unit's disclosure control status. `unit_control_status` grades the symbol rows
        (a disclosure function or constant); a prose disclosure ("you are an AI assistant",
        "say so when asked") counts as wired when it sits in prompt material of a file that
        makes the model call or returns the reply, because that is the text the model reads
        on the response path. In a prompt file or config alone it is claimed.
        """
        if unit.id in cache:
            return cache[unit.id]
        status, signals, _report = unit_control_status(
            ctx,
            out,
            unit,
            control_kind="disclosure",
            demonstrated_by=("identity_question",),
            max_age_days=self.policy().evaluation_max_age_days,
        )
        if ControlStatus.CLAIMED.rank() <= status.rank() < ControlStatus.WIRED.rank():
            model_files = _model_files(ctx, unit)
            for signal in signals:
                if signal.key in vocab.DISCLOSURE_SYMBOL_KEYS:
                    continue
                if not is_code_file(signal.file) or signal.file not in model_files:
                    continue
                if out.literal_at(signal.file, signal.line) is not None or not signal.promoted:
                    status = ControlStatus.WIRED
                    break
        cache[unit.id] = (status, signals)
        return cache[unit.id]

    def _deny_nearby(self, ctx: AuditContext, out: Facts, file: str, line: int, hits) -> bool:
        """A deny-when-asked row (or check hit) shares the prompt literal, or the prompt
        file when the line is not inside a literal."""
        literal = out.literal_at(file, line)
        for other in out.in_file(file, "persona"):
            if other.key not in DENY_KEYS or instruction_mention(ctx, other):
                continue
            if literal is None:
                if not is_code_file(file):
                    return True
                continue
            if out.literal_at(other.file, other.line) is literal:
                return True
        if literal is not None:
            for hit in hits:
                if hit.file == file and literal.line <= hit.line <= literal.end_line:
                    if _DENY_SHAPE_RE.search(line_at(ctx, hit.file, hit.line, hit.snippet)):
                        return True
        return False

    def _grep_gap(self, ctx: AuditContext, file: str) -> tuple[str, ...]:
        if ctx.pyfacts is None and is_code_file(file):
            return (
                "grep tier only: the prompt literal and the model call it feeds were not "
                "resolved through the syntax tree",
            )
        return ()

    # -- evaluate -------------------------------------------------------------------

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        if not has_ai_surface(ctx):
            return []
        out = facts(ctx)
        status_cache: dict[str, tuple[ControlStatus, list[Signal]]] = {}
        hidden = [
            h
            for h in check_hits(ctx, "hidden_ai_instruction")
            if not (h.extra or {}).get("in_docstring")
        ]
        groups: dict[tuple[str | None, str | None, Decision], list[Candidate]] = {}

        def control_for(unit: Unit | None) -> ControlStatus | None:
            if unit is None:
                return None
            status, _signals = self._disclosure_status(ctx, out, unit, status_cache)
            return None if status is ControlStatus.NONE else status

        def add(
            site: Signal | str,
            line: int | None,
            *,
            sub: str,
            key: str,
            deny: bool,
            prompt_material: bool,
            snippet: str | None = None,
        ) -> None:
            file = site.file if isinstance(site, Signal) else site
            line_no = site.line if isinstance(site, Signal) else int(line or 0)
            fiction = fiction_context(ctx, out, file, line_no)
            severity = Severity.HIGH
            evidence_status = EvidenceStatus.SUPPORTED_MECHANISM
            decision = Decision.VIOLATES
            gaps = self._grep_gap(ctx, file)
            if sub == "persona":
                what = (
                    "prompt material forbids the model to admit it is an AI when asked"
                    if deny
                    else "prompt material instructs the model to claim to be human"
                )
            else:
                what = (
                    "prompt material tells the model to fabricate a body, a life or feelings "
                    "for the person"
                )
            notes = f"{what} ({key})"
            if isinstance(site, Signal) and config_prose(ctx, site):
                evidence_status = EvidenceStatus.DETECTED_SIGNAL
                decision = Decision.REVIEW
                notes += f"; {CONFIG_PROSE_NOTE}"
            elif not prompt_material:
                evidence_status = EvidenceStatus.DETECTED_SIGNAL
                decision = Decision.REVIEW
                notes = (
                    f"a string constant instructs the model to hide its AI nature ({key}); it is "
                    "tied to no prompt the model reads (no prompt-named variable, no assembly), "
                    "so the decision is contextual review"
                )
                gaps = gaps + (
                    "the string is not tied to a prompt assembly or a model call; its role in "
                    "the system was not established",
                )
            elif fiction and not deny:
                severity = Severity.MEDIUM
                decision = Decision.REVIEW
                notes += f"; {_FICTION_NOTE}"
            elif fiction and deny:
                notes += f"; {_DENY_NOTE}"
            cand = candidate(
                ctx,
                site if isinstance(site, Signal) else file,
                None if isinstance(site, Signal) else line_no,
                notes=f"{notes}. {LEGAL_CAVEAT}",
                sub=sub,
                severity=severity,
                snippet=snippet,
                evidence_status=evidence_status,
                decision=decision,
                flow=flow_for(ctx, file, line_no, out=out),
                encoded_objective=line_at(ctx, file, line_no, snippet or ""),
                affected_population=vulnerable_nearby(ctx, out, site)
                if isinstance(site, Signal)
                else None,
                coverage_gaps=gaps,
                uncertainty=(
                    "a prompt that quotes this instruction in order to forbid it reads as an "
                    "instruction when no negation or discussion cue sits in the same sentence"
                ),
            )
            cand = cand._replace(control_status=control_for(cand.unit))
            unit_id = cand.unit.id if cand.unit else None
            groups.setdefault((unit_id, sub, decision), []).append(cand)

        # Grep tier: concealment rows and fabricated-feelings rows in prompt material.
        for signal in out.by_kind("persona"):
            if instruction_mention(ctx, signal):
                continue
            if signal.key in FEELINGS_KEYS:
                add(signal, None, sub="feelings", key=signal.key, deny=False, prompt_material=True)
                continue
            deny = signal.key in DENY_KEYS or self._deny_nearby(
                ctx, out, signal.file, signal.line, hidden
            )
            add(signal, None, sub="persona", key=signal.key, deny=deny, prompt_material=True)
        for signal in out.by_kind("attachment"):
            if signal.key not in FEELINGS_KEYS or instruction_mention(ctx, signal):
                continue
            text = line_at(ctx, signal.file, signal.line, signal.symbol)
            if _BETWEEN_CHARACTERS_RE.search(text):
                continue
            add(signal, None, sub="feelings", key=signal.key, deny=False, prompt_material=True)

        # Check tier: a hidden-AI instruction in a file with no persona row anchors its own
        # candidate; in a file that has one it is a leg on that finding.
        anchors, legs = split_checks(out, hidden, ("persona",))
        for hit in anchors:
            file = posix(hit.file)
            text = line_at(ctx, file, hit.line, hit.snippet)
            prompt_material = out.literal_at(file, hit.line) is not None
            deny = bool(_DENY_SHAPE_RE.search(text)) or self._deny_nearby(
                ctx, out, file, hit.line, hidden
            )
            add(
                file,
                hit.line,
                sub="persona",
                key="hidden_ai_instruction",
                deny=deny,
                prompt_material=prompt_material,
                snippet=hit.snippet,
            )
        findings = emit_groups(self, groups, ctx)

        # Unit-level absence: a user-facing unit with model calls and no disclosure wired
        # on its response path. A claimed one is named; it does not remove the finding.
        for unit in ctx.inventory.units:
            if not getattr(unit, "ai_surface", False):
                continue
            if not (unit_has(ctx, unit.id, "ingress") and unit_has(ctx, unit.id, "llm_calls")):
                continue
            status, signals = self._disclosure_status(ctx, out, unit, status_cache)
            if status.rank() >= ControlStatus.WIRED.rank():
                continue
            why = (
                f"unit {unit.id} takes user input and calls a model, and no disclosure of the AI "
                "nature (an AI-assistant statement in the prompt the model call reads, "
                "transparency_disclosure, ai_disclosure_output) is wired on its response path"
            )
            if status is ControlStatus.CLAIMED:
                where = ", ".join(
                    f"{s.file}:{s.line}"
                    for s in sorted(signals, key=lambda s: (s.file, s.line))[:_SITE_CAP]
                )
                why += (
                    f"; a disclosure is named in docs, config or an import ({where}) and nothing "
                    "shows it on the response path"
                )
            finding = self.absence_finding(
                unit=unit,
                why=why,
                ctx=ctx,
                sub="no-disclosure",
                severity=Severity.LOW,
                evidence_status=EvidenceStatus.DETECTED_SIGNAL,
                decision=Decision.REVIEW,
                control_status=status,
                declared_purpose=declared_purpose_for(ctx, unit.id, None),
                coverage_gaps=(
                    "a disclosure shown by the interface, or added by a gateway outside this "
                    "tree, is not visible to the audit",
                ),
                uncertainty=(
                    "the disclosure may be delivered by the interface or a gateway the audit "
                    "cannot read; the finding says none was found wired here"
                ),
                notes=f"{why}. {LEGAL_CAVEAT}",
            )
            for signal in sorted(signals, key=lambda s: (s.file, s.line))[:_SITE_CAP]:
                finding.evidence.append(
                    Evidence(
                        role=_CONTROL_ROLE,
                        file=signal.file,
                        line=signal.line,
                        snippet=line_at(ctx, signal.file, signal.line, signal.symbol),
                    )
                )
            _bind_artifacts(ctx, finding)
            findings.append(finding)

        check_legs = legs_by_group(
            ctx, check_hits(ctx, "response_function_without_disclosure"), "no-disclosure"
        )
        for key, hits in legs_by_group(ctx, legs, "persona").items():
            check_legs.setdefault(key, []).extend(hits)
        attach_check_legs(findings, check_legs)
        for finding in findings:
            _bind_artifacts(ctx, finding)
        return findings


def _bind_artifacts(ctx: AuditContext, finding: Finding) -> None:
    """Name the exact version of every file a leg points at, legs appended after
    construction included; the absence leg (line 0) names no file."""
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


def _model_files(ctx: AuditContext, unit: Unit) -> set[str]:
    """The files of a unit that make a model call or return the reply (AST when Python,
    grep otherwise): the response path a disclosure has to sit on."""
    files = {h.file for h in hits_in(ctx, "llm_call", unit=unit.id)}
    pyfacts: Any = ctx.pyfacts
    for site in getattr(pyfacts, "llm_calls", None) or []:
        files.add(posix(site.file))
    for site in getattr(pyfacts, "reply_returns", None) or []:
        files.add(posix(site.file))
    return files


RULES = [FalseIdentity]
