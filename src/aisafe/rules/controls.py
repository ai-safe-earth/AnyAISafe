# aisafe-audit: ignore-file
"""src/aisafe/rules/controls.py
----------------------------
The controls owed on a unit's response path. AUD-1106 (mechanism M8) grades the status of
a manipulation control in every unit that takes input, calls a model and carries an
influence signal: none, claimed, wired, exercised, demonstrated. A symbol never silences
the rule; it changes the sub-finding, and the finding always says that no control, at any
status, resolves the objective the other rules report on the unit. AUD-1108 (mechanism M5)
reports the absence of a crisis path where the prompts cast the model as a confidant, a
partner, a therapist or an in-character persona; a fresh evaluation report of the
`crisis_disclosure` family turns the static absence into observed behaviour, either way:
every scenario passing keeps the finding at LOW with the control demonstrated (a model
update can change that), a failing scenario makes it a violation. Fiction or in-character
framing never exempts; a failing report never silences.

The grep tier (person signals), the AST tier (prompt literals, model calls, reply
returns) and the evaluation reports in the tree feed both rules; every helper tolerates
`ctx.pyfacts is None` and `ctx.evaluation == []`.
"""

from __future__ import annotations

import re

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
    Hit,
    MatchKind,
    Recommendation,
    ReportRecord,
    Severity,
    Tier,
    Unit,
)
from aisafe.rules import AuditRule, artifact_of, hits_in
from aisafe.rules._common import (
    INFLUENCE_KINDS,
    LEGAL_CAVEAT,
    Facts,
    Signal,
    declared_purpose_for,
    evaluation_demonstrates,
    facts,
    fiction_context,
    has_ai_surface,
    is_code_file,
    is_mention,
    line_at,
    request_cue_nearby,
    surface_legs,
    unit_control_status,
    unit_has,
)

__all__ = ["RULES", "ManipulationControlStatus", "NoCrisisPath", "OBJECTIVE_RULES"]

# Which rule reports the objective each influence kind stands for. The AUD-1106 finding
# names them so a reader knows what the control, at any status, does not resolve.
OBJECTIVE_RULES: dict[str, str] = {
    "engagement": "AUD-1104",
    "monetisation": "AUD-1104",
    "persona": "AUD-1105",
    "attachment": "AUD-1109",
    "steering": "AUD-1110",
    "inference": "AUD-1102",
}
_CONTROL_FAMILIES = ("manipulation_elicitation", "goodbye_pressure")
_CRISIS_FAMILY = "crisis_disclosure"
_CONTROL_ROLE = "control"
_SITE_CAP = 3

_STATUS_TEXT: dict[ControlStatus, str] = {
    ControlStatus.NONE: (
        "no manipulation control symbol (a rails framework, a hub validator, an output "
        "scanner, a moderation call, a reply-screening function) appears in its code, config "
        "or tests"
    ),
    ControlStatus.CLAIMED: (
        "a control is named in docs, config or an import line and nothing shows it on the "
        "response path"
    ),
    ControlStatus.WIRED: (
        "a control is called in the file that makes the model call or returns the reply, and "
        "no test references it and no fresh evaluation demonstrates it"
    ),
    ControlStatus.EXERCISED: (
        "a control is wired on the response path and a test references it, and no fresh "
        "evaluation demonstrates it"
    ),
}
_STATUS_SEVERITY: dict[ControlStatus, Severity] = {
    ControlStatus.NONE: Severity.MEDIUM,
    ControlStatus.CLAIMED: Severity.MEDIUM,
    ControlStatus.WIRED: Severity.LOW,
    ControlStatus.EXERCISED: Severity.LOW,
}

# A line that starts as a comment says what someone meant to do, not what the code does.
_COMMENT_START_RE = re.compile(r"^\s*(?:#|//|/\*|\*|<!--|--\s)")


def _grep_gap(ctx: AuditContext) -> tuple[str, ...]:
    if ctx.pyfacts is None:
        return (
            "grep tier only: the file that makes the model call was read by same-file grep, "
            "not through the syntax tree",
        )
    return ()


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


# ---------------------------------------------------------------------------
# AUD-1106  Manipulation control status on the response path
# ---------------------------------------------------------------------------


class ManipulationControlStatus(AuditRule):
    id = "AUD-1106"
    title = "Manipulation control status on the response path"
    version = 2
    changed = (
        "v2: serves mechanism M8; a control symbol no longer silences the rule, it sets the "
        "control status and the sub-finding (/none, /claimed, /wired, /exercised)",
        "v2: a fresh evaluation report passing every manipulation_elicitation or "
        "goodbye_pressure case is a demonstrated control and emits no finding",
        "v2: the gating signals are the influence kinds (engagement, persona, attachment, "
        "steering, inference, monetisation); a profile alone no longer gates the rule, and "
        "mentions and requested analyses are excluded",
        "v2: the control symbols are generic (rails, hub validators, output scanners, "
        "moderation, reply-screening functions); the retired runtime package's symbols are gone",
        "v2: the finding names the rules whose objective the control does not resolve",
    )
    severity = Severity.MEDIUM
    basis = Basis.ABSENCE
    evidence_kind = EvidenceKind.ABSENCE
    match_kind = MatchKind.STRUCTURED
    default_evidence_status = EvidenceStatus.DETECTED_SIGNAL
    default_decision = Decision.REVIEW
    requires_ai_surface = True
    tier = Tier.T2
    references = ("EU:Art.5(1)(a)", "EU:Art.15", "LLM09", "NIST:MEASURE-2.7", "NIST:MANAGE-2.4")
    SUBS = (
        (
            "none",
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "no control symbol in a unit that takes input, calls a model and carries an "
            "influence signal",
        ),
        (
            "claimed",
            Severity.MEDIUM,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "a control is named in docs, config or an import and nothing shows it on the "
            "response path",
        ),
        (
            "wired",
            Severity.LOW,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "the control is called in the file that makes the model call or returns the "
            "reply; not exercised by a test, not demonstrated by an evaluation",
        ),
        (
            "exercised",
            Severity.LOW,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "a test references the wired control; no fresh evaluation demonstrates it",
        ),
    )
    known_failure_modes = (
        "a control outside the tree (a gateway, vendor moderation) is invisible, so the unit "
        "reads as /none",
        "wired means a call-shaped use of the symbol in a file that also makes the model call "
        "or returns the reply; a control invoked from a helper module the call site imports "
        "reads as claimed",
        "exercised means a test file references the symbol; it does not say the test asserts "
        "anything about manipulation",
        "demonstrated rests on an evaluation report found in the tree, read for its age and "
        "its per-family counts; the audit does not run the scenarios itself",
        "fires only in a unit that also carries an influence signal; a neutral assistant "
        "without one is not reported here, whatever it lacks",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Remove the objective or instruction the other rules report first; then put a "
            "control on the output stage in the code that returns the reply, cover it with a "
            "test, and evaluate the live replies on a schedule. No control at any status "
            "resolves the objective."
        ),
        alternatives=(
            "rewrite the objective as task completion and delete the persona, attachment or "
            "steering instruction; the control then has less to catch",
            "NeMo Guardrails output rails, or a Guardrails Hub validator, called where the "
            "reply is returned",
            "LLM Guard output scanners or a moderation endpoint on the reply, with a test that "
            "exercises the path",
            "aisafe evaluate --families manipulation_elicitation,goodbye_pressure against a "
            "staging endpoint, with authorisation, on a schedule inside the policy's window",
        ),
        removes=("objective", "intervention"),
    )

    def _influence_signals(self, ctx: AuditContext, out: Facts, unit: Unit) -> list[Signal]:
        signals: list[Signal] = []
        for signal in out.in_unit(unit.id, *INFLUENCE_KINDS):
            if is_mention(ctx, signal):
                continue
            if signal.kind == "inference" and request_cue_nearby(ctx, signal):
                continue
            signals.append(signal)
        return signals

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        if not has_ai_surface(ctx):
            return []
        out = facts(ctx)
        max_age = self.policy().evaluation_max_age_days
        findings: list[Finding] = []
        for unit in ctx.inventory.units:
            if not getattr(unit, "ai_surface", False):
                continue
            if not (unit_has(ctx, unit.id, "ingress") and unit_has(ctx, unit.id, "llm_calls")):
                continue
            signals = self._influence_signals(ctx, out, unit)
            if not signals:
                continue
            status, controls, _report = unit_control_status(
                ctx,
                out,
                unit,
                control_kind="manipulation_control",
                demonstrated_by=_CONTROL_FAMILIES,
                max_age_days=max_age,
            )
            if status is ControlStatus.DEMONSTRATED:
                # A fresh evaluation passed every case of a control family: the coverage
                # table records the mechanism as assessed; nothing is owed here.
                continue
            kinds = sorted({s.kind for s in signals})
            rules = sorted({OBJECTIVE_RULES[k] for k in kinds if k in OBJECTIVE_RULES})
            why = (
                f"unit {unit.id} takes user input, calls a model and carries influence signals "
                f"({', '.join(kinds)}); {_STATUS_TEXT[status]}"
            )
            notes = (
                f"{why}. This control, at any status, does not resolve the objective reported "
                f"by {', '.join(rules)}. {LEGAL_CAVEAT}"
            )
            finding = self.absence_finding(
                unit=unit,
                why=why,
                ctx=ctx,
                sub=status.value,
                severity=_STATUS_SEVERITY[status],
                evidence_status=EvidenceStatus.DETECTED_SIGNAL,
                decision=Decision.REVIEW,
                control_status=status,
                declared_purpose=declared_purpose_for(ctx, unit.id, None),
                coverage_gaps=_grep_gap(ctx)
                + (
                    "a control outside the tree (a gateway, vendor moderation) is not visible "
                    "to the audit",
                ),
                uncertainty=(
                    "a control may run in a gateway or a vendor layer the audit cannot read; "
                    "the finding says what status was shown in this tree"
                ),
                notes=notes,
            )
            seen = {(e.file, e.line) for e in finding.evidence}
            for signal in sorted(controls, key=lambda s: (s.file, s.line))[:_SITE_CAP]:
                if (signal.file, signal.line) in seen:
                    continue
                seen.add((signal.file, signal.line))
                finding.evidence.append(
                    Evidence(
                        role=_CONTROL_ROLE,
                        file=signal.file,
                        line=signal.line,
                        snippet=line_at(ctx, signal.file, signal.line, signal.symbol),
                    )
                )
            for leg in surface_legs(ctx, signals, cap=_SITE_CAP):
                if (leg.file, leg.line) not in seen:
                    seen.add((leg.file, leg.line))
                    finding.evidence.append(leg)
            _bind_artifacts(ctx, finding)
            findings.append(finding)
        return findings


# ---------------------------------------------------------------------------
# AUD-1108  No crisis path where a person confides in the AI
# ---------------------------------------------------------------------------


def _crisis_sites(ctx: AuditContext, out: Facts) -> dict[str | None, list[Hit]]:
    """
    Per unit, the hits that stand for a crisis path: a helpline or a crisis-protocol name
    anywhere in code, config or prompts, or a self-harm word in code outside prompt text
    (a keyword list, a `detect_self_harm` function). Liberal on purpose, because a control
    the rule cannot see raises a finding, with one exception: a self-harm word in PROMPT
    text alone is not a path. "Stay in character even if the user talks about suicide"
    names the crisis in order to dismiss it; a prompt that answers a crisis names
    somewhere to go.

    Comment lines are skipped in code only, and only outside a prompt literal: in a prompt
    file or a prompt string, `*` and `#` open a Markdown bullet or heading.
    """
    sites: dict[str | None, list[Hit]] = {}
    for table in ("person_signal", "person_signal_candidate"):
        for hit in hits_in(ctx, table):
            if vocab.kind_of(hit.key) != "crisis_control":
                continue
            in_code = is_code_file(hit.file)
            literal = out.literal_at(hit.file, hit.line)
            in_prompt = not in_code or table == "person_signal" or literal is not None
            if in_code and literal is None:
                if _COMMENT_START_RE.match(line_at(ctx, hit.file, hit.line, hit.snippet)):
                    continue
            if in_prompt and hit.key == "crisis_control:self_harm":
                continue
            sites.setdefault(hit.unit, []).append(hit)
    return sites


def _report_date(record: ReportRecord | None) -> str:
    raw = getattr(record, "generated_at", None)
    if isinstance(raw, str) and raw:
        return raw[:10]
    return "an unknown date"


def _vulnerable_word(ctx: AuditContext, signal: Signal) -> str:
    """The vulnerable-group word on the signal's line (the whole line is the fallback)."""
    text = line_at(ctx, signal.file, signal.line, signal.symbol)
    match = vocab.VULNERABLE_GROUP.search(text)
    return match.group(0) if match else signal.symbol


# The confidant row that keeps the model in a role whatever the person says: framing that
# the policy lists among the things that never exempt.
_IN_CHARACTER_KEY = "confidant:in_character"


class NoCrisisPath(AuditRule):
    id = "AUD-1108"
    title = "No crisis path where a person confides in the AI"
    version = 2
    changed = (
        "v2: serves mechanism M5; the static absence decides requires_contextual_review and "
        "carries an evidence status",
        "v2: a fresh evaluation report that sent crisis_disclosure is read: every case passing "
        "keeps the finding at LOW with the control demonstrated and observed behaviour; a "
        "failing case makes it observed behaviour that violates the policy, severity unchanged",
        "v2: a crisis path named in the code does not close the finding when a fresh "
        "evaluation shows a crisis disclosure answered without a referral",
        "v2: fiction and in-character framing are recorded and never exempt; a failing report "
        "never silences the finding",
    )
    severity = Severity.HIGH
    basis = Basis.ABSENCE
    evidence_kind = EvidenceKind.ABSENCE
    match_kind = MatchKind.STRUCTURED
    default_evidence_status = EvidenceStatus.SUPPORTED_MECHANISM
    default_decision = Decision.REVIEW
    requires_ai_surface = True
    tier = Tier.T2
    references = (
        "EU:Art.5(1)(b)",
        "EU:Art.9",
        "US-CA:SB243",
        "US-CA:SB1119",
        "US-NY:GBL-Art.47",
        "NIST:MAP-5.1",
        "NIST:MEASURE-2.6",
        "NIST:MANAGE-1.3",
    )
    SUBS = (
        (
            None,
            Severity.HIGH,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
            "a companion, partner or in-character role in the prompts and no crisis pattern, "
            "helpline or referral in the unit",
        ),
        (
            "mental-health",
            Severity.CRITICAL,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
            "a therapist or emotional-support role and no crisis path",
        ),
        (
            "vulnerable",
            Severity.CRITICAL,
            EvidenceStatus.SUPPORTED_MECHANISM,
            Decision.REVIEW,
            "a confidant role next to a vulnerable-group word and no crisis path",
        ),
        (
            None,
            Severity.LOW,
            EvidenceStatus.OBSERVED_BEHAVIOR,
            Decision.REVIEW,
            "any sub: no crisis path in the code, but a fresh evaluation shows a referral in "
            "every crisis scenario (control demonstrated; a model update can change that)",
        ),
        (
            None,
            Severity.HIGH,
            EvidenceStatus.OBSERVED_BEHAVIOR,
            Decision.VIOLATES,
            "any sub, severity unchanged: a fresh evaluation shows a crisis disclosure answered "
            "without a referral",
        ),
    )
    known_failure_modes = (
        "a helpline or crisis-protocol word anywhere in the unit counts as a path: a helpline "
        "printed on a landing page, or a prompt that says not to mention hotlines, closes the "
        "static finding though nothing checks the person's message; a self-harm word in prompt "
        "text alone does not count, so a prompt that answers a crisis without naming any help "
        "is reported",
        "the role is read from prompt material only; a companion whose role lives in a database "
        "row, a character card loaded at runtime or a JS template literal outside a prompt "
        "assignment is not seen as one",
        "a crisis control outside the tree (a moderation gateway, a vendor safety layer) is "
        "invisible",
        "fires only where the prompts cast the model as a therapist, partner, friend or "
        "in-character persona; a general assistant a person confides in anyway is not reported",
        "an evaluation report speaks for the endpoint it was run against, not for one unit; in "
        "a tree with several units the report is attached to every unit that owes a crisis path",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Check the person's message for suicide and self-harm signals before the model "
            "answers, reply with a fixed referral to crisis services for the person's region, "
            "publish the protocol, and evaluate the live reply on a schedule."
        ),
        alternatives=(
            "a crisis check on the input path that returns a fixed helpline reply instead of the "
            "model's (a keyword list for the obvious cases, a classifier for the rest)",
            "a moderation endpoint with a self-harm category (OpenAI moderation, Llama Guard S11) "
            "on the person's message, routing a hit to the referral reply",
            "a published protocol for suicidal ideation and self-harm with region-specific "
            "helplines and an escalation owner, recorded in the review record",
            "aisafe evaluate --families crisis_disclosure against a staging endpoint, with "
            "authorisation, which reports whether the last reply carries a referral",
        ),
        removes=("intervention",),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        if not has_ai_surface(ctx):
            return []
        out = facts(ctx)
        verdict, record = evaluation_demonstrates(
            ctx, _CRISIS_FAMILY, self.policy().evaluation_max_age_days
        )
        covered = _crisis_sites(ctx, out)
        findings: list[Finding] = []
        for unit in ctx.inventory.units:
            if not getattr(unit, "ai_surface", False):
                continue
            if not (unit_has(ctx, unit.id, "ingress") and unit_has(ctx, unit.id, "llm_calls")):
                continue
            statically_covered = unit.id in covered
            if statically_covered and verdict is not False:
                continue
            roles = [
                s for s in out.in_unit(unit.id, "confidant", "persona") if not is_mention(ctx, s)
            ]
            if not roles:
                continue
            # One leg per line: two role rows on one line are one place.
            seen_lines: set[tuple[str, int]] = set()
            unique_roles: list[Signal] = []
            for signal in sorted(roles, key=lambda s: (s.file, s.line)):
                if (signal.file, signal.line) in seen_lines:
                    continue
                seen_lines.add((signal.file, signal.line))
                unique_roles.append(signal)
            roles = unique_roles
            mental = any(s.key in vocab.CONFIDANT_MENTAL_HEALTH_KEYS for s in roles)
            # A vulnerable group escalates only in a file that sets the role, as AUD-1104's
            # does: "minor typos" in a review prompt elsewhere in the unit is not a group.
            role_files = {s.file for s in roles}
            vulnerable = [
                s
                for s in out.in_unit(unit.id, "vulnerable")
                if s.file in role_files and not is_mention(ctx, s)
            ]
            sub = "mental-health" if mental else ("vulnerable" if vulnerable else None)
            severity = Severity.CRITICAL if sub else Severity.HIGH
            what = (
                "a therapist or emotional-support role"
                if mental
                else "a companion, partner or in-character role"
            )
            if statically_covered:
                sites = sorted(covered[unit.id], key=lambda h: (h.file, h.line))[:_SITE_CAP]
                where = ", ".join(f"{h.file}:{h.line}" for h in sites)
                why = (
                    f"unit {unit.id} takes user input and calls a model, its prompts cast the "
                    f"model in {what}, a crisis pattern, helpline or referral is named in it "
                    f"({where}), and the evaluation of {_report_date(record)} shows a crisis "
                    "disclosure answered without a referral"
                )
            else:
                why = (
                    f"unit {unit.id} takes user input and calls a model, its prompts cast the "
                    f"model in {what}, and no crisis pattern, helpline or referral appears in its "
                    "code, config or prompts"
                )
            notes = why
            population = _vulnerable_word(ctx, vulnerable[0]) if vulnerable else None
            if population:
                notes += f"; a vulnerable group is named in the same unit ({population})"
            framed = any(s.key == _IN_CHARACTER_KEY for s in roles) or any(
                fiction_context(ctx, out, s.file, s.line) for s in roles
            )
            if framed:
                notes += "; fictional or in-character framing recorded, which is not an exemption"
            evidence_status = EvidenceStatus.SUPPORTED_MECHANISM
            decision = Decision.REVIEW
            control_status: ControlStatus | None = None
            report: dict | None = None
            if verdict is True and record is not None:
                evidence_status = EvidenceStatus.OBSERVED_BEHAVIOR
                control_status = ControlStatus.DEMONSTRATED
                severity = Severity.LOW
                report = record.finding_report()
                notes += (
                    f"; the code shows no crisis path; the evaluation of {_report_date(record)} "
                    "shows a referral in every crisis scenario; a model update can change that"
                )
            elif verdict is False and record is not None:
                evidence_status = EvidenceStatus.OBSERVED_BEHAVIOR
                decision = Decision.VIOLATES
                report = record.finding_report()
                if statically_covered:
                    control_status = ControlStatus.CLAIMED
                else:
                    notes += (
                        f"; the evaluation of {_report_date(record)} shows a crisis disclosure "
                        "answered without a referral"
                    )
            finding = self.absence_finding(
                unit=unit,
                why=why,
                ctx=ctx,
                sub=sub,
                severity=severity,
                evidence_status=evidence_status,
                decision=decision,
                control_status=control_status,
                affected_population=population,
                declared_purpose=declared_purpose_for(ctx, unit.id, None),
                coverage_gaps=_grep_gap(ctx)
                + (
                    "a crisis control outside the tree (a moderation gateway, a vendor safety "
                    "layer) is not visible to the audit",
                ),
                uncertainty=(
                    "a crisis path may run in a gateway or a vendor layer the audit cannot read; "
                    "an evaluation report speaks for the endpoint it was run against on that date"
                ),
                report=report,
                notes=f"{notes}. {LEGAL_CAVEAT}",
            )
            # Where the role is set, so a reader sees why the unit counts as a confidant.
            legs = surface_legs(ctx, roles, cap=_SITE_CAP)
            present = {(e.file, e.line) for e in finding.evidence} | {
                (e.file, e.line) for e in legs
            }
            finding.evidence.extend(legs)
            for signal in vulnerable[:1]:
                if (signal.file, signal.line) not in present:
                    finding.evidence.append(
                        Evidence(
                            role="surface",
                            file=signal.file,
                            line=signal.line,
                            snippet=line_at(ctx, signal.file, signal.line, signal.symbol),
                        )
                    )
            if statically_covered:
                for hit in sorted(covered[unit.id], key=lambda h: (h.file, h.line))[:_SITE_CAP]:
                    if (hit.file, hit.line) in present:
                        continue
                    present.add((hit.file, hit.line))
                    finding.evidence.append(
                        Evidence(
                            role=_CONTROL_ROLE,
                            file=hit.file,
                            line=hit.line,
                            snippet=line_at(ctx, hit.file, hit.line, hit.snippet),
                        )
                    )
            _bind_artifacts(ctx, finding)
            findings.append(finding)
        return findings


RULES = [ManipulationControlStatus, NoCrisisPath]
