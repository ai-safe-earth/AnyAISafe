# aisafe-audit: ignore-file
"""src/aisafe/rules/__init__.py
----------------------------
Rule base class and registry for `aisafe audit`. Selection is evaluated on every call.

A rule serves one mechanism of the policy (`aisafe.policy`); its `priority` is the
mechanism's position in the policy, a grouping order and nothing more. The number inside a
rule id (`AUD-1104`) is a legacy label that carries no severity and no order. Every finding
a rule emits says what was established (`EvidenceStatus`), what the policy decides about
it (`Decision`), the policy and rule versions it was decided under, and the exact artifact
versions it rests on.
"""

from __future__ import annotations

import importlib
from typing import Any, NamedTuple, Sequence

from aisafe.evidence.artifacts import sha256_of
from aisafe.evidence.model import (
    ArtifactRef,
    AuditContext,
    Basis,
    Confidence,
    ControlStatus,
    Decision,
    Evidence,
    EvidenceKind,
    EvidenceStatus,
    Finding,
    Flow,
    MatchKind,
    Recommendation,
    Scope,
    Severity,
    Tier,
    Unit,
    UnknownItem,
    fingerprint,
    sort_findings,
    truncate_snippet,
)
from aisafe.policy import Policy, load_policy

__all__ = [
    "ALL_RULES",
    "ALSO_CAP",
    "ALSO_ROLE",
    "MIN_PRECISION",
    "MISSING_RULE_MODULES",
    "AuditRule",
    "Candidate",
    "Recommendation",
    "SiteRef",
    "artifact_of",
    "coverage_table",
    "default_rules",
    "emit_groups",
    "experimental_rules",
    "file_text",
    "group_scope",
    "grouped_evidence",
    "hits_in",
    "is_demoted",
    "more_sites",
    "rule_by_id",
    "rules_of_mechanism",
    "run_rules",
    "select_rules",
    "unit_of",
]

# A rule measured below this precision does not fire without --experimental. `None`
# (unmeasured) is never demoted: absence of a measurement is not evidence of imprecision.
MIN_PRECISION = 0.80


class AuditRule:
    """
    One audit rule. Subclasses set the class attributes and implement `evaluate`.

    `measured_precision = None` means UNMEASURED, not perfect: an unmeasured rule
    keeps firing by default. Only a rule measured below MIN_PRECISION is demoted
    to `--experimental`. Never guess a value for it; it comes from a labelled corpus.

    `version` counts semantic changes of the rule; `changed` lists them, one line each,
    newest last, so a reader of a report knows what a rule meant when it fired.
    """

    id: str
    title: str
    version: int = 1
    changed: tuple[str, ...] = ()
    severity: Severity
    basis: Basis
    evidence_kind: EvidenceKind
    match_kind: MatchKind
    default_evidence_status: EvidenceStatus = EvidenceStatus.DETECTED_SIGNAL
    default_decision: Decision = Decision.REVIEW
    requires_ai_surface: bool = False
    measured_precision: float | None = None
    known_failure_modes: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    recommendation: Recommendation
    tier: Tier
    languages: tuple[str, ...] = ("*",)

    def __init__(self) -> None:
        # UNKNOWN items a rule raises while evaluating ("report age unknown", ...).
        # `run_rules` folds them into the run's unknown list after `evaluate`.
        self.unknown: list[UnknownItem] = []

    @classmethod
    def policy(cls) -> Policy:
        return load_policy()

    @classmethod
    def mechanism_id(cls) -> str:
        """The policy mechanism this rule serves ("M4"), or "" when the policy omits it."""
        mechanism = cls.policy().mechanism_of(cls.id)
        return mechanism.id if mechanism is not None else ""

    # `priority` is read from the policy on every access: a grouping order, never 11.
    @property
    def priority(self) -> int:
        return self.policy().order_of(self.id)

    @classmethod
    def experimental(cls) -> bool:
        """True when this rule only runs under `--experimental` (measured below threshold)."""
        return is_demoted(cls)

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        raise NotImplementedError

    def finding(
        self,
        ctx: AuditContext | None = None,
        *,
        file: str,
        line: int,
        snippet: str,
        evidence: list[Evidence] | None = None,
        scope: Scope | None = None,
        severity: Severity | None = None,
        sub: str | None = None,
        evidence_status: EvidenceStatus | None = None,
        decision: Decision | None = None,
        flow: Flow | None = None,
        encoded_objective: str | None = None,
        person_data_use: str | None = None,
        control_status: ControlStatus | None = None,
        affected_population: str | None = None,
        declared_purpose: str | None = None,
        coverage_gaps: Sequence[str] = (),
        uncertainty: str | None = None,
        report: dict | None = None,
        notes: str | None = None,
        title: str | None = None,
        match_kind: MatchKind | None = None,
        evidence_kind: EvidenceKind | None = None,
    ) -> Finding:
        """
        Build a Finding with id/title/priority/references/confidence filled from the class.

        The fingerprint is anchored on `file` + `snippet` and the display id
        (`AUD-1104/vulnerable` for a sub-finding), so extra evidence legs can be
        reordered without producing a "new" finding.

        `ctx` is optional for ad-hoc construction in tests; with it, every evidence file
        gets an `ArtifactRef` (content hash) so the finding names the exact version it
        rests on. `match_kind` / `evidence_kind` override the class defaults for one
        finding: a rule that resolves a path through the AST when `--deep python` ran and
        falls back to co-located grep otherwise reports the confidence it actually has.
        """
        relpath = file.replace("\\", "/")
        snip = truncate_snippet(snippet)
        display_id = f"{self.id}/{sub}" if sub else self.id
        if evidence is None:
            evidence = [Evidence(role="match", file=relpath, line=line, snippet=snip)]
        if scope is None:
            scope = Scope(kind="file", name=relpath)
        policy = self.policy()
        artifacts: tuple[ArtifactRef, ...] = ()
        if ctx is not None:
            artifacts = tuple(
                ref
                for ref in (
                    _artifact_ref(ctx, leg.file)
                    for leg in evidence
                    if leg.file and leg.file != "." and leg.line > 0
                )
                if ref is not None
            )
            artifacts = tuple(dict.fromkeys(artifacts))
        gitignored = ctx is not None and any(
            is_gitignored(ctx, leg.file) for leg in evidence if leg.file and leg.line > 0
        )
        return Finding(
            id=self.id,
            sub=sub,
            fingerprint=fingerprint(display_id, relpath, snip),
            title=title or self.title,
            severity=severity or self.severity,
            priority=policy.order_of(self.id),
            mechanism=self.mechanism_id(),
            policy_version=policy.version,
            rule_version=self.version,
            evidence_status=evidence_status or self.default_evidence_status,
            decision=decision or self.default_decision,
            basis=self.basis,
            confidence=Confidence(
                evidence_kind or self.evidence_kind,
                match_kind or self.match_kind,
                self.measured_precision,
            ),
            scope=scope,
            evidence=list(evidence),
            flow=flow,
            declared_purpose=declared_purpose,
            encoded_objective=None
            if encoded_objective is None
            else truncate_snippet(encoded_objective),
            person_data_use=person_data_use,
            control_status=control_status,
            affected_population=affected_population,
            artifacts=artifacts,
            references=self.references,
            recommendation=self.recommendation,
            known_failure_modes=self.known_failure_modes,
            coverage_gaps=tuple(coverage_gaps),
            uncertainty=uncertainty,
            report=report,
            notes=notes,
            gitignored=gitignored,
        )

    def absence_finding(
        self, *, unit: Unit | None, why: str, ctx: AuditContext | None = None, **kwargs: Any
    ) -> Finding:
        """A finding about something missing: file = unit root (or "."), line 0, role "absence"."""
        if unit is None:
            root, scope = ".", Scope(kind="repo", name=".")
        else:
            root = unit.root or "."
            scope = Scope(kind="unit", unit=unit.id, name=root)
        return self.finding(
            ctx,
            file=root,
            line=0,
            snippet=why,
            evidence=[Evidence(role="absence", file=root, line=0, snippet=why)],
            scope=scope,
            **kwargs,
        )


# ---------------------------------------------------------------------------
# Context helpers shared by rule modules
# ---------------------------------------------------------------------------


def file_text(ctx: AuditContext, relpath: str) -> str | None:
    """
    Decoded text of an enumerated file, cached on the context.

    Only files the walk enumerated (`ctx.files`) are readable through here: a rule
    never opens a path of its own choosing, so the walk's exclude/ignore/size rules
    hold for every byte a rule looks at. Unknown paths and unreadable files are None.
    """
    key = relpath.replace("\\", "/")
    if key in ctx.texts:
        return ctx.texts[key]
    text: str | None = None
    for record in ctx.files:
        if getattr(record, "relpath", None) == key:
            from aisafe.discovery.walk import read_text  # local: walk imports model too

            text = read_text(record.path)
            break
    ctx.texts[key] = text
    return text


def artifact_of(ctx: AuditContext, relpath: str) -> str | None:
    """sha256 of an enumerated file's bytes, cached on the context; None when unknown."""
    key = relpath.replace("\\", "/")
    if key in ctx.artifacts:
        return ctx.artifacts[key]
    digest: str | None = None
    for record in ctx.files:
        if getattr(record, "relpath", None) == key:
            digest = sha256_of(record.path)
            break
    if digest is not None:
        ctx.artifacts[key] = digest
    return digest


def is_gitignored(ctx: AuditContext, relpath: str) -> bool:
    """Whether the walk enumerated `relpath` as a gitignored file (`--include-ignored`)."""
    key = relpath.replace("\\", "/")
    return any(
        getattr(record, "relpath", None) == key and bool(getattr(record, "gitignored", False))
        for record in ctx.files
    )


def _artifact_ref(ctx: AuditContext, relpath: str) -> ArtifactRef | None:
    digest = artifact_of(ctx, relpath)
    return None if digest is None else ArtifactRef(file=relpath, sha256=digest)


def unit_of(ctx: AuditContext, relpath: str) -> Unit | None:
    """The Unit owning `relpath`, resolved through the walk's file records."""
    key = relpath.replace("\\", "/")
    unit_id = None
    for record in ctx.files:
        if getattr(record, "relpath", None) == key:
            unit_id = record.unit
            break
    if unit_id is None:
        return None
    for unit in ctx.inventory.units:
        if unit.id == unit_id:
            return unit
    return None


def hits_in(ctx: AuditContext, table: str, *, unit: str | None = None, file: str | None = None):
    """Hits from one grep table, optionally narrowed to a unit id or a relpath."""
    out = []
    for hit in ctx.hits:
        if hit.table != table:
            continue
        if unit is not None and hit.unit != unit:
            continue
        if file is not None and hit.file != file:
            continue
        out.append(hit)
    return out


# ---------------------------------------------------------------------------
# Grouping: one decision is one finding
# ---------------------------------------------------------------------------
# A rule that reports every occurrence of a repeated fact buries the document it
# feeds. So a rule with a natural grouping key emits one finding per group: the first
# site by path is the anchor and carries the fingerprint, up to ALSO_CAP further sites
# ride along as `also` evidence, and the rest are counted in the notes so the reader
# knows the list is cut rather than complete.
#
# The count is never dropped silently, and grouping never merges two different
# decisions: the key always separates what a person would fix separately.
ALSO_CAP = 8
ALSO_ROLE = "also"


class SiteRef(NamedTuple):
    """One location of a grouped finding: the anchor or an `also` entry."""

    file: str
    line: int
    snippet: str


class Candidate(NamedTuple):
    """A site plus what the finding built from it would say; the group's anchor decides."""

    site: SiteRef
    unit: Unit | None
    notes: str
    sub: str | None = None
    evidence_kind: EvidenceKind | None = None
    match_kind: MatchKind | None = None
    severity: Severity | None = None
    evidence_status: EvidenceStatus | None = None
    decision: Decision | None = None
    flow: Flow | None = None
    encoded_objective: str | None = None
    person_data_use: str | None = None
    control_status: ControlStatus | None = None
    affected_population: str | None = None
    declared_purpose: str | None = None
    coverage_gaps: tuple[str, ...] = ()
    uncertainty: str | None = None

    @property
    def order(self) -> tuple[str, int, str]:
        return (self.site.file, self.site.line, self.site.snippet)


def grouped_evidence(sites: Sequence[SiteRef]) -> tuple[list[Evidence], int]:
    """
    The anchor as `match` evidence plus up to `ALSO_CAP` further sites as `also`
    evidence, in the order given. Returns the evidence and how many sites were cut.
    """
    anchor, extra = sites[0], list(sites[1:])
    evidence = [Evidence(role="match", file=anchor.file, line=anchor.line, snippet=anchor.snippet)]
    evidence.extend(
        Evidence(role=ALSO_ROLE, file=site.file, line=site.line, snippet=site.snippet)
        for site in extra[:ALSO_CAP]
    )
    return evidence, max(0, len(extra) - ALSO_CAP)


def more_sites(notes: str, overflow: int) -> str:
    if overflow <= 0:
        return notes
    return f"{notes}; +{overflow} more site{'s' if overflow != 1 else ''}"


def group_scope(unit: Unit | None, anchor_file: str) -> Scope:
    """A grouped finding is about a unit; without one it falls back to the anchor file."""
    if unit is None:
        return Scope(kind="file", name=anchor_file)
    return Scope(kind="unit", unit=unit.id, name=unit.root or ".")


def emit_groups(rule: AuditRule, groups: dict, ctx: AuditContext | None = None) -> list[Finding]:
    """
    One finding per group. Candidates are sorted by (file, line, snippet) so the anchor,
    and with it the fingerprint, is the first site by path regardless of insertion
    order; a site seen twice for the same group is listed once. The anchor's decision,
    evidence status and chain are the group's; a group never mixes two decisions because
    the grouping key separates them.
    """
    findings: list[Finding] = []
    for candidates in groups.values():
        ordered: list[Candidate] = []
        seen: set[tuple[str, int]] = set()
        for candidate in sorted(candidates, key=lambda c: c.order):
            key = (candidate.site.file, candidate.site.line)
            if key in seen:
                continue
            seen.add(key)
            ordered.append(candidate)
        if not ordered:
            continue
        anchor = ordered[0]
        evidence, overflow = grouped_evidence([c.site for c in ordered])
        findings.append(
            rule.finding(
                ctx,
                file=anchor.site.file,
                line=anchor.site.line,
                snippet=anchor.site.snippet,
                evidence=evidence,
                scope=group_scope(anchor.unit, anchor.site.file),
                sub=anchor.sub,
                severity=anchor.severity,
                evidence_kind=anchor.evidence_kind,
                match_kind=anchor.match_kind,
                evidence_status=anchor.evidence_status,
                decision=anchor.decision,
                flow=anchor.flow,
                encoded_objective=anchor.encoded_objective,
                person_data_use=anchor.person_data_use,
                control_status=anchor.control_status,
                affected_population=anchor.affected_population,
                declared_purpose=anchor.declared_purpose,
                coverage_gaps=anchor.coverage_gaps,
                uncertainty=anchor.uncertainty,
                notes=more_sites(anchor.notes, overflow),
            )
        )
    return sorted(
        findings,
        key=lambda f: (f.evidence[0].file, f.evidence[0].line, f.sub or "", f.notes or ""),
    )


# Precision gating -- evaluated on every call, never snapshotted at import, so a
# `measured_precision` set after this module loads gates the right rules.


def is_demoted(rule: type[AuditRule]) -> bool:
    """Measured below MIN_PRECISION. `None` is unmeasured and is never demoted."""
    precision = rule.measured_precision
    return precision is not None and precision < MIN_PRECISION


def rule_by_id(rule_id: str) -> type[AuditRule] | None:
    for rule in ALL_RULES:
        if rule.id == rule_id:
            return rule
    return None


def rules_of_mechanism(mechanism_id: str) -> list[type[AuditRule]]:
    """The registered rules the policy lists under a mechanism, in registry order."""
    policy = load_policy()
    mechanism = policy.mechanism_by_id(mechanism_id)
    if mechanism is None:
        return []
    return [rule for rule in ALL_RULES if rule.id in mechanism.rules]


def default_rules() -> list[type[AuditRule]]:
    """Rules that run without --experimental."""
    return [r for r in ALL_RULES if not is_demoted(r)]


def experimental_rules() -> list[type[AuditRule]]:
    """Rules measured below MIN_PRECISION, which need --experimental to run."""
    return [r for r in ALL_RULES if is_demoted(r)]


def select_rules(
    ids: Sequence[str] | None = None, experimental: bool = False
) -> tuple[list[type[AuditRule]], list[str]]:
    """
    The rule set a run should use, plus notes for stderr.

    Naming a demoted rule in `ids` runs it anyway, with a note. Unknown ids are
    noted and skipped, never fatal.
    """
    notes: list[str] = []
    if ids is None:
        return (list(ALL_RULES) if experimental else default_rules()), notes
    chosen: list[type[AuditRule]] = []
    for rule_id in ids:
        rule = rule_by_id(rule_id)
        if rule is None:
            notes.append(f"unknown rule id {rule_id}")
            continue
        if is_demoted(rule) and not experimental:
            notes.append(
                f"rule {rule_id} is below MIN_PRECISION and runs only because it was named explicitly"
            )
        if rule not in chosen:
            chosen.append(rule)
    return chosen, notes


def run_rules(
    rules: Sequence[type[AuditRule]], ctx: AuditContext
) -> tuple[list[Finding], list[UnknownItem]]:
    """
    Instantiate and evaluate each rule. A rule exception becomes an UnknownItem,
    never a crash. Rules with `requires_ai_surface` are skipped, silently by
    design, when no unit in the inventory has an AI surface.
    """
    findings: list[Finding] = []
    unknown: list[UnknownItem] = []
    ai_surface = any(unit.ai_surface for unit in ctx.inventory.units)
    for rule in rules:
        if rule.requires_ai_surface and not ai_surface:
            continue
        rule_id = getattr(rule, "id", rule.__name__)
        try:
            instance = rule()
            produced = instance.evaluate(ctx)
            # Legs a rule appends after construction (surfaces, controls) can sit under a
            # gitignored directory too; the flag is settled once every leg is known.
            for finding in produced:
                finding.gitignored = finding.gitignored or any(
                    is_gitignored(ctx, leg.file)
                    for leg in finding.evidence
                    if leg.file and leg.line > 0
                )
            findings.extend(produced)
            unknown.extend(instance.unknown)
        except Exception as exc:  # broad on purpose: one bad rule must not sink the run
            unknown.append(
                UnknownItem(
                    category="runtime",
                    what=f"rule {rule_id}",
                    why=f"{type(exc).__name__}: {exc}",
                    rule_ids=(rule_id,),
                )
            )
    return sort_findings(findings), unknown


# ---------------------------------------------------------------------------
# Coverage: what each mechanism's rules could assess
# ---------------------------------------------------------------------------


def _surfaces_for(ctx: AuditContext | None) -> int:
    """How many units carry an AI surface; the denominator a coverage row names."""
    if ctx is None:
        return 0
    return sum(1 for unit in ctx.inventory.units if getattr(unit, "ai_surface", False))


def coverage_table(
    policy: Policy,
    rules_ran: Sequence[type[AuditRule]],
    findings: Sequence[Finding],
    ctx: AuditContext | None = None,
) -> list[dict[str, Any]]:
    """
    One row per mechanism in policy order: which of its rules ran, how many AI surfaces
    were there to read, how many findings landed on it, and the decision the report
    takes for the mechanism as a whole. `not_assessed` when none of its rules ran or
    there was no surface; `no_violation_identified_in_scope` when its rules ran on a
    surface and found nothing; otherwise the strongest decision among its findings.
    Never a score; the scope is in the row.
    """
    ran_ids = {rule.id for rule in rules_ran}
    surfaces = _surfaces_for(ctx)
    rows: list[dict[str, Any]] = []
    for mechanism in policy.mechanisms:
        mine = [f for f in findings if f.mechanism == mechanism.id]
        ran = [rule_id for rule_id in mechanism.rules if rule_id in ran_ids]
        if not ran or surfaces == 0:
            decision = Decision.NOT_ASSESSED
        elif not mine:
            decision = Decision.NO_VIOLATION
        else:
            decision = max((f.decision for f in mine), key=lambda d: Decision(d).rank())
        rows.append(
            {
                "id": mechanism.id,
                "name": mechanism.name,
                "rules": list(mechanism.rules),
                "ran": sorted(ran),
                "surfaces": surfaces,
                "findings": len(mine),
                "decision": Decision(decision).value,
            }
        )
    return rows


# Registry. Imported at the bottom to avoid a cycle: rule modules import `AuditRule`
# from this package. A module that does not exist yet lands in MISSING_RULE_MODULES and
# the registry stays partial; a module that exists but fails to import raises, because
# a silently vanished rule set is not partial, it is wrong.

_RULE_MODULES = ("profiling", "influence", "identity", "controls", "review")

ALL_RULES: list[type[AuditRule]] = []
MISSING_RULE_MODULES: list[str] = []

for _name in _RULE_MODULES:
    _qualname = f"{__name__}.{_name}"
    try:
        _module = importlib.import_module(_qualname)
    except ModuleNotFoundError as _exc:
        if _exc.name != _qualname:
            raise
        MISSING_RULE_MODULES.append(_name)
        continue
    ALL_RULES.extend(_module.RULES)
