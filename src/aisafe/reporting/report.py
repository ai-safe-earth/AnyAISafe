"""src/aisafe/reporting/report.py
------------------------------
Summary block, rule catalogue, exit-code rule and the renderers (json, sarif, markdown,
terminal; the html page lives in `html.py`) for `aisafe audit`. ASCII only, key order
fixed, nothing re-derived from raw files: every snippet arrives already redacted inside a
`Finding`.

Honesty rules carried here:

- The disclaimer is the first thing every format says, and it names the policy version
  the decisions were taken under.
- Every finding prints what was established (`evidence_status`) and what the policy says
  about it (`decision`) on one line, next to each other and never folded into one score.
- A reconstructed chain is printed link by link with how each link was established. A
  chain of co-located links is called lexical co-occurrence, never a verified flow.
- `[UNMEASURED]` sits next to every finding whose rule has no precision figure.
- A finding derived from an evaluation report on disk renders `[REPORTED <age>d, <source>]`
  so a stale file is never read as fresh evidence.
- Findings below `--fail-on` are still findings: the summary line always says how many
  were not counted toward the exit code, and zero findings still print the Mechanisms
  table and the UNKNOWN block.
- `--quiet` drops per-finding detail but keeps the severity, evidence and decision lines
  and the Mechanisms table, so a CI log still says what the count rests on.
- The debug self-check (`check_templates`) runs over this module's own fixed strings and
  the html renderer's, never over target text, so a comment in the audited repo cannot
  trip it.

Rendering economy: the alternatives, references and known-failure-mode blocks belong to
the rule, not the finding, so markdown and terminal print them in full at the first
finding of each rule id and replace them with a one-line reference on every later finding
of that rule (the markdown reference is an intra-document link). Everything else (scope,
status, evidence, chain, purpose, fix, gaps, uncertainty, note, accepted reason) stays per
finding. A later finding whose block differs from the first one's prints that block in
full again; a reference never hides a difference.
"""

from __future__ import annotations

import json
import re
import textwrap
from typing import Any, Iterable, Sequence

from aisafe import __version__
from aisafe.evidence.model import (
    DISCLAIMER,
    DISCLAIMER_TEMPLATE,
    FLOW_ESTABLISHED_BY,
    MODES,
    SCAN_REPORT_LABEL,
    SCHEMA_VERSION,
    SEVERITY_ORDER,
    AuditContext,
    Decision,
    Evidence,
    EvidenceStatus,
    Finding,
    Inventory,
    Report,
    ReportRecord,
    Severity,
    UnknownCategory,
    UnknownItem,
    disclaimer,
    sort_findings,
)
from aisafe.policy import Policy, load_policy
from aisafe.review.baseline import STATUS_RE_REVIEW, STATUS_UNCHANGED, BaselineDiff
from aisafe.rules import ALL_RULES, AuditRule, coverage_table, is_demoted

__all__ = [
    "BANNED_PHRASES",
    "DISTRIBUTION",
    "EVALUATION_KINDS",
    "FAIL_ON_CHOICES",
    "FORMATS",
    "SARIF_LEVEL",
    "TOOL_NAME",
    "WIDTH",
    "all_templates",
    "build_report",
    "catalogue",
    "label_line",
    "report_mode",
    "check_templates",
    "compute_exit_code",
    "render",
    "summarise",
    "to_json",
    "to_markdown",
    "to_sarif",
    "to_terminal",
    "tool_version",
]

DISTRIBUTION = "aisafe"
TOOL_NAME = "aisafe-audit"
FORMATS: tuple[str, ...] = ("terminal", "json", "sarif", "markdown", "html")
FAIL_ON_CHOICES: tuple[str, ...] = ("critical", "high", "medium", "low", "info", "never")
WIDTH = 100

# The on-disk report kinds the audit reads as evidence: `aisafe evaluate` and its
# predecessor `aisafe probe`.
EVALUATION_KINDS: tuple[str, ...] = ("evaluation", "probe")

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_FINGERPRINT_KEY = "aisgFingerprint/v1"

SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# The compliance-language ban list, lowercase. Assembled from fragments so this module
# never carries one of the phrases as a contiguous literal.
BANNED_PHRASES: tuple[str, ...] = tuple(
    " ".join(words)
    for words in (
        ("is", "compliant"),
        ("compliance", "verified"),
        ("certi" + "fied",),
        ("meets", "the", "requirements"),
        ("fully", "compliant"),
        ("passes", "the", "eu"),
        ("nist", "compliant"),
        # The bare word: "GDPR compliant" and "non-compliant" are verdicts too.
        ("compliant",),
    )
)

# ---------------------------------------------------------------------------
# Templates: every fixed string a renderer emits. `check_templates` scans these and
# nothing else.
# ---------------------------------------------------------------------------

_T_TITLE = "aisafe audit"
_T_MD_H1 = "# aisafe audit"
_T_LABEL_LINE = "{label} | mode: {mode}"
_T_SUMMARY = (
    "{n} finding{s} ({m} below --fail-on {level}, not counted in exit code); {k} unknown item{ks}"
)
_T_SEVERITY_LINE = "severity: {items}"
_T_EVIDENCE_LINE = "evidence: {items}"
_T_DECISIONS_LINE = "decisions: {items}"
_T_COUNT_ITEM = "{key} {n}"
_T_UNMEASURED = "[UNMEASURED]"
_T_MEASURED = "[MEASURED p={p}]"
_T_REPORTED = "[REPORTED {age}d, {source}]"
_T_REPORTED_UNKNOWN = "[REPORTED age unknown]"
_T_GITIGNORED = "(gitignored)"
_T_BASELINE_STATUS = "[baseline: {status}]"
_T_NONE = "(none)"
_T_NOT_INCLUDED = "(not included)"
_T_FINDINGS = "Findings"
_T_MECHANISMS = "Mechanisms"
_T_NOT_ATTRIBUTED = "Not attributed"
_T_UNKNOWN = "UNKNOWN"
_T_INVENTORY = "Inventory"
_T_MECH_HEAD = "{id} {name}"
_T_MECH_STATUS = (
    "rules {rules} | ran {ran} | surfaces {surfaces} | findings {findings} | decision {decision}"
)
_T_MECH_TABLE_HEADER = "| id | name | rules | ran | surfaces | findings | decision |"
_T_TABLE_RULE_7 = "|---|---|---|---|---|---|---|"
_T_SCOPE = "scope: {kind} {name}"
_T_STATUS = "status: {status} | decision: {decision}"
_T_STATUS_CONTROL = "status: {status} | decision: {decision} | control: {control}"
_T_REVIEW_DECISION = "review decision: {decision} -- {justification}"
_T_EVIDENCE = "[{role}] {file}:{line}: {snippet}"
_T_CHAIN = "chain: {links} [{status}]"
_T_CHAIN_NONE = "chain: none drawn [no trace for {pattern}: {missing}]"
_T_CHAIN_LINK = "{kind} ({by})"
_T_CHAIN_ARROW = " -> "
_T_CHAIN_LEXICAL = "lexical co-occurrence only"
_STATUS_ORDER = FLOW_ESTABLISHED_BY
# The trace against the finding's policy pattern: complete only when every link the pattern
# requires is present and supported; a partial trace names each required link it lacks.
_T_TRACE_COMPLETE = "trace complete for {pattern}"
_T_TRACE_PARTIAL = "partial trace for {pattern}: {missing}"
_T_TRACE_LEXICAL = "lexical co-occurrence only; no trace for {pattern}: {missing}"
_T_TRACE_MISSING = "{kind} not established"
_T_TRACE_UNSUPPORTED = "{kind} is {by}"
_T_LINKS_SUPPORTED = "links supported; no trace is defined for this rule"
_T_LINKS_PARTIAL = "a link is not supported; no trace is defined for this rule"
_T_PURPOSE = "purpose: declared: {declared} | encoded: {encoded}"
_T_POPULATION = "population: {text}"
_T_FIX = "fix ({tier}, removes {removes}): {summary}"
_T_FIX_PLAIN = "fix ({tier}): {summary}"
_T_ALTERNATIVES = "alternatives: {items}"
_T_REFERENCES = "references: {items}"
_T_FAILURE_MODES = "known failure modes: {items}"
_T_LABEL_ALTERNATIVES = "alternatives"
_T_LABEL_REFERENCES = "references"
_T_LABEL_FAILURE_MODES = "known failure modes"
_T_SEE_FIRST = "{items}: see the first {ref} above"
_T_MD_ANCHOR = '<a id="{anchor}"></a>'
_T_MD_LINK = "[{text}](#{anchor})"
_T_GAPS = "gaps: {items}"
_T_UNCERTAINTY = "uncertainty: {text}"
_T_NOTE = "note: {text}"
_T_ACCEPTED_REASON = "accepted: {reason}"
_T_ACCEPTED_RE_REVIEW = "accepted: {reason} (accepted under policy {old}; re-review under {new})"
_T_RE_REVIEW = (
    "re-review: the baseline lists this fingerprint without a reason and was not written "
    "under policy {new}"
)
_T_UNKNOWN_ITEM = "[{category}] {what}: {why}"
_T_RESOLVE = "resolve: {text}"
_T_FILE = "file: {file}"
_T_RULES = "rules: {items}"
_T_YES = "yes"
_T_NO = "no"
_T_DASH = "-"
_T_UNKNOWN_WORD = "unknown"
_T_INV_UNITS = "units: {n}"
_T_INV_LANGUAGES = "languages: {n} ({items})"
_T_INV_LLM_CALLS = "llm_calls: {n}"
_T_INV_PROMPTS = "prompts: {n}"
_T_INV_PERSON_SIGNALS = "person_signals: {n}"
_T_INV_MEMORY_STORES = "memory_stores: {n}"
_T_INV_REVIEW_RECORDS = "review_records: {n}"
_T_INV_OWN_OUTPUT = "own output skipped: {items}"
_T_INV_OWN_OUTPUT_NONE = "none"
_T_INV_OVERSIZE = "oversize files skipped: {n}"
_T_INV_OVERSIZE_UNRECORDED = "not recorded"
_T_BASELINE = "baseline: {new} new, {unchanged} unchanged, {gone} no longer reported ({file})"
_T_BASELINE_RE_REVIEW = (
    "baseline: {new} new, {unchanged} unchanged, {re_review} re-review, "
    "{gone} no longer reported ({file}, written under policy {old})"
)
_T_STALE_ACCEPTANCES = (
    "stale acceptances: {n} accepted under an older policy; re-review under {policy}"
)
_T_SARIF_MESSAGE = "[{label}] {title}"
_T_EXIT = "exit code: {code}"

_TEMPLATES: tuple[str, ...] = (
    DISCLAIMER_TEMPLATE,
    DISCLAIMER,
    _T_TITLE,
    _T_LABEL_LINE,
    _T_MD_H1,
    _T_SUMMARY,
    _T_SEVERITY_LINE,
    _T_EVIDENCE_LINE,
    _T_DECISIONS_LINE,
    _T_COUNT_ITEM,
    _T_UNMEASURED,
    _T_MEASURED,
    _T_REPORTED,
    _T_REPORTED_UNKNOWN,
    _T_GITIGNORED,
    _T_BASELINE_STATUS,
    _T_NONE,
    _T_NOT_INCLUDED,
    _T_FINDINGS,
    _T_MECHANISMS,
    _T_NOT_ATTRIBUTED,
    _T_UNKNOWN,
    _T_INVENTORY,
    _T_MECH_HEAD,
    _T_MECH_STATUS,
    _T_MECH_TABLE_HEADER,
    _T_TABLE_RULE_7,
    _T_SCOPE,
    _T_STATUS,
    _T_STATUS_CONTROL,
    _T_REVIEW_DECISION,
    _T_EVIDENCE,
    _T_CHAIN,
    _T_CHAIN_NONE,
    _T_CHAIN_LINK,
    _T_CHAIN_ARROW,
    _T_CHAIN_LEXICAL,
    _T_TRACE_COMPLETE,
    _T_TRACE_PARTIAL,
    _T_TRACE_LEXICAL,
    _T_TRACE_MISSING,
    _T_TRACE_UNSUPPORTED,
    _T_LINKS_SUPPORTED,
    _T_LINKS_PARTIAL,
    _T_PURPOSE,
    _T_POPULATION,
    _T_FIX,
    _T_FIX_PLAIN,
    _T_ALTERNATIVES,
    _T_REFERENCES,
    _T_FAILURE_MODES,
    _T_LABEL_ALTERNATIVES,
    _T_LABEL_REFERENCES,
    _T_LABEL_FAILURE_MODES,
    _T_SEE_FIRST,
    _T_MD_ANCHOR,
    _T_MD_LINK,
    _T_GAPS,
    _T_UNCERTAINTY,
    _T_NOTE,
    _T_ACCEPTED_REASON,
    _T_ACCEPTED_RE_REVIEW,
    _T_RE_REVIEW,
    _T_UNKNOWN_ITEM,
    _T_RESOLVE,
    _T_FILE,
    _T_RULES,
    _T_YES,
    _T_NO,
    _T_DASH,
    _T_UNKNOWN_WORD,
    _T_INV_UNITS,
    _T_INV_LANGUAGES,
    _T_INV_LLM_CALLS,
    _T_INV_PROMPTS,
    _T_INV_PERSON_SIGNALS,
    _T_INV_MEMORY_STORES,
    _T_INV_REVIEW_RECORDS,
    _T_INV_OWN_OUTPUT,
    _T_INV_OWN_OUTPUT_NONE,
    _T_INV_OVERSIZE,
    _T_INV_OVERSIZE_UNRECORDED,
    _T_BASELINE,
    _T_BASELINE_RE_REVIEW,
    _T_STALE_ACCEPTANCES,
    _T_SARIF_MESSAGE,
    _T_EXIT,
)


def all_templates() -> tuple[str, ...]:
    """
    Every fixed string any renderer emits: this module's plus the html renderer's.
    Imported lazily because `html.py` builds on this module's templates, so a module-level
    import in either direction is a cycle.
    """
    from aisafe.reporting.html import TEMPLATES as html_templates

    return _TEMPLATES + html_templates


def check_templates() -> list[str]:
    """Banned phrases present in the renderers' own fixed strings. Never scans findings."""
    found: list[str] = []
    for template in all_templates():
        lowered = template.lower()
        for phrase in BANNED_PHRASES:
            if phrase in lowered and phrase not in found:
                found.append(phrase)
    return found


# ---------------------------------------------------------------------------
# Version, catalogue, exit code, summary
# ---------------------------------------------------------------------------


def tool_version() -> str:
    """The version of the code that is running, which `scripts/bump_version.py` keeps equal to
    the release. Not the package metadata: it can describe another copy, such as an old
    `aisafe.egg-info` next to the source, and a report would name a version that never ran."""
    return __version__


def _mechanism_of_rule(rule: type[AuditRule]) -> str:
    """The policy mechanism a rule serves ("M4"), or "" for a rule the policy does not place."""
    mechanism_id = getattr(rule, "mechanism_id", None)
    if callable(mechanism_id):
        return str(mechanism_id() or "")
    return str(getattr(rule, "mechanism", "") or "")


def catalogue(rules: Sequence[type[AuditRule]], ran_ids: set[str]) -> list[dict[str, Any]]:
    """The `rules[]` block. `measured_precision` is the attribute value, `None` included."""
    return [
        {
            "id": rule.id,
            "title": rule.title,
            "version": int(getattr(rule, "version", 1)),
            "mechanism": _mechanism_of_rule(rule),
            "measured_precision": rule.measured_precision,
            "ran": rule.id in ran_ids,
            "experimental": is_demoted(rule),
        }
        for rule in rules
    ]


def _threshold_rank(fail_on: str) -> int | None:
    """Severity rank at or above which a finding counts; `None` for "never"."""
    level = str(fail_on).lower()
    if level == "never":
        return None
    try:
        return Severity(level).rank()
    except ValueError:
        raise ValueError(
            f"fail_on must be one of {', '.join(FAIL_ON_CHOICES)}, not {fail_on!r}"
        ) from None


def _counts_toward_exit(finding: Finding, threshold: int | None) -> bool:
    # Only `unchanged` is excused: a `new` finding counts, and so does a `re-review` one,
    # because a suppression taken under an older policy does not stand under this one.
    if threshold is None or finding.baseline_status == STATUS_UNCHANGED:
        return False
    return Severity(finding.severity).rank() >= threshold


def _category(item: UnknownItem) -> str:
    return getattr(item.category, "value", str(item.category))


def compute_exit_code(
    findings: Iterable[Finding],
    unknown: Iterable[UnknownItem],
    *,
    fail_on: str,
    fail_on_unknown: set[str] | None = None,
) -> int:
    """
    0 or 1. A finding counts when its severity is at or above `fail_on` and it is not
    `unchanged` against a baseline (so `new` and `re-review` both count); "never" means
    findings never count. With `fail_on_unknown`, any UnknownItem in one of those
    categories also yields 1.
    """
    threshold = _threshold_rank(fail_on)
    if any(_counts_toward_exit(f, threshold) for f in findings):
        return 1
    if fail_on_unknown:
        selected = {getattr(c, "value", str(c)) for c in fail_on_unknown}
        if any(_category(u) in selected for u in unknown):
            return 1
    return 0


def summarise(
    findings: Iterable[Finding],
    unknown: Iterable[UnknownItem],
    reports: Iterable[ReportRecord],
    baseline: BaselineDiff | None,
    fail_on: str,
    exit_code: int,
) -> dict[str, Any]:
    """
    The `summary` block, keys in the pinned order. `reports` is accepted for signature
    stability; the block is computed from the findings and the unknown items only.

    `re_review` counts the findings a baseline suppressed under another policy version
    (`baseline_status == "re-review"`, counted toward the exit code); `stale_acceptances`
    counts the findings accepted with a reason under an older policy (still `unchanged`,
    not counted, but marked for a second look). The two never overlap.
    """
    findings = list(findings)
    unknown = list(unknown)
    threshold = _threshold_rank(fail_on)
    by_severity = {sev.value: 0 for sev in SEVERITY_ORDER}
    by_status = {status.value: 0 for status in EvidenceStatus}
    by_decision = {decision.value: 0 for decision in Decision}
    below = suppressed = re_review = stale = 0
    for finding in findings:
        severity = Severity(finding.severity)
        by_severity[severity.value] += 1
        by_status[EvidenceStatus(finding.evidence_status).value] += 1
        by_decision[Decision(finding.decision).value] += 1
        if threshold is None or severity.rank() < threshold:
            below += 1
        if finding.suppressed:
            suppressed += 1
        if finding.baseline_status == STATUS_RE_REVIEW:
            re_review += 1
        if finding.accepted_reason is not None and finding.re_review:
            stale += 1
    by_category = {category.value: 0 for category in UnknownCategory}
    for item in unknown:
        key = _category(item)
        by_category[key] = by_category.get(key, 0) + 1
    return {
        "findings": len(findings),
        "by_severity": by_severity,
        "by_evidence_status": by_status,
        "by_decision": by_decision,
        "below_threshold": below,
        "fail_on": str(fail_on).lower(),
        "unknown_items": len(unknown),
        "unknown_by_category": by_category,
        "exit_code": exit_code,
        "top": findings[0].display_id if findings else None,
        "suppressed": suppressed,
        "baseline_new": len(baseline.new) if baseline is not None else None,
        "re_review": re_review,
        "stale_acceptances": stale,
    }


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------


def _posix(path: Any) -> str:
    return str(path).replace("\\", "/")


def _as_dict(obj: Any) -> Any:
    return obj.to_dict() if hasattr(obj, "to_dict") else obj


def _target(ctx: AuditContext) -> dict[str, Any]:
    source = (_as_dict(ctx.inventory) or {}).get("target") or {}
    # The walker excludes as resolved (CLI flag or `[tool.aisafe-audit]`): a reader of the
    # report sees what was not walked without re-deriving it from the pyproject.
    exclude = getattr(ctx.options, "exclude", None) or ()
    return {
        "path": _posix(source.get("path") or ctx.root),
        "git_sha": source.get("git_sha"),
        "dirty": source.get("dirty"),
        "exclude": [str(item) for item in exclude],
    }


def _number(value: Any) -> float | int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _evaluation_extract(body: Any) -> dict[str, Any]:
    """The numeric `summary` of an evaluation report (sent, passed, failed, ...). Nothing else."""
    summary = body.get("summary") if isinstance(body, dict) else None
    if not isinstance(summary, dict):
        return {}
    return {str(key): value for key, value in summary.items() if _number(value) is not None}


def _report_entry(record: ReportRecord | dict[str, Any]) -> dict[str, Any]:
    if isinstance(record, ReportRecord):
        meta = record.to_dict()
        body: Any = record.body
    else:
        meta = dict(record)
        body = meta.pop("body", None)
    entry: dict[str, Any] = {"source": meta.pop("file", None)}
    entry.update(meta)
    if entry.get("kind") in EVALUATION_KINDS:
        entry["summary"] = _evaluation_extract(body)
    return entry


def build_report(
    ctx: AuditContext,
    findings: Iterable[Finding],
    unknown: Iterable[UnknownItem],
    reports: Iterable[ReportRecord],
    baseline: BaselineDiff | None,
    *,
    rules: Sequence[type[AuditRule]],
    fail_on: str,
    exit_code: int,
    policy: Policy | None = None,
    inventory_included: bool = True,
) -> Report:
    """
    Assemble the `Report`. `rules` are the rules that ran; the catalogue lists the
    registry plus any ran rule missing from it, each flagged `ran` true/false. Findings
    are sorted here (severity, then mechanism order, then location; nothing is pinned).
    `policy` defaults to the packaged one; the disclaimer names its version and the
    Mechanisms table is built against it.
    """
    policy = policy or load_policy()
    ordered = sort_findings(findings)
    unknown_items = list(unknown)
    report_records = list(reports)
    ran_ids = {rule.id for rule in rules}
    base = list(ALL_RULES)
    for rule in rules:
        if rule not in base:
            base.append(rule)
    return Report(
        tool={"name": TOOL_NAME, "version": tool_version()},
        target=_target(ctx),
        policy=policy.to_dict(),
        summary=summarise(ordered, unknown_items, report_records, baseline, fail_on, exit_code),
        mechanisms=coverage_table(policy, rules, ordered, ctx),
        findings=ordered,
        reports=[_report_entry(r) for r in report_records],
        unknown=unknown_items,
        baseline=baseline.to_dict() if baseline is not None else None,
        inventory=ctx.inventory if inventory_included else None,
        rules=catalogue(base, ran_ids),
        disclaimer=disclaimer(policy.version),
        mode=report_mode(ctx),
    )


def report_mode(ctx: AuditContext) -> str:
    """The mode the run was made in (`--mode`); self-assessment unless the options say
    otherwise."""
    mode = getattr(ctx.options, "mode", None) or "self-assessment"
    return mode if mode in MODES else "self-assessment"


def label_line(report: Report) -> str:
    """`scan report | mode: self-assessment`: what the document is, and who made it."""
    return _T_LABEL_LINE.format(
        label=getattr(report, "label", SCAN_REPORT_LABEL) or SCAN_REPORT_LABEL,
        mode=getattr(report, "mode", "self-assessment") or "self-assessment",
    )


# ---------------------------------------------------------------------------
# Shared rendering helpers
# ---------------------------------------------------------------------------


def _summary_of(report: Report) -> dict[str, Any]:
    if report.summary and "findings" in report.summary:
        return report.summary
    # A hand-built Report without a summary block: compute one rather than print zeros.
    code = compute_exit_code(report.findings, report.unknown, fail_on="low")
    return summarise(report.findings, report.unknown, report.reports, None, "low", code)


def _policy_version(report: Report) -> str | None:
    policy = report.policy if isinstance(report.policy, dict) else {}
    version = policy.get("version")
    return str(version) if version else None


def _plural(n: int) -> str:
    return "" if n == 1 else "s"


def _summary_line(summary: dict[str, Any]) -> str:
    n = int(summary.get("findings", 0))
    k = int(summary.get("unknown_items", 0))
    return _T_SUMMARY.format(
        n=n,
        s=_plural(n),
        m=int(summary.get("below_threshold", 0)),
        level=summary.get("fail_on", "low"),
        k=k,
        ks=_plural(k),
    )


def _severity_items(summary: dict[str, Any]) -> str:
    counts = summary.get("by_severity") or {}
    return ", ".join(
        _T_COUNT_ITEM.format(key=sev.value, n=int(counts.get(sev.value, 0)))
        for sev in SEVERITY_ORDER
    )


def _evidence_items(summary: dict[str, Any]) -> str:
    counts = summary.get("by_evidence_status") or {}
    return " | ".join(
        _T_COUNT_ITEM.format(key=status.value, n=int(counts.get(status.value, 0)))
        for status in EvidenceStatus
    )


def _decision_items(summary: dict[str, Any]) -> str:
    """The two decisions a finding normally carries, always; the quiet two only when present."""
    counts = summary.get("by_decision") or {}
    shown = [Decision.VIOLATES, Decision.REVIEW]
    shown += [
        d for d in (Decision.NO_VIOLATION, Decision.NOT_ASSESSED) if int(counts.get(d.value, 0))
    ]
    return " | ".join(
        _T_COUNT_ITEM.format(key=d.value, n=int(counts.get(d.value, 0))) for d in shown
    )


def _tags(finding: Finding) -> str:
    """The confidence tag, then report, gitignored and baseline tags, in a fixed order."""
    precision = finding.confidence.precision
    parts = [_T_UNMEASURED if precision is None else _T_MEASURED.format(p=precision)]
    if finding.report is not None:
        block = finding.report if isinstance(finding.report, dict) else {}
        age = block.get("age_days")
        if age is None:
            parts.append(_T_REPORTED_UNKNOWN)
        else:
            parts.append(_T_REPORTED.format(age=age, source=block.get("age_source") or "unknown"))
    if finding.gitignored:
        parts.append(_T_GITIGNORED)
    if finding.baseline_status:
        parts.append(_T_BASELINE_STATUS.format(status=finding.baseline_status))
    return " ".join(parts)


def _mechanism_rows(report: Report) -> list[dict[str, Any]]:
    """
    The Mechanisms table rows, in policy order. From `report.mechanisms` when the report
    carries one; a hand-built Report without a coverage table gets rows from the policy,
    with the strongest decision among the findings placed on a mechanism as its decision
    and `not_assessed` where nothing landed, because nothing here knows what ran.
    """
    rows = [row for row in (report.mechanisms or ()) if isinstance(row, dict) and row.get("id")]
    if rows:
        return rows
    out: list[dict[str, Any]] = []
    for mechanism in load_policy().mechanisms:
        mine = [f for f in report.findings if f.mechanism == mechanism.id]
        decision = max(
            (Decision(f.decision) for f in mine),
            key=lambda d: d.rank(),
            default=Decision.NOT_ASSESSED,
        )
        out.append(
            {
                "id": mechanism.id,
                "name": mechanism.name,
                "rules": list(mechanism.rules),
                "ran": [],
                "surfaces": 0,
                "findings": len(mine),
                "decision": decision.value,
            }
        )
    return out


def _grouped(
    findings: Sequence[Finding], rows: Sequence[dict[str, Any]]
) -> list[tuple[str, list[Finding]]]:
    """One group per mechanism in policy order, severity first inside; a trailing group
    for findings whose mechanism the policy does not name. Empty groups are not printed:
    the Mechanisms table says what was assessed and found nothing."""
    groups: list[tuple[str, list[Finding]]] = []
    ids: list[str] = []
    for row in rows:
        mechanism_id = str(row["id"])
        ids.append(mechanism_id)
        mine = [f for f in findings if f.mechanism == mechanism_id]
        if mine:
            label = _T_MECH_HEAD.format(id=mechanism_id, name=row.get("name") or mechanism_id)
            groups.append((label, sort_findings(mine)))
    rest = [f for f in findings if f.mechanism not in ids]
    if rest:
        groups.append((_T_NOT_ATTRIBUTED, sort_findings(rest)))
    return groups


def _list_text(value: Any) -> str:
    if isinstance(value, bool):
        return _T_YES if value else _T_NO
    if isinstance(value, (list, tuple, set, frozenset)):
        return ", ".join(str(v) for v in value) or _T_NONE
    return str(value) if value not in (None, "") else _T_NONE


def _mechanism_status(row: dict[str, Any]) -> str:
    return _T_MECH_STATUS.format(
        rules=_list_text(row.get("rules")),
        ran=_list_text(row.get("ran")),
        surfaces=row.get("surfaces", _T_DASH),
        findings=row.get("findings", _T_DASH),
        decision=row.get("decision") or _T_DASH,
    )


def _scope_text(finding: Finding) -> str:
    name = finding.scope.name or finding.scope.unit or _T_DASH
    return _T_SCOPE.format(kind=finding.scope.kind, name=name)


def _status_text(finding: Finding) -> str:
    """`status: <evidence_status> | decision: <decision> | control: <status>`; the control
    segment only when the rule assessed one, so an unassessed control is not called anything."""
    status = EvidenceStatus(finding.evidence_status).value
    decision = Decision(finding.decision).value
    if finding.control_status is None:
        return _T_STATUS.format(status=status, decision=decision)
    control = getattr(finding.control_status, "value", str(finding.control_status))
    return _T_STATUS_CONTROL.format(status=status, decision=decision, control=control)


def _review_decision_text(finding: Finding) -> str | None:
    if finding.review_decision is None:
        return None
    return _T_REVIEW_DECISION.format(
        decision=finding.review_decision, justification=finding.review_justification or _T_DASH
    )


def _evidence_text(evidence: Evidence) -> str:
    return _T_EVIDENCE.format(
        role=evidence.role, file=evidence.file, line=evidence.line, snippet=evidence.snippet
    )


def _missing_text(finding: Finding) -> str:
    """Each required link the trace lacks: "not established" when no link of that kind is
    present, else the best status a present one has (co-located, runtime-only)."""
    flow = finding.flow
    parts: list[str] = []
    for kind in finding.missing_links:
        present = [] if flow is None else [link for link in flow.links if link.kind == kind]
        name = kind.replace("_", " ")
        if present:
            by = sorted({link.established_by for link in present}, key=_STATUS_ORDER.index)[0]
            parts.append(_T_TRACE_UNSUPPORTED.format(kind=name, by=by))
        else:
            parts.append(_T_TRACE_MISSING.format(kind=name))
    return ", ".join(parts)


def _chain_text(finding: Finding) -> str | None:
    """The reconstructed chain, link by link with how each was established, then the trace
    measured against the finding's policy pattern: complete, partial (naming each required
    link it lacks), or lexical co-occurrence only. A partial trace is never shown as
    complete; a rule that draws no trace says so. With no chain at all, a finding whose
    rule has a pattern still names the links a trace would need; one without says nothing."""
    flow = finding.flow
    if flow is None or not flow.links:
        pattern = finding.trace_pattern
        if pattern is None:
            return None
        return _T_CHAIN_NONE.format(pattern=pattern.display_id, missing=_missing_text(finding))
    rendered: list[str] = []
    for link in flow.links:
        text = _T_CHAIN_LINK.format(kind=link.kind.replace("_", " "), by=link.established_by)
        # A call and its reply are two intervention sites established the same way; the
        # chain names the step once (the JSON keeps every site).
        if not rendered or rendered[-1] != text:
            rendered.append(text)
    links = _T_CHAIN_ARROW.join(rendered)
    pattern = finding.trace_pattern
    lexical = not any(link.supported for link in flow.links)
    if pattern is None:
        status = (
            _T_CHAIN_LEXICAL
            if lexical
            else (_T_LINKS_SUPPORTED if flow.links_supported else _T_LINKS_PARTIAL)
        )
        return _T_CHAIN.format(links=links, status=status)
    if finding.trace_complete:
        status = _T_TRACE_COMPLETE.format(pattern=pattern.display_id)
    elif lexical:
        status = _T_TRACE_LEXICAL.format(pattern=pattern.display_id, missing=_missing_text(finding))
    else:
        status = _T_TRACE_PARTIAL.format(pattern=pattern.display_id, missing=_missing_text(finding))
    return _T_CHAIN.format(links=links, status=status)


def _purpose_text(finding: Finding) -> str | None:
    """Declared purpose (from the review record) against the encoded objective (from the
    prompt or the code), when either is known; the other side says `(none)`."""
    if finding.declared_purpose is None and finding.encoded_objective is None:
        return None
    return _T_PURPOSE.format(
        declared=finding.declared_purpose or _T_NONE, encoded=finding.encoded_objective or _T_NONE
    )


def _population_text(finding: Finding) -> str | None:
    if not finding.affected_population:
        return None
    return _T_POPULATION.format(text=finding.affected_population)


def _fix_text(finding: Finding) -> str:
    rec = finding.recommendation
    if rec.removes:
        return _T_FIX.format(
            tier=rec.tier.value, removes=", ".join(rec.removes), summary=rec.summary
        )
    return _T_FIX_PLAIN.format(tier=rec.tier.value, summary=rec.summary)


def _gaps_text(finding: Finding) -> str | None:
    if not finding.coverage_gaps:
        return None
    return _T_GAPS.format(items="; ".join(finding.coverage_gaps))


def _uncertainty_text(finding: Finding) -> str | None:
    if not finding.uncertainty:
        return None
    return _T_UNCERTAINTY.format(text=finding.uncertainty)


def _accepted_text(finding: Finding, policy_version: str | None = None) -> str | None:
    """The operator's reason, with the re-review marker when the acceptance predates the policy."""
    if finding.accepted_reason is None:
        return None
    if finding.re_review:
        return _T_ACCEPTED_RE_REVIEW.format(
            reason=finding.accepted_reason,
            old=finding.acceptance_policy_version or _T_UNKNOWN_WORD,
            new=policy_version or finding.policy_version or _T_UNKNOWN_WORD,
        )
    return _T_ACCEPTED_REASON.format(reason=finding.accepted_reason)


def _re_review_text(finding: Finding, policy_version: str | None = None) -> str | None:
    """Why a `re-review` finding counts again: the baseline suppressed it, and that baseline
    was not written under this policy (another version, or none recorded; the baseline line
    at the top names which)."""
    if finding.baseline_status != STATUS_RE_REVIEW:
        return None
    return _T_RE_REVIEW.format(new=policy_version or finding.policy_version or _T_UNKNOWN_WORD)


def _first_of_rule(seen: dict[str, Finding], finding: Finding) -> Finding | None:
    """
    The earlier finding of the same rule id whose shared blocks were printed in full,
    or `None` when `finding` is the first of its rule -- in which case it is recorded.
    Keyed on the rule id, not the display id: a sub-finding shares its rule's blocks.
    """
    first = seen.get(finding.id)
    if first is None:
        seen[finding.id] = finding
    return first


def _repeated_rule_ids(findings: Iterable[Finding]) -> set[str]:
    """Rule ids with more than one finding: the ones whose first occurrence needs an anchor."""
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.id] = counts.get(finding.id, 0) + 1
    return {rule_id for rule_id, n in counts.items() if n > 1}


def _anchor(finding: Finding) -> str:
    return finding.display_id.lower().replace("/", "-")


def _finding_detail_lines(
    finding: Finding,
    first: Finding | None = None,
    ref: str | None = None,
    policy_version: str | None = None,
) -> list[str]:
    """
    Detail lines shared by markdown and terminal, in a fixed order: scope, status and
    decision, the review record's decision, evidence, chain, purpose, population, fix,
    then the rule-level blocks (alternatives, references, known failure modes), then gaps,
    uncertainty, the note, and last the baseline's accepted reason or re-review marker.

    `first` is the earlier finding of the same rule whose rule-level blocks were already
    printed. A block identical to `first`'s is replaced by one reference line naming
    `ref` (default: `first.display_id`); a block that differs is printed in full.
    """
    lines = [_scope_text(finding), _status_text(finding)]
    review = _review_decision_text(finding)
    if review:
        lines.append(review)
    lines.extend(_evidence_text(e) for e in finding.evidence)
    for text in (_chain_text(finding), _purpose_text(finding), _population_text(finding)):
        if text:
            lines.append(text)
    lines.append(_fix_text(finding))
    rec = finding.recommendation
    folded: list[str] = []
    if rec.alternatives:
        if first is not None and first.recommendation.alternatives == rec.alternatives:
            folded.append(_T_LABEL_ALTERNATIVES)
        else:
            lines.append(_T_ALTERNATIVES.format(items="; ".join(rec.alternatives)))
    if finding.references:
        if first is not None and first.references == finding.references:
            folded.append(_T_LABEL_REFERENCES)
        else:
            lines.append(_T_REFERENCES.format(items=", ".join(finding.references)))
    if finding.known_failure_modes:
        if first is not None and first.known_failure_modes == finding.known_failure_modes:
            folded.append(_T_LABEL_FAILURE_MODES)
        else:
            lines.append(_T_FAILURE_MODES.format(items="; ".join(finding.known_failure_modes)))
    if folded and first is not None:
        lines.append(_T_SEE_FIRST.format(items=" / ".join(folded), ref=ref or first.display_id))
    for text in (_gaps_text(finding), _uncertainty_text(finding)):
        if text:
            lines.append(text)
    if finding.notes:
        lines.append(_T_NOTE.format(text=finding.notes))
    # The reason is why the finding is not counted; a reader of the terminal or markdown
    # output otherwise has to open the baseline file to learn it. A re-review marker says
    # why a baselined finding counts again.
    for text in (_accepted_text(finding, policy_version), _re_review_text(finding, policy_version)):
        if text:
            lines.append(text)
    return lines


def _unknown_head(item: UnknownItem) -> str:
    return _T_UNKNOWN_ITEM.format(category=_category(item), what=item.what, why=item.why)


def _unknown_detail_lines(item: UnknownItem) -> list[str]:
    lines: list[str] = []
    if item.how_to_resolve:
        lines.append(_T_RESOLVE.format(text=item.how_to_resolve))
    if item.file:
        lines.append(_T_FILE.format(file=item.file))
    if item.rule_ids:
        lines.append(_T_RULES.format(items=", ".join(item.rule_ids)))
    return lines


def _inventory_lines(inventory: Inventory | dict[str, Any] | None) -> list[str]:
    """Counts only: the full inventory is in the JSON document, not in a rendered page."""
    inv = _as_dict(inventory)
    if not isinstance(inv, dict) or not inv:
        return [_T_NOT_INCLUDED]
    languages = inv.get("languages") or {}
    items = ", ".join(f"{lang} {n}" for lang, n in sorted(languages.items())) or _T_NONE
    # The audit's own earlier output found in the tree and skipped by the walk. One line,
    # always: a page that re-reported its own snippets would be an audit of the audit.
    own = inv.get("own_output_skipped") or []
    own_items = ", ".join(str(p) for p in own) if isinstance(own, list) and own else None
    return [
        _T_INV_UNITS.format(n=len(inv.get("units") or [])),
        _T_INV_LANGUAGES.format(n=len(languages), items=items),
        _T_INV_LLM_CALLS.format(n=len(inv.get("llm_calls") or [])),
        _T_INV_PROMPTS.format(n=len(inv.get("prompts") or [])),
        _T_INV_PERSON_SIGNALS.format(n=len(inv.get("person_signals") or [])),
        _T_INV_MEMORY_STORES.format(n=len(inv.get("memory_stores") or [])),
        _T_INV_REVIEW_RECORDS.format(n=len(inv.get("review_records") or [])),
        _T_INV_OWN_OUTPUT.format(items=own_items or _T_INV_OWN_OUTPUT_NONE),
        _T_INV_OVERSIZE.format(n=_unrecorded(_oversize_files(inv))),
    ]


def _oversize_files(inv: Any) -> int | None:
    """
    `target.oversize_files`: files the walk never opened because they were over
    `max_size`. `None` when the document has no such key (an older report read back
    from disk): the renderers then say so rather than printing 0, because zero is a
    claim and nobody made it.
    """
    target = inv.get("target") if isinstance(inv, dict) else None
    value = target.get("oversize_files") if isinstance(target, dict) else None
    if isinstance(value, list):
        return len(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _unrecorded(count: int | None) -> str:
    return _T_INV_OVERSIZE_UNRECORDED if count is None else str(count)


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _baseline_lines(report: Report) -> list[str]:
    """The baseline count line (with the re-review count, and the policy version the
    baseline was written under, only when something re-reviews) and, when acceptances
    predate the policy, a second line saying how many and under which version."""
    block = report.baseline
    if not block:
        return []
    values = {
        "file": block.get("file") or _T_DASH,
        "new": _int(block.get("new")),
        "gone": len(block.get("no_longer_reported") or []),
        "unchanged": _int(block.get("unchanged")),
    }
    re_review = _int(block.get("re_review"))
    if re_review:
        # The baseline's own version says why its suppressions do not stand: `unknown`
        # when the file recorded none, which is also a mismatch.
        old = block.get("policy_version") or _T_UNKNOWN_WORD
        lines = [_T_BASELINE_RE_REVIEW.format(re_review=re_review, old=old, **values)]
    else:
        lines = [_T_BASELINE.format(**values)]
    stale = _int(block.get("stale_acceptances"))
    if stale:
        lines.append(
            _T_STALE_ACCEPTANCES.format(n=stale, policy=_policy_version(report) or _T_UNKNOWN_WORD)
        )
    return lines


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=True) + "\n"


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------


def _sarif_location(evidence: Evidence) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": evidence.file, "uriBaseId": "%SRCROOT%"},
            "region": {
                "startLine": max(int(evidence.line), 1),
                "snippet": {"text": evidence.snippet},
            },
        }
    }


def _sarif_rule(
    rule_id: str,
    title: str | None,
    precision: float | None,
    findings: Sequence[Finding],
    *,
    ran: bool | None,
    experimental: bool | None,
    version: int | None = None,
    mechanism: str | None = None,
) -> dict[str, Any]:
    tier = findings[0].recommendation.tier.value if findings else None
    entry: dict[str, Any] = {
        "id": rule_id,
        "name": title or rule_id,
        "shortDescription": {"text": title or rule_id},
    }
    if findings:
        entry["help"] = {"text": findings[0].recommendation.summary}
    entry["properties"] = {
        "measured_precision": precision,
        "tier": tier,
        "version": version,
        "mechanism": mechanism,
        "ran": ran,
        "experimental": experimental,
    }
    return entry


def _sarif_result(finding: Finding) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.display_id,
        "level": SARIF_LEVEL[Severity(finding.severity)],
        "message": {
            "text": _T_SARIF_MESSAGE.format(label=finding.confidence.label, title=finding.title)
        },
    }
    if finding.evidence:
        result["locations"] = [_sarif_location(finding.evidence[0])]
        if len(finding.evidence) > 1:
            result["relatedLocations"] = [
                dict(_sarif_location(e), message={"text": e.role}) for e in finding.evidence[1:]
            ]
    result["partialFingerprints"] = {SARIF_FINGERPRINT_KEY: finding.fingerprint}
    control = finding.control_status
    properties: dict[str, Any] = {
        "severity": Severity(finding.severity).value,
        "priority": finding.priority,
        "mechanism": finding.mechanism,
        "policy_version": finding.policy_version,
        "rule_version": finding.rule_version,
        "evidence_status": EvidenceStatus(finding.evidence_status).value,
        "decision": Decision(finding.decision).value,
        "basis": finding.basis.value,
        "confidence": finding.confidence.to_dict(),
        "scope": finding.scope.to_dict(),
        "sub": finding.sub,
        "flow": finding.flow_dict(),
        "pattern": None if finding.trace_pattern is None else finding.trace_pattern.id,
        "links_supported": finding.links_supported,
        "trace_complete": finding.trace_complete,
        "missing_links": list(finding.missing_links),
        "flow_established": finding.flow_established,
        "control_status": None if control is None else getattr(control, "value", str(control)),
        "references": list(finding.references),
        "report": finding.report,
        "gitignored": finding.gitignored,
        "baseline_status": finding.baseline_status,
        "recommendation": finding.recommendation.to_dict(),
    }
    if finding.notes is not None:
        properties["notes"] = finding.notes
    if finding.accepted_reason is not None:
        properties["accepted_reason"] = finding.accepted_reason
    if finding.acceptance_policy_version is not None:
        properties["acceptance_policy_version"] = finding.acceptance_policy_version
    if finding.re_review:
        properties["re_review"] = True
    if finding.review_decision is not None:
        properties["review_decision"] = finding.review_decision
        properties["review_justification"] = finding.review_justification
    result["properties"] = properties
    return result


def to_sarif(report: Report) -> str:
    findings = list(report.findings)
    by_display_id: dict[str, list[Finding]] = {}
    for finding in findings:
        by_display_id.setdefault(finding.display_id, []).append(finding)
    rules_out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in report.rules:
        rule_id = str(entry.get("id"))
        seen.add(rule_id)
        rules_out.append(
            _sarif_rule(
                rule_id,
                entry.get("title"),
                entry.get("measured_precision"),
                by_display_id.get(rule_id, []),
                ran=entry.get("ran"),
                experimental=entry.get("experimental"),
                version=entry.get("version"),
                mechanism=entry.get("mechanism"),
            )
        )
    for display_id, group in by_display_id.items():
        if display_id in seen:
            continue
        seen.add(display_id)
        first = group[0]
        rules_out.append(
            _sarif_rule(
                display_id,
                first.title,
                first.confidence.precision,
                group,
                ran=True,
                experimental=None,
                version=first.rule_version,
                mechanism=first.mechanism,
            )
        )
    version = (report.tool or {}).get("version") or tool_version()
    inv = _as_dict(report.inventory)
    own = inv.get("own_output_skipped") if isinstance(inv, dict) else None
    own_output = [str(p) for p in own] if isinstance(own, list) else []
    oversize_files = _oversize_files(inv)
    # No `schema` at the root: the 2.1.0 schema forbids unknown root keys and
    # Code Scanning uploads validate strictly. The marker rides in the run's
    # property bag, which is the one place SARIF allows arbitrary keys; so does
    # the own-output list, since SARIF has no inventory block of its own.
    # The property bag is the run's FIRST key, and `aisg_schema` then `own_output_skipped`
    # its first two: `walk.is_own_report` reads only the head of a file, and with the bag
    # after `results` a SARIF written into the tree was scanned like any other file and
    # reproduced its own findings on the next run. A test pins the order.
    doc = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "properties": {
                    "aisg_schema": SCHEMA_VERSION,
                    "own_output_skipped": own_output,
                    # SARIF has no inventory block; `null` means the count was not
                    # recorded, never zero.
                    "oversize_files": oversize_files,
                    "policy": _as_dict(report.policy) or {},
                    "label": report.label,
                    "mode": report.mode,
                    "disclaimer": report.disclaimer,
                    "generated_at": report.generated_at,
                    "target": _as_dict(report.target),
                    "summary": _summary_of(report),
                    "mechanisms": [dict(row) for row in _mechanism_rows(report)],
                    "unknown": [_as_dict(u) for u in report.unknown],
                    "baseline": report.baseline,
                },
                "tool": {"driver": {"name": TOOL_NAME, "version": version, "rules": rules_out}},
                "results": [_sarif_result(f) for f in findings],
            }
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def _md_cell(text: Any) -> str:
    return str(text).replace("|", "\\|")


def _md_text(text: str) -> str:
    """A detail line for Markdown: `&` and `<` become entities and a backtick is escaped, so
    text from the tree or a person (a baseline reason, a quote) opens no HTML comment, which
    a viewer would hide, no raw HTML and no code span. The assessment's `_md` does the same."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace("`", "\\`")


def _md_finding(
    finding: Finding, first: Finding | None, anchored: bool, policy_version: str | None
) -> list[str]:
    """
    One list item. The first finding of a rule that recurs carries an HTML anchor so the
    later ones can link back to its rule-level blocks instead of repeating them.
    """
    anchor = _T_MD_ANCHOR.format(anchor=_anchor(finding)) if anchored else ""
    head = (
        f"- {anchor}**{finding.display_id}** {finding.title} -- "
        f"{Severity(finding.severity).value} {_tags(finding)}"
    )
    ref = None
    if first is not None:
        ref = _T_MD_LINK.format(text=first.display_id, anchor=_anchor(first))
    details = _finding_detail_lines(finding, first, ref, policy_version)
    return [head] + [f"  - {_md_text(line)}" for line in details]


def _md_mechanisms(rows: Sequence[dict[str, Any]]) -> list[str]:
    lines = [f"## {_T_MECHANISMS}", "", _T_MECH_TABLE_HEADER, _T_TABLE_RULE_7]
    for row in rows:
        cells = (
            row.get("id"),
            row.get("name") or _T_DASH,
            _list_text(row.get("rules")),
            _list_text(row.get("ran")),
            row.get("surfaces", _T_DASH),
            row.get("findings", _T_DASH),
            row.get("decision") or _T_DASH,
        )
        lines.append("| " + " | ".join(_md_cell(c) for c in cells) + " |")
    return lines


def to_markdown(report: Report) -> str:
    summary = _summary_of(report)
    rows = _mechanism_rows(report)
    policy_version = _policy_version(report)
    lines: list[str] = [
        _T_MD_H1,
        "",
        label_line(report),
        "",
        f"> {report.disclaimer}",
        "",
        _summary_line(summary),
    ]
    for line in _baseline_lines(report):
        lines += ["", line]
    lines += [
        "",
        _T_SEVERITY_LINE.format(items=_severity_items(summary)),
        "",
        _T_EVIDENCE_LINE.format(items=_evidence_items(summary)),
        "",
        _T_DECISIONS_LINE.format(items=_decision_items(summary)),
        "",
        f"## {_T_FINDINGS}",
        "",
    ]
    findings = list(report.findings)
    if not findings:
        lines.append(_T_NONE)
    repeated = _repeated_rule_ids(findings)
    seen: dict[str, Finding] = {}
    for label, group in _grouped(findings, rows):
        lines.append(f"### {label}")
        lines.append("")
        for finding in group:
            first = _first_of_rule(seen, finding)
            anchored = first is None and finding.id in repeated
            lines.extend(_md_finding(finding, first, anchored, policy_version))
        lines.append("")
    lines.append("")
    lines.extend(_md_mechanisms(rows))
    lines += ["", f"## {_T_UNKNOWN}", ""]
    if not report.unknown:
        lines.append(_T_NONE)
    for item in report.unknown:
        lines.append(f"- {_unknown_head(item)}")
        lines.extend(f"  - {line}" for line in _unknown_detail_lines(item))
    lines += ["", f"## {_T_INVENTORY}", ""]
    lines.extend(f"- {line}" for line in _inventory_lines(report.inventory))
    lines += ["", _T_EXIT.format(code=summary.get("exit_code"))]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Terminal
# ---------------------------------------------------------------------------

_INDENT = " " * 8


def _ascii(text: str) -> str:
    return text.encode("ascii", "backslashreplace").decode("ascii")


def _emit(out: list[str], text: str, indent: str = "", first: str | None = None) -> None:
    """Append `text` wrapped to WIDTH columns, ASCII-escaped, with a hanging indent."""
    wrapped = textwrap.wrap(
        _ascii(text),
        width=WIDTH,
        initial_indent=indent if first is None else first,
        subsequent_indent=indent,
        break_long_words=True,
        break_on_hyphens=False,
    )
    out.extend(wrapped or [(indent if first is None else first).rstrip()])


def _disclaimer(out: list[str], text: str) -> None:
    """One sentence per line so no sentence is cut by the column wrap."""
    for sentence in re.split(r"(?<=\.)\s+", text):
        _emit(out, sentence)


def _heading(out: list[str], title: str) -> None:
    out.append("")
    out.append(title)
    out.append("-" * len(title))


def _severity_bar(severity: Severity) -> str:
    rank = Severity(severity).rank()
    width = len(SEVERITY_ORDER)
    return "[" + "#" * (rank + 1) + "." * (width - rank - 1) + "]"


def _terminal_finding(
    out: list[str], finding: Finding, first: Finding | None, policy_version: str | None
) -> None:
    severity = Severity(finding.severity)
    head = (
        f"{_severity_bar(severity)} {finding.display_id} {severity.value} "
        f"{_tags(finding)} {finding.title}"
    )
    _emit(out, head, indent=_INDENT, first="")
    for line in _finding_detail_lines(finding, first, None, policy_version):
        _emit(out, line, indent=_INDENT + "  ", first=_INDENT)


def _terminal_mechanisms(out: list[str], rows: Sequence[dict[str, Any]]) -> None:
    """Two lines per mechanism: its id and name, then what its rules could assess."""
    _heading(out, _T_MECHANISMS)
    if not rows:
        out.append(_T_NONE)
    for row in rows:
        head = _T_MECH_HEAD.format(id=row.get("id"), name=row.get("name") or _T_DASH)
        _emit(out, head, indent=_INDENT, first="")
        _emit(out, _mechanism_status(row), indent=_INDENT + "  ", first=_INDENT)


def _terminal_unknown(out: list[str], items: Sequence[UnknownItem]) -> None:
    _heading(out, _T_UNKNOWN)
    if not items:
        out.append(_T_NONE)
    for item in items:
        _emit(out, _unknown_head(item), indent=_INDENT, first="")
        for line in _unknown_detail_lines(item):
            _emit(out, line, indent=_INDENT + "  ", first=_INDENT)


def to_terminal(report: Report, quiet: bool = False) -> str:
    """
    Same order as Markdown. `quiet` keeps the disclaimer, the summary, baseline, severity,
    evidence and decision lines, the Mechanisms table and UNKNOWN; it never prints a finding.
    """
    summary = _summary_of(report)
    rows = _mechanism_rows(report)
    policy_version = _policy_version(report)
    out: list[str] = [_T_TITLE, "=" * len(_T_TITLE)]
    _emit(out, label_line(report))
    _disclaimer(out, report.disclaimer)
    out.append("")
    _emit(out, _summary_line(summary))
    for line in _baseline_lines(report):
        _emit(out, line)
    _emit(out, _T_SEVERITY_LINE.format(items=_severity_items(summary)))
    _emit(out, _T_EVIDENCE_LINE.format(items=_evidence_items(summary)))
    _emit(out, _T_DECISIONS_LINE.format(items=_decision_items(summary)))
    if quiet:
        _terminal_mechanisms(out, rows)
        _terminal_unknown(out, list(report.unknown))
        return "\n".join(out) + "\n"
    _heading(out, _T_FINDINGS)
    findings = list(report.findings)
    if not findings:
        out.append(_T_NONE)
    seen: dict[str, Finding] = {}
    for label, group in _grouped(findings, rows):
        out.append("")
        _emit(out, label)
        for finding in group:
            _terminal_finding(out, finding, _first_of_rule(seen, finding), policy_version)
    _terminal_mechanisms(out, rows)
    _terminal_unknown(out, list(report.unknown))
    _heading(out, _T_INVENTORY)
    for line in _inventory_lines(report.inventory):
        _emit(out, line)
    out.append("")
    _emit(out, _T_EXIT.format(code=summary.get("exit_code")))
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def render(report: Report, fmt: str, *, quiet: bool = False) -> str:
    """One renderer per run. `quiet` only affects the terminal format; every other
    document is exactly what the JSON says."""
    if fmt == "json":
        return to_json(report)
    if fmt == "sarif":
        return to_sarif(report)
    if fmt == "markdown":
        return to_markdown(report)
    if fmt == "terminal":
        return to_terminal(report, quiet=quiet)
    if fmt == "html":
        # Local import: `html.py` imports this module's templates, see `all_templates`.
        from aisafe.reporting.html import render_html

        return render_html(report, quiet=quiet)
    raise ValueError(f"unknown format {fmt!r}; expected one of {', '.join(FORMATS)}")
