"""src/aisafe/reporting/html.py
----------------------------
The html renderer for `aisafe audit`: one standalone page, no script, no external
resource, ASCII only. Document 1 (no baseline) is the survey: the mechanism map drawn
from the policy, one section per mechanism with the findings placed on it, and the plan.
Document 2 (`--baseline`) adds what changed, what is left and what is still UNKNOWN.

Every sentence the page emits is a fixed string in `TEMPLATES`; `report.check_templates`
scans them with the terminal's. Nothing user-controlled reaches the page unescaped, and
every non-ASCII character becomes a numeric entity, so the file is ASCII whatever the
audited tree contained. Line 1 is the audit's own ignore marker: a page written into the
audited tree is skipped by the next walk instead of re-reporting every snippet on it.

Rules that hold here and nowhere weaker:

- No severity colour. The map has neutral borders; `--warn` is the UNKNOWN box and
  nothing else, and no `--good` token exists.
- Every box and every section prints its UNKNOWN count, its decision and `[UNMEASURED]`,
  at zero findings too. A decision is the policy's word for what the findings on a
  mechanism amount to, never a score, and `not_assessed` is said as plainly as the rest.
- "no longer reported", never a verdict: a fingerprint absent from this run is exactly
  that, and a rename produces it as readily as a change.
- Identical input, identical bytes: no clock, no layout solver.
"""

from __future__ import annotations

import html as _html
import textwrap
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from aisafe.discovery import patterns
from aisafe.evidence.model import Decision, Finding, Report, Severity, UnknownItem, redact
from aisafe.policy import load_policy
from aisafe.reporting.report import (
    _T_DASH,
    _T_DECISIONS_LINE,
    _T_EVIDENCE_LINE,
    _T_EXIT,
    _T_NO,
    _T_NONE,
    _T_NOTE,
    _T_REFERENCES,
    _T_REPORTED,
    _T_REPORTED_UNKNOWN,
    _T_SEVERITY_LINE,
    _T_UNKNOWN,
    _T_UNKNOWN_WORD,
    _T_UNMEASURED,
    _T_YES,
    DISTRIBUTION,
    SCHEMA_VERSION,
    _baseline_lines,
    _chain_text,
    _decision_items,
    _evidence_items,
    _fix_text,
    _gaps_text,
    _inventory_lines,
    _mechanism_rows,
    _plural,
    _policy_version,
    _population_text,
    _purpose_text,
    _re_review_text,
    _review_decision_text,
    _severity_items,
    _status_text,
    _summary_line,
    _summary_of,
    _tags,
    _uncertainty_text,
    _unknown_detail_lines,
    _unknown_head,
    label_line,
    tool_version,
)

__all__ = ["NOT_ATTRIBUTED", "TEMPLATES", "render_html"]

# Caps. Beyond them the page says "+N more in the JSON"; it never drops silently.
MAX_FINDINGS_PER_SECTION = 12
# The box a finding or an UNKNOWN item lands on when no policy mechanism claims it.
NOT_ATTRIBUTED = "not_attributed"

# ---------------------------------------------------------------------------
# Templates: every fixed string this renderer emits. `report.check_templates` scans
# them (through `report.all_templates`) and nothing else.
# ---------------------------------------------------------------------------

_T_MARKER = (
    patterns.OWN_HTML_MARKER_LINE
)  # "<!-- # aisafe-audit: ignore-file -->", shared with walk
_T_PAGE_TITLE = "aisafe audit: {target}"
_T_H1 = "Prompt and algorithm audit: {target}"
_T_DOC1 = (
    "Document 1 of 2: the first survey. A later run with --baseline produces document 2, "
    "the comparison."
)
_T_DOC2 = "Document 2 of 2: compared against a baseline."
_T_HEAD_FACTS = (
    "commit {sha} -- uncommitted changes: {dirty} -- generated {generated_at} -- {tool} -- "
    "policy version {policy}"
)
_T_COMPARED_NONE = "Compared against: none -- this is the first survey"
_T_COMPARED = "Compared against: {file}, {age}"
_T_AGE = "written {n} {unit} ago"
_T_AGE_UNKNOWN = "age unknown"
_T_UNIT_DAY = "day"
_T_UNIT_HOUR = "hour"
_T_UNIT_MINUTE = "minute"
_T_REASONS = "operator-recorded reasons: {n}"
_T_REASONS_NONE = "operator-recorded reasons: none"
_T_REASONS_REPORT = (
    "operator-recorded reasons: none: the baseline was a report, not a baseline file"
)
_T_BASELINE_POLICY = "baseline policy version {version}"
_T_BASELINE_POLICY_NONE = "baseline policy version not recorded"
_T_RESOLVED_FAIL_ON = "fail-on: {fail_on}"
_T_RESOLVED_EXCLUDE = "exclude: {items}"
_T_READ_FIRST = "Read this first"
_T_ABSENCE = "Absence of a finding is not evidence of safety."
_T_UNKNOWN_COUNT = (
    "UNKNOWN: {n} item{s} the audit could not establish (listed in section {section})"
)
_T_BANNER_NO_RULES = (
    "Rules did not run. This page holds the inventory and the map only: there is no finding "
    "because nothing was checked, and there is no plan."
)
_T_SINCE = "Since the baseline"
_T_WHAT_CHANGED = "What changed"
_T_WHAT_LEFT = "What is left"
_T_WHAT_UNKNOWN = "What we still do not know"
_T_NO_LONGER = "No longer reported: {n}"
_T_NO_LONGER_NOTE = "no longer reported at this fingerprint; a rename or a move also produces this"
_T_NO_LONGER_ROW = "{rule} {title} -- {file}"
_T_NO_LONGER_UNNAMED = "{fingerprint} -- not in this run (the baseline did not record rule or file)"
_T_NEW_SINCE = "New since the baseline: {n}"
_T_RE_REVIEW_SINCE = (
    "Re-review (suppressed in a baseline not written under this policy version): {n}"
)
_T_STALE_SINCE = "Accepted under an older policy, re-review: {n}"
_T_FINDING_ROW = "{id} {title} -- {file}"
_T_LEFT = "{n} open row{s} in the plan; see section {section}, Remaining actions"
_T_STILL_UNKNOWN = "UNKNOWN: {n} item{s}; see section {section}"
_T_MAP = "Mechanism map"
_T_FIG_TITLE = "Fig. 1: mechanism map of {target}"
_T_FIG_CAPTION = (
    "Fig. 1 -- the mechanisms of the policy (version {policy}), drawn from the policy, not "
    "traced at runtime; each box counts the findings placed on it and the UNKNOWN items its "
    "rules raised. {k} of {total} rules ran. A box's decision is the strongest decision "
    "among its findings, about the surfaces the audit read; it is never a score."
)
_T_ROW_RANGE = "mechanisms {first} to {last}"
_T_BOX_STATUS = "findings {n} | UNKNOWN {m}"
_T_BOX_NOT_ATTRIBUTED = "Not attributed / UNKNOWN"
_T_BOX_NOT_ATTRIBUTED_LINE = "UNKNOWN not attributed to a mechanism: {m} | findings {n}"
_T_MECHANISMS = "Mechanisms"
_T_SECTION_STATUS = "findings {n} | UNKNOWN {m} | decision {decision} | rules ran {k}/{total}"
_T_SECTION_STATUS_REST = "findings {n} | UNKNOWN {m}"
_T_NOT_ATTRIBUTED_TITLE = "Not attributed"
_T_PROHIBITED = "Prohibited: {text}"
_T_DISTINCT = "Distinct from: {text}"
_T_RULES_OF = "Rules: {items}"
_T_MORE = "+{n} more in the JSON"
_T_FINDINGS_HEAD = "Findings placed here"
_T_UNKNOWN_HERE = "UNKNOWN items counted on this box: {n}; see section {section}"
_T_FINDING_HEAD = "{id} {title} -- {severity} {tags}"
_T_EVIDENCE_HTML = "[{role}] {file}:{line}"
_T_ACCEPTED = "Operator-recorded reason: {reason}"
_T_ACCEPTED_RE_REVIEW = (
    "Operator-recorded reason: {reason} (accepted under policy {old}; re-review under {new})"
)
_T_ACCEPTED_MOVED = "recorded at {old}, now reported at {new}"
_T_PLAN = "Plan"
_T_PLAN_HEADERS: tuple[str, ...] = (
    "#",
    "id",
    "severity",
    "mechanism",
    "decision",
    "remediation (removes)",
    "tier",
    "who",
    "status",
)
_T_REMEDIATION = "{summary} (removes {removes})"
_T_WHO_YOU = "you"
_T_STATUS_ACCEPTED = "accepted"
_T_STATUS_STALE = "accepted under an older policy; re-review"
_T_PLAN_NOTE = (
    "Walk the table top-down. Prefer a remediation that removes the objective, the inference "
    "or the intervention over one that adds a filter in front of the person. Re-run the audit "
    "after each change and read document 2: a change is not evidence the finding is gone until "
    "the next run says so."
)
_T_REMAINING = "Remaining actions"
_T_GROUP_OPEN = "Open"
_T_GROUP_RE_REVIEW = "Re-review: the baseline entry was not taken under the current policy"
_T_GROUP_ACCEPTED = "Accepted with a recorded reason"
_T_GROUP_ACCEPTED_ROW = "{id} {title} -- the operator wrote: {reason}"
_T_GROUP_UNKNOWN = "Still UNKNOWN"
_T_INVENTORY_SECTION = "Reports read and inventory counts"
_T_REPORTS_READ = "Evaluation reports read from disk"
_T_REPORT_READ = "{source} -- {kind} {tag}"
_T_INVENTORY_HEAD = "Inventory counts"
_T_FOOTER_GENERATED = "generated by {tool}; the JSON report is authoritative"

# Page chrome. Tokens on `:root`, one dark override; `--warn` is the UNKNOWN box's
# border and nothing else. There is deliberately no `--good`, and no length is a
# percentage: the page prints no percentage anywhere, its stylesheet included.
_CSS = """
:root{--bg:#f7f6f2;--panel:#ffffff;--fg:#1d1d1b;--muted:#5a5955;--rule:#d9d6cd;
--code-bg:#f0eee7;--code-fg:#2a2a27;--infra:#5b6470;--warn:#b7791f;--accent:#2f5d8a;
color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--panel:#1f1f1d;--fg:#e8e6df;
--muted:#a7a49b;--rule:#3a3935;--code-bg:#262523;--code-fg:#e0ddd4;--infra:#9aa3ad;
--warn:#e0a63a;--accent:#8ab4e8}}
html{background:var(--bg);color:var(--fg)}
body{margin:0;font:15px/1.5 -apple-system,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 20px 48px}
h1{font-size:1.5em;margin:.4em 0}
h2{font-size:1.2em;margin:1.6em 0 .5em;border-bottom:1px solid var(--rule);padding-bottom:.2em}
h3{font-size:1.05em;margin:1.2em 0 .4em}
h4{font-size:1em;margin:.8em 0 .3em}
p{margin:.35em 0}
ul,ol{margin:.3em 0 .6em;padding-left:1.4em}
a{color:var(--accent)}
.sub{color:var(--muted);margin:.15em 0}
.take{border-left:4px solid var(--accent);background:var(--panel);padding:10px 14px;margin:1em 0}
.banner{border:1px dashed var(--warn);padding:10px 14px;margin:1em 0}
.fig{background:var(--panel);border:1px solid var(--rule);border-radius:8px;padding:8px;
overflow-x:auto}
.fig svg{display:block;max-width:calc(100vw - 80px);height:auto}
.figcap{color:var(--muted);font-size:.9em}
table{border-collapse:collapse;font-size:.9em;margin:.5em 0}
th,td{border:1px solid var(--rule);padding:4px 8px;text-align:left;vertical-align:top}
code{background:var(--code-bg);color:var(--code-fg);padding:1px 4px;border-radius:3px;
font:.92em ui-monospace,Menlo,Consolas,monospace}
.finding{border:1px solid var(--rule);border-radius:6px;padding:6px 12px;margin:.6em 0;
background:var(--panel)}
.finding h4{margin:.2em 0 .4em}
.status{font:.9em ui-monospace,Menlo,Consolas,monospace;color:var(--muted)}
.svgt{font:600 11.5px -apple-system,"Segoe UI",Helvetica,Arial,sans-serif;fill:var(--fg)}
.svgs{font:10px ui-monospace,Menlo,Consolas,monospace;fill:var(--muted)}
.svgf{font:9px ui-monospace,Menlo,Consolas,monospace;fill:var(--muted)}
.svgm{font:10px ui-monospace,Menlo,Consolas,monospace;fill:var(--fg)}
.svgl{font:11px -apple-system,"Segoe UI",Helvetica,Arial,sans-serif;fill:var(--muted)}
footer{margin-top:2em;border-top:1px solid var(--rule);padding-top:1em;color:var(--muted);
font-size:.9em}
""".strip()

TEMPLATES: tuple[str, ...] = (
    _T_MARKER,
    _T_PAGE_TITLE,
    _T_H1,
    _T_DOC1,
    _T_DOC2,
    _T_HEAD_FACTS,
    _T_COMPARED_NONE,
    _T_COMPARED,
    _T_AGE,
    _T_AGE_UNKNOWN,
    _T_UNIT_DAY,
    _T_UNIT_HOUR,
    _T_UNIT_MINUTE,
    _T_REASONS,
    _T_REASONS_NONE,
    _T_REASONS_REPORT,
    _T_BASELINE_POLICY,
    _T_BASELINE_POLICY_NONE,
    _T_RESOLVED_FAIL_ON,
    _T_RESOLVED_EXCLUDE,
    _T_READ_FIRST,
    _T_ABSENCE,
    _T_UNKNOWN_COUNT,
    _T_BANNER_NO_RULES,
    _T_SINCE,
    _T_WHAT_CHANGED,
    _T_WHAT_LEFT,
    _T_WHAT_UNKNOWN,
    _T_NO_LONGER,
    _T_NO_LONGER_NOTE,
    _T_NO_LONGER_ROW,
    _T_NO_LONGER_UNNAMED,
    _T_NEW_SINCE,
    _T_RE_REVIEW_SINCE,
    _T_STALE_SINCE,
    _T_FINDING_ROW,
    _T_LEFT,
    _T_STILL_UNKNOWN,
    _T_MAP,
    _T_FIG_TITLE,
    _T_FIG_CAPTION,
    _T_ROW_RANGE,
    _T_BOX_STATUS,
    _T_BOX_NOT_ATTRIBUTED,
    _T_BOX_NOT_ATTRIBUTED_LINE,
    _T_MECHANISMS,
    _T_SECTION_STATUS,
    _T_SECTION_STATUS_REST,
    _T_NOT_ATTRIBUTED_TITLE,
    _T_PROHIBITED,
    _T_DISTINCT,
    _T_RULES_OF,
    _T_MORE,
    _T_FINDINGS_HEAD,
    _T_UNKNOWN_HERE,
    _T_FINDING_HEAD,
    _T_EVIDENCE_HTML,
    _T_ACCEPTED,
    _T_ACCEPTED_RE_REVIEW,
    _T_ACCEPTED_MOVED,
    _T_PLAN,
    *_T_PLAN_HEADERS,
    _T_REMEDIATION,
    _T_WHO_YOU,
    _T_STATUS_ACCEPTED,
    _T_STATUS_STALE,
    _T_PLAN_NOTE,
    _T_REMAINING,
    _T_GROUP_OPEN,
    _T_GROUP_RE_REVIEW,
    _T_GROUP_ACCEPTED,
    _T_GROUP_ACCEPTED_ROW,
    _T_GROUP_UNKNOWN,
    _T_INVENTORY_SECTION,
    _T_REPORTS_READ,
    _T_REPORT_READ,
    _T_INVENTORY_HEAD,
    _T_FOOTER_GENERATED,
    _CSS,
)

# ---------------------------------------------------------------------------
# Escaping, clipping, dates
# ---------------------------------------------------------------------------


def _esc(value: Any) -> str:
    """HTML-escape a text node, then encode every non-ASCII character as an entity. Quotes
    stay as they are: a text node needs none of that, and the disclaimer reads verbatim."""
    return _asciify(_html.escape(str(value), quote=False))


def _attr(value: Any) -> str:
    """HTML-escape an attribute value, quotes included, then encode non-ASCII as entities."""
    return _asciify(_html.escape(str(value), quote=True))


def _asciify(text: str) -> str:
    if text.isascii():
        return text
    return "".join(ch if ord(ch) < 128 else f"&#x{ord(ch):x};" for ch in text)


def _cell_width(ch: str) -> int:
    """Two cells for a wide or fullwidth character: a CJK name takes twice the box."""
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def _width(text: str) -> int:
    return sum(_cell_width(ch) for ch in text)


def _clip(text: str, width: int) -> str:
    """
    Shorten to `width` cells for a fixed-width SVG box; a page section is never clipped.
    Measured on the text before `_esc`: the entity a wide character becomes is eight
    ASCII characters on the wire and still one glyph two cells wide on the screen.
    """
    if _width(text) <= width:
        return text
    kept, used, budget = [], 0, max(width - 3, 1)
    for ch in text:
        used += _cell_width(ch)
        if used > budget:
            break
        kept.append(ch)
    return "".join(kept) + "..."


_ISO_Z = "%Y-%m-%dT%H:%M:%SZ"


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        return datetime.strptime(text, _ISO_Z).replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    # 3.10's fromisoformat rejects a trailing Z; the audit's own stamps carry one.
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _age_text(older: Any, newer: Any) -> str:
    """`written N days ago` from two ISO stamps; `age unknown` when either is missing or odd."""
    start, end = _parse_iso(older), _parse_iso(newer)
    if start is None or end is None:
        return _T_AGE_UNKNOWN
    seconds = max(int((end - start).total_seconds()), 0)
    days, hours, minutes = seconds // 86400, seconds // 3600, seconds // 60
    if days >= 1:
        return _T_AGE.format(n=days, unit=_T_UNIT_DAY + _plural(days))
    if hours >= 1:
        return _T_AGE.format(n=hours, unit=_T_UNIT_HOUR + _plural(hours))
    return _T_AGE.format(n=minutes, unit=_T_UNIT_MINUTE + _plural(minutes))


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _gone_entries(block: Mapping[str, Any]) -> list[Any]:
    """The baseline block's `no_longer_reported` list; the block carries no separate count."""
    gone = block.get("no_longer_reported")
    return list(gone) if isinstance(gone, list) else []


# ---------------------------------------------------------------------------
# Placement: findings, UNKNOWN items and rules onto the policy's mechanisms
# ---------------------------------------------------------------------------


@dataclass
class _Box:
    key: str
    title: str
    findings: list[Finding] = field(default_factory=list)
    unknown: int = 0
    ran: int = 0
    total: int = 0
    decision: str = ""
    rules: list[str] = field(default_factory=list)
    prohibited: str = ""
    distinct_from: str = ""


def _ran_count(value: Any, total: int) -> int:
    """The coverage row's `ran` is the list of rule ids that ran; a bool is tolerated."""
    if isinstance(value, bool):
        return total if value else 0
    if isinstance(value, (list, tuple, set, frozenset)):
        return len(value)
    return 0


def _place(report: Report) -> tuple[list[_Box], _Box]:
    """
    One `_Box` per mechanism of the policy, in policy order, from the report's Mechanisms
    table (a hand-built report falls back to the policy), plus the not-attributed box.
    A finding lands on the mechanism it names; a finding or an UNKNOWN item whose rule the
    policy does not place lands on the not-attributed box, never dropped.
    """
    policy = load_policy()
    boxes: dict[str, _Box] = {}
    order: list[_Box] = []
    for row in _mechanism_rows(report):
        mechanism_id = str(row["id"])
        mechanism = policy.mechanism_by_id(mechanism_id)
        rules = [str(r) for r in (row.get("rules") or (mechanism.rules if mechanism else ()))]
        box = _Box(
            key=mechanism_id,
            title=str(row.get("name") or (mechanism.name if mechanism else mechanism_id)),
            decision=str(row.get("decision") or Decision.NOT_ASSESSED.value),
            rules=rules,
            ran=_ran_count(row.get("ran"), len(rules)),
            total=len(rules),
            prohibited=mechanism.prohibited if mechanism else "",
            distinct_from=mechanism.distinct_from if mechanism else "",
        )
        boxes[mechanism_id] = box
        order.append(box)
    rest = _Box(NOT_ATTRIBUTED, _T_NOT_ATTRIBUTED_TITLE)
    by_rule = {
        str(row.get("id")): str(row.get("mechanism") or "")
        for row in (report.rules or ())
        if isinstance(row, dict)
    }

    def key_of(rule_id: str) -> str:
        parent = str(rule_id).split("/", 1)[0]
        mechanism_id = by_rule.get(parent)
        if not mechanism_id:
            mechanism = policy.mechanism_of(parent)
            mechanism_id = mechanism.id if mechanism is not None else ""
        return mechanism_id if mechanism_id in boxes else NOT_ATTRIBUTED

    for finding in report.findings:
        key = finding.mechanism if finding.mechanism in boxes else key_of(finding.id)
        boxes.get(key, rest).findings.append(finding)
    for item in report.unknown:
        rule_ids = tuple(getattr(item, "rule_ids", ()) or ())
        keys = {key_of(str(rule_id)) for rule_id in rule_ids} or {NOT_ATTRIBUTED}
        for key in keys:
            boxes.get(key, rest).unknown += 1
    # Rules the policy does not place are counted on the not-attributed box, so the
    # caption's "k of n rules ran" and the boxes add up.
    for row in report.rules or ():
        entry = row if isinstance(row, dict) else {}
        if key_of(str(entry.get("id") or "")) == NOT_ATTRIBUTED:
            rest.total += 1
            if entry.get("ran"):
                rest.ran += 1
    return order, rest


def _rules_ran(report: Report) -> tuple[int, int]:
    rows = [row for row in (report.rules or ()) if isinstance(row, dict)]
    return sum(1 for row in rows if row.get("ran")), len(rows)


# ---------------------------------------------------------------------------
# Per-finding block
# ---------------------------------------------------------------------------


def _path_part(location: str) -> str:
    """`a/b.py` from a baseline's `a/b.py:12`; a bare path stays as it is."""
    head, sep, tail = location.rpartition(":")
    return head if sep and tail.isdigit() else location


def _accepted_html(finding: Finding, policy_version: str | None) -> str:
    if finding.re_review:
        return _T_ACCEPTED_RE_REVIEW.format(
            reason=finding.accepted_reason,
            old=finding.acceptance_policy_version or _T_UNKNOWN_WORD,
            new=policy_version or finding.policy_version or _T_UNKNOWN_WORD,
        )
    return _T_ACCEPTED.format(reason=finding.accepted_reason)


def _finding_block(
    finding: Finding, accepted_index: dict[str, dict[str, Any]], policy_version: str | None
) -> list[str]:
    """
    One finding: head with tags, the status and decision line, the review record's
    decision, evidence, chain, purpose, population, fix, references, gaps, uncertainty,
    note, then the operator's reason or the re-review marker. The alternatives and the
    known failure modes stay in the JSON and the terminal; a page is navigated, not read
    end to end, and they belong to the rule, not the finding.
    """
    out = [f'<article class="finding" id="f-{_attr(finding.fingerprint)}">']
    head = _T_FINDING_HEAD.format(
        id=finding.display_id,
        title=finding.title,
        severity=Severity(finding.severity).value,
        tags=_tags(finding),
    )
    out.append(f"<h4>{_esc(head)}</h4>")
    out.append(f'<p class="status">{_esc(_status_text(finding))}</p>')
    review = _review_decision_text(finding)
    if review:
        out.append(f'<p class="status">{_esc(review)}</p>')
    if finding.evidence:
        out.append('<ul class="evidence">')
        for evidence in finding.evidence:
            where = _T_EVIDENCE_HTML.format(
                role=evidence.role, file=evidence.file, line=evidence.line
            )
            snippet = redact(str(evidence.snippet))
            out.append(f"<li>{_esc(where)} <code>{_esc(snippet)}</code></li>")
        out.append("</ul>")
    for text in (_chain_text(finding), _purpose_text(finding), _population_text(finding)):
        if text:
            out.append(f'<p class="status">{_esc(text)}</p>')
    out.append(f"<p>{_esc(_fix_text(finding))}</p>")
    if finding.references:
        references = _T_REFERENCES.format(items=", ".join(finding.references))
        out.append(f'<p class="sub">{_esc(references)}</p>')
    for text in (_gaps_text(finding), _uncertainty_text(finding)):
        if text:
            out.append(f'<p class="sub">{_esc(text)}</p>')
    if finding.notes:
        out.append(f'<p class="note">{_esc(_T_NOTE.format(text=finding.notes))}</p>')
    if finding.accepted_reason is not None:
        out.append(f'<p class="accepted">{_esc(_accepted_html(finding, policy_version))}</p>')
        entry = accepted_index.get(finding.fingerprint) or {}
        old = str(entry.get("file") or "")
        file, line = finding.location
        if old and file and _path_part(old) != file:
            moved = _T_ACCEPTED_MOVED.format(old=old, new=f"{file}:{line}")
            out.append(f'<p class="accepted">{_esc(moved)}</p>')
    re_review = _re_review_text(finding, policy_version)
    if re_review:
        out.append(f'<p class="accepted">{_esc(re_review)}</p>')
    out.append("</article>")
    return out


# ---------------------------------------------------------------------------
# The map
# ---------------------------------------------------------------------------

_SVG_W = 960
_BOX_W = 222
_BOX_H = 132
_GAP = 14
_X0 = 12
_ROW_GAP = 30
_ROW1_Y = 34
_STRIP_H = 60
_PER_ROW = 4
_XS = tuple(_X0 + i * (_BOX_W + _GAP) for i in range(_PER_ROW))
# Cells of 9px monospace that fit the box with its padding, and how many name lines.
_NAME_WIDTH = 34
_NAME_LINES = 3
_ROW_ATTRS = 'fill="var(--panel)" stroke="var(--infra)" stroke-width="1.2"'
_UNKNOWN_ATTRS = (
    'fill="var(--panel)" stroke="var(--warn)" stroke-width="1.4" stroke-dasharray="7 5"'
)


def _row_y(index: int) -> int:
    return _ROW1_Y + index * (_BOX_H + _ROW_GAP)


def _wrap_name(name: str) -> list[str]:
    """The mechanism name on up to `_NAME_LINES` box lines; the last one clipped when it overflows."""
    lines = textwrap.wrap(name, _NAME_WIDTH) or [name]
    if len(lines) > _NAME_LINES:
        lines = lines[: _NAME_LINES - 1] + [" ".join(lines[_NAME_LINES - 1 :])]
    return [_clip(line, _NAME_WIDTH) for line in lines]


def _svg_text(x: int, y: int, cls: str, text: str) -> str:
    return f'<text x="{x}" y="{y}" class="{cls}">{_esc(text)}</text>'


def _svg_box(x: int, y: int, box: _Box) -> list[str]:
    out = [f'<rect x="{x}" y="{y}" width="{_BOX_W}" height="{_BOX_H}" rx="10" {_ROW_ATTRS}/>']
    out.append(_svg_text(x + 8, y + 20, "svgt", box.key))
    for i, line in enumerate(_wrap_name(box.title)):
        out.append(_svg_text(x + 8, y + 36 + 14 * i, "svgf", line))
    status = _T_BOX_STATUS.format(n=len(box.findings), m=box.unknown)
    out.append(_svg_text(x + 8, y + 88, "svgm", status))
    out.append(_svg_text(x + 8, y + 104, "svgm", box.decision or _T_DASH))
    out.append(_svg_text(x + 8, y + 120, "svgs", _T_UNMEASURED))
    return out


def _svg(report: Report, boxes: Sequence[_Box], rest: _Box) -> list[str]:
    target = (report.target or {}).get("path") or _T_DASH
    rows = [boxes[i : i + _PER_ROW] for i in range(0, len(boxes), _PER_ROW)]
    strip_y = _row_y(len(rows))
    height = strip_y + _STRIP_H + 14
    out = [
        f'<svg viewBox="0 0 {_SVG_W} {height}" width="940" height="{height * 940 // _SVG_W}" '
        f'role="img" aria-labelledby="fig1-title">',
        f'<title id="fig1-title">{_esc(_T_FIG_TITLE.format(target=target))}</title>',
    ]
    for row_index, row in enumerate(rows):
        y = _row_y(row_index)
        label = _T_ROW_RANGE.format(first=row[0].key, last=row[-1].key)
        out.append(_svg_text(_X0, y - 10, "svgl", label))
        for i, box in enumerate(row):
            out.extend(_svg_box(_XS[i], y, box))
    # The not-attributed strip runs the full width under the mechanism rows.
    out.append(
        f'<rect x="{_X0}" y="{strip_y}" width="{_SVG_W - 2 * _X0}" height="{_STRIP_H}" rx="10" '
        f"{_UNKNOWN_ATTRS}/>"
    )
    out.append(_svg_text(_X0 + 8, strip_y + 22, "svgt", _T_BOX_NOT_ATTRIBUTED))
    line = _T_BOX_NOT_ATTRIBUTED_LINE.format(m=rest.unknown, n=len(rest.findings))
    out.append(_svg_text(_X0 + 8, strip_y + 44, "svgm", f"{line} {_T_UNMEASURED}"))
    out.append("</svg>")
    return out


# ---------------------------------------------------------------------------
# Page sections
# ---------------------------------------------------------------------------


def _numbering(doc2: bool, ran_any: bool) -> dict[str, int]:
    keys: list[str] = []
    if doc2:
        keys.append("since")
    keys += ["map", "mechanisms"]
    if ran_any:
        keys.append("plan")
    if doc2:
        keys.append("remaining")
    keys += ["unknown", "inventory"]
    return {key: i for i, key in enumerate(keys, 1)}


def _h2(number: int, title: str, anchor: str) -> str:
    return f'<h2 id="{anchor}">{number}. {_esc(title)}</h2>'


def _header(report: Report, doc2: bool, tool_label: str, policy_version: str | None) -> list[str]:
    target = (report.target or {}).get("path") or _T_DASH
    dirty = (report.target or {}).get("dirty")
    dirty_text = _T_UNKNOWN_WORD if dirty is None else (_T_YES if dirty else _T_NO)
    summary = _summary_of(report)
    out = [
        '<header class="doc">',
        f"<h1>{_esc(_T_H1.format(target=target))}</h1>",
        f'<p class="sub">{_esc(label_line(report))}</p>',
        f'<p class="sub">{_esc(_T_DOC2 if doc2 else _T_DOC1)}</p>',
        '<p class="sub">'
        + _esc(
            _T_HEAD_FACTS.format(
                sha=(report.target or {}).get("git_sha") or _T_DASH,
                dirty=dirty_text,
                generated_at=report.generated_at,
                tool=tool_label,
                policy=policy_version or _T_UNKNOWN_WORD,
            )
        )
        + "</p>",
    ]
    if not doc2:
        out.append(f'<p class="sub">{_esc(_T_COMPARED_NONE)}</p>')
    else:
        block = report.baseline or {}
        age = _age_text(block.get("generated_at"), report.generated_at)
        compared = _T_COMPARED.format(file=block.get("file") or _T_DASH, age=age)
        accepted = block.get("accepted")
        n = len(accepted) if isinstance(accepted, list) else 0
        if n:
            reasons = _T_REASONS.format(n=n)
        elif block.get("kind") == "audit":
            reasons = _T_REASONS_REPORT
        else:
            reasons = _T_REASONS_NONE
        old = block.get("policy_version")
        policy = _T_BASELINE_POLICY.format(version=old) if old else _T_BASELINE_POLICY_NONE
        out.append(f'<p class="sub">{_esc(compared)}; {_esc(reasons)}; {_esc(policy)}</p>')
    resolved = [_T_RESOLVED_FAIL_ON.format(fail_on=summary.get("fail_on", "low"))]
    exclude = (report.target or {}).get("exclude")
    if isinstance(exclude, (list, tuple)) and exclude:
        resolved.append(_T_RESOLVED_EXCLUDE.format(items=", ".join(str(x) for x in exclude)))
    out.append(f'<p class="sub">{_esc("; ".join(resolved))}</p>')
    out.append("</header>")
    return out


def _read_first(report: Report, numbers: dict[str, int], ran_any: bool) -> list[str]:
    n = len(report.unknown)
    summary = _summary_of(report)
    out = [
        '<div class="take">',
        f"<h4>{_esc(_T_READ_FIRST)}</h4>",
        f"<p>{_esc(report.disclaimer)}</p>",
        f"<p><strong>{_esc(_T_ABSENCE)}</strong></p>",
        "<p>"
        + _esc(_T_UNKNOWN_COUNT.format(n=n, s=_plural(n), section=numbers["unknown"]))
        + "</p>",
        f'<p class="status">{_esc(_T_SEVERITY_LINE.format(items=_severity_items(summary)))}</p>',
        f'<p class="status">{_esc(_T_EVIDENCE_LINE.format(items=_evidence_items(summary)))}</p>',
        f'<p class="status">{_esc(_T_DECISIONS_LINE.format(items=_decision_items(summary)))}</p>',
        "</div>",
    ]
    if not ran_any:
        out.append(f'<div class="banner">{_esc(_T_BANNER_NO_RULES)}</div>')
    return out


def _link(finding: Finding, text: str) -> str:
    return f'<li><a href="#f-{_attr(finding.fingerprint)}">{_esc(text)}</a></li>'


def _row_text(finding: Finding) -> str:
    file, line = finding.location
    where = f"{file}:{line}" if file else finding.scope.name or _T_DASH
    return _T_FINDING_ROW.format(id=finding.display_id, title=finding.title, file=where)


def _since(report: Report, numbers: dict[str, int], open_rows: int) -> list[str]:
    block = report.baseline or {}
    out = [_h2(numbers["since"], _T_SINCE, "since"), f"<h3>{_esc(_T_WHAT_CHANGED)}</h3>"]
    # The block carries no count: `no_longer_reported` is the list, one entry per gone
    # fingerprint, and its length is the number.
    gone = _gone_entries(block)
    out.append(f"<p>{_esc(_T_NO_LONGER.format(n=len(gone)))}</p>")
    if gone:
        out.append("<ul>")
        for entry in gone:
            item = entry if isinstance(entry, dict) else {"fingerprint": entry}
            if item.get("rule"):
                text = _T_NO_LONGER_ROW.format(
                    rule=item.get("rule"),
                    title=item.get("title") or _T_DASH,
                    file=item.get("file") or _T_DASH,
                )
            else:
                text = _T_NO_LONGER_UNNAMED.format(fingerprint=item.get("fingerprint") or _T_DASH)
            out.append(f"<li>{_esc(text)}</li>")
        out.append("</ul>")
        out.append(f'<p class="sub">{_esc(_T_NO_LONGER_NOTE)}</p>')
    groups = (
        (_T_NEW_SINCE, [f for f in report.findings if f.baseline_status == "new"]),
        (_T_RE_REVIEW_SINCE, [f for f in report.findings if f.baseline_status == "re-review"]),
        (_T_STALE_SINCE, [f for f in report.findings if f.re_review and f.accepted_reason]),
    )
    for template, items in groups:
        out.append(f"<p>{_esc(template.format(n=len(items)))}</p>")
        if items:
            out.append("<ul>")
            out.extend(_link(f, _row_text(f)) for f in items)
            out.append("</ul>")
    out.append(f"<h3>{_esc(_T_WHAT_LEFT)}</h3>")
    section = numbers.get("remaining", numbers.get("plan", 0))
    out.append(f"<p>{_esc(_T_LEFT.format(n=open_rows, s=_plural(open_rows), section=section))}</p>")
    out.append(f"<h3>{_esc(_T_WHAT_UNKNOWN)}</h3>")
    k = len(report.unknown)
    out.append(
        f"<p>{_esc(_T_STILL_UNKNOWN.format(n=k, s=_plural(k), section=numbers['unknown']))}</p>"
    )
    return out


def _map(
    report: Report,
    numbers: dict[str, int],
    boxes: Sequence[_Box],
    rest: _Box,
    policy_version: str | None,
) -> list[str]:
    ran, total = _rules_ran(report)
    out = [_h2(numbers["map"], _T_MAP, "map"), '<div class="fig">']
    out.extend(_svg(report, boxes, rest))
    out.append("</div>")
    caption = _T_FIG_CAPTION.format(policy=policy_version or _T_UNKNOWN_WORD, k=ran, total=total)
    out.append(f'<p class="figcap">{_esc(caption)}</p>')
    return out


def _mechanism_section(
    index: str,
    box: _Box,
    numbers: dict[str, int],
    accepted_index: dict[str, dict[str, Any]],
    policy_version: str | None,
) -> list[str]:
    if box.key == NOT_ATTRIBUTED:
        head = f"{index} {_esc(box.title)}"
        status = _T_SECTION_STATUS_REST.format(n=len(box.findings), m=box.unknown)
    else:
        head = f"{index} {_esc(box.key)} {_esc(box.title)}"
        status = _T_SECTION_STATUS.format(
            n=len(box.findings),
            m=box.unknown,
            decision=box.decision or _T_DASH,
            k=box.ran,
            total=box.total,
        )
    out = [
        f'<h3 id="sec-{_attr(box.key)}">{head} '
        f'<span class="status">-- {_esc(status)} {_esc(_T_UNMEASURED)}</span></h3>'
    ]
    # The policy's own words for the mechanism, so the reader judges the findings against
    # the line the policy draws, not against the rule's title.
    if box.prohibited:
        out.append(f'<p class="sub">{_esc(_T_PROHIBITED.format(text=box.prohibited))}</p>')
    if box.distinct_from:
        out.append(f'<p class="sub">{_esc(_T_DISTINCT.format(text=box.distinct_from))}</p>')
    if box.rules:
        out.append(f'<p class="sub">{_esc(_T_RULES_OF.format(items=", ".join(box.rules)))}</p>')
    if box.unknown:
        out.append(
            f'<p class="sub">{_esc(_T_UNKNOWN_HERE.format(n=box.unknown, section=numbers["unknown"]))}</p>'
        )
    out.append(f"<p>{_esc(_T_FINDINGS_HEAD)}</p>")
    if not box.findings:
        out.append(f"<p>{_esc(_T_NONE)}</p>")
    for finding in box.findings[:MAX_FINDINGS_PER_SECTION]:
        out.extend(_finding_block(finding, accepted_index, policy_version))
    if len(box.findings) > MAX_FINDINGS_PER_SECTION:
        rest = len(box.findings) - MAX_FINDINGS_PER_SECTION
        out.append(f"<p>{_esc(_T_MORE.format(n=rest))}</p>")
    return out


def _mechanisms(
    numbers: dict[str, int],
    boxes: Sequence[_Box],
    rest: _Box,
    accepted_index: dict[str, dict[str, Any]],
    policy_version: str | None,
) -> list[str]:
    number = numbers["mechanisms"]
    out = [_h2(number, _T_MECHANISMS, "mechanisms")]
    for i, box in enumerate(boxes, 1):
        out.extend(
            _mechanism_section(f"{number}.{i}", box, numbers, accepted_index, policy_version)
        )
    if rest.findings or rest.unknown:
        out.extend(
            _mechanism_section(
                f"{number}.{len(boxes) + 1}", rest, numbers, accepted_index, policy_version
            )
        )
    return out


def _plan_rows(report: Report) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for n, finding in enumerate(report.findings, 1):
        if finding.accepted_reason is not None:
            status = _T_STATUS_STALE if finding.re_review else _T_STATUS_ACCEPTED
        else:
            status = finding.baseline_status or _T_DASH
        rows.append({"n": n, "finding": finding, "status": status})
    return rows


def _is_open(row: Mapping[str, Any]) -> bool:
    """An accepted row is not work; one accepted under an older policy is (a second look)."""
    return row["status"] != _T_STATUS_ACCEPTED


def _remediation_cell(finding: Finding) -> str:
    rec = finding.recommendation
    if rec.removes:
        return _T_REMEDIATION.format(summary=rec.summary, removes=", ".join(rec.removes))
    return rec.summary


def _plan(numbers: dict[str, int], rows: Sequence[dict[str, Any]]) -> list[str]:
    out = [_h2(numbers["plan"], _T_PLAN, "plan")]
    if not rows:
        out.append(f"<p>{_esc(_T_NONE)}</p>")
    else:
        out.append("<table>")
        out.append("<tr>" + "".join(f"<th>{_esc(h)}</th>" for h in _T_PLAN_HEADERS) + "</tr>")
        for row in rows:
            finding: Finding = row["finding"]
            cells = [
                str(row["n"]),
                f'<a href="#f-{_attr(finding.fingerprint)}">{_esc(finding.display_id)}</a>',
                _esc(Severity(finding.severity).value),
                _esc(finding.mechanism or _T_DASH),
                _esc(Decision(finding.decision).value),
                _esc(_remediation_cell(finding)),
                _esc(finding.recommendation.tier.value),
                _esc(_T_WHO_YOU),
                _esc(row["status"]),
            ]
            out.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
        out.append("</table>")
    out.append(f"<p><strong>{_esc(_T_PLAN_NOTE)}</strong></p>")
    return out


def _remaining(report: Report, numbers: dict[str, int]) -> list[str]:
    out = [_h2(numbers["remaining"], _T_REMAINING, "remaining")]
    findings = list(report.findings)
    open_findings = [f for f in findings if f.accepted_reason is None and not f.re_review]
    re_review = [f for f in findings if f.re_review]
    accepted = [f for f in findings if f.accepted_reason is not None and not f.re_review]

    def group(title: str, items: list[str]) -> None:
        out.append(f"<h3>{_esc(title)}</h3>")
        if not items:
            out.append(f"<p>{_esc(_T_NONE)}</p>")
            return
        out.append("<ul>")
        out.extend(items)
        out.append("</ul>")

    def accepted_row(finding: Finding) -> str:
        return _T_GROUP_ACCEPTED_ROW.format(
            id=finding.display_id, title=finding.title, reason=finding.accepted_reason
        )

    group(_T_GROUP_OPEN, [_link(f, _row_text(f)) for f in open_findings])
    group(
        _T_GROUP_RE_REVIEW,
        [_link(f, accepted_row(f) if f.accepted_reason else _row_text(f)) for f in re_review],
    )
    group(_T_GROUP_ACCEPTED, [_link(f, accepted_row(f)) for f in accepted])
    k = len(report.unknown)
    out.append(f"<h3>{_esc(_T_GROUP_UNKNOWN)}</h3>")
    out.append(
        f"<p>{_esc(_T_STILL_UNKNOWN.format(n=k, s=_plural(k), section=numbers['unknown']))}</p>"
    )
    return out


def _unknown_section(report: Report, numbers: dict[str, int]) -> list[str]:
    out = [_h2(numbers["unknown"], _T_UNKNOWN, "unknown")]
    items: Sequence[UnknownItem] = report.unknown
    if not items:
        out.append(f"<p>{_esc(_T_NONE)}</p>")
        return out
    out.append("<ol>")
    for item in items:
        out.append(f"<li>{_esc(_unknown_head(item))}")
        details = _unknown_detail_lines(item)
        if details:
            out.append("<ul>" + "".join(f"<li>{_esc(d)}</li>" for d in details) + "</ul>")
        out.append("</li>")
    out.append("</ol>")
    return out


def _inventory_section(report: Report, numbers: dict[str, int]) -> list[str]:
    out = [_h2(numbers["inventory"], _T_INVENTORY_SECTION, "inventory")]
    out.append(f"<h3>{_esc(_T_REPORTS_READ)}</h3>")
    reports = [r for r in (report.reports or ()) if isinstance(r, dict)]
    if not reports:
        out.append(f"<p>{_esc(_T_NONE)}</p>")
    else:
        out.append("<ul>")
        for entry in reports:
            age = entry.get("age_days")
            if age is None:
                tag = _T_REPORTED_UNKNOWN
            else:
                tag = _T_REPORTED.format(age=age, source=entry.get("age_source") or _T_UNKNOWN_WORD)
            text = _T_REPORT_READ.format(
                source=entry.get("source") or _T_DASH, kind=entry.get("kind") or _T_DASH, tag=tag
            )
            out.append(f"<li>{_esc(text)}</li>")
        out.append("</ul>")
    out.append(f"<h3>{_esc(_T_INVENTORY_HEAD)}</h3>")
    out.append(
        "<ul>"
        + "".join(f"<li>{_esc(ln)}</li>" for ln in _inventory_lines(report.inventory))
        + "</ul>"
    )
    return out


def _footer(report: Report, tool_label: str) -> list[str]:
    summary = _summary_of(report)
    out = ["<footer>", f"<p>{_esc(_summary_line(summary))}</p>"]
    for line in _baseline_lines(report):
        out.append(f"<p>{_esc(line)}</p>")
    out.append(f"<p>{_esc(_T_EXIT.format(code=summary.get('exit_code')))}</p>")
    out.append(f"<p><strong>{_esc(_T_ABSENCE)}</strong></p>")
    out.append(f"<p>{_esc(_T_FOOTER_GENERATED.format(tool=tool_label))}</p>")
    out.append("</footer>")
    return out


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def render_html(report: Report, quiet: bool = False) -> str:
    """
    The page. `quiet` is accepted so `render()` can pass it through unconditionally and
    ignored: a page is read, not tailed, and every section is always present.
    """
    del quiet
    doc2 = report.baseline is not None
    ran_any = any(isinstance(r, dict) and r.get("ran") for r in (report.rules or ()))
    numbers = _numbering(doc2, ran_any)
    boxes, rest = _place(report)
    block = report.baseline or {}
    accepted_entries = block.get("accepted") if isinstance(block.get("accepted"), list) else []
    accepted_index = {str(e.get("fingerprint")): e for e in accepted_entries if isinstance(e, dict)}
    version = (report.tool or {}).get("version") or tool_version()
    tool_label = f"{DISTRIBUTION} {version}"
    policy_version = _policy_version(report)
    target = (report.target or {}).get("path") or _T_DASH
    rows = _plan_rows(report) if ran_any else []
    open_rows = sum(1 for r in rows if _is_open(r))

    out = [
        _T_MARKER,
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{_esc(_T_PAGE_TITLE.format(target=target))}</title>",
        f'<meta name="aisg-schema" content="{_attr(SCHEMA_VERSION)}">',
        f'<meta name="aisg-tool" content="{_attr(tool_label)}">',
        f"<style>{_CSS}</style>",
        "</head>",
        "<body>",
        "<main>",
    ]
    out.extend(_header(report, doc2, tool_label, policy_version))
    out.extend(_read_first(report, numbers, ran_any))
    if doc2:
        out.extend(_since(report, numbers, open_rows))
    out.extend(_map(report, numbers, boxes, rest, policy_version))
    out.extend(_mechanisms(numbers, boxes, rest, accepted_index, policy_version))
    if ran_any:
        out.extend(_plan(numbers, rows))
    if doc2:
        out.extend(_remaining(report, numbers))
    out.extend(_unknown_section(report, numbers))
    out.extend(_inventory_section(report, numbers))
    out.extend(_footer(report, tool_label))
    out += ["</main>", "</body>", "</html>"]
    # Last line of defence: a stray non-ASCII character in any fixed string becomes an
    # entity too, so the page is ASCII whatever it was built from.
    return _asciify("\n".join(out)) + "\n"
