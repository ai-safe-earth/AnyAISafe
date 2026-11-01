"""src/aisafe/assessment/render.py
--------------------------------
The assessment as Markdown, as one standalone HTML page (no script, no external resource,
ASCII only), and as a terminal summary. The JSON document is authoritative; these read it.

Both files start with the tool's own marker line, so a later walk skips them as the
tool's output. The sections keep the inputs apart, in this order: the outcome, the scope
(what was read and what was not), the ethical outcome per mechanism with the records
behind it, the legal section when profiles were applied, the machine inputs (the scan and
the records), the human inputs (review records), the sign-offs (who decided what, and why),
the auditee's inputs, the remediation check, and the inputs with their hashes. No colour
marks an outcome and no score exists.
"""

from __future__ import annotations

import html as _html
import re
from typing import Any, Iterable

from aisafe.discovery.patterns import OWN_HTML_MARKER_LINE

__all__ = [
    "TEMPLATES",
    "answers_source_line",
    "render_html",
    "render_markdown",
    "render_terminal",
]

# Every character str.splitlines() breaks a line on; CommonMark ends a line at CR or LF.
_LINE_BREAKS = re.compile("[\r\n\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]+")

# What opens a block when it comes first in a list item: a heading, a code fence, a quote,
# a list, a rule or a link definition. Group 2 is the number of an ordered list.
_ITEM_START = re.compile(r"^( *- )\s*(\d+(?=[.)])|(?=[#~>+*_\[-]))")

_T_TITLE = "aisafe assessment"
_T_LABEL = "{label} | mode: {mode}"
_T_FACTS = "target {path} | commit {commit} | policy {policy} | generated {generated_at} | {tool}"
_T_WORKING_TREE = "checked against the working tree, not a commit: {dirty} file(s) differ"
_T_WORKING_TREE_UNKNOWN = (
    "checked against the working tree, not a commit: git could not report which files differ "
    "from the commit (unknown)"
)
_T_DEPLOYMENT = "deployment: {deployment} | configuration: {configuration}"
_T_NOT_RECORDED = "not recorded"
_T_UNREAD = (
    "not read either: {tracked} tracked file(s) the walk skipped, {unsupported} file(s) in a "
    "language this version does not read"
)
_T_UNREAD_NO_GIT = (
    "not read either: {files} file(s) the walk skipped, {dirs} director(ies) it did not go "
    "into (committing the tree gives a precise list), {unsupported} file(s) in a language "
    "this version does not read"
)
_T_OVERALL = "overall ethical outcome: {overall} (the least favourable of the mechanisms)"
_T_ORDER = "outcomes, least favourable first: {order}"
_T_PEOPLE = "investigators: {investigators} | operators: {operators}"
_T_SCOPE = (
    "{surfaces} surfaces in the plan ({high} high); {queued} queued (budget {budget}), "
    "{left_out} left out ({left_out_high} high); {investigated} investigated; "
    "{unsupported} surface(s) in an unsupported language"
)
_T_NOT_READ = (
    "not read: {marker} file(s) skipped by the ignore-file marker, {own} as the tool's own "
    "output, {oversize} over the size limit, {unknown} UNKNOWN item(s) from the scan"
)
_T_MECH_ROW = "{id} {name}: {outcome}"
_T_CLOSED_ON = "closed on {closed} of {of} surface hypotheses carrying it"
_T_GAP = "gap ({kind}): {detail}"
_T_GAP_RECORD = "gap ({kind}, {record}): {detail}"
_T_UNCHALLENGED = "not counted: no skeptic pass upheld {record}"
_T_RECORD = (
    "{id}: {mechanism}/{pattern} on {type} {where} | {status} | {decision} | trace "
    "{trace} | skeptic {skeptic}"
)
_T_LINK = "{kind} ({by}) {file}:{line}: {quote}"
_T_NOTE = "note: {text}"
_T_REJECTED = "rejected: {path}: {errors}"
_T_SCAN_ROW = "{id} {severity} | {evidence_status} | {decision} | {file}:{line}"
_T_REVIEW_RECORD = "{file}: {reviewer}, {reviewed_at}, policy {policy_version}, scope {scope}"
_T_REVIEW_DECISION = "{id} {fingerprint}: {decision} -- {justification}"
_T_HUMAN_NOTE = "Decisions a named person recorded, shown beside the outcome; they never change it."
_T_AUDITEE_NOTE = (
    "What the team being audited said or supplied, shown beside the outcome; it never changes it."
)
_T_SIGNOFF_NOTE = (
    "A sign-off is a person's decision on a record at review or a file nobody read. It clears "
    "those gaps and no other, and never lowers a violation. The tool states who decided."
)
_T_SIGNOFF_LIMIT = (
    "self-assessed: a sign-off file carries no signature, and anyone with write access can "
    "write one"
)
_T_SIGNOFF = "{id}: {by}, {label}, {at}: {reason}"
_T_SIGNOFF_RECORD = "record {id}, sha256 {sha}"
_T_SIGNOFF_FILE = "file {path}, sha256 {sha}"
_T_SIGNOFF_REFUSED = "refused, counts for nothing: {file}: {why}"
_T_SIGNED_NOT_READ = "signed off, not read: {path}: {by} ({label}, sign-off {signoff}): {reason}"
_T_THROUGH_SIGNOFF = "{row} (through sign-off {ids})"
_T_NONE = "(none)"
_T_RETEST = "retest against {file} (commit {commit}, sha256 {sha})"
_T_RETEST_PREVIOUS = "previous assessment: mode {mode}; engagement: {engagement}"
_T_RETEST_ENGAGEMENT = "{auditor} ({organisation}) for {auditee}"
_T_RETEST_SAME = "the previous assessment is of the same commit: nothing changed to retest"
_T_RETEST_ROW = "{record}: {mechanism}/{pattern} {status}"
_T_STEP = "step {id} ({purpose}, {kind}): before {before}, now {now}: {detail}"
_T_INPUT = "{role}: {path} sha256 {sha256}"
_T_FOOTER = "generated by {tool}; the JSON document is authoritative"
_T_LEGAL_NONE = (
    "no legal profile was applied: the legal section needs an engagement with applicability "
    "answers (aisafe engagement init, then --engagement DIR)"
)
_T_UNTRUSTED = "untrusted text: {n} line(s) or file(s) addressed to an auditor or an AI tool"
_T_ENGAGEMENT = (
    "engagement: {auditor} ({organisation}) for {auditee}; independence statement {independence}; "
    "{authorisations} written authorisation(s); commits in scope: {commits}"
)
_T_ENGAGEMENT_OPEN = "engagement fields still to fill in: {fields}"
_T_NO_ENDPOINT = (
    "an evaluation report was read, and no written authorisation names an endpoint (one whose "
    "document changed does not count): nothing here shows the test was authorised"
)
_T_ANSWERS_OWN = "the applicability answers are the auditor's own: answered by {by}"
_T_ANSWERS_NOT_OWN = (
    "the applicability answers are NOT the auditor's own: answered by {by}, and the auditor is "
    "{auditor}; an answer from the audited team can make a whole profile not applicable"
)
_T_ANSWERS_NO_AUDITOR = (
    "whether the applicability answers are the auditor's own is unknown: answered by {by}, and "
    "the engagement names no auditor"
)
_T_ANSWERS_UNNAMED = "the applicability answers name nobody: they decide nothing"
_T_LEGAL_ANSWERS = (
    "audit date {date}; applicability answers by {by} on {on}; jurisdictions selected: "
    "{selected}; roles: {roles}; markets: {markets}"
)
_T_LEGAL_PROFILE = (
    "{title} [{id}, profile v{version}, text checked on {checked_on}, {review}]: "
    "applicability {applicability}"
)
_T_LEGAL_PROVISION = "{citation}: {result} -- {reason}"
_T_LEGAL_COUNTS = "results: {counts}"
_T_LEGAL_REPLACED = "{citation}: replaced by {law} from {when}: {note}"
_T_LEGAL_NOT_SELECTED = "profiles not selected by the engagement: {ids}"
_T_LEGAL_NOT_COVERED = "not covered: {text}"
_T_LEGAL_NOT_COVERED_MANY = "not covered: {n} item(s), see assessment.md"
_T_UNMATCHED = (
    "response {file} answers {to}, which names nothing in this assessment: shown here, placed "
    "nowhere"
)
_T_RESPONSE = "{id} to {to} by {by} ({date}): {text}"
_T_BESIDE = (
    "auditee response {id} to {to} by {by} ({date}), beside the outcome and never changing "
    "it: {text}"
)
_T_EVIDENCE = "evidence request {id} [{status}]: {what} -- {detail}"

TEMPLATES: tuple[str, ...] = (
    _T_TITLE,
    _T_LABEL,
    _T_FACTS,
    _T_WORKING_TREE,
    _T_WORKING_TREE_UNKNOWN,
    _T_DEPLOYMENT,
    _T_NOT_RECORDED,
    _T_UNREAD,
    _T_UNREAD_NO_GIT,
    _T_OVERALL,
    _T_ORDER,
    _T_PEOPLE,
    _T_SCOPE,
    _T_NOT_READ,
    _T_MECH_ROW,
    _T_CLOSED_ON,
    _T_GAP,
    _T_GAP_RECORD,
    _T_UNCHALLENGED,
    _T_RECORD,
    _T_LINK,
    _T_NOTE,
    _T_REJECTED,
    _T_SCAN_ROW,
    _T_REVIEW_RECORD,
    _T_REVIEW_DECISION,
    _T_HUMAN_NOTE,
    _T_AUDITEE_NOTE,
    _T_SIGNOFF_NOTE,
    _T_SIGNOFF_LIMIT,
    _T_SIGNOFF,
    _T_SIGNOFF_RECORD,
    _T_SIGNOFF_FILE,
    _T_SIGNOFF_REFUSED,
    _T_SIGNED_NOT_READ,
    _T_THROUGH_SIGNOFF,
    _T_NONE,
    _T_RETEST,
    _T_RETEST_PREVIOUS,
    _T_RETEST_ENGAGEMENT,
    _T_RETEST_SAME,
    _T_RETEST_ROW,
    _T_STEP,
    _T_INPUT,
    _T_FOOTER,
    _T_LEGAL_NONE,
    _T_UNTRUSTED,
    _T_ENGAGEMENT,
    _T_ENGAGEMENT_OPEN,
    _T_NO_ENDPOINT,
    _T_ANSWERS_OWN,
    _T_ANSWERS_NOT_OWN,
    _T_ANSWERS_NO_AUDITOR,
    _T_ANSWERS_UNNAMED,
    _T_LEGAL_ANSWERS,
    _T_LEGAL_PROFILE,
    _T_LEGAL_PROVISION,
    _T_LEGAL_COUNTS,
    _T_LEGAL_REPLACED,
    _T_LEGAL_NOT_SELECTED,
    _T_LEGAL_NOT_COVERED,
    _T_LEGAL_NOT_COVERED_MANY,
    _T_UNMATCHED,
    _T_RESPONSE,
    _T_BESIDE,
    _T_EVIDENCE,
)

_SECTIONS = (
    "Outcome",
    "Scope",
    "Ethical outcome by mechanism",
    "Legal profiles",
    "Machine inputs: the scan and the investigation records",
    "Human inputs: review records",
    "Sign-offs: a person's decisions",
    "Auditee inputs",
    "Remediation",
    "Inputs",
)


# ---------------------------------------------------------------------------
# The lines, shared by every format
# ---------------------------------------------------------------------------


_CONTROLS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _flat(value: Any) -> str:
    """Text a person or the audited tree supplied, on one line: a line break in it could
    otherwise start a heading or a list item of its own in the Markdown, and an escape
    sequence in a file name could clear or repaint the terminal it is shown on."""
    return _CONTROLS_RE.sub("?", " ".join(str(value if value is not None else "").split()))


def _flat_row(row: dict[str, Any], keys: Iterable[str]) -> dict[str, str]:
    return {k: _flat(row.get(k)) for k in keys}


def _join(items: Iterable[str]) -> str:
    items = [i for i in items if i]
    return ", ".join(items) if items else _T_NONE


def _tool(doc: dict[str, Any]) -> str:
    tool = doc.get("tool") or {}
    return f"{tool.get('name', 'aisafe')} {tool.get('version', 'unknown')}"


def _head(doc: dict[str, Any]) -> list[str]:
    target = doc.get("target") or {}
    lines = [
        _T_LABEL.format(label=doc.get("label"), mode=doc.get("mode")),
        _T_FACTS.format(
            path=target.get("path"),
            commit=target.get("commit") or "none (not a git checkout)",
            policy=(doc.get("policy") or {}).get("version"),
            generated_at=doc.get("generated_at"),
            tool=_tool(doc),
        ),
    ]
    if target.get("working_tree"):
        dirty = target.get("dirty")
        if target.get("status_failed") or dirty is None:
            lines.append(_T_WORKING_TREE_UNKNOWN)
        else:
            lines.append(_T_WORKING_TREE.format(dirty=len(dirty)))
    lines.append(
        _T_DEPLOYMENT.format(
            deployment=_described(target.get("deployment")),
            configuration=_described(target.get("configuration")),
        )
    )
    engagement = doc.get("engagement")
    if engagement:
        auditor = engagement.get("auditor") or {}
        lines.append(
            _T_ENGAGEMENT.format(
                auditor=auditor.get("name") or _T_NOT_RECORDED,
                organisation=auditor.get("organisation") or _T_NOT_RECORDED,
                auditee=(engagement.get("auditee") or {}).get("name") or _T_NOT_RECORDED,
                independence=(
                    "given"
                    if (engagement.get("independence") or {}).get("statement")
                    else "missing"
                ),
                authorisations=len(engagement.get("authorisations") or []),
                commits=_join((engagement.get("scope") or {}).get("commits") or []),
            )
        )
        if engagement.get("to_fill_in"):
            lines.append(
                _T_ENGAGEMENT_OPEN.format(
                    fields=_join(f.split(":")[0] for f in engagement["to_fill_in"])
                )
            )
        if engagement.get("evaluation_endpoint_named") is False:
            lines.append(_T_NO_ENDPOINT)
    people = doc.get("investigators") or []
    lines.append(
        _T_PEOPLE.format(
            investigators=_join(
                f"{p.get('agent')} {p.get('model')} {p.get('version')} ({p.get('role')})"
                for p in people
            ),
            operators=_join(
                f"{p.get('name')}" + (f" ({p.get('role')})" if p.get("role") else "")
                for p in doc.get("operators") or []
            ),
        )
    )
    return lines


def _label(row: dict[str, Any]) -> str:
    return "self-assessed" if row.get("self_assessed", True) else "auditor"


def _described(value: Any) -> str:
    if not value:
        return _T_NOT_RECORDED
    if isinstance(value, dict):
        return ", ".join(f"{k} {v}" for k, v in value.items() if v not in (None, ""))
    return str(value)


def _scope_lines(doc: dict[str, Any]) -> list[str]:
    scope = doc.get("scope") or {}
    plan = scope.get("plan") or {}
    by_priority = plan.get("by_priority") or {}
    unassessed = scope.get("unassessed") or {}
    oversize = unassessed.get("oversize_files")
    unsupported = len(unassessed.get("unsupported_files") or [])
    not_walked = unassessed.get("tracked_not_walked")
    if not_walked is None or (doc.get("target") or {}).get("commit"):
        unread = _T_UNREAD.format(
            tracked="an unknown number of" if not_walked is None else len(not_walked),
            unsupported=unsupported,
        )
    else:
        unread = _T_UNREAD_NO_GIT.format(
            files=len(not_walked),
            dirs=len(unassessed.get("dirs_not_walked") or []),
            unsupported=unsupported,
        )
    signed = [
        _T_SIGNED_NOT_READ.format(
            label=_label(row), **_flat_row(row, ("path", "by", "signoff", "reason"))
        )
        for row in unassessed.get("signed_off_not_read") or []
    ]
    return [
        _T_SCOPE.format(
            surfaces=plan.get("surfaces", 0),
            high=by_priority.get("high", 0),
            queued=plan.get("queued", 0),
            budget=plan.get("budget"),
            left_out=plan.get("left_out", 0),
            left_out_high=plan.get("left_out_high", 0),
            investigated=(scope.get("investigated") or {}).get("surfaces", 0),
            unsupported=plan.get("unsupported", 0),
        ),
        _T_NOT_READ.format(
            marker=len(unassessed.get("marker_skipped") or []),
            own=len(unassessed.get("own_output_skipped") or []),
            oversize="not recorded" if oversize is None else oversize,
            unknown=len(unassessed.get("unknown") or []),
        ),
        unread,
        *signed,
        _T_UNTRUSTED.format(n=len(scope.get("untrusted_text") or [])),
    ]


def _records_by_id(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    machine = doc.get("machine") or {}
    return {r.get("id"): r for r in machine.get("records") or [] if r.get("id")}


def _record_lines(record: dict[str, Any]) -> list[str]:
    surface = record.get("surface") or {}
    where = f"{surface.get('file')}" + (f":{surface.get('line')}" if surface.get("line") else "")
    effective = record.get("effective") or {}
    skeptic = record.get("skeptic") or {}
    lines = [
        _T_RECORD.format(
            id=record.get("id"),
            mechanism=record.get("mechanism"),
            pattern=record.get("pattern"),
            type=surface.get("type"),
            where=where,
            status=effective.get("evidence_status"),
            decision=effective.get("decision"),
            trace="complete" if record.get("complete") else "partial",
            skeptic=skeptic.get("result") + ("" if skeptic.get("bound") else " (not bound)")
            if skeptic.get("claimed") not in (None, "not_run")
            else skeptic.get("result"),
        )
    ]
    for link in record.get("links") or []:
        lines.append(
            "  "
            + _T_LINK.format(
                kind=link.get("kind"),
                by=link.get("established_by"),
                file=link.get("file"),
                line=link.get("line"),
                quote=link.get("quote"),
            )
        )
    for note in record.get("notes") or []:
        lines.append("  " + _T_NOTE.format(text=note))
    for reading in record.get("readings") or []:
        lines.append("  " + _T_NOTE.format(text=reading))
    return lines


def _gap_line(gap: dict[str, Any]) -> str:
    if gap.get("record"):
        return _T_GAP_RECORD.format(
            kind=gap.get("kind"), record=gap.get("record"), detail=gap.get("detail")
        )
    return _T_GAP.format(kind=gap.get("kind"), detail=gap.get("detail"))


def _responses_for(doc: dict[str, Any], mech: dict[str, Any]) -> list[dict[str, Any]]:
    """The auditee's responses that answer this mechanism: named by its id, by a record of
    it or by the fingerprint of one of its findings."""
    refs = {mech.get("id")}
    for key in ("establishing", "closing", "reviews", "unchallenged"):
        refs.update(str(rid).split(" ")[0] for rid in mech.get(key) or [])
    refs.update(row.get("fingerprint") for row in mech.get("scan") or [])
    machine = doc.get("machine") or {}
    refs.update(
        row.get("fingerprint")
        for row in machine.get("scan", {}).get("findings") or []
        if row.get("mechanism") == mech.get("id")
    )
    # Every accepted record: `place_responses` counts them all as matched, so each is placed.
    refs.update(
        row.get("id")
        for row in machine.get("records") or []
        if row.get("mechanism") == mech.get("id")
    )
    return [r for r in (doc.get("auditee") or {}).get("responses") or [] if r.get("to") in refs]


def _mechanism_blocks(doc: dict[str, Any]) -> list[tuple[str, list[str]]]:
    by_id = _records_by_id(doc)
    out = []
    for mech in (doc.get("outcome") or {}).get("mechanisms") or []:
        lines = list(mech.get("basis") or [])
        if mech.get("closed_on"):
            lines.append(_T_CLOSED_ON.format(**mech["closed_on"]))
        for gap in mech.get("gaps") or []:
            lines.append(_gap_line(gap))
        for key in ("establishing", "closing", "reviews", "unchallenged"):
            for rid in mech.get(key) or []:
                record = by_id.get(rid)
                if record is not None:
                    if key == "unchallenged":
                        lines.append(_T_UNCHALLENGED.format(record=rid))
                    lines.extend(_record_lines(record))
        for row in mech.get("scan") or []:
            lines.append(
                _T_SCAN_ROW.format(
                    **{
                        k: row.get(k)
                        for k in ("id", "severity", "evidence_status", "decision", "file", "line")
                    }
                )
            )
        for response in _responses_for(doc, mech):
            lines.append(
                _T_BESIDE.format(**_flat_row(response, ("id", "to", "by", "date", "text")))
            )
        title = _T_MECH_ROW.format(
            id=mech.get("id"), name=mech.get("name"), outcome=mech.get("outcome")
        )
        out.append((title, lines))
    return out


def _machine_lines(doc: dict[str, Any]) -> list[str]:
    machine = doc.get("machine") or {}
    scan = machine.get("scan") or {}
    lines = [
        f"{scan.get('label', 'scan report')}: {len(scan.get('findings') or [])} finding(s), "
        f"{scan.get('unknown', 0)} UNKNOWN item(s); rules {', '.join(scan.get('rules') or [])}"
    ]
    for row in scan.get("findings") or []:
        lines.append(
            _T_SCAN_ROW.format(
                **{
                    k: row.get(k)
                    for k in ("id", "severity", "evidence_status", "decision", "file", "line")
                }
            )
        )
    lines.append(
        f"{len(machine.get('records') or [])} accepted record(s), "
        f"{len(machine.get('superseded') or [])} superseded, {len(machine.get('rejected') or [])} rejected"
    )
    for record in machine.get("rejected") or []:
        lines.append(
            _T_REJECTED.format(
                path=record.get("path"), errors="; ".join(record.get("errors") or [])
            )
        )
    return lines


def _human_lines(doc: dict[str, Any]) -> list[str]:
    human = doc.get("human") or {}
    lines = [_T_HUMAN_NOTE]
    for row in human.get("review_records") or []:
        lines.append(
            _T_REVIEW_RECORD.format(
                file=row.get("file"),
                reviewer=row.get("reviewer"),
                reviewed_at=row.get("reviewed_at"),
                policy_version=row.get("policy_version"),
                scope=", ".join(row.get("scope") or []),
            )
        )
    for row in human.get("review_decisions") or []:
        lines.append(
            _T_REVIEW_DECISION.format(
                **{k: row.get(k) for k in ("id", "fingerprint", "decision", "justification")}
            )
        )
    if len(lines) == 1:
        lines.append(_T_NONE)
    return lines


def _unmatched_lines(doc: dict[str, Any]) -> list[str]:
    auditee = doc.get("auditee") or {}
    to = {row.get("file"): row.get("to") for row in auditee.get("responses") or []}
    return [
        _T_UNMATCHED.format(file=_flat(file), to=_flat(to.get(file)))
        for file in auditee.get("unmatched") or []
    ]


def _signoff_lines(doc: dict[str, Any]) -> list[str]:
    """Who decided what, and why. A refused row shows only what passed its checks."""
    signoffs = doc.get("signoffs") or {}
    accepted = signoffs.get("accepted") or []
    refused = signoffs.get("refused") or []
    if not accepted and not refused:
        return [_T_NONE]
    lines = [_T_SIGNOFF_NOTE]
    if any(row.get("self_assessed", True) for row in accepted):
        lines.append(_T_SIGNOFF_LIMIT)
    for row in accepted:
        lines.append(
            _T_SIGNOFF.format(label=_label(row), **_flat_row(row, ("id", "by", "at", "reason")))
        )
        for item in row.get("records") or []:
            sha = str(item.get("record_sha256"))[:16]
            lines.append("  " + _T_SIGNOFF_RECORD.format(id=_flat(item.get("id")), sha=sha))
        for item in row.get("files") or []:
            sha = str(item.get("sha256"))[:16]
            lines.append("  " + _T_SIGNOFF_FILE.format(path=_flat(item.get("path")), sha=sha))
    for row in refused:
        lines.append(
            _T_SIGNOFF_REFUSED.format(
                file=_flat(row.get("file")), why=_flat("; ".join(row.get("why") or []))
            )
        )
    return lines


def _auditee_lines(doc: dict[str, Any]) -> list[str]:
    auditee = doc.get("auditee") or {}
    lines = [_T_AUDITEE_NOTE]
    for row in auditee.get("responses") or []:
        lines.append(_T_RESPONSE.format(**_flat_row(row, ("id", "to", "by", "date", "text"))))
        if row.get("evidence"):
            lines.append("  evidence named: " + _join(_flat(e) for e in row["evidence"]))
    for row in auditee.get("evidence") or []:
        if not row.get("active", True):
            continue
        lines.append(_T_EVIDENCE.format(**_flat_row(row, ("id", "status", "what", "detail"))))
        for document in row.get("documents") or []:
            lines.append(
                f"  {document.get('path')} sha256 {str(document.get('sha256'))[:16]} "
                f"({document.get('state')})"
            )
    for problem in auditee.get("problems") or []:
        lines.append(f"not read: {_flat(problem)}")
    lines += _unmatched_lines(doc)
    if len(lines) == 1:
        lines.append(_T_NONE)
    return lines


def _previous_engagement(engagement: dict[str, Any] | None) -> str:
    if not engagement:
        return _T_NONE
    auditor = engagement.get("auditor") or {}
    return _T_RETEST_ENGAGEMENT.format(
        auditor=_flat(auditor.get("name")) or _T_NOT_RECORDED,
        organisation=_flat(auditor.get("organisation")) or _T_NOT_RECORDED,
        auditee=_flat((engagement.get("auditee") or {}).get("name")) or _T_NOT_RECORDED,
    )


def _remediation_lines(doc: dict[str, Any]) -> list[str]:
    remediation = doc.get("remediation")
    if not remediation:
        return [_T_NONE]
    prev = remediation.get("previous") or {}
    lines = [
        _T_RETEST.format(
            file=prev.get("file"), commit=prev.get("commit"), sha=(prev.get("sha256") or "")[:16]
        ),
        _T_RETEST_PREVIOUS.format(
            mode=_flat(prev.get("mode")), engagement=_previous_engagement(prev.get("engagement"))
        ),
    ]
    if remediation.get("same_commit"):
        lines.append(_T_RETEST_SAME)
    for row in remediation.get("results") or []:
        lines.append(
            _T_RETEST_ROW.format(
                **{k: row.get(k) for k in ("record", "mechanism", "pattern", "status")}
            )
        )
        for step in row.get("steps") or []:
            lines.append(
                "  "
                + _T_STEP.format(
                    **{k: step.get(k) for k in ("id", "purpose", "kind", "before", "now", "detail")}
                )
            )
        if row.get("not_reported"):
            lines.append(
                "  not reported now (never by itself a remediation): "
                + ", ".join(row["not_reported"])
            )
    lines.append(remediation.get("note") or "")
    return [line for line in lines if line]


def answers_source_line(source: dict[str, Any]) -> str:
    """The line that says whose the applicability answers are (`model.answers_source`), the
    same words in every report format and in `aisafe engagement status`."""
    by, auditor = _flat(source.get("answered_by")), _flat(source.get("auditor"))
    return {
        "auditor": _T_ANSWERS_OWN,
        "not_auditor": _T_ANSWERS_NOT_OWN,
        "no_auditor": _T_ANSWERS_NO_AUDITOR,
    }.get(str(source.get("state")), _T_ANSWERS_UNNAMED).format(by=by, auditor=auditor)


def _legal_lines(doc: dict[str, Any], *, terminal: bool = False) -> list[str]:
    """The legal section: kept apart from the ethical outcome above, one line per provision
    with its result and first reason; the JSON holds every reason and every evidence row. In
    auditor mode its first line says whose the applicability answers are. The terminal shows
    what is not covered on one line per profile: the items, or their count past three."""
    legal = doc.get("legal")
    if not legal:
        return [_T_LEGAL_NONE]
    answers = legal.get("answers") or {}
    source = legal.get("answers_source")
    lines = [
        answers_source_line(source) if source else "",
        str(legal.get("note") or ""),
        _T_LEGAL_ANSWERS.format(
            date=legal.get("audit_date"),
            by=answers.get("answered_by") or _T_NOT_RECORDED,
            on=answers.get("answered_on") or _T_NOT_RECORDED,
            selected=_join(answers.get("jurisdictions") or []),
            roles=_join(answers.get("roles") or []),
            markets=_join(answers.get("markets") or []),
        ),
    ]
    for prof in legal.get("profiles") or []:
        lines.append(
            _T_LEGAL_PROFILE.format(
                title=prof.get("title"),
                id=prof.get("id"),
                version=prof.get("profile_version"),
                checked_on=(prof.get("source") or {}).get("checked_on"),
                review=prof.get("review_status"),
                applicability=prof.get("applicability"),
            )
        )
        for prov in prof.get("provisions") or []:
            reasons = prov.get("reasons") or [""]
            lines.append(
                "  "
                + _T_LEGAL_PROVISION.format(
                    citation=prov.get("citation"), result=prov.get("result"), reason=reasons[0]
                )
            )
            replaced = prov.get("replaced_by")
            if replaced:
                lines.append(
                    "  "
                    + _T_LEGAL_REPLACED.format(
                        citation=prov.get("citation"),
                        law=replaced.get("law"),
                        when=replaced.get("from"),
                        note=replaced.get("note"),
                    )
                )
            ref = f"{prof.get('id')}/{prov.get('id')}"
            for response in (doc.get("auditee") or {}).get("responses") or []:
                if (response.get("resolved_to") or response.get("to")) == ref:
                    lines.append(
                        "  "
                        + _T_BESIDE.format(
                            **_flat_row(response, ("id", "to", "by", "date", "text"))
                        )
                    )
        counts = prof.get("counts") or {}
        lines.append(
            "  "
            + _T_LEGAL_COUNTS.format(
                counts=_join(f"{n} {result}" for result, n in counts.items() if n)
            )
        )
        items = prof.get("not_covered") or []
        if terminal and len(items) > 3:
            lines.append("  " + _T_LEGAL_NOT_COVERED_MANY.format(n=len(items)))
        elif terminal and items:
            lines.append("  " + _T_LEGAL_NOT_COVERED.format(text="; ".join(items)))
        elif not terminal:
            lines += ["  " + _T_LEGAL_NOT_COVERED.format(text=text) for text in items]
    if legal.get("not_selected"):
        lines.append(
            _T_LEGAL_NOT_SELECTED.format(ids=_join(p.get("id") for p in legal["not_selected"]))
        )
    return [line for line in lines if line]


def _input_lines(doc: dict[str, Any]) -> list[str]:
    return [
        _T_INPUT.format(**{k: row.get(k) for k in ("role", "path", "sha256")})
        for row in doc.get("inputs") or []
    ] or [_T_NONE]


def _outcome_lines(doc: dict[str, Any]) -> list[str]:
    outcome = doc.get("outcome") or {}
    lines = [
        _T_OVERALL.format(overall=outcome.get("overall")),
        _T_ORDER.format(order=", ".join(outcome.get("order") or [])),
    ]
    for mech in outcome.get("mechanisms") or []:
        row = _T_MECH_ROW.format(
            id=mech.get("id"), name=mech.get("name"), outcome=mech.get("outcome")
        )
        if mech.get("signoffs"):
            row = _T_THROUGH_SIGNOFF.format(row=row, ids=", ".join(mech["signoffs"]))
        lines.append(row)
    return lines


# ---------------------------------------------------------------------------
# Formats
# ---------------------------------------------------------------------------


def _md(text: str) -> str:
    """Escape a line for Markdown: every line break inside it becomes a space, so text
    from the audited tree or a person can start no heading or list item of its own; a
    backslash is doubled, so none of the escapes here can be cancelled; `&` and `<` become
    entities and backticks are escaped with a backslash, so it can open no HTML comment,
    no raw HTML and no code span; `](` is broken, so it can make no link or image, which
    would hide the text it quotes and could fetch a remote file; and text that comes first
    in a list item cannot open a block inside that item. Elsewhere a `>` alone opens
    nothing, and the blockquote of the disclaimer needs it. A `*`, and a `_` at the edge of
    a word, are escaped so `pkg/__init__.py` stays what it is; a `_` inside a word opens no
    emphasis, so `no_violation_identified` stays unchanged."""
    text = _LINE_BREAKS.sub(" ", text).replace("\\", "\\\\")
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace("`", "\\`")
    text = re.sub(r"\*|(?<![^\W_])_|_(?![^\W_])", lambda m: "\\" + m.group(), text)
    return _ITEM_START.sub(r"\1\2\\", text.replace("](", "]\\("))


def render_markdown(doc: dict[str, Any]) -> str:
    body = _markdown_body(doc)
    return "\n".join([OWN_HTML_MARKER_LINE, *(_md(line) for line in body)]) + "\n"


def _markdown_body(doc: dict[str, Any]) -> list[str]:
    out = [f"# {_T_TITLE}", ""]
    out += [f"{line}  " for line in _head(doc)]
    out += ["", f"> {doc.get('disclaimer')}", ""]
    sections = [
        ("Outcome", _outcome_lines(doc)),
        ("Scope", _scope_lines(doc)),
    ]
    for title, lines in sections:
        out += [f"## {title}", ""] + [f"- {line}" for line in lines] + [""]
    out += ["## Ethical outcome by mechanism", ""]
    for title, lines in _mechanism_blocks(doc):
        out += (
            [f"### {title}", ""]
            + [
                f"- {line}" if not line.startswith("  ") else f"  - {line.strip()}"
                for line in lines
            ]
            + [""]
        )
    for title, lines in (
        ("Legal profiles", _legal_lines(doc)),
        ("Machine inputs: the scan and the investigation records", _machine_lines(doc)),
        ("Human inputs: review records", _human_lines(doc)),
        ("Sign-offs: a person's decisions", _signoff_lines(doc)),
        ("Auditee inputs", _auditee_lines(doc)),
        ("Remediation", _remediation_lines(doc)),
        ("Inputs", _input_lines(doc)),
    ):
        out += (
            [f"## {title}", ""]
            + [
                f"- {line}" if not line.startswith("  ") else f"  - {line.strip()}"
                for line in lines
            ]
            + [""]
        )
    out.append(_T_FOOTER.format(tool=_tool(doc)))
    return out


def _esc(value: Any) -> str:
    text = _html.escape(str(value), quote=False)
    return text.encode("ascii", "xmlcharrefreplace").decode("ascii")


def render_html(doc: dict[str, Any]) -> str:
    from aisafe.reporting.html import _CSS

    def ul(lines: list[str]) -> list[str]:
        items = []
        for line in lines:
            if line.startswith("  "):
                items.append(f'<li class="sub">{_esc(line.strip())}</li>')
            else:
                items.append(f"<li>{_esc(line)}</li>")
        return ["<ul>", *items, "</ul>"]

    out = [
        OWN_HTML_MARKER_LINE,
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{_esc(_T_TITLE)}: {_esc((doc.get('target') or {}).get('path'))}</title>",
        f"<style>{_CSS}</style>",
        "</head>",
        "<body>",
        "<main>",
        '<header class="doc">',
        f"<h1>{_esc(_T_TITLE)}</h1>",
        *[f'<p class="sub">{_esc(line)}</p>' for line in _head(doc)],
        f'<p class="take">{_esc(doc.get("disclaimer"))}</p>',
        "</header>",
    ]
    number = 0
    for title, lines in (("Outcome", _outcome_lines(doc)), ("Scope", _scope_lines(doc))):
        number += 1
        out += [f"<h2>{number}. {_esc(title)}</h2>", *ul(lines)]
    number += 1
    out.append(f"<h2>{number}. {_esc('Ethical outcome by mechanism')}</h2>")
    for title, lines in _mechanism_blocks(doc):
        out += ['<section class="finding">', f"<h3>{_esc(title)}</h3>", *ul(lines), "</section>"]
    for title, lines in (
        ("Legal profiles", _legal_lines(doc)),
        ("Machine inputs: the scan and the investigation records", _machine_lines(doc)),
        ("Human inputs: review records", _human_lines(doc)),
        ("Sign-offs: a person's decisions", _signoff_lines(doc)),
        ("Auditee inputs", _auditee_lines(doc)),
        ("Remediation", _remediation_lines(doc)),
        ("Inputs", _input_lines(doc)),
    ):
        number += 1
        out += [f"<h2>{number}. {_esc(title)}</h2>", *ul(lines)]
    out += [
        "<footer>",
        f"<p>{_esc(_T_FOOTER.format(tool=_tool(doc)))}</p>",
        "</footer>",
        "</main>",
        "</body>",
        "</html>",
    ]
    return "\n".join(out) + "\n"


def render_terminal(doc: dict[str, Any]) -> str:
    out = [_T_TITLE, "=" * len(_T_TITLE)]
    out += _head(doc)
    out += [doc.get("disclaimer") or "", ""]
    out += _outcome_lines(doc)
    out.append("")
    out += _scope_lines(doc)
    for mech in (doc.get("outcome") or {}).get("mechanisms") or []:
        gaps = mech.get("gaps") or []
        if gaps:
            out.append("")
            out.append(f"{mech.get('id')}: {len(gaps)} gap(s)")
            for gap in gaps[:8]:
                out.append("  " + _gap_line(gap))
            if len(gaps) > 8:
                out.append(f"  +{len(gaps) - 8} more in the JSON")
    rejected = (doc.get("machine") or {}).get("rejected") or []
    if rejected:
        out.append("")
        for record in rejected:
            out.append(
                _T_REJECTED.format(
                    path=record.get("path"), errors="; ".join(record.get("errors") or [])
                )
            )
    signoffs = doc.get("signoffs") or {}
    if signoffs.get("accepted") or signoffs.get("refused"):
        out.append("")
        out += _signoff_lines(doc)
    if doc.get("remediation"):
        out.append("")
        out += _remediation_lines(doc)
    if doc.get("legal"):
        out.append("")
        out.append("Legal profiles (apart from the ethical outcome; not legal advice)")
        out += _legal_lines(doc, terminal=True)
    unmatched = _unmatched_lines(doc)
    if unmatched:
        out.append("")
        out.append("Auditee inputs")
        out += unmatched
    out.append("")
    out.append(f"exit code: {doc.get('exit_code')}")
    return "\n".join(out) + "\n"
