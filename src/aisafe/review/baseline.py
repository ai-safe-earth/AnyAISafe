"""src/aisafe/review/baseline.py
-----------------------------
Fingerprint baseline for `aisafe audit`: load, write, amend and diff. Only `new` and
`re-review` findings count toward the exit code; `unchanged` ones are still rendered,
still findings.

A baseline may carry an `accepted` list next to `fingerprints`: one entry per fingerprint
that a human looked at, with the reason it stays. `load_baseline` validates the list (a
reason is mandatory, and the fingerprint must also be in `fingerprints`) but returns the
same set either way: a fingerprint without a reason is a suppression, not an acceptance,
and the committed `audit-baseline.json` is held to the stricter shape by its own test.

The policy decides what a finding means, so a baseline records the policy version it was
written under (`policy_version`) and every accepted entry records the version it was
accepted under. When the policy moves on, an old baseline cannot stand in for the new
decisions, and `diff()` says so instead of staying silent:

- a fingerprint listed WITHOUT a reason (a suppression) is `unchanged` only while the
  baseline's `policy_version` equals the current one; under any other version (or none)
  the finding is `re-review`, counts toward the exit code like a new finding, and the
  summary counts it under `re_review`;
- a fingerprint listed WITH a reason (an acceptance) stays `unchanged` and uncounted, but
  when the entry's `policy_version` (or the document's, when the entry has none) is older
  than the current policy, the finding is marked `re_review` with the version it was
  accepted under, and the summary counts it under `stale_acceptances`.

A baseline written by this version also carries a trailing `index`: `{fingerprint: {rule,
file, title}}`, so a later run can name a fingerprint it no longer reports, and
`amend_baseline` can fill `rule`/`file` for an accepted entry without re-scanning. Older
files without the index still load; they simply yield less detail.

A reason is checked on the way in (`amend_baseline`, the one writer that takes free text
from the operator) and again on the way out (`read_baseline`, so a hand-edited file is held
to the same bar): it must be non-empty, a single line in any alphabet (no newline, tab,
control or hidden character: it is rendered as one `accepted: <reason>` line), carry
no verdict language (the `report.BANNED_PHRASES` list and the banned word) and contain
nothing secret-shaped, because the baseline file is itself scanned by the audit and would
otherwise reproduce the finding it accepts.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from aisafe.evidence.model import SCHEMA_VERSION, Finding, Report, now_iso, redact
from aisafe.policy import load_policy

__all__ = [
    "BASELINE_KIND",
    "REPORT_KIND",
    "STATUS_NEW",
    "STATUS_RE_REVIEW",
    "STATUS_UNCHANGED",
    "BaselineDiff",
    "BaselineDocument",
    "BaselineError",
    "amend_baseline",
    "diff",
    "load_accepted",
    "load_baseline",
    "load_generated_at",
    "load_index",
    "load_policy_version",
    "parse_accept",
    "read_baseline",
    "write_baseline",
]

BASELINE_KIND = "audit-baseline"
REPORT_KIND = "audit"
TOOL_NAME = "aisafe-audit"

# The three values `Finding.baseline_status` takes after a diff.
STATUS_NEW = "new"
STATUS_UNCHANGED = "unchanged"
STATUS_RE_REVIEW = "re-review"

# The one word the audit never says about a target. Built from fragments so this module
# does not carry it as a literal; the same construction is pinned in the report tests.
_BANNED_WORD_RE = re.compile(r"\bcl" + r"ean\b", re.IGNORECASE)

# Control characters (below space, plus DEL): ASCII, but not a single printable line.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

_INDEX_FIELDS = ("rule", "file", "title")


class BaselineError(Exception):
    """A baseline file that cannot be used. The message is a single line; main maps it to exit 2."""


def _read_document(path: Path) -> dict[str, Any]:
    """Parse `path` as a JSON object with the audit schema; anything else is a BaselineError."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
        raise BaselineError(f"baseline {path.as_posix()}: {reason}") from exc
    except (UnicodeDecodeError, ValueError) as exc:
        # A file in another encoding is a baseline error like any other, not a traceback
        # class name on stderr.
        raise BaselineError(f"baseline {path.as_posix()}: not UTF-8 ({exc})") from exc
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BaselineError(
            f"baseline {path.as_posix()}: invalid JSON ({exc.msg} at line {exc.lineno})"
        ) from exc
    except ValueError as exc:
        raise BaselineError(f"baseline {path.as_posix()}: invalid JSON ({exc})") from exc
    if not isinstance(doc, dict):
        raise BaselineError(f"baseline {path.as_posix()}: top level is not a JSON object")
    schema = doc.get("schema")
    if schema != SCHEMA_VERSION:
        raise BaselineError(
            f"baseline {path.as_posix()}: schema {schema!r} is not {SCHEMA_VERSION!r}"
        )
    return doc


def _version_text(value: Any, where: str, path: Path) -> str | None:
    """A policy version as written, `None` when absent; anything but a string is refused."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise BaselineError(f"baseline {path.as_posix()}: {where} is not a string")
    text = value.strip()
    return text or None


def _validate_accepted(
    doc: dict[str, Any], fingerprints: set[str], path: Path, doc_version: str | None
) -> tuple[dict[str, str], dict[str, str | None]]:
    """
    Check the optional `accepted` list and return `({fingerprint: reason}, {fingerprint:
    policy_version})`.

    Every entry needs a non-empty `reason` that `_check_reason` would have let in, and a
    `fingerprint` that is also listed under `fingerprints`; the error names the offending
    fingerprint so it can be found in the file. The version an acceptance was taken under
    is the entry's own `policy_version` when the key is present (`null` records that no
    policy version was known when it was taken, and stays `None`), else the document's
    `policy_version` (an older file stamps only the document). An absent `accepted` key is
    fine (a `--write-baseline` document without reasons has none).
    """
    raw = doc.get("accepted")
    if raw is None:
        return {}, {}
    if not isinstance(raw, list):
        raise BaselineError(f"baseline {path.as_posix()}: 'accepted' is not a list")
    reasons: dict[str, str] = {}
    versions: dict[str, str | None] = {}
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise BaselineError(
                f"baseline {path.as_posix()}: accepted entry #{index} is not an object"
            )
        fingerprint = entry.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            raise BaselineError(
                f"baseline {path.as_posix()}: accepted entry #{index} has no fingerprint"
            )
        reason = entry.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise BaselineError(
                f"baseline {path.as_posix()}: accepted entry {fingerprint} has no reason"
            )
        if fingerprint not in fingerprints:
            raise BaselineError(
                f"baseline {path.as_posix()}: accepted entry {fingerprint} is not in 'fingerprints'"
            )
        # The same bar as `--accept`: a reason edited by hand into the file is no exception.
        try:
            reasons[fingerprint] = _check_reason(fingerprint, reason)
        except BaselineError as exc:
            raise BaselineError(f"baseline {path.as_posix()}: {exc}") from None
        if "policy_version" in entry:
            versions[fingerprint] = _version_text(
                entry.get("policy_version"), f"accepted entry {fingerprint} policy_version", path
            )
        else:
            versions[fingerprint] = doc_version
    return reasons, versions


def _validate_index(doc: dict[str, Any], path: Path) -> dict[str, dict[str, Any]]:
    """
    The optional `index` block as `{fingerprint: {rule, file, title}}`. Absent means an older
    file and yields `{}`; present but malformed is a BaselineError. Only the three named
    fields are kept, each a string or `None`.
    """
    raw = doc.get("index")
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise BaselineError(f"baseline {path.as_posix()}: 'index' is not an object")
    index: dict[str, dict[str, Any]] = {}
    for fingerprint, entry in raw.items():
        if not isinstance(fingerprint, str) or not fingerprint:
            raise BaselineError(f"baseline {path.as_posix()}: index key is not a fingerprint")
        if not isinstance(entry, dict):
            raise BaselineError(
                f"baseline {path.as_posix()}: index entry {fingerprint} is not an object"
            )
        index[fingerprint] = {
            name: entry.get(name) if isinstance(entry.get(name), str) else None
            for name in _INDEX_FIELDS
        }
    return index


@dataclass
class BaselineDocument:
    """
    A parsed baseline (or full report used as one). `accepted` and `index` are empty for a
    report and for an older baseline file; `generated_at` is `None` when the file has none.
    `policy_version` is the version the document was written under (a report's `policy`
    block supplies it), `None` for a file that predates versioned baselines.
    `accepted_versions` holds each accepted entry's own `policy_version` (`None` when the
    entry has none). `raw` is the parsed JSON, kept so `amend_baseline` can rewrite what it
    did not touch.
    """

    kind: str
    fingerprints: set[str]
    accepted: dict[str, str] = field(default_factory=dict)
    accepted_versions: dict[str, str | None] = field(default_factory=dict)
    index: dict[str, dict[str, Any]] = field(default_factory=dict)
    generated_at: str | None = None
    policy_version: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


def read_baseline(path: Path) -> BaselineDocument:
    """
    Read and validate a baseline file or a full audit report, once.

    Accepts `{"schema": "aisg/1", "kind": "audit-baseline", "fingerprints": [...]}` (with an
    optional `policy_version`, an optional `accepted` list and `index` block, all validated)
    or `{"schema": "aisg/1", "kind": "audit", "findings": [{"fingerprint": ...}, ...]}`.
    Anything else raises `BaselineError` with a one-line reason.
    """
    path = Path(path)
    doc = _read_document(path)
    kind = doc.get("kind")
    policy_version: str | None
    if kind == BASELINE_KIND:
        raw = doc.get("fingerprints")
        if not isinstance(raw, list):
            raise BaselineError(f"baseline {path.as_posix()}: 'fingerprints' is not a list")
        candidates: list[Any] = raw
        policy_version = _version_text(doc.get("policy_version"), "'policy_version'", path)
    elif kind == REPORT_KIND:
        findings = doc.get("findings")
        if not isinstance(findings, list):
            raise BaselineError(f"baseline {path.as_posix()}: 'findings' is not a list")
        candidates = [f.get("fingerprint") for f in findings if isinstance(f, dict)]
        policy_block = doc.get("policy") if isinstance(doc.get("policy"), dict) else {}
        policy_version = _version_text(policy_block.get("version"), "'policy.version'", path)
    else:
        raise BaselineError(
            f"baseline {path.as_posix()}: kind {kind!r} is neither "
            f"{BASELINE_KIND!r} nor {REPORT_KIND!r}"
        )
    fingerprints: set[str] = set()
    for value in candidates:
        if not isinstance(value, str) or not value:
            raise BaselineError(
                f"baseline {path.as_posix()}: every fingerprint must be a non-empty string"
            )
        fingerprints.add(value)
    generated_at = doc.get("generated_at")
    result = BaselineDocument(
        kind=str(kind),
        fingerprints=fingerprints,
        generated_at=generated_at if isinstance(generated_at, str) else None,
        policy_version=policy_version,
        raw=doc,
    )
    if kind == BASELINE_KIND:
        result.accepted, result.accepted_versions = _validate_accepted(
            doc, fingerprints, path, policy_version
        )
        result.index = _validate_index(doc, path)
    return result


def load_baseline(path: Path) -> set[str]:
    """The fingerprint set of a baseline file or a full audit report (see `read_baseline`)."""
    return read_baseline(path).fingerprints


def load_accepted(path: Path) -> dict[str, str]:
    """
    `{fingerprint: reason}` from a baseline file's `accepted` list, after the same validation
    `load_baseline` applies. A full audit report, or a baseline without the list, yields `{}`.
    """
    return read_baseline(path).accepted


def load_index(path: Path) -> dict[str, dict[str, Any]]:
    """`{fingerprint: {rule, file, title}}` from a baseline's `index`; `{}` for a report or an older file."""
    return read_baseline(path).index


def load_generated_at(path: Path) -> str | None:
    """The `generated_at` string of a baseline file or report, or `None` when it has none."""
    return read_baseline(path).generated_at


def load_policy_version(path: Path) -> str | None:
    """The policy version a baseline (or report) was written under, or `None` when unrecorded."""
    return read_baseline(path).policy_version


def _findings_of(report_or_findings: Report | Iterable[Finding]) -> list[Finding]:
    if isinstance(report_or_findings, Report):
        return list(report_or_findings.findings)
    return list(report_or_findings)


def _fingerprints_of(findings: Iterable[Finding]) -> list[str]:
    return sorted({f.fingerprint for f in findings if f.fingerprint})


def _tool_block(report_or_findings: Report | Iterable[Finding]) -> dict[str, Any]:
    if isinstance(report_or_findings, Report) and report_or_findings.tool:
        return dict(report_or_findings.tool)
    # Local import: report.py imports BaselineDiff from here, so the dependency is
    # resolved at call time to keep the version lookup in one place.
    from aisafe.reporting.report import tool_version

    return {"name": TOOL_NAME, "version": tool_version()}


def _current_policy_version(
    report_or_findings: Report | Iterable[Finding] | None, policy_version: str | None
) -> str:
    """The version to write: the caller's, else the report's `policy` block, else the packaged policy."""
    if policy_version:
        return str(policy_version)
    if isinstance(report_or_findings, Report) and isinstance(report_or_findings.policy, dict):
        version = report_or_findings.policy.get("version")
        if version:
            return str(version)
    return load_policy().version


def _location_of(finding: Finding) -> str:
    """`file:line` of the first evidence entry; the scope name for a finding without one."""
    if finding.evidence:
        file, line = finding.location
        return f"{file}:{line}"
    return finding.scope.name or ""


def _index_of(findings: Iterable[Finding]) -> dict[str, dict[str, str]]:
    """
    The `index` block: rule (display id), file (`file:line`) and title per fingerprint, from
    the first finding that carries it, keyed in the same sorted order as `fingerprints`.
    """
    first: dict[str, Finding] = {}
    for finding in findings:
        if finding.fingerprint and finding.fingerprint not in first:
            first[finding.fingerprint] = finding
    return {
        fingerprint: {
            "rule": finding.display_id,
            "file": _location_of(finding),
            "title": finding.title,
        }
        for fingerprint, finding in sorted(first.items())
    }


def _accepted_of(
    findings: Iterable[Finding],
    reasons: Mapping[str, str],
    policy_version: str,
    accepted_versions: Mapping[str, str | None] | None = None,
) -> list[dict[str, Any]]:
    """
    One `accepted` entry per reason, in the order the findings were given (a report's order
    when a report was passed), taken from the first finding that carries the fingerprint.
    Each is stamped with the policy version the acceptance was taken under: the version
    `accepted_versions` carries for it when the caller copies the reason over from an
    earlier baseline (a refresh is not a second look, so a carried acceptance keeps its
    version, and one taken under no recorded policy is written as an explicit `null`, so
    the refreshed document's own stamp never claims it), else `policy_version`, the
    version of now. A reason for a fingerprint no finding carries, or
    an empty reason, is a `BaselineError`: the document it would produce could not be
    loaded back.
    """
    for fingerprint, reason in reasons.items():
        if not isinstance(reason, str) or not reason.strip():
            raise BaselineError(f"baseline: accepted entry {fingerprint} has no reason")
    accepted: list[dict[str, Any]] = []
    pending = set(reasons)
    for finding in findings:
        if finding.fingerprint not in pending:
            continue
        pending.discard(finding.fingerprint)
        entry: dict[str, Any] = {
            "fingerprint": finding.fingerprint,
            "rule": finding.display_id,
            "file": _location_of(finding),
            "reason": reasons[finding.fingerprint],
        }
        if accepted_versions is not None and finding.fingerprint in accepted_versions:
            carried = accepted_versions[finding.fingerprint]
            entry["policy_version"] = str(carried) if carried else None
        else:
            entry["policy_version"] = policy_version
        accepted.append(entry)
    if pending:
        missing = ", ".join(sorted(pending))
        raise BaselineError(f"baseline: accepted entry {missing} matches no finding in this run")
    return accepted


def _dump(doc: dict[str, Any], path: Path) -> None:
    # Like the audit's `_write_output`: the parent is created (`.aisafe-audit/` usually
    # does not exist on the first run, and the scan and the render are already done by
    # now), and LF on every platform, because a baseline is committed and a Windows write
    # must not turn into a whole-file diff on the next Linux refresh.
    target = Path(path)
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(doc, indent=2, ensure_ascii=True) + "\n")


def write_baseline(
    report_or_findings: Report | Iterable[Finding],
    path: Path,
    reasons: Mapping[str, str] | None = None,
    policy_version: str | None = None,
    accepted_versions: Mapping[str, str | None] | None = None,
) -> None:
    """
    Write the baseline document: schema, kind, generated_at, tool, policy_version,
    fingerprints (sorted, unique), then, when `reasons` (`{fingerprint: reason}`) is given,
    an `accepted` list with `rule` (display id), `file` (`file:line` of the first evidence)
    and `policy_version` per reason, and last the `index` block naming every fingerprint's
    rule, file and title. `policy_version` defaults to the report's policy block, else the
    packaged policy's version.

    A reason given here is stamped with that version, like one given to `amend_baseline`.
    A reason carried over from an earlier baseline (a `--write-baseline` refresh) is not a
    new acceptance: pass the earlier document's `accepted_versions` and each carried entry
    keeps the version it was accepted under, so a refresh never turns a stale acceptance
    into a current one behind the operator's back.
    """
    findings = _findings_of(report_or_findings)
    version = _current_policy_version(report_or_findings, policy_version)
    doc: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "kind": BASELINE_KIND,
        "generated_at": now_iso(),
        "tool": _tool_block(report_or_findings),
        "policy_version": version,
        "fingerprints": _fingerprints_of(findings),
    }
    if reasons is not None:
        doc["accepted"] = _accepted_of(findings, reasons, version, accepted_versions)
    doc["index"] = _index_of(findings)
    _dump(doc, Path(path))


# ---------------------------------------------------------------------------
# Amend: record a reason for a fingerprint the baseline already carries
# ---------------------------------------------------------------------------


def parse_accept(text: str) -> tuple[str, str]:
    """
    Split one `--accept FINGERPRINT=REASON` argument on its first `=`. The fingerprint must
    be non-empty; the reason is validated later by `amend_baseline`, where the file is known.
    """
    fingerprint, sep, reason = str(text).partition("=")
    fingerprint = fingerprint.strip()
    if not sep or not fingerprint:
        raise BaselineError(f"--accept expects FINGERPRINT=REASON, got {text!r}")
    return fingerprint, reason.strip()


def _check_reason(fingerprint: str, reason: str) -> str:
    """
    The reason as it will be written, or a `BaselineError` saying why it cannot be. A reason
    says why a finding stays; it never says the finding is fine, and it never carries the
    secret it may be about, because the baseline file is scanned by the audit too.
    """
    # Local import: report.py imports BaselineDiff from this module.
    from aisafe.reporting.report import BANNED_PHRASES

    text = reason.strip()
    if not text:
        raise BaselineError(f"accepted reason for {fingerprint} is empty")
    if _CONTROL_RE.search(text):
        # The reason is rendered as one `accepted: <reason>` line in the terminal and
        # markdown reports (a newline there breaks out of the markdown list item).
        raise BaselineError(f"accepted reason for {fingerprint} must be a single line")
    # Local import: the same check a review record's text passes, in any alphabet.
    from aisafe.review.records import check_text

    problem = check_text(f"accepted reason for {fingerprint}", text)
    if problem:
        raise BaselineError(problem)
    lowered = text.lower()
    if _BANNED_WORD_RE.search(text) or any(phrase in lowered for phrase in BANNED_PHRASES):
        raise BaselineError(
            f"accepted reason for {fingerprint} reads as a verdict; a reason says why the "
            "finding stays, not that the target is safe"
        )
    if redact(text) != text:
        raise BaselineError(
            f"accepted reason for {fingerprint} contains a secret-shaped token; the baseline "
            "file is scanned by the audit and would report it"
        )
    return text


def amend_baseline(
    path: Path, accepts: Mapping[str, str], policy_version: str | None = None
) -> int:
    """
    Record `accepts` (`{fingerprint: reason}`) in the baseline at `path` and rewrite it in
    the pinned key order. Returns the number of reasons recorded.

    Refused with `BaselineError`: a file that is not `kind: audit-baseline` (a report cannot
    carry acceptances), a fingerprint the file does not list, and any reason `_check_reason`
    rejects. An existing entry for the same fingerprint has its reason replaced in place;
    a new entry is appended with `rule`/`file` from the `index` (or `None` when the file
    predates the index). Every entry named in `accepts` is stamped with the current policy
    version (`policy_version`, else the packaged policy's): a reason given now is an
    acceptance under the policy of now. Entries not named keep the version they had, and
    the document's own `policy_version` is left as it was (absent stays absent: this call
    did not re-run the audit under the current policy). Nothing is written until every
    accept has passed.
    """
    path = Path(path)
    document = read_baseline(path)
    if document.kind != BASELINE_KIND:
        raise BaselineError(
            f"baseline {path.as_posix()}: kind {document.kind!r} cannot be amended; "
            f"only {BASELINE_KIND!r} carries accepted reasons"
        )
    if not accepts:
        raise BaselineError(f"baseline {path.as_posix()}: nothing to accept")
    checked: dict[str, str] = {}
    for fingerprint, reason in accepts.items():
        if fingerprint not in document.fingerprints:
            raise BaselineError(
                f"baseline {path.as_posix()}: fingerprint {fingerprint} is not in 'fingerprints'; "
                "run the audit with --write-baseline first"
            )
        checked[fingerprint] = _check_reason(fingerprint, str(reason))
    current = _current_policy_version(None, policy_version)

    raw = document.raw
    existing = raw.get("accepted") if isinstance(raw.get("accepted"), list) else []
    accepted: list[dict[str, Any]] = []
    for entry in existing:
        fingerprint = entry["fingerprint"]
        replaced = fingerprint in checked
        accepted.append(
            {
                "fingerprint": fingerprint,
                "rule": entry.get("rule"),
                "file": entry.get("file"),
                "reason": checked.get(fingerprint, entry["reason"]),
                "policy_version": current if replaced else entry.get("policy_version"),
            }
        )
    present = {entry["fingerprint"] for entry in accepted}
    for fingerprint, reason in checked.items():
        if fingerprint in present:
            continue
        named = document.index.get(fingerprint, {})
        accepted.append(
            {
                "fingerprint": fingerprint,
                "rule": named.get("rule"),
                "file": named.get("file"),
                "reason": reason,
                "policy_version": current,
            }
        )

    doc: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "kind": BASELINE_KIND,
        "generated_at": raw.get("generated_at"),
        "tool": raw.get("tool"),
    }
    if "policy_version" in raw:
        doc["policy_version"] = raw["policy_version"]
    doc["fingerprints"] = sorted(document.fingerprints)
    doc["accepted"] = accepted
    if "index" in raw:
        doc["index"] = raw["index"]
    _dump(doc, path)
    return len(checked)


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------


@dataclass
class BaselineDiff:
    """
    Findings partitioned against a baseline. `new` is what the baseline does not list;
    `unchanged` what it lists and still stands; `re_review` what it suppressed (listed
    without a reason) under another policy version, which counts like `new`;
    `stale_acceptances` the accepted findings whose acceptance predates the current policy
    (still `unchanged`, marked for a second look). `gone` holds the baseline fingerprints no
    finding carries any more; `no_longer_reported` names each of them (rule, file, title)
    when the baseline's `index` knows them. Neither is called "fixed" anywhere: a rename or
    a move produces the same absence. `accepted` lists the baseline's reasons that matched
    a finding in this run. `kind` is the compared document's kind (`audit-baseline` or
    `audit`): a report used as a baseline carries no reasons, and a renderer says so rather
    than "none recorded". `policy_version` is the baseline's own; `current_policy_version`
    the one this run decided under.

    `to_dict` carries no count for `gone`: the list is `no_longer_reported`, one entry per
    fingerprint, and its length is the count. `re_review` and `stale_acceptances` are ints.
    """

    new: list[Finding] = field(default_factory=list)
    gone: list[str] = field(default_factory=list)
    unchanged: list[Finding] = field(default_factory=list)
    file: str = ""
    accepted: list[dict[str, Any]] = field(default_factory=list)
    generated_at: str | None = None
    no_longer_reported: list[dict[str, Any]] = field(default_factory=list)
    kind: str | None = None
    re_review: list[Finding] = field(default_factory=list)
    stale_acceptances: list[Finding] = field(default_factory=list)
    policy_version: str | None = None
    current_policy_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "kind": self.kind,
            "new": len(self.new),
            "unchanged": len(self.unchanged),
            "re_review": len(self.re_review),
            "stale_acceptances": len(self.stale_acceptances),
            "accepted": [dict(entry) for entry in self.accepted],
            "generated_at": self.generated_at,
            "policy_version": self.policy_version,
            "no_longer_reported": [dict(entry) for entry in self.no_longer_reported],
        }


def _named(fingerprint: str, index: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    entry = index.get(fingerprint)
    if not entry:
        return {"fingerprint": fingerprint}
    return {"fingerprint": fingerprint, **{name: entry.get(name) for name in _INDEX_FIELDS}}


def _version_key(text: str) -> tuple[int, ...] | None:
    """`"1.2.0"` as `(1, 2, 0)`; `None` when a component is not a number."""
    parts = re.split(r"[.\-+]", text.strip())
    key: list[int] = []
    for part in parts:
        if not part.isdigit():
            return None
        key.append(int(part))
    return tuple(key)


def _older(version: str | None, current: str) -> bool:
    """
    `version` predates `current`. An unrecorded version does (nothing says it was taken
    under the current policy); equal strings do not; numeric versions compare as numbers
    (`1.0` and `1.0.0` are the same); a pair that does not parse is older when it differs.
    """
    if version is None:
        return True
    if version == current:
        return False
    a, b = _version_key(version), _version_key(current)
    if a is None or b is None:
        return True
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) < b + (0,) * (width - len(b))


def diff(
    findings: Iterable[Finding],
    baseline: set[str] | BaselineDocument,
    file: str,
    *,
    accepted: Mapping[str, str] | None = None,
    index: Mapping[str, Mapping[str, Any]] | None = None,
    generated_at: str | None = None,
    kind: str | None = None,
    policy_version: str | None = None,
    baseline_policy_version: str | None = None,
    accepted_versions: Mapping[str, str | None] | None = None,
) -> BaselineDiff:
    """
    Partition `findings` into new/unchanged/re-review by fingerprint and set
    `Finding.baseline_status` in place. Fingerprints in the baseline that no finding
    carries any more are `gone`.

    `baseline` is the fingerprint set, or the whole `BaselineDocument`, in which case
    `accepted`, `index`, `generated_at`, `kind`, `baseline_policy_version` and
    `accepted_versions` are read from it unless given explicitly.

    `policy_version` is the version this run decided under; it defaults to the packaged
    policy's, so the check is never silently off. A fingerprint listed without a reason
    stays `unchanged` only when the baseline's own `policy_version` equals it; otherwise
    the finding is `re-review` (`re_review = True`), counts toward the exit code like
    `new`, and is listed in `BaselineDiff.re_review`. A caller that passes a bare
    fingerprint set and no `baseline_policy_version` has told the diff nothing about the
    baseline's policy, so every suppression in it re-reviews; pass the document.

    With `accepted` (`{fingerprint: reason}`), every finding whose fingerprint has a reason
    gets `Finding.accepted_reason` and stays `unchanged`; `acceptance_policy_version` is
    the entry's version (else the document's). When that version is older than
    `policy_version` the finding is marked `re_review = True` and listed in
    `stale_acceptances`. The diff's `accepted` list carries one entry per such finding
    (rule/file from `index` when the baseline names them, else from the finding). `index`
    also names the gone fingerprints in `no_longer_reported`.
    """
    if policy_version is None:
        policy_version = load_policy().version
    if isinstance(baseline, BaselineDocument):
        fingerprints = set(baseline.fingerprints)
        accepted = baseline.accepted if accepted is None else accepted
        index = baseline.index if index is None else index
        generated_at = baseline.generated_at if generated_at is None else generated_at
        kind = baseline.kind if kind is None else kind
        if baseline_policy_version is None:
            baseline_policy_version = baseline.policy_version
        if accepted_versions is None:
            accepted_versions = baseline.accepted_versions
    else:
        fingerprints = set(baseline)
    reasons = dict(accepted or {})
    versions = dict(accepted_versions or {})
    named = index or {}
    result = BaselineDiff(
        file=str(file).replace("\\", "/"),
        generated_at=generated_at,
        kind=kind,
        policy_version=baseline_policy_version,
        current_policy_version=policy_version,
    )
    # A suppression stands only under the policy that wrote it; a baseline that recorded
    # no version (or one the caller did not pass on) has not shown it was that policy.
    suppression_stands = baseline_policy_version == policy_version
    seen: set[str] = set()
    listed: set[str] = set()
    for finding in findings:
        seen.add(finding.fingerprint)
        reason = reasons.get(finding.fingerprint)
        if finding.fingerprint not in fingerprints:
            finding.baseline_status = STATUS_NEW
            result.new.append(finding)
        elif reason is None and not suppression_stands:
            finding.baseline_status = STATUS_RE_REVIEW
            finding.re_review = True
            result.re_review.append(finding)
        else:
            finding.baseline_status = STATUS_UNCHANGED
            result.unchanged.append(finding)
            # A carried fingerprint with no reason is a suppression nobody signed.
            finding.suppressed = reason is None
        if reason is None:
            continue
        finding.accepted_reason = reason
        accepted_under = versions.get(finding.fingerprint, baseline_policy_version)
        finding.acceptance_policy_version = accepted_under
        if _older(accepted_under, policy_version):
            finding.re_review = True
            result.stale_acceptances.append(finding)
        if finding.fingerprint in listed:
            continue
        listed.add(finding.fingerprint)
        entry = named.get(finding.fingerprint) or {}
        result.accepted.append(
            {
                "fingerprint": finding.fingerprint,
                "rule": entry.get("rule") or finding.display_id,
                "file": entry.get("file") or _location_of(finding),
                "reason": reason,
                "policy_version": accepted_under,
            }
        )
    result.gone = sorted(fingerprints - seen)
    result.no_longer_reported = [_named(fingerprint, named) for fingerprint in result.gone]
    return result
