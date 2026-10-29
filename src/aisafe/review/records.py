"""src/aisafe/review/records.py
-----------------------------
The review record: who read the prompts and the code around them, when, which files they
read (bound by content hash), which mechanisms of the policy they considered, what purpose
they declare for the system, and the contextual decisions they recorded on findings.

    aisafe-review.yaml        at the audited root; `.aisafe/review.yaml` and
                              `.aisafe-audit/review.yaml` are found too; `--review-record
                              PATH` overrides all three

    review = find_records(root, files, override)       # never raises
    review.errors                                      # one line per problem; the audit
                                                       # turns each into UNKNOWN (runtime)
    record.covers(unit_id, relpath)                    # does the record speak for the file?
    record.is_stale(hash_fn, today, max_age_days)      # reasons, or [] when fresh and bound
    record.decision_for(fingerprint)                   # a person's contextual decision

Honesty rules this module carries:

- A record binds a person's name to exact artifact versions. A hash that no longer
  matches makes the record stale for that artifact; the audit says which one and why. An
  old review is never presented as a current one.
- A malformed record covers nothing. Every problem is one line in `errors`, never an
  exception and never a half-trusted record.
- The free text a person writes (reviewer, purpose, justification, notes) is held to the
  baseline's bar: printable ASCII, no verdict language, nothing secret-shaped. A record
  says who reviewed what; it never says the system is fine.
- The reviewer is a person. A tool that helped is named in `assisted_by` and nowhere else.

`aisafe review init|record|check` lives in `aisafe.review.cli`; this module is the schema
both the command and the audit read.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable, Iterable, Mapping, Sequence

import yaml

from aisafe.evidence.model import SCHEMA_VERSION, ArtifactRef, UnknownCategory, UnknownItem, redact
from aisafe.policy import Policy, PolicyError, load_policy

__all__ = [
    "DEFAULT_RECORD_FILE",
    "PLACEHOLDER",
    "RECORD_CANDIDATES",
    "RECORD_KEYS",
    "REVIEW_KIND",
    "ReviewDecision",
    "ReviewRecord",
    "ReviewSet",
    "check_text",
    "dump_document",
    "find_records",
    "load_record_file",
    "main",
    "parse_date",
    "parse_review_document",
    "record_document",
    "relative_to_root",
    "version_older",
]

REVIEW_KIND = "review"
DEFAULT_RECORD_FILE = "aisafe-review.yaml"
# Looked up in this order at the audited root. The first one found is the record file.
RECORD_CANDIDATES: tuple[str, ...] = (
    DEFAULT_RECORD_FILE,
    ".aisafe/review.yaml",
    ".aisafe-audit/review.yaml",
)
# What `aisafe review init` writes where a person has to type something. A record that
# still carries it is incomplete, and incomplete covers nothing.
PLACEHOLDER = "TODO"
# The keys of one entry under `reviews`, in the order the file is written.
RECORD_KEYS: tuple[str, ...] = (
    "reviewer",
    "assisted_by",
    "reviewed_at",
    "units",
    "scope",
    "declared_purpose",
    "affected_population",
    "artifacts",
    "decisions",
    "notes",
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# A finding fingerprint is sixteen hex characters (evidence.model.fingerprint).
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{16}$")
# Control characters (below space, plus DEL): ASCII, but not a printable line.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
# The same, with the newline allowed: `notes` may run over several lines.
_CONTROL_MULTILINE_RE = re.compile(r"[\x00-\x09\x0b-\x1f\x7f]")
# The one word the audit never says about a target. Built from fragments so this module
# does not carry it as a literal; the baseline and the report tests use the same shape.
_BANNED_WORD_RE = re.compile(r"\bcl" + r"ean\b", re.IGNORECASE)
# The report module's list, assembled the same way, for the moment its import fails (a
# partial checkout). Kept equal to `aisafe.reporting.report.BANNED_PHRASES` by a test.
_FALLBACK_PHRASES: tuple[str, ...] = tuple(
    " ".join(words)
    for words in (
        ("is", "compliant"),
        ("compliance", "verified"),
        ("certi" + "fied",),
        ("meets", "the", "requirements"),
        ("fully", "compliant"),
        ("passes", "the", "eu"),
        ("nist", "compliant"),
        ("compliant",),
    )
)


def _banned_phrases() -> tuple[str, ...]:
    # Imported on use: the report module imports the baseline, which sits in this package.
    # Any failure of that import (a missing module, or whatever a half-migrated renderer
    # raises while loading) falls back to the copy: reading a record never depends on a
    # renderer loading.
    try:
        from aisafe.reporting.report import BANNED_PHRASES
    except Exception:  # broad on purpose: see above
        return _FALLBACK_PHRASES
    return tuple(BANNED_PHRASES)


def _posix(path: Any) -> str:
    """A relative path as the walk spells it: forward slashes, no `.` segments, no repeated
    or leading or trailing slashes. `""` and `"/"` pass through unchanged. A listed
    artifact and the finding's file have to compare equal however a person typed the
    path, or a reviewed file reads as uncovered."""
    text = str(path).replace("\\", "/").strip()
    if text in ("", "/"):
        return text
    # PurePosixPath drops `.` segments and collapses repeated slashes; it keeps `..`,
    # which the artifact check refuses on its own.
    out = PurePosixPath(text).as_posix().strip("/")
    return "" if out == "." else out


# ---------------------------------------------------------------------------
# Field checks
# ---------------------------------------------------------------------------


_TOOL_NAME_RE = re.compile(
    r"^(?:an?\s+)?(?:claude|chatgpt|gpt(?:-?[\w.]+)?|gemini|copilot|codex|llama|mistral|cursor"
    r"|openai|anthropic|llm|ai|a\.i\.|model|language\s+model|bot|chatbot|assistant|agent"
    r"|ai\s+(?:assistant|agent|model|reviewer)|the\s+(?:model|tool|agent|assistant))\s*$",
    re.IGNORECASE,
)


def tool_name_problem(reviewer: Any) -> str | None:
    """
    Why `reviewer` cannot be the person who reviewed: the name part (before any `<role>`)
    is a model, a tool or a generic word for one. A tool that helped belongs in
    `assisted_by`; the reviewer is a person, by name. None when the name passes.
    """
    if not isinstance(reviewer, str):
        return None
    name = reviewer.split("<", 1)[0].strip().strip("\"'")
    if _TOOL_NAME_RE.match(name):
        return (
            f"reviewer {reviewer.strip()!r} names a tool, not a person; the reviewer is the "
            "person who read the artifacts (name and role), and a tool that helped is named "
            "in assisted_by"
        )
    return None


def check_text(label: str, value: Any, *, multiline: bool = False) -> str | None:
    """
    The baseline's reason checks applied to one free-text field: non-empty, not the
    placeholder, printable ASCII (one line unless `multiline`), no verdict language, no
    secret-shaped token. None when the text passes, else one line saying why not. The
    record file sits in the audited tree and is scanned like any other, so a secret in it
    would be reported, and a verdict in it would say what the tool never says.
    """
    if value is None or (isinstance(value, str) and not value.strip()):
        return f"{label} is empty"
    if not isinstance(value, str):
        return f"{label} must be a string"
    text = value.strip()
    if text.upper() == PLACEHOLDER:
        return f"{label} is the placeholder {PLACEHOLDER}"
    if not text.isascii():
        return f"{label} is not ASCII"
    if (_CONTROL_MULTILINE_RE if multiline else _CONTROL_RE).search(text):
        shape = "printable ASCII" if multiline else "a single line of printable ASCII"
        return f"{label} must be {shape}"
    lowered = text.lower()
    if _BANNED_WORD_RE.search(text) or any(phrase in lowered for phrase in _banned_phrases()):
        return (
            f"{label} reads as a verdict; a record says who reviewed what, "
            "not that the system is fine"
        )
    if redact(text) != text:
        return (
            f"{label} contains a secret-shaped token; the record is scanned by the audit "
            "and would report it"
        )
    return None


def parse_date(value: Any) -> date | None:
    """A `date` from what YAML gives us: a date, a datetime, or an ISO string. None otherwise."""
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            if "T" in text or " " in text:
                return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
            return date.fromisoformat(text)
        except ValueError:
            return None
    return None


def _version_key(version: str | None) -> tuple[int, ...] | None:
    if not version:
        return None
    parts = str(version).strip().split(".")
    try:
        return tuple(int(part) for part in parts)
    except ValueError:
        return None


def version_older(version: str | None, current: str) -> bool:
    """True when `version` predates `current` (dotted integers), or is missing, or cannot be
    compared and differs. A record decided under no known policy is due for re-review."""
    if version is None or not str(version).strip():
        return True
    mine, theirs = _version_key(version), _version_key(current)
    if mine is None or theirs is None:
        return str(version).strip() != str(current).strip()
    return mine < theirs


def relative_to_root(path: Path | str, root: Path | str) -> str:
    """The POSIX path of `path` relative to `root` when it lies under it, else as given."""
    try:
        return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except (ValueError, OSError):
        return Path(path).as_posix()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReviewDecision:
    """A person's contextual decision on one finding, with their reason. A decision never
    hides the finding; `no_violation_identified_in_scope` is shown next to it, and
    `violates_policy` from a record upgrades the finding's decision."""

    fingerprint: str
    decision: str
    justification: str

    def to_dict(self) -> dict[str, str]:
        return {
            "fingerprint": self.fingerprint,
            "decision": self.decision,
            "justification": self.justification,
        }


@dataclass(frozen=True)
class ReviewRecord:
    """One entry under `reviews`, validated. See the module docstring for what each field is."""

    reviewer: str
    reviewed_at: date | None
    scope: tuple[str, ...]
    declared_purpose: str
    affected_population: str | None = None
    artifacts: tuple[ArtifactRef, ...] = ()
    units: tuple[str, ...] = ()
    decisions: tuple[ReviewDecision, ...] = ()
    notes: str | None = None
    assisted_by: str | None = None
    source_file: str = DEFAULT_RECORD_FILE
    policy_version: str | None = None
    # Position in the file's `reviews` list, for messages ("record 2: ...").
    index: int = 0

    @property
    def artifact_paths(self) -> frozenset[str]:
        return frozenset(ref.file for ref in self.artifacts)

    @property
    def reviewed_at_iso(self) -> str | None:
        return None if self.reviewed_at is None else self.reviewed_at.isoformat()

    def covers(self, unit_id: str | None, relpath: str | None = None) -> bool:
        """
        Whether this record speaks for a file in a unit. The unit has to be one the record
        names in `units` (any unit when it names none). With a `relpath`, the file also has
        to be a listed artifact: the binding is by hash, so a file the reviewer did not
        list was not reviewed, whatever unit it sits in. Without a `relpath`, a record that
        names no units answers for every unit; a caller that wants "the units the
        artifacts fall in" passes each file.
        """
        if self.units and unit_id not in self.units:
            return False
        return relpath is None or _posix(relpath) in self.artifact_paths

    def is_stale(
        self,
        hash_fn: Callable[[str], str | None],
        today: date,
        max_age_days: int,
    ) -> list[str]:
        """
        Why the record no longer stands, one reason per line; [] when every listed artifact
        still hashes to what the reviewer read and the review is within `max_age_days`.
        `hash_fn(relpath)` returns the current sha256, or None when the file is not there.
        """
        reasons: list[str] = []
        for ref in self.artifacts:
            digest = hash_fn(ref.file)
            if digest is None:
                reasons.append(f"artifact {ref.file} is missing")
            elif str(digest).lower() != ref.sha256:
                reasons.append(f"artifact {ref.file} changed since the review")
        if isinstance(today, datetime):
            today = today.date()
        if self.reviewed_at is None:
            reasons.append("reviewed_at is missing")
        elif self.reviewed_at > today:
            # A date in the future would never age out; it cannot be a review that happened.
            reasons.append(
                f"reviewed_at {self.reviewed_at_iso} is after today ({today.isoformat()})"
            )
        elif (today - self.reviewed_at).days > int(max_age_days):
            reasons.append(
                f"reviewed_at {self.reviewed_at_iso} is older than {int(max_age_days)} days"
            )
        return reasons

    def decision_for(self, fingerprint: str) -> ReviewDecision | None:
        wanted = str(fingerprint).strip().lower()
        for decision in self.decisions:
            if decision.fingerprint == wanted:
                return decision
        return None

    def policy_outdated(self, current_version: str) -> bool:
        """The record was decided under an older policy than `current_version` (or none)."""
        return version_older(self.policy_version, current_version)

    def to_inventory(self) -> dict[str, Any]:
        """The `review_records[]` row of the inventory: who, when, under which policy, how
        many artifacts, which mechanisms. The text fields stay in the file."""
        return {
            "file": self.source_file,
            "reviewer": self.reviewer,
            "reviewed_at": self.reviewed_at_iso,
            "policy_version": self.policy_version,
            "artifacts": len(self.artifacts),
            "scope": list(self.scope),
        }

    def to_document(self) -> dict[str, Any]:
        """The entry as the file spells it (plain values), for re-emission by `dump_document`."""
        return {
            "reviewer": self.reviewer,
            "assisted_by": self.assisted_by,
            "reviewed_at": self.reviewed_at,
            "units": list(self.units),
            "scope": list(self.scope),
            "declared_purpose": self.declared_purpose,
            "affected_population": self.affected_population,
            "artifacts": [{"path": ref.file, "sha256": ref.sha256} for ref in self.artifacts],
            "decisions": [decision.to_dict() for decision in self.decisions],
            "notes": self.notes,
        }


@dataclass
class ReviewSet:
    """What `find_records` found: the valid records of the one record file, the file's path
    (None when none exists), every problem as one line, and the file's policy version."""

    records: list[ReviewRecord] = field(default_factory=list)
    file: str | None = None
    errors: list[str] = field(default_factory=list)
    policy_version: str | None = None

    @property
    def found(self) -> bool:
        return self.file is not None

    def covering(self, unit_id: str | None, relpath: str | None = None) -> list[ReviewRecord]:
        return [record for record in self.records if record.covers(unit_id, relpath)]

    def decision_for(self, fingerprint: str) -> ReviewDecision | None:
        for record in self.records:
            decision = record.decision_for(fingerprint)
            if decision is not None:
                return decision
        return None

    def declared_purpose_for(self, unit_id: str | None, relpath: str | None = None) -> str | None:
        for record in self.covering(unit_id, relpath):
            if record.declared_purpose.strip():
                return record.declared_purpose.strip()
        return None

    def unknown_items(self) -> list[UnknownItem]:
        """One UNKNOWN (runtime) item per error: a record the audit could not use is a gap
        in what it knows, never a silent skip."""
        what = f"review record {self.file}" if self.file else "review record"
        return [
            UnknownItem(
                category=UnknownCategory.RUNTIME,
                what=what,
                why=error,
                how_to_resolve="fix the record, or rewrite it with `aisafe review record`",
                file=self.file,
                rule_ids=("AUD-1107",),
            )
            for error in self.errors
        ]

    def to_inventory(self) -> list[dict[str, Any]]:
        return [record.to_inventory() for record in self.records]


# ---------------------------------------------------------------------------
# Parsing and validation
# ---------------------------------------------------------------------------


def _optional_text(raw: Mapping[str, Any], key: str, where: str, errors: list[str]) -> str | None:
    value = raw.get(key)
    if value is None:
        return None
    problem = check_text(f"{where}.{key}", value, multiline=(key == "notes"))
    if problem:
        errors.append(problem)
        return None
    return str(value).strip()


def _parse_scope(raw: Any, where: str, policy: Policy, errors: list[str]) -> tuple[str, ...]:
    ids = [mechanism.id for mechanism in policy.mechanisms]
    valid = ", ".join(ids)
    if not isinstance(raw, list) or not raw:
        errors.append(f"{where}.scope must be a non-empty list of mechanism ids ({valid})")
        return ()
    chosen: list[str] = []
    unknown: list[str] = []
    for item in raw:
        mechanism_id = str(item).strip().upper()
        if mechanism_id in ids:
            if mechanism_id not in chosen:
                chosen.append(mechanism_id)
        else:
            unknown.append(str(item))
    if unknown:
        errors.append(
            f"{where}.scope names unknown mechanism ids {', '.join(unknown)}; valid ids are {valid}"
        )
    return tuple(sorted(chosen, key=ids.index))


def _parse_units(raw: Any, where: str, errors: list[str]) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        errors.append(f"{where}.units must be a list of unit ids")
        return ()
    units: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{where}.units holds an empty or non-string unit id")
            continue
        if item.strip() not in units:
            units.append(item.strip())
    return tuple(units)


def _parse_artifacts(raw: Any, where: str, errors: list[str]) -> tuple[ArtifactRef, ...]:
    if not isinstance(raw, list) or not raw:
        errors.append(f"{where}.artifacts must be a non-empty list of {{path, sha256}} entries")
        return ()
    refs: list[ArtifactRef] = []
    seen: set[str] = set()
    for index, entry in enumerate(raw):
        label = f"{where}.artifacts[{index}]"
        if not isinstance(entry, Mapping):
            errors.append(f"{label} is not a mapping with path and sha256")
            continue
        path_raw = entry.get("path", entry.get("file"))
        if not isinstance(path_raw, str) or not path_raw.strip():
            errors.append(f"{label}.path is empty")
            continue
        # Checked on both path flavours before normalising: `/etc/x` is not absolute to
        # Windows and `C:/x` is not absolute to POSIX, and the hash is taken under the root.
        # A drive-relative `C:x` is absolute to neither, yet `root / "C:x"` leaves the root
        # on Windows, so any drive letter is refused too.
        given = path_raw.strip().replace("\\", "/")
        path = _posix(path_raw)
        if (
            PurePosixPath(given).is_absolute()
            or PureWindowsPath(given).is_absolute()
            or PureWindowsPath(given).drive
            or given.startswith("~")
            or ".." in path.split("/")
        ):
            errors.append(f"{label}.path {path_raw!r} must be relative to the audited root")
            continue
        digest = entry.get("sha256")
        digest_text = str(digest).strip().lower() if digest is not None else ""
        if not _SHA256_RE.match(digest_text):
            errors.append(f"{label}.sha256 for {path} is not a 64-character hex sha256")
            continue
        if path in seen:
            errors.append(f"{where}.artifacts lists {path} twice")
            continue
        seen.add(path)
        refs.append(ArtifactRef(file=path, sha256=digest_text))
    return tuple(refs)


def _parse_decisions(
    raw: Any, where: str, policy: Policy, errors: list[str]
) -> tuple[ReviewDecision, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        errors.append(f"{where}.decisions must be a list")
        return ()
    valid = ", ".join(policy.decisions)
    out: list[ReviewDecision] = []
    seen: set[str] = set()
    for index, entry in enumerate(raw):
        label = f"{where}.decisions[{index}]"
        if not isinstance(entry, Mapping):
            errors.append(f"{label} is not a mapping with fingerprint, decision and justification")
            continue
        fingerprint = str(entry.get("fingerprint") or "").strip().lower()
        if not _FINGERPRINT_RE.match(fingerprint):
            errors.append(f"{label}.fingerprint is not a 16-character hex finding fingerprint")
            continue
        decision = str(entry.get("decision") or "").strip()
        if decision not in policy.decisions:
            errors.append(f"{label}.decision {decision!r} is not one of {valid}")
            continue
        # A decision without a reason is a suppression, not a decision (the same rule the
        # baseline applies to an accepted finding).
        problem = check_text(f"{label}.justification", entry.get("justification"))
        if problem:
            errors.append(problem)
            continue
        if fingerprint in seen:
            errors.append(f"{where}.decisions records {fingerprint} twice")
            continue
        seen.add(fingerprint)
        out.append(ReviewDecision(fingerprint, decision, str(entry["justification"]).strip()))
    return tuple(out)


def _parse_record(
    raw: Any,
    where: str,
    policy: Policy,
    policy_version: str | None,
    source_file: str,
    index: int,
) -> tuple[ReviewRecord | None, list[str]]:
    errors: list[str] = []
    if not isinstance(raw, Mapping):
        return None, [f"{where} is not a mapping"]
    problem = check_text(f"{where}.reviewer", raw.get("reviewer")) or tool_name_problem(
        raw.get("reviewer")
    )
    if problem:
        errors.append(problem)
    assisted_by = _optional_text(raw, "assisted_by", where, errors)
    reviewed_at: date | None = None
    if raw.get("reviewed_at") is None:
        errors.append(
            f"{where}.reviewed_at is missing; complete the record with `aisafe review record`"
        )
    else:
        reviewed_at = parse_date(raw.get("reviewed_at"))
        if reviewed_at is None:
            errors.append(f"{where}.reviewed_at is not an ISO date (YYYY-MM-DD)")
    units = _parse_units(raw.get("units"), where, errors)
    scope = _parse_scope(raw.get("scope"), where, policy, errors)
    problem = check_text(f"{where}.declared_purpose", raw.get("declared_purpose"))
    if problem:
        errors.append(problem)
    affected = _optional_text(raw, "affected_population", where, errors)
    artifacts = _parse_artifacts(raw.get("artifacts"), where, errors)
    decisions = _parse_decisions(raw.get("decisions"), where, policy, errors)
    notes = _optional_text(raw, "notes", where, errors)
    if errors:
        # A record with any problem covers nothing: a half-valid record would present a
        # review that may not have happened as one that did.
        return None, errors
    return (
        ReviewRecord(
            reviewer=str(raw["reviewer"]).strip(),
            reviewed_at=reviewed_at,
            scope=scope,
            declared_purpose=str(raw["declared_purpose"]).strip(),
            affected_population=affected,
            artifacts=artifacts,
            units=units,
            decisions=decisions,
            notes=notes,
            assisted_by=assisted_by,
            source_file=source_file,
            policy_version=policy_version,
            index=index,
        ),
        [],
    )


def parse_review_document(
    data: Any, source: str, policy: Policy
) -> tuple[list[ReviewRecord], list[str], str | None]:
    """
    Validate a loaded review document. Returns the valid records, one line per problem,
    and the document's `policy_version` (None when absent). A document of another schema
    or kind yields no records and one error; a record with a problem is dropped and its
    problems listed, while the other records of the file stay usable.
    """
    if not isinstance(data, Mapping):
        return [], [f"{source}: not a mapping"], None
    errors: list[str] = []
    if data.get("schema") != SCHEMA_VERSION:
        errors.append(f"{source}: schema must be {SCHEMA_VERSION}")
    if data.get("kind") != REVIEW_KIND:
        errors.append(f"{source}: kind must be {REVIEW_KIND}")
    if errors:
        return [], errors, None
    raw_version = data.get("policy_version")
    policy_version = None if raw_version is None else str(raw_version).strip()
    reviews = data.get("reviews")
    if not isinstance(reviews, list) or not reviews:
        return [], [f"{source}: reviews must be a non-empty list"], policy_version
    records: list[ReviewRecord] = []
    for index, raw in enumerate(reviews):
        record, record_errors = _parse_record(
            raw, f"{source}: reviews[{index}]", policy, policy_version, source, index
        )
        errors.extend(record_errors)
        if record is not None:
            records.append(record)
    return records, errors, policy_version


def load_record_file(
    path: Path | str,
    root: Path | str,
    policy: Policy | None = None,
    *,
    display: str | None = None,
) -> ReviewSet:
    """Read and validate one record file. Never raises: an unreadable or malformed file is
    a ReviewSet with the problems in `errors` and no records."""
    file_path = Path(path)
    shown = display or relative_to_root(file_path, root)
    out = ReviewSet(file=shown)
    try:
        policy = policy or load_policy()
        try:
            text = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            out.errors.append(f"{shown}: {exc.strerror or type(exc).__name__}")
            return out
        except (UnicodeDecodeError, ValueError) as exc:
            out.errors.append(f"{shown}: not UTF-8 ({exc})")
            return out
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            out.errors.append(f"{shown}: invalid YAML ({' '.join(str(exc).split())})")
            return out
        records, errors, policy_version = parse_review_document(data, shown, policy)
        out.records = records
        out.errors.extend(errors)
        out.policy_version = policy_version
    except Exception as exc:  # broad on purpose: a record file never sinks the audit
        out.errors.append(f"{shown}: {type(exc).__name__}: {' '.join(str(exc).split())}")
    return out


def _locate(root: Path, override: str | Path | None) -> tuple[Path | None, str | None, list[str]]:
    """The record file to read: the override (as given, else under the root) or the first
    candidate present at the root. The disk is the source of truth, not the walk: a
    dot-directory or an ignore marker keeps a file out of the walk, not out of a review."""
    if override is not None and str(override).strip():
        given = Path(str(override)).expanduser()
        for candidate in (given, root / given):
            if candidate.is_file():
                return candidate, relative_to_root(candidate, root), []
        return None, None, [f"review record {given.as_posix()} not found"]
    present = [root / name for name in RECORD_CANDIDATES if (root / name).is_file()]
    if not present:
        return None, None, []
    errors: list[str] = []
    if len(present) > 1:
        names = ", ".join(relative_to_root(p, root) for p in present)
        errors.append(
            f"{len(present)} review record files found ({names}); "
            f"reading {relative_to_root(present[0], root)} only"
        )
    return present[0], relative_to_root(present[0], root), errors


def find_records(
    root: Path | str,
    files: Iterable[Any] | None = None,
    override: str | Path | None = None,
    policy: Policy | None = None,
) -> ReviewSet:
    """
    The review records of the tree at `root`. Never raises.

    `files` (the walk's records) is accepted for the pipeline's call shape and not needed
    to find the file: the candidates are fixed paths at the root, and a record under
    `.aisafe/` must be found whether or not the walk descended there. `override` is the
    `--review-record` path. Every problem, from a missing override to a verdict-shaped
    reviewer, is one line in `errors`; the audit shows each as UNKNOWN (runtime).
    """
    root_path = Path(root)
    try:
        policy = policy or load_policy()
    except PolicyError as exc:
        return ReviewSet(errors=[str(exc)])
    try:
        path, display, lookup_errors = _locate(root_path, override)
    except Exception as exc:  # broad on purpose: see the docstring
        return ReviewSet(errors=[f"review record lookup: {type(exc).__name__}: {exc}"])
    if path is None:
        return ReviewSet(errors=lookup_errors)
    out = load_record_file(path, root_path, policy, display=display)
    out.errors = lookup_errors + out.errors
    return out


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

# The explanation at the top of a skeleton. Plain words only: the file is scanned by the
# audit like any other, so the header spells no detection vocabulary.
_HEADER_LINES: tuple[str, ...] = (
    "# aisafe review record (schema aisg/1, kind review).",
    "# - reviewer: the person who read the artifacts below, by name and role. A tool that",
    "#   helped goes in assisted_by, never here.",
    "# - reviewed_at: the ISO date (YYYY-MM-DD) the review was done; null until it is.",
    "# - scope: the policy mechanisms considered, by id (M1..M8; see policy/charter.md).",
    "# - declared_purpose: what the system is for, in the operator's words.",
    "# - affected_population: who uses the system or is decided about (optional).",
    "# - units: the units the record speaks for (optional; default: every unit).",
    "# - artifacts: the files read, bound by sha256. A changed file makes the record stale.",
    "# - decisions: contextual decisions on findings, by fingerprint, each with a",
    "#   justification. A decision never hides a finding.",
    "# Write justifications and notes in your own words; do not quote the matched text, or",
    "# the audit reports this file. `aisafe review record` fills and refreshes this file.",
)


def _scalar(value: Any) -> str:
    """One YAML scalar. Strings go out as JSON strings, which YAML reads as double-quoted
    scalars, so a colon, a hash or a leading digit in a name never changes its type."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=True)
    return json.dumps(str(value), ensure_ascii=True)


def _flow_list(values: Iterable[Any]) -> str:
    return "[" + ", ".join(_scalar(v) for v in values) + "]"


def _emit_record(review: Mapping[str, Any], lines: list[str]) -> None:
    keys = [key for key in RECORD_KEYS if key in review]
    keys += [key for key in review if key not in RECORD_KEYS]
    first = True
    for key in keys:
        prefix = "  - " if first else "    "
        first = False
        value = review[key]
        if key == "artifacts":
            entries = list(value or [])
            if not entries:
                lines.append(f"{prefix}artifacts: []")
                continue
            lines.append(f"{prefix}artifacts:")
            for entry in entries:
                path = entry.get("path", entry.get("file")) if isinstance(entry, Mapping) else None
                digest = entry.get("sha256") if isinstance(entry, Mapping) else None
                lines.append(f"      - {{path: {_scalar(path)}, sha256: {_scalar(digest)}}}")
        elif key == "decisions":
            entries = list(value or [])
            if not entries:
                lines.append(f"{prefix}decisions: []")
                continue
            lines.append(f"{prefix}decisions:")
            for entry in entries:
                entry = entry if isinstance(entry, Mapping) else {}
                lines.append(f"      - fingerprint: {_scalar(entry.get('fingerprint'))}")
                lines.append(f"        decision: {_scalar(entry.get('decision'))}")
                lines.append(f"        justification: {_scalar(entry.get('justification'))}")
        elif isinstance(value, (list, tuple)):
            lines.append(f"{prefix}{key}: {_flow_list(value)}")
        elif isinstance(value, Mapping):
            # Not part of the schema; kept as a flow mapping so nothing a person wrote is lost.
            body = ", ".join(f"{_scalar(str(k))}: {_scalar(v)}" for k, v in value.items())
            lines.append(f"{prefix}{key}: {{{body}}}")
        else:
            lines.append(f"{prefix}{key}: {_scalar(value)}")


def dump_document(doc: Mapping[str, Any], *, header: bool = False) -> str:
    """
    The record file text for a document in the file's shape (`schema`, `kind`,
    `policy_version`, `reviews: [...]`). Written by hand rather than by a YAML dumper so
    the layout is stable across runs (a diff shows what changed), every string is ASCII,
    and the skeleton can carry its explanation as comments.
    """
    lines: list[str] = []
    if header:
        lines.extend(_HEADER_LINES)
    lines.append(f"schema: {doc.get('schema', SCHEMA_VERSION)}")
    lines.append(f"kind: {doc.get('kind', REVIEW_KIND)}")
    lines.append(f"policy_version: {_scalar(doc.get('policy_version'))}")
    reviews = list(doc.get("reviews") or [])
    if not reviews:
        lines.append("reviews: []")
    else:
        lines.append("reviews:")
        for review in reviews:
            _emit_record(review if isinstance(review, Mapping) else {}, lines)
    return "\n".join(lines) + "\n"


def _stripped(value: Any) -> Any:
    """Free text as the parser keeps it (stripped); anything else passes through so the
    validation step, not the writer, says what is wrong with it."""
    return value.strip() if isinstance(value, str) else value


def _canonical_decision(decision: Mapping[str, Any]) -> dict[str, Any]:
    """A decision entry as the file spells it after validation; other keys pass through."""
    out = dict(decision)
    for key in ("fingerprint", "decision", "justification"):
        value = out.get(key)
        if isinstance(value, str):
            out[key] = value.strip().lower() if key == "fingerprint" else value.strip()
    return out


def record_document(
    *,
    reviewer: str,
    reviewed_at: date | None,
    scope: Sequence[str],
    declared_purpose: str,
    artifacts: Sequence[ArtifactRef],
    policy_version: str,
    affected_population: str | None = None,
    assisted_by: str | None = None,
    units: Sequence[str] = (),
    decisions: Sequence[Mapping[str, Any]] = (),
    notes: str | None = None,
    extra_reviews: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """A document in the file's shape with one record first and `extra_reviews` (records
    of an existing file that are not being rewritten) after it, as plain values. Decisions
    carried over from a file are written in their canonical form (lower-case fingerprint,
    stripped text) so a rewrite is a diff of what changed, not of how it was typed."""
    review: dict[str, Any] = {
        "reviewer": reviewer.strip(),
        "assisted_by": _stripped(assisted_by),
        "reviewed_at": reviewed_at,
        "units": [str(unit).strip() for unit in units],
        "scope": list(scope),
        "declared_purpose": declared_purpose.strip(),
        "affected_population": _stripped(affected_population),
        "artifacts": [{"path": ref.file, "sha256": ref.sha256} for ref in artifacts],
        "decisions": [_canonical_decision(decision) for decision in decisions],
        "notes": _stripped(notes),
    }
    return {
        "schema": SCHEMA_VERSION,
        "kind": REVIEW_KIND,
        "policy_version": policy_version,
        "reviews": [review, *[dict(extra) for extra in extra_reviews]],
    }


def main(argv: list[str] | None = None) -> int:
    """`aisafe review`, for a dispatcher that imports the command from this module. The
    command itself lives in `aisafe.review.cli`, imported here on use so that reading a
    record never loads argparse or the discovery engine."""
    from aisafe.review.cli import main as _main

    return _main(argv)
