"""src/aisafe/evidence/model.py
----------------------------
Dataclasses, enums, constants, fingerprinting, redaction and sorting for `aisafe audit`.

This module knows nothing about source code, regex tables or rules. It is the shared
vocabulary every other module imports: what a finding is, how it serialises, how it is
identified across runs, and how secrets are kept out of the report.

Honesty rules carried by the types here:

- A finding separates three things and never folds them into one score: what was
  established (`EvidenceStatus`), what the project's policy says about it (`Decision`),
  and what could not be checked (`UnknownItem`, `Finding.coverage_gaps`).
- `Confidence.precision is None` means UNMEASURED. It never means good, and an
  unmeasured rule still fires.
- A reconstructed chain says two separate things. `Flow.links_supported`: every link it holds
  is `ast`, `declared` or `investigated` (cited by a validated investigation record).
  `Finding.trace_complete`: every link the finding's pattern requires (the policy's
  `patterns`) is present and supported. A partial trace is never presented as complete, and
  co-location in a file is never presented as a flow. `flow_established` survives in the JSON
  as a deprecated alias of `trace_complete`.
- The disclaimer is emitted on every report; it names the policy version the decisions
  were taken under and says that absence of a finding is not evidence of safety.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

__all__ = [
    "SCHEMA_VERSION",
    "DISCLAIMER_TEMPLATE",
    "DISCLAIMER",
    "DEFAULT_REPORT",
    "SEVERITY_ORDER",
    "SCOPE_KINDS",
    "FLOW_LINK_KINDS",
    "PERSON_DATA_LINK_KINDS",
    "LINK_KINDS_BY_VIEW",
    "VIEWS",
    "FLOW_ESTABLISHED_BY",
    "SUPPORTED_LINK_STATUSES",
    "REMOVES",
    "FINDING_KEYS",
    "INVENTORY_KEYS",
    "REPORT_KEYS",
    "REDACT_PATTERNS",
    "Severity",
    "Basis",
    "EvidenceKind",
    "MatchKind",
    "Tier",
    "EvidenceStatus",
    "Decision",
    "ControlStatus",
    "UnknownCategory",
    "Confidence",
    "Evidence",
    "Scope",
    "Hit",
    "ArtifactRef",
    "FlowLink",
    "Flow",
    "Recommendation",
    "Finding",
    "UnknownItem",
    "Unit",
    "Inventory",
    "ReportRecord",
    "Report",
    "AuditContext",
    "disclaimer",
    "fingerprint",
    "redact",
    "truncate_snippet",
    "sort_findings",
    "now_iso",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "aisg/1"

DISCLAIMER_TEMPLATE = (
    "This report lists observations about prompts and code, and the decision the "
    "project's policy (version {v}) takes on each. "
    "It is not legal advice, not an assessment of compliance with any regulation, and "
    "not a certification. "
    "Every rule in this report is UNMEASURED: no precision figure exists for it yet. "
    "Absence of a finding is not evidence of safety."
)


def disclaimer(policy_version: str) -> str:
    """The disclaimer for a report decided under `policy_version`."""
    return DISCLAIMER_TEMPLATE.format(v=policy_version)


# The policy-less form, for templates checked by the renderers' self-test.
DISCLAIMER = disclaimer("unknown")

DEFAULT_REPORT = "audit-report.json"

SNIPPET_LIMIT = 160

SCOPE_KINDS = frozenset({"unit", "function", "file", "repo"})

# The chain a finding may reconstruct, in order, by view, and how each link may be
# established. The values equal the policy's `link_kinds` and `link_statuses` (a test pins
# them). The influence view is the one the scan builds; the person-data view follows data
# about the person that feeds M1 to M3, and only investigation records build it.
FLOW_LINK_KINDS: tuple[str, ...] = (
    "objective",
    "ingress",
    "person_data",
    "inference",
    "prompt",
    "intervention",
    "feedback",
)
PERSON_DATA_LINK_KINDS: tuple[str, ...] = (
    "collection",
    "storage",
    "retrieval",
    "transformation",
    "transmission",
    "logging",
    "deletion",
)
VIEWS: tuple[str, ...] = ("influence", "person-data")
LINK_KINDS_BY_VIEW: dict[str, tuple[str, ...]] = {
    "influence": FLOW_LINK_KINDS,
    "person-data": PERSON_DATA_LINK_KINDS,
}
FLOW_ESTABLISHED_BY: tuple[str, ...] = (
    "ast",
    "declared",
    "investigated",
    "co-located",
    "runtime-only",
)
# A link is supported when the syntax tree connects it, the prompt text declares it, or a
# validated investigation record cites it; co-located and runtime-only links are present
# and unsupported.
SUPPORTED_LINK_STATUSES: tuple[str, ...] = ("ast", "declared", "investigated")

# What a remediation takes out of the chain.
REMOVES: tuple[str, ...] = ("objective", "inference", "intervention", "feedback", "record")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """What the mechanism does to the person. Never adjusted by confidence or by rule id."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def rank(self) -> int:
        """Numeric rank, highest for CRITICAL and 0 for INFO."""
        return _SEVERITY_RANK[self]


SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)
_SEVERITY_RANK: dict[Severity, int] = {
    sev: len(SEVERITY_ORDER) - 1 - index for index, sev in enumerate(SEVERITY_ORDER)
}


class Basis(str, Enum):
    PRESENCE = "presence"
    ABSENCE = "absence"


class EvidenceKind(str, Enum):
    CODE = "code"
    CONFIG = "config"
    ABSENCE = "absence"
    REPORT = "report"


class MatchKind(str, Enum):
    GREP = "grep"
    STRUCTURED = "structured"
    AST = "ast"


class Tier(str, Enum):
    """Effort of a remediation: T1 a text or config change, T2 a new step, T3 restructuring."""

    T1 = "T1"
    T2 = "T2"
    T3 = "T3"


class EvidenceStatus(str, Enum):
    """What was established. Values equal the keys of `evidence_statuses` in the policy."""

    DETECTED_SIGNAL = "detected_signal"
    SUPPORTED_MECHANISM = "supported_mechanism"
    OBSERVED_BEHAVIOR = "observed_behavior"
    UNKNOWN = "unknown"

    def rank(self) -> int:
        return _EVIDENCE_RANK[self]


_EVIDENCE_RANK: dict[EvidenceStatus, int] = {
    EvidenceStatus.UNKNOWN: 0,
    EvidenceStatus.DETECTED_SIGNAL: 1,
    EvidenceStatus.SUPPORTED_MECHANISM: 2,
    EvidenceStatus.OBSERVED_BEHAVIOR: 3,
}


class Decision(str, Enum):
    """What the policy says. Values equal the keys of `decisions` in the policy."""

    VIOLATES = "violates_policy"
    REVIEW = "requires_contextual_review"
    NO_VIOLATION = "no_violation_identified_in_scope"
    NOT_ASSESSED = "not_assessed"

    def rank(self) -> int:
        """Strongest first: a violation outranks a review, which outranks the two quiet ones."""
        return _DECISION_RANK[self]


_DECISION_RANK: dict[Decision, int] = {
    Decision.NOT_ASSESSED: 0,
    Decision.NO_VIOLATION: 1,
    Decision.REVIEW: 2,
    Decision.VIOLATES: 3,
}


class ControlStatus(str, Enum):
    """What a control was shown to be. Values equal the keys of `control_statuses`."""

    NONE = "none"
    CLAIMED = "claimed"
    WIRED = "wired"
    EXERCISED = "exercised"
    DEMONSTRATED = "demonstrated"
    UNKNOWN = "unknown"

    def rank(self) -> int:
        return _CONTROL_RANK[self]


_CONTROL_RANK: dict[ControlStatus, int] = {
    ControlStatus.UNKNOWN: -1,
    ControlStatus.NONE: 0,
    ControlStatus.CLAIMED: 1,
    ControlStatus.WIRED: 2,
    ControlStatus.EXERCISED: 3,
    ControlStatus.DEMONSTRATED: 4,
}


class UnknownCategory(str, Enum):
    COVERAGE = "coverage"  # prompt-only unit, remote or runtime prompt, opaque model
    DEEP = "deep"  # no deep analysis for a language (non-Python unit) or a file that did not parse
    REPORTS = "reports"  # on-disk evaluation report unreadable, wrong schema, age unknown
    RUNTIME = "runtime"  # anything else the audit cannot establish statically


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def _plain(obj: Any) -> Any:
    """Recursively turn enums, dataclasses, paths and containers into JSON-ready values."""
    if isinstance(obj, Enum):
        return obj.value
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        return obj.to_dict()
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: _plain(getattr(obj, f.name)) for f in fields(obj)}
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(obj, dict):
        return {str(k): _plain(v) for k, v in obj.items()}
    if isinstance(obj, (set, frozenset)):
        try:
            return [_plain(v) for v in sorted(obj)]
        except TypeError:
            return [_plain(v) for v in obj]
    if isinstance(obj, (list, tuple)):
        return [_plain(v) for v in obj]
    return obj


def _posix(relpath: str) -> str:
    return str(relpath).replace("\\", "/")


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------


def now_iso() -> str:
    """Current UTC time as ISO 8601 'YYYY-MM-DDTHH:MM:SSZ'."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

# Ordered: the most specific prefix first. Group 1 of each pattern is the recognisable
# prefix that survives redaction; the whole match is the token. Every token is rendered
# as "<redacted:PREFIX...LAST4>". Secrets are not what this audit looks for, but a prompt
# file or a config it quotes may carry one, and a report must never reproduce it.
REDACT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("anthropic", re.compile(r"\b(sk-ant-)[A-Za-z0-9_\-]{20,}")),
    ("openai", re.compile(r"\b(sk-)[A-Za-z0-9_\-]{20,}")),
    ("github_pat", re.compile(r"\b(github_pat_)[A-Za-z0-9_]{20,}")),
    ("github", re.compile(r"\b(gh[pousr]_)[A-Za-z0-9]{20,}")),
    ("aws", re.compile(r"\b((?:AKIA|ASIA))[0-9A-Z]{16}\b")),
    ("slack", re.compile(r"\b(xox[abpors]-)[A-Za-z0-9\-]{10,}")),
    ("google", re.compile(r"\b(AIza)[0-9A-Za-z_\-]{35}")),
)

_BEARER_RE = re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9_\-.=+/]{20,})")

_KEY_NAME = (
    r"[A-Za-z0-9_.\-]*"
    r"(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|"
    r"private[_\-]?key|credential|authorization)"
    r"[A-Za-z0-9_.\-]*"
)
_KV_RE = re.compile(
    r"(?i)(?P<key>\b" + _KEY_NAME + r")(?P<sep>[\"']?\s*[:=]\s*)"
    r"(?:(?P<q>[\"'])(?P<qval>[^\"'\s]{8,})(?P=q)"
    r"|(?P<bval>[A-Za-z0-9_\-+/=]{8,})(?![A-Za-z0-9_\-+/=(\[.]))"
)
# Key names where "token" means tokenisation, not a credential.
_KV_KEY_EXCLUDE = re.compile(r"tokens\b|tokeniz|token_?count|token_?limit|token_?budget", re.I)
# Values that are references or placeholders, never a secret worth hiding.
_KV_VALUE_SKIP = ("$", "{", "%", "<")

_NEAR_RE = re.compile(
    r"(?i)(?P<lead>(?:key|secret|token|password|passwd|credential)s?\b[^\n]{0,24}?)"
    r"(?P<val>\b(?:[A-Fa-f0-9]{32,}|(?=[A-Za-z0-9+/]*\d)[A-Za-z0-9+/]{32,}={0,2})\b)"
)


def _mask(prefix: str, token: str) -> str:
    return f"<redacted:{prefix}...{token[-4:]}>"


def _redact_prefixed(match: re.Match[str]) -> str:
    return _mask(match.group(1), match.group(0))


def _redact_bearer(match: re.Match[str]) -> str:
    return match.group(1) + _mask("", match.group(2))


def _redact_kv(match: re.Match[str]) -> str:
    if _KV_KEY_EXCLUDE.search(match.group("key")):
        return match.group(0)
    quoted = match.group("qval")
    if quoted is not None:
        if quoted.startswith(_KV_VALUE_SKIP):
            return match.group(0)
        quote = match.group("q")
        return match.group("key") + match.group("sep") + quote + _mask("", quoted) + quote
    return match.group("key") + match.group("sep") + _mask("", match.group("bval"))


def _redact_near(match: re.Match[str]) -> str:
    return match.group("lead") + _mask("", match.group("val"))


def redact(snippet: str) -> str:
    """Replace every secret-shaped token in `snippet` with "<redacted:PREFIX...LAST4>".

    Idempotent: a redacted token never matches again.
    """
    if not snippet:
        return snippet
    out = snippet
    for _name, pattern in REDACT_PATTERNS:
        out = pattern.sub(_redact_prefixed, out)
    out = _BEARER_RE.sub(_redact_bearer, out)
    out = _KV_RE.sub(_redact_kv, out)
    out = _NEAR_RE.sub(_redact_near, out)
    return out


def _normalise_ws(text: str) -> str:
    return " ".join(str(text).split())


def truncate_snippet(snippet: str, limit: int = SNIPPET_LIMIT) -> str:
    """Whitespace-normalise, redact, then cut to `limit` characters.

    Redaction runs before truncation so a cut can never expose a partial secret.
    """
    out = redact(_normalise_ws(snippet))
    if len(out) <= limit:
        return out
    if limit <= 3:
        return out[:limit]
    return out[: limit - 3] + "..."


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------

_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b")


def _strip_ident_digits(match: re.Match[str]) -> str:
    return re.sub(r"\d", "", match.group(0))


def _norm(snippet: str) -> str:
    """Collapse whitespace and strip digits from identifiers of three or more characters.

    `foo1` and `foo2` normalise to `foo`, so a renamed local or a renumbered line does
    not create a "new" finding. Pure numbers such as `4096` are not identifiers and
    survive intact.
    """
    return _IDENT_RE.sub(_strip_ident_digits, _normalise_ws(snippet))


def fingerprint(rule_id: str, relpath: str, snippet: str) -> str:
    """Stable 16-hex-char identity of a finding across runs and line renumbering."""
    payload = f"{rule_id}|{_posix(relpath)}|{_norm(snippet)}"
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Confidence:
    """How a finding was produced. `precision is None` is UNMEASURED and still fires."""

    evidence_kind: EvidenceKind
    match_kind: MatchKind
    precision: float | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_kind", EvidenceKind(self.evidence_kind))
        object.__setattr__(self, "match_kind", MatchKind(self.match_kind))

    @property
    def label(self) -> str:
        return "UNMEASURED" if self.precision is None else "MEASURED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_kind": self.evidence_kind.value,
            "match_kind": self.match_kind.value,
            "precision": self.precision,
            "label": self.label,
        }


@dataclass(frozen=True)
class Evidence:
    """One location backing a finding. The snippet is always redacted and <= 160 chars."""

    role: str
    file: str
    line: int
    snippet: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "file", _posix(self.file))
        object.__setattr__(self, "snippet", truncate_snippet(self.snippet))

    def to_dict(self) -> dict[str, Any]:
        return {"role": self.role, "file": self.file, "line": self.line, "snippet": self.snippet}


@dataclass(frozen=True)
class Scope:
    kind: str  # unit | function | file | repo
    unit: str | None = None
    name: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in SCOPE_KINDS:
            raise ValueError(f"scope kind {self.kind!r} not in {sorted(SCOPE_KINDS)}")

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "unit": self.unit, "name": self.name}


@dataclass(frozen=True)
class Hit:
    """A raw grep hit: which table and key matched where. Snippet is the raw line."""

    file: str
    line: int
    col: int
    snippet: str
    table: str
    key: str
    unit: str | None = None
    lang: str | None = None


@dataclass(frozen=True)
class ArtifactRef:
    """A file at an exact content version: the sha256 of its bytes, full hex."""

    file: str
    sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "file", _posix(self.file))

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "sha256": self.sha256}


@dataclass(frozen=True)
class FlowLink:
    """One link of the reconstructed chain and how it was established.

    `established_by` is `ast` (the syntax tree connects it), `declared` (it sits inside the
    same prompt literal the chain reads), `investigated` (a validated investigation record
    cites it, named in `record`), `co-located` (same file or window only, which is lexical
    co-occurrence and never a flow) or `runtime-only` (it exists only at runtime).
    """

    kind: str
    file: str
    line: int
    snippet: str
    established_by: str
    record: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in FLOW_LINK_KINDS and self.kind not in PERSON_DATA_LINK_KINDS:
            raise ValueError(
                f"flow link kind {self.kind!r} not in {FLOW_LINK_KINDS + PERSON_DATA_LINK_KINDS}"
            )
        if self.established_by not in FLOW_ESTABLISHED_BY:
            raise ValueError(
                f"flow link established_by {self.established_by!r} not in {FLOW_ESTABLISHED_BY}"
            )
        if self.established_by == "investigated" and not self.record:
            raise ValueError("an investigated flow link names the record that cites it")
        object.__setattr__(self, "file", _posix(self.file))
        object.__setattr__(self, "snippet", truncate_snippet(self.snippet))

    @property
    def supported(self) -> bool:
        return self.established_by in SUPPORTED_LINK_STATUSES

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "kind": self.kind,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "established_by": self.established_by,
        }
        if self.record is not None:
            out["record"] = self.record
        return out


@dataclass
class Flow:
    """A reconstructed chain in one view, as far as it could be followed: in the influence
    view objective -> ingress -> person data -> inference -> prompt -> intervention ->
    feedback; in the person-data view collection -> storage -> retrieval -> transformation ->
    transmission -> logging -> deletion.

    `links_supported` says every link present is supported (`ast`, `declared` or
    `investigated`). Whether the chain is complete depends on what it is a trace of: the
    pattern of a finding or a record names the links it requires, and `complete_for` checks
    them. Neither property ever reads co-location as a flow."""

    links: list[FlowLink] = field(default_factory=list)
    view: str = "influence"

    def __post_init__(self) -> None:
        if self.view not in LINK_KINDS_BY_VIEW:
            raise ValueError(f"flow view {self.view!r} not in {VIEWS}")
        order = LINK_KINDS_BY_VIEW[self.view]
        for link in self.links:
            if link.kind not in order:
                raise ValueError(f"flow link kind {link.kind!r} is not a {self.view} link")
        self.links = sorted(
            self.links, key=lambda link: (order.index(link.kind), link.file, link.line)
        )

    @property
    def links_supported(self) -> bool:
        """True when the chain holds at least one link and every link it holds is supported."""
        return bool(self.links) and all(link.supported for link in self.links)

    def kinds(self) -> tuple[str, ...]:
        return tuple(link.kind for link in self.links)

    def supported_kinds(self) -> frozenset[str]:
        return frozenset(link.kind for link in self.links if link.supported)

    def missing(self, required: Iterable[str]) -> tuple[str, ...]:
        """The required kinds no supported link of this chain carries, in chain order."""
        have = self.supported_kinds()
        return tuple(kind for kind in required if kind not in have)

    def complete_for(self, required: Iterable[str]) -> bool:
        """True when `required` names at least one kind and each has a supported link."""
        required = tuple(required)
        return bool(required) and not self.missing(required)

    def to_dict(self) -> dict[str, Any]:
        return {
            "view": self.view,
            "links": [link.to_dict() for link in self.links],
            "links_supported": self.links_supported,
        }


@dataclass(frozen=True)
class Recommendation:
    """What to change. `removes` names which part of the chain the change takes out; a
    remediation that removes the objective, the inference or the intervention is preferred
    over one that adds a filter in front of the person."""

    tier: Tier
    summary: str
    alternatives: tuple[str, ...] = ()
    removes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "tier", Tier(self.tier))
        object.__setattr__(self, "alternatives", tuple(self.alternatives))
        object.__setattr__(self, "removes", tuple(self.removes))
        for item in self.removes:
            if item not in REMOVES:
                raise ValueError(f"recommendation removes {item!r} not in {REMOVES}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier.value,
            "summary": self.summary,
            "alternatives": list(self.alternatives),
            "removes": list(self.removes),
        }


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

FINDING_KEYS: tuple[str, ...] = (
    "id",
    "rule_id",
    "sub",
    "fingerprint",
    "title",
    "severity",
    "priority",
    "mechanism",
    "policy_version",
    "rule_version",
    "evidence_status",
    "decision",
    "basis",
    "confidence",
    "scope",
    "evidence",
    "flow",
    "pattern",
    "links_supported",
    "trace_complete",
    "missing_links",
    "flow_established",
    "declared_purpose",
    "encoded_objective",
    "person_data_use",
    "control_status",
    "affected_population",
    "artifacts",
    "references",
    "recommendation",
    "known_failure_modes",
    "coverage_gaps",
    "uncertainty",
    "suppressed",
    "gitignored",
)


@dataclass(kw_only=True)
class Finding:
    """One audit observation. Keyword-only: the field list is long and order-sensitive.

    `fingerprint` is computed from `display_id` (so a sub-finding never collides with its
    parent), the first evidence file and snippet when left empty. Set `sub` at
    construction time; changing it afterwards leaves the fingerprint stale.
    """

    id: str
    fingerprint: str = ""
    title: str
    severity: Severity
    priority: int
    mechanism: str = ""
    policy_version: str = ""
    rule_version: int = 1
    evidence_status: EvidenceStatus = EvidenceStatus.DETECTED_SIGNAL
    decision: Decision = Decision.REVIEW
    basis: Basis
    confidence: Confidence
    scope: Scope
    evidence: list[Evidence] = field(default_factory=list)
    flow: Flow | None = None
    declared_purpose: str | None = None
    encoded_objective: str | None = None
    person_data_use: str | None = None
    control_status: ControlStatus | None = None
    affected_population: str | None = None
    artifacts: tuple[ArtifactRef, ...] = ()
    references: tuple[str, ...] = ()
    recommendation: Recommendation
    known_failure_modes: tuple[str, ...] = ()
    coverage_gaps: tuple[str, ...] = ()
    uncertainty: str | None = None
    suppressed: bool = False
    gitignored: bool = False
    # Extensions beyond the core.
    sub: str | None = None  # sub-finding kind: "sensitive", "vulnerable", "persona", ...
    report: dict[str, Any] | None = None  # file/schema/generated_at/age_source/age_days
    baseline_status: str | None = None  # "new" | "unchanged" | "re-review"
    # The operator's recorded reason from the baseline's `accepted` list. Their words,
    # never the audit's; rendered under a label that says so.
    accepted_reason: str | None = None
    acceptance_policy_version: str | None = None
    re_review: bool = False
    # A contextual decision recorded in a review record for this fingerprint.
    review_decision: str | None = None
    review_justification: str | None = None
    notes: str | None = None

    def __post_init__(self) -> None:
        self.severity = Severity(self.severity)
        self.basis = Basis(self.basis)
        self.evidence_status = EvidenceStatus(self.evidence_status)
        self.decision = Decision(self.decision)
        if self.control_status is not None:
            self.control_status = ControlStatus(self.control_status)
        self.priority = int(self.priority)
        self.rule_version = int(self.rule_version)
        self.evidence = list(self.evidence)
        self.artifacts = tuple(self.artifacts)
        self.references = tuple(self.references)
        self.known_failure_modes = tuple(self.known_failure_modes)
        self.coverage_gaps = tuple(self.coverage_gaps)
        if isinstance(self.recommendation, dict):
            self.recommendation = Recommendation(**self.recommendation)
        if isinstance(self.flow, dict):
            self.flow = Flow(
                links=[FlowLink(**link) for link in self.flow.get("links", [])],
                view=self.flow.get("view", "influence"),
            )
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()

    @property
    def display_id(self) -> str:
        return f"{self.id}/{self.sub}" if self.sub else self.id

    @property
    def location(self) -> tuple[str, int]:
        """(file, line) of the first evidence entry, or ("", 0) for absence findings."""
        if self.evidence:
            first = self.evidence[0]
            return first.file, int(first.line)
        return "", 0

    # -- the trace ---------------------------------------------------------------
    @property
    def trace_pattern(self) -> Any:
        """The policy pattern this finding's trace is measured against (a `Pattern`), or
        None when its rule draws no trace (the review rules of M8). Read from the packaged
        policy by the display id; never stored on the finding."""
        from aisafe.policy import load_policy  # local: the model must not load YAML on import

        return load_policy().pattern_of(self.display_id)

    @property
    def required_links(self) -> tuple[str, ...]:
        pattern = self.trace_pattern
        return () if pattern is None else tuple(pattern.links)

    @property
    def links_supported(self) -> bool:
        return self.flow is not None and self.flow.links_supported

    @property
    def missing_links(self) -> tuple[str, ...]:
        """The required links no supported link of the chain carries. Every required link is
        missing when there is no chain, or the chain is of another view than the pattern."""
        pattern = self.trace_pattern
        if pattern is None:
            return ()
        if self.flow is None or self.flow.view != pattern.view:
            return tuple(pattern.links)
        return self.flow.missing(pattern.links)

    @property
    def trace_complete(self) -> bool | None:
        """True when every link the finding's pattern requires is present and supported;
        None when the rule draws no trace. A partial trace is False, never complete."""
        pattern = self.trace_pattern
        if pattern is None:
            return None
        return not self.missing_links

    @property
    def flow_established(self) -> bool:
        """Deprecated alias of `trace_complete` (False where no trace is defined)."""
        return self.trace_complete is True

    def flow_dict(self) -> dict[str, Any] | None:
        """The serialised chain with the trace measured against this finding's pattern."""
        if self.flow is None:
            return None
        out = self.flow.to_dict()
        pattern = self.trace_pattern
        out["pattern"] = None if pattern is None else pattern.id
        out["required"] = list(self.required_links)
        out["missing"] = list(self.missing_links)
        out["trace_complete"] = self.trace_complete
        out["established"] = self.flow_established  # deprecated alias of trace_complete
        return out

    def compute_fingerprint(self) -> str:
        if self.evidence:
            first = self.evidence[0]
            return fingerprint(self.display_id, first.file, first.snippet)
        return fingerprint(self.display_id, self.scope.name or "", "")

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.display_id,
            "rule_id": self.id,
            "sub": self.sub,
            "fingerprint": self.fingerprint,
            "title": self.title,
            "severity": self.severity.value,
            "priority": self.priority,
            "mechanism": self.mechanism,
            "policy_version": self.policy_version,
            "rule_version": self.rule_version,
            "evidence_status": self.evidence_status.value,
            "decision": self.decision.value,
            "basis": self.basis.value,
            "confidence": _plain(self.confidence),
            "scope": _plain(self.scope),
            "evidence": [_plain(e) for e in self.evidence],
            "flow": self.flow_dict(),
            "pattern": None if self.trace_pattern is None else self.trace_pattern.id,
            "links_supported": self.links_supported,
            "trace_complete": self.trace_complete,
            "missing_links": list(self.missing_links),
            "flow_established": self.flow_established,
            "declared_purpose": self.declared_purpose,
            "encoded_objective": self.encoded_objective,
            "person_data_use": self.person_data_use,
            "control_status": None if self.control_status is None else self.control_status.value,
            "affected_population": self.affected_population,
            "artifacts": [a.to_dict() for a in self.artifacts],
            "references": list(self.references),
            "recommendation": _plain(self.recommendation),
            "known_failure_modes": list(self.known_failure_modes),
            "coverage_gaps": list(self.coverage_gaps),
            "uncertainty": self.uncertainty,
            "suppressed": self.suppressed,
            "gitignored": self.gitignored,
        }
        if self.report is not None:
            out["report"] = _plain(self.report)
        if self.baseline_status is not None:
            out["baseline_status"] = self.baseline_status
        if self.accepted_reason is not None:
            out["accepted_reason"] = self.accepted_reason
        if self.acceptance_policy_version is not None:
            out["acceptance_policy_version"] = self.acceptance_policy_version
        if self.re_review:
            out["re_review"] = True
        if self.review_decision is not None:
            out["review_decision"] = self.review_decision
            out["review_justification"] = self.review_justification
        if self.notes is not None:
            out["notes"] = self.notes
        return out


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Sort by (severity rank desc, mechanism order, file, line). Nothing is pinned."""

    def key(f: Finding) -> tuple[int, int, str, int]:
        file, line = f.location
        return (-Severity(f.severity).rank(), f.priority, file, line)

    return sorted(findings, key=key)


# ---------------------------------------------------------------------------
# Unknown items
# ---------------------------------------------------------------------------


@dataclass
class UnknownItem:
    """Something the audit could not establish. Never a pass, never silent."""

    category: UnknownCategory
    what: str
    why: str
    how_to_resolve: str | None = None
    file: str | None = None
    rule_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        self.category = UnknownCategory(self.category)
        self.rule_ids = tuple(self.rule_ids)
        if self.file is not None:
            self.file = _posix(self.file)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "category": self.category.value,
            "what": self.what,
            "why": self.why,
        }
        if self.how_to_resolve is not None:
            out["how_to_resolve"] = self.how_to_resolve
        if self.file is not None:
            out["file"] = self.file
        if self.rule_ids:
            out["rule_ids"] = list(self.rule_ids)
        return out


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


@dataclass
class Unit:
    """A deployable unit: the nearest manifest above a file."""

    id: str
    root: str
    manifest: str | None
    language: str
    ai_surface: bool = False

    def __post_init__(self) -> None:
        self.root = _posix(self.root)
        if self.manifest is not None:
            self.manifest = _posix(self.manifest)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "root": self.root,
            "manifest": self.manifest,
            "language": self.language,
            "ai_surface": self.ai_surface,
        }


@dataclass
class ReportRecord:
    """An on-disk `aisafe evaluate` report (or a legacy `aisafe probe` one) as the audit reads it.

    Reading a report is not running it: findings derived from one carry the report's age
    so a stale file is never rendered as fresh evidence.
    """

    kind: str  # "evaluation" | "probe" (legacy)
    file: str
    schema: str | None
    generated_at: str | None = None
    age_source: str = "unknown"  # generated_at | mtime | git | unknown
    age_days: int | None = None
    families: list[str] = field(default_factory=list)
    config_digest: str | None = None
    body: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.file = _posix(self.file)
        self.families = list(self.families)

    def to_dict(self) -> dict[str, Any]:
        """Inventory shape (`reports[]`); the body is deliberately left out."""
        return {
            "kind": self.kind,
            "file": self.file,
            "schema": self.schema,
            "generated_at": self.generated_at,
            "age_source": self.age_source,
            "age_days": self.age_days,
            "families": list(self.families),
            "config_digest": self.config_digest,
        }

    def finding_report(self) -> dict[str, Any]:
        """The `report` block a report-derived finding carries."""
        return {
            "file": self.file,
            "schema": self.schema,
            "generated_at": self.generated_at,
            "age_source": self.age_source,
            "age_days": self.age_days,
        }


INVENTORY_KEYS: tuple[str, ...] = (
    "schema",
    "kind",
    "target",
    "units",
    "languages",
    "llm_calls",
    "models",
    "frameworks",
    "ingress",
    "prompts",
    "person_signals",
    "memory_stores",
    "personas",
    "review_records",
    "reports",
    "system_card",
    "own_output_skipped",
    "unknown",
)


@dataclass
class Inventory:
    """What discovery found. Entries are plain dicts."""

    target: dict[str, Any] = field(default_factory=dict)
    units: list[Unit] = field(default_factory=list)
    languages: dict[str, int] = field(default_factory=dict)
    llm_calls: list[dict[str, Any]] = field(default_factory=list)
    models: list[dict[str, Any]] = field(default_factory=list)
    frameworks: list[dict[str, Any]] = field(default_factory=list)
    ingress: list[dict[str, Any]] = field(default_factory=list)
    # Prompt material: files under the prompt globs, prompt literals and assemblies.
    # `{file, line, kind, name, is_system, unit}`.
    prompts: list[dict[str, Any]] = field(default_factory=list)
    # Where the code or the prompts touch PEOPLE. `{file, line, kind, symbol, unit}`.
    person_signals: list[dict[str, Any]] = field(default_factory=list)
    memory_stores: list[dict[str, Any]] = field(default_factory=list)
    personas: list[dict[str, Any]] = field(default_factory=list)
    # `{file, reviewer, reviewed_at, policy_version, artifacts, scope}`.
    review_records: list[dict[str, Any]] = field(default_factory=list)
    reports: list[Any] = field(default_factory=list)  # ReportRecord or dict
    # Legacy `ai-system-card.yaml`, read only for `prompt_audit` and `affected_persons`.
    system_card: dict[str, Any] | None = None
    # The audit's own JSON reports found in the tree and not scanned: their evidence
    # snippets would re-report every finding at a second path. Listed, never silent.
    own_output_skipped: list[str] = field(default_factory=list)
    unknown: list[UnknownItem] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"schema": SCHEMA_VERSION, "kind": "inventory"}
        for key in INVENTORY_KEYS[2:]:
            out[key] = _plain(getattr(self, key))
        return out


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

REPORT_KEYS: tuple[str, ...] = (
    "schema",
    "kind",
    "tool",
    "target",
    "generated_at",
    "disclaimer",
    "policy",
    "summary",
    "mechanisms",
    "findings",
    "reports",
    "unknown",
    "baseline",
    "inventory",
    "rules",
)


@dataclass
class Report:
    """The audit document. `to_dict()` emits REPORT_KEYS in that exact order."""

    tool: dict[str, Any] = field(default_factory=dict)
    target: dict[str, Any] = field(default_factory=dict)
    generated_at: str = field(default_factory=now_iso)
    policy: dict[str, Any] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)
    mechanisms: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    reports: list[dict[str, Any]] = field(default_factory=list)
    unknown: list[UnknownItem] = field(default_factory=list)
    baseline: dict[str, Any] | None = None
    inventory: Inventory | dict[str, Any] | None = None
    rules: list[dict[str, Any]] = field(default_factory=list)
    disclaimer: str = DISCLAIMER

    def to_dict(self) -> dict[str, Any]:
        inventory = self.inventory
        return {
            "schema": SCHEMA_VERSION,
            "kind": "audit",
            "tool": _plain(self.tool),
            "target": _plain(self.target),
            "generated_at": self.generated_at,
            "disclaimer": self.disclaimer,
            "policy": _plain(self.policy),
            "summary": _plain(self.summary),
            "mechanisms": _plain(self.mechanisms),
            "findings": [_plain(f) for f in self.findings],
            "reports": _plain(self.reports),
            "unknown": [_plain(u) for u in self.unknown],
            "baseline": _plain(self.baseline),
            "inventory": {} if inventory is None else _plain(inventory),
            "rules": _plain(self.rules),
        }


# ---------------------------------------------------------------------------
# Run context
# ---------------------------------------------------------------------------


@dataclass
class AuditContext:
    """Mutable bag passed through walk -> discover -> pydeep -> checks -> flows -> rules."""

    root: Path
    inventory: Inventory
    pyfacts: object | None = None
    hits: list[Hit] = field(default_factory=list)
    options: object | None = None
    unknown: list[UnknownItem] = field(default_factory=list)
    files: list[Any] = field(default_factory=list)
    # The evaluation reports found in the tree (kind "evaluation", or legacy "probe").
    evaluation: list[ReportRecord] = field(default_factory=list)
    # relpath -> decoded text, filled lazily by `rules.file_text()` so rules that
    # need a window of source share one read per file.
    texts: dict[str, str | None] = field(default_factory=dict, repr=False, compare=False)
    # relpath -> sha256, filled lazily by `rules.artifact_of()`.
    artifacts: dict[str, str] = field(default_factory=dict, repr=False, compare=False)
    # Per-run memo for derived views several rules compute from the same inputs. Keyed
    # by the owning module's name; never serialised.
    cache: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)
    # analysis.checks.CheckFacts: the native checks over the walked Python files, evidence
    # legs for the rules. None when the checks did not run; every rule tolerates that.
    checks: object | None = None
    # review.records.ReviewSet: the review records found (or named by --review-record).
    review: object | None = None
    # analysis.flows: the reconstructed chains, per prompt. Rules attach the matching one.
    flows: list[Flow] = field(default_factory=list, repr=False, compare=False)
