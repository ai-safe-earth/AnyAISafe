# aisafe-audit: ignore-file
"""src/aisafe/rules/review.py
--------------------------
Mechanism M8, rule AUD-1107: is there a record that a named person reviewed the prompts and
the algorithms around them for the policy's mechanisms, and does that record still stand?

The rule reads the review set the pipeline built from the record file (`ctx.review`, see
`aisafe.review.records`) and the person signals the other rules' vocabulary found. For
every unit carrying a person signal (mentions excluded) it asks, in this order: does any
record speak for the unit (`/missing`); does a record list every signal-carrying file and
consider every mechanism those signals implicate (`/uncovered`); do the listed artifacts
still hash to what the reviewer read, within the policy's window (`/stale`); was the record
decided under the current policy (`/policy`). When no record exists but a legacy
`ai-system-card.yaml` carries a filled `prompt_audit` block, the one finding is `/unbound`:
a review is claimed and bound to nothing.

Evidence tier: structural (a file that is or is not there, a hash that does or does not
match, a date). Every finding is `requires_contextual_review`: a record is a claim by a
person about what they read, and nothing here judges the reading. A record never hides a
finding of another rule, and no finding of another rule is weakened by one.
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from aisafe.discovery import vocabulary as vocab
from aisafe.evidence.artifacts import sha256_of
from aisafe.evidence.model import (
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
    Scope,
    Severity,
    Tier,
    Unit,
    UnknownCategory,
    UnknownItem,
)
from aisafe.policy import Policy
from aisafe.review.records import RECORD_CANDIDATES
from aisafe.rules import AuditRule, artifact_of, emit_groups, file_text
from aisafe.rules._common import (
    LEGAL_CAVEAT,
    PERSON_KINDS,
    SURFACE_ROLE,
    Signal,
    candidate,
    facts,
    has_ai_surface,
    line_at,
    posix,
    unit_id_of,
)
from aisafe.rules.influence import instruction_mention

__all__ = ["MECHANISM_OF_KIND", "RULES", "ReviewRecordGap", "today"]

# Which mechanism a signal kind implicates, for the scope check: a record covering a unit
# whose prompts carry an attachment instruction should say it considered M5. `vulnerable`
# names a population, not a mechanism, so it has no entry and asks for no scope.
MECHANISM_OF_KIND: dict[str, str] = {
    "profile_sdk": "M1",
    "profile_name": "M1",
    "profile_placeholder": "M1",
    "memory": "M1",
    "affect": "M2",
    "biometric_cat": "M2",
    "inference": "M2",
    "scoring": "M3",
    "engagement": "M4",
    "objective_code": "M4",
    "experiment": "M4",
    "monetisation": "M4",
    "outreach_personalised": "M4",
    "attachment": "M5",
    "romantic_role": "M5",
    "confidant": "M5",
    "persona": "M6",
    "steering": "M7",
}

STALE_ROLE = "stale"
LIST_CAP = 8

RECORD_LOCATION_GAP = (
    "review records are read from the record file at the audited root only; a review kept "
    "outside the tree is not visible"
)

_REVIEWS_KEY_RE = re.compile(r"^reviews\s*:")
_LIST_ITEM_RE = re.compile(r"^(\s*)-\s")
_REVIEWER_KEY_RE = re.compile(r"^\s*-?\s*reviewer\s*:")


def today() -> date:
    """The date the review window is measured against. A function so a test can pin it."""
    return date.today()


# ---------------------------------------------------------------------------
# Small readers
# ---------------------------------------------------------------------------


def _unit_by_id(ctx: AuditContext, unit_id: str | None) -> Unit | None:
    for unit in ctx.inventory.units or []:
        if unit.id == unit_id:
            return unit
    return None


def _scope_for(ctx: AuditContext, unit_ids: list[str | None]) -> tuple[Scope, str]:
    """A unit scope when the finding is about one unit, else the repository."""
    if len(unit_ids) == 1:
        unit = _unit_by_id(ctx, unit_ids[0])
        if unit is not None:
            root = unit.root or "."
            return Scope(kind="unit", unit=unit.id, name=root), root
    return Scope(kind="repo", name="."), "."


def _listed(items: list[str], cap: int = LIST_CAP) -> str:
    shown = ", ".join(items[:cap])
    rest = len(items) - cap
    return f"{shown} and {rest} more" if rest > 0 else shown


def _file_legs(ctx: AuditContext, signals: list[Signal], cap: int = LIST_CAP) -> list[Evidence]:
    """One `role: surface` leg per signal-carrying file (its first signal line), so every
    file owed a review is named on the finding and hashed into its artifacts."""
    legs: list[Evidence] = []
    seen: set[str] = set()
    for signal in sorted(signals, key=lambda s: (s.file, s.line)):
        if signal.file in seen:
            continue
        seen.add(signal.file)
        legs.append(
            Evidence(
                role=SURFACE_ROLE,
                file=signal.file,
                line=signal.line,
                snippet=line_at(ctx, signal.file, signal.line, signal.symbol),
            )
        )
        if len(legs) >= cap:
            break
    return legs


def _current_hash(ctx: AuditContext, relpath: str) -> str | None:
    """The sha256 the file has now: the walk's cached hash, or the bytes on disk for a
    listed artifact the walk did not enumerate. None when the file is not there."""
    digest = artifact_of(ctx, relpath)
    if digest is not None:
        return digest
    return sha256_of(ctx.root / posix(relpath))


def _key_line(ctx: AuditContext, relpath: str, key: str) -> int:
    """1-based line of a top-level `key:` in a YAML file the walk enumerated, else 0."""
    text = file_text(ctx, relpath)
    if not text:
        return 0
    pattern = re.compile(rf"^{re.escape(key)}\s*:")
    for number, line in enumerate(text.split("\n"), 1):
        if pattern.match(line):
            return number
    return 0


def _record_line(ctx: AuditContext, record: Any) -> int:
    """1-based line of the record's `reviewer:` entry in the record file, else 0.

    The record is the n-th item of the top-level `reviews` list (n = `record.index`, which
    counts the file's entries, dropped ones included), so the items are located by the
    list's own indentation: an entry the parser rejected for lacking a reviewer still
    occupies its place and does not shift the anchor onto another person's record. An item
    without a `reviewer:` line anchors on its first line."""
    text = file_text(ctx, record.source_file)
    if not text:
        return 0
    lines = text.split("\n")
    start = next((i for i, line in enumerate(lines) if _REVIEWS_KEY_RE.match(line)), None)
    if start is None:
        return 0
    indent: int | None = None
    items: list[int] = []
    for i in range(start + 1, len(lines)):
        line = lines[i]
        stripped = line.strip()
        if stripped and not line[0].isspace() and not stripped.startswith("#"):
            break  # the next top-level key ends the list
        match = _LIST_ITEM_RE.match(line)
        if match is None:
            continue
        depth = len(match.group(1))
        if indent is None:
            indent = depth
        if depth == indent:
            items.append(i)
    index = int(record.index)
    if index >= len(items):
        return 0
    begin = items[index]
    end = items[index + 1] if index + 1 < len(items) else len(lines)
    for i in range(begin, end):
        if _REVIEWER_KEY_RE.match(lines[i]):
            return i + 1
    return begin + 1


def _inside_tree(relpath: str) -> bool:
    """Whether a record file's display path lies under the audited root: relative on both
    path flavours, no drive, no `..` segment."""
    text = posix(relpath)
    if not text:
        return False
    if (
        PurePosixPath(text).is_absolute()
        or PureWindowsPath(text).is_absolute()
        or PureWindowsPath(text).drive
    ):
        return False
    return ".." not in text.split("/")


def _file_label(path: Any) -> str:
    """How a finding names a record file: its path under the audited root, or, for a
    `--review-record` file kept outside the tree, the option and the file's basename. A
    path outside the tree names the machine, not the project, and would make the same
    record produce a different fingerprint on every checkout."""
    text = posix(path or "")
    if _inside_tree(text):
        return text
    return f"--review-record {PurePosixPath(text).name or text}"


def _record_ref(ctx: AuditContext, record: Any) -> tuple[str, str, int]:
    """(label, anchor file, anchor line) of a record: the record file and its `reviewer:`
    line when the file lies under the audited root, else the root with line 0."""
    source = posix(record.source_file)
    if _inside_tree(source):
        return source, source, _record_line(ctx, record)
    return _file_label(source), ".", 0


def _covers_unit(ctx: AuditContext, record: Any, unit_id: str | None) -> bool:
    """Whether the record speaks for the unit: it names the unit, or names no unit and
    lists an artifact that falls in it (the schema's default: every unit the artifacts
    fall in)."""
    covers = getattr(record, "covers", None)
    if not callable(covers) or not covers(unit_id):
        return False
    if getattr(record, "units", ()):
        return True
    return any(unit_id_of(ctx, ref.file) == unit_id for ref in getattr(record, "artifacts", ()))


def _mechanism_order(policy: Policy) -> dict[str, int]:
    return {mechanism.id: index for index, mechanism in enumerate(policy.mechanisms)}


def _mechanisms_of(signals: list[Signal], policy: Policy) -> list[str]:
    order = _mechanism_order(policy)
    found = {MECHANISM_OF_KIND[s.kind] for s in signals if s.kind in MECHANISM_OF_KIND}
    return sorted(found, key=lambda m: order.get(m, 99))


def _population(ctx: AuditContext, signals: list[Signal]) -> str | None:
    """The vulnerable-group word the unit's signal files carry, when they carry one."""
    for signal in signals:
        if signal.kind != "vulnerable":
            continue
        match = vocab.VULNERABLE_GROUP.search(line_at(ctx, signal.file, signal.line, signal.symbol))
        if match:
            return match.group(0)
    return None


def _record_population(records: list[Any]) -> str | None:
    for record in records:
        text = getattr(record, "affected_population", None)
        if isinstance(text, str) and text.strip():
            return text.strip()
    return None


def _record_purpose(records: list[Any]) -> str | None:
    for record in records:
        text = getattr(record, "declared_purpose", None)
        if isinstance(text, str) and text.strip():
            return text.strip()
    return None


def _legacy_block_filled(card: Any) -> bool:
    """A legacy `prompt_audit` block with both a reviewer and a date set."""
    if not isinstance(card, dict):
        return False
    block = card.get("prompt_audit")
    if not isinstance(block, dict):
        return False
    return not (vocab.is_unset(block.get("reviewed_at")) or vocab.is_unset(block.get("reviewer")))


# ---------------------------------------------------------------------------
# AUD-1107  Review record missing, stale or unbound
# ---------------------------------------------------------------------------


class ReviewRecordGap(AuditRule):
    id = "AUD-1107"
    title = "Review record missing, stale or unbound"
    version = 2
    changed = (
        "v2: reads the review record file (aisafe-review.yaml, bound to the reviewed artifacts "
        "by content hash) instead of the system card's prompt_audit block, and no longer "
        "depends on any system-card rule",
        "v2: one finding per gap instead of one per repository: /missing, /uncovered (a file, "
        "or a mechanism out of scope), /stale (a changed hash or an expired window), /policy "
        "(an older policy version) and /unbound (the legacy block alone)",
        "v2: severity LOW for a missing, uncovered, stale or policy-outdated record; INFO only "
        "for a legacy unbound block; the decision is requires_contextual_review on every "
        "sub-finding",
        "v2: a mention of the vocabulary no longer makes a unit owe a review; the remediation "
        "points at aisafe review init and aisafe review record",
    )
    severity = Severity.LOW
    basis = Basis.ABSENCE
    evidence_kind = EvidenceKind.ABSENCE
    match_kind = MatchKind.STRUCTURED
    default_evidence_status = EvidenceStatus.DETECTED_SIGNAL
    default_decision = Decision.REVIEW
    requires_ai_surface = True
    tier = Tier.T1
    references = (
        "EU:Art.9",
        "EU:Art.11",
        "EU:Art.26",
        "GDPR:Art.35",
        "NIST:GOVERN-1.1",
        "NIST:GOVERN-1.2",
        "NIST:GOVERN-4.2",
        "NIST:MAP-1.1",
        "NIST:MEASURE-2.8",
    )
    # (sub, severity, evidence status, decision, meaning), read by the docs generator.
    SUBS = (
        (
            "missing",
            Severity.LOW,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "no review record covers a unit whose files carry person signals",
        ),
        (
            "uncovered",
            Severity.LOW,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "a file carrying person signals is listed in no record covering its unit, or a "
            "mechanism those signals implicate is in no covering record's scope",
        ),
        (
            "stale",
            Severity.LOW,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "a listed artifact no longer hashes to what the reviewer read, or the review is "
            "older than the policy's window",
        ),
        (
            "unbound",
            Severity.INFO,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "only a legacy ai-system-card.yaml prompt_audit block claims a review, bound to "
            "no artifact",
        ),
        (
            "policy",
            Severity.LOW,
            EvidenceStatus.DETECTED_SIGNAL,
            Decision.REVIEW,
            "the record was decided under an older policy version than the current one",
        ),
    )
    known_failure_modes = (
        "one record file at the audited root is read (aisafe-review.yaml, .aisafe/review.yaml "
        "or .aisafe-audit/review.yaml, or the --review-record path); a review kept in a ticket "
        "system, a wiki or a pull request is reported as missing",
        "a record says who read which file versions and when; whether the reading was careful, "
        "and whether the declared purpose is true, is not something the tool can check, and a "
        "fresh record never closes a finding of another rule",
        "the files owed a review are the ones carrying person signals at the grep and AST "
        "tiers, mentions excluded; a prompt the discovery does not read (another language, a "
        "runtime fetch, a database row) is listed as neither covered nor uncovered",
        "the mechanisms a record should scope are inferred from the signal kinds in the unit; "
        "a mechanism with no detectable signal is not asked for, and a false signal asks for "
        "one",
        "a changed hash says the file changed, not what changed; a reformatted prompt reads as "
        "stale exactly like a rewritten one",
    )
    recommendation = Recommendation(
        tier=Tier.T1,
        summary=(
            "Run `aisafe review init` to list the prompt and algorithm artifacts with their "
            "content hashes, have a named person read them for the policy's mechanisms, then "
            "run `aisafe review record --reviewer NAME --purpose TEXT --scope M1,...` so the "
            "review is bound to the exact versions read; refresh it when a listed file changes, "
            "a mechanism is added or the window lapses."
        ),
        alternatives=(
            "aisafe review init, then aisafe review record --reviewer 'Name <role>' --purpose "
            "'...' --scope M1,M4,M5,M6 once the listed files have been read",
            "a pull-request template that asks a named reviewer to sign off on every prompt or "
            "ranking change, with the record refreshed in the same change (the audit reads the "
            "record, not the template)",
            "a CI step running aisafe review check, so a prompt edited after the review fails "
            "the pipeline until the record is refreshed",
            "a review log kept outside the tree (a ticket per prompt change, a wiki page) is a "
            "practice the audit cannot see; mirror its date, reviewer and scope into the record "
            "file so the binding to the files is checked",
        ),
        removes=("record",),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        if not has_ai_surface(ctx):
            return []
        out = facts(ctx)
        signals = [s for s in out.by_kind(*PERSON_KINDS) if not instruction_mention(ctx, s)]
        if not signals:
            return []
        by_unit: dict[str | None, list[Signal]] = {}
        for signal in signals:
            unit_id = signal.unit or unit_id_of(ctx, signal.file)
            by_unit.setdefault(unit_id, []).append(signal)
        units = sorted(by_unit, key=lambda u: (u is None, u or ""))

        review = getattr(ctx, "review", None)
        if review is None:
            self.unknown.append(
                UnknownItem(
                    category=UnknownCategory.RUNTIME,
                    what="review records",
                    why=(
                        f"the review record lookup did not run; whether a record covers the "
                        f"{len(units)} unit(s) carrying person signals could not be assessed"
                    ),
                    how_to_resolve=(
                        "run `aisafe audit`, which reads the record file at the audited root, "
                        "or `aisafe review check`"
                    ),
                    rule_ids=(self.id,),
                )
            )
            return []
        records = list(getattr(review, "records", None) or [])
        policy = self.policy()

        if not records:
            # The legacy card speaks only when there is no record file at all: a record
            # file that exists but holds no valid record is reported as missing, with the
            # problems in UNKNOWN, never papered over by an older claim.
            card = getattr(ctx.inventory, "system_card", None)
            if not getattr(review, "found", False) and _legacy_block_filled(card):
                return [self._unbound(ctx, card, by_unit)]
            return [
                self._missing(ctx, review, policy, unit_id, by_unit[unit_id]) for unit_id in units
            ]

        findings: list[Finding] = []
        units_of_record: dict[Any, list[str | None]] = {}
        for unit_id in units:
            unit_signals = by_unit[unit_id]
            covering = [r for r in records if _covers_unit(ctx, r, unit_id)]
            if not covering:
                findings.append(self._missing(ctx, review, policy, unit_id, unit_signals))
                continue
            for record in covering:
                units_of_record.setdefault(record, []).append(unit_id)
            findings.extend(self._uncovered_files(ctx, unit_id, unit_signals, covering))
            findings.extend(
                self._uncovered_mechanisms(ctx, policy, unit_id, unit_signals, covering)
            )

        when = today()
        for record in records:
            unit_ids = units_of_record.get(record)
            if not unit_ids:
                continue
            reasons = record.is_stale(
                lambda relpath: _current_hash(ctx, relpath), when, policy.review_max_age_days
            )
            if reasons:
                findings.append(self._stale(ctx, record, unit_ids, reasons))
            if record.policy_outdated(policy.version):
                findings.append(self._policy(ctx, record, unit_ids, policy))
        return findings

    # -- sub-findings --------------------------------------------------------

    def _missing(
        self,
        ctx: AuditContext,
        review: Any,
        policy: Policy,
        unit_id: str | None,
        signals: list[Signal],
    ) -> Finding:
        scope, root = _scope_for(ctx, [unit_id])
        why = (
            f"no review record covers unit {root}; the files below carry person signals and "
            f"no named person is recorded as having reviewed them"
        )
        files = sorted({s.file for s in signals})
        kinds = sorted({s.kind for s in signals})
        mechanisms = _mechanisms_of(signals, policy)
        if getattr(review, "found", False):
            where = (
                f"The record file {_file_label(review.file)} was found but no valid record "
                f"could be read from it (see UNKNOWN)"
            )
        else:
            where = f"No record file was found (looked for {', '.join(RECORD_CANDIDATES)})"
        notes = (
            f"{why}. Signals: {', '.join(kinds)} in {len(files)} file(s): {_listed(files)}. "
            f"Mechanisms implicated: {', '.join(mechanisms) or 'none beyond a vulnerable-group word'}. "
            f"{where}. {LEGAL_CAVEAT}"
        )
        evidence = [
            Evidence(role="absence", file=root, line=0, snippet=why),
            *_file_legs(ctx, signals),
        ]
        return self.finding(
            ctx,
            file=root,
            line=0,
            snippet=why,
            evidence=evidence,
            scope=scope,
            sub="missing",
            severity=Severity.LOW,
            evidence_status=EvidenceStatus.DETECTED_SIGNAL,
            decision=Decision.REVIEW,
            affected_population=_population(ctx, signals),
            coverage_gaps=(RECORD_LOCATION_GAP,),
            uncertainty=(
                "A review may have happened and been recorded outside the tree; only a record "
                "file under the audited root is read."
            ),
            notes=notes,
        )

    def _uncovered_files(
        self,
        ctx: AuditContext,
        unit_id: str | None,
        signals: list[Signal],
        covering: list[Any],
    ) -> list[Finding]:
        _scope, root = _scope_for(ctx, [unit_id])
        files = sorted({s.file for s in signals})
        uncovered = [f for f in files if not any(r.covers(unit_id, f) for r in covering)]
        if not uncovered:
            return []
        record_files = sorted({_file_label(r.source_file) for r in covering})
        listed = sorted(
            {p for r in covering for p in r.artifact_paths if unit_id_of(ctx, p) == unit_id}
        )
        notes = (
            f"{len(uncovered)} file(s) carrying person signals are listed in no review record "
            f"covering unit {root}: {_listed(uncovered)}; the record(s) in "
            f"{', '.join(record_files)} list {len(listed)} artifact(s) of this unit. Read the "
            f"files and add them with `aisafe review record`. {LEGAL_CAVEAT}"
        )
        purpose = _record_purpose(covering)
        population = _record_population(covering) or _population(ctx, signals)
        candidates = []
        for relpath in uncovered:
            first = min((s for s in signals if s.file == relpath), key=lambda s: s.line)
            cand = candidate(
                ctx,
                relpath,
                first.line,
                notes=notes,
                sub="uncovered",
                severity=Severity.LOW,
                snippet=(
                    f"{relpath} carries person signals and is listed in no review record "
                    f"covering unit {root}"
                ),
                evidence_status=EvidenceStatus.DETECTED_SIGNAL,
                decision=Decision.REVIEW,
                affected_population=population,
                uncertainty=(
                    "The file may carry only a false signal, in which case no review of it is "
                    "owed; the signal line is the first evidence leg."
                ),
            )
            candidates.append(cand._replace(declared_purpose=purpose))
        return emit_groups(self, {(unit_id, "uncovered"): candidates}, ctx)

    def _uncovered_mechanisms(
        self,
        ctx: AuditContext,
        policy: Policy,
        unit_id: str | None,
        signals: list[Signal],
        covering: list[Any],
    ) -> list[Finding]:
        scope, root = _scope_for(ctx, [unit_id])
        order = _mechanism_order(policy)

        def ordered(mechanisms: set[str]) -> str:
            return ", ".join(sorted(mechanisms, key=lambda m: order.get(m, 99))) or "no mechanism"

        # The scope that answers for a signal is the scope of the record(s) that list its
        # file: a file read for M1 by one reviewer is not covered for M4 because another
        # record considered M4 for a different file. A file no record lists (reported on
        # its own as an uncovered file) is held to the union of the covering records.
        unit_scope = {m for r in covering for m in r.scope}
        needed: dict[str, list[Signal]] = {}
        for signal in signals:
            mechanism = MECHANISM_OF_KIND.get(signal.kind)
            if mechanism is None:
                continue
            listing = [r for r in covering if r.covers(unit_id, signal.file)]
            scoped = {m for r in listing for m in r.scope} if listing else unit_scope
            if mechanism not in scoped:
                needed.setdefault(mechanism, []).append(signal)
        if not needed:
            return []
        record_files = sorted({_file_label(r.source_file) for r in covering})
        label, anchor_file, anchor_line = _record_ref(ctx, covering[0])
        purpose = _record_purpose(covering)
        population = _record_population(covering) or _population(ctx, signals)
        findings: list[Finding] = []
        for mechanism_id in sorted(needed, key=lambda m: order.get(m, 99)):
            mechanism = policy.mechanism_by_id(mechanism_id)
            name = mechanism.name if mechanism is not None else mechanism_id
            its = needed[mechanism_id]
            files = sorted({s.file for s in its})
            kinds = sorted({s.kind for s in its})
            listing = [r for r in covering if any(r.covers(unit_id, f) for f in files)]
            if listing:
                names = ", ".join(sorted({_file_label(r.source_file) for r in listing}))
                considered = (
                    f"the record(s) in {names} list these files and consider "
                    f"{ordered({m for r in listing for m in r.scope})}"
                )
            else:
                considered = (
                    f"the record(s) in {', '.join(record_files)} list none of these files and "
                    f"consider {ordered(unit_scope)}"
                )
            why = f"no review record covering unit {root} has {mechanism_id} in scope"
            notes = (
                f"{why}: {', '.join(kinds)} signal(s) in {_listed(files)} implicate "
                f"{mechanism_id} ({name}); {considered}. Read the files for {mechanism_id} and "
                f"add it to the scope with `aisafe review record --scope`. {LEGAL_CAVEAT}"
            )
            evidence = [
                Evidence(role="match", file=anchor_file, line=anchor_line, snippet=why),
                *_file_legs(ctx, its),
            ]
            findings.append(
                self.finding(
                    ctx,
                    file=anchor_file,
                    line=anchor_line,
                    snippet=why,
                    evidence=evidence,
                    scope=scope,
                    sub="uncovered",
                    severity=Severity.LOW,
                    evidence_kind=EvidenceKind.CONFIG,
                    evidence_status=EvidenceStatus.DETECTED_SIGNAL,
                    decision=Decision.REVIEW,
                    declared_purpose=purpose,
                    affected_population=population,
                    uncertainty=(
                        "The mechanism is inferred from the signal kinds in the unit; a signal "
                        "that is a false match implicates nothing."
                    ),
                    notes=notes,
                )
            )
        return findings

    def _stale(
        self,
        ctx: AuditContext,
        record: Any,
        unit_ids: list[str | None],
        reasons: list[str],
    ) -> Finding:
        scope, _root = _scope_for(ctx, unit_ids)
        label, anchor_file, anchor_line = _record_ref(ctx, record)
        why = f"review record {label} (entry {int(record.index) + 1}) no longer stands"
        evidence = [Evidence(role="match", file=anchor_file, line=anchor_line, snippet=why)]
        changed = 0
        for ref in record.artifacts:
            digest = _current_hash(ctx, ref.file)
            if digest is None:
                evidence.append(
                    Evidence(
                        role=STALE_ROLE, file=ref.file, line=0, snippet="listed artifact is missing"
                    )
                )
            elif digest.lower() != ref.sha256:
                changed += 1
                evidence.append(
                    Evidence(
                        role=STALE_ROLE,
                        file=ref.file,
                        line=1,
                        snippet=(
                            f"changed since the review: recorded {ref.sha256[:12]}, "
                            f"now {digest[:12]}"
                        ),
                    )
                )
        dated = [r for r in reasons if r.startswith("reviewed_at")]
        for reason in dated:
            evidence.append(Evidence(role=STALE_ROLE, file=anchor_file, line=0, snippet=reason))
        if changed:
            uncertainty = (
                "A changed hash cannot tell a reformatted file from a rewritten prompt; the diff "
                "since the review decides what the re-review covers."
            )
        elif dated:
            uncertainty = (
                "The window is the policy's review_max_age_days; a review the operator still "
                "stands by needs its date refreshed to show that."
            )
        else:
            uncertainty = (
                "A listed artifact that is not in the tree may have moved; the record should "
                "name its new path."
            )
        notes = (
            f"{why}: {'; '.join(reasons)}. Reviewed by {record.reviewer} on "
            f"{record.reviewed_at_iso or 'an unknown date'} for "
            f"{', '.join(record.scope) or 'no mechanism'}. Re-read the changed artifacts and "
            f"refresh the record with `aisafe review record`. {LEGAL_CAVEAT}"
        )
        return self.finding(
            ctx,
            file=anchor_file,
            line=anchor_line,
            snippet=why,
            evidence=evidence,
            scope=scope,
            sub="stale",
            severity=Severity.LOW,
            evidence_kind=EvidenceKind.CONFIG,
            evidence_status=EvidenceStatus.DETECTED_SIGNAL,
            decision=Decision.REVIEW,
            declared_purpose=_record_purpose([record]),
            affected_population=_record_population([record]),
            uncertainty=uncertainty,
            notes=notes,
        )

    def _policy(
        self,
        ctx: AuditContext,
        record: Any,
        unit_ids: list[str | None],
        policy: Policy,
    ) -> Finding:
        scope, _root = _scope_for(ctx, unit_ids)
        label, anchor_file, anchor_line = _record_ref(ctx, record)
        why = f"review record {label} (entry {int(record.index) + 1}) predates the current policy"
        notes = (
            f"{why}: decided under policy_version {record.policy_version or 'none'}; the "
            f"current policy is {policy.version}. The mechanisms and the decision vocabulary may "
            f"have changed since; re-review under {policy.version} and refresh the record with "
            f"`aisafe review record`. {LEGAL_CAVEAT}"
        )
        return self.finding(
            ctx,
            file=anchor_file,
            line=anchor_line,
            snippet=why,
            evidence=[Evidence(role="match", file=anchor_file, line=anchor_line, snippet=why)],
            scope=scope,
            sub="policy",
            severity=Severity.LOW,
            evidence_kind=EvidenceKind.CONFIG,
            evidence_status=EvidenceStatus.DETECTED_SIGNAL,
            decision=Decision.REVIEW,
            declared_purpose=_record_purpose([record]),
            affected_population=_record_population([record]),
            uncertainty=(
                "The policy change may not touch the mechanisms this record considered; the "
                "re-review can be short."
            ),
            notes=notes,
        )

    def _unbound(
        self,
        ctx: AuditContext,
        card: dict[str, Any],
        by_unit: dict[str | None, list[Signal]],
    ) -> Finding:
        relpath = posix(card.get("file") or "ai-system-card.yaml")
        signals = [s for unit_signals in by_unit.values() for s in unit_signals]
        files = sorted({s.file for s in signals})
        why = (
            f"{relpath} has a prompt_audit block (a reviewer and a date) bound to no artifact; "
            f"no review record file exists"
        )
        notes = (
            f"{why}. The block names a reviewer and a date; which files were read, and whether "
            f"they changed since, cannot be told without content hashes. {len(files)} file(s) "
            f"carry person signals: {_listed(files)}. Run `aisafe review init`, read the listed "
            f"artifacts, then `aisafe review record`. {LEGAL_CAVEAT}"
        )
        line = _key_line(ctx, relpath, "prompt_audit")
        evidence = [
            Evidence(role="match", file=relpath, line=line, snippet=why),
            *_file_legs(ctx, signals),
        ]
        return self.finding(
            ctx,
            file=relpath,
            line=line,
            snippet=why,
            evidence=evidence,
            scope=Scope(kind="repo", name="."),
            sub="unbound",
            severity=Severity.INFO,
            evidence_kind=EvidenceKind.CONFIG,
            evidence_status=EvidenceStatus.DETECTED_SIGNAL,
            decision=Decision.REVIEW,
            control_status=ControlStatus.CLAIMED,
            affected_population=_population(ctx, signals),
            coverage_gaps=(RECORD_LOCATION_GAP,),
            uncertainty=(
                "The legacy block may describe a careful review; without hashes the audit cannot "
                "tell which files it covered or whether they changed since."
            ),
            notes=notes,
        )


RULES = [ReviewRecordGap]
