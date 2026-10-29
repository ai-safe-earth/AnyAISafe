"""
bench/score.py
--------------
Two measurements of the `aisafe audit` rules, both written as markdown.

1. The real corpus (`--tool audit`, the default): read the hand-labelled verdicts in
   bench/findings-audit.csv and write bench/precision-audit.md. This mode measures; it
   never invents. If a single finding is unlabelled or carries a verdict outside
   {tp, fp, unclear}, it refuses to produce a report and exits non-zero: a precision
   number computed over a partly-labelled sample is worse than no number at all.
   Precision is tp / (tp + fp). `unclear` rows leave the denominator and are reported
   separately, so a rule whose sample is mostly unclear is visible as a thin sample
   rather than hidden inside a confident-looking ratio.

2. The synthetic corpus (`--cases DIR`): run the audit in-process over every
   `<DIR>/<id>/tree` and compare the findings with `<DIR>/<id>/expected.yaml`
   (bench/protocol.md section 3). Per rule and sub-finding: true positives, false
   negatives, false positives, precision and recall, each with its counts, separately
   for the `dev` and `heldout` splits and separately for reviewed and unreviewed cases.
   The headline uses reviewed cases only and says so. Every mismatch is listed verbatim.
   A number from this corpus is never copied onto a rule: the cases were written by
   people who know the detector.

Usage:
    python bench/score.py --tool audit
    python bench/score.py --tool audit --min-precision 0.80
    python bench/score.py --tool audit --allow-partial     # score only the labelled subset
    python bench/score.py --cases bench/cases --out bench/cases-score.md

Exit codes: 0 when a report was written; 1 when the labelled CSV is incomplete or
invalid; 2 when a synthetic case is malformed.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BENCH = Path(__file__).resolve().parent
ROOT = BENCH.parent
sys.path.insert(0, str(ROOT / "src"))

TOOLS = ("audit",)
VALID = {"tp", "fp", "unclear"}
DEFAULT_MIN_PRECISION = 0.80
WORST_N = 3

LABELS = {
    "audit": {
        "csv": BENCH / "findings-audit.csv",
        "results": BENCH / "results-audit",
        "out": BENCH / "precision-audit.md",
        "title": "aisafe audit rule precision",
        "run": "python bench/run.py",
        "score": "python bench/score.py --tool audit",
        "gate": "`aisafe audit --experimental`",
    },
}

CASES_OUT = BENCH / "cases-score.md"
SPLITS = ("dev", "heldout")
# The decision and evidence ladders, weakest first. Mirrors `Decision.rank()` and
# `EvidenceStatus.rank()` in aisafe.evidence.model; spelled here so a label file is
# validated even when the package cannot be imported.
DECISIONS = (
    "not_assessed",
    "no_violation_identified_in_scope",
    "requires_contextual_review",
    "violates_policy",
)
EVIDENCE_STATUSES = ("unknown", "detected_signal", "supported_mechanism", "observed_behavior")
UNKNOWN_CATEGORIES = ("coverage", "deep", "reports", "runtime")


def die(msg: str) -> None:
    print(f"\nERROR: {msg}\n", file=sys.stderr)
    sys.exit(1)


def _show(path: Path) -> str:
    """A path as the repository names it, or in full when it lies outside."""
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


# ---------------------------------------------------------------------------
# The real corpus: a hand-labelled CSV
# ---------------------------------------------------------------------------


def load_rows(csv_path: Path, run_hint: str) -> list[dict]:
    if not csv_path.is_file():
        die(f"{csv_path} not found. Run `{run_hint}` first.")
    with csv_path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        die(f"{csv_path} has no findings. Nothing to score.")
    return rows


def validate(rows: list[dict], allow_partial: bool, csv_path: Path) -> list[dict]:
    """Refuse to score an incompletely or invalidly labelled sample."""
    blank, bad = [], []
    for i, row in enumerate(rows, start=2):  # +2: header is line 1
        v = (row.get("verdict") or "").strip().lower()
        if not v:
            blank.append((i, row))
        elif v not in VALID:
            bad.append((i, row, v))

    if bad:
        print(
            f"\nERROR: {len(bad)} row(s) have a verdict outside {{tp, fp, unclear}}:",
            file=sys.stderr,
        )
        for line, row, v in bad[:10]:
            print(
                f"  line {line}: {row['rule_id']} {row['repo']}/{row['file']}:{row['line']} -> {v!r}",
                file=sys.stderr,
            )
        if len(bad) > 10:
            print(f"  ... and {len(bad) - 10} more", file=sys.stderr)
        sys.exit(1)

    if blank and not allow_partial:
        total = len(rows)
        done = total - len(blank)
        print(
            f"\nERROR: {len(blank)} of {total} findings are unlabelled "
            f"({done}/{total} done, {100 * done / total:.1f}%).",
            file=sys.stderr,
        )
        print(
            "\nPrecision over a partly-labelled sample is not a measurement. Label every row, or",
            file=sys.stderr,
        )
        print(
            "re-run with --allow-partial to score only the labelled subset "
            "(the report will say so).",
            file=sys.stderr,
        )
        by_rule: dict[str, int] = defaultdict(int)
        for _, row in blank:
            by_rule[row["rule_id"]] += 1
        print("\nUnlabelled by rule:", file=sys.stderr)
        for rid, n in sorted(by_rule.items(), key=lambda kv: -kv[1]):
            print(f"  {rid:<16} {n}", file=sys.stderr)
        print(f"\nFirst unlabelled row: line {blank[0][0]} in {csv_path}", file=sys.stderr)
        sys.exit(1)

    for row in rows:
        row["verdict"] = (row.get("verdict") or "").strip().lower()
    return [r for r in rows if r["verdict"] in VALID]


def load_snippets(results_dir: Path) -> dict[tuple, dict]:
    """
    Pull the first evidence leg (already redacted), the recommendation and the
    audit's own statements out of the raw JSON reports, so the report can quote a
    false positive verbatim rather than paraphrasing it.
    """
    out: dict[tuple, dict] = {}
    if not results_dir.is_dir():
        return out
    for jf in sorted(results_dir.glob("*.json")):
        repo = jf.stem
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for f in data.get("findings", []):
            evidence = f.get("evidence") or []
            first = evidence[0] if evidence and isinstance(evidence[0], dict) else {}
            fname = str(first.get("file") or "").replace("\\", "/")
            rule_id = f.get("rule_id") or str(f.get("id", "")).split("/")[0]
            key = (repo, fname.rsplit("/", 1)[-1], str(first.get("line", "")), rule_id)
            recommendation = f.get("recommendation") or {}
            out[key] = {
                "snippet": first.get("snippet", ""),
                "description": recommendation.get("summary", ""),
                "severity": f.get("severity", ""),
                "references": ", ".join(f.get("references") or []),
                "title": f.get("title", ""),
                "decision": f.get("decision", ""),
                "evidence_status": f.get("evidence_status", ""),
            }
    return out


def enrich(row: dict, snippets: dict[tuple, dict]) -> dict:
    key = (row["repo"], row["file"].rsplit("/", 1)[-1], str(row["line"]), row["rule_id"])
    return snippets.get(key, {})


def rule_metadata() -> dict[str, dict]:
    """Severity, references, title, version and mechanism from the rule registry, when importable."""
    meta: dict[str, dict] = {}
    try:
        from aisafe.rules import ALL_RULES
    except Exception:
        return meta
    for r in ALL_RULES:
        try:
            mechanism = r.mechanism_id()
        except Exception:
            mechanism = ""
        meta[r.id] = {
            "severity": getattr(r.severity, "value", str(r.severity)),
            "references": ", ".join(getattr(r, "references", ()) or ()),
            "title": r.title,
            "declared_precision": getattr(r, "measured_precision", None),
            "version": getattr(r, "version", 1),
            "mechanism": mechanism,
            "class_name": r.__name__ if isinstance(r, type) else type(r).__name__,
        }
    return meta


def score_labels(args: argparse.Namespace) -> int:
    labels = LABELS[args.tool]
    csv_path: Path = args.csv or labels["csv"]
    results_dir: Path = args.results or labels["results"]
    out_path: Path = args.out or labels["out"]

    raw = load_rows(csv_path, labels["run"])
    rows = validate(raw, args.allow_partial, csv_path)
    partial = len(rows) != len(raw)
    snippets = load_snippets(results_dir)
    meta = rule_metadata()

    by_rule: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_rule[row["rule_id"]].append(row)

    stats = {}
    for rid, rrows in by_rule.items():
        tp = sum(1 for r in rrows if r["verdict"] == "tp")
        fp = sum(1 for r in rrows if r["verdict"] == "fp")
        unclear = sum(1 for r in rrows if r["verdict"] == "unclear")
        judged = tp + fp
        stats[rid] = {
            "tp": tp,
            "fp": fp,
            "unclear": unclear,
            "judged": judged,
            "total": len(rrows),
            "precision": (tp / judged) if judged else None,
            "repos": len({r["repo"] for r in rrows}),
        }

    # "Worst" = from the least precise rule first; then the rule contributing the
    # most false positives; then deterministic by location.
    def fp_sort_key(row: dict):
        s = stats[row["rule_id"]]
        prec = s["precision"] if s["precision"] is not None else 1.0
        sev = (
            meta.get(row["rule_id"], {}).get("severity")
            or enrich(row, snippets).get("severity")
            or "medium"
        )
        return (
            prec,
            0 if sev in ("critical", "high") else 1,
            -s["fp"],
            row["repo"],
            row["file"],
            int(row["line"] or 0),
        )

    worst = sorted((r for r in rows if r["verdict"] == "fp"), key=fp_sort_key)[:WORST_N]

    ordered = sorted(
        stats.items(),
        key=lambda kv: (kv[1]["precision"] if kv[1]["precision"] is not None else 2.0, kv[0]),
    )

    L: list[str] = []
    L.append(f"# {labels['title']}")
    L.append("")
    L.append(
        f"Measured over `{csv_path.name}` -- {len(rows)} hand-labelled findings "
        f"from {len({r['repo'] for r in rows})} repositories, "
        f"{len(by_rule)} rules fired."
    )
    L.append("")
    if partial:
        L.append(
            f"> **Partial sample.** {len(raw) - len(rows)} of {len(raw)} findings were "
            f"unlabelled and are excluded. These numbers describe the labelled subset only."
        )
        L.append("")
    L.append(
        "`precision = tp / (tp + fp)`. `unclear` rows are excluded from the denominator "
        "and counted separately, so a rule resting on a thin sample is visible rather than "
        "hidden behind a confident ratio."
    )
    L.append("")
    L.append(
        f"Default-on threshold: **{args.min_precision:.2f}**. "
        f"Rules below it should be gated behind {labels['gate']}."
    )
    L.append("")
    L.append("## Per-rule precision")
    L.append("")
    L.append(
        "| Rule | Severity | Precision | tp | fp | unclear | n (judged/total) | Repos | Default-on |"
    )
    L.append("|---|---|---:|---:|---:|---:|---:|---:|---|")
    for rid, s in ordered:
        m = meta.get(rid, {})
        sev = m.get("severity", "?")
        prec = "n/a" if s["precision"] is None else f"{s['precision']:.3f}"
        if s["precision"] is None:
            gate = "no judgeable sample"
        elif s["precision"] >= args.min_precision:
            gate = "yes"
        else:
            gate = "**NO -- experimental**"
        L.append(
            f"| `{rid}` | {sev} | {prec} | {s['tp']} | {s['fp']} | {s['unclear']} "
            f"| {s['judged']}/{s['total']} | {s['repos']} | {gate} |"
        )
    L.append("")

    below = [
        (rid, s)
        for rid, s in ordered
        if s["precision"] is not None and s["precision"] < args.min_precision
    ]
    nosample = [rid for rid, s in ordered if s["precision"] is None]

    L.append("## Rules below threshold")
    L.append("")
    if below:
        L.append(
            f"{len(below)} rule(s) measured below {args.min_precision:.2f}. "
            "Set `measured_precision` on each and they stop firing by default:"
        )
        L.append("")
        L.append("```python")
        for rid, s in below:
            m = meta.get(rid, {})
            cls = m.get("class_name")
            label = f"{rid} {cls}" if cls else rid
            if m.get("version"):
                label += f" (v{m['version']})"
            L.append(f"# {label}: {s['tp']}/{s['judged']} judged findings were true positives")
            L.append(f"measured_precision = {s['precision']:.3f}")
        L.append("```")
    else:
        L.append(f"None. Every rule with a judgeable sample met {args.min_precision:.2f}.")
    L.append("")
    if nosample:
        L.append(
            f"{len(nosample)} rule(s) produced findings but no tp/fp judgement "
            f"(all `unclear`): {', '.join('`' + r + '`' for r in nosample)}. "
            "Precision is unmeasured for these -- leave `measured_precision = None`."
        )
        L.append("")

    fired = set(by_rule)
    silent = sorted(set(meta) - fired)
    if silent:
        L.append("## Rules that never fired")
        L.append("")
        L.append(
            f"{len(silent)} rule(s) produced no findings anywhere in the corpus, so their "
            "precision is unmeasured -- not perfect. Leave `measured_precision = None`:"
        )
        L.append("")
        L.append(", ".join(f"`{r}`" for r in silent))
        L.append("")

    L.append(f"## {WORST_N} worst false positives")
    L.append("")
    if not worst:
        L.append("No findings were labelled `fp`.")
    else:
        L.append(
            "Ordered by the firing rule's precision (lowest first), then severity, then "
            "how many false positives that rule contributed. Quoted verbatim from the "
            "scanned source (redacted where the audit redacts)."
        )
        L.append("")
        for i, row in enumerate(worst, 1):
            info = enrich(row, snippets)
            m = meta.get(row["rule_id"], {})
            s = stats[row["rule_id"]]
            prec = "n/a" if s["precision"] is None else f"{s['precision']:.3f}"
            sub = row.get("sub") or ""
            shown = f"{row['rule_id']}/{sub}" if sub else row["rule_id"]
            L.append(f"### {i}. `{shown}` -- {row['message']}")
            L.append("")
            L.append(f"- **Location:** `{row['repo']}` -> `{row['file']}:{row['line']}`")
            L.append(f"- **References:** {m.get('references') or info.get('references') or '?'}")
            L.append(f"- **Severity:** {m.get('severity') or info.get('severity') or '?'}")
            decision = row.get("decision") or info.get("decision") or ""
            status = row.get("evidence_status") or info.get("evidence_status") or ""
            if decision or status:
                L.append(
                    f"- **Audit said:** decision `{decision or '?'}`, "
                    f"evidence status `{status or '?'}`"
                )
            L.append(f"- **Rule precision:** {prec} ({s['fp']} fp / {s['judged']} judged)")
            L.append("")
            snippet = (info.get("snippet") or row.get("snippet") or "").rstrip()
            if snippet:
                L.append("```python")
                L.append(snippet)
                L.append("```")
            else:
                L.append(f"> No snippet recorded in `{results_dir.name}/` for this finding.")
            L.append("")
            if info.get("description"):
                L.append(f"> **Rule says:** {info['description']}")
                L.append("")

    L.append("---")
    L.append("")
    L.append(
        f"Regenerate with `{labels['score']}` after editing "
        f"`{csv_path.name}`. Every number above is derived from that file; "
        "none is hand-written."
    )
    L.append("")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(L), encoding="utf-8")

    print(f"Scored {len(rows)} labelled findings across {len(by_rule)} rules -> {out_path}")
    if below:
        print(
            f"\n{len(below)} rule(s) below {args.min_precision:.2f} "
            f"-- should be --experimental only:"
        )
        for rid, s in below:
            print(f"  {rid:<16} precision={s['precision']:.3f}  (tp={s['tp']} fp={s['fp']})")
    if nosample:
        print(f"\n{len(nosample)} rule(s) had no judgeable sample (all unclear).")
    return 0


# ---------------------------------------------------------------------------
# The synthetic corpus: `--cases DIR`
# ---------------------------------------------------------------------------


class CaseError(Exception):
    """A case directory whose labels cannot be scored. Exit 2, never a guess."""


@dataclass(frozen=True)
class Label:
    """One `expected` or `forbidden` entry. None means "any" for sub, decision and status."""

    rule: str
    sub: str | None = None
    decision: str | None = None
    evidence_status: str | None = None

    @property
    def key(self) -> str:
        return f"{self.rule}/{self.sub}" if self.sub else f"{self.rule}/*"

    def want(self) -> str:
        text = f"{self.key} {self.decision or 'any decision'}"
        if self.evidence_status:
            text += f" ({self.evidence_status})"
        return text


@dataclass
class Case:
    id: str
    path: Path
    split: str
    pair: int | None
    description: str
    policy_version: str | None
    expected: list[Label]
    forbidden: list[Label]
    expected_unknown: list[str]
    reviewed_by: str | None
    disagreement: str | None

    @property
    def reviewed(self) -> bool:
        return bool(self.reviewed_by)


@dataclass(frozen=True)
class Reported:
    """One finding the audit reported on a case tree, reduced to what the labels name."""

    rule: str
    sub: str | None
    decision: str
    evidence_status: str
    file: str
    line: int

    @property
    def key(self) -> str:
        return f"{self.rule}/{self.sub}" if self.sub else self.rule

    @property
    def pair(self) -> tuple[str, str | None]:
        return (self.rule, self.sub)

    def got(self) -> str:
        where = f" at {self.file}:{self.line}" if self.file and self.file != "." else ""
        return f"{self.key} {self.decision} ({self.evidence_status}){where}"


@dataclass
class CaseRun:
    case: Case
    findings: list[Reported] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)  # UNKNOWN categories seen
    error: str | None = None


@dataclass(frozen=True)
class Outcome:
    case: str
    kind: str  # "tp" | "fn" | "fp"
    key: str  # the rule/sub the count is credited to
    rule: str
    expected: str
    got: str


def _mapping(value: Any, where: str) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise CaseError(f"{where}: expected a mapping, got {type(value).__name__}")
    return value


def _entries(value: Any, where: str) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise CaseError(f"{where}: expected a list, got {type(value).__name__}")
    return value


def _any_or_one(value: Any, allowed: tuple[str, ...], where: str) -> str | None:
    if value is None or value == "any":
        return None
    if not isinstance(value, str) or value not in allowed:
        raise CaseError(f"{where}: {value!r} is not one of {', '.join(allowed)} or any")
    return value


def _label(entry: Any, where: str) -> Label:
    raw = _mapping(entry, where)
    rule = raw.get("rule")
    if not isinstance(rule, str) or not rule.strip():
        raise CaseError(f"{where}: `rule` must be a non-empty string")
    sub = raw.get("sub")
    if sub is not None and (not isinstance(sub, str) or not sub.strip()):
        raise CaseError(f"{where}: `sub` must be a non-empty string or null")
    return Label(
        rule=rule.strip(),
        sub=sub.strip() if isinstance(sub, str) else None,
        decision=_any_or_one(raw.get("decision"), DECISIONS, f"{where}.decision"),
        evidence_status=_any_or_one(
            raw.get("evidence_status"), EVIDENCE_STATUSES, f"{where}.evidence_status"
        ),
    )


def load_case(case_dir: Path) -> Case:
    """Read and validate `<case_dir>/expected.yaml`. Raises CaseError when malformed."""
    import yaml

    spec_path = case_dir / "expected.yaml"
    name = case_dir.name
    if not spec_path.is_file():
        raise CaseError(f"{name}: no expected.yaml")
    if not (case_dir / "tree").is_dir():
        raise CaseError(f"{name}: no tree/ directory to audit")
    try:
        data = yaml.safe_load(spec_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
        raise CaseError(f"{name}: expected.yaml is unreadable: {exc}") from exc
    data = _mapping(data, f"{name}: expected.yaml")
    if data.get("schema") != "aisg/1":
        raise CaseError(f"{name}: schema must be aisg/1, got {data.get('schema')!r}")
    if data.get("kind") != "bench-case":
        raise CaseError(f"{name}: kind must be bench-case, got {data.get('kind')!r}")
    if data.get("id") != name:
        raise CaseError(f"{name}: id {data.get('id')!r} does not match the directory name")
    split = data.get("split")
    if split not in SPLITS:
        raise CaseError(f"{name}: split must be one of {', '.join(SPLITS)}, got {split!r}")
    pair = data.get("pair")
    if pair is not None and not isinstance(pair, int):
        raise CaseError(f"{name}: pair must be an integer or null")
    expected = [
        _label(e, f"{name}: expected[{i}]")
        for i, e in enumerate(_entries(data.get("expected"), f"{name}: expected"))
    ]
    forbidden = [
        _label(e, f"{name}: forbidden[{i}]")
        for i, e in enumerate(_entries(data.get("forbidden"), f"{name}: forbidden"))
    ]
    unknown = _entries(data.get("expected_unknown"), f"{name}: expected_unknown")
    for category in unknown:
        if category not in UNKNOWN_CATEGORIES:
            raise CaseError(
                f"{name}: expected_unknown {category!r} is not one of "
                f"{', '.join(UNKNOWN_CATEGORIES)}"
            )
    labels = _mapping(data.get("labels"), f"{name}: labels")
    reviewed_by = labels.get("reviewed_by")
    if reviewed_by is not None and not isinstance(reviewed_by, str):
        raise CaseError(f"{name}: labels.reviewed_by must be a string or null")
    disagreement = labels.get("disagreement")
    policy_version = data.get("policy_version")
    return Case(
        id=name,
        path=case_dir,
        split=split,
        pair=pair,
        description=str(data.get("description") or ""),
        policy_version=None if policy_version is None else str(policy_version),
        expected=expected,
        forbidden=forbidden,
        expected_unknown=[str(c) for c in unknown],
        reviewed_by=reviewed_by.strip() if isinstance(reviewed_by, str) else None,
        disagreement=str(disagreement) if disagreement else None,
    )


def load_cases(root: Path) -> list[Case]:
    """
    Every case under `root`. A directory holding a `tree/` or an `expected.yaml` is a
    case and must hold both (`load_case` raises on the missing half); a directory with
    neither (a cache, a folder of notes) is not a case and is skipped.
    """
    if not root.is_dir():
        raise CaseError(f"{root} is not a directory")
    dirs = sorted(
        p
        for p in root.iterdir()
        if p.is_dir() and ((p / "expected.yaml").is_file() or (p / "tree").is_dir())
    )
    if not dirs:
        raise CaseError(f"{root} holds no case directory with an expected.yaml")
    return [load_case(d) for d in dirs]


def build_context(root: Path):
    """
    An AuditContext for a tree the way `aisafe audit` and the test fixture
    `audit_context` (tests/conftest.py) build it: walk -> discover -> pydeep ->
    checks -> flows -> review records, every UNKNOWN item folded in. The modules are
    imported directly; no CLI runs and nothing is written.
    """
    from aisafe.analysis import checks, flows, pydeep
    from aisafe.discovery import discover, walk
    from aisafe.evidence.model import AuditContext, UnknownCategory, UnknownItem
    from aisafe.review import records

    root = Path(root)
    files, units, unknown = walk.walk(root, walk.WalkOptions())
    inventory, hits = discover.discover(root, files, units, None)
    unknown = list(unknown) + list(inventory.unknown)
    pyfacts = pydeep.analyse_unit([f for f in files if f.lang == "python"], inventory)
    unknown.extend(pyfacts.unknown)
    # The audit adds pydeep's prompt literals and assemblies to the inventory's prompt
    # rows after the deep pass; the rules read them from there.
    discover.merge_pyfacts_prompts(inventory, pyfacts)
    texts = {f.relpath: walk.read_text(f.path) for f in files if f.lang == "python"}
    check_facts = checks.run_checks(files, texts)
    # A check that failed on a file is an UNKNOWN item in the audit, never a crash.
    unknown.extend(getattr(check_facts, "errors", ()))
    review = records.find_records(root, files, None)
    for problem in review.errors:
        unknown.append(
            UnknownItem(
                category=UnknownCategory.RUNTIME,
                what="review record",
                why=problem,
                file=review.file,
            )
        )
    ctx = AuditContext(
        root=root,
        inventory=inventory,
        pyfacts=pyfacts,
        hits=hits,
        options=None,
        unknown=unknown,
        files=files,
        evaluation=[
            r for r in inventory.reports if getattr(r, "kind", None) in ("evaluation", "probe")
        ],
        checks=check_facts,
        review=review,
    )
    # The rules share the Python texts the checks read, as in `aisafe audit`.
    ctx.texts.update(texts)
    ctx.flows = flows.build_flows(ctx)
    return ctx


def run_case(case: Case) -> CaseRun:
    """Audit one case tree in-process with every registered rule (experimental ones too)."""
    from aisafe import rules as rules_mod

    run = CaseRun(case=case)
    try:
        from aisafe.evidence.model import Decision
        from aisafe.rules._common import review_decision_for

        ctx = build_context(case.path / "tree")
        findings, unknown = rules_mod.run_rules(list(rules_mod.ALL_RULES), ctx)
        # As `aisafe audit` does after the rules: a reviewer's recorded `violates_policy`
        # upgrades the finding's decision. No recorded decision hides a finding.
        for f in findings:
            recorded = review_decision_for(ctx, f.fingerprint)
            decision = str(getattr(recorded, "decision", "") or "") if recorded else ""
            if decision == Decision.VIOLATES.value:
                f.decision = Decision.VIOLATES
    except Exception as exc:  # a crash is reported, never hidden behind an empty result
        run.error = f"{type(exc).__name__}: {exc}"
        return run
    for f in findings:
        file, line = f.location
        run.findings.append(
            Reported(
                rule=f.id,
                sub=f.sub or None,
                decision=f.decision.value,
                evidence_status=f.evidence_status.value,
                file=file,
                line=int(line),
            )
        )
    run.unknown = sorted({item.category.value for item in list(ctx.unknown) + list(unknown)})
    return run


def _covers(label: Label, f: Reported) -> bool:
    return f.rule == label.rule and (label.sub is None or f.sub == label.sub)


def _satisfies(label: Label, f: Reported) -> bool:
    if label.decision is not None and f.decision != label.decision:
        return False
    if label.evidence_status is not None and f.evidence_status != label.evidence_status:
        return False
    return True


def _compare(label: Label, f: Reported) -> str:
    """Why a covered finding did not satisfy its label: the ladder it missed, and how."""
    if label.decision is not None and f.decision != label.decision:
        got, want = DECISIONS.index(f.decision), DECISIONS.index(label.decision)
        return "weaker decision" if got < want else "stronger decision"
    got = EVIDENCE_STATUSES.index(f.evidence_status)
    want = EVIDENCE_STATUSES.index(label.evidence_status or f.evidence_status)
    if got < want:
        return "weaker evidence status"
    if got > want:
        return "stronger evidence status"
    return "different evidence status"


def judge(run: CaseRun) -> tuple[list[Outcome], list[Reported], list[str]]:
    """
    Apply bench/protocol.md section 3 to one case. Returns the counted outcomes, the
    reported findings that no label mentions (listed, never counted), and the UNKNOWN
    categories the case expected but the run did not list.

    Counts are per case: a rule/sub that fires on two files of one tree counts once.
    """
    case = run.case
    outcomes: list[Outcome] = []
    if run.error is not None:
        for label in case.expected:
            outcomes.append(
                Outcome(case.id, "fn", label.key, label.rule, label.want(), f"error: {run.error}")
            )
        return outcomes, [], list(case.expected_unknown)

    findings = run.findings
    mentioned: set[tuple[str, str | None]] = set()
    for label in case.expected:
        covered = [f for f in findings if _covers(label, f)]
        mentioned.update(f.pair for f in covered)
        if not covered:
            outcomes.append(Outcome(case.id, "fn", label.key, label.rule, label.want(), "absent"))
            continue
        satisfied = [f for f in covered if _satisfies(label, f)]
        if satisfied:
            hit = satisfied[0]
            outcomes.append(Outcome(case.id, "tp", hit.key, hit.rule, label.want(), hit.got()))
            continue
        strongest = max(
            covered,
            key=lambda f: (DECISIONS.index(f.decision), EVIDENCE_STATUSES.index(f.evidence_status)),
        )
        outcomes.append(
            Outcome(
                case.id,
                "fn",
                strongest.key,
                strongest.rule,
                label.want(),
                f"{strongest.got()} [{_compare(label, strongest)}]",
            )
        )

    counted_fp: set[tuple[str, str | None]] = set()
    for label in case.forbidden:
        for f in findings:
            if not _covers(label, f):
                continue
            mentioned.add(f.pair)
            if f.pair in counted_fp:
                continue
            counted_fp.add(f.pair)
            outcomes.append(
                Outcome(case.id, "fp", f.key, f.rule, f"not {label.key} (forbidden)", f.got())
            )

    extra: list[Reported] = []
    seen_extra: set[tuple[str, str | None]] = set()
    for f in findings:
        if f.pair in mentioned or f.pair in seen_extra:
            continue
        seen_extra.add(f.pair)
        if not case.expected:
            counted_fp.add(f.pair)
            outcomes.append(
                Outcome(case.id, "fp", f.key, f.rule, "nothing (expected list is empty)", f.got())
            )
        else:
            extra.append(f)

    unknown_missing = [c for c in case.expected_unknown if c not in run.unknown]
    return outcomes, extra, unknown_missing


def _ratio(num: int, den: int) -> str:
    """A ratio with its counts; `n/a` when the denominator is zero. Never a bare number."""
    if den == 0:
        return f"n/a ({num}/{den})"
    return f"{num / den:.3f} ({num}/{den})"


def _tally(outcomes: list[Outcome], by_rule: bool) -> dict[str, dict[str, int]]:
    stats: dict[str, dict[str, int]] = {}
    for o in outcomes:
        key = o.rule if by_rule else o.key
        row = stats.setdefault(key, {"tp": 0, "fp": 0, "fn": 0})
        row[o.kind] += 1
    return stats


def _table(stats: dict[str, dict[str, int]], head: str) -> list[str]:
    if not stats:
        return ["No findings were expected, forbidden or reported.", ""]
    L = [
        f"| {head} | tp | fp | fn | Precision tp/(tp+fp) | Recall tp/(tp+fn) |",
        "|---|---:|---:|---:|---|---|",
    ]
    for key in sorted(stats):
        s = stats[key]
        L.append(
            f"| `{key}` | {s['tp']} | {s['fp']} | {s['fn']} "
            f"| {_ratio(s['tp'], s['tp'] + s['fp'])} | {_ratio(s['tp'], s['tp'] + s['fn'])} |"
        )
    L.append("")
    return L


def _group_section(
    title: str, runs: list[CaseRun], outcomes: list[Outcome], level: str = "###"
) -> list[str]:
    L = [f"{level} {title} ({len(runs)} case{'s' if len(runs) != 1 else ''})", ""]
    if not runs:
        L.append("No cases.")
        L.append("")
        return L
    ids = {r.case.id for r in runs}
    mine = [o for o in outcomes if o.case in ids]
    L.append(f"{level}# Per rule")
    L.append("")
    L.extend(_table(_tally(mine, by_rule=True), "Rule"))
    L.append(f"{level}# Per rule and sub-finding")
    L.append("")
    L.extend(_table(_tally(mine, by_rule=False), "Rule/sub"))
    return L


def _rules_line() -> tuple[str, list[str], str]:
    """What ran: a sentence naming each rule and version, the missing modules, the policy."""
    try:
        from aisafe import rules as rules_mod
        from aisafe.policy import load_policy
    except Exception as exc:
        return f"Rules run: none (`aisafe.rules` could not be imported: {exc}).", [], "unknown"
    missing = list(getattr(rules_mod, "MISSING_RULE_MODULES", []))
    try:
        policy_version = load_policy().version
    except Exception:
        policy_version = "unknown"
    names = []
    for r in rules_mod.ALL_RULES:
        try:
            mechanism = r.mechanism_id()
        except Exception:
            mechanism = ""
        names.append(
            f"`{r.id}` v{getattr(r, 'version', 1)}" + (f" ({mechanism})" if mechanism else "")
        )
    if not names:
        return "Rules run: none (the rule registry is empty).", missing, policy_version
    return f"Rules run: {', '.join(names)}.", missing, policy_version


def render_cases_report(cases_dir: Path, runs: list[CaseRun]) -> str:
    judged = {run.case.id: judge(run) for run in runs}
    outcomes = [o for run in runs for o in judged[run.case.id][0]]
    reviewed = [r for r in runs if r.case.reviewed]
    unreviewed = [r for r in runs if not r.case.reviewed]
    rules_line, missing, policy_version = _rules_line()

    L: list[str] = []
    L.append("# Synthetic corpus score")
    L.append("")
    L.append(
        f"Scored `{_show(cases_dir)}`: {len(runs)} case{'s' if len(runs) != 1 else ''} "
        f"({len(reviewed)} reviewed, {len(unreviewed)} unreviewed; "
        f"{sum(1 for r in runs if r.case.split == 'dev')} dev, "
        f"{sum(1 for r in runs if r.case.split == 'heldout')} heldout). "
        f"Policy version {policy_version}."
    )
    L.append("")
    L.append(rules_line)
    if missing:
        L.append("")
        L.append(
            f"Rule modules missing from the registry: {', '.join(f'`{m}`' for m in missing)}. "
            "Every finding those modules would report counts as absent below."
        )
    L.append("")
    L.append(
        "> The labels decide. A number here says how far the detector agrees with the "
        "labels of these cases, written by people who know the detector. It is not a "
        "rule's precision on real software and is never copied onto a rule: "
        "`measured_precision` comes from the real corpus only (`bench/protocol.md`)."
    )
    L.append("")

    L.append("## Headline")
    L.append("")
    if reviewed:
        L.append(
            f"Reviewed cases only ({len(reviewed)}: `labels.reviewed_by` set). The "
            f"{len(unreviewed)} unreviewed draft(s) are scored separately below."
        )
        L.append("")
        for split in SPLITS:
            L.extend(
                _group_section(split, [r for r in reviewed if r.case.split == split], outcomes)
            )
        if unreviewed:
            L.append("## Unreviewed cases (drafts, not in the headline)")
            L.append("")
            L.append(
                "A case counts in the headline once a second person has recorded a review "
                "in `labels.reviewed_by`. Until then its labels are the author's alone."
            )
            L.append("")
            for split in SPLITS:
                L.extend(
                    _group_section(
                        split, [r for r in unreviewed if r.case.split == split], outcomes
                    )
                )
    else:
        L.append("**No reviewed cases: every number below is from unreviewed labels.**")
        L.append("")
        L.append(
            "A case counts as reviewed once a second person has recorded a review in "
            "`labels.reviewed_by`. Until then its labels are the author's alone and these "
            "tables are regression counts, not an accuracy claim."
        )
        L.append("")
        for split in SPLITS:
            L.extend(_group_section(split, [r for r in runs if r.case.split == split], outcomes))

    L.append("## Mismatches")
    L.append("")
    mismatches = [o for o in outcomes if o.kind != "tp"]
    if not mismatches:
        L.append(
            "None: every expected finding was reported as labelled and nothing forbidden fired."
        )
    else:
        L.append(
            f"{len(mismatches)} mismatch{'es' if len(mismatches) != 1 else ''}, verbatim. "
            "Each is a detector bug or a label bug; the resolution belongs in the case's "
            "`labels.disagreement`, never in a quiet edit of the label."
        )
        L.append("")
        L.append("| Case | Rule | Counted as | Expected | Got |")
        L.append("|---|---|---|---|---|")
        for o in sorted(mismatches, key=lambda o: (o.case, o.kind, o.key, o.got)):
            L.append(f"| `{o.case}` | `{o.key}` | {o.kind} | {o.expected} | {o.got} |")
    L.append("")

    extras = [(run.case.id, f) for run in runs for f in judged[run.case.id][1]]
    L.append("## Reported but not labelled")
    L.append("")
    if not extras:
        L.append("None.")
    else:
        L.append(
            f"{len(extras)} finding(s) reported on a case whose `expected` list names other "
            "findings, and which no `expected` or `forbidden` entry mentions. Not counted; "
            "the protocol says nothing else may fire, so each needs a label."
        )
        L.append("")
        L.append("| Case | Finding | Decision | Evidence status | Where |")
        L.append("|---|---|---|---|---|")
        for case_id, f in sorted(extras, key=lambda e: (e[0], e[1].key)):
            where = f"{f.file}:{f.line}" if f.file and f.file != "." else "unit"
            L.append(f"| `{case_id}` | `{f.key}` | {f.decision} | {f.evidence_status} | {where} |")
    L.append("")

    expecting = [run for run in runs if run.case.expected_unknown]
    L.append("## UNKNOWN items the cases expect")
    L.append("")
    if not expecting:
        L.append("No case names an `expected_unknown` category.")
    else:
        L.append("| Case | Category | Result |")
        L.append("|---|---|---|")
        for run in expecting:
            missing_cats = judged[run.case.id][2]
            for category in run.case.expected_unknown:
                if run.error is not None:
                    result = "not checked (case error)"
                elif category in missing_cats:
                    result = "**absent**"
                else:
                    result = "listed"
                L.append(f"| `{run.case.id}` | {category} | {result} |")
    L.append("")

    L.append("## Cases")
    L.append("")
    L.append("| Case | Split | Pair | Reviewed | Expected | Forbidden | tp | fp | fn | Note |")
    L.append("|---|---|---:|---|---:|---:|---:|---:|---:|---|")
    for run in runs:
        case = run.case
        mine = judged[case.id][0]
        counts = {k: sum(1 for o in mine if o.kind == k) for k in ("tp", "fp", "fn")}
        notes = []
        if run.error is not None:
            notes.append(f"error: {run.error}")
        if case.policy_version and case.policy_version != policy_version:
            notes.append(f"labelled under policy {case.policy_version}")
        if judged[case.id][2] and run.error is None:
            notes.append("expected UNKNOWN absent: " + ", ".join(judged[case.id][2]))
        L.append(
            f"| `{case.id}` | {case.split} | {case.pair if case.pair is not None else ''} "
            f"| {'yes' if case.reviewed else 'no'} | {len(case.expected)} | {len(case.forbidden)} "
            f"| {counts['tp']} | {counts['fp']} | {counts['fn']} | {'; '.join(notes)} |"
        )
    L.append("")

    disagreements = [run.case for run in runs if run.case.disagreement]
    L.append("## Disagreements recorded")
    L.append("")
    if not disagreements:
        L.append("None recorded in `labels.disagreement`.")
    else:
        for case in disagreements:
            L.append(f"- `{case.id}`: {' '.join(str(case.disagreement).split())}")
    L.append("")

    errors = [run for run in runs if run.error is not None]
    if errors:
        L.append("## Errors")
        L.append("")
        L.append(
            f"{len(errors)} case(s) could not be audited; every finding they expect counts "
            "as absent above. A crash here is a tool bug, not a label."
        )
        L.append("")
        for run in errors:
            L.append(f"- `{run.case.id}`: {run.error}")
        L.append("")

    L.append("## Method")
    L.append("")
    L.append(
        "- **tp**: an `expected` entry reported with the labelled decision, and with the "
        "labelled evidence status when the case names one (`any` matches every status)."
    )
    L.append(
        "- **fn**: an `expected` entry not reported, or reported only with a decision or "
        "evidence status other than the labelled one; the mismatch table says whether it "
        "was weaker or stronger."
    )
    L.append(
        "- **fp**: a `forbidden` entry reported, or any finding on a case whose `expected` "
        "list is empty, review-only findings included. A finding owed on such a case must "
        "be labelled."
    )
    L.append(
        "- `sub: null` (or no `sub`) in a label means any sub-finding of the rule. Counts "
        "are per case: a rule/sub reported on two files of one tree counts once. Counts "
        "are credited to the rule/sub as reported, or as labelled when nothing was reported "
        "(`AUD-1104/*`)."
    )
    L.append(
        "- **precision** = tp / (tp + fp); **recall** = tp / (tp + fn); each printed with "
        "its counts and `n/a` when the denominator is zero."
    )
    L.append(
        "- `heldout` cases are not read while a rule is tuned; a failure there is a finding "
        "about the detector."
    )
    L.append("")
    L.append("---")
    L.append("")
    L.append(
        f"Regenerate with `python bench/score.py --cases {_show(cases_dir)}`. Every number "
        "above is derived from the case labels and one in-process run of the rules; none is "
        "hand-written."
    )
    L.append("")
    return "\n".join(L)


def score_cases(cases_dir: Path, out_path: Path) -> int:
    try:
        cases = load_cases(cases_dir)
    except CaseError as exc:
        print(f"\nERROR: malformed case: {exc}\n", file=sys.stderr)
        return 2
    runs = [run_case(case) for case in cases]
    text = render_cases_report(cases_dir, runs)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8")

    outcomes = [o for run in runs for o in judge(run)[0]]
    counts = {k: sum(1 for o in outcomes if o.kind == k) for k in ("tp", "fp", "fn")}
    reviewed = sum(1 for run in runs if run.case.reviewed)
    print(
        f"Scored {len(runs)} case(s) ({reviewed} reviewed): "
        f"tp={counts['tp']} fp={counts['fp']} fn={counts['fn']} -> {out_path}"
    )
    errors = [run for run in runs if run.error is not None]
    for run in errors:
        print(f"  !! {run.case.id}: {run.error}", file=sys.stderr)
    if reviewed == 0:
        print("  no reviewed cases: every number below is from unreviewed labels")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="bench/score.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--tool",
        choices=TOOLS,
        default="audit",
        help="which CLI's labelled rows to score (the audit is the only one)",
    )
    p.add_argument(
        "--min-precision",
        type=float,
        default=DEFAULT_MIN_PRECISION,
        help=f"Default-on threshold (default: {DEFAULT_MIN_PRECISION})",
    )
    p.add_argument(
        "--allow-partial",
        action="store_true",
        help="Score only the labelled subset instead of failing",
    )
    p.add_argument("--csv", type=Path, default=None, help="labelled CSV (default: per --tool)")
    p.add_argument(
        "--results", type=Path, default=None, help="raw report directory (default: per --tool)"
    )
    p.add_argument(
        "--cases",
        type=Path,
        default=None,
        metavar="DIR",
        help="score the synthetic corpus under DIR (one <id>/tree + <id>/expected.yaml per case)",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=None,
        help=f"markdown to write (default: per --tool, or {_show(CASES_OUT)} with --cases)",
    )
    args = p.parse_args(argv)

    if args.cases is not None:
        if args.csv is not None or args.results is not None or args.allow_partial:
            p.error(
                "--cases scores the synthetic corpus; --csv, --results and --allow-partial belong to the labelled-CSV mode"
            )
        return score_cases(args.cases, args.out or CASES_OUT)
    return score_labels(args)


if __name__ == "__main__":
    sys.exit(main())
