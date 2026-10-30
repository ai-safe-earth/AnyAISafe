"""
bench/investigate.py
--------------------
Compare investigation records with the labels people wrote, and print every disagreement.

Two label sources:

1. The synthetic cases (`--cases bench/cases`). Records for a case live under
   `<RECORDS>/<case-id>/`; each is validated against a copy of the case's `tree/` (outside
   git, so its `target.commit` is `null`) and its effective claim per mechanism pattern is
   compared with the case's `expected` and `forbidden` labels: an expected
   `violates_policy` wants a record that establishes the pattern, an expected review wants
   a record at review (or stronger, reported as such), a forbidden label or an empty
   `expected` list wants no record that establishes it.
2. The blind reference labels from the review console (`--reference
   research/results/reference/<set>-labels.csv`). A confirmed line naming a mechanism wants
   a record of that mechanism that establishes it and cites the line; a rejected line wants
   no establishing record that cites it. Records live under `<RECORDS>/<repo>/` and are
   validated against the pinned clone under `--clones` (default `bench/.cache`).

Every agreement and disagreement is counted and every disagreement is printed with the
case or repository, the label and the record. Precision and recall are printed only for
labels a second person reviewed (`labels.reviewed_by` on a case; a `second_reviewer`
column on a reference row); every other number is printed as "unreviewed".

Held-out repositories (`split: heldout` in `research/corpus.yaml`) are never investigated
in this milestone: a record directory named after one is refused, and the script exits 2.

Usage:
    python bench/investigate.py --records bench/investigations --cases bench/cases
    python bench/investigate.py --records research/investigations --reference research/results/reference/dev-labels.csv

Exit codes: 0 a report was printed (disagreements are results, not failures); 2 malformed
input or a record directory for a held-out repository.
"""

from __future__ import annotations

import argparse
import csv
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

BENCH = Path(__file__).resolve().parent
ROOT = BENCH.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(BENCH))

CORPUS = ROOT / "research" / "corpus.yaml"
CLONES = BENCH / ".cache"


@dataclass
class Tally:
    agree: int = 0
    disagree: int = 0
    not_investigated: int = 0
    reviewed_agree: int = 0
    reviewed_disagree: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    lines: list[str] = field(default_factory=list)

    def add(self, verdict: str, reviewed: bool, text: str, kind: str | None = None) -> None:
        if verdict == "agree":
            self.agree += 1
            self.reviewed_agree += int(reviewed)
        elif verdict == "disagree":
            self.disagree += 1
            self.reviewed_disagree += int(reviewed)
            self.lines.append("disagree: " + text)
        else:
            self.not_investigated += 1
            self.lines.append("not investigated: " + text)
        if reviewed and kind:
            setattr(self, kind, getattr(self, kind) + 1)


def heldout_names() -> set[str]:
    import yaml

    data = yaml.safe_load(CORPUS.read_text(encoding="utf-8")) or {}
    return {
        str(repo.get("name"))
        for repo in data.get("repos") or []
        if isinstance(repo, dict) and repo.get("split") == "heldout"
    }


def _validate(tree: Path, records: Path):
    from aisafe.investigation.plan import build_plan
    from aisafe.investigation.scan import machine_scan
    from aisafe.investigation.validate import validate_paths

    scan = machine_scan(tree)
    plan = build_plan(scan)
    run = validate_paths([records], scan, plan_surfaces={s["id"]: s for s in plan["surfaces"]})
    return run


def _claims(run) -> dict[tuple[str, str], list]:
    out: dict[tuple[str, str], list] = {}
    for result in run.results:
        if result.accepted:
            out.setdefault((result.mechanism, result.pattern), []).append(result)
    return out


def compare_cases(cases_dir: Path, records_dir: Path, tally: Tally) -> None:
    from score import load_cases

    from aisafe.policy import load_policy

    policy = load_policy()
    for case in load_cases(cases_dir):
        mine = records_dir / case.id
        if not mine.is_dir():
            continue
        if case.split == "heldout":
            raise SystemExit(f"bench/investigate.py: {case.id} is a held-out case; refused")
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "tree"
            shutil.copytree(case.path / "tree", tree)
            run = _validate(tree, mine)
        for result in run.results:
            if result.status == "rejected":
                tally.lines.append(
                    f"rejected: {case.id}: {result.path}: {'; '.join(result.errors)}"
                )
        claims = _claims(run)
        reviewed = case.reviewed
        for label in case.expected:
            pattern = policy.pattern_of(label.key.replace("/*", ""))
            if pattern is None:
                continue
            got = claims.get((pattern.mechanism, pattern.id), [])
            what = f"{case.id}: {label.want()} ({pattern.display_id})"
            if not got:
                tally.add("not_investigated", reviewed, what, kind="fn")
                continue
            strongest = (
                "establishes"
                if any(r.claim == "establishes" for r in got)
                else ("review" if any(r.claim == "review" for r in got) else "closes")
            )
            if label.decision == "violates_policy":
                ok = strongest == "establishes"
            else:
                ok = strongest in ("review", "establishes")
            tally.add(
                "agree" if ok else "disagree",
                reviewed,
                f"{what}: records {', '.join(f'{r.id} {r.claim}' for r in got)}",
                kind="tp"
                if ok and label.decision == "violates_policy"
                else ("fn" if not ok else None),
            )
        negatives = list(case.forbidden)
        for pattern_key, got in claims.items():
            establishing = [r for r in got if r.claim == "establishes"]
            if not establishing:
                continue
            forbidden = any(
                (p := policy.pattern_of(label.key.replace("/*", ""))) is not None
                and (p.mechanism, p.id) == pattern_key
                for label in negatives
            )
            if forbidden or not case.expected:
                tally.add(
                    "disagree",
                    reviewed,
                    f"{case.id}: {pattern_key[0]}/{pattern_key[1]} established by "
                    f"{', '.join(r.id for r in establishing)}, which the labels forbid",
                    kind="fp",
                )


def compare_reference(
    reference: Path, records_root: Path, clones: Path, tally: Tally, heldout: set[str]
) -> None:
    with reference.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    by_repo: dict[str, list[dict]] = {}
    for row in rows:
        by_repo.setdefault(row.get("repo") or "", []).append(row)
    for repo, labels in sorted(by_repo.items()):
        if repo in heldout:
            continue  # held-out lines are never compared with records in this milestone
        mine = records_root / repo
        if not mine.is_dir():
            for row in labels:
                if row.get("verdict") == "confirm" and row.get("mechanism"):
                    tally.add(
                        "not_investigated",
                        False,
                        f"{repo} {row.get('file')}:{row.get('line')} {row.get('mechanism')}",
                    )
            continue
        tree = clones / repo
        if not tree.is_dir():
            tally.lines.append(f"not validated: {repo}: no clone at {tree.as_posix()}")
            continue
        run = _validate(tree, mine)
        accepted = [r for r in run.results if r.accepted]
        for row in labels:
            verdict = row.get("verdict")
            mechanism = row.get("mechanism") or ""
            if verdict not in ("confirm", "reject") or not mechanism.startswith("M"):
                continue
            reviewed = bool((row.get("second_reviewer") or "").strip())
            file, line = row.get("file") or "", int(row.get("line") or 0)
            citing = [
                r
                for r in accepted
                if r.mechanism == mechanism
                and any(
                    link["file"] == file
                    and link["line"] <= line <= (link["end_line"] or link["line"])
                    for link in r.links
                )
            ]
            where = f"{repo} {file}:{line} {verdict} {mechanism}"
            if verdict == "confirm":
                if not citing:
                    tally.add("not_investigated", reviewed, where, kind="fn")
                elif any(r.claim == "establishes" for r in citing):
                    tally.add("agree", reviewed, where, kind="tp")
                else:
                    tally.add(
                        "disagree",
                        reviewed,
                        where + ": " + ", ".join(f"{r.id} {r.claim}" for r in citing),
                        kind="fn",
                    )
            else:
                establishing = [r for r in citing if r.claim == "establishes"]
                if establishing:
                    tally.add(
                        "disagree",
                        reviewed,
                        where + ": established by " + ", ".join(r.id for r in establishing),
                        kind="fp",
                    )
                else:
                    tally.add("agree", reviewed, where)


def _ratio(num: int, den: int) -> str:
    return f"{num}/{den} = {num / den:.2f}" if den else f"{num}/0 = n/a"


def render(tally: Tally) -> str:
    lines = [
        "# Investigation records against the labels",
        "",
        f"- agree: {tally.agree}",
        f"- disagree: {tally.disagree}",
        f"- not investigated: {tally.not_investigated}",
    ]
    reviewed = tally.reviewed_agree + tally.reviewed_disagree
    if reviewed:
        lines.append(f"- precision (reviewed labels): {_ratio(tally.tp, tally.tp + tally.fp)}")
        lines.append(f"- recall (reviewed labels): {_ratio(tally.tp, tally.tp + tally.fn)}")
    else:
        lines.append("- precision: unreviewed (no second person reviewed these labels)")
        lines.append("- recall: unreviewed (no second person reviewed these labels)")
    lines.append("")
    lines += [f"- {line}" for line in tally.lines] or ["- (no disagreement)"]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--records",
        required=True,
        help="a directory with one sub-directory of records per case or repository",
    )
    parser.add_argument("--cases", default=None, help="the synthetic cases (bench/cases)")
    parser.add_argument(
        "--reference", action="append", default=[], help="a reference-labels CSV from the console"
    )
    parser.add_argument("--clones", default=str(CLONES), help="the pinned clones of the corpus")
    parser.add_argument("--out", default=None, help="write the report here instead of stdout")
    args = parser.parse_args(argv)
    records = Path(args.records)
    if not records.is_dir():
        print(f"bench/investigate.py: {records} is not a directory", file=sys.stderr)
        return 2
    heldout = heldout_names()
    refused = sorted(p.name for p in records.iterdir() if p.is_dir() and p.name in heldout)
    if refused:
        print(
            "bench/investigate.py: records for held-out repositories are refused in this "
            "milestone: " + ", ".join(refused),
            file=sys.stderr,
        )
        return 2
    tally = Tally()
    try:
        if args.cases:
            compare_cases(Path(args.cases), records, tally)
        for reference in args.reference:
            compare_reference(Path(reference), records, Path(args.clones), tally, heldout)
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:  # malformed cases or labels
        print(f"bench/investigate.py: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    text = render(tally)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
