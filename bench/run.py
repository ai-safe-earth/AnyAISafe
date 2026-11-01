"""
bench/run.py
------------
Clone every repository in a corpus manifest at its pinned commit, run `aisafe audit`
over it, and collect the findings for hand-labelling.

Outputs (under `--out-dir`, default bench/):
    results-audit/<name>.json   the audit report per repository
    findings-audit.csv          one row per sampled finding, `verdict` left EMPTY
    findings-audit-all.csv      every finding, unsampled

The verdict column is deliberately blank. It is filled in by hand -- tp / fp /
unclear -- and bench/score.py refuses to run until it is complete. Nothing in
this harness infers, guesses or defaults a verdict.

Usage:
    python bench/run.py                        # full corpus
    python bench/run.py --only langchain crewAI
    python bench/run.py --keep-clones          # leave checkouts in bench/.cache
    python bench/run.py --experimental         # also run rules measured below threshold

Another corpus, written somewhere else, a subset of the rules (research/):
    python bench/run.py --corpus research/corpus.yaml \
        --out-dir research/results --rules AUD-1101,AUD-1102
`--out-dir` holds that run's results-audit/ and both CSVs; `bench/score.py` then
takes `--csv`, `--results` and `--out` pointing into it. Clones share bench/.cache.

`--tool audit` is accepted for compatibility with older notes; the audit is the only tool.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

BENCH = Path(__file__).resolve().parent
ROOT = BENCH.parent
sys.path.insert(0, str(ROOT / "src"))

from aisafe.devtools._git import GitError, fetch_pinned  # noqa: E402
from aisafe.devtools.fleet import _child_env, _safe_path_works  # noqa: E402

CORPUS = BENCH / "corpus.yaml"
CACHE = BENCH / ".cache"

RESULTS_AUDIT = BENCH / "results-audit"
CSV_AUDIT_PATH = BENCH / "findings-audit.csv"
CSV_AUDIT_ALL_PATH = BENCH / "findings-audit-all.csv"

TOOLS = ("audit",)

# Findings kept per rule for hand-labelling. A full corpus produces thousands of
# findings, which nobody labels; precision needs roughly 30-50 judged findings per
# rule, not thousands. 0 disables sampling.
DEFAULT_SAMPLE_PER_RULE = 40

# One row per finding. `rule_id` is the PARENT rule (precision is a class attribute);
# `sub` is the sub-finding; `decision` and `evidence_status` are the audit's own
# statements, carried so a labeller judges the claim the report made, not a guess at it;
# `snippet` is the first evidence leg, already redacted by the audit, so a labeller needs
# no clone and a quoted key never reaches the CSV.
AUDIT_CSV_COLUMNS = [
    "repo",
    "file",
    "line",
    "rule_id",
    "sub",
    "decision",
    "evidence_status",
    "message",
    "snippet",
    "verdict",
]


def paths_for(tool: str = "audit", base: Path = BENCH) -> tuple[Path, Path, Path, list[str]]:
    """(results dir, sampled CSV, full CSV, columns) for a tool, under `base`."""
    if tool not in TOOLS:
        raise ValueError(f"unknown tool {tool!r}; the audit is the only tool")
    return (
        base / RESULTS_AUDIT.name,
        base / CSV_AUDIT_PATH.name,
        base / CSV_AUDIT_ALL_PATH.name,
        AUDIT_CSV_COLUMNS,
    )


def load_corpus(path: Path = CORPUS) -> list[dict]:
    try:
        import yaml
    except ModuleNotFoundError:
        sys.exit("pyyaml is required: pip install pyyaml")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    repos = data.get("repos") or []
    if not repos:
        sys.exit(f"No repos listed in {path}")
    for r in repos:
        missing = {"name", "url", "sha"} - set(r)
        if missing:
            sys.exit(f"corpus entry {r.get('name', '?')} missing keys: {sorted(missing)}")
        if len(str(r["sha"])) != 40:
            sys.exit(f"corpus entry {r['name']}: sha is not a full 40-char commit id")
    return repos


def fetch(repo: dict) -> Path:
    """
    Shallow-fetch exactly the pinned commit through `aisafe.devtools._git.fetch_pinned`
    (one implementation, shared with `aisafe fleet`). A cached checkout whose stamp
    names the SHA is reused.
    """
    dest = CACHE / repo["name"]
    stamp = dest / ".aisafe-bench-sha"
    if stamp.is_file() and stamp.read_text(encoding="utf-8").strip() == repo["sha"]:
        print(f"    cached at {repo['sha'][:12]}")
        return dest
    fetch_pinned(repo["url"], repo["sha"], dest, branch=repo.get("branch"), timeout=1800)
    return dest


def audit_argv(out_file: Path, rules: str | None = None, experimental: bool = False) -> list[str]:
    """
    The child command: `aisafe audit . --format json --fail-on never -o <out>`.
    `rules` is a CSV of rule ids passed through as `--rules`, so a corpus built for one
    group measures only that group; `experimental` passes `--experimental` so rules
    measured below threshold run too (a benchmark measures them, it does not trust them).
    """
    argv = [
        sys.executable,
        "-m",
        "aisafe.cli",
        "audit",
        ".",
        "--format",
        "json",
        "--fail-on",
        "never",
        "-o",
        str(out_file.resolve()),
    ]
    if rules:
        argv += ["--rules", rules]
    if experimental:
        argv.append("--experimental")
    return argv


def audit(
    path: Path, out_file: Path, rules: str | None = None, experimental: bool = False
) -> tuple[int, dict | None]:
    """
    Run the audit with the clone as cwd (so the target's own `[tool.aisafe-audit]`
    applies, as under the skill). Exit 0 and 1 are both a completed audit; 2 is fatal
    and says so.
    """
    proc = subprocess.run(
        audit_argv(out_file, rules, experimental),
        capture_output=True,
        text=True,
        cwd=str(path),
        env=_child_env(),
        timeout=3600,
    )
    if proc.returncode == 2:
        print(f"    !! audit fatal: {proc.stderr.strip()[:300]}")
    summary = None
    if out_file.is_file():
        try:
            summary = json.loads(out_file.read_text(encoding="utf-8")).get("summary")
        except json.JSONDecodeError as exc:
            print(f"    !! unreadable JSON report: {exc}")
    return proc.returncode, summary


def rows_from_audit_json(name: str, jf: Path) -> list[dict]:
    """
    One row per audit finding, flattened from the report: the parent `rule_id`
    (the class the precision belongs to), the `sub`, the audit's `decision` and
    `evidence_status`, the title, and the first evidence leg's file, line and snippet.
    The snippet is already redacted by the audit. A finding with no evidence keeps an
    empty file and line. `verdict` stays empty by design.
    """
    if not jf.is_file():
        return []
    try:
        data = json.loads(jf.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    rows = []
    for f in data.get("findings", []):
        evidence = f.get("evidence") or []
        first = evidence[0] if evidence and isinstance(evidence[0], dict) else {}
        rows.append(
            {
                "repo": name,
                "file": str(first.get("file") or "").replace("\\", "/"),
                "line": first.get("line", "") if first.get("line") is not None else "",
                "rule_id": f.get("rule_id") or str(f.get("id", "")).split("/")[0],
                "sub": f.get("sub") or "",
                "decision": f.get("decision") or "",
                "evidence_status": f.get("evidence_status") or "",
                "message": f.get("title", ""),
                "snippet": " ".join(str(first.get("snippet") or "").split()),
                "verdict": "",
            }
        )
    return rows


def sample_per_rule(rows: list[dict], per_rule: int) -> list[dict]:
    """
    Keep at most `per_rule` findings for each rule, spread across repos.

    Round-robin over repos rather than taking the first N, so a rule is not
    measured entirely against whichever repo happens to sort first -- one
    codebase's idiosyncrasies would masquerade as the rule's precision.

    Deterministic: the same findings yield the same sample every run, so
    labelling work is never invalidated by a re-run. Keyed on `rule_id`, `repo`,
    `file` and `line` only, so extra columns never change the draw.
    """
    if per_rule <= 0:
        return rows

    by_rule: dict[str, dict[str, list[dict]]] = {}
    for row in rows:
        by_rule.setdefault(row["rule_id"], {}).setdefault(row["repo"], []).append(row)

    kept: list[dict] = []
    for rule in sorted(by_rule):
        per_repo = by_rule[rule]
        for repo in per_repo:
            per_repo[repo].sort(key=lambda r: (r["file"], int(r["line"] or 0)))
        repos = sorted(per_repo)
        taken, idx = 0, 0
        while taken < per_rule and any(per_repo[r] for r in repos):
            repo = repos[idx % len(repos)]
            if per_repo[repo]:
                kept.append(per_repo[repo].pop(0))
                taken += 1
            idx += 1
    return kept


def merge_preserving_verdicts(new_rows: list[dict], path: Path = CSV_AUDIT_PATH) -> list[dict]:
    """
    Re-running the harness must never destroy labelling work already done.
    Verdicts are carried over by (repo, file, line, rule_id).
    """
    if not path.is_file():
        return new_rows
    existing: dict[tuple, str] = {}
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            key = (row.get("repo"), row.get("file"), str(row.get("line")), row.get("rule_id"))
            if (row.get("verdict") or "").strip():
                existing[key] = row["verdict"].strip()
    carried = 0
    for row in new_rows:
        key = (row["repo"], row["file"], str(row["line"]), row["rule_id"])
        if key in existing:
            row["verdict"] = existing[key]
            carried += 1
    if carried:
        print(f"\nCarried over {carried} existing verdict(s) from the previous {path.name}")
    return new_rows


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="bench/run.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--tool",
        choices=TOOLS,
        default="audit",
        help="which CLI to run (the audit is the only one; kept for compatibility)",
    )
    p.add_argument("--only", nargs="*", default=None, help="Limit to these corpus names")
    p.add_argument("--keep-clones", action="store_true", help="Leave checkouts in bench/.cache")
    p.add_argument(
        "--experimental",
        action="store_true",
        help="pass `--experimental` to the audit so rules measured below threshold run too",
    )
    p.add_argument(
        "--sample-per-rule",
        type=int,
        default=DEFAULT_SAMPLE_PER_RULE,
        metavar="N",
        help=(
            f"Findings kept per rule in the labelling CSV, spread across repos "
            f"(default: {DEFAULT_SAMPLE_PER_RULE}; 0 = keep everything). "
            "The complete set is always written to the -all CSV."
        ),
    )
    p.add_argument(
        "--corpus",
        type=Path,
        default=CORPUS,
        metavar="YAML",
        help=f"corpus manifest to run (default: {CORPUS.relative_to(ROOT)})",
    )
    p.add_argument(
        "--out-dir",
        type=Path,
        default=BENCH,
        metavar="DIR",
        help="where results-audit/ and the two CSVs go (default: bench/)",
    )
    p.add_argument(
        "--rules",
        default=None,
        metavar="CSV",
        help="audit only these rule ids, passed through as `aisafe audit --rules`",
    )
    args = p.parse_args(argv)

    results_dir, csv_path, csv_all_path, columns = paths_for(args.tool, args.out_dir)

    if not _safe_path_works():
        sys.exit(
            "bench/run.py needs Python 3.11 or later: each audit runs inside a clone, and only "
            "from 3.11 does PYTHONSAFEPATH stop a folder of that clone standing in for aisafe"
        )
    repos = load_corpus(args.corpus)
    if args.only:
        wanted = {n.lower() for n in args.only}
        repos = [r for r in repos if r["name"].lower() in wanted]
        if not repos:
            available = ", ".join(r["name"] for r in load_corpus(args.corpus))
            sys.exit(f"--only matched nothing. Available: {available}")

    results_dir.mkdir(parents=True, exist_ok=True)
    CACHE.mkdir(parents=True, exist_ok=True)

    failures: list[str] = []
    started = time.time()

    for i, repo in enumerate(repos, 1):
        name = repo["name"]
        print(f"[{i}/{len(repos)}] {repo.get('repo', repo['url'])} @ {repo['sha'][:12]}")
        t0 = time.time()
        try:
            clone = fetch(repo)
        except GitError as exc:
            print(f"    !! clone failed: {str(exc)[:300]}")
            failures.append(f"{name}: clone failed")
            continue

        try:
            code, summary = audit(
                clone, results_dir / f"{name}.json", args.rules, args.experimental
            )
        except subprocess.TimeoutExpired:
            print("    !! audit timed out after 3600s")
            failures.append(f"{name}: audit timeout")
            continue

        rows = rows_from_audit_json(name, results_dir / f"{name}.json")
        if summary:
            severity = summary.get("by_severity") or {}
            print(
                f"    {len(rows)} findings "
                f"({severity.get('critical', 0)}C/{severity.get('high', 0)}H), "
                f"{summary.get('unknown_items', 0)} UNKNOWN, exit={code} "
                f"in {time.time() - t0:.1f}s"
            )
        else:
            print(f"    no summary produced (exit={code})")
            failures.append(f"{name}: no summary")

        if not args.keep_clones:
            shutil.rmtree(clone, ignore_errors=True)

    # Rebuild from every report in the results dir, not just the repos scanned now.
    # Otherwise `--only <repo>` would silently drop every other repo's rows.
    all_rows: list[dict] = []
    for jf in sorted(results_dir.glob("*.json")):
        all_rows.extend(rows_from_audit_json(jf.stem, jf))

    all_rows = merge_preserving_verdicts(all_rows, csv_path)
    order = lambda r: (r["rule_id"], r["repo"], r["file"], int(r["line"] or 0))  # noqa: E731
    all_rows.sort(key=order)

    def write(path: Path, rows: list[dict]) -> None:
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=columns)
            w.writeheader()
            w.writerows(rows)

    # The complete set is always kept, so sampling never loses evidence.
    write(csv_all_path, all_rows)

    sampled = sample_per_rule(all_rows, args.sample_per_rule)
    sampled.sort(key=order)
    write(csv_path, sampled)

    unlabelled = sum(1 for r in sampled if not r["verdict"])
    distinct = len({r["rule_id"] for r in sampled})
    print("\n" + "=" * 70)
    print(
        f"{len(all_rows)} findings across {len(repos) - len(failures)} repos "
        f"in {time.time() - started:.0f}s"
    )
    print(f"{distinct} distinct rules fired")
    print(f"\nfull set  -> {csv_all_path}  ({len(all_rows)} rows)")
    if args.sample_per_rule > 0:
        print(
            f"to label  -> {csv_path}  ({len(sampled)} rows, "
            f"<={args.sample_per_rule} per rule spread across repos)"
        )
        print("            --sample-per-rule 0 keeps everything")
    else:
        print(f"to label  -> {csv_path}  ({len(sampled)} rows, sampling disabled)")
    if failures:
        print(f"\n{len(failures)} repo(s) did not complete:")
        for f in failures:
            print(f"  - {f}")
    print(f"\nNEXT: label the `verdict` column ({unlabelled} blank) with tp / fp / unclear,")
    flags = " --tool audit"
    if args.out_dir.resolve() != BENCH.resolve():
        out = args.out_dir
        flags += f" --csv {csv_path} --results {results_dir} --out {out / 'precision-audit.md'}"
    print(f"      then run:  python bench/score.py{flags}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
