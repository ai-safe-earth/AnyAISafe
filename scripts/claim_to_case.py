"""scripts/claim_to_case.py
-------------------------
Turn a claim a person confirmed into a bench-case skeleton: a positive case and its
benign twin, under `bench/drafts/` (move both into `bench/cases/` once the twin's tree and
labels are written, so a half-made twin never enters a score).

    python scripts/claim_to_case.py --record .aisafe-audit/investigations/inv-attach.json \\
        --tree . --confirmed-by "J. Doe <product owner>" --case-id attachment-evening-wait
    python scripts/claim_to_case.py --reference research/results/reference/dev-labels.csv \\
        --item <item_id> --clones bench/.cache --case-id persona-denial-template

The positive case copies the files the claim cites into `tree/` and writes
`expected.yaml` with the decision the person confirmed, attributed to them
(`labels.authored_by`), `reviewed_by: null` until a second person reviews it. The twin
copies the same files and writes an `expected.yaml` with **no** label: the person who edits
the twin's tree into the benign lookalike (the mechanism's `distinct_from` text, quoted in
`TWIN.md`) writes its labels. Nothing here writes, prefills or suggests a verdict nobody
gave.

A claim from a held-out repository (`split: heldout` in `research/corpus.yaml`) is refused:
held-out material never becomes a case. An existing case directory is never overwritten.
Exit codes: 0 written, 2 refused or malformed input. Not shipped; run from the repo root.
"""

from __future__ import annotations

import argparse
import csv
import shutil
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

CASES = REPO / "bench" / "drafts"
CORPUS = REPO / "research" / "corpus.yaml"


def _die(message: str) -> int:
    print(f"claim_to_case: {message}", file=sys.stderr)
    return 2


def heldout_names() -> set[str]:
    import yaml

    data = yaml.safe_load(CORPUS.read_text(encoding="utf-8")) or {}
    return {
        str(r.get("name"))
        for r in data.get("repos") or []
        if isinstance(r, dict) and r.get("split") == "heldout"
    }


def _cited_files(record: dict[str, Any]) -> list[str]:
    files: set[str] = set()
    for link in record.get("links") or []:
        files.add(str(link.get("file")))
        for hop in link.get("via") or []:
            files.add(str(hop.get("file")))
    for control in record.get("controls") or []:
        location = control.get("location")
        if isinstance(location, dict):
            files.add(str(location.get("file")))
    surface = record.get("surface") or {}
    if surface.get("type") != "person_facing_unit" and surface.get("file"):
        files.add(str(surface.get("file")))
    return sorted(f for f in files if f and f != "None")


def _copy(tree: Path, files: list[str], dest: Path) -> None:
    root = tree.resolve()
    for rel in files:
        source = (root / rel).resolve()
        if root not in source.parents:
            raise ValueError(f"{rel} is outside the tree")
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    for manifest in ("pyproject.toml", "package.json"):
        if (root / manifest).is_file() and not (dest / manifest).exists():
            shutil.copyfile(root / manifest, dest / manifest)


def _yaml(doc: dict[str, Any]) -> str:
    import yaml

    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=False)


def _write_pair(
    case_id: str,
    tree: Path,
    files: list[str],
    *,
    description: str,
    expected: list[dict[str, Any]],
    investigation: dict[str, Any],
    confirmed_by: str,
    confirmed_at: str,
    distinct_from: str,
    cases: Path,
) -> list[Path]:
    from aisafe.policy import load_policy

    positive = cases / case_id
    twin = cases / f"{case_id}-benign"
    for path in (positive, twin):
        if path.exists():
            raise ValueError(f"{path.as_posix()} exists; a case is never overwritten")
    policy = load_policy()
    pair = None
    for directory, kind in ((positive, "positive"), (twin, "twin")):
        _copy(tree, files, directory / "tree")
        doc: dict[str, Any] = {
            "schema": "aisg/1",
            "kind": "bench-case",
            "id": directory.name,
            "pair": pair,
            "split": "dev",
            "description": description if kind == "positive" else f"the benign twin of {case_id}",
            "policy_version": policy.version,
            "expected": expected if kind == "positive" else [],
            "forbidden": [],
            "expected_unknown": [],
            "investigation": investigation if kind == "positive" else None,
            "labels": {
                "authored_by": confirmed_by if kind == "positive" else None,
                "authored_at": confirmed_at if kind == "positive" else None,
                "reviewed_by": None,
                "reviewed_at": None,
                "disagreement": None,
            },
        }
        (directory / "expected.yaml").write_text(_yaml(doc), encoding="utf-8", newline="\n")
    (twin / "TWIN.md").write_text(
        "# The benign twin\n\n"
        f"Edit `tree/` so that it looks like `{case_id}` and the mechanism is absent. The\n"
        "policy draws the line here:\n\n"
        f"> {distinct_from}\n\n"
        "Then write this case's labels in `expected.yaml` yourself: nothing was filled in\n"
        "for you, and `labels.authored_by` is whoever writes them.\n",
        encoding="utf-8",
        newline="\n",
    )
    return [positive, twin]


def from_record(args: argparse.Namespace) -> int:
    from aisafe.investigation.records import INVESTIGATION_SCHEMA, RecordError, load_json
    from aisafe.policy import load_policy

    if not args.confirmed_by or not args.confirmed_by.strip():
        return _die("--confirmed-by names the person who confirmed the claim")
    try:
        record = load_json(Path(args.record))
    except RecordError as exc:
        return _die(str(exc))
    if not isinstance(record, dict) or record.get("schema") != INVESTIGATION_SCHEMA:
        return _die("not an investigation record")
    target = str((record.get("target") or {}).get("path") or "")
    if Path(args.tree).resolve().name in heldout_names() or Path(target).name in heldout_names():
        return _die("the claim comes from a held-out repository; refused")
    policy = load_policy()
    pattern = policy.pattern_by_id(str(record.get("mechanism")), str(record.get("pattern")))
    if pattern is None:
        return _die("the record names no policy pattern")
    decision = str((record.get("proposed") or {}).get("decision") or "")
    if decision not in ("violates_policy", "requires_contextual_review"):
        return _die("only a claim that establishes or reviews a mechanism becomes a positive case")
    expected = []
    if pattern.rules:
        rule, _, sub = pattern.rules[0].partition("/")
        expected.append(
            {"rule": rule, "sub": sub or None, "decision": decision, "evidence_status": "any"}
        )
    mechanism = policy.mechanism_by_id(pattern.mechanism)
    try:
        written = _write_pair(
            args.case_id,
            Path(args.tree),
            _cited_files(record),
            description=str(record.get("hypothesis") or ""),
            expected=expected,
            investigation={
                "mechanism": pattern.mechanism,
                "pattern": pattern.id,
                "decision": decision,
                "record": record.get("id"),
            },
            confirmed_by=args.confirmed_by.strip(),
            confirmed_at=args.confirmed_at,
            distinct_from=mechanism.distinct_from if mechanism else "",
            cases=Path(args.cases),
        )
    except (OSError, ValueError) as exc:
        return _die(str(exc))
    for path in written:
        print(path.as_posix())
    if not expected:
        print(f"note: {pattern.display_id} has no rule; the case measures investigation only")
    return 0


def from_reference(args: argparse.Namespace) -> int:
    from aisafe.policy import load_policy

    with Path(args.reference).open(newline="", encoding="utf-8") as fh:
        row = next((r for r in csv.DictReader(fh) if r.get("item_id") == args.item), None)
    if row is None:
        return _die(f"no reference row {args.item}")
    if row.get("verdict") != "confirm" or not (row.get("reviewer") or "").strip():
        return _die("only a line a named reviewer confirmed becomes a case")
    if row.get("repo") in heldout_names():
        return _die("the line comes from a held-out repository; refused")
    mechanism = load_policy().mechanism_by_id(row.get("mechanism") or "")
    if mechanism is None:
        return _die("the confirmed line names no mechanism")
    try:
        written = _write_pair(
            args.case_id,
            Path(args.clones) / str(row.get("repo")),
            [str(row.get("file"))],
            description=f"{row.get('behaviour') or mechanism.name} ({row.get('repo')} {row.get('file')}:{row.get('line')})",
            expected=[],
            investigation={"mechanism": mechanism.id, "reference_item": args.item},
            confirmed_by=str(row.get("reviewer")).strip(),
            confirmed_at=str(row.get("labelled_at") or ""),
            distinct_from=mechanism.distinct_from,
            cases=Path(args.cases),
        )
    except (OSError, ValueError) as exc:
        return _die(str(exc))
    for path in written:
        print(path.as_posix())
    print("note: a reference line names a mechanism, not a rule; add the rule label yourself")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--record", help="an investigation record a person confirmed")
    source.add_argument("--reference", help="a reference-labels CSV from the review console")
    parser.add_argument("--item", help="with --reference: the confirmed row's item_id")
    parser.add_argument("--tree", default=".", help="with --record: the tree the record cites")
    parser.add_argument("--clones", default=str(REPO / "bench" / ".cache"), help="with --reference")
    parser.add_argument(
        "--confirmed-by", default=None, help="with --record: the person, 'Name <role>'"
    )
    parser.add_argument(
        "--confirmed-at", default=None, help="with --record: the date they confirmed it"
    )
    parser.add_argument(
        "--case-id", required=True, help="the new case's id (the twin gets -benign)"
    )
    parser.add_argument(
        "--cases", default=str(CASES), help="where the drafts go (default bench/drafts)"
    )
    args = parser.parse_args(argv)
    if args.record:
        if args.confirmed_at is None:
            from datetime import date

            args.confirmed_at = date.today().isoformat()
        return from_record(args)
    if not args.item:
        return _die("--reference needs --item")
    return from_reference(args)


if __name__ == "__main__":
    sys.exit(main())
