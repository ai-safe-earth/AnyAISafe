"""
research/console/console.py
---------------------------
Feed the review console and read its labels back.

The console is a private claude.ai page (research/console/index.html) where the owner
labels findings, answers open decisions and reads the research documents, from a phone
or any browser. The page holds no findings of its own: it reads a review set, a JSON
file this script builds from the labelling CSV, the audit reports and the clones, and it
keeps the owner's labels in the page's database. Claude reads those labels back and this
script writes them into the CSV, so `bench/score.py` scores them as before.

    python research/console/console.py build --set run3 \
        --csv research/results/run3/findings-audit.csv \
        --results research/results/run3/results-audit

    python research/console/console.py import --set run3 \
        --csv research/results/run3/findings-audit.csv --labels labels.json

`build` writes research/console/build/ (gitignored: it quotes other repositories' code).
`import` fills the `verdict` column and writes review-notes.csv beside the CSV. A label
is the owner's: the script copies it, never makes one, and refuses a verdict outside
{tp, fp, unclear}.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import quote

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from aisafe.evidence.model import redact  # noqa: E402

_KEY_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_KEY_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")

# Secret-shaped tokens, masked whole before `redact()` runs: the prefixes that
# `aisafe.evidence.model.REDACT_PATTERNS` recognises (Anthropic, OpenAI, GitHub, AWS,
# Slack, Google), a bearer token, and a PEM private-key header or footer on its own line.
_SECRET_RE = re.compile(
    r"\b(?:sk-ant-|sk-|github_pat_|gh[pousr]_)[A-Za-z0-9_\-]{20,}"
    r"|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
    r"|\bxox[abpors]-[A-Za-z0-9\-]{10,}"
    r"|\bAIza[0-9A-Za-z_\-]{35}"
    r"|(?i:\bbearer\s+)[A-Za-z0-9_\-.=+/]{20,}"
    r"|-----(?:BEGIN|END) [A-Z ]*PRIVATE KEY-----"
)
# Personal data a quoted line may carry: an e-mail address, an IBAN-shaped account
# number, and a phone-shaped run of nine or more digits with optional separators.
_PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    ("phone", re.compile(r"(?<![\w/.])\+?\d(?:[ \-.()]?\d){8,}(?![\w/.])")),
)

BUILD = ROOT / "research" / "console" / "build"
CORPUS = ROOT / "research" / "corpus.yaml"
CLONES = ROOT / "bench" / ".cache"
NOTES_SITE = ROOT / "research" / "results" / "notes-site.csv"
NOTES_UNIT = ROOT / "research" / "results" / "notes-unit.csv"
DOCS = (
    ("method", "Method", "research/README.md"),
    ("catalogue", "Catalogue", "research/catalogue.md"),
    ("log", "Research log", "research/log.md"),
)

VALID = ("tp", "fp", "unclear")
CONTEXT = 6  # lines shown above and below a matched line
LONG_LINE = 1200  # the matched line itself
SHORT_LINE = 240  # its neighbours

# What the owner judges for each rule: the finding's claim, never the app as a whole.
# `real` is a tp, `false` an fp. Where the rule's own definition leaves a case open, the
# guide says so instead of settling it.
GUIDES: dict[str, dict] = {
    "AUD-1101": {
        "question": "Does the app put what it knows about the real person into the prompt?",
        "real": "The code or template puts a stored or collected profile of the real user "
        "(history, traits, preferences, behaviour) into what the model reads.",
        "false": "The slot holds fiction such as a character card, the match is in a test, "
        "doc or build file, or nothing about a real person is kept.",
        "open": "If the only data is what the person typed about themselves for this chat, "
        "decide whether that is a profile. Unclear is a valid answer.",
        "subs": {
            "sensitive": {
                "question": "Does the app put a sensitive profile of the real person into "
                "the prompt?",
                "real": "As above, and the profile covers health, religion, sex life, "
                "politics, ethnicity, union membership, biometrics, mental state or "
                "disability.",
            }
        },
    },
    "AUD-1102": {
        "question": "Does the code guess a real person's emotions or body traits from their "
        "face, voice or body?",
        "real": "It reads a face, voice, body or other biometric signal of a person to infer "
        "emotion, identity or traits.",
        "false": "Text-only sentiment (the rule does not count it), a fictional character's "
        "mood, a setting or label name, or a test, doc or demo file.",
        "subs": {
            "categorisation": {
                "question": "Does the code sort people by protected traits using biometric data?",
                "real": "It infers race, politics, religion, sexual orientation or union "
                "membership from a face, voice or body.",
            }
        },
    },
    "AUD-1103": {
        "question": "Does the software decide or score something about a person with no human "
        "check first?",
        "real": "A score, rank or decision about a person takes effect with no review step.",
        "false": "The person word is only in a name or signature, it ranks documents or "
        "sources rather than people, or a human reviews the result first.",
        "subs": {
            "decision": {
                "question": "Does this function decide something about a person (approve, "
                "reject, rank, flag) with no human check before it takes effect?",
            },
            "scoring": {
                "question": "Does this prompt tell the model to score or rank people?",
                "real": "Prompt text asks the model to rate, score or rank persons.",
                "false": "It scores answers, documents or sources, or it is a test or example.",
            },
        },
    },
    "AUD-1104": {
        "question": "Is this an aim to keep the person engaged or coming back, rather than "
        "doing their task?",
        "real": "The prompt or code aims at time spent, retention, streaks, emotional "
        "bonding, or keeping the conversation going for its own sake.",
        "false": "A word match in CI, ad tooling, analytics or tests; an aim the person set "
        "themselves; or ordinary task wording.",
        "subs": {
            "outreach": {
                "question": "Does the app contact the person on its own schedule to bring "
                "them back?",
                "real": "A scheduled job sends the person a message, e-mail or push they "
                "did not ask for, such as a nudge or a re-engagement message.",
                "false": "A timer that polls the UI or an internal service, a reminder the "
                "person set, or a send that does not reach a person.",
            }
        },
    },
    "AUD-1105": {
        "question": "Does the person get AI output without being told it comes from an AI?",
        "real": "The software answers people with model output and hides or never states "
        "that it is an AI.",
        "false": "Nothing here reaches a person, or the AI nature is stated.",
        "subs": {
            "no-disclosure": {
                "question": "Does this part answer a real person with model output and never "
                "say it is an AI?",
                "real": "The unit serves model replies to people, and nothing in its code, "
                "config, prompts or UI says the replies come from an AI.",
                "false": "The unit does not face a person (a pipeline, library, training "
                "script or notebook), or it states the AI nature somewhere the rule did "
                "not look, such as UI text.",
            },
            "persona": {
                "question": "Does the prompt tell the model to claim to be human or hide that "
                "it is an AI?",
                "real": "The prompt tells the model to deny its AI nature, or to present "
                "itself to the person as human.",
                "false": "Role-play wording that never denies being an AI, or a test or doc.",
            },
            "synthetic": {
                "question": "Does the app make AI content (voice, image, video, post) that "
                "reaches people without a label saying it is AI-made?",
                "real": "Generated media or posts go out with no AI label or watermark.",
                "false": "The line is not about making content (a help text, a migration, a "
                "validator), or a label exists.",
            },
        },
    },
    "AUD-1106": {
        "question": "Does this part answer a person, carry a profile, engagement aim or "
        "persona, and have nothing that checks replies for manipulation?",
        "real": "The unit serves model replies to people, carries one of those signals, and "
        "no check reads the replies.",
        "false": "The unit does not face a person, the signal that set it off is wrong, or a "
        "reply check exists.",
    },
    "AUD-1108": {
        "question": "Can a person confide in this AI (as therapist, partner, friend or "
        "character) with no crisis path?",
        "real": "People chat with a confidant-style AI here, and there is no helpline, fixed "
        "crisis reply or self-harm check.",
        "false": "The unit does not face a person, the role is not one people confide in, or "
        "a crisis path exists that the rule missed.",
    },
}

VERDICTS = [
    {"v": "tp", "label": "Real", "help": "The evidence shows what the finding says."},
    {"v": "fp", "label": "False alarm", "help": "The evidence does not show it."},
    {
        "v": "unclear",
        "label": "Unclear",
        "help": "You cannot tell from what is here. It leaves the precision count.",
    },
]


def _show(path: Path) -> str:
    """A path as the repository names it, or in full when it lies outside."""
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def item_id(repo: str, file: str, line: str | int, rule_id: str, sub: str) -> str:
    """Stable id of one CSV row. The console stores labels under it."""
    key = "\x1f".join([repo, file, str(line), rule_id, sub or ""])
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


def row_id(row: dict) -> str:
    return item_id(row["repo"], row["file"], row["line"], row["rule_id"], row.get("sub", ""))


def read_csv(path: Path) -> tuple[list[str], list[dict]]:
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        return list(reader.fieldnames or []), list(reader)


def read_notes(path: Path) -> list[dict]:
    """The notes CSVs open with one `#` comment line."""
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        lines = [ln for ln in fh if not ln.startswith("#")]
    return list(csv.DictReader(lines))


def load_repos() -> dict[str, dict]:
    data = yaml.safe_load(CORPUS.read_text(encoding="utf-8"))
    out = {}
    for r in data.get("repos", []):
        out[r["name"]] = {
            "slug": r.get("repo", ""),
            "sha": r.get("sha", ""),
            "category": r.get("category", ""),
            "note": r.get("note", ""),
            "positive_control": bool(r.get("positive_control")),
        }
    return out


def first_leg_key(f: dict) -> tuple[str, str]:
    """The (file, line) bench/run.py writes for a finding: its first evidence leg."""
    evidence = f.get("evidence") or []
    first = evidence[0] if evidence and isinstance(evidence[0], dict) else {}
    line = first.get("line", "")
    return str(first.get("file") or "").replace("\\", "/"), "" if line is None else str(line)


def load_findings(results: Path) -> dict[tuple, dict]:
    out = {}
    for jf in sorted(results.glob("*.json")):
        data = json.loads(jf.read_text(encoding="utf-8"))
        for f in data.get("findings", []):
            file, line = first_leg_key(f)
            rule = f.get("rule_id") or str(f.get("id", "")).split("/")[0]
            out[(jf.stem, file, line, rule, f.get("sub") or "")] = f
    return out


def clip(text: str, limit: int) -> str:
    text = text.rstrip("\r\n")
    return text if len(text) <= limit else text[:limit] + " ..."


def mask(line: str) -> str:
    """Hide what a quoted line must not carry: secret tokens, personal data, then redact()."""
    line = _SECRET_RE.sub("<secret>", line)
    for entity, rx in _PII_PATTERNS:
        line = rx.sub(f"<pii:{entity}>", line)
    return redact(line)


def _key_blocks(lines: list[str]) -> set[int]:
    """1-based numbers of the lines inside a PEM private-key block."""
    hidden, inside = set(), False
    for n, text in enumerate(lines, start=1):
        if _KEY_BEGIN.search(text):
            inside = True
        if inside:
            hidden.add(n)
        if _KEY_END.search(text):
            inside = False
    return hidden


def clone_at(repo: str, sha: str) -> bool:
    """True when bench/.cache/<repo> was checked out at the pinned commit."""
    stamp = CLONES / repo / ".aisafe-bench-sha"
    try:
        return bool(sha) and stamp.read_text(encoding="utf-8").strip() == sha
    except OSError:
        return False


def context(repo: str, file: str, line: int) -> dict | None:
    """The lines around `line` in the clone, masked like the audit's own snippets."""
    if not file or file == "." or line <= 0:
        return None
    path = CLONES / repo / file
    if not path.is_file():
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if line > len(lines):
        return None
    hidden = _key_blocks(lines)
    start = max(1, line - CONTEXT)
    end = min(len(lines), line + CONTEXT)
    shown = []
    for n in range(start, end + 1):
        if n in hidden:
            shown.append("<private key line hidden>")
            continue
        limit = LONG_LINE if n == line else SHORT_LINE
        shown.append(mask(clip(lines[n - 1], limit)))
    full = "<private key line hidden>" if line in hidden else mask(lines[line - 1])
    return {"start": start, "hit": line, "lines": shown, "full": full}


def github_link(repo: dict, file: str, line: int, unit: bool) -> str:
    if not repo.get("slug") or not repo.get("sha"):
        return ""
    base = f"https://github.com/{repo['slug']}"
    if unit or not file or file == ".":
        path = "" if not file or file == "." else "/" + quote(file)
        return f"{base}/tree/{repo['sha']}{path}"
    return f"{base}/blob/{repo['sha']}/{quote(file)}#L{line}"


def site_note(notes: list[dict], key: tuple) -> dict:
    for n in notes:
        if (n["repo"], n["rule"], n.get("sub", ""), n["file"], n["line"]) == key:
            return {
                "what": n.get("what", ""),
                "faces_person": n.get("faces_person", ""),
                "reading": n.get("behaviour_here", ""),
            }
    return {}


def unit_note(notes: list[dict], repo: str, rule: str, name: str) -> dict:
    for n in notes:
        if n["repo"] == repo and n["rule"] == rule and n["unit"].split(" (")[0] == name:
            return {
                "what": n.get("what", ""),
                "faces_person": n.get("faces_person", ""),
                "reading": n.get("why", ""),
            }
    return {}


def build(args: argparse.Namespace) -> int:
    _, rows = read_csv(args.csv)
    findings = load_findings(args.results)
    repos = load_repos()
    notes_site = read_notes(NOTES_SITE)
    notes_unit = read_notes(NOTES_UNIT)

    items, missing, stale = [], [], set()
    for n, row in enumerate(rows, start=1):
        sub = row.get("sub", "")
        key = (row["repo"], row["file"], row["line"], row["rule_id"], sub)
        f = findings.get(key)
        if f is None:
            missing.append(key)
            continue
        repo = repos.get(row["repo"], {})
        # Code lines come from the clone only when it is at the commit the audit read.
        pinned = clone_at(row["repo"], repo.get("sha", ""))
        if not pinned:
            stale.add(row["repo"])
        scope = f.get("scope") or {}
        # Every finding names its unit; a unit-level one (an absence) has no matched line.
        first = (f.get("evidence") or [{}])[0]
        unit = first.get("role") == "absence" or not first.get("line")
        legs = []
        for leg in f.get("evidence") or []:
            lf = str(leg.get("file") or "").replace("\\", "/")
            ln = int(leg.get("line") or 0)
            legs.append(
                {
                    "role": leg.get("role", ""),
                    "file": lf,
                    "line": ln,
                    "snippet": leg.get("snippet", ""),
                    "context": context(row["repo"], lf, ln) if pinned else None,
                    "link": github_link(repo, lf, ln, unit=ln <= 0),
                }
            )
        hit = legs[0]["context"] if legs else None
        for leg in legs:
            if leg["context"]:
                leg["context"] = {k: v for k, v in leg["context"].items() if k != "full"}
        # "Same line" means the same evidence: the exact matched line and every other leg.
        group = ""
        if not unit and hit:
            others = sorted((leg["role"], leg["snippet"]) for leg in legs[1:])
            text = "\x1e".join([hit["full"], *("\x1d".join(o) for o in others)])
            group = hashlib.sha1(
                "\x1f".join([row["repo"], row["rule_id"], sub, text]).encode("utf-8")
            ).hexdigest()[:12]
        if unit:
            note = unit_note(notes_unit, row["repo"], row["rule_id"], scope.get("name", ""))
        else:
            note = site_note(notes_site, key)
        line = int(row["line"] or 0)
        items.append(
            {
                "id": row_id(row),
                "n": n,
                "repo": row["repo"],
                "rule": row["rule_id"],
                "sub": sub,
                "title": f.get("title", row.get("message", "")),
                "severity": f.get("severity", ""),
                "file": row["file"],
                "line": line,
                "unit": f"{scope.get('name', '')} ({scope.get('unit', '')})" if unit else "",
                "legs": legs,
                "fix": (f.get("recommendation") or {}).get("summary", ""),
                "failure_modes": f.get("known_failure_modes") or [],
                "note": note,
                "group": group,
                "link": github_link(repo, row["file"], line, unit=unit),
            }
        )
    if missing:
        print(f"ERROR: {len(missing)} CSV row(s) have no finding in {args.results}:")
        for key in missing[:10]:
            print("  ", key)
        return 1
    if stale:
        print(
            f"note: {len(stale)} clone(s) not at the pinned commit, shown with the audit's "
            f"snippet only: {', '.join(sorted(stale))}"
        )

    sizes: dict[str, int] = defaultdict(int)
    for it in items:
        if it["group"]:
            sizes[it["group"]] += 1
    for it in items:
        if sizes.get(it["group"], 0) < 2:
            it["group"] = ""

    used = sorted({it["rule"] for it in items})
    set_doc = {
        "id": args.set,
        "title": args.title,
        "about": args.about,
        "source": _show(args.csv),
        "verdicts": VERDICTS,
        "guides": {r: GUIDES[r] for r in used if r in GUIDES},
        "repos": {name: repos[name] for name in sorted({it["repo"] for it in items})},
        "items": items,
    }
    (BUILD / "sets").mkdir(parents=True, exist_ok=True)
    out = BUILD / "sets" / f"{args.set}.json"
    out.write_text(json.dumps(set_doc, ensure_ascii=False, separators=(",", ":")), "utf-8")

    manifest_path = BUILD / "manifest.json"
    manifest: dict = {"sets": [], "docs": []}
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = {
        "id": args.set,
        "title": args.title,
        "about": args.about,
        "file": f"sets/{args.set}.json",
        "count": len(items),
        "rules": used,
    }
    manifest["sets"] = [s for s in manifest.get("sets", []) if s["id"] != args.set] + [entry]
    manifest["docs"] = [
        {"id": d, "title": t, "file": f"docs/{d}.md", "source": s} for d, t, s in DOCS
    ]
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=1), "utf-8")
    print(f"{len(items)} items -> {_show(out)}")
    print(f"manifest   -> {_show(manifest_path)}")
    return 0


def _body(d: dict) -> dict:
    """A document's fields, whether or not the export wraps them in `data`."""
    inner = d.get("data")
    return inner if isinstance(inner, dict) else d


def read_labels(path: Path, set_id: str) -> tuple[dict[str, dict], int, list[str]]:
    """Label documents of one set keyed by item id: (labels, skipped, duplicate ids).

    `path` is either a directory, as a database read with `out_dir` writes it
    (`<path>/sets/<set>/labels/<item id>.json`, or the labels folder itself), or one JSON
    file holding a list of documents, each with an `id` (or `doc_id`) and its fields,
    bare or under `data`. A document whose `set` names another set is skipped.
    """
    found: list[tuple[str, dict]] = []
    if path.is_dir():
        folder = path / "sets" / set_id / "labels"
        folder = folder if folder.is_dir() else path
        for jf in sorted(folder.glob("*.json")):
            found.append((jf.stem, _body(json.loads(jf.read_text(encoding="utf-8")))))
    else:
        raw = json.loads(path.read_text(encoding="utf-8"))
        docs = raw.get("documents", []) if isinstance(raw, dict) else raw
        for d in docs:
            doc_id = d.get("id") or d.get("doc_id")
            if doc_id:
                found.append((str(doc_id).rsplit("/", 1)[-1], _body(d)))
    labels: dict[str, dict] = {}
    skipped, dupes = 0, []
    for doc_id, body in found:
        if body.get("set") and body["set"] != set_id:
            skipped += 1
            continue
        if doc_id in labels:
            dupes.append(doc_id)
        labels[doc_id] = body
    return labels, skipped, dupes


NOTE_FIELDS = [
    "repo",
    "file",
    "line",
    "rule_id",
    "sub",
    "verdict",
    "note",
    "same_line_as",
    "labelled_at",
]


def _note_key(row: dict) -> tuple:
    return (row["repo"], row["file"], str(row["line"]), row["rule_id"], row.get("sub", ""))


def import_labels(args: argparse.Namespace) -> int:
    """Copy the console's labels into the CSV. Rows without a label stay as they were."""
    labels, skipped, dupes = read_labels(args.labels, args.set)
    if dupes:
        print(f"ERROR: {len(dupes)} item id(s) appear twice in the export: {dupes[:5]}")
        return 1
    bad = [(k, v.get("verdict")) for k, v in labels.items() if v.get("verdict") not in (*VALID, "")]
    if bad:
        print(f"ERROR: {len(bad)} label(s) outside {{tp, fp, unclear}}: {bad[:5]}")
        return 1

    columns, rows = read_csv(args.csv)
    ids = {row_id(r): r for r in rows}
    # A verdict already in the CSV with no label in this export means the export is
    # partial (a database list is paged) or the CSV was labelled by hand: either way,
    # importing would leave that row unchecked against the console.
    kept = [
        r for rid, r in ids.items() if r.get("verdict") and not labels.get(rid, {}).get("verdict")
    ]
    if kept and not args.partial:
        print(
            f"ERROR: {len(kept)} row(s) have a verdict in the CSV but no label in this export. "
            "Export every label document (page through the list), or pass --partial to keep "
            "those rows as they are."
        )
        return 1
    stray = sorted(set(labels) - set(ids))
    filled = changed = 0
    notes: dict[tuple, dict] = {}
    notes_path = args.csv.with_name("review-notes.csv")
    if notes_path.is_file():
        _, old = read_csv(notes_path)
        notes = {_note_key(r): r for r in old}
    for rid, row in ids.items():
        lab = labels.get(rid)
        if not lab:
            continue
        verdict = (lab.get("verdict") or "").strip()
        note = " ".join(str(lab.get("note") or "").split())
        if verdict:
            if row.get("verdict") and row["verdict"] != verdict:
                changed += 1
            row["verdict"] = verdict
            filled += 1
        if verdict or note:
            notes[_note_key(row)] = {
                "repo": row["repo"],
                "file": row["file"],
                "line": row["line"],
                "rule_id": row["rule_id"],
                "sub": row.get("sub", ""),
                "verdict": verdict or row.get("verdict", ""),
                "note": note,
                "same_line_as": lab.get("bulk_from", ""),
                "labelled_at": lab.get("at", ""),
            }

    with args.csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=columns)
        w.writeheader()
        w.writerows(rows)
    order = {_note_key(r): i for i, r in enumerate(rows)}
    merged = sorted(notes.values(), key=lambda r: order.get(_note_key(r), len(order)))
    with notes_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=NOTE_FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(merged)

    blank = sum(1 for r in rows if not r.get("verdict"))
    print(
        f"{filled} verdicts -> {_show(args.csv)} "
        f"({changed} changed, {blank} of {len(rows)} rows still unlabelled)"
    )
    print(f"{len(merged)} rows -> {_show(notes_path)}")
    if skipped:
        print(f"note: {skipped} label(s) belong to another set and were skipped")
    if stray:
        print(f"WARNING: {len(stray)} label(s) match no CSV row; was the set rebuilt?")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    cmds = p.add_subparsers(dest="cmd", required=True)
    b = cmds.add_parser("build", help="write a review set and the manifest")
    b.add_argument("--set", required=True, help="set id, e.g. run3")
    b.add_argument("--csv", type=Path, required=True)
    b.add_argument("--results", type=Path, required=True)
    b.add_argument("--title", default="Run 3 findings")
    b.add_argument(
        "--about",
        default="The sampled findings of run 3: AUD-1101 to AUD-1108 on 33 repositories. "
        "Each label measures one rule's precision.",
    )
    i = cmds.add_parser("import", help="copy labels from the console into the CSV")
    i.add_argument("--set", required=True)
    i.add_argument("--csv", type=Path, required=True)
    i.add_argument(
        "--labels",
        type=Path,
        required=True,
        help="a directory of <item id>.json label documents, or one JSON list of them",
    )
    i.add_argument(
        "--partial",
        action="store_true",
        help="keep CSV verdicts that have no label in this export instead of refusing",
    )
    args = p.parse_args(argv)
    for name in ("csv", "results", "labels"):
        val = getattr(args, name, None)
        if val is not None:
            setattr(args, name, val.resolve())
    return build(args) if args.cmd == "build" else import_labels(args)


if __name__ == "__main__":
    sys.exit(main())
