"""src/aisafe/investigation/signoff.py
-----------------------------------
The sign-off (`aisg/signoff/1`): a decision the machine cannot make, recorded by a person,
by name, with a reason, bound to exactly what that person looked at. One JSON file in the
records directory; `aisafe investigate signoff` writes it and `aisafe assess` reads it.

Two gaps have no other way to clear. A record the machine sent to a person, a closing by a
control outside Python for one, keeps its mechanism inconclusive (`record_at_review`). A
file nobody read keeps every mechanism inconclusive (`files_not_read`). A sign-off clears
those two and nothing else. It lowers no violation and clears no skeptic refutation, no
missing skeptic pass, no runtime-only link, no rejected record and no scan finding.

A sign-off counts only while it is bound, and `refusals` is the one test, run by the command
before it writes and again by the assessment on whatever the file says now: the file is
data, and the command's checks mean nothing to a file written by hand. Same commit, on a tree
that is that commit; same policy version; same mode; each record's digest equal to the
record as it is now; each file on the list of unread files and equal to the file at the
commit; no record or file listed twice; a person's name and a reason that pronounces no
verdict, in a file whose own name does not either (`bind_signoffs` reads the name). In
auditor mode the name is the engagement's auditor, and the file sits outside the audited
tree. A sign-off that fails any of this counts for nothing, whole, and the assessment lists
it with why. Outside git
there is no commit to bind to, so every sign-off is refused there.

A record it names must also be one a person can close (`why_not_signable`): at review, with
a closing proposed, its evidence supported, a bound skeptic pass upheld, no runtime-only
link, and nothing it says itself is still open (open questions, missing evidence, another
reading found supported). Evidence the machine could not read stays unknown, whoever signs.

The limit: nothing here is signed. In self-assessment anyone with write access can write a
sign-off file in any name, an AI agent included, so reports label it self-assessed. The tool
states who decided, as the file says; it never says the system is safe.
"""

from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Collection, Mapping, Sequence

from aisafe.discovery.walk import run_git
from aisafe.evidence.model import MODES, Decision, EvidenceStatus, redact
from aisafe.investigation.records import (
    ID_RE,
    SIGNOFF_KIND,
    SIGNOFF_SCHEMA,
    RecordError,
    fold_text,
    load_json,
    verdict_words_in,
)
from aisafe.review.records import check_text, parse_date, tool_name_problem

if TYPE_CHECKING:
    from aisafe.engagement.model import Engagement
    from aisafe.investigation.scan import MachineScan
    from aisafe.investigation.validate import RecordResult

__all__ = [
    "Scene",
    "SignoffSet",
    "apply_signoffs",
    "bind_signoffs",
    "build_signoff",
    "file_sha_at",
    "person_problems",
    "refusals",
    "scene_of",
    "tree_problems",
    "why_not_signable",
    "write_signoff",
]

_CLOSE = Decision.NO_VIOLATION.value
_SUPPORTED = EvidenceStatus.SUPPORTED_MECHANISM.value
# A date is written in UTC here and may be written in a later zone by hand.
_FUTURE_TOLERANCE = timedelta(days=1)
_SHOWN = 120
_NOT_SHOWN = "(not shown)"


@dataclass(frozen=True)
class Scene:
    """What a sign-off is read against. `records`: the accepted records by id. `unread`: the
    files on the list a file sign-off may name. `auditor`, `auditee`: the engagement's names."""

    root: Path
    commit: str | None
    is_git: bool
    clean: bool
    policy_version: str
    mode: str
    today: date
    unread: frozenset[str] = frozenset()
    records: Mapping[str, RecordResult] = field(default_factory=dict)
    auditor: str | None = None
    auditee: str | None = None


@dataclass
class SignoffSet:
    """The sign-offs one assessment read. `accepted` rows carry what counted; `refused` rows
    carry why, and only fields that passed their checks."""

    accepted: list[dict[str, Any]] = field(default_factory=list)
    refused: list[dict[str, Any]] = field(default_factory=list)
    # Where each row's file sits, in the order of `accepted` then `refused`: the row's
    # `file` hides a part of the path that `_shown` would not show, and the assessment
    # still hashes the file. Not part of `to_dict`.
    sources: list[Path] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": [dict(row) for row in self.accepted],
            "refused": [dict(row) for row in self.refused],
            "note": (
                "A sign-off is a person's decision, bound to one commit, one policy version and "
                "the exact records and files named. It clears a record at review and a file "
                "nobody read, and no other gap; it never lowers a violation. It carries no "
                "signature: a self-assessed one can be written by anyone with write access."
            ),
        }


def scene_of(
    scan: MachineScan,
    unread: Collection[str],
    *,
    today: date,
    results: Sequence[RecordResult] = (),
    engagement: Engagement | None = None,
) -> Scene:
    data = engagement.data if engagement is not None else {}
    return Scene(
        root=scan.root,
        commit=scan.state.commit,
        is_git=scan.state.is_git,
        clean=scan.state.clean,
        policy_version=scan.policy.version,
        mode=scan.mode,
        today=today,
        unread=frozenset(unread),
        records={r.id: r for r in results if r.accepted and r.id},
        auditor=str((data.get("auditor") or {}).get("name") or "").strip() or None,
        auditee=str((data.get("auditee") or {}).get("name") or "").strip() or None,
    )


def _shown(value: Any) -> str:
    """A value from a file that may have been written by hand, safe on one line of a report:
    what `check_text` or the verdict words refuse is not shown at all, since a refusal is not
    a way to get those words into a report."""
    text = value if isinstance(value, str) else str(value)
    if check_text("the value", text) is not None or verdict_words_in(text):
        return _NOT_SHOWN
    return ascii(redact(value) if isinstance(value, str) else value)[:_SHOWN]


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _inside(path: Path, tree: Path) -> bool:
    try:
        path.resolve().relative_to(tree.resolve())
    except ValueError:
        return False
    return True


def _name_key(name: str) -> str:
    """A name as two spellings of it compare: spacing, case and accents do not make a
    second person."""
    return " ".join(fold_text(name).split()).casefold()


def person_problems(by: Any, reason: Any) -> list[str]:
    """Why the name or the reason cannot stand: the review record's checks, and the verdict
    words of an investigation record's free text on top of them."""
    problems = []
    name = check_text("the name (by)", by)
    if name is None and tool_name_problem(by):
        name = (
            "the name (by) is no person's name (a tool or an agent, no letter before any "
            "<role>, or a verdict): a sign-off is a person's decision"
        )
    if name is not None:
        problems.append(name)
    why = check_text("the reason", reason)
    # The words are not repeated: a refusal is not a way to get them into a report.
    if why is None and verdict_words_in(reason if isinstance(reason, str) else ""):
        why = "the reason pronounces a verdict: it says what the person read and decided"
    if why is not None:
        problems.append(why)
    return problems


def tree_problems(scene: Scene) -> list[str]:
    """Why no sign-off can bind on this tree."""
    if not scene.is_git or scene.commit is None:
        return ["the tree is not a git checkout, so there is no commit to bind to: commit first"]
    if not scene.clean:
        return [f"the tree differs from commit {scene.commit}: commit first, then sign"]
    return []


def why_not_signable(record: RecordResult) -> str | None:
    """Why a person's sign-off cannot close this record; None when it can. A record that
    lists open questions or missing evidence, or weighed another reading and found it
    supported, says itself that it is not done: a person answers that in a new record, which
    the skeptic reads, and a sign-off does not answer it."""
    proposed = record.proposed.get("decision")
    status = record.effective.get("evidence_status")
    if record.claim != "review":
        return f"its claim is {record.claim}, and a sign-off acts only on a record at review"
    if proposed != _CLOSE:
        return f"it proposes {proposed}, and a sign-off can only close what proposes a closing"
    if status != _SUPPORTED:
        return f"its evidence is {status}: what could not be read stays unknown"
    skeptic = record.skeptic or {}
    if not skeptic.get("bound") or skeptic.get("result") != "upheld":
        return "no bound skeptic pass upheld it"
    if record.runtime or any(
        link.get("established_by") == "runtime-only" for link in record.links or []
    ):
        return "it rests on a runtime-only link"
    raw = record.raw if isinstance(record.raw, dict) else {}
    for key, what in (
        ("open_questions", "open questions"),
        ("missing_evidence", "missing evidence"),
    ):
        if isinstance(raw.get(key), list) and raw[key]:
            return f"it lists {what}: answer them in a new record, not in a sign-off"
    counter = raw.get("counterevidence")
    if isinstance(counter, list) and any(
        isinstance(item, dict) and item.get("result") == "supported" for item in counter
    ):
        return "it found another reading supported: weigh it in a new record, not in a sign-off"
    return None


def file_sha_at(root: Path, commit: str, relpath: str) -> str | None:
    """`content_sha256` of the file as the commit holds it; None when git cannot show it. The
    path has to be on the list of unread files before it gets here: it reaches git. The `--`
    keeps git from also trying the whole argument as a file name, which fails outright on a
    long Windows path."""
    data = run_git(("show", f"{commit}:./{relpath}", "--"), root, timeout=60)
    if data is None:
        return None
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def _record_refusals(items: Any, scene: Scene) -> list[str]:
    why = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            why.append("a row of `records` is not {id, record_sha256}")
            continue
        record_id = item.get("id")
        record = scene.records.get(record_id) if isinstance(record_id, str) else None
        if record is None:
            why.append(f"record {_shown(record_id)} is no accepted record at this commit")
            continue
        if record_id in seen:
            why.append(f"record {record_id} is listed twice")
            continue
        seen.add(record_id)
        if item.get("record_sha256") != record.digest:
            why.append(f"record {record_id} changed after the sign-off")
        problem = why_not_signable(record)
        if problem is not None:
            why.append(f"record {record_id}: {problem}")
    return why


def _file_refusals(items: Any, scene: Scene) -> list[str]:
    why = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            why.append("a row of `files` is not {path, sha256}")
            continue
        path = item.get("path")
        if not isinstance(path, str) or path not in scene.unread:
            why.append(f"file {_shown(path)} is not on the list of unread files")
        elif path in seen:
            why.append(f"file {_shown(path)} is listed twice")
        elif scene.commit is None:
            continue  # `tree_problems` says why: outside git no file can be compared
        else:
            seen.add(path)
            now = file_sha_at(scene.root, scene.commit, path)
            if now is None:
                why.append(f"file {_shown(path)}: git cannot show it at this commit")
            elif item.get("sha256") != now:
                why.append(f"file {_shown(path)} is not the file the sign-off looked at")
    return why


def refusals(doc: Any, scene: Scene, path: Path | None = None) -> list[str]:
    """Why this sign-off does not count here; [] when it does. See the module docstring.
    `path` is where the file sits, or will sit."""
    if not isinstance(doc, dict):
        return ["the file is not a JSON object"]
    why = person_problems(doc.get("by"), doc.get("reason"))
    if doc.get("schema") != SIGNOFF_SCHEMA or doc.get("kind") != SIGNOFF_KIND:
        why.append(f"it is not a {SIGNOFF_SCHEMA} document")
    if not isinstance(doc.get("id"), str) or not ID_RE.fullmatch(doc["id"]):
        why.append("`id` must be 1 to 64 letters, digits, dots, dashes or underscores")
    elif _shown(doc["id"]) == _NOT_SHOWN:
        why.append("`id` reads as a verdict")
    at = parse_date(doc.get("at"))
    if at is None:
        why.append("`at` is not an ISO date")
    elif at > scene.today + _FUTURE_TOLERANCE:
        why.append("`at` is in the future")
    why += tree_problems(scene)
    target = doc.get("target") if isinstance(doc.get("target"), dict) else {}
    commit = target.get("commit")
    if scene.commit is not None and commit != scene.commit:
        why.append(f"it was made at commit {_shown(commit)}; the tree is at {scene.commit}")
    if doc.get("policy_version") != scene.policy_version:
        why.append(
            f"it was made under policy {_shown(doc.get('policy_version'))}; this is policy "
            f"{scene.policy_version}"
        )
    mode = doc.get("mode")
    if mode not in MODES:
        why.append(f"`mode` must be one of {', '.join(MODES)}")
    elif mode != scene.mode:
        why.append(f"it was made in {mode} mode; this run is in {scene.mode} mode")
    if scene.mode == "auditor":
        why += _auditor_refusals(doc, scene, path)
    records, files = doc.get("records"), doc.get("files")
    if not isinstance(records, list) or not isinstance(files, list):
        return [*why, "`records` and `files` must be lists"]
    if not records and not files:
        why.append("it names no record and no file")
    return [*why, *_record_refusals(records, scene), *_file_refusals(files, scene)]


def _auditor_refusals(doc: dict[str, Any], scene: Scene, path: Path | None) -> list[str]:
    why = []
    by = _text(doc.get("by"))
    if scene.auditor is None or by != scene.auditor:
        why.append(f"in auditor mode only the engagement's auditor signs, not {_shown(by)}")
    elif scene.auditee is not None and _name_key(by) == _name_key(scene.auditee):
        why.append("the engagement names this person as the audited team as well")
    if path is not None and _inside(path, scene.root):
        why.append("in auditor mode a sign-off sits outside the audited tree")
    return why


def build_signoff(
    *,
    by: str,
    reason: str,
    record_ids: Sequence[str],
    file_paths: Sequence[str],
    scene: Scene,
) -> dict[str, Any]:
    """The document, with every digest and hash computed from the records and the tree, so a
    person types neither. A name it cannot resolve gets no hash, and `refusals` says so."""
    records = []
    for record_id in record_ids:
        record = scene.records.get(record_id)
        records.append(
            {"id": record_id, "record_sha256": None if record is None else record.digest}
        )
    files = []
    for path in file_paths:
        known = scene.commit is not None and path in scene.unread
        sha = file_sha_at(scene.root, str(scene.commit), path) if known else None
        files.append({"path": path, "sha256": sha})
    body = {
        "by": by.strip(),
        "at": scene.today.isoformat(),
        "mode": scene.mode,
        "target": {"commit": scene.commit},
        "policy_version": scene.policy_version,
        "reason": reason.strip(),
        "records": records,
        "files": files,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()
    return {
        "schema": SIGNOFF_SCHEMA,
        "kind": SIGNOFF_KIND,
        "id": f"signoff-{digest[:12]}",
        **body,
    }


def write_signoff(directory: Path, doc: dict[str, Any]) -> Path:
    """Write `<id>.json`. Raises FileExistsError rather than write over a sign-off."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{doc['id']}.json"
    with open(path, "x", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    return path


def _read(path: Path) -> tuple[Any, str | None]:
    """The file's document, or why it cannot be read. A link is not followed: the skeptic
    file's rule."""
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            return None, "it is not a regular file"
        return load_json(path), None
    except OSError as exc:
        return None, f"it cannot be read ({exc.strerror or exc})"
    except RecordError as exc:
        return None, f"it cannot be read ({exc})"


def _file_shown(path: Path) -> str:
    """The sign-off's path as a report shows it: each part of it that `_shown` would not
    show (a verdict, a secret-shaped token, a hidden character) is `(not shown)`."""
    parts = path.as_posix().split("/")
    return "/".join(
        part if not part or _shown(part) != _NOT_SHOWN else _NOT_SHOWN for part in parts
    )


def _name_refusal(path: Path) -> str | None:
    """Why the file's own name cannot stand in a report; None when it can. The name is
    chosen by whoever wrote the file, as its words are."""
    if _shown(path.name) == _NOT_SHOWN:
        return (
            "its file name reads as a verdict, holds a secret-shaped token or a hidden "
            "character: rename it to the id it carries"
        )
    return None


def _refused_row(path: Path, doc: Any, why: list[str]) -> dict[str, Any]:
    """Shows only what passed its check: a file refused for its words is not a way to get
    those words into a report."""
    doc = doc if isinstance(doc, dict) else {}
    named = doc.get("id")
    fit = isinstance(named, str) and ID_RE.fullmatch(named) and _shown(named) != _NOT_SHOWN
    clear = not person_problems(doc.get("by"), doc.get("reason"))
    return {
        "file": _file_shown(path),
        "id": named if fit else None,
        "by": _text(doc.get("by")) if clear else None,
        "reason": _text(doc.get("reason")) if clear else None,
        "why": why,
    }


def _accepted_row(path: Path, doc: dict[str, Any]) -> dict[str, Any]:
    """Rebuilt from the keys that were checked: what else a row holds was read by nobody."""
    return {
        "file": _file_shown(path),
        "id": doc["id"],
        "by": _text(doc["by"]),
        "at": str(doc["at"]),
        "mode": doc["mode"],
        "self_assessed": doc["mode"] != "auditor",
        "commit": doc["target"]["commit"],
        "policy_version": doc["policy_version"],
        "reason": _text(doc["reason"]),
        "records": [
            {"id": item["id"], "record_sha256": item["record_sha256"]} for item in doc["records"]
        ],
        "files": [{"path": item["path"], "sha256": item["sha256"]} for item in doc["files"]],
    }


def bind_signoffs(paths: Sequence[Path], scene: Scene) -> SignoffSet:
    """Read every sign-off file. An id two files claim is neither's."""
    read = []
    # One file reached by two spellings is one file, never two claims on its id.
    for path in sorted({Path(p).resolve(): Path(p) for p in paths}.values(), key=Path.as_posix):
        doc, problem = _read(path)
        why = [problem] if problem else refusals(doc, scene, path)
        named_badly = _name_refusal(path)
        read.append((path, doc, [*why, named_badly] if named_badly else why))
    named = [doc.get("id") for _, doc, _ in read if isinstance(doc, dict)]
    out = SignoffSet()
    accepted_paths: list[Path] = []
    refused_paths: list[Path] = []
    for path, doc, why in read:
        if isinstance(doc, dict) and named.count(doc.get("id")) > 1:
            why = [*why, "another sign-off file uses the same id"]
        if why:
            out.refused.append(_refused_row(path, doc, why))
            refused_paths.append(path)
        else:
            out.accepted.append(_accepted_row(path, doc))
            accepted_paths.append(path)
    out.sources = [*accepted_paths, *refused_paths]
    return out


def apply_signoffs(records: Sequence[RecordResult], accepted: Sequence[dict[str, Any]]) -> None:
    """Turn each record a bound sign-off names into a closing that carries the sign-off.
    `bind_signoffs` has checked each one, on the record as validated, so this runs after it,
    before the outcome and the retest read the records."""
    by_id = {record.id: record for record in records}
    for row in accepted:
        stamp = {key: row[key] for key in ("id", "by", "at", "mode", "self_assessed", "reason")}
        for item in row["records"]:
            record = by_id[item["id"]]
            if not record.signoffs:
                record.machine_effective = dict(record.effective)
            record.claim = "closes"
            record.effective = {**record.effective, "decision": _CLOSE}
            record.signoffs.append(stamp)
            label = "self-assessed" if row["self_assessed"] else "auditor"
            record.notes.append(
                f"closed by a person's decision: {row['by']} ({label}, sign-off {row['id']}); "
                f"the machine's reading was {record.machine_effective.get('decision')}"
            )
