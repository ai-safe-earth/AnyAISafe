"""src/aisafe/engagement/model.py
------------------------------
The files of an engagement directory and the checks on them. Nothing here decides an
outcome: the engagement says who audits whom, under which authorisations and within
which scope, and carries the answers a person gave; the assessment reads them.

    DIR/engagement.json         aisg/engagement/1
    DIR/investigations/         investigation records and skeptic passes
    DIR/evidence/               documents received from the auditee, hashed
    DIR/evidence-requests.json  aisg/evidence-requests/1
    DIR/responses/*.json        aisg/auditee-response/1
    DIR/qa.json                 aisg/qa-signoff/1 (optional second-auditor sign-off)
    DIR/assessment/             the assessment and its bundle manifest (aisg/bundle/1)

Every field a person answers starts empty: `init` never writes a statement, an answer or
a decision. A document is counted only while its bytes still match the sha256 recorded
when it was received.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Iterable, Sequence

from aisafe.evidence.model import MODES, now_iso
from aisafe.legal.profile import ANSWER_VALUES, DEFINITION_ANSWERS, LIST_ANSWERS

__all__ = [
    "ASSESSMENT_DIR",
    "BUNDLE_FILE",
    "BUNDLE_KIND",
    "BUNDLE_SCHEMA",
    "ENGAGEMENT_FILE",
    "ENGAGEMENT_KIND",
    "ENGAGEMENT_SCHEMA",
    "EVIDENCE_DIR",
    "INVESTIGATIONS_DIR",
    "QA_DECISIONS",
    "QA_FILE",
    "QA_KIND",
    "QA_SCHEMA",
    "REQUESTS_FILE",
    "REQUESTS_KIND",
    "REQUESTS_SCHEMA",
    "REQUEST_STATUSES",
    "RESPONSES_DIR",
    "RESPONSE_KIND",
    "RESPONSE_SCHEMA",
    "Engagement",
    "EngagementError",
    "add_response",
    "add_signoff",
    "check_engagement",
    "file_sha256",
    "inside",
    "known_codes",
    "qa_state",
    "authorisation_states",
    "load_engagement",
    "load_qa",
    "load_requests",
    "load_responses",
    "mark_insufficient",
    "merge_requests",
    "missing_fields",
    "receive",
    "request_states",
    "skeleton",
    "write_json",
]

ENGAGEMENT_SCHEMA = "aisg/engagement/1"
ENGAGEMENT_KIND = "engagement"
ENGAGEMENT_FILE = "engagement.json"
REQUESTS_SCHEMA = "aisg/evidence-requests/1"
REQUESTS_KIND = "evidence-requests"
REQUESTS_FILE = "evidence-requests.json"
RESPONSE_SCHEMA = "aisg/auditee-response/1"
RESPONSE_KIND = "auditee-response"
RESPONSES_DIR = "responses"
QA_SCHEMA = "aisg/qa-signoff/1"
QA_KIND = "qa-signoff"
QA_FILE = "qa.json"
BUNDLE_SCHEMA = "aisg/bundle/1"
BUNDLE_KIND = "bundle"
BUNDLE_FILE = "bundle.json"
EVIDENCE_DIR = "evidence"
INVESTIGATIONS_DIR = "investigations"
ASSESSMENT_DIR = "assessment"

REQUEST_STATUSES: tuple[str, ...] = ("requested", "received", "insufficient")
QA_DECISIONS: tuple[str, ...] = ("approved", "changes_requested")
_COMMIT = re.compile(r"^[0-9a-f]{7,40}$")
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


class EngagementError(ValueError):
    """The engagement directory cannot be used. One line; the CLI maps it to exit 2."""


def file_sha256(path: Path) -> str:
    """sha256 of the file's bytes as read (what `sha256sum` prints). Raises OSError."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inside(path: Path, tree: Path) -> bool:
    """True when `path` is `tree` or under it, after resolving both."""
    try:
        Path(path).resolve().relative_to(Path(tree).resolve())
    except ValueError:
        return False
    return True


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise EngagementError(f"{path.as_posix()}: {exc.strerror or exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EngagementError(f"{path.as_posix()}: not valid UTF-8 JSON ({exc})") from exc


def _today() -> str:
    return date.today().isoformat()


# ---------------------------------------------------------------------------
# engagement.json
# ---------------------------------------------------------------------------


def skeleton(
    *,
    target: str,
    mode: str,
    auditor: str | None,
    organisation: str | None,
    auditee: str | None,
    definitions: Iterable[str],
) -> dict[str, Any]:
    """A new engagement: the names given on the command line, every other answer empty."""
    return {
        "schema": ENGAGEMENT_SCHEMA,
        "kind": ENGAGEMENT_KIND,
        "created_at": now_iso(),
        "mode": mode,
        "auditor": {"name": auditor, "organisation": organisation},
        "auditee": {"name": auditee, "contact": None},
        "independence": {"statement": None, "by": None, "date": None},
        "scope": {
            "target": target,
            "commits": [],
            "deployment": None,
            "configuration": None,
            "environments": [],
            "exclusions": [],
        },
        "authorisations": [],
        "applicability": {
            "answered_by": None,
            "answered_on": None,
            "markets": [],
            "jurisdictions": [],
            "roles": [],
            "product_type": None,
            "minors": None,
            "age_assurance": None,
            "eu_placement": [],
            "definitions": {key: {"answer": None, "reason": None} for key in definitions},
        },
        "qa": {"required": False},
    }


def _text_or_none(value: Any) -> bool:
    return value is None or (isinstance(value, str) and bool(value.strip()))


def _date_or_none(value: Any) -> bool:
    if value is None:
        return True
    try:
        date.fromisoformat(str(value))
    except ValueError:
        return False
    return True


def known_codes() -> tuple[str, ...]:
    """The jurisdiction codes the shipped legal profiles use, in order."""
    from aisafe.legal.profile import load_profiles

    return tuple(sorted({p.jurisdiction for p in load_profiles()}))


def check_engagement(data: Any, *, codes: Sequence[str] | None = None) -> list[str]:
    """Every reason the file cannot be read as an engagement (wrong types, unknown
    values); empty when it can. An incomplete engagement is not malformed: see
    `missing_fields`. `codes` are the jurisdiction codes a market or a jurisdiction may
    name (default: the shipped profiles'); a market may also be `other`."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["engagement.json must hold a JSON object"]
    if data.get("schema") != ENGAGEMENT_SCHEMA or data.get("kind") != ENGAGEMENT_KIND:
        errors.append(f"`schema` must be {ENGAGEMENT_SCHEMA} and `kind` {ENGAGEMENT_KIND}")
    if data.get("mode") not in MODES:
        errors.append(f"`mode` must be one of {', '.join(MODES)}")
    for block, keys in (
        ("auditor", ("name", "organisation")),
        ("auditee", ("name", "contact")),
        ("independence", ("statement", "by")),
    ):
        value = data.get(block)
        if not isinstance(value, dict):
            errors.append(f"`{block}` must be an object")
            continue
        for key in keys:
            if not _text_or_none(value.get(key)):
                errors.append(f"`{block}.{key}` must be text or null")
    if isinstance(data.get("independence"), dict) and not _date_or_none(
        data["independence"].get("date")
    ):
        errors.append("`independence.date` must be a date or null")
    scope = data.get("scope")
    if not isinstance(scope, dict):
        errors.append("`scope` must be an object")
    else:
        if not isinstance(scope.get("target"), str) or not scope["target"]:
            errors.append("`scope.target` must name the audited tree")
        commits = scope.get("commits")
        if not isinstance(commits, list) or not all(
            isinstance(c, str) and _COMMIT.match(c) for c in commits
        ):
            errors.append("`scope.commits` must list commit hashes (7 to 40 hex digits)")
        for key in ("deployment", "configuration"):
            if not _text_or_none(scope.get(key)):
                errors.append(f"`scope.{key}` must be text or null")
        envs = scope.get("environments")
        if not isinstance(envs, list) or not all(
            isinstance(e, dict) and isinstance(e.get("name"), str) and e["name"] for e in envs
        ):
            errors.append("`scope.environments` must list objects with a `name`")
        if not isinstance(scope.get("exclusions"), list):
            errors.append("`scope.exclusions` must be a list")
    auths = data.get("authorisations")
    if not isinstance(auths, list):
        errors.append("`authorisations` must be a list")
    else:
        for index, auth in enumerate(auths):
            if not isinstance(auth, dict):
                errors.append(f"`authorisations[{index}]` must be an object")
                continue
            for key in ("what", "by"):
                if not isinstance(auth.get(key), str) or not auth[key].strip():
                    errors.append(f"`authorisations[{index}].{key}` must be text")
            if not _date_or_none(auth.get("date")) or auth.get("date") is None:
                errors.append(f"`authorisations[{index}].date` must be a date")
            doc = auth.get("document")
            if doc is not None and (
                not isinstance(doc, dict) or not doc.get("path") or not doc.get("sha256")
            ):
                errors.append(f"`authorisations[{index}].document` must hold path and sha256")
    answers = data.get("applicability")
    if not isinstance(answers, dict):
        errors.append("`applicability` must be an object")
    else:
        errors.extend(_check_answers(answers, known_codes() if codes is None else codes))
    qa = data.get("qa")
    if not isinstance(qa, dict) or not isinstance(qa.get("required"), bool):
        errors.append("`qa.required` must be true or false")
    return errors


def _check_answers(answers: dict[str, Any], codes: Sequence[str]) -> list[str]:
    errors = []
    for key in ("answered_by", "product_type"):
        if not _text_or_none(answers.get(key)):
            errors.append(f"`applicability.{key}` must be text or null")
    if not _date_or_none(answers.get("answered_on")):
        errors.append("`applicability.answered_on` must be a date or null")
    for key in ("markets", "jurisdictions", *sorted(LIST_ANSWERS - {"markets"})):
        value = answers.get(key)
        if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
            errors.append(f"`applicability.{key}` must be a list of values")
            continue
        allowed = ANSWER_VALUES.get(key)
        if key == "markets":
            # A code a profile does not know would read as a definite no: name the market
            # with a profile's code, or `other` for every market no profile covers.
            allowed = (*codes, "other")
        elif key == "jurisdictions":
            allowed = tuple(codes)
        if allowed is not None:
            for v in value:
                if v not in allowed:
                    errors.append(
                        f"`applicability.{key}`: {v!r} is not one of {', '.join(allowed)}"
                    )
    for key in ("minors", "age_assurance"):
        value = answers.get(key)
        allowed = ANSWER_VALUES[key] or ()
        if value is not None and value not in allowed:
            errors.append(f"`applicability.{key}` must be null or one of {', '.join(allowed)}")
    definitions = answers.get("definitions")
    if not isinstance(definitions, dict):
        errors.append("`applicability.definitions` must be an object")
    else:
        for key, value in definitions.items():
            if not isinstance(value, dict):
                errors.append(f"`applicability.definitions.{key}` must be {{answer, reason}}")
                continue
            if value.get("answer") is not None and value["answer"] not in DEFINITION_ANSWERS:
                errors.append(
                    f"`applicability.definitions.{key}.answer` must be null or one of "
                    + ", ".join(DEFINITION_ANSWERS)
                )
            if not _text_or_none(value.get("reason")):
                errors.append(f"`applicability.definitions.{key}.reason` must be text or null")
    return errors


def missing_fields(data: dict[str, Any], *, definitions: Iterable[str] = ()) -> list[str]:
    """What a person still has to fill in, one line each. In auditor mode the names, the
    independence statement, a commit and an authorisation are needed before an assessment;
    the applicability answers are needed before a legal result can be more than
    undetermined."""
    out: list[str] = []
    auditor = data.get("auditor") or {}
    auditee = data.get("auditee") or {}
    independence = data.get("independence") or {}
    scope = data.get("scope") or {}
    answers = data.get("applicability") or {}
    if not auditor.get("name"):
        out.append("auditor.name: who audits")
    if not auditor.get("organisation"):
        out.append("auditor.organisation: the auditor's organisation")
    if not auditee.get("name"):
        out.append("auditee.name: whose system is audited")
    if data.get("mode") == "auditor":
        if not independence.get("statement"):
            out.append("independence.statement: the auditor's own statement of independence")
        for key in ("by", "date"):
            if not independence.get(key):
                out.append(f"independence.{key}: who made the statement, and when")
        if not data.get("authorisations"):
            out.append("authorisations: the written authorisation to audit (and to test)")
    if not scope.get("commits"):
        out.append("scope.commits: the commits in scope")
    for key in ("deployment", "configuration"):
        if not scope.get(key):
            out.append(f"scope.{key}: what was assessed, in words (or 'not in scope')")
    if not answers.get("answered_by"):
        out.append("applicability.answered_by: who gave the applicability answers")
    for key in ("markets", "jurisdictions", "roles", "eu_placement"):
        if not answers.get(key):
            out.append(f"applicability.{key}")
    for key in ("minors", "age_assurance", "product_type"):
        if answers.get(key) in (None, ""):
            out.append(f"applicability.{key}")
    given = answers.get("definitions") or {}
    for key in definitions:
        entry = given.get(key) or {}
        if entry.get("answer") in (None, "unknown"):
            out.append(f"applicability.definitions.{key}")
        elif not entry.get("reason"):
            out.append(f"applicability.definitions.{key}.reason: an answer needs its reason")
    return out


@dataclass
class Engagement:
    dir: Path
    data: dict[str, Any]
    sha256: str

    @property
    def path(self) -> Path:
        return self.dir / ENGAGEMENT_FILE

    @property
    def mode(self) -> str:
        return str(self.data.get("mode"))

    @property
    def answers(self) -> dict[str, Any]:
        return dict(self.data.get("applicability") or {})

    @property
    def commits(self) -> list[str]:
        return list((self.data.get("scope") or {}).get("commits") or [])

    def summary(self) -> dict[str, Any]:
        """The engagement as the assessment carries it: who, scope, authorisations, the
        independence statement and the answers, with the file's hash."""
        data = self.data
        return {
            "path": self.path.as_posix(),
            "sha256": self.sha256,
            "mode": data.get("mode"),
            "auditor": dict(data.get("auditor") or {}),
            "auditee": dict(data.get("auditee") or {}),
            "independence": dict(data.get("independence") or {}),
            "scope": dict(data.get("scope") or {}),
            "authorisations": [dict(a) for a in data.get("authorisations") or []],
            "applicability": self.answers,
            "qa": dict(data.get("qa") or {}),
        }


def load_engagement(directory: Path) -> Engagement:
    """Read DIR/engagement.json. Raises EngagementError on a missing or malformed file."""
    directory = Path(directory)
    path = directory / ENGAGEMENT_FILE
    if not path.is_file():
        raise EngagementError(
            f"no {ENGAGEMENT_FILE} in {directory.as_posix()} (run `aisafe engagement init`)"
        )
    data = _read_json(path)
    errors = check_engagement(data)
    if errors:
        more = f" (and {len(errors) - 1} more)" if errors[1:] else ""
        raise EngagementError(f"{path.as_posix()}: {errors[0]}{more}")
    return Engagement(dir=directory, data=data, sha256=file_sha256(path))


# ---------------------------------------------------------------------------
# Evidence requests
# ---------------------------------------------------------------------------


def _empty_requests() -> dict[str, Any]:
    return {"schema": REQUESTS_SCHEMA, "kind": REQUESTS_KIND, "updated_at": None, "requests": []}


def load_requests(directory: Path) -> dict[str, Any]:
    """DIR/evidence-requests.json, or an empty set when there is none yet."""
    path = Path(directory) / REQUESTS_FILE
    if not path.is_file():
        return _empty_requests()
    data = _read_json(path)
    if (
        not isinstance(data, dict)
        or data.get("schema") != REQUESTS_SCHEMA
        or not isinstance(data.get("requests"), list)
    ):
        raise EngagementError(f"{path.as_posix()}: not an {REQUESTS_SCHEMA} document")
    for item in data["requests"]:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise EngagementError(f"{path.as_posix()}: a request without an id")
        if item.get("status") not in REQUEST_STATUSES:
            raise EngagementError(
                f"{path.as_posix()}: request {item['id']} has status {item.get('status')!r}"
            )
    return data


def merge_requests(
    doc: dict[str, Any], wanted: Sequence[dict[str, Any]], *, today: str | None = None
) -> dict[str, Any]:
    """The requests file with every request in `wanted` present: a new one `requested`, an
    existing one unchanged (status, documents, history kept), one no longer generated kept
    with `active: false`. `wanted` items are {id, source, what}."""
    today = today or _today()
    by_id = {item["id"]: item for item in doc.get("requests") or []}
    wanted_ids = []
    for want in wanted:
        wanted_ids.append(want["id"])
        item = by_id.get(want["id"])
        if item is None:
            by_id[want["id"]] = {
                "id": want["id"],
                "source": dict(want.get("source") or {}),
                "what": want["what"],
                "status": "requested",
                "active": True,
                "requested_on": today,
                "documents": [],
                "insufficient": None,
                "history": [{"status": "requested", "by": "aisafe assess", "date": today}],
            }
        else:
            item["active"] = True
            if item.get("what") != want["what"] and item.get("status") != "requested":
                # The documents answered another question: they are kept, and the request
                # is open again until a person looks at them against the new wording.
                item.setdefault("history", []).append(
                    {
                        "status": "requested",
                        "by": "aisafe assess",
                        "date": today,
                        "note": "the request's wording changed after it was "
                        + str(item.get("status")),
                    }
                )
                item["status"] = "requested"
            item["what"] = want["what"]
    for item_id, item in by_id.items():
        if item_id not in wanted_ids:
            item["active"] = False
    out = dict(doc)
    out["schema"] = REQUESTS_SCHEMA
    out["kind"] = REQUESTS_KIND
    out["updated_at"] = now_iso()
    out["requests"] = sorted(by_id.values(), key=lambda item: item["id"])
    return out


def request_states(directory: Path, doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Per request id: its status, and `counted` (received, active, every document present
    with the sha256 it was received with). A changed or missing document is never counted."""
    directory = Path(directory)
    out: dict[str, dict[str, Any]] = {}
    for item in doc.get("requests") or []:
        documents = []
        intact = True
        for document in item.get("documents") or []:
            path = directory / str(document.get("path"))
            try:
                now = file_sha256(path)
            except OSError:
                now = None
            ok = now is not None and now == document.get("sha256")
            intact = intact and ok
            documents.append(
                {
                    "path": document.get("path"),
                    "sha256": document.get("sha256"),
                    "state": "intact" if ok else ("missing" if now is None else "changed"),
                }
            )
        status = item.get("status")
        counted = bool(status == "received" and item.get("active", True) and documents and intact)
        if status == "received" and not documents:
            detail = "marked received with no document"
        elif status == "received" and not intact:
            detail = "a received document is missing or no longer matches its sha256"
        elif status == "insufficient":
            decided = item.get("insufficient") or {}
            detail = (
                f"insufficient, decided by {decided.get('by') or 'nobody named'} on "
                f"{decided.get('date') or '?'}: {decided.get('reason') or ''}"
            )
        elif status == "requested":
            detail = "requested on " + str(item.get("requested_on") or "?") + ", not received"
        else:
            detail = "received; every document matches its sha256"
        out[item["id"]] = {
            "id": item["id"],
            "status": status,
            "active": item.get("active", True),
            "counted": counted,
            "detail": detail,
            "documents": documents,
            "what": item.get("what"),
            "source": item.get("source"),
        }
    return out


def _find_request(doc: dict[str, Any], request_id: str) -> dict[str, Any]:
    for item in doc.get("requests") or []:
        if item.get("id") == request_id:
            return item
    raise EngagementError(
        f"no evidence request {request_id!r} (run `aisafe assess --engagement` to list them)"
    )


def receive(
    directory: Path,
    request_id: str,
    files: Sequence[Path],
    *,
    by: str,
    note: str | None = None,
    today: str | None = None,
) -> dict[str, Any]:
    """Copy each file into DIR/evidence/<request>/, record its sha256 and mark the request
    received. Returns the updated requests document (already written)."""
    directory = Path(directory)
    today = today or _today()
    doc = load_requests(directory)
    item = _find_request(doc, request_id)
    if not by.strip():
        raise EngagementError("--by must name the person who received the documents")
    folder = directory / EVIDENCE_DIR / _SAFE.sub("_", request_id.replace("/", "__"))
    if item.get("status") == "insufficient":
        judged = {d.get("sha256") for d in item.get("documents") or []}
        fresh = [Path(f) for f in files if Path(f).is_file() and file_sha256(Path(f)) not in judged]
        if not fresh:
            decided = item.get("insufficient") or {}
            raise EngagementError(
                f"{request_id} was judged insufficient by {decided.get('by')} on "
                f"{decided.get('date')}, with these documents; receive a new document, or "
                "the decision stands"
            )
    for source in files:
        source = Path(source)
        if not source.is_file():
            raise EngagementError(f"no such file: {source.as_posix()}")
        if inside(source, directory / EVIDENCE_DIR):
            target = source.resolve()
        else:
            folder.mkdir(parents=True, exist_ok=True)
            target = folder / source.name
            if target.exists() and file_sha256(target) != file_sha256(source):
                raise EngagementError(
                    f"{target.as_posix()} already holds another document; rename the file"
                )
            shutil.copyfile(source, target)
        rel = target.resolve().relative_to(directory.resolve()).as_posix()
        item["documents"] = [d for d in item.get("documents") or [] if d.get("path") != rel]
        item["documents"].append(
            {
                "path": rel,
                "sha256": file_sha256(target),
                "received_on": today,
                "received_by": by,
                "note": note,
            }
        )
    item["status"] = "received"
    item["insufficient"] = None
    item.setdefault("history", []).append(
        {"status": "received", "by": by, "date": today, "note": note}
    )
    doc["updated_at"] = now_iso()
    write_json(directory / REQUESTS_FILE, doc)
    return doc


def mark_insufficient(
    directory: Path, request_id: str, *, by: str, reason: str, today: str | None = None
) -> dict[str, Any]:
    """Mark a request insufficient with the auditor's reason. The documents stay listed."""
    directory = Path(directory)
    today = today or _today()
    if not by.strip() or not reason.strip():
        raise EngagementError("--by and --reason are both needed")
    doc = load_requests(directory)
    item = _find_request(doc, request_id)
    item["status"] = "insufficient"
    item["insufficient"] = {"by": by, "date": today, "reason": reason}
    item.setdefault("history", []).append(
        {"status": "insufficient", "by": by, "date": today, "note": reason}
    )
    doc["updated_at"] = now_iso()
    write_json(directory / REQUESTS_FILE, doc)
    return doc


# ---------------------------------------------------------------------------
# Auditee responses
# ---------------------------------------------------------------------------


def load_responses(directory: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Every response in DIR/responses/, and the files that are not one."""
    folder = Path(directory) / RESPONSES_DIR
    responses: list[dict[str, Any]] = []
    problems: list[str] = []
    for path in sorted(folder.glob("*.json")) if folder.is_dir() else []:
        try:
            data = _read_json(path)
        except EngagementError as exc:
            problems.append(str(exc))
            continue
        if (
            not isinstance(data, dict)
            or data.get("schema") != RESPONSE_SCHEMA
            or not all(isinstance(data.get(k), str) and data[k] for k in ("to", "by", "text"))
        ):
            problems.append(f"{path.as_posix()}: not an {RESPONSE_SCHEMA} response")
            continue
        data = dict(data)
        data["file"] = path.relative_to(Path(directory)).as_posix()
        data["sha256"] = file_sha256(path)
        responses.append(data)
    return responses, problems


def add_response(
    directory: Path,
    *,
    to: str,
    by: str,
    text: str,
    evidence: Sequence[str] = (),
    today: str | None = None,
) -> Path:
    """Write one auditee response. `to` names what it answers: a mechanism (M5), a record
    id, a finding fingerprint or a provision (profile/provision)."""
    directory = Path(directory)
    if not to.strip() or not by.strip() or not text.strip():
        raise EngagementError("--to, --by and --text are all needed")
    folder = directory / RESPONSES_DIR
    folder.mkdir(parents=True, exist_ok=True)
    index = 1 + len(list(folder.glob("*.json")))
    path = folder / f"response-{index:03d}.json"
    while path.exists():
        index += 1
        path = folder / f"response-{index:03d}.json"
    write_json(
        path,
        {
            "schema": RESPONSE_SCHEMA,
            "kind": RESPONSE_KIND,
            "id": path.stem,
            "to": to,
            "by": by,
            "date": today or _today(),
            "text": text,
            "evidence": list(evidence),
        },
    )
    return path


# ---------------------------------------------------------------------------
# QA sign-off
# ---------------------------------------------------------------------------


def load_qa(directory: Path) -> dict[str, Any]:
    path = Path(directory) / QA_FILE
    if not path.is_file():
        return {"schema": QA_SCHEMA, "kind": QA_KIND, "signoffs": []}
    data = _read_json(path)
    if (
        not isinstance(data, dict)
        or data.get("schema") != QA_SCHEMA
        or not isinstance(data.get("signoffs"), list)
    ):
        raise EngagementError(f"{path.as_posix()}: not an {QA_SCHEMA} document")
    for index, row in enumerate(data["signoffs"]):
        # A sign-off that names nobody, or no assessment, is no sign-off: refused, not skipped.
        if (
            not isinstance(row, dict)
            or not str(row.get("by") or "").strip()
            or row.get("decision") not in QA_DECISIONS
            or not isinstance(row.get("assessment"), dict)
            or not (row.get("assessment") or {}).get("sha256")
        ):
            raise EngagementError(
                f"{path.as_posix()}: sign-off {index + 1} must name the second auditor, a "
                f"decision ({', '.join(QA_DECISIONS)}) and the assessment's sha256"
            )
    return data


def add_signoff(
    directory: Path,
    *,
    by: str,
    decision: str,
    assessment: Path,
    notes: str | None = None,
    today: str | None = None,
    auditor: str | None = None,
) -> dict[str, Any]:
    """Append a second auditor's sign-off, bound to the assessment file's sha256. `auditor`
    is the engagement's auditor, who cannot sign it."""
    directory = Path(directory)
    if decision not in QA_DECISIONS:
        raise EngagementError(f"--decision must be one of {', '.join(QA_DECISIONS)}")
    if not by.strip():
        raise EngagementError("--by must name the second auditor")
    if auditor and by.strip().casefold() == str(auditor).strip().casefold():
        raise EngagementError("the QA sign-off is a second auditor's: --by names the auditor")
    if not Path(assessment).is_file():
        raise EngagementError(f"no assessment at {Path(assessment).as_posix()}")
    data = load_qa(directory)
    data["signoffs"].append(
        {
            "by": by,
            "date": today or _today(),
            "decision": decision,
            "notes": notes,
            "assessment": {
                "path": Path(assessment).as_posix(),
                "sha256": file_sha256(Path(assessment)),
            },
        }
    )
    write_json(directory / QA_FILE, data)
    return data


def qa_state(qa: dict[str, Any], current: str | None) -> dict[str, Any]:
    """The sign-offs, each marked `current` when bound to the assessment of sha256
    `current`, and the decision that stands for it: `approved` only when every second
    auditor's latest sign-off of the current assessment approves it; `changes_requested`
    when any of them asks for changes; None when nobody signed it. qa.json is append-only,
    so the order of the rows, not their dates, says which is latest."""
    rows = [
        {
            **row,
            "current": bool(current) and (row.get("assessment") or {}).get("sha256") == current,
        }
        for row in qa.get("signoffs") or []
    ]
    latest: dict[str, str] = {}
    for row in rows:
        if row["current"]:
            latest[str(row["by"]).strip().casefold()] = str(row["decision"])
    if not latest:
        standing = None
    elif all(decision == "approved" for decision in latest.values()):
        standing = "approved"
    else:
        standing = "changes_requested"
    return {"signoffs": rows, "standing": standing}


def authorisation_states(directory: Path, data: dict[str, Any]) -> list[dict[str, Any]]:
    """Each written authorisation, and whether its document (when it names one) still
    matches the sha256 recorded for it."""
    out = []
    for auth in data.get("authorisations") or []:
        document = auth.get("document")
        state = None
        if isinstance(document, dict) and document.get("path"):
            try:
                now: str | None = file_sha256(Path(directory) / str(document["path"]))
            except OSError:
                now = None
            state = (
                "missing"
                if now is None
                else ("intact" if now == document.get("sha256") else "changed")
            )
        out.append(
            {
                "what": auth.get("what"),
                "by": auth.get("by"),
                "date": auth.get("date"),
                "document": document,
                "state": state,
            }
        )
    return out
