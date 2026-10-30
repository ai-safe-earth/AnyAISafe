"""tests/unit/investigation_helpers.py
-----------------------------------
Builders for investigation records in tests: copy a fixture tree out of git (so its commit
is `None`), cite a line the way `aisafe investigate cite` does, assemble a record with
the defaults a deciding record needs, and write a skeptic pass bound to it. Not a test
module; the tests import it by name.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from aisafe.investigation.records import record_digest
from aisafe.investigation.text import content_sha256, file_lines, normalise

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "investigate"
OPERATOR = {"name": "T. Tester", "role": "test operator"}
INVESTIGATOR = {
    "agent": "test agent",
    "model": "test-model-1",
    "version": "0.0.1",
    "session": "investigator-session",
}
SKEPTIC = {
    "agent": "test agent",
    "model": "test-model-1",
    "version": "0.0.1",
    "session": "skeptic-session",
}


def copy_tree(name: str, tmp_path: Path) -> Path:
    """The fixture `name` copied under `tmp_path` (outside git)."""
    dest = tmp_path / name
    shutil.copytree(FIXTURES / name, dest)
    return dest


def cite(
    root: Path, file: str, line: int, quote: str | None = None, end_line: int | None = None
) -> dict[str, Any]:
    """`{file, line, quote, sha256}` for `file:line`; the quote defaults to the whole line."""
    path = root / file
    lines = file_lines(path)
    if quote is None:
        last = end_line or line
        quote = "\n".join(normalise(text) for text in lines[line - 1 : last])
    out: dict[str, Any] = {
        "file": file,
        "line": line,
        "quote": quote,
        "sha256": content_sha256(path),
    }
    if end_line is not None:
        out["end_line"] = end_line
    return out


def link(
    root: Path,
    kind: str,
    file: str,
    line: int,
    *,
    id: str,
    how: str = "read",
    quote: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    return {"id": id, "kind": kind, "how": how, **cite(root, file, line, quote), **extra}


def make_record(
    *,
    id: str,
    mechanism: str,
    pattern: str,
    view: str = "influence",
    surface: dict[str, Any],
    links: list[dict[str, Any]],
    decision: str,
    evidence_status: str = "supported_mechanism",
    counterevidence: list[dict[str, Any]] | None = None,
    controls: list[dict[str, Any]] | None = None,
    absent_links: list[dict[str, Any]] | None = None,
    steps: list[dict[str, Any]] | None = None,
    commit: str | None = None,
    mode: str = "self-assessment",
    **extra: Any,
) -> dict[str, Any]:
    deciding = decision in ("violates_policy", "no_violation_identified_in_scope")
    record: dict[str, Any] = {
        "schema": "aisg/investigation/1",
        "kind": "investigation",
        "id": id,
        "created_at": "2026-10-30T12:00:00Z",
        "target": {"path": ".", "commit": commit},
        "mode": mode,
        "engagement": None,
        "operator": dict(OPERATOR),
        "mechanism": mechanism,
        "pattern": pattern,
        "view": view,
        "surface": surface,
        "hypothesis": f"{mechanism}/{pattern} on {surface.get('type')} {surface.get('file')}",
        "links": links,
        "counterevidence": counterevidence
        if counterevidence is not None
        else (
            [
                {
                    "reading": "the benign reading the mechanism's distinct_from text names",
                    "result": "refuted",
                    "reason": "the cited lines show otherwise",
                    "citations": [],
                }
            ]
            if deciding
            else []
        ),
        "controls": controls or [],
        "absent_links": absent_links or [],
        "open_questions": [],
        "missing_evidence": [],
        "proposed": {"evidence_status": evidence_status, "decision": decision},
        "verification_steps": steps
        if steps is not None
        else (
            [
                {
                    "id": "v1",
                    "purpose": "remediation",
                    "kind": "reinvestigate",
                    "note": "read the path again",
                }
            ]
            if deciding
            else []
        ),
        "investigator": dict(INVESTIGATOR),
        "skeptic": {"result": "not_run", "reason": "not yet run"},
    }
    record.update(extra)
    return record


def write_record(
    directory: Path,
    record: dict[str, Any],
    *,
    skeptic: str | None = None,
    session: str | None = None,
) -> Path:
    """Write `record` as `<id>.json`; with `skeptic` (`upheld`/`refuted`) also write a bound
    skeptic pass and fill the record's `skeptic` block."""
    directory.mkdir(parents=True, exist_ok=True)
    if skeptic is not None:
        name = f"{record['id']}.skeptic.json"
        doc = {
            "schema": "aisg/skeptic/1",
            "kind": "skeptic",
            "record_id": record["id"],
            "record_sha256": record_digest(record),
            "created_at": "2026-10-30T12:30:00Z",
            "skeptic": dict(SKEPTIC, session=session or SKEPTIC["session"]),
            "result": skeptic,
            "claims": [
                {
                    "claim": "the record's reading",
                    "result": skeptic,
                    "reason": "read the cited lines",
                }
            ],
        }
        (directory / name).write_text(json.dumps(doc, indent=2), encoding="utf-8")
        record["skeptic"] = {"result": skeptic, "reason": "the skeptic pass", "file": name}
    path = directory / f"{record['id']}.json"
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return path


def surface_of(
    plan: dict[str, Any], kind: str, file: str, line: int | None = None
) -> dict[str, Any]:
    """The plan's surface of `kind` at `file` (and `line`), as a record's `surface` block."""
    for surface in plan["surfaces"]:
        if (
            surface["type"] == kind
            and surface["file"] == file
            and (line is None or surface["line"] == line)
        ):
            return {"id": surface["id"], "type": kind, "file": file, "line": surface["line"]}
    raise AssertionError(f"no {kind} surface at {file}:{line} in the plan")
