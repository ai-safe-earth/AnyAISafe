"""tests/unit/test_fixes3_signoff.py
---------------------------------
Third round on the named sign-off. It does not move the legal section by any route; a review
scope binds a person-facing unit too; a real name in any alphabet can sign and be a reviewer,
while a lookalike, a hidden character or an accent gets past no check; a name is a name; what
a sign-off file holds beyond what was checked reaches no report; a file name cannot drive the
terminal.
"""

from __future__ import annotations

import json
import shutil
from datetime import date
from pathlib import Path
from typing import Any

import pytest
import yaml
from investigation_helpers import write_record
from test_signoff import (
    NAME,
    PATTERN,
    POLICY,
    REASON,
    STAMP,
    R,
    _assess,
    _auditor_assess,
    _auditor_setup,
    _engagement,
    _mech,
    _record,
    _repo,
    _sign,
    _signoff_file,
    _surface,
    needs_git,
)

from aisafe.assessment.outcome import mechanism_outcomes
from aisafe.assessment.render import _flat, render_html, render_markdown, render_terminal
from aisafe.engagement import model
from aisafe.investigation import signoff
from aisafe.investigation.records import fold_text, verdict_words_in
from aisafe.investigation.signoff import _shown, file_sha_at, person_problems
from aisafe.legal.evaluate import _Evidence
from aisafe.review import cli as review_cli
from aisafe.review.records import (
    check_text,
    dump_document,
    parse_review_document,
    record_document,
    tool_name_problem,
)

RUNNING = [r for m in POLICY.mechanisms for r in m.rules]
AT_REVIEW = {"evidence_status": "supported_mechanism", "decision": "requires_contextual_review"}
OSCAR = "\u00d3scar Arroyo"
JOSE = "Jos\u00e9"
IVAN = "\u0418\u0432\u0430\u043d"
WANG = "\u738b\u4f1f"
# A character past U+FFFF, in a real family name: a JSON escape makes it a surrogate pair.
KICHI = "\U00020bb7\u91ce"
SECRET = "sk-ant-api03-" + "A" * 40


def _not_passing(by: str) -> list[str]:
    return person_problems(by, REASON)


# ---------------------------------------------------------------------------
# The legal section
# ---------------------------------------------------------------------------


def _evidence(records: list[R], **kw: Any) -> _Evidence:
    outcomes = mechanism_outcomes(
        POLICY,
        records=records,
        rejected=[],
        findings=[],
        surfaces=[_surface()],
        rules_ran=RUNNING,
        **kw,
    )
    return _Evidence(
        policy=POLICY,
        outcomes=outcomes,
        records=records,
        surfaces=[_surface()],
        findings=[],
        evaluation=None,
        requests={},
        carried=[],
    )


INDICATORS = {"mechanisms": ["M2"], "what": "article 5"}
CLOSED = {"kind": "closed", "mechanism": "M2", "pattern": PATTERN, "what": "x"}


def test_a_signed_record_does_not_move_the_indicators_item() -> None:
    at_review = R("r1", "M2", PATTERN, "review", {"id": "s-1"}, effective=AT_REVIEW)
    signed = R("r1", "M2", PATTERN, "closes", {"id": "s-1"}, signoffs=[STAMP])
    assert _evidence([at_review]).indicators_item(INDICATORS)["status"] == "missing"
    row = _evidence([signed]).indicators_item(INDICATORS)
    assert row["status"] == "missing" and "sign-off" in row["detail"]


def test_a_signed_file_does_not_move_the_indicators_item() -> None:
    machine = R("r1", "M2", PATTERN, "closes", {"id": "s-1"})
    assert _evidence([machine]).indicators_item(INDICATORS)["status"] == "indicators"
    unread = dict(unsupported_files=["deploy.sh"])
    assert _evidence([machine], **unread).indicators_item(INDICATORS)["status"] == "missing"
    stamp = {**STAMP, "files": [{"path": "deploy.sh", "sha256": "0" * 64}]}
    row = _evidence([machine], **unread, signed_files=[stamp]).indicators_item(INDICATORS)
    assert row["status"] == "missing"


def test_a_violation_is_still_an_indicator() -> None:
    violation = R(
        "r1",
        "M2",
        PATTERN,
        "establishes",
        {"id": "s-1"},
        effective={"evidence_status": "supported_mechanism", "decision": "violates_policy"},
    )
    row = _evidence([violation]).indicators_item(INDICATORS)
    assert row["status"] == "indicators" and "M2" in row["detail"]


def test_a_signed_record_beside_an_unsigned_closing_holds_the_pattern_item_back() -> None:
    machine = R("r1", "M2", PATTERN, "closes", {"id": "s-1"})
    at_review = R("r2", "M2", PATTERN, "review", {"id": "s-1"}, effective=AT_REVIEW)
    signed = R("r2", "M2", PATTERN, "closes", {"id": "s-1"}, signoffs=[STAMP])
    assert _evidence([machine, at_review]).pattern_item(CLOSED)["status"] == "missing"
    row = _evidence([machine, signed]).pattern_item(CLOSED)
    assert row["status"] == "missing" and "r2" in row["detail"]
    assert _evidence([machine]).pattern_item(CLOSED)["status"] == "met"


# ---------------------------------------------------------------------------
# The scope of a review, on a person-facing unit
# ---------------------------------------------------------------------------


def _m8(surfaces: list[dict[str, Any]], *reviews: dict[str, Any]) -> Any:
    outcomes = mechanism_outcomes(
        POLICY,
        records=[],
        rejected=[],
        findings=[],
        surfaces=surfaces,
        review_records=list(reviews),
        rules_ran=RUNNING,
        today=date(2026, 11, 1),
    )
    return next(o for o in outcomes if o.id == "M8")


def _review_row(**over: Any) -> dict[str, Any]:
    row = {
        "file": "r.yaml",
        "reviewed_at": "2026-10-30",
        "policy_version": POLICY.version,
        "stale": [],
        "artifact_files": ["a.py"],
        "units": [],
        "scope": ["M1"],
    }
    return {**row, **over}


UNIT = {
    "id": "s0",
    "type": "person_facing_unit",
    "file": ".",
    "line": 0,
    "unit": ".",
    "hypotheses": [{"mechanism": "M5", "pattern": "x", "signalled": True}],
}
PROMPT = {
    "id": "s1",
    "type": "prompt",
    "file": "a.py",
    "line": 1,
    "unit": ".",
    "hypotheses": [{"mechanism": "M1", "pattern": "y", "signalled": True}],
}


def test_a_review_scope_binds_a_person_facing_unit_as_it_binds_a_file() -> None:
    narrow = _m8([UNIT, PROMPT], _review_row())
    assert [gap.kind for gap in narrow.gaps] == ["surface_not_reviewed"]
    wide = _m8([UNIT, PROMPT], _review_row(scope=["M1", "M5"]))
    assert not wide.gaps


def test_a_review_of_another_unit_does_not_bind_this_one() -> None:
    other = _m8([UNIT, PROMPT], _review_row(scope=["M1", "M5"], units=["web"]))
    assert [gap.kind for gap in other.gaps] == ["surface_not_reviewed"]


# ---------------------------------------------------------------------------
# A real name, in any alphabet
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "by",
    [
        OSCAR,
        JOSE,
        "Fran\u00e7ois M\u00fcller",
        "Mar\u00eda-Jos\u00e9 O'Neill",
        IVAN + " \u041f\u0435\u0442\u0440\u043e\u0432",
        WANG,
        KICHI,
        "\u4f50\u85e4\u3055\u304f\u3089",  # kanji and kana in one word: one writing system
        "Ana Ruiz <Lead>",
    ],
)
def test_a_real_name_passes(by: str) -> None:
    assert _not_passing(by) == []
    assert check_text("reviewer", by) is None and tool_name_problem(by) is None


def test_a_reason_in_another_language_passes() -> None:
    assert person_problems(NAME, "revis\u00e9 las l\u00edneas con el equipo") == []
    assert check_text("x", "\u4f7f\u7528GPT\u6a21\u578b\u7684app.py") is None  # no spaces in CJK
    assert check_text("x", "\u0444\u0430\u0439\u043b.py") is None  # the dot ends the word


@pytest.mark.parametrize(
    "by",
    [
        "Cl\u00e1ude",
        "\u0421laude",  # a Cyrillic C
        "\uff23\uff4c\uff41\uff55\uff44\uff45",  # fullwidth
        "\U0001d402\U0001d425\U0001d41a\U0001d42e\U0001d41d\U0001d41e",  # mathematical bold
        "Ana\u202eRuiz",  # right-to-left override
        "Cl\u200baude",  # zero-width space
        "Ana\u0085Ruiz",
        "Ana\u2028Ruiz",
        "Ana\ue000Ruiz",  # private use
        "Ana\u0378Ruiz",  # unassigned
        "A\u3164na",  # a letter that prints as nothing
        "\u0301",  # a mark and nothing it marks
    ],
)
def test_a_lookalike_or_a_hidden_character_does_not_pass_as_a_name(by: str) -> None:
    assert _not_passing(by)


@pytest.mark.parametrize(
    "reason",
    [
        "the system is s\u00e1fe",
        "the system is s\u0430fe",  # a Cyrillic a
        "this is compli\u00e1nt",
        "it is certif\u00eded",
        "is s\u200bafe",
        "the system is \uff53\uff41\uff46\uff45",  # fullwidth
        "it is\u00a0safe",  # a no-break space
        "it is s\ufe0fafe",  # a variation selector
        "key \uff53\uff4b-ant-api03-" + "A" * 40,  # a fullwidth secret
    ],
)
def test_an_accent_or_a_lookalike_does_not_get_a_refused_word_past(reason: str) -> None:
    assert person_problems(NAME, reason)


def test_the_refusal_never_repeats_what_it_refused() -> None:
    for value in ("Cl\u00e1ude", "Ana\u202eRuiz", "the system is s\u0430fe"):
        problem = check_text("x", value)
        assert problem is None or value not in problem


def test_a_line_break_stays_a_notes_field_only() -> None:
    assert check_text("x", "one\ntwo", multiline=True) is None
    assert check_text("x", "one\ntwo") == "x must be a single line of printable text"
    assert check_text("x", "one\u2028two", multiline=True) == "x must be printable text"


def test_the_fold_is_what_a_check_reads_and_never_what_is_kept() -> None:
    assert fold_text(OSCAR) == "Oscar Arroyo"
    assert fold_text(WANG) == WANG
    assert verdict_words_in("the system is s\u00e1fe") == ["is safe"]
    assert verdict_words_in("the system is s\u200bafe") == ["is safe"]


@pytest.mark.parametrize("name", [OSCAR, IVAN, WANG, KICHI])
def test_a_name_survives_the_record_file(name: str) -> None:
    doc = record_document(
        reviewer=f"{name} <lead>",
        reviewed_at=date(2026, 10, 30),
        scope=["M1"],
        declared_purpose="revis\u00e9 el prop\u00f3sito",
        artifacts=[],
        policy_version=POLICY.version,
        notes="primera l\u00ednea\nsegunda",
    )
    text = dump_document(doc)
    assert f'reviewer: "{name} <lead>"' in text
    back = yaml.safe_load(text)
    assert back["reviews"][0]["reviewer"] == f"{name} <lead>"
    assert back["reviews"][0]["notes"] == "primera l\u00ednea\nsegunda"


def test_a_field_outside_the_schema_stays_readable_as_yaml() -> None:
    doc = {"reviews": [{"reviewer": "x", "extra": "a\x85b\x7fc\u2028d"}]}
    assert yaml.safe_load(dump_document(doc))["reviews"][0]["extra"] == "a\x85b\x7fc\u2028d"


@pytest.fixture
def companion(tmp_path: Path, audit_fixture) -> Path:
    root = tmp_path / "companion"
    shutil.copytree(audit_fixture("persons_companion"), root)
    return root


def test_the_review_command_takes_a_name_and_its_output_stays_ascii(
    companion: Path, capsys
) -> None:
    argv = ["record", str(companion), "--reviewer", f"{IVAN} <lead>", "--purpose", "a tutor"]
    argv += ["--scope", "M1"]
    code = review_cli.main(argv)
    out = capsys.readouterr()
    assert code == review_cli.EXIT_OK, out.err
    assert out.out.isascii()
    written = (companion / "aisafe-review.yaml").read_text(encoding="utf-8")
    assert IVAN in written
    assert review_cli.main(["check", str(companion)]) == review_cli.EXIT_OK
    assert capsys.readouterr().out.isascii()


def test_the_reader_takes_what_the_writer_wrote() -> None:
    doc = yaml.safe_load(
        dump_document(
            record_document(
                reviewer=KICHI,
                reviewed_at=date(2026, 10, 30),
                scope=["M1"],
                declared_purpose="a tutor",
                artifacts=[],
                policy_version=POLICY.version,
            )
        )
    )
    _records, errors, _version = parse_review_document(doc, "r.yaml", POLICY)
    assert not [e for e in errors if "reviewer" in e]


@needs_git
def test_a_name_with_an_accent_signs_and_every_format_shows_it(tmp_path: Path, capsys) -> None:
    root, commit = _repo(tmp_path)
    records = tmp_path / "records"
    write_record(records, _record(root, commit), skeptic="upheld")
    reason = "revis\u00e9 las l\u00edneas citadas con el equipo"
    assert _sign(records, root, "--record", "inv-tone", by=OSCAR, reason=reason) == 0
    doc = _assess(root, records)
    (row,) = doc["signoffs"]["accepted"]
    assert row["by"] == OSCAR and row["reason"] == reason
    assert OSCAR in render_markdown(doc)
    assert render_html(doc).isascii() and "&#211;scar" in render_html(doc)
    assert OSCAR in render_terminal(doc)


# ---------------------------------------------------------------------------
# A name is a name
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "by",
    [
        "<Claude Code>",
        "<",
        "<x>",
        " <AI agent>",
        "-",
        ".",
        "?",
        "12345",
        "Claude.",
        "(Claude)",
        "`Claude`",
        "*Claude*",
        "_Claude_",
        '"Claude"',
        "'Claude Code'",
        "Claude,",
        "AI assistant.",
        "A.I.",
        "the system is safe",
        "This system is safe to deploy",
    ],
)
def test_what_is_no_persons_name_is_refused(by: str) -> None:
    (problem,) = _not_passing(by)
    assert "no person's name" in problem
    assert tool_name_problem(by) is not None


def test_a_verdict_is_no_reviewer() -> None:
    problem = tool_name_problem("the system is safe")
    assert problem is not None and "the system is safe" not in problem


@needs_git
def test_a_verdict_for_a_name_never_prints_as_a_persons_decision(tmp_path: Path, capsys) -> None:
    root, commit = _repo(tmp_path)
    records = tmp_path / "records"
    write_record(records, _record(root, commit), skeptic="upheld")
    assert _sign(records, root, "--record", "inv-tone", by="the system is safe") == 2
    assert not list(records.glob("signoff-*.json"))


# ---------------------------------------------------------------------------
# What a sign-off file holds beyond what was checked
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "the whole system is safe to deploy and compliant",
        "the system is certified safe",
        f"{SECRET} is here",
        "line\nbreak",
        "s\u0430fe word",
    ],
)
def test_refused_words_are_not_shown(value: str) -> None:
    assert _shown(value) == "(not shown)"


def test_a_plain_value_is_shown_quoted_and_cut() -> None:
    assert _shown("inv-x") == "'inv-x'"
    assert _shown(None) == "None"
    assert _shown(["the system is safe"]) == "(not shown)"
    assert len(_shown("a b " * 100)) == 120


def _signed(tmp_path: Path, *extra: str) -> tuple[Path, Path, str]:
    root, commit = _repo(tmp_path, *extra)
    records = tmp_path / "records"
    write_record(records, _record(root, commit), skeptic="upheld")
    args = ["--file", extra[0]] if extra else []
    assert _sign(records, root, "--record", "inv-tone", *args) == 0
    return root, records, commit


def _rewrite(records: Path, **fields: Any) -> dict[str, Any]:
    path = _signoff_file(records)
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc.update(fields)
    path.write_text(json.dumps(doc), encoding="utf-8")
    return doc


@needs_git
def test_refused_words_reach_no_report(tmp_path: Path) -> None:
    root, records, _ = _signed(tmp_path)
    doc = json.loads(_signoff_file(records).read_text(encoding="utf-8"))
    doc["records"].append({"id": "the whole system is safe to deploy and compliant"})
    doc["files"] = [{"path": f"{SECRET} is safe to deploy"}]
    doc["policy_version"] = "the system is certified safe"
    _signoff_file(records).write_text(json.dumps(doc), encoding="utf-8")
    assessed = _assess(root, records)
    assert not assessed["signoffs"]["accepted"]
    (row,) = assessed["signoffs"]["refused"]
    assert "(not shown)" in " ".join(row["why"])
    for text in (render_markdown(assessed), render_terminal(assessed), json.dumps(row)):
        assert "safe to deploy" not in text and "certified safe" not in text
        assert SECRET not in text


@needs_git
def test_a_verdict_for_an_id_counts_for_nothing_and_is_not_shown(tmp_path: Path) -> None:
    root, records, _ = _signed(tmp_path)
    _rewrite(records, id="certified")
    assessed = _assess(root, records)
    (row,) = assessed["signoffs"]["refused"]
    assert row["id"] is None and "`id` reads as a verdict" in row["why"]


@needs_git
def test_what_a_row_holds_beyond_its_keys_is_not_carried(tmp_path: Path) -> None:
    root, records, _ = _signed(tmp_path, "deploy.sh")
    doc = json.loads(_signoff_file(records).read_text(encoding="utf-8"))
    doc["records"][0]["note"] = "the system is safe to deploy"
    doc["files"][0]["verdict"] = "certified safe"
    _signoff_file(records).write_text(json.dumps(doc), encoding="utf-8")
    assessed = _assess(root, records)
    (row,) = assessed["signoffs"]["accepted"]
    assert set(row["records"][0]) == {"id", "record_sha256"}
    assert set(row["files"][0]) == {"path", "sha256"}
    assert "safe to deploy" not in json.dumps(assessed["signoffs"])


@needs_git
@pytest.mark.parametrize("key", ["records", "files"])
def test_a_row_listed_twice_counts_for_nothing(tmp_path: Path, key: str) -> None:
    root, records, _ = _signed(tmp_path, "deploy.sh")
    doc = json.loads(_signoff_file(records).read_text(encoding="utf-8"))
    doc[key] = [*doc[key], dict(doc[key][0]), dict(doc[key][0])]
    _signoff_file(records).write_text(json.dumps(doc), encoding="utf-8")
    assessed = _assess(root, records)
    assert not assessed["signoffs"]["accepted"]
    (row,) = assessed["signoffs"]["refused"]
    assert sum("listed twice" in line for line in row["why"]) == 2
    assert "inconclusive" in _mech(assessed, "M2")["outcome"]


@needs_git
def test_a_file_name_in_a_deep_tree_is_shown_by_git(tmp_path: Path, monkeypatch) -> None:
    root, commit = _repo(tmp_path, "guía despliegue.sh")
    seen: list[tuple[str, ...]] = []
    real = signoff.run_git

    def spy(args: tuple[str, ...], *rest: Any, **kw: Any) -> Any:
        seen.append(args)
        return real(args, *rest, **kw)

    monkeypatch.setattr(signoff, "run_git", spy)
    assert file_sha_at(root, commit, "guía despliegue.sh") is not None
    # Without the `--`, git also stats `<commit>:./<path>`, and past 260 characters it dies.
    assert seen[-1][-1] == "--"


# ---------------------------------------------------------------------------
# The audited team, however it is spelled
# ---------------------------------------------------------------------------


@needs_git
@pytest.mark.parametrize(
    "auditee", ["T.  Auditor", "t. auditor", "T.\u00a0Auditor", "T. \u00c1uditor", "  T. Auditor "]
)
def test_the_auditor_is_the_auditee_however_the_name_is_spaced(
    tmp_path: Path, auditee: str
) -> None:
    root, eng, records = _auditor_setup(tmp_path)
    args = ("--record", "inv-tone", "--engagement", str(eng))
    assert _sign(records, root, *args, by="T. Auditor") == 0
    path = eng / model.ENGAGEMENT_FILE
    data = json.loads(path.read_text(encoding="utf-8"))
    data["auditee"]["name"] = auditee
    path.write_text(json.dumps(data), encoding="utf-8")
    assessed = _auditor_assess(root, eng, records)
    assert not assessed["signoffs"]["accepted"]
    assert "audited team" in " ".join(assessed["signoffs"]["refused"][0]["why"])


@needs_git
def test_an_auditor_with_an_accent_signs(tmp_path: Path) -> None:
    root, commit = _repo(tmp_path)
    eng = _engagement(tmp_path, root, commit)
    path = eng / model.ENGAGEMENT_FILE
    data = json.loads(path.read_text(encoding="utf-8"))
    data["auditor"]["name"] = OSCAR
    data["independence"]["by"] = OSCAR
    path.write_text(json.dumps(data), encoding="utf-8")
    records = eng / model.INVESTIGATIONS_DIR
    write_record(records, _record(root, commit, mode="auditor"), skeptic="upheld")
    args = ("--record", "inv-tone", "--engagement", str(eng))
    assert _sign(records, root, *args, by=OSCAR) == 0


# ---------------------------------------------------------------------------
# A file name on the terminal
# ---------------------------------------------------------------------------


def test_flat_replaces_every_control_character() -> None:
    assert _flat("a\x1b[2Jb\x9b31m\x7f\x00") == "a?[2Jb?31m??"
    assert _flat("one\ntwo\ttab") == "one two tab"
    assert _flat(None) == ""
    assert _flat(OSCAR) == OSCAR


@needs_git
def test_a_file_name_cannot_drive_the_terminal(tmp_path: Path) -> None:
    root, records, _ = _signed(tmp_path)
    doc = _assess(root, records)
    doc = dict(doc)
    doc["signoffs"] = {
        "accepted": [],
        "refused": [
            {"file": "x\x1b[2J\x9b31m.json", "id": None, "by": None, "reason": None, "why": ["w"]}
        ],
    }
    text = render_terminal(doc)
    assert "\x1b" not in text and "\x9b" not in text
