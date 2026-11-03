"""tests/unit/test_fixes6_signoff.py
---------------------------------
Sixth round on the named sign-off and the engagement. A lookalike letter from another
alphabet, or a small capital, gets past no verdict or tool-name check, while a real name in
Cyrillic or Greek still passes; three stems catch a German or French verdict; a refusal never
repeats the verdict it refused, nor the file name it refused; a record that says it is not done
cannot be signed; the QA sign-off compares names as the sign-off does; every name and every
free text the engagement records is checked; a file named like a secret is not copied in; and
a baseline reason opens no HTML comment in the audit's Markdown.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from investigation_helpers import write_record
from test_review_baseline import make_report, three
from test_signoff import (
    NAME,
    REASON,
    _assess,
    _edit,
    _record,
    _repo,
    _sign,
    _signed_repo,
    _signoff_file,
    needs_git,
)

from aisafe.assessment.render import render_markdown, render_terminal
from aisafe.engagement import model
from aisafe.engagement.cli import main as eng_main
from aisafe.investigation.records import fold_text, verdict_words_in
from aisafe.investigation.signoff import person_problems
from aisafe.reporting.report import render
from aisafe.review.baseline import BaselineError, _check_reason
from aisafe.review.records import check_text, tool_name_problem

IVAN = "\u0418\u0432\u0430\u043d \u041f\u0435\u0442\u0440\u043e\u0432"
ELENI = (
    "\u0395\u03bb\u03ad\u03bd\u03b7"
    " \u03a0\u03b1\u03c0\u03b1\u03b4\u03bf\u03c0\u03bf\u03cd\u03bb\u03bf\u03c5"
)
# "the system is safe" with a Cyrillic i and dze: no word mixes two alphabets.
CYRILLIC_IS = "read it all: the system \u0456\u0455 safe"
SMALL_CAPS = "the system is \u1d04\u1d07\u0280\u1d1b\u026a\ua730\u026a\u1d07\u1d05"
SECRET_NAME = "AKIA" + "IOSFODNN7EXAMPLE"
SECRET = "sk-ant-api03-" + "A" * 40


# ---------------------------------------------------------------------------
# 1. Lookalike letters, and the stems of a verdict in another language
# ---------------------------------------------------------------------------


def test_a_lookalike_verdict_is_still_a_verdict() -> None:
    assert verdict_words_in(CYRILLIC_IS) == ["is safe"]
    assert verdict_words_in("the system \u026as safe") == ["is safe"]
    assert verdict_words_in("the system is cert\u0131f\u0131ed") == ["certified"]
    assert verdict_words_in(SMALL_CAPS) == ["certified"]
    assert check_text("r", SMALL_CAPS) is not None
    assert person_problems(NAME, CYRILLIC_IS)
    assert person_problems(NAME, SMALL_CAPS)


@pytest.mark.parametrize(
    "name",
    [
        "\u0391\u0399",  # Greek capital alpha and iota
        "\u0412\u041e\u0422",  # Cyrillic capitals ve, o, te
        "\u1d04\u029f\u1d00\u1d1c\u1d05\u1d07",  # small capitals
        "Gem\u0131n\u0131",  # dotless i
        "GPT-4 AI",
    ],
)
def test_a_lookalike_tool_name_is_a_tool_name(name: str) -> None:
    assert tool_name_problem(name) is not None
    assert person_problems(name, REASON)


@pytest.mark.parametrize("name", [IVAN, ELENI, "\u0412\u0430\u043d \u041b\u0438"])
def test_a_real_name_in_cyrillic_or_greek_still_passes(name: str) -> None:
    assert check_text("the name", name) is None
    assert tool_name_problem(name) is None
    assert person_problems(name, REASON) == []
    # The mix check reads the plain fold: a word wholly in one alphabet mixes nothing.
    assert fold_text(name) != fold_text(name, lookalikes=True)


def test_honest_text_in_cyrillic_passes() -> None:
    text = "\u043f\u0440\u043e\u0447\u0438\u0442\u0430\u043b\u0438 \u043a\u043e\u0434"
    assert check_text("the reason", text) is None
    assert verdict_words_in(text) == []


def test_three_stems_catch_a_german_or_french_verdict() -> None:
    assert verdict_words_in("das System ist konform und zertifiziert") == [
        "konform",
        "zertifiziert",
    ]
    assert verdict_words_in("le syst\u00e8me est certifi\u00e9") == ["certifie"]
    assert verdict_words_in("a certification of the pipeline") == ["certification"]
    assert person_problems(NAME, "das System ist konform")


def test_everyday_words_in_other_languages_pass() -> None:
    for text in ("el sistema es seguro y conforme", "das ist sicher", "nonkonform"):
        assert verdict_words_in(text) == [], text
        assert person_problems(NAME, text) == [], text
    # A stem is matched at the start of a word only.
    assert verdict_words_in("an uncertified build") == []


def test_a_baseline_reason_in_german_that_pronounces_a_verdict_is_refused() -> None:
    with pytest.raises(BaselineError) as info:
        _check_reason("494b8d2efb84b87b", "laut Vertrag ist das System konform und zertifiziert")
    assert "verdict" in str(info.value) and "konform" not in str(info.value)
    assert _check_reason("494b8d2efb84b87b", "kept for the pilot, read with the team")


# ---------------------------------------------------------------------------
# 2. A refusal does not repeat the verdict
# ---------------------------------------------------------------------------


def test_the_refusal_names_no_verdict_word() -> None:
    (problem,) = person_problems(NAME, "the system is safe for minors")
    assert "verdict" in problem and "is safe" not in problem


@needs_git
def test_a_refused_reason_reaches_no_report(tmp_path: Path) -> None:
    root, _, records = _signed_repo(tmp_path)
    _edit(records, reason="read it all; there is no risk left")
    doc = _assess(root, records)
    assert doc["signoffs"]["accepted"] == []
    (row,) = doc["signoffs"]["refused"]
    assert row["reason"] is None
    assert "no risk" not in json.dumps(doc["signoffs"])
    for text in (render_markdown(doc), render_terminal(doc)):
        assert "(no risk)" not in text and "no risk left" not in text


# ---------------------------------------------------------------------------
# 3. The sign-off's file name
# ---------------------------------------------------------------------------


@needs_git
@pytest.mark.parametrize(
    "file_name", ["the-system-is-certified-compliant.json", f"{SECRET_NAME}.json"]
)
def test_a_file_named_like_a_verdict_or_a_secret_is_refused_and_not_shown(
    tmp_path: Path, file_name: str
) -> None:
    root, _, records = _signed_repo(tmp_path)
    path = _signoff_file(records)
    path.rename(records / file_name)
    doc = _assess(root, records)
    assert doc["signoffs"]["accepted"] == []
    (row,) = doc["signoffs"]["refused"]
    assert row["file"].endswith("/(not shown)")
    assert any("file name" in why for why in row["why"])
    stem = file_name.removesuffix(".json")
    # `machine.skipped_files` still lists the path as read: outside this change's scope.
    assert stem not in json.dumps([doc["signoffs"], doc["inputs"]])
    for text in (render_markdown(doc), render_terminal(doc)):
        assert stem not in text
    (shown,) = [item for item in doc["inputs"] if item["role"] == "sign-off"]
    assert shown["path"].endswith("/(not shown)") and len(shown["sha256"]) == 64


@needs_git
def test_a_plain_file_name_is_shown_as_it_is(tmp_path: Path) -> None:
    root, _, records = _signed_repo(tmp_path)
    path = _signoff_file(records)
    doc = _assess(root, records)
    (row,) = doc["signoffs"]["accepted"]
    assert row["file"] == path.as_posix()
    (shown,) = [item for item in doc["inputs"] if item["role"] == "sign-off"]
    assert shown["path"] == path.as_posix()


# ---------------------------------------------------------------------------
# 4. A record that says it is not done
# ---------------------------------------------------------------------------


@needs_git
@pytest.mark.parametrize(
    ("over", "said"),
    [
        ({"open_questions": ["does the reply reach the person unreviewed?"]}, "open questions"),
        ({"missing_evidence": ["the deploy configuration"]}, "missing evidence"),
        (
            {
                "counterevidence": [
                    {
                        "reading": "the tone analysis is used to steer the person",
                        "result": "supported",
                        "reason": "the cited lines show the analysis feeds the reply",
                        "citations": [],
                    }
                ]
            },
            "another reading supported",
        ),
    ],
)
def test_a_record_that_is_not_done_cannot_be_signed(
    tmp_path: Path, capsys, over: dict, said: str
) -> None:
    root, commit = _repo(tmp_path)
    records = tmp_path / "records"
    write_record(records, _record(root, commit, **over), skeptic="upheld")
    before = _assess(root, records)
    (record,) = before["machine"]["records"]
    assert record["claim"] == "review"
    assert _sign(records, root, "--record", "inv-tone") == 2
    err = capsys.readouterr().err
    assert said in err and "new record" in err
    assert not list(records.glob("signoff-*.json"))
    doc = _assess(root, records)
    assert doc["signoffs"]["accepted"] == []


# ---------------------------------------------------------------------------
# 5, 6. The engagement: QA by the auditor, names and free text
# ---------------------------------------------------------------------------


def _requests(tmp_path: Path) -> Path:
    eng = tmp_path / "eng"
    eng.mkdir()
    model.write_json(
        eng / model.REQUESTS_FILE,
        model.merge_requests({"requests": []}, [{"id": "p/x/doc", "source": {}, "what": "doc"}]),
    )
    return eng


@pytest.mark.parametrize("by", ["T.  Auditor", "T. Aud\u00edtor", "t. auditor"])
def test_the_auditor_cannot_sign_qa_under_another_spelling(tmp_path: Path, by: str) -> None:
    assessment = tmp_path / "assessment.json"
    assessment.write_text("{}", encoding="utf-8")
    with pytest.raises(model.EngagementError, match="second auditor"):
        model.add_signoff(
            tmp_path, by=by, decision="approved", assessment=assessment, auditor="T. Auditor"
        )
    assert not (tmp_path / model.QA_FILE).exists()


def test_qa_takes_a_person_and_checked_notes(tmp_path: Path) -> None:
    assessment = tmp_path / "assessment.json"
    assessment.write_text("{}", encoding="utf-8")
    for by, notes in (("Claude", None), ("Q. Reviewer", "the system is certified")):
        with pytest.raises(model.EngagementError):
            model.add_signoff(
                tmp_path,
                by=by,
                decision="approved",
                assessment=assessment,
                notes=notes,
                auditor="T. Auditor",
            )
    model.add_signoff(
        tmp_path,
        by="Q. Reviewer",
        decision="approved",
        assessment=assessment,
        notes="read the bundle and the records",
        auditor="T. Auditor",
    )


def test_insufficient_takes_a_person_and_a_checked_reason(tmp_path: Path) -> None:
    eng = _requests(tmp_path)
    for by, reason in (
        ("Claude", "unsigned"),
        ("ChatGPT", "unsigned"),
        ("T. Auditor", "the system is compliant and certified"),
        ("T. Auditor", "there is no risk"),
        ("T. Auditor", f"the key {SECRET} is in it"),
        ("T. Auditor", "unsigned\x1b[2J"),
    ):
        with pytest.raises(model.EngagementError) as info:
            model.mark_insufficient(eng, "p/x/doc", by=by, reason=reason)
        assert reason not in str(info.value)
    assert model.load_requests(eng)["requests"][0]["status"] == "requested"
    model.mark_insufficient(eng, "p/x/doc", by="T. Auditor", reason="unsigned")


def test_a_response_may_disagree_and_may_not_pronounce_a_verdict(tmp_path: Path) -> None:
    eng = tmp_path / "eng"
    for by, text in (
        ("Claude", "We disagree."),
        ("P. Owner", "the system is safe to deploy and certified"),
        ("P. Owner", "We disagree.\x07"),
        ("P. Owner", f"see {SECRET}"),
    ):
        with pytest.raises(model.EngagementError):
            model.add_response(eng, to="M6", by=by, text=text)
    assert not list((eng / model.RESPONSES_DIR).glob("*.json"))
    model.add_response(
        eng, to="M6", by="P. Owner <CTO>", text="We disagree: the tone analysis\nis off."
    )


def test_receive_takes_a_person_and_a_checked_note(tmp_path: Path) -> None:
    eng = _requests(tmp_path)
    source = tmp_path / "protocol.txt"
    source.write_text("the crisis protocol", encoding="utf-8")
    for by, note in (("Claude", None), ("T. Auditor", "certified by the vendor")):
        with pytest.raises(model.EngagementError):
            model.receive(eng, "p/x/doc", [source], by=by, note=note)
    assert not (eng / model.EVIDENCE_DIR).exists()
    model.receive(eng, "p/x/doc", [source], by="T. Auditor", note="the signed copy")


def test_the_cli_refuses_a_tool_as_the_person(tmp_path: Path, capsys) -> None:
    root = tmp_path / "t"
    root.mkdir()
    eng = tmp_path / "engagement"
    argv = ["init", "--engagement", str(eng), "--target", str(root), "--auditor", "T. Auditor"]
    assert eng_main(argv) == 0
    capsys.readouterr()
    signed = tmp_path / "authorisation.txt"
    signed.write_text("signed", encoding="utf-8")
    base = ["--engagement", str(eng)]
    what = ["--what", "authorisation to test the staging endpoint", "--date", "2026-10-29"]
    assert eng_main(["authorise", *base, *what, "--by", "ChatGPT", "--file", str(signed)]) == 2
    assert eng_main(["respond", *base, "--to", "M2", "--by", "Claude", "--text", "x"]) == 2
    err = capsys.readouterr().err
    assert err.count("no person's name") == 2
    data = json.loads((eng / model.ENGAGEMENT_FILE).read_text(encoding="utf-8"))
    assert not any(a.get("by") == "ChatGPT" for a in data.get("authorisations") or [])
    assert (
        eng_main(["authorise", *base, *what, "--by", "B. Owner <CTO>", "--file", str(signed)]) == 0
    )


# ---------------------------------------------------------------------------
# 7. A file named like a secret is not copied in
# ---------------------------------------------------------------------------


def test_receive_refuses_a_file_named_like_a_secret(tmp_path: Path) -> None:
    eng = _requests(tmp_path)
    source = tmp_path / f"{SECRET_NAME}.txt"
    source.write_text("a document", encoding="utf-8")
    with pytest.raises(model.EngagementError) as info:
        model.receive(eng, "p/x/doc", [source], by="T. Auditor")
    assert SECRET_NAME not in str(info.value)
    assert not (eng / model.EVIDENCE_DIR).exists()
    assert model.load_requests(eng)["requests"][0]["status"] == "requested"


def test_authorise_refuses_a_file_named_like_a_secret(tmp_path: Path) -> None:
    root = tmp_path / "t"
    root.mkdir()
    eng = tmp_path / "engagement"
    argv = ["init", "--engagement", str(eng), "--target", str(root), "--auditor", "T. Auditor"]
    assert eng_main(argv) == 0
    source = tmp_path / f"{SECRET_NAME}.txt"
    source.write_text("signed", encoding="utf-8")
    with pytest.raises(model.EngagementError) as info:
        model.add_authorisation(
            eng, what="authorisation to test", by="B. Owner", on="2026-10-29", document=source
        )
    assert SECRET_NAME not in str(info.value)
    assert not (eng / model.AUTHORISATIONS_DIR).exists()


# ---------------------------------------------------------------------------
# 8. A baseline reason in the audit's Markdown
# ---------------------------------------------------------------------------


def test_a_baseline_reason_opens_no_html_comment_in_the_markdown() -> None:
    findings = three()
    findings[0].accepted_reason = "read with the team <!-- hidden --> & kept `for` the pilot"
    findings[0].baseline_status = "unchanged"
    text = render(make_report(findings), "markdown")
    (line,) = [line for line in text.splitlines() if "read with the team" in line]
    assert "<!--" not in line
    assert "&lt;!-- hidden --> &amp; kept \\`for\\` the pilot" in line
    # The terminal shows it as it is: nothing there hides a comment.
    terminal = render(make_report(findings), "terminal")
    assert "<!-- hidden -->" in terminal
