"""tests/unit/test_fixes3_misc.py
-------------------------------
A baseline reason in any alphabet, and no report written through a link.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aisafe.assessment.cli import main as assess_main
from aisafe.discovery import walk
from aisafe.investigation.cli import main as investigate_main
from aisafe.review.baseline import BaselineError, _check_reason

FP = "3f9a1c0b2d4e5f67"


@pytest.mark.parametrize("reason", ["revisé las líneas del prompt", "plain words", "Иван смотрел"])
def test_a_baseline_reason_takes_any_alphabet(reason: str) -> None:
    assert _check_reason(FP, reason) == reason


@pytest.mark.parametrize(
    "reason",
    [
        "two\nlines",
        "a​hidden character",
        "the target is sаfe",
        "the target is compliánt",
    ],
)
def test_a_baseline_reason_still_refuses_what_it_refused(reason: str) -> None:
    with pytest.raises(BaselineError):
        _check_reason(FP, reason)


def _as_if_linked(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    monkeypatch.setattr(walk, "is_link", lambda path: Path(path).name == name)


def test_a_plan_is_not_written_through_a_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _as_if_linked(monkeypatch, ".aisafe-audit")
    target = tmp_path / ".aisafe-audit" / "plan.json"
    assert investigate_main(["plan", str(tmp_path), "-o", str(target)]) == 2
    assert "goes through a link" in capsys.readouterr().err
    assert not target.exists()


def test_an_assessment_is_not_written_through_a_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _as_if_linked(monkeypatch, "out")
    records = tmp_path / "records"
    records.mkdir()
    code = assess_main(
        [str(tmp_path), "--investigations", str(records), "-o", str(tmp_path / "out")]
    )
    assert code == 2
    assert "goes through a link" in capsys.readouterr().err
