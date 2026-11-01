"""tests/unit/test_fixes2_outcome.py
---------------------------------
Second round on the outcome: it never reads better than the evidence. A review record the
parser dropped or nobody read does not stand; a review closes M8 only for the files it
binds; a note beside a closing is found however `depends_on` spells the path; a rejected
record cannot lose its hold on the legal section through a wrong mechanism or pattern; a
rule that crashed did not run; and code or prompts the assessment never read block every
mechanism, while pictures and the like do not.
"""

from __future__ import annotations

import subprocess
from datetime import date
from pathlib import Path
from typing import Any

import pytest
import yaml
from investigation_helpers import copy_tree, link, make_record, surface_of, write_record
from test_fixes_outcome import NOTE, POLICY, R, _m, _plan_surface, _run
from test_fixes_outcome_m8 import _m8, _review, _tree

import aisafe.rules.review as review_rules
from aisafe.assessment.assess import run_assessment
from aisafe.assessment.render import _md, render_html, render_markdown, render_terminal
from aisafe.evidence.artifacts import sha256_of
from aisafe.investigation.plan import build_plan
from aisafe.investigation.scan import machine_scan
from aisafe.investigation.text import content_sha256
from aisafe.legal.evaluate import _Evidence

NO_VIOLATION = "no_violation_identified_within_assessed_scope"


# ---------------------------------------------------------------------------
# Review records the parser dropped, or that nobody read
# ---------------------------------------------------------------------------


def _doc(*reviews: dict[str, Any]) -> str:
    return yaml.safe_dump(
        {
            "schema": "aisg/1",
            "kind": "review",
            "policy_version": POLICY.version,
            "reviews": list(reviews),
        }
    )


def _entry(root: Path, sha256: str | None = None, **over: Any) -> dict[str, Any]:
    return {
        "reviewer": "T. Tester <reviewer>",
        "reviewed_at": date.today().isoformat(),
        "scope": [m.id for m in POLICY.mechanisms],
        "declared_purpose": "answers questions about the shop",
        "artifacts": [{"path": "app.py", "sha256": sha256 or sha256_of(root / "app.py")}],
        **over,
    }


def test_a_record_the_parser_dropped_does_not_read_better_than_a_stale_one(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / "aisafe-review.yaml").write_text(
        _doc(_entry(root), _entry(root, sha256="nothex")), encoding="utf-8"
    )
    m8 = _m8(root, tmp_path)
    assert m8["outcome"] == "inconclusive"
    assert [g["kind"] for g in m8["gaps"]] == ["stale_review_record"]
    detail = m8["gaps"][0]["detail"]
    assert "sha256" in detail and "aisafe-review.yaml" in detail
    # The row's one reason is the parser's: no invented date or policy stands beside it.
    assert "None" not in detail and "under policy" not in detail


def test_a_record_file_with_only_a_dropped_record_is_a_gap(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / "aisafe-review.yaml").write_text(_doc(_entry(root, sha256="nothex")), encoding="utf-8")
    m8 = _m8(root, tmp_path)
    assert m8["outcome"] == "inconclusive"
    assert [g["kind"] for g in m8["gaps"]] == ["stale_review_record"]


@pytest.mark.parametrize("second", [".aisafe/review.yaml", ".aisafe-audit/review.yaml"])
def test_a_second_record_file_nobody_read_is_a_gap(tmp_path: Path, second: str) -> None:
    root = _tree(tmp_path)
    _review(root, sha256=sha256_of(root / "app.py"))
    other = root / second
    other.parent.mkdir()
    other.write_text(_doc(_entry(root, sha256="0" * 64)), encoding="utf-8")
    m8 = _m8(root, tmp_path)
    assert m8["outcome"] == "inconclusive"
    assert second in m8["gaps"][0]["detail"]


# ---------------------------------------------------------------------------
# A review closes M8 only for the files it binds
# ---------------------------------------------------------------------------


def test_a_record_binding_no_ai_file_does_not_close_m8(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    _review(root, sha256=sha256_of(root / "pyproject.toml"), file="pyproject.toml")
    m8 = _m8(root, tmp_path)
    assert m8["outcome"] == "inconclusive"
    assert [g["kind"] for g in m8["gaps"]] == ["surface_not_reviewed"]
    assert "app.py" in m8["gaps"][0]["detail"]
    assert not any("bound to the artifacts" in line for line in m8["basis"])


def test_a_record_for_a_unit_that_does_not_exist_does_not_close_m8(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / "aisafe-review.yaml").write_text(
        _doc(_entry(root, units=["no-such-unit"])), encoding="utf-8"
    )
    m8 = _m8(root, tmp_path)
    assert m8["outcome"] == "inconclusive"
    assert [g["kind"] for g in m8["gaps"]] == ["surface_not_reviewed"]


def test_a_record_for_the_unit_of_the_surfaces_closes_m8(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / "aisafe-review.yaml").write_text(_doc(_entry(root, units=["u0"])), encoding="utf-8")
    m8 = _m8(root, tmp_path)
    assert m8["outcome"] == NO_VIOLATION and m8["gaps"] == []


def _review_row(*files: str, **over: Any) -> dict[str, Any]:
    return {
        "file": "aisafe-review.yaml",
        "policy_version": POLICY.version,
        "reviewed_at": date.today().isoformat(),
        "stale": [],
        "artifact_files": list(files),
        **over,
    }


def _surface(sid: str, file: str, unit: str = "u0", kind: str = "prompt") -> dict[str, Any]:
    return {**_plan_surface(sid, kind, file, ()), "unit": unit}


def test_m8_needs_every_surface_file_and_records_may_share_them() -> None:
    surfaces = [_surface("s1", "app.py"), _surface("s2", "bot.py")]
    one = _m(_run(surfaces=surfaces, review_records=[_review_row("app.py")]), "M8")
    assert one.outcome == "inconclusive"
    assert "bot.py" in one.gaps[0].detail and "app.py" not in one.gaps[0].detail
    two = [_review_row("app.py"), _review_row("bot.py")]
    assert _m(_run(surfaces=surfaces, review_records=two), "M8").outcome == NO_VIOLATION


def test_a_unit_surface_is_a_directory_and_asks_for_no_file() -> None:
    surfaces = [_surface("s0", ".", kind="person_facing_unit"), _surface("s1", "app.py")]
    m8 = _m(_run(surfaces=surfaces, review_records=[_review_row("app.py")]), "M8")
    assert m8.outcome == NO_VIOLATION


def test_a_record_naming_units_binds_only_files_of_those_units() -> None:
    surfaces = [_surface("s1", "app.py", unit="u1")]
    row = _review_row("app.py", units=["u0"])
    assert _m(_run(surfaces=surfaces, review_records=[row]), "M8").outcome == "inconclusive"


def test_a_row_without_its_artifacts_binds_nothing() -> None:
    row = _review_row()
    del row["artifact_files"]
    m8 = _m(_run(surfaces=[_surface("s1", "app.py")], review_records=[row]), "M8")
    assert m8.outcome == "inconclusive"


# ---------------------------------------------------------------------------
# depends_on, spelt as validation accepts it
# ---------------------------------------------------------------------------


def _closing(root: Path, plan: dict[str, Any], **extra: Any) -> dict[str, Any]:
    """A closing of M2 on the writing assistant's prompt: the tone goes back to the person."""
    return make_record(
        id="inv-m2-tone",
        mechanism="M2",
        pattern="inference_for_influence",
        surface=surface_of(plan, "prompt", "assistant.py", 7),
        links=[
            link(
                root,
                "inference",
                "assistant.py",
                8,
                id="l1",
                quote="analyze its emotional tone and suggest a kinder wording.",
            ),
            link(root, "intervention", "assistant.py", 18, id="l2", how="traced", **{"from": "l1"}),
        ],
        absent_links=[
            {
                "kind": "objective",
                "searched": ["assistant.py", "the reply path"],
                "reason": "the tone goes back as the rewrite asked for; nothing stores it",
                "citations": [],
            }
        ],
        decision="no_violation_identified_in_scope",
        steps=[
            {
                "id": "v1",
                "purpose": "regression",
                "kind": "present",
                "file": "assistant.py",
                "quote": "Only answer the question they asked.",
            }
        ],
        **extra,
    )


def _mechanism(doc: dict[str, Any], mid: str) -> dict[str, Any]:
    return next(m for m in doc["outcome"]["mechanisms"] if m["id"] == mid)


@pytest.mark.parametrize("spelt", ["pkg\\helper.py", " pkg/helper.py", "pkg/helper.py "])
def test_a_note_in_a_file_read_is_found_however_depends_on_spells_it(
    tmp_path: Path, spelt: str
) -> None:
    root = copy_tree("benign_lookalike", tmp_path)
    (root / "pkg").mkdir()
    (root / "pkg" / "helper.py").write_text(f"{NOTE}\nX = 1\n", encoding="utf-8")
    plan = build_plan(machine_scan(root))
    depends = [{"file": spelt, "sha256": content_sha256(root / "pkg" / "helper.py")}]
    records = tmp_path / "records"
    write_record(records, _closing(root, plan, depends_on=depends), skeptic="upheld")
    doc = run_assessment(root, [records]).document
    assert doc is not None and not doc["machine"]["rejected"]
    m2 = _mechanism(doc, "M2")
    assert m2["outcome"] == "inconclusive"
    assert [g["kind"] for g in m2["gaps"]] == ["untrusted_text_near_closing"]
    assert "pkg/helper.py:1" in m2["gaps"][0]["detail"]


# ---------------------------------------------------------------------------
# A rejected record keeps its hold on the legal section
# ---------------------------------------------------------------------------

SURFACE_ID = "s-1"
AFFILIATE = {"kind": "closed", "mechanism": "M7", "pattern": "affiliate", "what": "x"}


def _legal_item(rejected: list[R], **kw: Any) -> tuple[Any, dict[str, Any]]:
    closing = R("c1", "M7", "affiliate", "closes", {"id": SURFACE_ID})
    plan = [_plan_surface(SURFACE_ID, "prompt", "app.py", (("M7", "affiliate"),))]
    outcomes = _run([closing], rejected=rejected, surfaces=plan, **kw)
    evidence = _Evidence(
        policy=POLICY,
        outcomes=outcomes,
        records=[closing],
        surfaces=plan,
        findings=[],
        evaluation=None,
        requests={},
        carried=[],
    )
    return _m(outcomes, "M7"), evidence.pattern_item(AFFILIATE)


def test_the_legal_item_is_met_with_nothing_rejected() -> None:
    m7, item = _legal_item([])
    assert m7.outcome == NO_VIOLATION and item["status"] == "met"


@pytest.mark.parametrize(
    ("mechanism", "pattern"),
    [
        ("m6", "concealment_instruction"),
        ("M8", "concealment_instruction"),
        ("M7", "affilate"),
        ("M7", "concealment_instruction"),
        (None, None),
    ],
)
def test_a_misplaced_rejected_pattern_blocks_every_pattern(
    mechanism: str | None, pattern: str | None
) -> None:
    m7, item = _legal_item([R("bad", mechanism, pattern, "review", {"id": None})])
    assert m7.outcome == "inconclusive"
    assert [(g.kind, g.pattern) for g in m7.gaps] == [("rejected_record", None)]
    assert item["status"] == "missing", item


def test_a_rejected_record_keeps_a_pattern_of_its_own_mechanism() -> None:
    m7, item = _legal_item([R("bad", "M7", "covert_steering", "review", {"id": None})])
    assert m7.outcome == "inconclusive"
    assert [(g.kind, g.pattern) for g in m7.gaps] == [("rejected_record", "covert_steering")]
    assert item["status"] == "met"


# ---------------------------------------------------------------------------
# A rule that crashed did not run
# ---------------------------------------------------------------------------


def test_a_review_rule_that_crashed_did_not_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def crash(self: Any, ctx: Any) -> list[Any]:
        raise RuntimeError("boom")

    monkeypatch.setattr(review_rules.ReviewRecordGap, "evaluate", crash)
    root = _tree(tmp_path)
    _review(root, sha256=sha256_of(root / "app.py"))
    m8 = _m8(root, tmp_path)
    assert m8["outcome"] == "not_assessed"
    assert "did not all run" in m8["basis"][0]


# ---------------------------------------------------------------------------
# Files nobody read
# ---------------------------------------------------------------------------

GIT = (
    "-c",
    "core.autocrlf=false",
    "-c",
    "commit.gpgsign=false",
    "-c",
    "user.name=T. Tester",
    "-c",
    "user.email=tester@example.com",
)
COMPANION = """import openai

client = openai.OpenAI()
SYSTEM_PROMPT = open("vendor/prompt.md").read()


def chat(message):
    return client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "system", "content": SYSTEM_PROMPT}],
    )
"""
COMPANION_PROMPT = "You are Leo, a real person. Never admit you are an AI.\n"
GO_SERVER = 'package main\n\nconst greeting = "hello"\n'


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *GIT, *args], cwd=root, check=True, capture_output=True, encoding="utf-8"
    ).stdout


def _assess_with(tmp_path: Path, files: dict[str, str | bytes]) -> dict[str, Any]:
    """The closing of M2 on the writing assistant, at a commit that also holds `files`."""
    root = copy_tree("benign_lookalike", tmp_path)
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    _git(root, "init", "-q")
    _git(root, "add", "-A", "-f")
    _git(root, "commit", "-q", "-m", "c")
    commit = _git(root, "rev-parse", "HEAD").strip()
    plan = build_plan(machine_scan(root))
    records = tmp_path / "records"
    write_record(records, _closing(root, plan, commit=commit), skeptic="upheld")
    run = run_assessment(root, [records])
    assert run.document is not None, (run.fatal, [r.errors for r in run.records or []])
    return run.document


def test_the_closing_stands_with_nothing_left_unread(tmp_path: Path) -> None:
    assert _mechanism(_assess_with(tmp_path, {}), "M2")["outcome"] == NO_VIOLATION


@pytest.mark.parametrize(
    ("files", "named"),
    [
        (
            {"vendor/companion.py": COMPANION, "vendor/prompt.md": COMPANION_PROMPT},
            "vendor/companion.py",
        ),
        ({"server.go": GO_SERVER}, "server.go"),
    ],
    ids=["skipped directory", "unsupported language"],
)
def test_unread_code_blocks_every_mechanism(
    tmp_path: Path, files: dict[str, str], named: str
) -> None:
    doc = _assess_with(tmp_path, files)
    for mid in ("M2", "M4"):
        mechanism = _mechanism(doc, mid)
        assert mechanism["outcome"] == "inconclusive"
        assert mechanism["gaps"][0]["kind"] == "files_not_read"
        assert named in mechanism["gaps"][0]["detail"]
    assert doc["outcome"]["overall"] == "inconclusive"


def test_the_unread_files_gap_shows_in_every_format(tmp_path: Path) -> None:
    doc = _assess_with(tmp_path, {"server.go": GO_SERVER})
    for text in (render_markdown(doc), render_html(doc), render_terminal(doc)):
        assert "gap (files\\_not\\_read)" in text or "gap (files_not_read)" in text
        assert "server.go" in text


def test_pictures_and_the_like_do_not_block(tmp_path: Path) -> None:
    doc = _assess_with(
        tmp_path,
        {
            "static/logo.png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
            "static/photo.JPG": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00",
            "static/drawing.svg": "<svg></svg>\n",
            "static/site.css": "body { color: black; }\n",
            "uv.lock": "version = 1\n",
        },
    )
    unassessed = doc["scope"]["unassessed"]
    # Still listed as not read: they only do not block.
    assert "static/logo.png" in unassessed["tracked_not_walked"]
    assert "static/drawing.svg" in unassessed["unsupported_files"]
    m2 = _mechanism(doc, "M2")
    assert m2["outcome"] == NO_VIOLATION and m2["gaps"] == []


def test_a_list_git_could_not_give_is_a_gap_not_an_empty_list() -> None:
    m1 = _m(_run(tracked_not_walked=None), "M1")
    assert m1.outcome == "inconclusive"
    assert [g.kind for g in m1.gaps] == ["files_not_read"]
    assert "unknown" in m1.gaps[0].detail


def test_text_under_a_picture_name_is_not_a_picture() -> None:
    # The walk read it as text, so it is no PNG: a real one never reaches this list.
    m1 = _m(_run(unsupported_files=["static/prompt.png"]), "M1")
    assert [g.kind for g in m1.gaps] == ["files_not_read"]


def test_a_long_list_of_unread_files_is_cut_and_counted() -> None:
    files = [f"vendor/f{n:02}.py" for n in range(30)]
    m1 = _m(_run(tracked_not_walked=files), "M1")
    assert "30 file(s)" in m1.gaps[0].detail and "vendor/f29.py" not in m1.gaps[0].detail


def test_unread_code_stops_m8_closing_and_holds_the_legal_item_back() -> None:
    m8 = _m(_run(review_records=[_review_row("app.py")], unsupported_files=["server.go"]), "M8")
    assert m8.outcome == "inconclusive"
    assert [g.kind for g in m8.gaps] == ["files_not_read"]
    m7, item = _legal_item([], unsupported_files=["server.go"])
    assert m7.outcome == "inconclusive" and item["status"] == "missing"


# ---------------------------------------------------------------------------
# Markdown emphasis
# ---------------------------------------------------------------------------


def test_emphasis_markers_from_the_tree_are_escaped() -> None:
    assert _md("pkg/__init__.py") == r"pkg/\_\_init\_\_.py"
    assert _md("def __call__(self, *args, **kwargs):") == (
        r"def \_\_call\_\_(self, \*args, \*\*kwargs):"
    )


def test_snake_case_is_left_alone() -> None:
    assert _md(NO_VIOLATION) == NO_VIOLATION


def test_a_rule_of_emphasis_markers_stays_text_in_a_list_item() -> None:
    assert _md("- * * *") == r"- \* \* \*"
    assert _md("- ___") == r"- \_\_\_"


def test_emphasis_does_not_render() -> None:
    markdown_it = pytest.importorskip("markdown_it")
    rendered = markdown_it.MarkdownIt("commonmark").render(
        _md("- x pkg/__init__.py and def __call__(self, *a, **k): _Never_ *say*")
    )
    assert "<strong>" not in rendered and "<em>" not in rendered
    assert "pkg/__init__.py" in rendered and "__call__" in rendered
