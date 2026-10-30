"""tests/unit/test_research_console.py
-----------------------------------
`research/console/console.py` feeds the review console and reads its labels back. These
tests pin the reference half: a reference set holds the sweep's verified lines of one
split and nothing that could unblind the person judging them (no rule finding, no
investigation record, no corpus note, no positive-control flag, no skeptic text), and the
import keeps a person's judgements apart from the finding labels, with the reviewer and
the date, refusing values the policy does not define and an export that would drop
judgements already imported. They also pin that the labelling guides cover the rules
that run.
"""

from __future__ import annotations

import csv
import importlib.util
import json
import sys
from argparse import Namespace
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "research" / "console" / "console.py"


def _load():
    spec = importlib.util.spec_from_file_location("research_console", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules.setdefault("research_console", module)
    spec.loader.exec_module(module)
    return module


console = _load()

SHA_DEV = "a" * 40
SHA_HELD = "b" * 40
SHA_EMPTY = "c" * 40


@pytest.fixture()
def world(tmp_path, monkeypatch):
    """A three-repository corpus (two dev, one held out), a sweep and pinned clones."""
    corpus = tmp_path / "corpus.yaml"
    corpus.write_text(
        yaml.safe_dump(
            {
                "repos": [
                    {
                        "name": "devapp",
                        "repo": "o/devapp",
                        "url": "https://example.invalid/o/devapp.git",
                        "sha": SHA_DEV,
                        "category": "companion",
                        "note": "a corpus note the labeller must not see",
                        "positive_control": True,
                    },
                    {
                        "name": "quiet",
                        "repo": "o/quiet",
                        "url": "https://example.invalid/o/quiet.git",
                        "sha": SHA_EMPTY,
                        "category": "tutor",
                    },
                    {
                        "name": "heldapp",
                        "repo": "o/heldapp",
                        "url": "https://example.invalid/o/heldapp.git",
                        "sha": SHA_HELD,
                        "category": "memory",
                        "split": "heldout",
                        "status": "proposed",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    clones = tmp_path / "clones"
    for name, sha, text in (
        ("devapp", SHA_DEV, "line one\npersona = 'warm'\nline three\n"),
        ("heldapp", SHA_HELD, "a\nb\nremember(user)\n"),
        ("quiet", SHA_EMPTY, "nothing\n"),
    ):
        (clones / name).mkdir(parents=True)
        (clones / name / ".aisafe-bench-sha").write_text(sha, encoding="utf-8")
        (clones / name / "app.py").write_text(text, encoding="utf-8")
    skeptic = {"refuted": False, "location": "prompt", "reason": "skeptic text, not shown"}
    sweep = {
        "swept": "test",
        "method": "test",
        "repos": {
            "devapp": {
                "summary": "an agent's summary, not shown",
                "evidence": [
                    {
                        "behaviour": "disclosure",
                        "kind": "designed_in",
                        "file": "app.py",
                        "line": 2,
                        "quote": "persona = 'warm'",
                        "why": "the sweep's reason",
                        "status": "verified",
                        "skeptics": [skeptic, skeptic],
                        "pass": "pass1",
                    },
                    {
                        "behaviour": "memory",
                        "kind": "designed_in",
                        "file": "app.py",
                        "line": 3,
                        "quote": "line three",
                        "why": "refuted line",
                        "status": "refuted",
                        "skeptics": [skeptic],
                        "pass": "pass1",
                    },
                    {
                        "behaviour": "crisis",
                        "kind": "present_control",
                        "file": "app.py",
                        "line": 1,
                        "quote": "line one",
                        "why": "unverified line",
                        "status": "unverified",
                        "skeptics": [],
                        "pass": "pass2",
                    },
                ],
            },
            "heldapp": {
                "summary": "held",
                "evidence": [
                    {
                        "behaviour": "memory",
                        "kind": "designed_in",
                        "file": "app.py",
                        "line": 3,
                        "quote": "remember(user)",
                        "why": "held reason",
                        "status": "verified",
                        "skeptics": [skeptic, skeptic],
                        "pass": "pass1",
                    }
                ],
            },
        },
    }
    sweep_path = tmp_path / "sweep.json"
    sweep_path.write_text(json.dumps(sweep), encoding="utf-8")
    build = tmp_path / "build"
    build.mkdir()
    (build / "manifest.json").write_text(
        json.dumps({"sets": [{"id": "run4", "file": "sets/run4.json"}], "docs": []}),
        encoding="utf-8",
    )
    monkeypatch.setattr(console, "CORPUS", corpus)
    monkeypatch.setattr(console, "CLONES", clones)
    monkeypatch.setattr(console, "SWEEP", sweep_path)
    monkeypatch.setattr(console, "BUILD", build)
    return tmp_path


def _build(split: str, set_id: str) -> dict:
    args = Namespace(set=set_id, split=split, title="t", about="a")
    assert console.build_reference(args) == 0
    return json.loads((console.BUILD / "references" / f"{set_id}.json").read_text("utf-8"))


def _export(root: Path, set_id: str, labels: dict, added: dict) -> Path:
    for folder, docs in (("labels", labels), ("added", added)):
        target = root / "reference" / set_id / folder
        target.mkdir(parents=True, exist_ok=True)
        for doc_id, body in docs.items():
            (target / f"{doc_id}.json").write_text(json.dumps(body), encoding="utf-8")
    return root


def _import(world: Path, set_id: str, export: Path, partial: bool = False) -> int:
    args = Namespace(set=set_id, labels=export, out=world / "reference", partial=partial)
    return console.import_reference(args)


def _rows(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# ---------------------------------------------------------------------------
# build-reference
# ---------------------------------------------------------------------------


def test_reference_item_ids_are_stable_and_keyed_on_the_claim() -> None:
    one = console.ref_item_id("r", "f.py", 3, "memory", "designed_in")
    assert one == console.ref_item_id("r", "f.py", "3", "memory", "designed_in")
    assert one != console.ref_item_id("r", "f.py", 3, "memory", "present_control")
    assert one != console.ref_item_id("r", "f.py", 3, "crisis", "designed_in")
    # A finding label's id and a reference id never coincide for the same place.
    assert one != console.item_id("r", "f.py", 3, "memory", "designed_in")


def test_reference_set_holds_only_verified_lines_of_its_split(world) -> None:
    doc = _build("dev", "ref-dev")
    assert doc["kind"] == "reference" and doc["split"] == "dev"
    assert [(it["repo"], it["line"]) for it in doc["items"]] == [("devapp", 2)]
    # Every repository of the split is listed, the ones with no verified line too, so
    # the person can still add the places the sweep missed there.
    assert set(doc["repos"]) == {"devapp", "quiet"}
    assert doc["repos"]["quiet"]["lines"] == 0
    held = _build("heldout", "ref-heldout")
    assert [it["repo"] for it in held["items"]] == ["heldapp"]
    assert set(held["repos"]) == {"heldapp"}


def test_reference_set_carries_nothing_that_unblinds(world) -> None:
    doc = _build("dev", "ref-dev")
    text = json.dumps(doc)
    for absent in (
        "a corpus note the labeller must not see",
        "skeptic text, not shown",
        "an agent's summary, not shown",
        "positive_control",
        "fingerprint",
        "rule_id",
        "AUD-",
        "investigation",
    ):
        assert absent not in text, absent
    item = doc["items"][0]
    assert item["claim"] == "This line designs the behaviour in: AI disclosure or concealment."
    assert item["context"]["hit"] == 2
    assert "persona = 'warm'" in item["context"]["lines"][1]
    assert item["link"].endswith("/blob/" + SHA_DEV + "/app.py#L2")
    assert [m["id"] for m in doc["mechanisms"]] == [f"M{n}" for n in range(1, 9)]


def test_reference_sets_join_the_manifest_without_touching_finding_sets(world) -> None:
    _build("dev", "ref-dev")
    _build("heldout", "ref-heldout")
    _build("dev", "ref-dev")  # rebuilt: replaced, not duplicated
    manifest = json.loads((console.BUILD / "manifest.json").read_text("utf-8"))
    assert [s["id"] for s in manifest["sets"]] == ["run4"]
    assert sorted(r["id"] for r in manifest["references"]) == ["ref-dev", "ref-heldout"]
    assert {r["id"]: r["split"] for r in manifest["references"]} == {
        "ref-dev": "dev",
        "ref-heldout": "heldout",
    }


def test_an_unknown_split_in_the_corpus_is_refused(world) -> None:
    data = yaml.safe_load(console.CORPUS.read_text("utf-8"))
    data["repos"][0]["split"] = "test"
    console.CORPUS.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(SystemExit):
        _build("dev", "ref-dev")


# ---------------------------------------------------------------------------
# import-reference
# ---------------------------------------------------------------------------


def _label(verdict: str, **kw) -> dict:
    body = {
        "verdict": verdict,
        "mechanism": "",
        "control": "",
        "note": "",
        "at": "2026-10-30T10:00:00Z",
        "by": "u-1",
        "reviewer": "J. Doe",
        "set": "ref-dev",
    }
    body.update(kw)
    return body


def test_import_writes_judgements_and_added_places_with_reviewer_and_date(world) -> None:
    doc = _build("dev", "ref-dev")
    item = doc["items"][0]["id"]
    export = _export(
        world / "export",
        "ref-dev",
        {item: _label("confirm", mechanism="M6", note="it denies being an AI")},
        {
            "a-1": {
                "repo": "quiet",
                "file": "app.py",
                "line": 1,
                "kind": "designed_in",
                "mechanism": "M4",
                "control": "",
                "note": "a place the sweep missed",
                "at": "2026-10-30T11:00:00Z",
                "by": "u-1",
                "reviewer": "J. Doe",
                "set": "ref-dev",
            }
        },
    )
    assert _import(world, "ref-dev", export) == 0
    rows = _rows(world / "reference" / "ref-dev-labels.csv")
    assert rows == [
        {
            "set": "ref-dev",
            "item_id": item,
            "repo": "devapp",
            "file": "app.py",
            "line": "2",
            "behaviour": "disclosure",
            "sweep_kind": "designed_in",
            "verdict": "confirm",
            "mechanism": "M6",
            "control": "",
            "note": "it denies being an AI",
            "reviewer": "J. Doe",
            "by": "u-1",
            "labelled_at": "2026-10-30T10:00:00Z",
        }
    ]
    added = _rows(world / "reference" / "ref-dev-added.csv")
    assert [(a["repo"], a["file"], a["line"], a["mechanism"]) for a in added] == [
        ("quiet", "app.py", "1", "M4")
    ]


def test_import_reads_a_single_json_export_too(world) -> None:
    doc = _build("dev", "ref-dev")
    item = doc["items"][0]["id"]
    export = world / "export.json"
    export.write_text(
        json.dumps(
            [
                {"id": f"reference/ref-dev/labels/{item}", "data": _label("reject")},
                {"id": "sets/run4/labels/0123456789abcdef", "data": {"verdict": "tp"}},
            ]
        ),
        encoding="utf-8",
    )
    assert _import(world, "ref-dev", export) == 0
    rows = _rows(world / "reference" / "ref-dev-labels.csv")
    assert [r["verdict"] for r in rows] == ["reject"]


@pytest.mark.parametrize(
    "body",
    [
        _label("tp"),
        _label("confirm", mechanism="M9"),
        _label("confirm", set="ref-heldout"),
    ],
    ids=["finding-verdict", "unknown-mechanism", "other-set"],
)
def test_import_refuses_values_the_set_does_not_define(world, body, capsys) -> None:
    doc = _build("dev", "ref-dev")
    export = _export(world / "export", "ref-dev", {doc["items"][0]["id"]: body}, {})
    assert _import(world, "ref-dev", export) == 1
    assert "ERROR" in capsys.readouterr().out
    assert not (world / "reference" / "ref-dev-labels.csv").exists()


def test_import_refuses_an_added_place_outside_the_set(world) -> None:
    _build("dev", "ref-dev")
    export = _export(
        world / "export",
        "ref-dev",
        {},
        {"a-1": {"repo": "heldapp", "file": "app.py", "line": 3, "mechanism": "M1"}},
    )
    assert _import(world, "ref-dev", export) == 1


def test_import_refuses_an_export_that_drops_imported_judgements(world) -> None:
    doc = _build("dev", "ref-dev")
    item = doc["items"][0]["id"]
    full = _export(world / "full", "ref-dev", {item: _label("unclear")}, {})
    assert _import(world, "ref-dev", full) == 0
    empty = _export(world / "empty", "ref-dev", {}, {})
    assert _import(world, "ref-dev", empty) == 1
    assert _import(world, "ref-dev", empty, partial=True) == 0


def test_import_needs_the_built_set(world) -> None:
    export = _export(world / "export", "ref-dev", {}, {})
    assert _import(world, "ref-dev", export) == 1


def test_a_confirmed_line_without_a_name_is_reported_not_filled_in(world, capsys) -> None:
    doc = _build("dev", "ref-dev")
    item = doc["items"][0]["id"]
    export = _export(world / "export", "ref-dev", {item: _label("confirm")}, {})
    assert _import(world, "ref-dev", export) == 0
    assert "name no mechanism and no control" in capsys.readouterr().out
    row = _rows(world / "reference" / "ref-dev-labels.csv")[0]
    assert row["mechanism"] == "" and row["control"] == ""


# ---------------------------------------------------------------------------
# guides
# ---------------------------------------------------------------------------


def test_every_rule_that_runs_has_a_labelling_guide() -> None:
    from aisafe.rules import ALL_RULES

    assert {rule.id for rule in ALL_RULES} == set(console.GUIDES)
    for rule_id, guide in console.GUIDES.items():
        assert guide.get("question"), rule_id
        for sub, extra in guide.get("subs", {}).items():
            assert extra.get("question"), f"{rule_id}/{sub}"
