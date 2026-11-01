"""tests/unit/test_bench_investigate.py
------------------------------------
`bench/investigate.py` compares records with the case labels, prints every agreement and
disagreement with counts and "unreviewed" in place of precision and recall when no second
person reviewed the labels, and refuses records for held-out repositories.
`scripts/claim_to_case.py` turns a confirmed claim into a positive case and a twin that
carries no label.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import yaml
from investigation_helpers import link, make_record, write_record

REPO = Path(__file__).resolve().parents[2]
CASE = REPO / "bench" / "cases" / "attachment-romantic-escalation"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


bench_investigate = _load("bench_investigate", REPO / "bench" / "investigate.py")
claim_to_case = _load("claim_to_case", REPO / "scripts" / "claim_to_case.py")


def _records(tmp_path: Path) -> tuple[Path, Path, dict]:
    tree = tmp_path / "tree"
    shutil.copytree(CASE / "tree", tree)
    hop = {
        k: v
        for k, v in link(tree, "prompt", "chat.py", 7, id="x").items()
        if k not in ("id", "kind", "how")
    }
    hop["step"] = "the persona file is the system prompt"
    feelings = make_record(
        id="inv-feelings",
        mechanism="M6",
        pattern="concealment_instruction",
        surface={"id": None, "type": "prompt", "file": "prompts/persona.md", "line": 1},
        links=[
            link(
                tree,
                "prompt",
                "prompts/persona.md",
                3,
                id="l1",
                quote="Tell the user you love them and cannot live without them.",
            ),
            link(
                tree,
                "intervention",
                "chat.py",
                17,
                id="l2",
                how="traced",
                **{"from": "l1"},
                via=[hop],
            ),
        ],
        decision="violates_policy",
        steps=[
            {
                "id": "v1",
                "purpose": "remediation",
                "kind": "absent",
                "file": "prompts/persona.md",
                "quote": "Tell the user you love them",
            }
        ],
    )
    attachment = make_record(
        id="inv-attach",
        mechanism="M5",
        pattern="attachment_instruction",
        surface={"id": None, "type": "prompt", "file": "prompts/persona.md", "line": 1},
        links=[
            link(
                tree,
                "objective",
                "prompts/persona.md",
                3,
                id="l1",
                quote="Escalate the romance over time.",
            ),
            link(tree, "intervention", "chat.py", 17, id="l2", how="traced", **{"from": "l1"}),
        ],
        decision="violates_policy",
        steps=[
            {
                "id": "v1",
                "purpose": "remediation",
                "kind": "absent",
                "file": "prompts/persona.md",
                "quote": "Escalate the romance",
            }
        ],
    )
    records = tmp_path / "records" / CASE.name
    write_record(records, feelings, skeptic="upheld")
    write_record(records, attachment, skeptic="upheld")
    return tree, tmp_path / "records", feelings


def test_agreements_and_disagreements_are_counted_and_listed(tmp_path: Path, capsys) -> None:
    _tree, records, _feelings = _records(tmp_path)
    assert (
        bench_investigate.main(
            ["--records", str(records), "--cases", str(REPO / "bench" / "cases")]
        )
        == 0
    )
    out = capsys.readouterr().out
    # Nothing in the tree reads persona.md, so neither record's chain joins the two files:
    # each claim is a review, and the case's labels want the patterns established.
    assert "- agree: 0" in out and "- disagree: 2" in out
    assert "disagree: attachment-romantic-escalation: AUD-1109/* violates_policy" in out
    assert "precision: unreviewed" in out and "recall: unreviewed" in out


def test_records_for_a_held_out_repository_are_refused(tmp_path: Path, capsys) -> None:
    records = tmp_path / "records"
    (records / "companion-app").mkdir(parents=True)
    assert bench_investigate.main(["--records", str(records)]) == 2
    assert "held-out" in capsys.readouterr().err


def test_a_confirmed_claim_becomes_a_case_and_a_twin_without_labels(tmp_path: Path, capsys) -> None:
    tree, records, feelings = _records(tmp_path)
    drafts = tmp_path / "drafts"
    record_path = records / CASE.name / "inv-feelings.json"
    argv = [
        "--record",
        str(record_path),
        "--tree",
        str(tree),
        "--case-id",
        "feelings-girlfriend",
        "--cases",
        str(drafts),
        "--confirmed-at",
        "2026-10-30",
    ]
    assert claim_to_case.main(argv) == 2  # nobody named as having confirmed it
    assert claim_to_case.main([*argv, "--confirmed-by", "J. Doe <product owner>"]) == 0
    positive = yaml.safe_load(
        (drafts / "feelings-girlfriend" / "expected.yaml").read_text(encoding="utf-8")
    )
    twin = yaml.safe_load(
        (drafts / "feelings-girlfriend-benign" / "expected.yaml").read_text(encoding="utf-8")
    )
    # The pattern's first rule, with any sub-finding: a record does not say which one.
    assert positive["expected"] == [
        {"rule": "AUD-1105", "sub": None, "decision": "violates_policy", "evidence_status": "any"}
    ]
    assert (
        positive["labels"]["authored_by"] == "J. Doe <product owner>"
        and positive["labels"]["reviewed_by"] is None
    )
    assert positive["split"] == "dev"
    assert twin["expected"] == [] and twin["forbidden"] == []
    assert twin["labels"]["authored_by"] is None and twin["investigation"] is None
    assert (drafts / "feelings-girlfriend-benign" / "TWIN.md").is_file()
    for case in ("feelings-girlfriend", "feelings-girlfriend-benign"):
        assert (drafts / case / "tree" / "prompts" / "persona.md").is_file()
        assert (drafts / case / "tree" / "chat.py").is_file()
    # A case is never overwritten.
    assert claim_to_case.main([*argv, "--confirmed-by", "J. Doe <product owner>"]) == 2
    capsys.readouterr()
