"""
tests/unit/test_bench_sampling.py
---------------------------------
Tests for the benchmark harness: bench/run.py's audit-report flattening and
stratified sampling, and bench/score.py's two modes (the hand-labelled CSV and the
synthetic cases of bench/protocol.md).

Sampling must hold three properties, or labelling work is lost:

  1. Deterministic -- a re-run must not invalidate labelling already done.
  2. Nested -- a smaller cap must be a subset of a larger one, so changing the
     cap never orphans a row someone already labelled.
  3. Spread across repos -- otherwise a rule's "precision" is really one
     codebase's idiosyncrasies.
"""

from __future__ import annotations

import csv
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

BENCH = Path(__file__).resolve().parents[2] / "bench"


def _load(name: str, filename: str):
    """bench/ is a script directory, not a package."""
    spec = importlib.util.spec_from_file_location(name, BENCH / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


run = _load("bench_run", "run.py")
score = _load("bench_score", "score.py")


def make_rows(spec: dict[str, dict[str, int]]) -> list[dict]:
    """spec: {rule_id: {repo: how_many}}, in the audit CSV's columns."""
    rows = []
    for rule, repos in spec.items():
        for repo, n in repos.items():
            for i in range(n):
                rows.append(
                    {
                        "repo": repo,
                        "file": f"src/mod{i // 10}.py",
                        "line": str(i),
                        "rule_id": rule,
                        "sub": "",
                        "decision": "requires_contextual_review",
                        "evidence_status": "detected_signal",
                        "message": "x",
                        "snippet": f"x = {i}",
                        "verdict": "",
                    }
                )
    return rows


def key(row: dict) -> tuple:
    return (row["repo"], row["file"], row["line"], row["rule_id"])


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=run.AUDIT_CSV_COLUMNS)
        w.writeheader()
        w.writerows(rows)


class TestSamplePerRule:
    def test_zero_disables_sampling(self):
        rows = make_rows({"R1": {"a": 50}})
        assert len(run.sample_per_rule(rows, 0)) == 50

    def test_negative_disables_sampling(self):
        rows = make_rows({"R1": {"a": 50}})
        assert len(run.sample_per_rule(rows, -1)) == 50

    def test_caps_each_rule_independently(self):
        rows = make_rows({"R1": {"a": 100}, "R2": {"a": 5}})
        out = run.sample_per_rule(rows, 10)
        counts = {r: sum(1 for x in out if x["rule_id"] == r) for r in ("R1", "R2")}
        assert counts == {"R1": 10, "R2": 5}, "a thin rule must keep everything it has"

    def test_deterministic(self):
        rows = make_rows({"R1": {"a": 60, "b": 40, "c": 20}})
        first = [key(r) for r in run.sample_per_rule(list(rows), 30)]
        for _ in range(4):
            assert [key(r) for r in run.sample_per_rule(list(rows), 30)] == first

    def test_smaller_cap_is_a_subset_of_larger(self):
        """Tightening the cap must not orphan an already-labelled row."""
        rows = make_rows({"R1": {"a": 60, "b": 40}, "R2": {"a": 30}})
        small = {key(r) for r in run.sample_per_rule(list(rows), 10)}
        large = {key(r) for r in run.sample_per_rule(list(rows), 25)}
        assert small <= large

    def test_spreads_across_repos(self):
        """
        Taking the first N would draw every finding from whichever repo sorts
        first, and call one codebase's quirks the rule's precision.
        """
        rows = make_rows({"R1": {"aaa": 100, "bbb": 100, "ccc": 100}})
        out = run.sample_per_rule(rows, 30)
        per_repo = {r: sum(1 for x in out if x["repo"] == r) for r in ("aaa", "bbb", "ccc")}
        assert per_repo == {"aaa": 10, "bbb": 10, "ccc": 10}

    def test_uneven_repos_still_fill_the_quota(self):
        """One repo running dry must not leave the quota short."""
        rows = make_rows({"R1": {"aaa": 2, "bbb": 100}})
        out = run.sample_per_rule(rows, 20)
        assert len(out) == 20
        assert sum(1 for x in out if x["repo"] == "aaa") == 2

    def test_quota_larger_than_available(self):
        rows = make_rows({"R1": {"a": 3, "b": 4}})
        assert len(run.sample_per_rule(rows, 100)) == 7

    def test_empty_input(self):
        assert run.sample_per_rule([], 10) == []

    def test_preserves_row_contents(self):
        rows = make_rows({"R1": {"a": 5}})
        out = run.sample_per_rule(rows, 3)
        for r in out:
            assert set(r) == set(run.AUDIT_CSV_COLUMNS)

    def test_verdicts_survive_sampling(self):
        rows = make_rows({"R1": {"a": 10}})
        rows[0]["verdict"] = "tp"
        out = run.sample_per_rule(rows, 10)
        assert any(r["verdict"] == "tp" for r in out)

    def test_extra_columns_never_change_the_draw(self):
        """The draw keys on rule, repo, file and line only."""
        rows = make_rows({"AUD-1104": {"a": 60, "b": 40}, "AUD-1109": {"a": 30}})
        first = [key(r) for r in run.sample_per_rule(list(rows), 30)]
        for r in rows:
            r["decision"] = "violates_policy"
            r["evidence_status"] = "supported_mechanism"
        assert [key(r) for r in run.sample_per_rule(list(rows), 30)] == first
        small = {key(r) for r in run.sample_per_rule(list(rows), 10)}
        large = {key(r) for r in run.sample_per_rule(list(rows), 25)}
        assert small <= large


# A report as `aisafe audit --format json` writes it, reduced to the keys the runner reads.
REPORT = {
    "schema": "aisg/1",
    "kind": "audit",
    "findings": [
        {
            "id": "AUD-1104/outreach-personalised",
            "rule_id": "AUD-1104",
            "sub": "outreach-personalised",
            "title": "Engagement, retention, spend or experimentation objective",
            "severity": "high",
            "evidence_status": "supported_mechanism",
            "decision": "violates_policy",
            "evidence": [
                {
                    "role": "match",
                    "file": "app\\nudges.py",
                    "line": 12,
                    "snippet": "  send_push(user,   text)\n",
                },
                {"role": "also", "file": "app/nudges.py", "line": 40, "snippet": "x"},
            ],
        },
        {
            "id": "AUD-1107/missing",
            "rule_id": "AUD-1107",
            "sub": "missing",
            "title": "Review record missing, stale or unbound",
            "severity": "low",
            "evidence_status": "detected_signal",
            "decision": "requires_contextual_review",
            "evidence": [{"role": "absence", "file": ".", "line": 0, "snippet": "no record"}],
        },
        {
            "id": "AUD-1105",
            "rule_id": "AUD-1105",
            "sub": None,
            "title": "False human identity or fabricated feelings",
            "severity": "high",
            "evidence_status": "detected_signal",
            "decision": "requires_contextual_review",
            "evidence": [],
        },
    ],
}


class TestAuditRunner:
    """The runner knows one tool, the audit, and flattens its JSON report."""

    def test_audit_is_the_only_tool_and_the_columns_are_pinned(self, tmp_path: Path):
        assert run.TOOLS == ("audit",)
        assert run.AUDIT_CSV_COLUMNS == [
            "repo",
            "file",
            "line",
            "rule_id",
            "sub",
            "decision",
            "evidence_status",
            "message",
            "snippet",
            "verdict",
        ]
        results, sampled, full, columns = run.paths_for("audit", tmp_path)
        assert columns is run.AUDIT_CSV_COLUMNS
        assert (results, sampled, full) == (
            tmp_path / "results-audit",
            tmp_path / "findings-audit.csv",
            tmp_path / "findings-audit-all.csv",
        )
        with pytest.raises(ValueError):
            run.paths_for("lint")

    def test_child_command_is_the_audit_with_no_external_tools(self, tmp_path: Path):
        argv = run.audit_argv(tmp_path / "r.json", rules="AUD-1104,AUD-1109", experimental=True)
        assert argv[1:5] == ["-m", "aisafe.cli", "audit", "."]
        assert argv[argv.index("--format") + 1] == "json"
        assert argv[argv.index("--fail-on") + 1] == "never"
        assert argv[argv.index("-o") + 1] == str((tmp_path / "r.json").resolve())
        assert argv[argv.index("--rules") + 1] == "AUD-1104,AUD-1109"
        assert "--experimental" in argv
        assert "--no-external" not in argv
        assert "lint" not in argv
        plain = run.audit_argv(tmp_path / "r.json")
        assert "--rules" not in plain and "--experimental" not in plain

    def test_rows_from_audit_json_flatten_the_first_evidence_leg(self, tmp_path: Path):
        jf = tmp_path / "companion.json"
        jf.write_text(json.dumps(REPORT), encoding="utf-8")
        rows = run.rows_from_audit_json("companion", jf)
        assert len(rows) == 3
        for row in rows:
            assert set(row) == set(run.AUDIT_CSV_COLUMNS)
            assert row["repo"] == "companion" and row["verdict"] == ""
            assert "/" not in row["rule_id"]  # the parent rule, never `AUD-1104/outreach`
        first, absence, bare = rows
        assert first["rule_id"] == "AUD-1104" and first["sub"] == "outreach-personalised"
        assert first["decision"] == "violates_policy"
        assert first["evidence_status"] == "supported_mechanism"
        assert first["file"] == "app/nudges.py" and first["line"] == 12
        assert first["snippet"] == "send_push(user, text)"
        assert first["message"].startswith("Engagement")
        assert absence["file"] == "." and absence["line"] == 0
        assert absence["decision"] == "requires_contextual_review"
        assert bare["sub"] == "" and bare["file"] == "" and bare["line"] == ""

    def test_rows_from_a_missing_or_broken_report_are_empty(self, tmp_path: Path):
        assert run.rows_from_audit_json("x", tmp_path / "none.json") == []
        broken = tmp_path / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        assert run.rows_from_audit_json("x", broken) == []

    def test_merge_preserving_verdicts_takes_a_path(self, tmp_path: Path):
        rows = make_rows({"AUD-1104": {"a": 2}})
        rows[0]["verdict"] = "fp"
        path = tmp_path / "findings-audit.csv"
        write_csv(path, rows)
        fresh = make_rows({"AUD-1104": {"a": 2}})
        merged = run.merge_preserving_verdicts(fresh, path)
        assert [r["verdict"] for r in merged] == ["fp", ""]


class TestScoreLabels:
    """`score.py --tool audit` refuses a partly labelled CSV and reports the rest."""

    def test_refuses_a_partly_labelled_csv_then_scores_a_full_one(self, tmp_path: Path):
        rows = make_rows({"AUD-1104": {"a": 3}})
        rows[0]["verdict"] = "tp"
        path = tmp_path / "findings-audit.csv"
        write_csv(path, rows)
        out = tmp_path / "precision-audit.md"
        argv = [
            sys.executable,
            str(BENCH / "score.py"),
            "--tool",
            "audit",
            "--csv",
            str(path),
            "--results",
            str(tmp_path / "none"),
            "--out",
            str(out),
        ]
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False)
        assert proc.returncode == 1
        assert "2 of 3 findings are unlabelled" in proc.stderr
        assert not out.exists()

        for r in rows:
            r["verdict"] = r["verdict"] or "fp"
        write_csv(path, rows)
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False)
        assert proc.returncode == 0, proc.stderr
        text = out.read_text(encoding="utf-8")
        assert text.startswith("# aisafe audit rule precision")
        assert "measured_precision = 0.333" in text
        assert "# AUD-1104" in text and "1/3 judged findings were true positives" in text
        assert "`aisafe audit --experimental`" in text
        # The worst-fp section shows what the audit itself said about the finding.
        assert "**Audit said:** decision `requires_contextual_review`" in text
        assert "evidence status `detected_signal`" in text
        assert "lint" not in text

    def test_cases_and_csv_flags_do_not_mix(self, tmp_path: Path):
        with pytest.raises(SystemExit):
            score.main(["--cases", str(tmp_path), "--csv", str(tmp_path / "x.csv")])


# ---------------------------------------------------------------------------
# `score.py --cases`: the synthetic corpus, scored with a stub rule registry
# ---------------------------------------------------------------------------


def _stub_registry() -> list[type]:
    """One rule that fires `AUD-9901/stub` (violates, supported) on a file named fire.py."""
    from aisafe import rules
    from aisafe.evidence.model import (
        Basis,
        Decision,
        EvidenceKind,
        EvidenceStatus,
        MatchKind,
        Recommendation,
        Severity,
        Tier,
    )

    class StubRule(rules.AuditRule):
        id = "AUD-9901"
        title = "Stub: a file named fire.py"
        severity = Severity.HIGH
        basis = Basis.PRESENCE
        evidence_kind = EvidenceKind.CODE
        match_kind = MatchKind.GREP
        default_evidence_status = EvidenceStatus.SUPPORTED_MECHANISM
        default_decision = Decision.VIOLATES
        tier = Tier.T1
        recommendation = Recommendation(
            tier=Tier.T1,
            summary="delete fire.py",
            alternatives=("a", "b", "c"),
            removes=("objective",),
        )
        known_failure_modes = ("a file named fire.py that is not on fire",)
        references = ("EU:Art.5(1)(a)",)

        def evaluate(self, ctx):
            return [
                self.finding(ctx, file=f.relpath, line=1, snippet="fire", sub="stub")
                for f in ctx.files
                if f.relpath.endswith("fire.py")
            ]

    return [StubRule]


def write_case(
    root: Path,
    case_id: str,
    *,
    expected: list[dict],
    forbidden: list[dict],
    split: str = "dev",
    reviewed_by: str | None = None,
    fire: bool = True,
    expected_unknown: tuple[str, ...] = (),
    disagreement: str | None = None,
) -> Path:
    case = root / case_id
    (case / "tree").mkdir(parents=True)
    if fire:
        (case / "tree" / "fire.py").write_text("# fire\n", encoding="utf-8")
    else:
        (case / "tree" / "quiet.py").write_text("# quiet\n", encoding="utf-8")
    spec = {
        "schema": "aisg/1",
        "kind": "bench-case",
        "id": case_id,
        "pair": 1,
        "split": split,
        "description": "a synthetic case",
        "policy_version": "1.0.0",
        "expected": expected,
        "forbidden": forbidden,
        "expected_unknown": list(expected_unknown),
        "labels": {
            "authored_by": "the test",
            "authored_at": "2026-10-29",
            "reviewed_by": reviewed_by,
            "reviewed_at": None,
            "disagreement": disagreement,
        },
    }
    (case / "expected.yaml").write_text(yaml.safe_dump(spec, sort_keys=False), encoding="utf-8")
    return case


@pytest.fixture
def stub_rules(monkeypatch):
    import aisafe.rules as rules_mod

    monkeypatch.setattr(rules_mod, "ALL_RULES", _stub_registry())
    monkeypatch.setattr(rules_mod, "MISSING_RULE_MODULES", [])
    return rules_mod.ALL_RULES


OWED = {
    "rule": "AUD-9901",
    "sub": "stub",
    "decision": "violates_policy",
    "evidence_status": "any",
}


class TestScoreCases:
    def test_two_cases_count_tp_fp_fn_and_say_the_labels_are_unreviewed(
        self, tmp_path: Path, stub_rules
    ):
        root = tmp_path / "cases"
        # One expected finding reported (tp) plus one owed by a rule that never fires (fn).
        write_case(
            root,
            "a-owed",
            expected=[OWED, {"rule": "AUD-9902", "decision": "requires_contextual_review"}],
            forbidden=[],
        )
        # One forbidden finding reported (fp).
        write_case(root, "b-forbidden", expected=[], forbidden=[{"rule": "AUD-9901"}])
        out = tmp_path / "cases-score.md"

        assert score.main(["--cases", str(root), "--out", str(out)]) == 0
        text = out.read_text(encoding="utf-8")

        assert "No reviewed cases: every number below is from unreviewed labels" in text
        assert "Rules run: `AUD-9901` v1" in text
        assert "| `AUD-9901/stub` | 1 | 1 | 0 | 0.500 (1/2) | 1.000 (1/1) |" in text
        assert "| `AUD-9902/*` | 0 | 0 | 1 | n/a (0/0) | 0.000 (0/1) |" in text
        # The per-rule roll-up carries the same counts.
        assert "| `AUD-9901` | 1 | 1 | 0 | 0.500 (1/2) | 1.000 (1/1) |" in text
        # Every mismatch verbatim: case, rule, expected, got.
        assert (
            "| `a-owed` | `AUD-9902/*` | fn | AUD-9902/* requires_contextual_review | absent |"
            in text
        )
        assert (
            "| `b-forbidden` | `AUD-9901/stub` | fp | not AUD-9901/* (forbidden) "
            "| AUD-9901/stub violates_policy (supported_mechanism) at fire.py:1 |" in text
        )
        assert "| `a-owed` | dev | 1 | no | 2 | 0 | 1 | 0 | 1 |" in text
        assert "| `b-forbidden` | dev | 1 | no | 0 | 1 | 0 | 1 | 0 |" in text
        assert text.isascii()

    def test_reviewed_cases_make_the_headline_and_splits_stay_apart(
        self, tmp_path: Path, stub_rules
    ):
        root = tmp_path / "cases"
        write_case(
            root,
            "held",
            expected=[OWED],
            forbidden=[],
            split="heldout",
            reviewed_by="A. Reviewer <second person>",
        )
        write_case(root, "draft", expected=[OWED], forbidden=[], split="dev")
        out = tmp_path / "score.md"
        assert score.main(["--cases", str(root), "--out", str(out)]) == 0
        text = out.read_text(encoding="utf-8")
        assert "No reviewed cases" not in text
        assert "Reviewed cases only (1" in text
        headline, drafts = text.split("## Unreviewed cases (drafts, not in the headline)")
        assert "### dev (0 cases)" in headline and "### heldout (1 case)" in headline
        assert "### dev (1 case)" in drafts and "### heldout (0 cases)" in drafts
        assert headline.count("| `AUD-9901/stub` | 1 | 0 | 0 | 1.000 (1/1) | 1.000 (1/1) |") == 1
        assert "| `held` | heldout | 1 | yes | 1 | 0 | 1 | 0 | 0 |" in text

    def test_a_stronger_decision_than_labelled_is_a_listed_mismatch(
        self, tmp_path: Path, stub_rules
    ):
        root = tmp_path / "cases"
        milder = dict(OWED, decision="requires_contextual_review")
        write_case(root, "over", expected=[milder], forbidden=[])
        out = tmp_path / "score.md"
        assert score.main(["--cases", str(root), "--out", str(out)]) == 0
        text = out.read_text(encoding="utf-8")
        assert "| `AUD-9901/stub` | 0 | 0 | 1 | n/a (0/0) | 0.000 (0/1) |" in text
        assert "[stronger decision]" in text

    def test_expected_unknown_and_unlabelled_findings_are_listed_not_counted(
        self, tmp_path: Path, stub_rules
    ):
        root = tmp_path / "cases"
        # The stub fires, but the only label is for another rule: the finding is listed
        # under "Reported but not labelled" and counts nowhere. No UNKNOWN item is
        # raised for a one-file Python tree, so the expected category is reported absent.
        write_case(
            root,
            "loose",
            expected=[{"rule": "AUD-9902", "decision": "any"}],
            forbidden=[],
            expected_unknown=("reports",),
            disagreement="author and reviewer disagree on the sub",
        )
        out = tmp_path / "score.md"
        assert score.main(["--cases", str(root), "--out", str(out)]) == 0
        text = out.read_text(encoding="utf-8")
        assert (
            "| `loose` | `AUD-9901/stub` | violates_policy | supported_mechanism | fire.py:1 |"
            in text
        )
        assert "| `loose` | reports | **absent** |" in text
        assert "- `loose`: author and reviewer disagree on the sub" in text
        assert "| `AUD-9901" not in text.split("## Mismatches")[0].split("## Headline")[1]

    def test_an_empty_registry_reports_what_ran(self, tmp_path: Path, monkeypatch):
        import aisafe.rules as rules_mod

        monkeypatch.setattr(rules_mod, "ALL_RULES", [])
        monkeypatch.setattr(rules_mod, "MISSING_RULE_MODULES", ["profiling", "influence"])
        root = tmp_path / "cases"
        write_case(root, "owed", expected=[OWED], forbidden=[])
        out = tmp_path / "score.md"
        assert score.main(["--cases", str(root), "--out", str(out)]) == 0
        text = out.read_text(encoding="utf-8")
        assert "Rules run: none (the rule registry is empty)." in text
        assert "Rule modules missing from the registry: `profiling`, `influence`." in text
        assert "| `AUD-9901/stub` | 0 | 0 | 1 | n/a (0/0) | 0.000 (0/1) |" in text

    def test_a_malformed_case_exits_2_and_writes_nothing(self, tmp_path: Path, stub_rules):
        root = tmp_path / "cases"
        case = write_case(root, "bad-split", expected=[OWED], forbidden=[])
        spec = case / "expected.yaml"
        spec.write_text(
            spec.read_text(encoding="utf-8").replace("split: dev", "split: nightly"),
            encoding="utf-8",
        )
        out = tmp_path / "score.md"
        assert score.main(["--cases", str(root), "--out", str(out)]) == 2
        assert not out.exists()

        # An unquoted colon in the description is not YAML; a draft like that is a
        # malformed case, not a case with zero findings.
        spec.write_text(
            "schema: aisg/1\nkind: bench-case\nid: bad-split\nsplit: dev\n"
            "description: the mirror case: the other side\nexpected: []\nforbidden: []\n",
            encoding="utf-8",
        )
        assert score.main(["--cases", str(root), "--out", str(out)]) == 2
        assert not out.exists()

    def test_the_committed_corpus_is_well_formed(self):
        """Every bench/cases/<id>/expected.yaml loads under the scorer's validation."""
        cases_dir = BENCH / "cases"
        if not cases_dir.is_dir():
            pytest.skip("bench/cases is not present")
        problems = []
        for case_dir in sorted(p for p in cases_dir.iterdir() if p.is_dir()):
            try:
                score.load_case(case_dir)
            except score.CaseError as exc:
                problems.append(str(exc))
        assert not problems, "\n".join(problems)


class TestShippedCorpusIsLabellable:
    """The committed labelling CSV, when present, must actually be hand-labellable."""

    @pytest.mark.skipif(
        not (BENCH / "findings-audit.csv").is_file(), reason="benchmark has not been run"
    )
    def test_sample_is_a_realistic_size(self):
        with (BENCH / "findings-audit.csv").open(newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert 0 < len(rows) <= 2000, (
            f"{len(rows)} rows is too many to hand-label; "
            "lower --sample-per-rule or re-run the harness"
        )

    @pytest.mark.skipif(
        not (BENCH / "findings-audit-all.csv").is_file(), reason="benchmark has not been run"
    )
    def test_full_set_is_retained_alongside_the_sample(self):
        with (BENCH / "findings-audit-all.csv").open(newline="", encoding="utf-8") as fh:
            full = list(csv.DictReader(fh))
        with (BENCH / "findings-audit.csv").open(newline="", encoding="utf-8") as fh:
            sample = list(csv.DictReader(fh))
        assert len(full) >= len(sample), "sampling must never lose evidence"
        assert {key(r) for r in sample} <= {key(r) for r in full}
