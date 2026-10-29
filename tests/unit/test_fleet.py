"""tests/unit/test_fleet.py
------------------------
`aisafe fleet` audits many repositories, one subprocess each, and aggregates counts, names,
decisions and paths; never a snippet. These tests pin the list formats and their
validation, the three documents (key order, the CSV columns with the decision and
inventory counts, the markdown with the disclaimer, the mechanism table and the rule
frequency), the exit-code rule (a repository that could not be audited is the fleet's
failure, a finding in one is not), `--resume`, `--proposal` (plan by mechanism, review
table, no snippet), that local paths open no socket and are never written into, and that
the only program the fleet spawns is this interpreter.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from aisafe.devtools import fleet
from aisafe.devtools.fleet import (
    CSV_COLUMNS,
    DECISIONS,
    EXIT_FATAL,
    EXIT_INCOMPLETE,
    EXIT_OK,
    FleetError,
    FleetOptions,
    Target,
    audit_argv,
    build_parser,
    check_templates,
    main,
    read_list,
    render_markdown,
    render_proposal,
    run_fleet,
    summarise,
)
from aisafe.policy import POLICY_VERSION
from aisafe.reporting.report import BANNED_PHRASES

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures" / "audit"

# Launchers that could install something on the way; the fleet never spawns one.
FORBIDDEN_LAUNCHERS = frozenset({"uv", "uvx", "pipx", "npx", "pip", "poetry", "conda"})

EXPECTED_CSV_COLUMNS = (
    "name",
    "url",
    "sha",
    "status",
    "duration_s",
    "exit_code",
    "findings",
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "violates_policy",
    "requires_contextual_review",
    "unknown_items",
    "languages",
    "providers",
    "frameworks",
    "prompts",
    "person_signals",
    "memory_stores",
    "review_records",
    "report",
)
HIGHLIGHT_KEYS = {
    "languages",
    "providers",
    "frameworks",
    "prompts",
    "person_signals",
    "memory_stores",
    "review_records",
}
PROPOSAL_HEADINGS = (
    "## Findings by severity",
    "## Findings by decision",
    "## Plan (by mechanism, policy order)",
    "## Review",
    "## UNKNOWN",
    "## How this was produced",
    "## How to apply",
)
PLAN_HEADER = (
    "| # | id | title | file:line | severity | evidence | decision | remediation (removes) | "
    "tier | language | who |"
)
REVIEW_HEADER = "| # | decision (apply / defer / contextual review) | reason |"


def _tree(root: Path) -> dict[str, bytes]:
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def _snippets(report: dict) -> list[str]:
    return [
        e["snippet"] for f in report["findings"] for e in f.get("evidence", []) if e.get("snippet")
    ]


@pytest.fixture(autouse=True)
def no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args, **kwargs):
        raise AssertionError("aisafe fleet opened a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture
def neutral_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    return cwd


@pytest.fixture
def two_repos(tmp_path: Path) -> tuple[Path, Path]:
    """Copies of the two reference fixtures (so the repo's own pyproject is not above them)."""
    a = tmp_path / "repos" / "clean_py"
    b = tmp_path / "repos" / "persons_companion"
    shutil.copytree(FIXTURES / "clean_py", a)
    shutil.copytree(FIXTURES / "persons_companion", b)
    return a, b


@pytest.fixture
def companion_report(tmp_path: Path, neutral_cwd: Path) -> dict:
    """One audit report of the reference fixture, produced in-process, for the document tests."""
    from aisafe.audit import main as audit_main

    out = tmp_path / "companion-report.json"
    code = audit_main([str(FIXTURES / "persons_companion"), "--format", "json", "-o", str(out)])
    assert code == 1
    return json.loads(out.read_text(encoding="utf-8"))


def _yaml_list(path: Path, entries: list[dict]) -> Path:
    import yaml

    path.write_text(yaml.safe_dump({"repos": entries}, sort_keys=False), encoding="utf-8")
    return path


def _options(list_path: Path, out: Path, **over) -> FleetOptions:
    base = dict(list_path=str(list_path), out=str(out), fail_on="never")
    base.update(over)
    return FleetOptions(**base)


# ---------------------------------------------------------------------------
# The list
# ---------------------------------------------------------------------------


class TestList:
    def test_yaml_and_csv_parse_to_the_same_targets(self, tmp_path: Path):
        yaml_path = _yaml_list(
            tmp_path / "fleet.yaml",
            [
                {
                    "name": "one",
                    "url": "https://example.test/one.git",
                    "sha": "a" * 40,
                    "branch": "main",
                },
                {"name": "two", "path": "/tmp/two"},
            ],
        )
        csv_path = tmp_path / "fleet.csv"
        csv_path.write_text(
            "name,url,path,sha,branch\none,https://example.test/one.git,,"
            + "a" * 40
            + ",main\ntwo,,/tmp/two,,\n",
            encoding="utf-8",
        )
        assert read_list(yaml_path) == read_list(csv_path)
        assert read_list(yaml_path)[0] == Target(
            "one", "https://example.test/one.git", None, "a" * 40, "main"
        )
        assert read_list(yaml_path)[1].location == "/tmp/two"

    def test_bench_corpus_is_a_valid_fleet_list(self):
        targets = read_list(REPO / "bench" / "corpus.yaml")
        assert len(targets) >= 10
        assert all(t.url and t.sha and len(t.sha) == 40 for t in targets)

    @pytest.mark.parametrize(
        "entries, fragment",
        [
            ([{"name": "x"}], "exactly one of"),
            ([{"name": "x", "url": "u", "path": "p"}], "exactly one of"),
            ([{"name": "../x", "path": "p"}], "file-system safe"),
            ([{"name": "x", "path": "p", "sha": "zz"}], "not a commit id"),
            ([{"name": "x", "path": "p"}, {"name": "x", "path": "q"}], "duplicate names"),
            ([], "non-empty list"),
        ],
    )
    def test_bad_entries_are_refused(self, tmp_path: Path, entries, fragment: str):
        path = _yaml_list(tmp_path / "fleet.yaml", entries)
        with pytest.raises(FleetError, match=fragment):
            read_list(path)

    def test_unknown_suffix_and_missing_file(self, tmp_path: Path):
        (tmp_path / "list.txt").write_text("x", encoding="utf-8")
        with pytest.raises(FleetError, match="expected a .yaml"):
            read_list(tmp_path / "list.txt")
        with pytest.raises(FleetError):
            read_list(tmp_path / "none.yaml")


# ---------------------------------------------------------------------------
# The run over local paths
# ---------------------------------------------------------------------------


class TestRun:
    def test_two_local_repos_produce_the_three_documents(
        self, tmp_path: Path, two_repos, neutral_cwd: Path
    ):
        a, b = two_repos
        list_path = _yaml_list(
            tmp_path / "fleet.yaml",
            [{"name": "clean_py", "path": str(a)}, {"name": "persons_companion", "path": str(b)}],
        )
        before = (_tree(a), _tree(b))
        doc, code = run_fleet(_options(list_path, neutral_cwd / "out"), echo=False)
        assert code == EXIT_OK
        assert list(doc) == [
            "schema",
            "kind",
            "tool",
            "generated_at",
            "policy",
            "options",
            "totals",
            "disclaimer",
            "repos",
        ]
        assert doc["schema"] == "aisg/1" and doc["kind"] == "fleet"
        assert doc["tool"]["name"] == "aisafe-fleet"
        assert doc["policy"] == {"version": POLICY_VERSION}
        assert list(doc["totals"]) == [
            "repos",
            "completed",
            "failed",
            "findings",
            "by_severity",
            "by_evidence_status",
            "by_decision",
            "rule_frequency",
            "mechanisms",
            "unknown_items",
            "repos_with_exit_1",
        ]
        totals = doc["totals"]
        assert totals["repos"] == 2 and totals["completed"] == 2 and totals["failed"] == 0
        assert set(totals["by_decision"]) == set(DECISIONS)
        assert set(totals["mechanisms"]) == {f"M{i}" for i in range(1, 9)}
        rows = {r["name"]: r for r in doc["repos"]}
        companion = rows["persons_companion"]
        assert companion["status"] == "ok" and companion["summary"]["findings"] > 0
        assert companion["exit_code"] == 0  # fail_on never: findings never count
        assert list(companion["summary"]) == [
            "findings",
            "by_severity",
            "by_evidence_status",
            "by_decision",
            "unknown_items",
            "unknown_by_category",
            "exit_code",
            "policy_version",
            "mechanisms",
        ]
        assert companion["summary"]["policy_version"] == POLICY_VERSION
        assert companion["summary"]["by_decision"]["violates_policy"] >= 1
        assert set(companion["highlights"]) == HIGHLIGHT_KEYS
        assert "python" in companion["highlights"]["languages"]
        assert companion["highlights"]["providers"] == ["anthropic"]
        assert companion["highlights"]["memory_stores"] >= 1
        assert rows["clean_py"]["status"] == "ok" and rows["clean_py"]["summary"]["findings"] == 0
        out = neutral_cwd / "out"
        assert (out / "fleet-report.json").is_file()
        assert (out / "persons_companion" / "audit-report.json").is_file()
        csv_text = (out / "fleet-report.csv").read_text(encoding="utf-8")
        assert csv_text.splitlines()[0] == ",".join(CSV_COLUMNS)
        md = (out / "fleet-report.md").read_text(encoding="utf-8")
        assert md.startswith("# aisafe fleet\n\n> This report lists observations")
        assert "| persons_companion | ok |" in md
        assert "## Mechanisms" in md and "## Rule frequency" in md
        assert "| M4 " in md
        # the fleet never writes into the audited trees
        assert (_tree(a), _tree(b)) == before
        # and copies no snippet: the JSON carries counts, names, decisions and paths only
        report = json.loads(
            (out / "persons_companion" / "audit-report.json").read_text(encoding="utf-8")
        )
        snippets = _snippets(report)
        text = json.dumps(doc)
        assert snippets and not any(s in text for s in snippets)
        assert not any("evidence" in r or "snippet" in r for r in doc["repos"])

    def test_findings_do_not_fail_the_fleet_but_fail_on_findings_does(
        self, tmp_path: Path, two_repos, neutral_cwd: Path
    ):
        _, b = two_repos
        list_path = _yaml_list(
            tmp_path / "fleet.yaml", [{"name": "persons_companion", "path": str(b)}]
        )
        doc, code = run_fleet(_options(list_path, neutral_cwd / "out", fail_on="high"), echo=False)
        assert code == EXIT_OK
        assert doc["repos"][0]["exit_code"] == 1 and doc["totals"]["repos_with_exit_1"] == 1
        doc, code = run_fleet(
            _options(list_path, neutral_cwd / "out2", fail_on="high", fail_on_findings=True),
            echo=False,
        )
        assert code == EXIT_INCOMPLETE

    def test_missing_path_is_clone_failed_and_exit_one(
        self, tmp_path: Path, two_repos, neutral_cwd: Path
    ):
        a, _ = two_repos
        list_path = _yaml_list(
            tmp_path / "fleet.yaml",
            [
                {"name": "clean_py", "path": str(a)},
                {"name": "gone", "path": str(tmp_path / "nope")},
            ],
        )
        doc, code = run_fleet(_options(list_path, neutral_cwd / "out"), echo=False)
        assert code == EXIT_INCOMPLETE
        rows = {r["name"]: r for r in doc["repos"]}
        assert (
            rows["gone"]["status"] == "clone_failed" and "does not exist" in rows["gone"]["error"]
        )
        assert rows["gone"]["report"] is None and rows["gone"]["exit_code"] is None
        assert doc["totals"]["failed"] == 1
        md = (neutral_cwd / "out" / "fleet-report.md").read_text(encoding="utf-8")
        assert "## Not audited" in md and "- gone: clone_failed:" in md

    def test_resume_skips_a_repository_whose_report_parses(
        self, tmp_path: Path, two_repos, neutral_cwd: Path, monkeypatch
    ):
        a, _ = two_repos
        list_path = _yaml_list(tmp_path / "fleet.yaml", [{"name": "clean_py", "path": str(a)}])
        out = neutral_cwd / "out"
        first, _ = run_fleet(_options(list_path, out), echo=False)
        calls: list[list[str]] = []
        real_run = subprocess.run

        def spy(argv, *args, **kwargs):
            calls.append(list(argv))
            return real_run(argv, *args, **kwargs)

        monkeypatch.setattr(fleet.subprocess, "run", spy)
        second, code = run_fleet(_options(list_path, out, resume=True), echo=False)
        assert code == EXIT_OK and calls == []
        assert second["repos"][0]["resumed"] is True
        assert second["repos"][0]["summary"] == first["repos"][0]["summary"]

    def test_proposal_has_plan_and_review_tables_and_no_snippet(
        self, tmp_path: Path, two_repos, neutral_cwd: Path
    ):
        _, b = two_repos
        list_path = _yaml_list(
            tmp_path / "fleet.yaml", [{"name": "persons_companion", "path": str(b)}]
        )
        run_fleet(_options(list_path, neutral_cwd / "out", proposal=True), echo=False)
        text = (neutral_cwd / "out" / "persons_companion" / "proposal.md").read_text(
            encoding="utf-8"
        )
        assert text.startswith(
            "# AI safety audit: persons_companion\n\n> This report lists observations"
        )
        assert f"under policy {POLICY_VERSION}" in text
        for heading in PROPOSAL_HEADINGS:
            assert heading in text, heading
        # one plan section per mechanism with findings, in policy order
        sections = [line for line in text.splitlines() if line.startswith("### M")]
        assert sections and sections == sorted(sections)
        assert any(line.startswith("### M4 ") for line in sections)
        assert "### Not attributed to a mechanism" not in text
        assert PLAN_HEADER in text
        assert "| 1 | AUD-" in text
        assert REVIEW_HEADER in text
        assert "| 1 | | |" in text
        assert "-m aisafe.cli audit . --format json" in text
        assert "--no-external" not in text
        assert "never pushes" in text
        assert "aisafe review record" in text
        report = json.loads(
            (neutral_cwd / "out" / "persons_companion" / "audit-report.json").read_text(
                encoding="utf-8"
            )
        )
        snippets = _snippets(report)
        assert snippets and not any(s in text for s in snippets)
        assert text.isascii()
        lowered = text.lower()
        for phrase in BANNED_PHRASES:
            assert phrase not in lowered, phrase

    def test_jobs_two_yields_the_same_document(self, tmp_path: Path, two_repos, neutral_cwd: Path):
        a, b = two_repos
        list_path = _yaml_list(
            tmp_path / "fleet.yaml",
            [{"name": "clean_py", "path": str(a)}, {"name": "persons_companion", "path": str(b)}],
        )
        one, _ = run_fleet(_options(list_path, neutral_cwd / "o1"), echo=False)
        two, _ = run_fleet(_options(list_path, neutral_cwd / "o2", jobs=2), echo=False)

        def stable(doc: dict) -> dict:
            repos = []
            for r in doc["repos"]:
                r = dict(r)
                r.pop("duration_s")
                r["report"] = Path(r["report"]).name if r["report"] else None
                repos.append(r)
            return {"totals": doc["totals"], "repos": repos}

        assert stable(one) == stable(two)

    def test_only_this_interpreter_is_spawned(
        self, tmp_path: Path, two_repos, neutral_cwd: Path, monkeypatch
    ):
        a, _ = two_repos
        list_path = _yaml_list(tmp_path / "fleet.yaml", [{"name": "clean_py", "path": str(a)}])
        seen: list[list[str]] = []
        real_run = subprocess.run

        def spy(argv, *args, **kwargs):
            seen.append(list(argv))
            return real_run(argv, *args, **kwargs)

        monkeypatch.setattr(fleet.subprocess, "run", spy)
        run_fleet(_options(list_path, neutral_cwd / "out"), echo=False)
        assert seen and all(argv[0] == sys.executable for argv in seen)
        assert all(
            Path(argv[0]).name.lower().split(".")[0] not in FORBIDDEN_LAUNCHERS for argv in seen
        )
        assert all("install" not in token for argv in seen for token in argv)

    def test_extra_args_reach_every_audit(self):
        argv = audit_argv("high", Path("r.json"), ("--rules", "AUD-1104"))
        assert argv[:4] == [sys.executable, "-m", "aisafe.cli", "audit"]
        assert argv[4:8] == [".", "--format", "json", "--fail-on"]
        assert argv[-2:] == ["--rules", "AUD-1104"]
        assert "--no-external" not in argv


# ---------------------------------------------------------------------------
# Documents without a run
# ---------------------------------------------------------------------------


class TestDocuments:
    def test_csv_columns_carry_decisions_and_inventory_counts(self):
        assert CSV_COLUMNS == EXPECTED_CSV_COLUMNS
        assert DECISIONS == ("violates_policy", "requires_contextual_review")
        for removed in ("tools", "mcp_servers", "hosts", "guardrails", "evals", "trifecta"):
            assert removed not in CSV_COLUMNS, removed

    def test_summarise_reads_counts_decisions_mechanisms_names_and_sha(self, companion_report):
        report = companion_report
        summary, frequency, highlights, sha = summarise(report)
        assert summary["findings"] == report["summary"]["findings"] > 0
        assert set(summary["by_severity"]) == {"critical", "high", "medium", "low", "info"}
        assert summary["by_severity"] == report["summary"]["by_severity"]
        assert set(summary["by_decision"]) == set(DECISIONS)
        assert (
            summary["by_decision"]["violates_policy"]
            == (report["summary"]["by_decision"]["violates_policy"])
        )
        assert set(summary["by_evidence_status"]) == {
            "detected_signal",
            "supported_mechanism",
            "observed_behavior",
            "unknown",
        }
        assert summary["policy_version"] == report["policy"]["version"] == POLICY_VERSION
        assert summary["exit_code"] == report["summary"]["exit_code"]
        assert list(summary["mechanisms"]) == [f"M{i}" for i in range(1, 9)]
        for row in report["mechanisms"]:
            mine = summary["mechanisms"][row["id"]]
            assert mine == {
                "name": row["name"],
                "decision": row["decision"],
                "findings": row["findings"],
            }
        assert sum(frequency.values()) == len(report["findings"])
        assert all(rule.startswith("AUD-11") for rule in frequency)
        assert set(highlights) == HIGHLIGHT_KEYS
        assert highlights["providers"] == ["anthropic"]
        assert highlights["prompts"] == len(report["inventory"]["prompts"])
        assert highlights["person_signals"] == len(report["inventory"]["person_signals"])
        assert highlights["memory_stores"] == len(report["inventory"]["memory_stores"])
        assert highlights["review_records"] == 0
        assert sha == (report["target"].get("git_sha") or None)

    def test_summarise_tolerates_an_empty_report(self):
        summary, frequency, highlights, sha = summarise({})
        assert summary["findings"] == 0 and summary["exit_code"] is None
        assert summary["policy_version"] is None and summary["mechanisms"] == {}
        assert all(v == 0 for v in summary["by_decision"].values())
        assert frequency == {} and sha is None
        assert highlights == {
            "languages": [],
            "providers": [],
            "frameworks": [],
            "prompts": 0,
            "person_signals": 0,
            "memory_stores": 0,
            "review_records": 0,
        }

    def test_templates_are_free_of_banned_phrases(self):
        assert check_templates() == []
        assert fleet.DISCLAIMER.isascii() and f"(version {POLICY_VERSION})" in fleet.DISCLAIMER

    def test_markdown_sorts_by_critical_then_high_then_name(self):
        def repo(name, critical, high):
            return {
                "name": name,
                "url": name,
                "sha": None,
                "status": "ok",
                "duration_s": 1.0,
                "exit_code": 0,
                "report": f"{name}/audit-report.json",
                "summary": {
                    "findings": critical + high,
                    "by_severity": {
                        "critical": critical,
                        "high": high,
                        "medium": 0,
                        "low": 0,
                        "info": 0,
                    },
                    "by_decision": {
                        "violates_policy": critical,
                        "requires_contextual_review": high,
                    },
                    "unknown_items": 0,
                },
                "rule_frequency": {"AUD-1104/vulnerable": critical} if critical else {},
                "highlights": {},
                "error": None,
                "resumed": False,
            }

        options = FleetOptions(list_path="l.yaml")
        doc = fleet.build_report([], options, "2026-10-19T00:00:00Z")
        doc["repos"] = [repo("b", 1, 0), repo("a", 1, 0), repo("c", 0, 5)]
        doc["totals"]["rule_frequency"] = {"AUD-1104/vulnerable": 2}
        md = render_markdown(doc)
        order = [
            line.split("|")[1].strip()
            for line in md.splitlines()
            if line.startswith("| ") and " | ok | " in line
        ]
        assert order == ["a", "b", "c"]
        assert "| a | ok | 1 | 1 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | a/audit-report.json |" in md
        assert "| AUD-1104/vulnerable | 2 | 2 |" in md
        # no run: the mechanism table has one dash row rather than nothing
        assert "| - | - | - | - | - |" in md
        lowered = md.lower()
        for phrase in BANNED_PHRASES:
            assert phrase not in lowered

    def test_markdown_mechanism_table_comes_from_the_per_repo_summaries(self, companion_report):
        summary, frequency, highlights, _sha = summarise(companion_report)
        result = fleet.RepoResult(
            name="persons_companion",
            url="x",
            sha=None,
            status="ok",
            duration_s=1.0,
            exit_code=1,
            report="persons_companion/audit-report.json",
            summary=summary,
            rule_frequency=frequency,
            highlights=highlights,
        )
        doc = fleet.build_report([result], FleetOptions(list_path="l.yaml"), "2026-10-19T00:00:00Z")
        assert list(doc["totals"]["mechanisms"]) == [f"M{i}" for i in range(1, 9)]
        m4 = doc["totals"]["mechanisms"]["M4"]
        assert m4["repos_with_findings"] == 1 and m4["findings"] >= 1
        assert m4["repos_violates_policy"] == 1 and m4["repos_requires_contextual_review"] == 0
        md = render_markdown(doc)
        assert "| M4 Optimisation of attention, retention or spending" in md
        assert "| M2 Vulnerability inference used for influence | 0 | 0 | 0 | 0 |" in md

    def test_proposal_who_column_is_always_you(self, companion_report):
        text = render_proposal(
            Target("persons_companion", path="x"),
            companion_report,
            ["python", "-m", "aisafe.cli", "audit", "."],
        )
        rows = [line for line in text.splitlines() if line.startswith("| ") and "| AUD-" in line]
        assert len(rows) == len(companion_report["findings"])
        assert {line.split("|")[-2].strip() for line in rows} == {"you"}
        assert "approval needed" not in text
        # every row names what was established and what the policy decided
        for line in rows:
            cells = [cell.strip() for cell in line.split("|")[1:-1]]
            assert cells[5] in {
                "detected_signal",
                "supported_mechanism",
                "observed_behavior",
                "unknown",
            }
            assert cells[6] in DECISIONS
            assert "(removes " in cells[7]
        # the review table has one empty row per plan row
        assert text.count("| | |\n") >= len(rows)

    def test_proposal_without_findings_prints_the_empty_plan(self):
        report = {
            "schema": "aisg/1",
            "kind": "audit",
            "policy": {"version": POLICY_VERSION},
            "summary": {"findings": 0, "by_severity": {}, "by_decision": {}},
            "mechanisms": [],
            "findings": [],
            "unknown": [],
            "inventory": {"units": []},
        }
        text = render_proposal(Target("empty", path="x"), report, ["python", "-m", "aisafe.cli"])
        assert "(no findings)" in text and "(none listed)" in text
        assert text.isascii()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCli:
    def test_help_starts_with_the_prog_name(self, capsys):
        with pytest.raises(SystemExit) as exc:
            build_parser().parse_args(["--help"])
        assert exc.value.code == 0
        assert capsys.readouterr().out.startswith("usage: aisafe fleet")

    def test_bad_list_exits_two(self, tmp_path: Path, neutral_cwd: Path, capsys):
        path = _yaml_list(tmp_path / "fleet.yaml", [{"name": "x"}])
        assert main([str(path)]) == EXIT_FATAL
        assert "exactly one of" in capsys.readouterr().err

    def test_main_runs_and_prints_the_summary_line(
        self, tmp_path: Path, two_repos, neutral_cwd: Path, capsys
    ):
        a, _ = two_repos
        list_path = _yaml_list(tmp_path / "fleet.yaml", [{"name": "clean_py", "path": str(a)}])
        assert main([str(list_path), "--out", "out", "--fail-on", "never", "--quiet"]) == EXIT_OK
        out = capsys.readouterr().out
        assert "aisafe fleet: 1/1 audited, 0 not audited" in out
        assert (neutral_cwd / "out" / "fleet-report.json").is_file()

    def test_jobs_zero_is_fatal(self, tmp_path: Path, neutral_cwd: Path):
        path = _yaml_list(tmp_path / "fleet.yaml", [{"name": "x", "path": str(tmp_path)}])
        assert main([str(path), "--jobs", "0"]) == EXIT_FATAL

    def test_console_script_routes_fleet(self):
        from aisafe import cli

        assert "fleet" in cli.COMMANDS
        assert "aisafe fleet" in cli._EPILOG
