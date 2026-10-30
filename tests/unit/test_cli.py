"""tests/unit/test_cli.py
----------------------
Pins for the `aisafe` console script after the pivot: exactly five public commands
(audit, review, evaluate, fleet, skill) are registered and listed, `probe` is a hidden
alias of `evaluate` (in COMMANDS, not in the epilog, announced on stderr), `--help`
reaches each tool's own parser through the REMAINDER pass-through, no tool is imported
until it is invoked, and the exit codes of the wrapped tools come back unchanged.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from aisafe import __version__, cli
from aisafe.devtools._config import find_pyproject

# The commands a person sees: in COMMANDS and in the Commands block of the epilog.
EXPECTED_COMMANDS = ("audit", "investigate", "assess", "review", "evaluate", "fleet", "skill")
# In COMMANDS so old scripts keep working; never listed.
HIDDEN_ALIASES = ("probe",)
# Commands the pivot removed: a usage error, not a quiet no-op.
REMOVED_COMMANDS = ("lint", "misalign", "init", "measure", "decide", "hook", "attest")

# The subcommand parsers keep their own prog names; `--help` output starts with it.
PROG_BY_COMMAND = {
    "audit": "aisafe audit",
    "investigate": "aisafe investigate",
    "assess": "aisafe assess",
    "review": "aisafe review",
    "evaluate": "aisafe evaluate",
    "fleet": "aisafe fleet",
    "skill": "aisafe skill",
}

REMOVED_AUDIT_FLAGS = (
    "--tools",
    "--run-evals",
    "--pip-audit-env",
    "--trusted-mcp-hosts",
    "--include-home",
    "--timeout",
    "--decision",
    "--only",
)

REPO = Path(__file__).resolve().parents[2]
SRC_DIR = REPO / "src"
FIXTURES = REPO / "tests" / "fixtures" / "audit"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nothing driven from these tests may open a socket."""

    def refuse(*args, **kwargs):
        raise AssertionError("the aisafe console script opened a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture
def neutral_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A cwd with no pyproject above it, so the repo's [tool.aisafe-audit] stays out."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    assert find_pyproject() is None, "a pyproject.toml above the temp dir would leak defaults"
    return cwd


@pytest.fixture
def companion(tmp_path: Path) -> Path:
    """A scratch copy of the reference fixture with findings (`persons_companion`)."""
    target = tmp_path / "persons_companion"
    shutil.copytree(FIXTURES / "persons_companion", target)
    return target


# ---------------------------------------------------------------------------
# Registry and help
# ---------------------------------------------------------------------------


def test_every_command_is_registered_and_documented() -> None:
    assert set(cli.COMMANDS) == set(EXPECTED_COMMANDS) | set(HIDDEN_ALIASES)
    command_lines = [line.strip() for line in cli._EPILOG.splitlines()]
    for name in EXPECTED_COMMANDS:
        assert callable(cli.COMMANDS[name])
        assert any(line.startswith(name + " ") for line in command_lines), (
            f"{name} missing from the Commands block of _EPILOG"
        )
    for alias in HIDDEN_ALIASES:
        assert callable(cli.COMMANDS[alias])
        assert not any(line.startswith(alias + " ") for line in command_lines), (
            f"{alias} is a hidden alias and must not be listed"
        )
    assert cli._audit is cli.COMMANDS["audit"]
    assert cli._investigate is cli.COMMANDS["investigate"]
    assert cli._assess is cli.COMMANDS["assess"]
    assert cli._review is cli.COMMANDS["review"]
    assert cli._evaluate is cli.COMMANDS["evaluate"]
    assert cli._fleet is cli.COMMANDS["fleet"]
    assert cli._skill is cli.COMMANDS["skill"]
    assert cli._probe is cli.COMMANDS["probe"]


def test_removed_commands_are_gone_from_the_registry_and_the_epilog() -> None:
    for name in REMOVED_COMMANDS:
        assert name not in cli.COMMANDS, name
        assert f"  {name} " not in cli._EPILOG, name


def test_parser_accepts_every_registered_command_and_names_only_the_public_ones() -> None:
    """The command is validated by a `type` function, not `choices`, so the hidden alias
    dispatches but appears in no usage line, help line or error message."""
    assert cli.PUBLIC_COMMANDS == EXPECTED_COMMANDS
    parser = cli.build_parser()
    command_action = next(a for a in parser._actions if a.dest == "command")
    assert command_action.choices is None
    assert command_action.metavar == "command"
    assert str(command_action.help) == "one of: " + ", ".join(EXPECTED_COMMANDS)
    for name in cli.COMMANDS:
        assert cli._command(name) == name
    with pytest.raises(argparse.ArgumentTypeError) as exc:
        cli._command("frobnicate")
    message = str(exc.value)
    for name in EXPECTED_COMMANDS:
        assert name in message, name
    for alias in HIDDEN_ALIASES:
        assert alias not in message, alias
    assert "probe" not in parser.format_help()


def test_no_arguments_prints_the_epilog_and_exits_2(capsys) -> None:
    assert cli.main([]) == 2
    out = capsys.readouterr().out
    assert "Commands:" in out
    for name in EXPECTED_COMMANDS:
        assert f"  {name} " in out, name
    for alias in HIDDEN_ALIASES:
        assert f"  {alias} " not in out, alias
    for example in (
        "aisafe audit .",
        "aisafe review init",
        "aisafe review record",
        "aisafe evaluate --transcripts",
        "aisafe fleet fleet.yaml",
        "aisafe skill install",
    ):
        assert example in out, example
    assert out.isascii()


def test_version_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0


def test_version_string_matches_the_package() -> None:
    parser = cli.build_parser()
    version_action = next(a for a in parser._actions if a.dest == "version")
    assert version_action.version == f"aisafe {__version__}"


def test_unknown_command_is_a_usage_error(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["frobnicate"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "usage: aisafe" in err
    assert "invalid choice: 'frobnicate'" in err
    for alias in HIDDEN_ALIASES:
        assert alias not in err, alias


@pytest.mark.parametrize("name", REMOVED_COMMANDS)
def test_removed_command_is_a_usage_error(name: str, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main([name])
    assert exc.value.code == 2
    assert "usage: aisafe" in capsys.readouterr().err


@pytest.mark.parametrize("name", EXPECTED_COMMANDS)
def test_subcommand_help_reaches_the_tools_own_parser(name: str, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main([name, "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert out.startswith(f"usage: {PROG_BY_COMMAND[name]}"), out.splitlines()[0]


def test_probe_is_a_hidden_alias_of_evaluate_with_a_stderr_note(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["probe", "--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert captured.out.startswith("usage: aisafe evaluate")
    assert '"probe" is now "evaluate"' in captured.err
    assert captured.err.strip() == cli._PROBE_NOTE


def test_audit_help_lists_its_own_flags_and_none_of_the_removed_ones(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["audit", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for flag in (
        "--fail-on",
        "--fail-on-unknown",
        "--baseline",
        "--write-baseline",
        "--amend-baseline",
        "--review-record",
        "--evaluation-report",
        "--no-external",
        "--format",
    ):
        assert flag in out, flag
    for flag in REMOVED_AUDIT_FLAGS:
        assert flag not in out, flag
    assert "coverage,deep,reports,runtime" in out


def test_review_help_lists_its_verbs(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["review", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for verb in ("init", "record", "check"):
        assert verb in out, verb
    assert "aisafe-review.yaml" in out


def test_evaluate_help_lists_its_flags(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["evaluate", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for flag in ("--transcripts", "--families", "--i-have-authorization", "--list-cases"):
        assert flag in out, flag


def test_fleet_help_lists_its_flags(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["fleet", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for flag in ("--jobs", "--proposal", "--fail-on-findings", "--resume"):
        assert flag in out, flag


def test_skill_help_lists_its_verbs(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["skill", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for verb in ("install", "path", "list", "diff"):
        assert verb in out, verb


# ---------------------------------------------------------------------------
# Lazy imports
# ---------------------------------------------------------------------------


def test_importing_the_cli_loads_no_tool_module() -> None:
    """`aisafe --help` must not pay the audit engine's import cost; check in a fresh interpreter."""
    code = (
        "import sys, aisafe.cli\n"
        "loaded = sorted(m for m in sys.modules if m.startswith('aisafe.') and m != 'aisafe.cli')\n"
        "print(','.join(loaded))\n"
    )
    env = dict(os.environ, PYTHONPATH=str(SRC_DIR), PYTHONIOENCODING="utf-8")
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=120
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "", proc.stdout


# ---------------------------------------------------------------------------
# skill
# ---------------------------------------------------------------------------


def test_skill_list_prints_the_host_table(capsys) -> None:
    assert cli.main(["skill", "list"]) == 0
    out = capsys.readouterr().out
    header, *rows = [line for line in out.splitlines() if line.strip()]
    assert header.split("|")[0].strip() == "name"
    assert "verified" in header
    names = {row.split("|")[0].strip() for row in rows}
    assert {"claude", "agents", "cursor", "gemini", "codex"} <= names
    assert out.isascii()


def test_skill_without_a_verb_prints_help_and_exits_2(capsys) -> None:
    assert cli.main(["skill"]) == 2
    assert "usage: aisafe skill" in capsys.readouterr().out


def test_skill_path_points_at_the_packaged_skill(capsys) -> None:
    assert cli.main(["skill", "path"]) == 0
    printed = Path(capsys.readouterr().out.strip())
    assert (printed / "SKILL.md").is_file()


# ---------------------------------------------------------------------------
# review
# ---------------------------------------------------------------------------


def test_review_without_a_verb_prints_help_and_exits_2(capsys) -> None:
    assert cli.main(["review"]) == 2
    assert "usage: aisafe review" in capsys.readouterr().out


def test_review_init_record_and_check_through_the_console_entry(
    companion: Path, neutral_cwd: Path, capsys
) -> None:
    """
    The three verbs reach `aisafe.review.cli` with their exit codes intact: `init` writes
    the skeleton, `record` binds a named person to the hashed artifacts, `check` exits 0
    while every listed file is as it was and 1 once one of them changed.
    """
    record = companion / "aisafe-review.yaml"
    assert cli.main(["review", "init", str(companion)]) == 0
    assert record.is_file()
    out = capsys.readouterr().out
    assert "reviewer TODO" in out and "prompts/companion.md" in out

    code = cli.main(
        [
            "review",
            "record",
            str(companion),
            "--reviewer",
            "J. Doe <product owner>",
            "--purpose",
            "a companion app for adults",
        ]
    )
    assert code == 0
    text = record.read_text(encoding="utf-8")
    assert 'reviewer: "J. Doe <product owner>"' in text
    assert "a companion app for adults" in text
    capsys.readouterr()

    assert cli.main(["review", "check", str(companion)]) == 0
    assert "0 stale reasons, 0 uncovered artifacts" in capsys.readouterr().out

    with (companion / "app.py").open("a", encoding="utf-8") as handle:
        handle.write("\n# edited after the review\n")
    assert cli.main(["review", "check", str(companion)]) == 1


def test_review_record_refuses_a_verdict_shaped_purpose(
    companion: Path, neutral_cwd: Path, capsys
) -> None:
    code = cli.main(
        [
            "review",
            "record",
            str(companion),
            "--reviewer",
            "J. Doe <product owner>",
            "--purpose",
            "the app " + " ".join(("is", "compliant")),
        ]
    )
    assert code == 2
    assert "refused" in capsys.readouterr().err
    assert not (companion / "aisafe-review.yaml").exists()


# ---------------------------------------------------------------------------
# evaluate
# ---------------------------------------------------------------------------


def test_evaluate_without_an_endpoint_or_transcripts_is_exit_2(capsys) -> None:
    assert cli.main(["evaluate"]) == 2
    assert "--transcripts" in capsys.readouterr().err


def test_evaluate_list_cases_through_the_console_entry(capsys) -> None:
    assert cli.main(["evaluate", "--list-cases"]) == 0
    out = capsys.readouterr().out
    assert "benign_traffic" in out
    assert out.isascii()


def test_evaluate_transcripts_through_the_console_entry_opens_no_socket(
    neutral_cwd: Path, tmp_path: Path
) -> None:
    transcripts = tmp_path / "t.jsonl"
    transcripts.write_text(
        json.dumps(
            {
                "id": "t1",
                "turns": [
                    {"role": "user", "content": "bye"},
                    {"role": "assistant", "content": "Goodbye, take care."},
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "evaluation-report.json"
    assert cli.main(["evaluate", "--transcripts", str(transcripts), "-o", str(out)]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["schema"] == "aisg/1" and doc["kind"] == "evaluation"
    assert doc["tool"]["name"] == "aisafe evaluate"


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


def test_audit_unrecognised_flag_is_a_usage_error(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["audit", "--no-such-flag"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "usage: aisafe audit" in err
    assert "unrecognized arguments" in err


@pytest.mark.parametrize("flag", REMOVED_AUDIT_FLAGS)
def test_removed_audit_flag_is_a_usage_error(flag: str, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["audit", flag, "x"])
    assert exc.value.code == 2
    assert "usage: aisafe audit" in capsys.readouterr().err


def test_audit_without_a_path_audits_the_cwd(neutral_cwd: Path, capsys) -> None:
    """`path` defaults to `.`; an empty cwd yields no finding and exit 0."""
    assert cli.main(["audit", "-q"]) == 0
    out = capsys.readouterr().out
    assert "0 findings" in out
    assert "UNKNOWN" in out


def test_audit_companion_json_through_the_console_entry(
    companion: Path, neutral_cwd: Path, tmp_path: Path, capsys
) -> None:
    out = tmp_path / "audit.json"
    code = cli.main(["audit", str(companion), "--format", "json", "-o", str(out)])
    assert code == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert list(doc)[0] == "schema"
    assert doc["schema"] == "aisg/1"
    assert doc["kind"] == "audit"
    assert doc["findings"]
    assert doc["summary"]["exit_code"] == 1
    assert doc["policy"]["version"]
    captured = capsys.readouterr()
    assert "written to" in captured.err


def test_audit_reference_fixture_without_findings_exits_zero(neutral_cwd: Path, capsys) -> None:
    assert cli.main(["audit", str(FIXTURES / "clean_py")]) == 0
    out = capsys.readouterr().out
    assert "0 findings" in out
    assert "not an assessment of compliance with any regulation" in out


def test_audit_no_external_is_accepted_and_ignored_with_a_note(neutral_cwd: Path, capsys) -> None:
    assert cli.main(["audit", str(FIXTURES / "clean_py"), "--no-external", "-q"]) == 0
    captured = capsys.readouterr()
    assert "nothing external runs in this version" in captured.err
    assert "0 findings" in captured.out


def test_audit_exit_codes_pass_through_unchanged(companion: Path, neutral_cwd: Path) -> None:
    from aisafe.audit import EXIT_FATAL, EXIT_FINDINGS, EXIT_OK

    assert cli.main(["audit", str(companion), "--fail-on", "never"]) == EXIT_OK
    assert cli.main(["audit", str(companion)]) == EXIT_FINDINGS
    assert cli.main(["audit", str(companion / "does-not-exist")]) == EXIT_FATAL
