"""tests/unit/test_ci_surface.py
------------------------------
The CI files other people depend on, after the pivot. `release.yml` publishes the
package: it must use trusted publishing (no password, no token secret), pause on the
`pypi` environment for a reviewer, gate on the version sites, the generated rule
documents, the suite and the self-audit, and smoke-test the published package through
`uvx` on the reference fixtures with exact exit codes. The consumer surface is one
composite action, one GitLab template, one pre-commit hook and the dogfood job in
`tests.yml`; none of them names a removed command, and none passes the retired
`--no-external` flag.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github" / "workflows"
RELEASE = WORKFLOWS / "release.yml"
TESTS_WORKFLOW = WORKFLOWS / "tests.yml"
ACTION = REPO / "action.yml"
PRE_COMMIT_HOOKS = REPO / ".pre-commit-hooks.yaml"
PRE_COMMIT_CONFIG = REPO / ".pre-commit-config.yaml"
GITLAB = REPO / ".gitlab-ci-aisafe.yml"

CONSUMER_FILES = (RELEASE, TESTS_WORKFLOW, ACTION, PRE_COMMIT_HOOKS, PRE_COMMIT_CONFIG, GITLAB)

# Commands the pivot removed; a CI file that still calls one would fail every consumer.
REMOVED_COMMANDS = (
    "aisafe lint",
    "aisafe misalign",
    "aisafe init",
    "aisafe measure",
    "aisafe decide",
    "aisafe hook",
    "aisafe attest",
    "aisafe probe",
    "euaiact-lint",
    "misalignment-check",
)


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _triggers(doc: dict) -> dict:
    # PyYAML reads the bare key `on` as the boolean True.
    return doc.get("on") or doc.get(True) or {}


def _steps_text(job: dict) -> str:
    return "\n".join(
        str(step.get("run", "")) + " " + str(step.get("uses", "")) for step in job.get("steps", [])
    )


def _project_version() -> str:
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    return re.search(r'^version\s*=\s*"([^"]+)"', text, re.M).group(1)


# ---------------------------------------------------------------------------
# The whole surface
# ---------------------------------------------------------------------------


class TestSurface:
    def test_the_workflows_are_exactly_tests_and_release(self) -> None:
        names = sorted(p.name for p in WORKFLOWS.iterdir() if p.suffix in (".yml", ".yaml"))
        assert names == ["release.yml", "tests.yml"]
        assert not (WORKFLOWS / "eu-ai-act-compliance.yml").exists()

    def test_the_gitlab_template_was_renamed(self) -> None:
        assert GITLAB.is_file()
        assert not (REPO / ".gitlab-ci-euaiact.yml").exists()

    def test_no_consumer_file_names_a_removed_command(self) -> None:
        for path in CONSUMER_FILES:
            text = path.read_text(encoding="utf-8")
            for command in REMOVED_COMMANDS:
                assert command not in text, (path.name, command)

    def test_no_consumer_file_passes_the_retired_flag(self) -> None:
        # `--no-external` is accepted and ignored by the audit, with a note on stderr; a
        # shipped CI file that still passes it would print that note on every run.
        for path in CONSUMER_FILES:
            assert "--no-external" not in path.read_text(encoding="utf-8"), path.name

    def test_every_consumer_file_is_ascii(self) -> None:
        for path in CONSUMER_FILES:
            assert path.read_text(encoding="utf-8").isascii(), path.name


# ---------------------------------------------------------------------------
# release.yml
# ---------------------------------------------------------------------------


class TestReleaseWorkflow:
    def test_parses_and_triggers_on_version_tags(self) -> None:
        doc = _load(RELEASE)
        triggers = _triggers(doc)
        assert triggers["push"]["tags"] == ["v*"]
        assert "workflow_dispatch" in triggers
        assert set(doc["jobs"]) == {"gate", "build", "publish", "github-release", "smoke"}

    def test_default_permissions_are_read_only(self) -> None:
        doc = _load(RELEASE)
        assert doc["permissions"] == {"contents": "read"}

    def test_gate_checks_version_sites_generated_docs_suite_and_self_audit(self) -> None:
        gate = _load(RELEASE)["jobs"]["gate"]
        text = _steps_text(gate)
        assert "scripts/bump_version.py --check --tag" in text
        assert "scripts/sync_skill.py --check" in text
        assert "scripts/rules_md.py --check" in text
        assert "pytest -q" in text
        assert "aisafe audit . --fail-on high --baseline audit-baseline.json" in text
        # The generators the pivot deleted are not run.
        assert "controls_md" not in text and "levels_md" not in text

    def test_gate_installs_the_dev_and_devtools_extras(self) -> None:
        gate = _load(RELEASE)["jobs"]["gate"]
        assert 'pip install -e ".[dev,devtools]"' in _steps_text(gate)

    def test_publish_uses_trusted_publishing_behind_the_pypi_environment(self) -> None:
        publish = _load(RELEASE)["jobs"]["publish"]
        assert publish["environment"] == "pypi"
        assert publish["permissions"]["id-token"] == "write"
        assert publish["needs"] == "build"
        uses = [str(step.get("uses", "")) for step in publish["steps"]]
        assert any(u.startswith("pypa/gh-action-pypi-publish@") for u in uses)
        raw = RELEASE.read_text(encoding="utf-8")
        assert "password" not in raw
        assert "PYPI_TOKEN" not in raw and "PYPI_API_TOKEN" not in raw
        assert not re.search(r"secrets\.\w*PYPI", raw)

    def test_publish_release_and_smoke_run_only_on_a_pushed_tag(self) -> None:
        jobs = _load(RELEASE)["jobs"]
        for name in ("publish", "github-release", "smoke"):
            assert jobs[name]["if"] == "github.event_name == 'push'", name

    def test_release_notes_come_from_the_changelog(self) -> None:
        job = _load(RELEASE)["jobs"]["github-release"]
        text = _steps_text(job)
        assert "bump_version.py --changelog-section" in text
        assert "gh release create" in text
        assert job["permissions"]["contents"] == "write"

    def test_smoke_runs_the_published_package_through_uvx_with_exact_exit_codes(self) -> None:
        smoke = _load(RELEASE)["jobs"]["smoke"]
        text = _steps_text(smoke)
        assert 'uvx --from "aisafe==${V}" aisafe --version' in text
        # The reference fixtures: no AI surface exits 0, the companion prompt exits 1.
        assert "clean_py" in text and "persons_companion" in text
        assert "py_agent" not in text
        assert '[ "$rc" -eq 0 ]' in text and '[ "$rc" -eq 1 ]' in text
        assert "mktemp -d" in text  # never from this repo's root: [tool.aisafe-audit] would leak

    def test_build_pins_the_build_tool_and_checks_the_top_level_name(self) -> None:
        build = _load(RELEASE)["jobs"]["build"]
        text = _steps_text(build)
        assert "pip install build==" in text
        assert 'if pkgs != {"aisafe"}' in text

    def test_every_third_party_action_is_pinned_to_a_tag(self) -> None:
        doc = _load(RELEASE)
        for job in doc["jobs"].values():
            for step in job["steps"]:
                uses = step.get("uses")
                if uses:
                    assert "@" in uses, uses


# ---------------------------------------------------------------------------
# tests.yml
# ---------------------------------------------------------------------------


class TestTestsWorkflow:
    def test_jobs_are_test_audit_lint_build_and_action(self) -> None:
        jobs = _load(TESTS_WORKFLOW)["jobs"]
        assert set(jobs) == {"test", "audit", "lint", "build", "action"}
        assert jobs["audit"]["needs"] == "test"

    def test_matrix_covers_the_floor_and_the_ceiling_of_requires_python(self) -> None:
        test = _load(TESTS_WORKFLOW)["jobs"]["test"]
        assert test["strategy"]["matrix"]["python-version"] == ["3.10", "3.13"]
        text = _steps_text(test)
        assert "pytest -q" in text
        assert 'pip install -e ".[dev,devtools]"' in text

    def test_audit_gate_pins_the_fixture_exit_codes_exactly(self) -> None:
        audit = _load(TESTS_WORKFLOW)["jobs"]["audit"]
        step = next(s for s in audit["steps"] if s.get("name") == "Fixture exit codes")
        run = str(step["run"])
        assert 'aisafe audit "$fixtures/persons_companion"' in run
        assert 'aisafe audit "$fixtures/ts_agent" --fail-on-unknown deep' in run
        assert 'aisafe audit "$fixtures/clean_py"' in run
        assert run.count('test "$rc" -eq 1') == 2
        assert run.count('test "$rc" -eq 0') == 1
        assert "mktemp -d" in run
        assert "|| rc=$?" in run and "|| true" not in run

    def test_audit_gate_runs_the_self_audit_and_the_generator_checks(self) -> None:
        audit = _load(TESTS_WORKFLOW)["jobs"]["audit"]
        text = _steps_text(audit)
        assert "aisafe audit . --fail-on high --baseline audit-baseline.json" in text
        assert "python scripts/sync_skill.py --check" in text
        assert "python scripts/rules_md.py --check" in text
        assert "python -m build --wheel" in text
        assert "from aisafe.skills import skill_root" in text

    def test_build_job_reads_the_policy_and_the_corpus_from_the_wheel(self) -> None:
        build = _load(TESTS_WORKFLOW)["jobs"]["build"]
        text = _steps_text(build)
        assert "from aisafe.policy import load_policy" in text
        assert "from aisafe.evaluation.scenarios import load_corpus" in text
        assert "len(policy.mechanisms) == 8" in text
        assert 'if pkgs != {"aisafe"}' in text

    def test_nothing_of_the_removed_product_survives(self) -> None:
        raw = TESTS_WORKFLOW.read_text(encoding="utf-8")
        for fragment in ("measure", "probe-corpus", "presets", "Optional deps", "controls_md"):
            assert fragment not in raw, fragment


# ---------------------------------------------------------------------------
# The consumer-facing surface: action.yml, .pre-commit-hooks.yaml, the GitLab template and
# the dogfood job in tests.yml.
# ---------------------------------------------------------------------------


class TestCompositeAction:
    def test_parses_as_a_composite_action_with_the_expected_inputs(self) -> None:
        doc = _load(ACTION)
        assert doc["runs"]["using"] == "composite"
        assert set(doc["inputs"]) == {
            "path",
            "fail-on",
            "baseline",
            "extra-args",
            "version",
            "install-from",
            "python-version",
            "upload-sarif",
            "sarif-category",
            "step-summary",
            "pr-comment",
            "output-dir",
        }
        assert set(doc["outputs"]) == {"exit-code", "findings", "new-findings", "report"}
        assert doc["inputs"]["fail-on"]["default"] == "high"
        assert doc["inputs"]["install-from"]["default"] == "pypi"

    def test_version_default_is_pinned_to_pyproject(self) -> None:
        assert _load(ACTION)["inputs"]["version"]["default"] == _project_version()

    def test_install_pins_the_distribution_to_the_version(self) -> None:
        text = _steps_text(_load(ACTION)["runs"])
        assert 'pip install --quiet "aisafe[devtools]==${AISAFE_VERSION}"' in text
        for line in re.findall(r"pip install[^\n]*", text):
            if re.search(r"\baisafe(?:\[|==|\s|\"|$)", line):
                assert "==${AISAFE_VERSION}" in line, line
        assert '"${ACTION_PATH}[devtools]"' in text

    def test_audit_calls_tolerate_only_exit_1_and_the_exit_code_comes_from_the_json(self) -> None:
        text = _steps_text(_load(ACTION)["runs"])
        calls = re.findall(r'^\s*(aisafe audit "[^\n]*)', text, re.M)
        assert len(calls) == 3
        for call in calls:
            assert call.rstrip().endswith("|| [ $? -eq 1 ]"), call
            assert "--no-external" not in call
        assert "|| true" not in text
        assert 'report.get("kind") != "audit"' in text
        assert 'code = int(summary["exit_code"])' in text and "sys.exit(code)" in text

    def test_no_compliance_verdict_in_the_action_text(self) -> None:
        text = ACTION.read_text(encoding="utf-8").lower()
        for phrase in (
            " ".join(("is", "compliant")),
            "certi" + "fied",
            " ".join(("fully", "compliant")),
        ):
            assert phrase not in text, phrase
        assert "no compliance verdict" in text

    def test_third_party_actions_are_pinned_and_sarif_is_conditional(self) -> None:
        steps = _load(ACTION)["runs"]["steps"]
        for step in steps:
            if step.get("uses"):
                assert "@" in step["uses"], step["uses"]
        sarif = next(s for s in steps if "upload-sarif" in str(s.get("uses", "")))
        assert sarif["if"] == "inputs.upload-sarif == 'true'"
        comment = next(s for s in steps if "sticky-pull-request-comment" in str(s.get("uses", "")))
        assert "inputs.pr-comment == 'true'" in comment["if"]


class TestPreCommitHooks:
    def test_the_only_hook_is_the_audit(self) -> None:
        hooks = {h["id"]: h for h in _load(PRE_COMMIT_HOOKS)}
        assert set(hooks) == {"aisafe-audit"}
        audit = hooks["aisafe-audit"]
        assert audit["entry"] == "aisafe audit" and audit["language"] == "python"
        assert audit["pass_filenames"] is False and audit["always_run"] is True
        assert audit["stages"] == ["pre-push"]
        assert audit["args"] == ["--fail-on", "high"]
        assert "compliance verdict" in audit["description"]

    def test_the_hook_needs_only_tomli_on_old_pythons(self) -> None:
        hooks = {h["id"]: h for h in _load(PRE_COMMIT_HOOKS)}
        deps = hooks["aisafe-audit"]["additional_dependencies"]
        assert (
            len(deps) == 1 and deps[0].startswith("tomli") and "python_version < '3.11'" in deps[0]
        )

    def test_our_own_config_runs_the_audit_at_push_time_against_the_baseline(self) -> None:
        doc = _load(PRE_COMMIT_CONFIG)
        local = next(r for r in doc["repos"] if r["repo"] == "local")
        audit = next(h for h in local["hooks"] if h["id"] == "aisafe-audit")
        assert audit["entry"] == "aisafe audit"
        assert audit["stages"] == ["pre-push"]
        assert audit["args"][-2:] == ["--baseline", "audit-baseline.json"]
        assert "--fail-on" in audit["args"] and "high" in audit["args"]
        assert "--no-external" not in audit["args"]

    def test_our_own_config_keeps_the_companion_hooks_and_drops_the_removed_ones(self) -> None:
        doc = _load(PRE_COMMIT_CONFIG)
        ids = {h["id"] for repo in doc["repos"] for h in repo["hooks"]}
        assert ids == {"aisafe-audit", "detect-secrets", "ruff", "ruff-format", "pip-audit"}


class TestGitLabAuditJob:
    def test_job_present_with_variables_and_exit_1_tolerance(self) -> None:
        doc = _load(GITLAB)
        job = doc["aisafe-audit"]
        assert job["extends"] == ".aisafe-base"
        for key in ("AUDIT_PATH", "AUDIT_FAIL_ON", "AUDIT_BASELINE", "AISAFE_VERSION"):
            assert key in doc["variables"], key
        assert doc["variables"]["AUDIT_FAIL_ON"] == "high"
        scripts = job["script"]
        assert all(isinstance(entry, str) for entry in scripts)
        audit_calls = [s for s in scripts if s.startswith("aisafe audit")]
        assert len(audit_calls) == 2 and all(s.endswith("|| [ $? -eq 1 ]") for s in audit_calls)
        assert any("--format json" in s for s in audit_calls)
        assert any("--format sarif" in s for s in audit_calls)
        assert job["artifacts"]["reports"]["sast"] == "aisafe-audit-results.sarif"
        assert job["allow_failure"] is False

    def test_template_holds_only_the_base_and_the_audit_job(self) -> None:
        doc = _load(GITLAB)
        jobs = {key for key in doc if key not in ("stages", "variables")}
        assert jobs == {".aisafe-base", "aisafe-audit"}
        assert doc["stages"] == ["audit"]

    def test_base_installs_the_pinned_release(self) -> None:
        doc = _load(GITLAB)
        before = "\n".join(doc[".aisafe-base"]["before_script"])
        assert 'pip install --quiet "aisafe[devtools]==${AISAFE_VERSION}"' in before
        assert doc["variables"]["AISAFE_VERSION"] == _project_version()

    def test_exit_code_step_reads_the_json(self) -> None:
        job = _load(GITLAB)["aisafe-audit"]
        text = "\n".join(job["script"])
        assert 'report.get("kind") != "audit"' in text
        assert 'sys.exit(int(s["exit_code"]))' in text


class TestDogfoodJob:
    def test_tests_workflow_runs_the_action_from_the_action_path(self) -> None:
        jobs = _load(TESTS_WORKFLOW)["jobs"]
        job = jobs["action"]
        step = next(s for s in job["steps"] if s.get("uses") == "./")
        assert step["with"]["install-from"] == "action-path"
        assert step["with"]["baseline"] == "audit-baseline.json"
        assert step["with"]["fail-on"] == "high"
        assert step["with"]["upload-sarif"] == "false"
        text = _steps_text(job)
        assert 'test "$EXIT_CODE" -eq 0' in text
        assert 'test -f "$REPORT"' in text
