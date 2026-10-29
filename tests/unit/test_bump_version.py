"""tests/unit/test_bump_version.py
--------------------------------
`scripts/bump_version.py` keeps every version string equal to pyproject's. These
tests pin that the committed tree agrees with itself, that the sites are exactly the
five of the pivoted product, that a disagreement is named by file, that the tag check
works both ways, and that the CHANGELOG carries the current version's section (the
release notes come from it).
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import re
import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "bump_version.py"

# The places the version lives, in the order they are rewritten. The lint reporter, the
# misalignment checker and their templates were removed with the pivot and are no sites.
EXPECTED_SITES = (
    "pyproject.toml",
    "src/aisafe/__init__.py",
    ".gitlab-ci-aisafe.yml",
    "action.yml",
    "plugins/aisafe/.claude-plugin/plugin.json",
)


def _load():
    spec = importlib.util.spec_from_file_location("bump_version", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules.setdefault("bump_version", module)
    spec.loader.exec_module(module)
    return module


bump_version = _load()


def _copy_sites(dest: Path) -> None:
    """The version sites and the CHANGELOG, copied into a scratch root."""
    for site in bump_version.SITES:
        src = REPO / site.relpath
        if not src.is_file():
            continue
        target = dest / site.relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, target)
    shutil.copyfile(REPO / "CHANGELOG.md", dest / "CHANGELOG.md")


def test_committed_tree_is_in_sync() -> None:
    assert bump_version.check(REPO) == []


def test_sites_are_exactly_the_five_of_the_pivot() -> None:
    relpaths = tuple(site.relpath for site in bump_version.SITES)
    assert relpaths == EXPECTED_SITES
    for relpath in relpaths:
        for removed in ("reporters.py", "euaiact", "misalign", "controls", "levels"):
            assert removed not in relpath, relpath


def test_every_site_exists_in_this_checkout() -> None:
    for site in bump_version.SITES:
        assert site.path(REPO).is_file(), site.relpath


def test_every_mandatory_site_matches_its_pattern() -> None:
    for site, found in bump_version.site_versions(REPO):
        assert found is not None, site.relpath
        assert bump_version.VERSION_RE.match(found), (site.relpath, found)


def test_gitlab_template_pin_is_a_site() -> None:
    """The template installs `aisafe[devtools]==${AISAFE_VERSION}`; that pin must move with
    the release or every consumer installs the previous version."""
    versions = {site.relpath: found for site, found in bump_version.site_versions(REPO)}
    assert versions[".gitlab-ci-aisafe.yml"] == bump_version.project_version(REPO)


def test_changelog_has_the_current_version_heading() -> None:
    version = bump_version.project_version(REPO)
    assert version in bump_version.changelog_versions(REPO)
    section = bump_version.changelog_section(f"v{version}", REPO)
    assert section.strip()
    assert not re.search(r"^\[[^\]]+\]:\s+http", section, re.M)  # link refs stripped


def test_tag_must_match_pyproject() -> None:
    version = bump_version.project_version(REPO)
    assert bump_version.check(REPO, tag=f"v{version}") == []
    problems = bump_version.check(REPO, tag="v9.9.9")
    assert problems and "tag v9.9.9" in problems[0]


def test_a_drifted_site_is_named(tmp_path: Path) -> None:
    _copy_sites(tmp_path)
    init = tmp_path / "src/aisafe/__init__.py"
    init.write_text(
        init.read_text("utf-8").replace('__version__ = "', '__version__ = "9.'), "utf-8"
    )
    problems = bump_version.check(tmp_path)
    assert len(problems) == 1
    assert problems[0].startswith("src/aisafe/__init__.py: says 9.")


def test_a_drifted_gitlab_pin_is_named(tmp_path: Path) -> None:
    _copy_sites(tmp_path)
    template = tmp_path / ".gitlab-ci-aisafe.yml"
    template.write_text(
        re.sub(
            r'(AISAFE_VERSION:\s*")([^"]+)(")',
            lambda m: f"{m.group(1)}0.0.1{m.group(3)}",
            template.read_text("utf-8"),
            count=1,
        ),
        "utf-8",
    )
    problems = bump_version.check(tmp_path)
    version = bump_version.project_version(tmp_path)
    assert problems == [f".gitlab-ci-aisafe.yml: says 0.0.1, pyproject says {version}"]


def test_bump_rewrites_every_site_and_retitles_the_changelog(tmp_path: Path) -> None:
    _copy_sites(tmp_path)
    old = bump_version.project_version(tmp_path)
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        changelog.read_text("utf-8").replace(
            "## [Unreleased]\n", "## [Unreleased]\n\n### Added\n\n- A thing.\n", 1
        ),
        "utf-8",
    )
    changed = bump_version.bump("9.8.7", tmp_path, today=dt.date(2030, 1, 2))
    assert "pyproject.toml" in changed and "CHANGELOG.md" in changed
    assert set(changed) >= set(EXPECTED_SITES)
    assert bump_version.project_version(tmp_path) == "9.8.7"
    assert bump_version.check(tmp_path) == []
    text = changelog.read_text("utf-8")
    assert "## [9.8.7] - 2030-01-02\n\n### Added\n\n- A thing." in text
    assert f"## [{old}]" in text  # the previous release keeps its section
    assert "[9.8.7]: https://github.com/ai-safe-earth/AnyAISafe/releases/tag/v9.8.7" in text
    assert "compare/v9.8.7...HEAD" in text
    assert text.count("## [Unreleased]") == 1


def test_bump_refuses_a_non_version(tmp_path: Path) -> None:
    _copy_sites(tmp_path)
    with pytest.raises(SystemExit):
        bump_version.bump("latest", tmp_path)


def test_cli_check_and_section(capsys: pytest.CaptureFixture[str]) -> None:
    assert bump_version.main(["--check"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("in sync: version ")
    assert f"at {len(EXPECTED_SITES)} sites" in out
    version = bump_version.project_version(REPO)
    assert bump_version.main(["--changelog-section", f"v{version}"]) == 0
    assert capsys.readouterr().out.strip()
    assert bump_version.main(["--changelog-section", "v0.0.0"]) == 1


def test_optional_sites_are_the_action_and_the_plugin() -> None:
    optional = {s.relpath for s in bump_version.SITES if s.optional}
    assert optional == {"action.yml", "plugins/aisafe/.claude-plugin/plugin.json"}
