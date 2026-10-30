"""tests/unit/test_migration_surface.py
------------------------------------
The pivot's completion criteria that can be pinned on the tree: no active module imports a
removed package, no legacy rule id (AUD-101..AUD-1003) survives in `src/`, the console
script lists exactly the focused commands, and the documents the migration promises exist.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src" / "aisafe"

REMOVED_PACKAGES = (
    "aisafe.core",
    "aisafe.modules",
    "aisafe.integrations",
    "aisafe.config",
    "aisafe.devtools.audit",
    "aisafe.probes",
)
LEGACY_RULE_ID = re.compile(r"\bAUD-(?:[1-9]\d{2}|10\d{2})\b")  # AUD-101 .. AUD-1099
PY_FILES = sorted(p for p in SRC.rglob("*.py") if "__pycache__" not in p.parts)


@pytest.mark.parametrize("path", PY_FILES, ids=lambda p: p.relative_to(SRC).as_posix())
def test_no_module_imports_a_removed_package(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for package in REMOVED_PACKAGES:
        assert not re.search(rf"(?m)^\s*(?:from|import)\s+{re.escape(package)}\b", text), (
            f"{path.relative_to(REPO)} imports {package}"
        )


@pytest.mark.parametrize("path", PY_FILES, ids=lambda p: p.relative_to(SRC).as_posix())
def test_no_legacy_rule_id_in_src(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert not LEGACY_RULE_ID.search(text), f"{path.relative_to(REPO)} names a P1-P10 rule id"


def test_no_removed_package_directory_exists() -> None:
    for name in ("core", "modules", "integrations", "config", "probes"):
        assert not (SRC / name).exists(), name
    assert not (SRC / "devtools" / "audit").exists()


def test_console_commands_are_exactly_the_focused_set() -> None:
    from aisafe import cli

    assert set(cli.COMMANDS) == {
        "audit",
        "investigate",
        "assess",
        "review",
        "evaluate",
        "fleet",
        "skill",
        "probe",
    }
    for removed in ("lint", "misalign", "init", "measure", "decide", "hook", "attest"):
        assert removed not in cli.COMMANDS


def test_help_lists_the_public_commands_and_hides_the_alias(capsys) -> None:
    from aisafe import cli

    assert cli.main([]) == 2
    out = capsys.readouterr().out
    for name in ("audit", "investigate", "assess", "review", "evaluate", "fleet", "skill"):
        assert f"  {name} " in out, name
    for removed in ("lint ", "misalign", "measure", "decide", "hook", "attest", " init "):
        assert removed not in out, removed


def test_migration_documents_exist_and_name_the_legacy_refs() -> None:
    migration = (REPO / "docs" / "migration.md").read_text(encoding="utf-8")
    assert "legacy/broad-product" in migration and "legacy/pre-pivot-0.1.0" in migration
    assert "dc2dfcb" in migration
    for path in (
        "docs/methodology.md",
        "docs/architecture.md",
        "docs/rules.md",
        "policy/charter.md",
    ):
        assert (REPO / path).is_file(), path
    architecture = (REPO / "docs" / "architecture.md").read_text(encoding="utf-8")
    assert architecture.count("```mermaid") >= 2
