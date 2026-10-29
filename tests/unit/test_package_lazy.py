"""tests/unit/test_package_lazy.py
--------------------------------
`import aisafe` must pay for nothing it does not run: the engine, the policy and the
finding types load on first attribute access (PEP 562), so `aisafe --help` and the console
script start fast and a user who only wants `aisafe.Finding` does not import the walker.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import aisafe

SRC = Path(aisafe.__file__).resolve().parents[1]


def _fresh_interpreter(code: str) -> str:
    env = dict(os.environ, PYTHONPATH=str(SRC), PYTHONIOENCODING="utf-8")
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, env=env
    )
    return result.stdout.strip()


def test_import_aisafe_loads_no_engine_module() -> None:
    code = (
        "import sys, aisafe; "
        "print(sorted(m for m in sys.modules if m.startswith('aisafe.') "
        "and not m.startswith('aisafe.__')))"
    )
    assert _fresh_interpreter(code) == "[]"


def test_lazy_attributes_resolve_to_the_real_objects_and_stick() -> None:
    from aisafe.evidence.model import Decision, Finding, Report
    from aisafe.policy import load_policy

    assert aisafe.Finding is Finding
    assert aisafe.Report is Report
    assert aisafe.Decision is Decision
    assert aisafe.load_policy is load_policy
    # Resolved once, then an ordinary module attribute.
    assert "Finding" in vars(aisafe)


def test_lazy_names_stay_in_all_and_dir() -> None:
    expected = {"run_audit", "load_policy", "Finding", "Report", "Decision", "EvidenceStatus"}
    assert expected <= set(aisafe.__all__)
    assert expected <= set(dir(aisafe))


def test_every_public_name_resolves() -> None:
    for name in aisafe.__all__:
        assert getattr(aisafe, name) is not None


def test_version_is_a_string() -> None:
    assert isinstance(aisafe.__version__, str) and aisafe.__version__.count(".") == 2


def test_unknown_attribute_still_raises() -> None:
    with pytest.raises(AttributeError, match="NoSuchThing"):
        aisafe.NoSuchThing  # noqa: B018
