"""tests/unit/test_source_hygiene.py
---------------------------------
No tracked text file of the repository carries a control character other than a tab, a
line feed or a carriage return. A stray one is invisible in an editor and silently
changes what code does: run 4 of the persons study (research/log.md, 2026-10-30) found a
literal backspace inside a regular expression where `\\b` was meant, and the expression
never matched.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CONTROL = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
TEXT_SUFFIXES = {
    ".py",
    ".pyi",
    ".md",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".txt",
    ".html",
    ".js",
    ".ts",
    ".sh",
    ".ps1",
    ".cfg",
    ".ini",
}


def _tracked() -> list[Path]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=REPO,
            capture_output=True,
            check=True,
            timeout=60,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        pytest.skip("git is not available to list the tracked files")
    names = [n for n in out.decode("utf-8", "replace").split("\0") if n]
    return [REPO / n for n in names if Path(n).suffix.lower() in TEXT_SUFFIXES]


def test_no_tracked_text_file_carries_a_control_character() -> None:
    bad = []
    for path in _tracked():
        try:
            data = path.read_bytes()
        except OSError:
            continue
        match = CONTROL.search(data)
        if match:
            line = data.count(b"\n", 0, match.start()) + 1
            bad.append(f"{path.relative_to(REPO).as_posix()}:{line}: {match.group()!r}")
    assert bad == [], bad
