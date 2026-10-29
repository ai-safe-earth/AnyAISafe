"""src/aisafe/discovery/configs.py
-------------------------------
Structured loaders for the files discovery reads whole: JSON, TOML and YAML through
json / tomllib / yaml.safe_load, never by regex over the body, plus the YAML frontmatter
of an agent file (`agents/*.md`, `.claude/agents/*.md`).

Error handling: a loader given invalid input returns `(None, "<reason>")` and never
raises. `parse_error(path, text)` is the one-line message to record in an UnknownItem
when a file the audit wanted to read could not be parsed.
"""

from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import Any

import yaml

from aisafe.evidence.model import truncate_snippet

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

__all__ = [
    "load_structured",
    "parse_agent_frontmatter",
    "parse_error",
]

_FORMAT_BY_EXT = {".json": "json", ".toml": "toml", ".yaml": "yaml", ".yml": "yaml"}


def _posix(path: str) -> str:
    return str(path).replace("\\", "/")


def _basename(path: str) -> str:
    return PurePosixPath(_posix(path)).name


def _format_for(path: str) -> str | None:
    return _FORMAT_BY_EXT.get(PurePosixPath(_posix(path)).suffix.lower())


def _load(path: str, text: str) -> tuple[Any, str | None]:
    """Parse `text` by the file's extension. Returns (data, error); data is None on error."""
    fmt = _format_for(path)
    try:
        if fmt == "json":
            return json.loads(text), None
        if fmt == "toml":
            if tomllib is None:
                return None, "tomllib unavailable on this interpreter (install tomli)"
            return tomllib.loads(text), None
        if fmt == "yaml":
            return yaml.safe_load(text), None
    except Exception as exc:  # json/toml/yaml raise their own hierarchies
        return None, f"{exc.__class__.__name__}: {truncate_snippet(str(exc), 200)}"
    return None, f"unsupported config format: {_basename(path)}"


def _load_mapping(path: str, text: str) -> dict[str, Any] | None:
    data, error = _load(path, text)
    if error is not None or not isinstance(data, dict):
        return None
    return data


def load_structured(path: str, text: str) -> tuple[Any, str | None]:
    """The parsed JSON / TOML / YAML value of `text` and None, or (None, reason).

    The public spelling of `_load` for the modules outside discovery (the review records
    reader, the evaluation report reader) that want one loader for every format.
    """
    return _load(path, text)


def parse_error(path: str, text: str) -> str | None:
    """The reason a config could not be parsed, or None when it parses to a mapping."""
    data, error = _load(path, text)
    if error is not None:
        return error
    if not isinstance(data, dict):
        return f"top-level value is {type(data).__name__}, expected a mapping"
    return None


def parse_agent_frontmatter(path: str, text: str) -> dict[str, Any]:
    """YAML frontmatter of an agent or model-card markdown file; {} when absent or invalid.

    `tools` is normalised to a list of str (a comma-separated string is split), so a
    reader never has to care which spelling the host accepted.
    """
    del path  # kept for symmetry with the other loaders; the format is fixed here
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    end = next((i for i, line in enumerate(lines[1:], 1) if line.strip() in ("---", "...")), None)
    if end is None:
        return {}
    try:
        data = yaml.safe_load("\n".join(lines[1:end]))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    out = dict(data)
    if "tools" in out:
        tools = out["tools"]
        if isinstance(tools, str):
            out["tools"] = [part.strip() for part in tools.split(",") if part.strip()]
        elif isinstance(tools, (list, tuple)):
            out["tools"] = [str(item).strip() for item in tools if item is not None]
        else:
            out["tools"] = []
    return out
