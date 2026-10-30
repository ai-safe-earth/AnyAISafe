"""src/aisafe/engagement/bundle.py
-------------------------------
The bundle manifest (`aisg/bundle/1`) `aisafe assess` writes next to its outputs: the
target commit, the mode, and the sha256 of every input it read and every output it
wrote, so anyone holding the files can check that none changed. Paths are relative to the
manifest's directory where they can be, so an engagement directory can be moved whole.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Sequence

from aisafe.engagement.model import BUNDLE_KIND, BUNDLE_SCHEMA, file_sha256
from aisafe.evidence.model import now_iso

__all__ = ["build_bundle", "hash_now", "verify_bundle"]

_NOTE = (
    "sha256 of each file's bytes as read (what sha256sum prints). The audited tree is named "
    "by its commit; its files are not listed. A file that no longer matches its sha256 is "
    "not the file the assessment read or wrote."
)


def _relative(path: Path, base: Path) -> str:
    try:
        return Path(os.path.relpath(path.resolve(), base.resolve())).as_posix()
    except ValueError:  # another drive on Windows
        return path.resolve().as_posix()


def hash_now(items: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """The items with the sha256 of each file as it is now. The CLI calls it on the inputs
    before writing any output, so an input the run also writes is hashed as it was read."""
    out = []
    for item in items:
        try:
            digest: str | None = file_sha256(Path(item["path"]))
        except OSError:
            digest = None
        out.append({**item, "sha256": digest})
    return out


def _entries(items: Sequence[dict[str, Any]], base: Path) -> list[dict[str, Any]]:
    out = []
    seen: set[tuple[str, str]] = set()
    for item in items:
        path = Path(item["path"])
        key = (item["role"], path.resolve().as_posix())
        if key in seen:
            continue
        seen.add(key)
        if "sha256" in item:
            digest = item["sha256"]
        else:
            try:
                digest = file_sha256(path)
            except OSError:
                digest = None
        out.append(
            {
                "role": item["role"],
                "path": _relative(path, base),
                "sha256": digest,
                **({"missing": True} if digest is None else {}),
            }
        )
    return out


def _entries_with_paths(
    items: Sequence[dict[str, Any]], base: Path
) -> list[tuple[dict[str, Any], str]]:
    entries = _entries(items, base)
    paths = []
    seen: set[tuple[str, str]] = set()
    for item in items:
        key = (item["role"], Path(item["path"]).resolve().as_posix())
        if key in seen:
            continue
        seen.add(key)
        paths.append(key[1])
    return list(zip(entries, paths))


def _rewritten(
    entries: list[dict[str, Any]], outputs: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Mark the inputs this run also wrote (the evidence requests): their hash is the file
    as read, and the file now holds what the run wrote over it."""
    written = {Path(item["path"]).resolve().as_posix() for item in outputs}
    out = []
    for entry, path in entries:
        out.append({**entry, "rewritten": True} if path in written else entry)
    return out


def build_bundle(
    *,
    bundle_dir: Path,
    document: dict[str, Any],
    inputs: Sequence[dict[str, Any]],
    outputs: Sequence[dict[str, Any]],
    engagement_dir: Path | None,
) -> dict[str, Any]:
    target = document.get("target") or {}
    return {
        "schema": BUNDLE_SCHEMA,
        "kind": BUNDLE_KIND,
        "generated_at": now_iso(),
        "mode": document.get("mode"),
        "label": document.get("label"),
        "target": {
            "path": target.get("path"),
            "commit": target.get("commit"),
            "dirty": list(target.get("dirty") or []),
            "working_tree": target.get("working_tree"),
        },
        "engagement": None
        if engagement_dir is None
        else _relative(Path(engagement_dir), Path(bundle_dir)),
        "inputs": _rewritten(_entries_with_paths(inputs, Path(bundle_dir)), outputs),
        "outputs": _entries(outputs, Path(bundle_dir)),
        "note": _NOTE,
    }


def verify_bundle(path: Path) -> list[dict[str, Any]]:
    """Each entry of the manifest at `path` with its state now: intact, changed or missing."""
    import json

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    base = Path(path).parent
    rows = []
    for group in ("inputs", "outputs"):
        for entry in data.get(group) or []:
            file = (
                base / entry["path"]
                if not Path(entry["path"]).is_absolute()
                else Path(entry["path"])
            )
            try:
                now: str | None = file_sha256(file)
            except OSError:
                now = None
            if entry.get("rewritten"):
                # Read, then written over by the same run: the output entry vouches for it.
                state = "rewritten"
            elif now is None:
                state = "missing"
            elif entry.get("sha256") == now:
                state = "intact"
            else:
                state = "changed"
            rows.append({"group": group, **entry, "state": state})
    return rows
