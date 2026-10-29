"""src/aisafe/evidence/artifacts.py
--------------------------------
Content hashes for the files a finding or a review record points at.

A finding names the exact version of each artifact it rests on (`ArtifactRef(file,
sha256)`), and a review record binds the reviewer's decision to the same hashes, so a
prompt edited after the review reads as stale, and a report can be matched to the text it
described. The hash is over the file's bytes as stored; the walk's reader is not used
here because the hash has to agree with what `aisafe review init` computed on the same
file, with or without a BOM.

    sha256_of(Path("prompts/system.md"))        # full 64-hex digest, or None when unreadable
    artifact_refs(root, ["prompts/system.md"])  # [ArtifactRef(...)], unreadable files skipped
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterable

from aisafe.evidence.model import ArtifactRef

__all__ = ["artifact_refs", "sha256_of", "short"]

_CHUNK = 1 << 16


def sha256_of(path: Path) -> str | None:
    """Full hex sha256 of the file's bytes; None when the file cannot be read."""
    digest = hashlib.sha256()
    try:
        with Path(path).open("rb") as handle:
            while True:
                chunk = handle.read(_CHUNK)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def short(digest: str | None, length: int = 12) -> str:
    """The first characters of a digest, for a rendered line; `-` when there is none."""
    return digest[:length] if digest else "-"


def artifact_refs(root: Path, relpaths: Iterable[str]) -> list[ArtifactRef]:
    """One `ArtifactRef` per readable relpath, sorted by path, duplicates dropped."""
    out: list[ArtifactRef] = []
    seen: set[str] = set()
    for relpath in sorted(set(str(p).replace("\\", "/") for p in relpaths)):
        if relpath in seen or not relpath or relpath == ".":
            continue
        seen.add(relpath)
        digest = sha256_of(Path(root) / relpath)
        if digest is None:
            continue
        out.append(ArtifactRef(file=relpath, sha256=digest))
    return out
