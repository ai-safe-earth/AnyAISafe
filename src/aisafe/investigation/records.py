"""src/aisafe/investigation/records.py
------------------------------------
The investigation record (`aisg/investigation/1`) and the skeptic pass
(`aisg/skeptic/1`): the two file formats through which reasoning done in a host coding
agent enters aisafe. Nothing here judges a record; `validate.py` does that, mechanically.

An investigation record is one JSON file per investigation of one hypothesis on one
surface: the mechanism and the policy pattern it tests, the links it cites (each with a
quote and the cited file's content hash), the counterevidence it weighed, the controls it
checked on the path, what it could not establish, the evidence status and decision it
proposes, the steps that would verify a fix, who investigated (agent, model, version,
session) and the result of a skeptic pass run in a fresh context. The full field list is
`references/investigate.md` in the packaged skill.

A skeptic pass is its own file, bound to the record by `record_sha256`: the sha256 of the
record's canonical JSON with its `skeptic` block left out (`record_digest`). A skeptic
result counts only when that hash matches and the skeptic ran in a different session from
the investigator.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from pathlib import Path
from typing import Any

__all__ = [
    "COUNTER_RESULTS",
    "HOW",
    "ID_RE",
    "INVESTIGATION_KIND",
    "INVESTIGATION_SCHEMA",
    "ON_PATH",
    "RECORD_DIR",
    "SHA_RE",
    "SIGNOFF_KIND",
    "SIGNOFF_SCHEMA",
    "SKEPTIC_KIND",
    "SKEPTIC_RESULTS",
    "SKEPTIC_SCHEMA",
    "STEP_KINDS",
    "STEP_PURPOSES",
    "VERDICT_WORDS",
    "RecordError",
    "fold_text",
    "load_json",
    "record_digest",
    "verdict_words_in",
]

INVESTIGATION_SCHEMA = "aisg/investigation/1"
INVESTIGATION_KIND = "investigation"
SKEPTIC_SCHEMA = "aisg/skeptic/1"
SKEPTIC_KIND = "skeptic"
# A person's decision, read by `aisafe.investigation.signoff`.
SIGNOFF_SCHEMA = "aisg/signoff/1"
SIGNOFF_KIND = "signoff"
# Where the skill keeps records in self-assessment mode; an auditor keeps them in the
# engagement directory, outside the audited tree.
RECORD_DIR = ".aisafe-audit/investigations"

# How a link was established by the investigator: `read` (the cited line says it),
# `traced` (callers, imports, branches or configuration were followed to it; the `via`
# hops cite the way), `runtime-only` (the cited line shows where a runtime value comes
# from, and the value itself is not in the tree).
HOW: tuple[str, ...] = ("read", "traced", "runtime-only")
ON_PATH: tuple[str, ...] = ("yes", "no", "unknown")
SKEPTIC_RESULTS: tuple[str, ...] = ("upheld", "refuted", "not_run")
COUNTER_RESULTS: tuple[str, ...] = ("supported", "refuted")
STEP_PURPOSES: tuple[str, ...] = ("remediation", "regression")
# `absent`/`present`: a quote is absent from, or present in, a file. `no_finding`: the
# scan reports no finding of a rule (in a file). `evaluation`: a fresh evaluation report
# in the tree passes a scenario family. `reinvestigate`: a person or agent reads again;
# never passes mechanically.
STEP_KINDS: tuple[str, ...] = ("absent", "present", "no_finding", "evaluation", "reinvestigate")

ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")

# A record proposes an evidence status and a decision. Its free text says what was read;
# it never pronounces the system safe or compliant.
VERDICT_WORDS: tuple[str, ...] = (
    "compliant",
    "compliance verified",
    "certified",
    "meets the requirements",
    "is safe",
    "safe to deploy",
    "risk-free",
    "no risk",
    "guaranteed",
)
_VERDICT_RE = re.compile(
    r"(?<![A-Za-z])(?:" + "|".join(re.escape(w) for w in VERDICT_WORDS) + r")(?![A-Za-z])",
    re.I,
)
_SPACE_RE = re.compile(r"\s+")


class RecordError(Exception):
    """A record or skeptic file cannot be read as JSON of the expected shape."""


def load_json(path: Path) -> Any:
    """Parse `path` as JSON (UTF-8, BOM tolerated). Raises RecordError. A document that
    cannot be written back as UTF-8 (a lone surrogate from a `\\ud800` escape) is refused
    here, so nothing downstream has to carry text it cannot print or hash."""
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise RecordError(f"{Path(path).as_posix()}: {exc.strerror or exc}") from exc
    except UnicodeDecodeError as exc:
        raise RecordError(f"{Path(path).as_posix()}: not UTF-8 ({exc.reason})") from exc
    try:
        document = json.loads(text)
        json.dumps(document, ensure_ascii=False).encode("utf-8")
    except json.JSONDecodeError as exc:
        raise RecordError(f"{Path(path).as_posix()}: invalid JSON ({exc.msg})") from exc
    except RecursionError as exc:
        raise RecordError(f"{Path(path).as_posix()}: nested too deeply to read") from exc
    except UnicodeEncodeError as exc:
        raise RecordError(f"{Path(path).as_posix()}: holds a lone surrogate") from exc
    except ValueError as exc:  # an integer past Python's limit on digits
        raise RecordError(f"{Path(path).as_posix()}: holds a number too long to read") from exc
    return document


def record_digest(record: dict[str, Any]) -> str:
    """sha256 of the record's canonical JSON (keys sorted, no whitespace, UTF-8) with its
    `skeptic` block left out: what a skeptic file names in `record_sha256`."""
    body = {key: value for key, value in record.items() if key != "skeptic"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()


def fold_text(text: str) -> str:
    """`text` as a check reads it, never as it is kept: compatibility forms undone (NFKD, so
    a fullwidth or mathematical letter is the plain one), combining marks and format
    characters gone. An accent or a hidden character cannot step around a list of words."""
    if text.isascii():
        return text
    return "".join(
        char
        for char in unicodedata.normalize("NFKD", text)
        if unicodedata.category(char)[0] != "M" and unicodedata.category(char) != "Cf"
    )


def verdict_words_in(text: str) -> list[str]:
    """The verdict phrases `text` holds, lowercased, in order of appearance, however their
    words are spaced. Reads the fold: an accent on a verdict is still a verdict."""
    spaced = _SPACE_RE.sub(" ", fold_text(text or ""))
    return [match.group(0).lower() for match in _VERDICT_RE.finditer(spaced)]
