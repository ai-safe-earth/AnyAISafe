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
# it never pronounces the system safe or compliant. The last three are stems, matched at
# the start of a word in any of its forms: the French and English "certifi-", the German
# "zertifiz-" and "konform". Other words in other languages are not listed: "seguro",
# "sicher" or "conforme" have everyday meanings, and refusing them would refuse honest text.
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
    "certifi",
    "zertifiz",
    "konform",
)
_VERDICT_STEMS: frozenset[str] = frozenset({"certifi", "zertifiz", "konform"})
_VERDICT_RE = re.compile(
    r"(?<![A-Za-z])(?:(?:"
    + "|".join(re.escape(w) for w in VERDICT_WORDS if w not in _VERDICT_STEMS)
    + r")(?![A-Za-z])|(?:"
    + "|".join(re.escape(w) for w in VERDICT_WORDS if w in _VERDICT_STEMS)
    + r")[A-Za-z]*)",
    re.I,
)
# Letters drawn like Latin ones that NFKD leaves as they are: Cyrillic and Greek capitals
# and small letters, Latin small capitals, and the dotless i and j. "the system \u0456\u0455
# safe" holds no word that mixes two alphabets, and still reads as a verdict. Only the word
# lists read through this table (the verdict words, the tool names, the banned phrases);
# the alphabet-mix check reads the plain fold, so a name in Cyrillic or Greek stays a name.
_LOOKALIKES = str.maketrans(
    # Cyrillic capitals, then small letters.
    "\u0410\u0412\u0415\u041a\u041c\u041d\u041e\u0420\u0421\u0422\u0423\u0425\u0405"
    "\u0406\u0408\u04ae\u04ba\u04c0\u051a\u051c"
    "\u0430\u0432\u0435\u043a\u043c\u043d\u043e\u0440\u0441\u0442\u0443\u0445\u0455"
    "\u0456\u0458\u04af\u04bb\u04cf\u0501\u051b\u051d"
    # Greek capitals, then small letters.
    "\u0391\u0392\u0395\u0396\u0397\u0399\u039a\u039c\u039d\u039f\u03a1\u03a4\u03a5"
    "\u03a7\u03f9\u037f"
    "\u03b1\u03b3\u03b5\u03b7\u03b9\u03ba\u03bd\u03bf\u03c1\u03c4\u03c5\u03c7\u03f2"
    "\u03f3"
    # Latin small capitals A to Z (no X), then the dotless i and j, alpha and script g.
    "\u1d00\u0299\u1d04\u1d05\u1d07\ua730\u0262\u029c\u026a\u1d0a\u1d0b\u029f\u1d0d"
    "\u0274\u1d0f\u1d18\ua7af\u0280\ua731\u1d1b\u1d1c\u1d20\u1d21\u028f\u1d22"
    "\u0131\u0237\u0251\u0261",
    "ABEKMHOPCTYXSIJYHIQW"
    "abekmhopctyxsijyhldqw"
    "ABEZHIKMNOPTYXCJ"
    "ayenikvoptuxcj"
    "abcdefghijklmnopqrstuvwyz"
    "ijag",
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


def fold_text(text: str, *, lookalikes: bool = False) -> str:
    """`text` as a check reads it, never as it is kept: compatibility forms undone (NFKD, so
    a fullwidth or mathematical letter is the plain one), combining marks and format
    characters gone. An accent or a hidden character cannot step around a list of words.
    With `lookalikes`, a Cyrillic, Greek or small-capital letter drawn like a Latin one is
    that Latin letter too (`_LOOKALIKES`): for the word lists only, never for the check of
    alphabets mixed inside a word, which would then see none."""
    if text.isascii():
        return text
    folded = "".join(
        char
        for char in unicodedata.normalize("NFKD", text)
        if unicodedata.category(char)[0] != "M" and unicodedata.category(char) != "Cf"
    )
    return folded.translate(_LOOKALIKES) if lookalikes else folded


def verdict_words_in(text: str) -> list[str]:
    """The verdict phrases `text` holds, lowercased, in order of appearance, however their
    words are spaced; a stem gives the whole word it starts. Reads the fold with lookalike
    letters as Latin ones: an accent, a small capital or a Cyrillic letter on a verdict is
    still a verdict. Text in other languages is accepted and not checked for verdicts,
    beyond the three stems of `VERDICT_WORDS`."""
    spaced = _SPACE_RE.sub(" ", fold_text(text or "", lookalikes=True))
    return [match.group(0).lower() for match in _VERDICT_RE.finditer(spaced)]
