"""src/aisafe/legal/profile.py
---------------------------
Load and check the legal profiles (`aisg/legal-profile/1`) shipped in
`aisafe/legal/profiles/`.

A profile is one law: where its text was read (`source`: URL, version, `checked_on`), who
reviewed it (`legal_review`, `{by: null, date: null}` until a lawyer has), the conditions
under which it applies, and its provisions. A provision quotes its text verbatim from the
source, says when it is in force (a date the law states, or a derived one, flagged), the
mechanisms it links to, the code, evaluation and organisational evidence a result needs,
the testable controls and procedures, and the legal elements no code can show
(`specialist`). A provision whose text could not be checked against its source is
`verified: false` and never reads better than requires_specialist_review.

Conditions read the engagement's applicability answers: `{answer, includes | includes_any |
equals [, false_if]}` and `{definition}` / `{definitions_any}` (the auditor's reading of a
scope definition, with a reason). Selecting a jurisdiction only selects the profile; no
condition reads `jurisdictions`.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Iterable, Sequence

import yaml

__all__ = [
    "ANSWER_VALUES",
    "APPLICABILITY",
    "DEFINITION_ANSWERS",
    "LIST_ANSWERS",
    "PROFILES_DIR",
    "PROFILE_KIND",
    "PROFILE_SCHEMA",
    "RESULTS",
    "LegalProfile",
    "ProfileError",
    "check_profile",
    "definition_questions",
    "load_profiles",
]

PROFILE_SCHEMA = "aisg/legal-profile/1"
PROFILE_KIND = "legal-profile"
PROFILES_DIR = Path(__file__).resolve().parent / "profiles"

# Least favourable first: the order a summary reads them in.
RESULTS: tuple[str, ...] = (
    "gap_identified",
    "insufficient_evidence",
    "requires_specialist_review",
    "satisfied_within_scope",
    "not_applicable",
)
APPLICABILITY: tuple[str, ...] = ("applies", "does_not_apply", "undetermined")
DEFINITION_ANSWERS: tuple[str, ...] = ("meets", "does_not_meet", "unknown")
CODE_KINDS: tuple[str, ...] = ("control", "closed", "indicators")
CEILINGS: tuple[str, ...] = ("requires_specialist_review",)

# The applicability answers a condition can read and the values each takes; None means
# free codes ("EU", "US-NY", ...). "unknown" is always allowed and never decides.
ANSWER_VALUES: dict[str, tuple[str, ...] | None] = {
    "markets": None,
    "roles": ("provider", "deployer", "operator", "unknown"),
    "minors": ("known", "none_known", "unknown"),
    "age_assurance": ("none", "self_declaration", "age_estimation", "age_verification", "unknown"),
    "eu_placement": ("placed_on_market", "put_into_service", "used", "none", "unknown"),
}
LIST_ANSWERS = frozenset({"markets", "roles", "eu_placement"})

_ID = re.compile(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$")
_DEFINITION_ID = re.compile(r"^[a-z0-9-]+/[a-z0-9-]+$")
_ITEM_ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class ProfileError(ValueError):
    """A shipped legal profile cannot be used. One line; the CLI maps it to exit 2."""


@dataclass(frozen=True)
class LegalProfile:
    id: str
    title: str
    jurisdiction: str
    path: Path
    sha256: str
    data: dict[str, Any]

    @property
    def reviewed(self) -> bool:
        review = self.data.get("legal_review") or {}
        return bool(review.get("by")) and bool(review.get("date"))


def _iso(value: Any) -> str | None:
    """A date as YAML gives it (a `date`, or a string) as an ISO string; None when it is not
    one."""
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, str):
        try:
            return date.fromisoformat(value).isoformat()
        except ValueError:
            return None
    return None


def _normalise(value: Any) -> Any:
    """The profile with every date as an ISO string, so the assessment can carry it as JSON."""
    if isinstance(value, dict):
        return {k: _normalise(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalise(v) for v in value]
    if isinstance(value, date):
        return value.isoformat()
    return value


def _families() -> set[str]:
    corpus = Path(__file__).resolve().parent.parent / "evaluation" / "corpus"
    return {p.stem for p in corpus.glob("*.yaml")}


class _Check:
    def __init__(self, where: str) -> None:
        self.where = where
        self.errors: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(f"{self.where}: {message}")

    def text(self, value: Any, what: str) -> bool:
        if not isinstance(value, str) or not value.strip():
            self.error(f"`{what}` must be non-empty text")
            return False
        return True

    def texts(self, value: Any, what: str) -> None:
        if not isinstance(value, list):
            self.error(f"`{what}` must be a list")
            return
        for index, item in enumerate(value):
            self.text(item, f"{what}[{index}]")


def _quote(check: _Check, value: Any, what: str, sources: set[str]) -> None:
    if not isinstance(value, dict):
        check.error(f"`{what}` must be a quote: cite, source, excerpt, url, quote")
        return
    for key in ("cite", "excerpt", "quote"):
        check.text(value.get(key), f"{what}.{key}")
    if value.get("source") not in sources:
        check.error(f"`{what}.source` names no source of the profile: {value.get('source')!r}")
    url = value.get("url")
    if not isinstance(url, str) or not url.startswith("https://"):
        check.error(f"`{what}.url` must be an https URL")


def _condition(check: _Check, cond: Any, what: str, sources: set[str]) -> None:
    if not isinstance(cond, dict):
        check.error(f"`{what}` must be a condition object")
        return
    check.text(cond.get("why"), f"{what}.why")
    if "quote" in cond:
        _quote(check, cond["quote"], f"{what}.quote", sources)
    for index, also in enumerate(cond.get("also") or []):
        _quote(check, also, f"{what}.also[{index}]", sources)
    if "answer" in cond:
        key = cond["answer"]
        if key not in ANSWER_VALUES:
            check.error(f"`{what}.answer` is not an applicability answer: {key!r}")
            return
        allowed = ANSWER_VALUES[key]
        ops = [op for op in ("includes", "includes_any", "equals") if op in cond]
        if len(ops) != 1:
            check.error(f"`{what}` needs exactly one of includes, includes_any, equals")
            return
        op = ops[0]
        values = cond[op] if op == "includes_any" else [cond[op]]
        if not isinstance(values, list) or not values:
            check.error(f"`{what}.{op}` must name at least one value")
            return
        if (op == "equals") == (key in LIST_ANSWERS):
            check.error(f"`{what}`: {op} does not fit the answer {key!r}")
        values = [*values, *(cond.get("false_if") or [])]
        for value in values:
            if not isinstance(value, str) or not value:
                check.error(f"`{what}`: every value must be text")
            elif allowed is not None and value not in allowed:
                check.error(f"`{what}`: {value!r} is not a value of {key!r}")
            elif value == "unknown":
                check.error(f"`{what}`: 'unknown' never decides a condition")
        return
    ids = [cond["definition"]] if "definition" in cond else cond.get("definitions_any")
    if not isinstance(ids, list) or not ids:
        check.error(f"`{what}` needs `answer`, `definition` or `definitions_any`")
        return
    for definition in ids:
        if not isinstance(definition, str) or not _DEFINITION_ID.match(definition):
            check.error(f"`{what}`: {definition!r} is not a definition id (profile/name)")
    check.text(cond.get("question"), f"{what}.question")


def check_profile(
    data: Any,
    *,
    patterns: dict[tuple[str, str], str | None],
    mechanisms: set[str],
    families: set[str] | None = None,
    where: str = "profile",
) -> list[str]:
    """Every reason the profile cannot be used, one line each; empty when it can.
    `patterns` maps (mechanism, pattern) to the pattern's absent control."""
    check = _Check(where)
    if not isinstance(data, dict):
        return [f"{where}: a profile must be a mapping"]
    families = _families() if families is None else families
    if data.get("schema") != PROFILE_SCHEMA:
        check.error(f"`schema` must be {PROFILE_SCHEMA}")
    if data.get("kind") != PROFILE_KIND:
        check.error(f"`kind` must be {PROFILE_KIND}")
    pid = data.get("id")
    if not isinstance(pid, str) or not _ID.match(pid):
        check.error("`id` must be lower-case letters, digits and dashes")
    check.text(data.get("title"), "title")
    check.text(data.get("jurisdiction"), "jurisdiction")
    if not isinstance(data.get("profile_version"), int) or data["profile_version"] < 1:
        check.error("`profile_version` must be a whole number from 1")
    source = data.get("source")
    if not isinstance(source, dict):
        check.error("`source` must hold url, version and checked_on")
    else:
        if not str(source.get("url", "")).startswith("https://"):
            check.error("`source.url` must be an https URL")
        check.text(source.get("version"), "source.version")
        if _iso(source.get("checked_on")) is None:
            check.error("`source.checked_on` must be a date")
    review = data.get("legal_review")
    if not isinstance(review, dict) or set(review) != {"by", "date"}:
        check.error("`legal_review` must be {by, date}: both null until a lawyer reviewed it")
    elif (review["by"] is None) != (review["date"] is None):
        check.error("`legal_review` names a reviewer and a date, or neither")
    elif review["by"] is not None:
        check.text(review["by"], "legal_review.by")
        if _iso(review["date"]) is None:
            check.error("`legal_review.date` must be a date")
    source_ids: set[str] = set()
    for index, item in enumerate(data.get("sources") or []):
        if not isinstance(item, dict):
            check.error(f"`sources[{index}]` must be a mapping")
            continue
        sid = item.get("id")
        if not isinstance(sid, str) or sid in source_ids:
            check.error(f"`sources[{index}].id` is missing or repeated")
            continue
        source_ids.add(sid)
        for key in ("title", "version", "status"):
            check.text(item.get(key), f"sources[{index}].{key}")
        if not str(item.get("url", "")).startswith("https://"):
            check.error(f"`sources[{index}].url` must be an https URL")
        if _iso(item.get("checked_on")) is None:
            check.error(f"`sources[{index}].checked_on` must be a date")
    if not source_ids:
        check.error("`sources` must list where the text was read")
    if not data.get("applicability"):
        # Without a condition, selecting the jurisdiction would make every provision apply.
        check.error("`applicability` must hold at least one condition")
    for index, cond in enumerate(data.get("applicability") or []):
        _condition(check, cond, f"applicability[{index}]", source_ids)
    provisions = data.get("provisions")
    if not isinstance(provisions, list) or not provisions:
        check.error("`provisions` must list at least one provision")
        provisions = []
    seen: set[str] = set()
    for index, prov in enumerate(provisions):
        where_p = f"provisions[{index}]"
        if not isinstance(prov, dict):
            check.error(f"`{where_p}` must be a mapping")
            continue
        prov_id = prov.get("id")
        if not isinstance(prov_id, str) or not _ID.match(prov_id) or prov_id in seen:
            check.error(f"`{where_p}.id` is missing, malformed or repeated")
        else:
            seen.add(prov_id)
        check.text(prov.get("citation"), f"{where_p}.citation")
        check.text(prov.get("title"), f"{where_p}.title")
        verified = prov.get("verified")
        if not isinstance(verified, bool):
            check.error(f"`{where_p}.verified` must be true or false")
        texts = prov.get("text") or []
        if verified and not texts:
            check.error(f"`{where_p}`: a verified provision quotes its text")
        if verified is False:
            check.text(prov.get("unverified_reason"), f"{where_p}.unverified_reason")
        for t_index, quote in enumerate(texts):
            _quote(check, quote, f"{where_p}.text[{t_index}]", source_ids)
        in_force = prov.get("in_force")
        if not isinstance(in_force, dict):
            check.error(f"`{where_p}.in_force` must hold from, until and their basis")
        else:
            for key in ("from", "until"):
                if in_force.get(key) is not None and _iso(in_force.get(key)) is None:
                    check.error(f"`{where_p}.in_force.{key}` must be a date or null")
                # Said every time: a missing flag would read a derived date as stated.
                if not isinstance(in_force.get(f"{key}_derived"), bool):
                    check.error(f"`{where_p}.in_force.{key}_derived` must be true or false")
            check.text(in_force.get("basis"), f"{where_p}.in_force.basis")
            if "quote" in in_force:
                _quote(check, in_force["quote"], f"{where_p}.in_force.quote", source_ids)
        for c_index, cond in enumerate(prov.get("applies_if") or []):
            _condition(check, cond, f"{where_p}.applies_if[{c_index}]", source_ids)
        for mech in prov.get("mechanisms") or []:
            if mech not in mechanisms:
                check.error(f"`{where_p}.mechanisms`: {mech!r} is not a policy mechanism")
        ceiling = prov.get("ceiling")
        if ceiling is not None and ceiling not in CEILINGS:
            check.error(f"`{where_p}.ceiling` must be one of {', '.join(CEILINGS)}")
        evidence = prov.get("evidence")
        if not isinstance(evidence, dict) or set(evidence) != {
            "code",
            "evaluation",
            "organisational",
        }:
            check.error(f"`{where_p}.evidence` must hold code, evaluation and organisational")
            evidence = {"code": [], "evaluation": [], "organisational": []}
        for e_index, item in enumerate(evidence.get("code") or []):
            at = f"{where_p}.evidence.code[{e_index}]"
            kind = item.get("kind") if isinstance(item, dict) else None
            if kind not in CODE_KINDS:
                check.error(f"`{at}.kind` must be one of {', '.join(CODE_KINDS)}")
                continue
            check.text(item.get("what"), f"{at}.what")
            if kind == "indicators":
                if not item.get("mechanisms") or not set(item["mechanisms"]) <= mechanisms:
                    check.error(f"`{at}.mechanisms` must name policy mechanisms")
                if ceiling is None:
                    check.error(f"`{at}`: indicators need the requires_specialist_review ceiling")
                continue
            key = (item.get("mechanism"), item.get("pattern"))
            if key not in patterns:
                check.error(f"`{at}` names no policy pattern: {key[0]}/{key[1]}")
                continue
            if kind == "control" and patterns[key] != item.get("control"):
                check.error(
                    f"`{at}.control` must be the pattern's absent control ({patterns[key]})"
                )
        if not any(evidence.get(group) for group in ("code", "evaluation", "organisational")):
            # Nothing to check would read as everything present.
            check.error(f"`{where_p}.evidence` must name at least one piece of evidence")
        for e_index, item in enumerate(evidence.get("evaluation") or []):
            at = f"{where_p}.evidence.evaluation[{e_index}]"
            if not isinstance(item, dict) or item.get("family") not in families:
                check.error(f"`{at}.family` must be an evaluation family")
                continue
            check.text(item.get("what"), f"{at}.what")
            if item.get("fail", "gap") not in ("gap", "missing"):
                check.error(f"`{at}.fail` must be gap or missing")
        org_ids: set[str] = set()
        for e_index, item in enumerate(evidence.get("organisational") or []):
            at = f"{where_p}.evidence.organisational[{e_index}]"
            item_id = item.get("id") if isinstance(item, dict) else None
            if not isinstance(item_id, str) or not _ITEM_ID.match(item_id) or item_id in org_ids:
                check.error(f"`{at}.id` is missing, malformed or repeated")
                continue
            org_ids.add(item_id)
            check.text(item.get("what"), f"{at}.what")
        check.texts(prov.get("controls") or [], f"{where_p}.controls")
        check.texts(prov.get("specialist") or [], f"{where_p}.specialist")
        for g_index, quote in enumerate(prov.get("guidance") or []):
            _quote(check, quote, f"{where_p}.guidance[{g_index}]", source_ids)
        replaced = prov.get("replaced_by")
        if replaced is not None:
            if not isinstance(replaced, dict):
                check.error(f"`{where_p}.replaced_by` must be a mapping")
            else:
                check.text(replaced.get("law"), f"{where_p}.replaced_by.law")
                check.text(replaced.get("note"), f"{where_p}.replaced_by.note")
                if replaced.get("from") is not None and _iso(replaced.get("from")) is None:
                    check.error(f"`{where_p}.replaced_by.from` must be a date")
    check.texts(data.get("not_covered") or [], "not_covered")
    check.texts(data.get("notes") or [], "notes")
    return check.errors


def _policy_tables(policy: Any) -> tuple[dict[tuple[str, str], str | None], set[str]]:
    patterns = {
        (mechanism.id, pattern.id): pattern.absent_control
        for mechanism in policy.mechanisms
        for pattern in mechanism.patterns
    }
    return patterns, {mechanism.id for mechanism in policy.mechanisms}


def load_profiles(directory: Path | None = None, *, policy: Any = None) -> list[LegalProfile]:
    """Every profile in `directory` (default: the shipped ones), checked, ordered by id.
    Raises ProfileError on the first profile that cannot be used: a broken profile is never
    skipped quietly."""
    from aisafe.policy import load_policy

    policy = policy or load_policy()
    patterns, mechanisms = _policy_tables(policy)
    families = _families()
    folder = Path(directory) if directory is not None else PROFILES_DIR
    paths = sorted(folder.glob("*.yaml")) if folder.is_dir() else []
    if not paths:
        # An install without its profiles would print a legal section with nothing in it.
        raise ProfileError(f"no legal profile found in {folder.as_posix()}")
    out: list[LegalProfile] = []
    for path in paths:
        raw = path.read_bytes()
        try:
            data = yaml.safe_load(raw.decode("utf-8"))
        except (UnicodeDecodeError, yaml.YAMLError) as exc:
            raise ProfileError(f"{path.name}: not readable YAML ({exc})") from exc
        errors = check_profile(
            data, patterns=patterns, mechanisms=mechanisms, families=families, where=path.name
        )
        if errors:
            raise ProfileError(errors[0] + (f" (and {len(errors) - 1} more)" if errors[1:] else ""))
        data = _normalise(data)
        out.append(
            LegalProfile(
                id=data["id"],
                title=data["title"],
                jurisdiction=data["jurisdiction"],
                path=path,
                sha256=hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest(),
                data=data,
            )
        )
    ids = [p.id for p in out]
    if len(ids) != len(set(ids)):
        raise ProfileError("two legal profiles share an id")
    return out


def _conditions(profile: LegalProfile) -> Iterable[dict[str, Any]]:
    yield from profile.data.get("applicability") or []
    for prov in profile.data.get("provisions") or []:
        yield from prov.get("applies_if") or []


def definition_questions(profiles: Sequence[LegalProfile]) -> dict[str, str]:
    """Every scope definition the profiles ask the auditor about, with its question."""
    out: dict[str, str] = {}
    for profile in profiles:
        for cond in _conditions(profile):
            ids = [cond["definition"]] if "definition" in cond else cond.get("definitions_any")
            for definition in ids or []:
                out.setdefault(definition, str(cond.get("question") or cond.get("why") or ""))
    return dict(sorted(out.items()))
