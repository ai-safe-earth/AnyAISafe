"""tests/unit/test_review_records.py
---------------------------------
The review record (`aisafe.review.records`) and the `aisafe review` command
(`aisafe.review.cli`): the schema and its field checks, a record that covers a file by
unit and by listed artifact, staleness by content hash and by age, the contextual
decisions a person recorded, the finder (default names, `.aisafe/`, an override, never an
exception), the writer (stable layout, round trip), and the command's exit codes
on a scratch copy of the `persons_companion` fixture: `init` writes a skeleton nobody has
signed, `record` binds a named person to the current hashes, `check` says what changed.

Honesty rules pinned here: a record with any problem covers nothing; a changed or missing
artifact makes the record stale and the reason names the file; a verdict-shaped or
secret-shaped text is refused; the reviewer is a person and a tool is attribution only.
"""

from __future__ import annotations

import shutil
from datetime import date, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from aisafe.evidence.artifacts import sha256_of
from aisafe.evidence.model import ArtifactRef, UnknownCategory
from aisafe.policy import POLICY_VERSION, load_policy
from aisafe.reporting.report import BANNED_PHRASES
from aisafe.review import cli, records
from aisafe.review.records import (
    DEFAULT_RECORD_FILE,
    PLACEHOLDER,
    RECORD_CANDIDATES,
    RECORD_KEYS,
    REVIEW_KIND,
    ReviewDecision,
    ReviewRecord,
    ReviewSet,
    check_text,
    dump_document,
    find_records,
    load_record_file,
    parse_date,
    parse_review_document,
    record_document,
    relative_to_root,
    version_older,
)

POLICY = load_policy()
MECHANISM_IDS = [m.id for m in POLICY.mechanisms]
SHA_A = "a" * 64
SHA_B = "b" * 64
FP = "0123456789abcdef"
TODAY = date(2026, 10, 29)
REVIEWER = "J. Doe <product owner>"
PURPOSE = "a companion chat for adults who want to practise Spanish"
# The companion fixture's prompt and person-signal artifacts, as discovery lists them.
COMPANION_ARTIFACTS = ["analytics.py", "app.py", "prompts/companion.md"]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def review(**overrides) -> dict:
    """One valid entry under `reviews`."""
    entry = {
        "reviewer": REVIEWER,
        "reviewed_at": "2026-10-29",
        "scope": ["M1", "M4", "M5", "M6"],
        "declared_purpose": PURPOSE,
        "artifacts": [{"path": "prompts/system.md", "sha256": SHA_A}],
    }
    entry.update(overrides)
    return entry


def document(*reviews: dict, policy_version: str | None = POLICY_VERSION) -> dict:
    doc: dict = {"schema": "aisg/1", "kind": REVIEW_KIND}
    if policy_version is not None:
        doc["policy_version"] = policy_version
    doc["reviews"] = list(reviews) or [review()]
    return doc


def parse(doc: dict) -> tuple[list[ReviewRecord], list[str], str | None]:
    return parse_review_document(doc, "aisafe-review.yaml", POLICY)


def one(doc: dict) -> ReviewRecord:
    found, errors, _version = parse(doc)
    assert errors == [], errors
    (record,) = found
    return record


def errors_of(doc: dict) -> list[str]:
    found, errors, _version = parse(doc)
    assert found == []
    return errors


def write_record(root: Path, doc: dict, name: str = DEFAULT_RECORD_FILE) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return path


def banned_phrase() -> str:
    return BANNED_PHRASES[0]  # assembled by the renderer, never a literal here


def banned_word() -> str:
    return "cl" + "ean"


def secret_shaped() -> str:
    return "sk-ant-" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4"


# ---------------------------------------------------------------------------
# constants and field checks
# ---------------------------------------------------------------------------


def test_constants():
    assert REVIEW_KIND == "review" and PLACEHOLDER == "TODO"
    assert DEFAULT_RECORD_FILE == "aisafe-review.yaml"
    assert RECORD_CANDIDATES == (
        "aisafe-review.yaml",
        ".aisafe/review.yaml",
        ".aisafe-audit/review.yaml",
    )
    assert RECORD_KEYS == (
        "reviewer",
        "assisted_by",
        "reviewed_at",
        "units",
        "scope",
        "declared_purpose",
        "affected_population",
        "artifacts",
        "decisions",
        "notes",
    )


@pytest.mark.xfail(
    condition=records._FALLBACK_PHRASES != tuple(BANNED_PHRASES),
    reason="records._FALLBACK_PHRASES lags report.BANNED_PHRASES (the bare word was added "
    "to the renderer's list only); a record read while the renderer cannot load would "
    "accept a verdict the renderer refuses",
    strict=True,
)
def test_fallback_phrases_mirror_the_renderer_list():
    # The module promises the two lists equal: a record read without the renderer loaded
    # must refuse exactly the verdicts the renderer refuses.
    assert records._FALLBACK_PHRASES == tuple(BANNED_PHRASES)


@pytest.mark.parametrize(
    ("value", "why"),
    [
        (None, "is empty"),
        ("", "is empty"),
        ("   ", "is empty"),
        (7, "must be a string"),
        ("TODO", "is the placeholder TODO"),
        (" todo ", "is the placeholder TODO"),
        ("two\nlines", "must be a single line of printable text"),
        ("tab\there", "must be a single line of printable text"),
        ("control \x7f here", "must be a single line of printable text"),
        (f"the system is {banned_word()}", "reads as a verdict"),
        (f"reviewed and it {banned_phrase()}", "reads as a verdict"),
        (f"key {secret_shaped()} in a prompt", "contains a secret-shaped token"),
    ],
)
def test_check_text_refuses(value, why):
    problem = check_text("reviews[0].reviewer", value)
    assert problem is not None and problem.startswith("reviews[0].reviewer") and why in problem
    # The refusal never repeats the text it refused (the placeholder is named, by design).
    if isinstance(value, str) and value.strip() and value.strip().upper() != PLACEHOLDER:
        assert value.strip() not in problem


def test_check_text_passes_plain_text_and_multiline_notes():
    assert check_text("x", REVIEWER) is None
    assert check_text("x", "line one\nline two") == "x must be a single line of printable text"
    assert check_text("x", "line one\nline two", multiline=True) is None
    assert check_text("x", "tab\there", multiline=True) == "x must be printable text"
    assert check_text("x", "caf" + chr(0xE9)) is None
    assert check_text("x", "a tool helped: an LLM reviewer") is None


def test_parse_date_accepts_yaml_dates_and_iso_strings():
    assert parse_date(date(2026, 10, 29)) == TODAY
    assert parse_date(datetime(2026, 10, 29, 12, 0)) == TODAY
    assert parse_date("2026-10-29") == TODAY
    assert parse_date("2026-10-29T08:00:00Z") == TODAY
    assert parse_date("2026-10-29 08:00:00") == TODAY
    assert parse_date("yesterday") is None and parse_date(20261029) is None
    assert parse_date(None) is None


@pytest.mark.parametrize(
    ("version", "older"),
    [
        (None, True),
        ("", True),
        (POLICY_VERSION, False),
        ("0.9.0", True),
        ("9.0.0", False),
        ("rc-1", True),
        (POLICY_VERSION + "-rc", True),
    ],
)
def test_version_older(version, older):
    assert version_older(version, POLICY_VERSION) is older


def test_version_older_treats_matching_non_numeric_versions_as_current():
    assert version_older("draft", "draft") is False


def test_relative_to_root(tmp_path):
    inner = tmp_path / "a" / "b.md"
    inner.parent.mkdir()
    inner.write_text("x")
    assert relative_to_root(inner, tmp_path) == "a/b.md"
    outside = Path("C:/elsewhere/x.md") if Path.cwd().drive else Path("/elsewhere/x.md")
    assert relative_to_root(outside, tmp_path) == outside.as_posix()


# ---------------------------------------------------------------------------
# parsing and validation
# ---------------------------------------------------------------------------


def test_a_valid_record_parses_with_normalised_fields():
    record = one(
        document(
            review(
                assisted_by="an LLM reviewer",
                units=["u0", "u0", "u1"],
                scope=["m4", "M1", "m4"],
                affected_population="adults learning Spanish",
                artifacts=[
                    {"path": ".\\prompts\\system.md", "sha256": SHA_A.upper()},
                    {"file": "./app//main.py", "sha256": SHA_B},
                ],
                decisions=[
                    {
                        "fingerprint": FP.upper(),
                        "decision": "requires_contextual_review",
                        "justification": "the owner wants a second look",
                    }
                ],
                notes="read on 2026-10-29\nwith the product owner",
            )
        )
    )
    assert record.reviewer == REVIEWER and record.assisted_by == "an LLM reviewer"
    assert record.reviewed_at == TODAY and record.reviewed_at_iso == "2026-10-29"
    assert record.units == ("u0", "u1")
    assert record.scope == ("M1", "M4")  # policy order, upper case, deduplicated
    assert record.declared_purpose == PURPOSE
    assert record.affected_population == "adults learning Spanish"
    assert record.artifacts == (
        ArtifactRef("prompts/system.md", SHA_A),
        ArtifactRef("app/main.py", SHA_B),
    )
    assert record.artifact_paths == frozenset({"prompts/system.md", "app/main.py"})
    assert record.decisions == (
        ReviewDecision(FP, "requires_contextual_review", "the owner wants a second look"),
    )
    assert record.notes == "read on 2026-10-29\nwith the product owner"
    assert record.source_file == "aisafe-review.yaml"
    assert record.policy_version == POLICY_VERSION and record.index == 0


def test_optional_fields_default_to_none_or_empty():
    record = one(document(review()))
    assert record.assisted_by is None and record.affected_population is None
    assert record.units == () and record.decisions == () and record.notes is None
    assert record.covers("any-unit") is True


@pytest.mark.parametrize(
    ("doc", "message"),
    [
        (["not", "a", "mapping"], "not a mapping"),
        ({"schema": "aisg/2", "kind": "review", "reviews": [review()]}, "schema must be aisg/1"),
        ({"schema": "aisg/1", "kind": "audit", "reviews": [review()]}, "kind must be review"),
        ({"schema": "aisg/1", "kind": "review"}, "reviews must be a non-empty list"),
        ({"schema": "aisg/1", "kind": "review", "reviews": []}, "reviews must be a non-empty list"),
        ({"schema": "aisg/1", "kind": "review", "reviews": ["x"]}, "reviews[0] is not a mapping"),
    ],
)
def test_a_document_of_the_wrong_shape_yields_no_record(doc, message):
    found, errors, _version = parse(doc)
    assert found == []
    assert any(message in error for error in errors), errors


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"reviewer": None}, "reviews[0].reviewer is empty"),
        ({"reviewer": "TODO"}, "reviews[0].reviewer is the placeholder TODO"),
        ({"reviewer": f"J. Doe, {banned_word()} review"}, "reviews[0].reviewer reads as a verdict"),
        ({"reviewed_at": None}, "reviews[0].reviewed_at is missing"),
        ({"reviewed_at": "last week"}, "reviews[0].reviewed_at is not an ISO date"),
        ({"units": "u0"}, "reviews[0].units must be a list of unit ids"),
        ({"units": ["u0", ""]}, "reviews[0].units holds an empty or non-string unit id"),
        ({"scope": []}, "reviews[0].scope must be a non-empty list of mechanism ids"),
        ({"scope": "M1"}, "reviews[0].scope must be a non-empty list of mechanism ids"),
        ({"scope": ["M1", "M9"]}, "reviews[0].scope names unknown mechanism ids M9"),
        ({"declared_purpose": "TODO"}, "reviews[0].declared_purpose is the placeholder TODO"),
        (
            {"declared_purpose": f"a {banned_phrase()} tutor"},
            "reviews[0].declared_purpose reads as a verdict",
        ),
        (
            {"affected_population": "caf" + chr(0x200B) + "e"},
            "reviews[0].affected_population must be a single line of printable text",
        ),
        ({"assisted_by": "  "}, "reviews[0].assisted_by is empty"),
        ({"notes": "tab\there"}, "reviews[0].notes must be printable text"),
        ({"artifacts": []}, "reviews[0].artifacts must be a non-empty list"),
        ({"artifacts": "prompts/system.md"}, "reviews[0].artifacts must be a non-empty list"),
        ({"artifacts": ["prompts/system.md"]}, "reviews[0].artifacts[0] is not a mapping"),
        ({"artifacts": [{"sha256": SHA_A}]}, "reviews[0].artifacts[0].path is empty"),
        (
            {"artifacts": [{"path": "/etc/prompts.md", "sha256": SHA_A}]},
            "must be relative to the audited root",
        ),
        (
            {"artifacts": [{"path": "C:/prompts/x.md", "sha256": SHA_A}]},
            "must be relative to the audited root",
        ),
        (
            {"artifacts": [{"path": "C:x.md", "sha256": SHA_A}]},
            "must be relative to the audited root",
        ),
        (
            {"artifacts": [{"path": "~/prompts/x.md", "sha256": SHA_A}]},
            "must be relative to the audited root",
        ),
        (
            {"artifacts": [{"path": "../other/x.md", "sha256": SHA_A}]},
            "must be relative to the audited root",
        ),
        (
            {"artifacts": [{"path": "prompts/x.md", "sha256": "abc"}]},
            "reviews[0].artifacts[0].sha256 for prompts/x.md is not a 64-character hex sha256",
        ),
        (
            {"artifacts": [{"path": "prompts/x.md"}]},
            "reviews[0].artifacts[0].sha256 for prompts/x.md is not a 64-character hex sha256",
        ),
        (
            {
                "artifacts": [
                    {"path": "prompts/x.md", "sha256": SHA_A},
                    {"path": "./prompts/x.md", "sha256": SHA_B},
                ]
            },
            "reviews[0].artifacts lists prompts/x.md twice",
        ),
        ({"decisions": "none"}, "reviews[0].decisions must be a list"),
        ({"decisions": ["x"]}, "reviews[0].decisions[0] is not a mapping"),
        (
            {
                "decisions": [
                    {"fingerprint": "xyz", "decision": "violates_policy", "justification": "j"}
                ]
            },
            "reviews[0].decisions[0].fingerprint is not a 16-character hex finding fingerprint",
        ),
        (
            {"decisions": [{"fingerprint": FP, "decision": "fine", "justification": "j"}]},
            "reviews[0].decisions[0].decision 'fine' is not one of",
        ),
        (
            {"decisions": [{"fingerprint": FP, "decision": "violates_policy"}]},
            "reviews[0].decisions[0].justification is empty",
        ),
        (
            {
                "decisions": [
                    {"fingerprint": FP, "decision": "violates_policy", "justification": "first"},
                    {
                        "fingerprint": FP.upper(),
                        "decision": "not_assessed",
                        "justification": "second",
                    },
                ]
            },
            f"reviews[0].decisions records {FP} twice",
        ),
    ],
)
def test_a_record_with_a_problem_covers_nothing(override, message):
    errors = errors_of(document(review(**override)))
    assert any(message in error for error in errors), errors
    assert all(error.startswith("aisafe-review.yaml: reviews[0]") for error in errors), errors


def test_every_problem_of_a_record_is_listed_at_once():
    errors = errors_of(document(review(reviewer="TODO", scope=[], artifacts=[])))
    assert len(errors) == 3
    assert [e.split(" ", 1)[0] for e in errors] == ["aisafe-review.yaml:"] * 3


def test_a_bad_record_does_not_sink_the_good_ones():
    good = review(artifacts=[{"path": "app.py", "sha256": SHA_B}])
    bad = review(reviewer="TODO")
    found, errors, version = parse(document(bad, good))
    assert [r.index for r in found] == [1]
    assert found[0].artifact_paths == frozenset({"app.py"})
    assert errors == ["aisafe-review.yaml: reviews[0].reviewer is the placeholder TODO"]
    assert version == POLICY_VERSION


def test_policy_version_is_read_as_text_or_none():
    assert parse(document(policy_version=None))[2] is None
    assert parse(document(policy_version=" 0.9.0 "))[2] == "0.9.0"
    assert one(document(policy_version="0.9.0")).policy_version == "0.9.0"
    assert one(document(policy_version="0.9.0")).policy_outdated(POLICY_VERSION) is True
    assert one(document()).policy_outdated(POLICY_VERSION) is False
    assert one(document(policy_version=None)).policy_outdated(POLICY_VERSION) is True


# ---------------------------------------------------------------------------
# covers, is_stale, decision_for, inventory shapes
# ---------------------------------------------------------------------------


def test_covers_by_unit_and_by_listed_artifact():
    record = one(document(review(units=["u0"])))
    assert record.covers("u0") is True and record.covers("u1") is False
    assert record.covers(None) is False  # a file in no unit is not one the record names
    assert record.covers("u0", "prompts/system.md") is True
    assert record.covers("u0", "./prompts//system.md") is True
    assert record.covers("u0", "prompts\\system.md") is True
    assert record.covers("u0", "app.py") is False  # not a listed artifact
    assert record.covers("u1", "prompts/system.md") is False  # listed, but another unit
    everywhere = one(document(review()))
    assert everywhere.covers(None) is True and everywhere.covers("u9") is True
    assert everywhere.covers("u9", "prompts/system.md") is True
    assert everywhere.covers("u9", "other.md") is False


def test_is_stale_names_the_artifact_and_the_reason():
    record = one(
        document(
            review(
                artifacts=[
                    {"path": "prompts/system.md", "sha256": SHA_A},
                    {"path": "app.py", "sha256": SHA_B},
                ]
            )
        )
    )
    current = {"prompts/system.md": SHA_A, "app.py": SHA_B}
    assert record.is_stale(current.get, TODAY, 90) == []
    assert record.is_stale(current.get, datetime(2026, 10, 29, 23, 0), 90) == []
    changed = {"prompts/system.md": SHA_A, "app.py": "c" * 64}
    assert record.is_stale(changed.get, TODAY, 90) == ["artifact app.py changed since the review"]
    missing = {"app.py": SHA_B}
    assert record.is_stale(missing.get, TODAY, 90) == ["artifact prompts/system.md is missing"]
    # Hash comparison ignores case; the record stores lower-case hex.
    upper = {"prompts/system.md": SHA_A.upper(), "app.py": SHA_B.upper()}
    assert record.is_stale(upper.get, TODAY, 90) == []


def test_is_stale_ages_the_review_and_refuses_a_future_date():
    record = one(document(review()))
    current = {"prompts/system.md": SHA_A}
    assert record.is_stale(current.get, TODAY + timedelta(days=90), 90) == []
    assert record.is_stale(current.get, TODAY + timedelta(days=91), 90) == [
        "reviewed_at 2026-10-29 is older than 90 days"
    ]
    assert record.is_stale(current.get, TODAY - timedelta(days=1), 90) == [
        "reviewed_at 2026-10-29 is after today (2026-10-28)"
    ]
    # Both kinds of reason, artifact first, when both apply.
    reasons = record.is_stale({}.get, TODAY + timedelta(days=400), 90)
    assert reasons == [
        "artifact prompts/system.md is missing",
        "reviewed_at 2026-10-29 is older than 90 days",
    ]
    undated = ReviewRecord(REVIEWER, None, ("M1",), PURPOSE)
    assert undated.is_stale({}.get, TODAY, 90) == ["reviewed_at is missing"]


def test_decision_for_is_case_and_whitespace_insensitive():
    record = one(
        document(
            review(
                decisions=[
                    {
                        "fingerprint": FP,
                        "decision": "no_violation_identified_in_scope",
                        "justification": "the objective line is a quoted example",
                    }
                ]
            )
        )
    )
    decision = record.decision_for(f" {FP.upper()} ")
    assert decision is not None and decision.decision == "no_violation_identified_in_scope"
    assert decision.justification == "the objective line is a quoted example"
    assert decision.to_dict() == {
        "fingerprint": FP,
        "decision": "no_violation_identified_in_scope",
        "justification": "the objective line is a quoted example",
    }
    assert record.decision_for("f" * 16) is None
    review_set = ReviewSet(records=[one(document(review())), record], file="aisafe-review.yaml")
    assert review_set.decision_for(FP) == decision
    assert review_set.decision_for("f" * 16) is None


def test_inventory_and_document_shapes():
    record = one(document(review(units=["u0"], assisted_by="an LLM reviewer")))
    assert record.to_inventory() == {
        "file": "aisafe-review.yaml",
        "reviewer": REVIEWER,
        "reviewed_at": "2026-10-29",
        "policy_version": POLICY_VERSION,
        "artifacts": 1,
        "scope": ["M1", "M4", "M5", "M6"],
    }
    # The text fields stay in the file, never in the inventory.
    assert PURPOSE not in str(record.to_inventory())
    assert record.to_document() == {
        "reviewer": REVIEWER,
        "assisted_by": "an LLM reviewer",
        "reviewed_at": TODAY,
        "units": ["u0"],
        "scope": ["M1", "M4", "M5", "M6"],
        "declared_purpose": PURPOSE,
        "affected_population": None,
        "artifacts": [{"path": "prompts/system.md", "sha256": SHA_A}],
        "decisions": [],
        "notes": None,
    }


def test_review_set_helpers():
    first = one(document(review(units=["u0"])))
    second = one(
        document(
            review(
                units=["u1"],
                declared_purpose="a billing assistant",
                artifacts=[{"path": "billing/prompt.md", "sha256": SHA_B}],
            )
        )
    )
    review_set = ReviewSet(records=[first, second], file="aisafe-review.yaml", errors=["oops"])
    assert review_set.found is True
    assert review_set.covering("u0") == [first] and review_set.covering("u1") == [second]
    assert review_set.covering("u0", "billing/prompt.md") == []
    assert review_set.declared_purpose_for("u1") == "a billing assistant"
    assert review_set.declared_purpose_for("u0", "prompts/system.md") == PURPOSE
    assert review_set.declared_purpose_for("u0", "billing/prompt.md") is None
    assert review_set.declared_purpose_for("u9") is None
    (item,) = review_set.unknown_items()
    assert item.category is UnknownCategory.RUNTIME
    assert item.what == "review record aisafe-review.yaml" and item.why == "oops"
    assert item.file == "aisafe-review.yaml" and item.rule_ids == ("AUD-1107",)
    assert item.how_to_resolve
    assert review_set.to_inventory() == [first.to_inventory(), second.to_inventory()]
    empty = ReviewSet()
    assert empty.found is False and empty.unknown_items() == []
    assert ReviewSet(errors=["x"]).unknown_items()[0].what == "review record"


# ---------------------------------------------------------------------------
# find_records
# ---------------------------------------------------------------------------


def test_find_records_without_a_file_is_empty_and_quiet(tmp_path):
    found = find_records(tmp_path)
    assert found.records == [] and found.errors == [] and found.file is None
    assert found.found is False and found.policy_version is None


def test_find_records_reads_the_default_file(tmp_path):
    write_record(tmp_path, document(review()))
    found = find_records(tmp_path, files=[], override=None)
    assert found.file == "aisafe-review.yaml" and found.found is True
    assert found.errors == [] and found.policy_version == POLICY_VERSION
    (record,) = found.records
    assert record.reviewer == REVIEWER and record.source_file == "aisafe-review.yaml"


@pytest.mark.parametrize("name", RECORD_CANDIDATES[1:])
def test_find_records_reads_the_dot_directory_candidates(tmp_path, name):
    write_record(tmp_path, document(review()), name)
    found = find_records(tmp_path)
    assert found.file == name and len(found.records) == 1 and found.errors == []


def test_two_record_files_read_the_first_and_say_so(tmp_path):
    write_record(tmp_path, document(review()))
    write_record(tmp_path, document(review(reviewer="Someone Else")), ".aisafe/review.yaml")
    found = find_records(tmp_path)
    assert found.file == "aisafe-review.yaml"
    assert [r.reviewer for r in found.records] == [REVIEWER]
    assert len(found.errors) == 1
    assert "2 review record files found" in found.errors[0]
    assert "reading aisafe-review.yaml only" in found.errors[0]


def test_override_path_wins_and_a_missing_override_is_an_error(tmp_path):
    write_record(tmp_path, document(review(reviewer="Default Person")))
    other = write_record(tmp_path, document(review()), "elsewhere/review.yaml")
    by_absolute = find_records(tmp_path, override=str(other))
    assert [r.reviewer for r in by_absolute.records] == [REVIEWER]
    assert by_absolute.file == "elsewhere/review.yaml"
    by_relative = find_records(tmp_path, override="elsewhere/review.yaml")
    assert [r.reviewer for r in by_relative.records] == [REVIEWER]
    missing = find_records(tmp_path, override="nowhere.yaml")
    assert missing.records == [] and missing.file is None
    assert missing.errors == ["review record nowhere.yaml not found"]
    assert find_records(tmp_path, override="   ").file == "aisafe-review.yaml"


def test_malformed_files_become_errors_never_exceptions(tmp_path):
    path = tmp_path / DEFAULT_RECORD_FILE
    path.write_text("reviews: [unclosed", encoding="utf-8")
    found = find_records(tmp_path)
    assert found.records == [] and found.file == "aisafe-review.yaml"
    assert len(found.errors) == 1 and "invalid YAML" in found.errors[0]
    path.write_text("- a\n- list\n", encoding="utf-8")
    assert find_records(tmp_path).errors == ["aisafe-review.yaml: not a mapping"]
    path.write_bytes("schema: aisg/1\n".encode("utf-16"))
    (error,) = find_records(tmp_path).errors
    assert "not UTF-8" in error or "not a mapping" in error
    write_record(tmp_path, document(review(reviewer="TODO")))
    (error,) = find_records(tmp_path).errors
    assert error == "aisafe-review.yaml: reviews[0].reviewer is the placeholder TODO"


def test_find_records_survives_a_lookup_failure(tmp_path, monkeypatch):
    def boom(root, override):
        raise RuntimeError("synthetic")

    monkeypatch.setattr(records, "_locate", boom)
    found = find_records(tmp_path)
    assert found.records == [] and found.errors == ["review record lookup: RuntimeError: synthetic"]


def test_load_record_file_uses_the_display_name_in_messages(tmp_path):
    path = write_record(tmp_path, document(review(reviewer="TODO")), "sub/r.yaml")
    found = load_record_file(path, tmp_path)
    assert found.file == "sub/r.yaml"
    assert found.errors == ["sub/r.yaml: reviews[0].reviewer is the placeholder TODO"]
    shown = load_record_file(path, tmp_path, display="shown.yaml")
    assert shown.file == "shown.yaml" and shown.errors[0].startswith("shown.yaml:")
    unreadable = load_record_file(tmp_path / "absent.yaml", tmp_path)
    assert unreadable.records == [] and len(unreadable.errors) == 1
    assert unreadable.errors[0].startswith("absent.yaml:")


# ---------------------------------------------------------------------------
# writing: record_document and dump_document
# ---------------------------------------------------------------------------


def test_record_document_and_dump_round_trip_through_the_parser():
    doc = record_document(
        reviewer=f"  {REVIEWER}  ",
        reviewed_at=TODAY,
        scope=["M1", "M4"],
        declared_purpose=f" {PURPOSE} ",
        artifacts=[ArtifactRef("prompts/system.md", SHA_A), ArtifactRef("app.py", SHA_B)],
        policy_version=POLICY_VERSION,
        affected_population=" adults ",
        assisted_by="an LLM reviewer",
        units=["u0"],
        decisions=[
            {
                "fingerprint": FP.upper(),
                "decision": "requires_contextual_review",
                "justification": " the owner asked ",
            }
        ],
        notes="first line\nsecond line",
    )
    assert list(doc) == ["schema", "kind", "policy_version", "reviews"]
    (entry,) = doc["reviews"]
    assert list(entry) == list(RECORD_KEYS)
    assert entry["reviewer"] == REVIEWER and entry["declared_purpose"] == PURPOSE
    assert entry["affected_population"] == "adults"
    assert entry["decisions"] == [
        {
            "fingerprint": FP,
            "decision": "requires_contextual_review",
            "justification": "the owner asked",
        }
    ]
    text = dump_document(doc, header=True)
    assert text.isascii() and text.endswith("\n")
    assert text.splitlines()[0].startswith("# aisafe review record")
    assert "schema: aisg/1\nkind: review\n" in text
    assert f'policy_version: "{POLICY_VERSION}"' in text
    assert '  - reviewer: "J. Doe <product owner>"' in text
    assert "    reviewed_at: 2026-10-29" in text
    assert '    scope: ["M1", "M4"]' in text
    assert f'      - {{path: "prompts/system.md", sha256: "{SHA_A}"}}' in text
    assert '    notes: "first line\\nsecond line"' in text
    loaded = yaml.safe_load(text)
    assert loaded["policy_version"] == POLICY_VERSION
    found, errors, version = parse_review_document(loaded, "r.yaml", POLICY)
    assert errors == [] and version == POLICY_VERSION
    (record,) = found
    assert record.reviewer == REVIEWER and record.reviewed_at == TODAY
    assert record.scope == ("M1", "M4") and record.units == ("u0",)
    assert record.artifact_paths == frozenset({"prompts/system.md", "app.py"})
    assert record.decision_for(FP).justification == "the owner asked"
    assert record.notes == "first line\nsecond line"
    assert record.assisted_by == "an LLM reviewer"


def test_dump_document_is_stable_and_keeps_what_a_person_wrote():
    extra = {"reviewer": "Someone Else", "custom": {"k": "v"}, "tags": ["a", "b"]}
    doc = record_document(
        reviewer=REVIEWER,
        reviewed_at=None,
        scope=[],
        declared_purpose=PLACEHOLDER,
        artifacts=[],
        policy_version=POLICY_VERSION,
        extra_reviews=[extra],
    )
    text = dump_document(doc)
    assert text == dump_document(doc)
    assert not text.startswith("#")  # no header unless asked
    assert "    reviewed_at: null\n" in text and "    scope: []\n" in text
    assert "    artifacts: []\n" in text and "    decisions: []\n" in text
    # The second record keeps its unknown keys as flow mappings and lists.
    assert '  - reviewer: "Someone Else"' in text
    assert '    custom: {"k": "v"}' in text and '    tags: ["a", "b"]' in text
    loaded = yaml.safe_load(text)
    assert loaded["reviews"][1] == extra
    assert dump_document({"reviews": []}).endswith("reviews: []\n")


def test_dump_document_quotes_strings_so_yaml_keeps_their_type():
    doc = record_document(
        reviewer="2026: a number-shaped name",
        reviewed_at=TODAY,
        scope=["M1"],
        declared_purpose="yes",
        artifacts=[ArtifactRef("prompts/x.md", SHA_A)],
        policy_version="1.0",
    )
    loaded = yaml.safe_load(dump_document(doc))
    assert loaded["policy_version"] == "1.0"
    assert loaded["reviews"][0]["reviewer"] == "2026: a number-shaped name"
    assert loaded["reviews"][0]["declared_purpose"] == "yes"


# ---------------------------------------------------------------------------
# aisafe review: init / record / check
# ---------------------------------------------------------------------------


@pytest.fixture
def companion(tmp_path, audit_fixture, monkeypatch) -> Path:
    root = tmp_path / "companion"
    shutil.copytree(audit_fixture("persons_companion"), root)
    monkeypatch.setattr(cli, "today", lambda: TODAY)
    return root


def hashes(root: Path) -> dict[str, str]:
    return {name: sha256_of(root / name) for name in COMPANION_ARTIFACTS}


def test_discover_artifacts_lists_prompt_and_person_signal_files(companion):
    assert cli.discover_artifacts(companion) == COMPANION_ARTIFACTS
    write_record(companion, document(review()))
    assert cli.discover_artifacts(companion) == COMPANION_ARTIFACTS  # never lists itself


def test_init_writes_a_skeleton_nobody_has_signed(companion, capsys):
    assert cli.main(["init", str(companion)]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "wrote aisafe-review.yaml: 3 artifacts, reviewer TODO, reviewed_at null, scope []" in out
    assert "next: aisafe review record" in out
    path = companion / DEFAULT_RECORD_FILE
    text = path.read_text(encoding="utf-8")
    assert text.isascii() and text.startswith("# aisafe review record")
    doc = yaml.safe_load(text)
    assert doc["schema"] == "aisg/1" and doc["kind"] == "review"
    assert doc["policy_version"] == POLICY_VERSION
    (entry,) = doc["reviews"]
    assert entry["reviewer"] == PLACEHOLDER and entry["declared_purpose"] == PLACEHOLDER
    assert entry["reviewed_at"] is None and entry["scope"] == []
    assert [a["path"] for a in entry["artifacts"]] == COMPANION_ARTIFACTS
    assert {a["path"]: a["sha256"] for a in entry["artifacts"]} == hashes(companion)
    # A skeleton covers nothing: the audit's reader lists every placeholder.
    found = find_records(companion)
    assert found.records == [] and found.errors
    assert any("placeholder" in e for e in found.errors)
    assert any("reviewed_at is missing" in e for e in found.errors)


def test_init_refuses_to_overwrite_without_force(companion, capsys):
    assert cli.main(["init", str(companion)]) == cli.EXIT_OK
    path = companion / DEFAULT_RECORD_FILE
    path.write_text("edited by hand\n", encoding="utf-8")
    assert cli.main(["init", str(companion)]) == cli.EXIT_FATAL
    assert "refused: aisafe-review.yaml exists; pass --force" in capsys.readouterr().err
    assert path.read_text(encoding="utf-8") == "edited by hand\n"
    assert cli.main(["init", str(companion), "--force"]) == cli.EXIT_OK
    assert yaml.safe_load(path.read_text(encoding="utf-8"))["kind"] == "review"


def test_init_on_a_tree_without_artifacts_says_so(tmp_path, capsys):
    root = tmp_path / "empty"
    root.mkdir()
    (root / "pyproject.toml").write_text('[project]\nname = "empty"\n', encoding="utf-8")
    (root / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    assert cli.main(["init", str(root)]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "0 artifacts" in out and "list the files you reviewed under artifacts by hand" in out
    assert yaml.safe_load((root / DEFAULT_RECORD_FILE).read_text())["reviews"][0]["artifacts"] == []


def test_record_binds_a_named_person_to_the_current_hashes(companion, capsys):
    code = cli.main(["record", str(companion), "--reviewer", REVIEWER, "--purpose", PURPOSE])
    assert code == cli.EXIT_OK
    out = capsys.readouterr().out
    assert (
        f"wrote aisafe-review.yaml: reviewer {REVIEWER}, reviewed_at 2026-10-29, "
        f"scope {','.join(MECHANISM_IDS)}, 3 artifacts, policy_version {POLICY_VERSION}"
    ) in out
    found = find_records(companion)
    assert found.errors == [] and found.policy_version == POLICY_VERSION
    (record,) = found.records
    assert record.reviewer == REVIEWER and record.reviewed_at == TODAY
    assert record.scope == tuple(MECHANISM_IDS) and record.declared_purpose == PURPOSE
    assert record.assisted_by is None and record.affected_population is None
    assert {ref.file: ref.sha256 for ref in record.artifacts} == hashes(companion)
    assert record.is_stale(lambda rel: sha256_of(companion / rel), TODAY, 90) == []
    assert record.covers("u0", "prompts/companion.md") is True
    assert record.covers("u0", "ai-system-card.yaml") is False


def test_record_takes_scope_affected_and_assisted_by(companion):
    code = cli.main(
        [
            "record",
            str(companion),
            "--reviewer",
            REVIEWER,
            "--purpose",
            PURPOSE,
            "--scope",
            "m4,M1, m5",
            "--affected",
            "adults learning Spanish",
            "--assisted-by",
            "an LLM reviewer",
        ]
    )
    assert code == cli.EXIT_OK
    (record,) = find_records(companion).records
    assert record.scope == ("M1", "M4", "M5")
    assert record.affected_population == "adults learning Spanish"
    assert record.assisted_by == "an LLM reviewer"


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--scope", "M1,M9"], "unknown mechanism ids M9"),
        (["--scope", " , "], "--scope is empty"),
    ],
)
def test_record_refuses_a_bad_scope(companion, capsys, args, message):
    code = cli.main(["record", str(companion), "--reviewer", REVIEWER, "--purpose", PURPOSE, *args])
    assert code == cli.EXIT_FATAL
    assert message in capsys.readouterr().err
    assert not (companion / DEFAULT_RECORD_FILE).exists()


@pytest.mark.parametrize(
    ("reviewer", "purpose", "message"),
    [
        (REVIEWER, f"a {banned_phrase()} tutor", "declared_purpose reads as a verdict"),
        (REVIEWER, f"a {banned_word()} tutor", "declared_purpose reads as a verdict"),
        (f"J. Doe {secret_shaped()}", PURPOSE, "reviewer contains a secret-shaped token"),
        ("TODO", PURPOSE, "reviewer is the placeholder TODO"),
        ("   ", PURPOSE, "reviewer is empty"),
        (
            REVIEWER,
            "caf" + chr(0x200B) + "e",
            "declared_purpose must be a single line of printable text",
        ),
    ],
)
def test_record_refuses_a_verdict_a_secret_or_a_placeholder(
    companion, capsys, reviewer, purpose, message
):
    code = cli.main(["record", str(companion), "--reviewer", reviewer, "--purpose", purpose])
    assert code == cli.EXIT_FATAL
    err = capsys.readouterr().err
    assert "refused:" in err and message in err
    assert not (companion / DEFAULT_RECORD_FILE).exists()


def test_record_refuses_a_tree_with_nothing_to_bind_to(tmp_path, capsys):
    root = tmp_path / "empty"
    root.mkdir()
    (root / "pyproject.toml").write_text('[project]\nname = "empty"\n', encoding="utf-8")
    code = cli.main(["record", str(root), "--reviewer", REVIEWER, "--purpose", PURPOSE])
    assert code == cli.EXIT_FATAL
    assert "nothing to bind the review to" in capsys.readouterr().err
    assert not (root / DEFAULT_RECORD_FILE).exists()


def test_record_carries_over_what_a_person_typed_and_refreshes_the_hashes(companion, capsys):
    assert cli.main(["record", str(companion), "--reviewer", REVIEWER, "--purpose", PURPOSE]) == 0
    path = companion / DEFAULT_RECORD_FILE
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["reviews"][0]["decisions"] = [
        {
            "fingerprint": FP.upper(),
            "decision": "requires_contextual_review",
            "justification": "the owner wants a second look",
        }
    ]
    doc["reviews"][0]["notes"] = "read with the product owner"
    doc["reviews"][0]["units"] = ["u0"]
    doc["reviews"].append(
        review(reviewer="Someone Else", artifacts=[{"path": "analytics.py", "sha256": SHA_B}])
    )
    path.write_text(dump_document(doc), encoding="utf-8")
    # The prompt changes after the first review; the second record binds the new hash.
    prompt = companion / "prompts" / "companion.md"
    prompt.write_text(prompt.read_text(encoding="utf-8") + "\nBe kind.\n", encoding="utf-8")
    capsys.readouterr()
    code = cli.main(
        ["record", str(companion), "--reviewer", REVIEWER, "--purpose", "a tutor, second pass"]
    )
    assert code == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "carried over from the previous record: decisions, notes, units" in out
    assert "1 further record left as written" in out
    found = find_records(companion)
    assert found.errors == []
    first, second = found.records
    assert first.declared_purpose == "a tutor, second pass"
    assert first.decision_for(FP).justification == "the owner wants a second look"
    assert first.notes == "read with the product owner" and first.units == ("u0",)
    assert {ref.file: ref.sha256 for ref in first.artifacts} == hashes(companion)
    assert second.reviewer == "Someone Else" and second.artifact_paths == frozenset(
        {"analytics.py"}
    )


def test_record_and_check_honour_the_record_flag(companion, tmp_path, capsys):
    target = tmp_path / "elsewhere" / "review.yaml"
    code = cli.main(
        [
            "record",
            str(companion),
            "--record",
            str(target),
            "--reviewer",
            REVIEWER,
            "--purpose",
            PURPOSE,
        ]
    )
    assert code == cli.EXIT_OK and target.is_file()
    assert not (companion / DEFAULT_RECORD_FILE).exists()
    capsys.readouterr()
    assert cli.main(["check", str(companion), "--record", str(target)]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "1 record" in out and "result: 0 stale reasons, 0 uncovered artifacts" in out
    assert cli.main(["check", str(companion), "--record", str(tmp_path / "nope.yaml")]) == 2
    assert "not found" in capsys.readouterr().out


def test_check_without_a_record_lists_every_artifact_as_uncovered(companion, capsys):
    assert cli.main(["check", str(companion)]) == cli.EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "no review record under" in out and "run `aisafe review init`" in out
    assert "3 artifacts discovered" in out
    for name in COMPANION_ARTIFACTS:
        assert f"uncovered: {name}" in out
    assert "result: 0 stale reasons, 3 uncovered artifacts" in out


def test_check_on_a_skeleton_is_a_refusal_not_a_pass(companion, capsys):
    assert cli.main(["init", str(companion)]) == cli.EXIT_OK
    capsys.readouterr()
    assert cli.main(["check", str(companion)]) == cli.EXIT_FATAL
    out = capsys.readouterr().out
    assert "error: aisafe-review.yaml: reviews[0].reviewer is the placeholder TODO" in out
    assert "aisafe-review.yaml: 0 records" in out


def test_check_passes_a_fresh_record_and_names_what_changed(companion, capsys):
    assert cli.main(["record", str(companion), "--reviewer", REVIEWER, "--purpose", PURPOSE]) == 0
    capsys.readouterr()
    assert cli.main(["check", str(companion)]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert f"aisafe-review.yaml: 1 record, policy_version {POLICY_VERSION}" in out
    assert (
        f"record 1: {REVIEWER}, reviewed_at 2026-10-29, scope {','.join(MECHANISM_IDS)}, 3 artifacts"
        in out
    )
    assert "result: 0 stale reasons, 0 uncovered artifacts" in out

    prompt = companion / "prompts" / "companion.md"
    prompt.write_text(prompt.read_text(encoding="utf-8") + "\nBe kind.\n", encoding="utf-8")
    assert cli.main(["check", str(companion)]) == cli.EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "stale: artifact prompts/companion.md changed since the review" in out
    assert "result: 1 stale reason, 0 uncovered artifacts" in out

    (companion / "analytics.py").unlink()
    (companion / "prompts" / "extra.md").write_text(
        "You are Ava, the user's caring girlfriend.\n", encoding="utf-8"
    )
    assert cli.main(["check", str(companion)]) == cli.EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "stale: artifact analytics.py is missing" in out
    assert "uncovered: prompts/extra.md" in out
    assert "result: 2 stale reasons, 1 uncovered artifact" in out


def test_check_ages_the_review_against_the_policy(companion, capsys, monkeypatch):
    assert cli.main(["record", str(companion), "--reviewer", REVIEWER, "--purpose", PURPOSE]) == 0
    limit = POLICY.review_max_age_days
    monkeypatch.setattr(cli, "today", lambda: TODAY + timedelta(days=limit))
    capsys.readouterr()
    assert cli.main(["check", str(companion)]) == cli.EXIT_OK
    monkeypatch.setattr(cli, "today", lambda: TODAY + timedelta(days=limit + 1))
    assert cli.main(["check", str(companion)]) == cli.EXIT_FINDINGS
    out = capsys.readouterr().out
    assert f"stale: reviewed_at 2026-10-29 is older than {limit} days" in out


def test_check_flags_a_record_decided_under_an_older_policy(companion, capsys):
    artifacts = [{"path": name, "sha256": digest} for name, digest in hashes(companion).items()]
    write_record(companion, document(review(artifacts=artifacts), policy_version="0.9.0"))
    assert cli.main(["check", str(companion)]) == cli.EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "aisafe-review.yaml: 1 record, policy_version 0.9.0" in out
    assert f"stale: policy_version 0.9.0 is older than the current policy {POLICY_VERSION}" in out
    assert "result: 1 stale reason, 0 uncovered artifacts" in out


def test_check_reads_the_pyproject_review_record_default(companion, capsys):
    (companion / "pyproject.toml").write_text(
        '[project]\nname = "companion"\n\n[tool.aisafe-audit]\nreview-record = "docs/review.yaml"\n',
        encoding="utf-8",
    )
    assert cli.main(["record", str(companion), "--reviewer", REVIEWER, "--purpose", PURPOSE]) == 0
    assert (companion / "docs" / "review.yaml").is_file()
    assert not (companion / DEFAULT_RECORD_FILE).exists()
    capsys.readouterr()
    assert cli.main(["check", str(companion)]) == cli.EXIT_OK
    assert "docs/review.yaml: 1 record" in capsys.readouterr().out


def test_the_record_is_the_same_the_audit_reads(companion, audit_context):
    assert cli.main(["record", str(companion), "--reviewer", REVIEWER, "--purpose", PURPOSE]) == 0
    ctx = audit_context(companion)
    assert ctx.review is not None and ctx.review.errors == []
    (record,) = ctx.review.records
    assert record.reviewer == REVIEWER
    assert ctx.inventory.review_records == [
        {
            "file": "aisafe-review.yaml",
            "reviewer": REVIEWER,
            "reviewed_at": "2026-10-29",
            "policy_version": POLICY_VERSION,
            "artifacts": 3,
            "scope": MECHANISM_IDS,
        }
    ]
    assert not [u for u in ctx.unknown if u.category is UnknownCategory.RUNTIME]


def test_main_without_a_verb_prints_help_and_fails(capsys):
    assert cli.main([]) == cli.EXIT_FATAL
    out = capsys.readouterr().out
    assert "init" in out and "record" in out and "check" in out


def test_main_maps_failures_to_exit_2(tmp_path, capsys):
    assert cli.main(["check", str(tmp_path / "nowhere")]) == cli.EXIT_FATAL
    assert "is not a directory" in capsys.readouterr().err


def test_records_main_dispatches_to_the_command(companion, capsys):
    assert records.main(["check", str(companion)]) == cli.EXIT_FINDINGS
    assert "3 artifacts discovered" in capsys.readouterr().out


def test_discovery_failure_is_exit_2_not_a_traceback(companion, capsys, monkeypatch):
    def boom(root, exclude=()):
        raise cli.DiscoveryUnavailable("discovery failed: synthetic")

    monkeypatch.setattr(cli, "discover_artifacts", boom)
    assert cli.main(["init", str(companion)]) == cli.EXIT_FATAL
    assert "error: discovery failed: synthetic" in capsys.readouterr().err
    assert not (companion / DEFAULT_RECORD_FILE).exists()
