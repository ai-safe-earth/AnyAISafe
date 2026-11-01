"""tests/unit/test_review_baseline.py
----------------------------------
Pins for the fingerprint baseline: write/load round trip, a full audit report read as a
baseline yields the same set, anything else is a `BaselineError`, and `diff` marks
new/unchanged/re-review in place so the exit code counts what is new and what was
suppressed under another policy.

The policy version travels with the document and with every accepted entry. A
fingerprint listed WITHOUT a reason (a suppression) stands only under the policy that
wrote it: under any other version, or none, the finding is `re-review` and counts like a
new one. A fingerprint listed WITH a reason (an acceptance) stays `unchanged` and uncounted,
but an acceptance taken under an older policy is marked for a second look
(`re_review`, `acceptance_policy_version`, `stale_acceptances`). A refresh never turns a
stale acceptance into a current one behind the operator's back.

The `accepted` list: `write_baseline(..., reasons=...)` fills it from the findings,
`load_baseline` validates it (a reason per entry, every entry also in `fingerprints`), and
the committed `audit-baseline.json` is held to that shape -- plus one more: scanning the
baseline file itself must not reproduce the findings it accepts.

The `index` block names every fingerprint (rule, file, title) so a later diff can say what
a fingerprint that is no longer reported was, and `amend_baseline` records a reason without
a re-scan; it refuses a reason that is empty, non-ASCII, not a single printable line,
verdict-shaped or secret-shaped, and never writes on a refusal. `read_baseline` applies the
same reason check, so a hand-edited file cannot carry what `--accept` would have refused.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from aisafe.evidence.model import (
    AuditContext,
    Basis,
    Confidence,
    Decision,
    Evidence,
    EvidenceKind,
    EvidenceStatus,
    Finding,
    Inventory,
    MatchKind,
    Recommendation,
    Scope,
    Severity,
    Tier,
)
from aisafe.policy import POLICY_VERSION, load_policy
from aisafe.reporting.report import (
    BANNED_PHRASES,
    build_report,
    compute_exit_code,
    render,
    tool_version,
)
from aisafe.review.baseline import (
    BASELINE_KIND,
    REPORT_KIND,
    STATUS_NEW,
    STATUS_RE_REVIEW,
    STATUS_UNCHANGED,
    BaselineDiff,
    BaselineDocument,
    BaselineError,
    amend_baseline,
    diff,
    load_accepted,
    load_baseline,
    load_generated_at,
    load_index,
    load_policy_version,
    parse_accept,
    read_baseline,
    write_baseline,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
COMMITTED_BASELINE = REPO_ROOT / "audit-baseline.json"
POLICY = load_policy()
OLDER_POLICY = "0.9.0"

# The document's key order, as this version writes it.
BASELINE_KEYS = [
    "schema",
    "kind",
    "generated_at",
    "tool",
    "policy_version",
    "fingerprints",
    "accepted",
    "index",
]
DIFF_KEYS = [
    "file",
    "kind",
    "new",
    "unchanged",
    "re_review",
    "stale_acceptances",
    "accepted",
    "generated_at",
    "policy_version",
    "no_longer_reported",
]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def make_finding(
    rule_id: str,
    file: str,
    snippet: str,
    severity: Severity = Severity.HIGH,
    sub: str | None = None,
) -> Finding:
    mechanism = POLICY.mechanism_of(rule_id)
    return Finding(
        id=rule_id,
        title=f"title for {rule_id}",
        severity=severity,
        priority=POLICY.order_of(rule_id),
        mechanism=mechanism.id if mechanism is not None else "",
        policy_version=POLICY_VERSION,
        rule_version=2,
        evidence_status=EvidenceStatus.SUPPORTED_MECHANISM,
        decision=Decision.VIOLATES,
        basis=Basis.PRESENCE,
        confidence=Confidence(EvidenceKind.CODE, MatchKind.GREP),
        scope=Scope(kind="file", name=file),
        evidence=[Evidence(role="match", file=file, line=3, snippet=snippet)],
        references=("EU:Art.5(1)(a)",),
        recommendation=Recommendation(Tier.T1, "fix", ("a", "b", "c"), ("objective",)),
        sub=sub,
    )


def make_absence_finding(rule_id: str, unit_root: str) -> Finding:
    """An absence finding carries no evidence; its location is the scope name."""
    return Finding(
        id=rule_id,
        title=f"title for {rule_id}",
        severity=Severity.LOW,
        priority=POLICY.order_of(rule_id),
        mechanism="M8",
        basis=Basis.ABSENCE,
        confidence=Confidence(EvidenceKind.ABSENCE, MatchKind.STRUCTURED),
        scope=Scope(kind="unit", unit="u0", name=unit_root),
        evidence=[],
        recommendation=Recommendation(Tier.T1, "add", ("a", "b", "c"), ("record",)),
    )


def three() -> list[Finding]:
    return [
        make_finding("AUD-1104", "prompts/system.md", "Your goal is to maximize engagement."),
        make_finding("AUD-1105", "app.py", "never admit you are an AI"),
        make_finding("AUD-1109", "prompts/persona.md", "say you missed them", Severity.CRITICAL),
    ]


def make_report(findings: list[Finding], baseline: BaselineDiff | None = None):
    ctx = AuditContext(root=Path("target"), inventory=Inventory(target={"path": "target"}))
    code = compute_exit_code(findings, [], fail_on="low")
    return build_report(ctx, findings, [], [], baseline, rules=[], fail_on="low", exit_code=code)


def _doc(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _baseline_doc(
    fingerprints: list[str], accepted: object = None, policy_version: object = POLICY_VERSION
) -> str:
    doc: dict = {"schema": "aisg/1", "kind": BASELINE_KIND}
    if policy_version is not None:
        doc["policy_version"] = policy_version
    doc["fingerprints"] = fingerprints
    if accepted is not None:
        doc["accepted"] = accepted
    return json.dumps(doc)


def _written(
    tmp_path: Path,
    reasons: dict[int, str] | None = None,
    policy_version: str | None = None,
) -> tuple[Path, list[Finding]]:
    """A three-finding baseline on disk; `reasons` is keyed by finding index."""
    findings = three()
    findings[1] = make_finding("AUD-1105", "app.py", "never admit you are an AI", sub="persona")
    path = tmp_path / "audit-baseline.json"
    by_fingerprint = None
    if reasons is not None:
        by_fingerprint = {findings[i].fingerprint: reason for i, reason in reasons.items()}
    write_baseline(findings, path, reasons=by_fingerprint, policy_version=policy_version)
    return path, findings


# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------


def test_kinds_and_statuses():
    assert BASELINE_KIND == "audit-baseline" and REPORT_KIND == "audit"
    assert (STATUS_NEW, STATUS_UNCHANGED, STATUS_RE_REVIEW) == ("new", "unchanged", "re-review")


# ---------------------------------------------------------------------------
# write / load
# ---------------------------------------------------------------------------


def test_write_then_load_round_trip(tmp_path: Path):
    findings = three()
    path = tmp_path / "audit-baseline.json"
    write_baseline(findings, path)
    doc = _doc(path)
    assert list(doc) == [
        "schema",
        "kind",
        "generated_at",
        "tool",
        "policy_version",
        "fingerprints",
        "index",
    ]
    assert doc["schema"] == "aisg/1" and doc["kind"] == BASELINE_KIND
    assert doc["tool"] == {"name": "aisafe-audit", "version": tool_version()}
    assert doc["policy_version"] == POLICY_VERSION
    assert doc["fingerprints"] == sorted(doc["fingerprints"])
    assert len(doc["fingerprints"]) == len(set(doc["fingerprints"])) == 3
    assert load_baseline(path) == {f.fingerprint for f in findings}
    assert load_policy_version(path) == POLICY_VERSION
    document = read_baseline(path)
    assert isinstance(document, BaselineDocument)
    assert document.kind == BASELINE_KIND and document.policy_version == POLICY_VERSION
    assert document.accepted == {} and document.accepted_versions == {}
    assert document.raw == doc


def test_write_baseline_takes_an_explicit_policy_version(tmp_path: Path):
    path = tmp_path / "b.json"
    write_baseline(three(), path, policy_version=OLDER_POLICY)
    assert load_policy_version(path) == OLDER_POLICY
    # A report carries its own policy block; that version wins over the packaged one.
    report = make_report(three())
    report.policy = {"version": "0.8.0", "charter": "x", "adopted": "y"}
    write_baseline(report, path)
    assert load_policy_version(path) == "0.8.0"


def test_write_baseline_index_names_every_fingerprint(tmp_path: Path):
    findings = three()
    findings[1] = make_finding("AUD-1105", "app.py", "never admit you are an AI", sub="persona")
    path = tmp_path / "audit-baseline.json"
    write_baseline(findings, path)
    doc = _doc(path)
    # Same order as `fingerprints`; rule is the display id, file the first evidence.
    assert list(doc["index"]) == doc["fingerprints"]
    assert doc["index"][findings[1].fingerprint] == {
        "rule": "AUD-1105/persona",
        "file": "app.py:3",
        "title": "title for AUD-1105",
    }
    assert load_index(path) == doc["index"]
    assert load_generated_at(path) == doc["generated_at"]
    assert path.read_text(encoding="utf-8").isascii()


def test_write_baseline_index_uses_the_scope_name_for_an_absence_finding(tmp_path: Path):
    absent = make_absence_finding("AUD-1107", ".")
    path = tmp_path / "b.json"
    write_baseline([absent], path)
    assert load_index(path)[absent.fingerprint]["file"] == "."


def test_load_tolerates_an_old_baseline_and_a_report(tmp_path: Path):
    fp = three()[0].fingerprint
    old = tmp_path / "old.json"
    old.write_text(json.dumps({"schema": "aisg/1", "kind": BASELINE_KIND, "fingerprints": [fp]}))
    assert load_baseline(old) == {fp}
    assert load_index(old) == {}
    assert load_generated_at(old) is None
    assert load_policy_version(old) is None  # unrecorded, never guessed
    report_path = tmp_path / "audit-report.json"
    report_path.write_text(render(make_report(three()), "json"), encoding="utf-8")
    assert load_index(report_path) == {}
    assert isinstance(load_generated_at(report_path), str)
    document = read_baseline(report_path)
    assert document.kind == REPORT_KIND and len(document.fingerprints) == 3
    assert document.accepted == {} and document.index == {}
    # A report's `policy` block supplies the version it was decided under.
    assert document.policy_version == POLICY_VERSION


@pytest.mark.parametrize(
    ("index", "reason"),
    [
        (["not", "a", "dict"], "not an object"),
        ({"abc": "not an object"}, "not an object"),
        ({"": {"rule": "AUD-1104"}}, "not a fingerprint"),
    ],
)
def test_load_baseline_rejects_a_malformed_index(tmp_path: Path, index: object, reason: str):
    fp = three()[0].fingerprint
    path = tmp_path / "b.json"
    path.write_text(
        json.dumps(
            {"schema": "aisg/1", "kind": BASELINE_KIND, "fingerprints": [fp], "index": index}
        )
    )
    with pytest.raises(BaselineError) as info:
        load_baseline(path)
    assert reason in str(info.value) and "b.json" in str(info.value)


def test_load_baseline_rejects_a_policy_version_that_is_not_a_string(tmp_path: Path):
    fp = three()[0].fingerprint
    path = tmp_path / "b.json"
    path.write_text(_baseline_doc([fp], policy_version=1))
    with pytest.raises(BaselineError) as info:
        load_baseline(path)
    assert "policy_version" in str(info.value) and "b.json" in str(info.value)
    path.write_text(_baseline_doc([fp], policy_version="  "))
    assert load_policy_version(path) is None  # blank is unrecorded


def test_write_baseline_dedups_and_accepts_a_report(tmp_path: Path):
    findings = three() + three()
    report = make_report(findings)
    path = tmp_path / "b.json"
    write_baseline(report, path)
    doc = _doc(path)
    assert len(doc["fingerprints"]) == 3
    assert doc["tool"] == report.tool
    assert doc["policy_version"] == report.policy["version"]


def test_load_baseline_reads_a_full_audit_report_identically(tmp_path: Path):
    findings = three()
    report_path = tmp_path / "audit-report.json"
    report_path.write_text(render(make_report(findings), "json"), encoding="utf-8")
    baseline_path = tmp_path / "audit-baseline.json"
    write_baseline(findings, baseline_path)
    assert load_baseline(report_path) == load_baseline(baseline_path)
    assert load_baseline(report_path) == {f.fingerprint for f in findings}


def test_load_baseline_empty_report_yields_empty_set(tmp_path: Path):
    report_path = tmp_path / "audit-report.json"
    report_path.write_text(render(make_report([]), "json"), encoding="utf-8")
    assert load_baseline(report_path) == set()


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ('{"schema": "aisg/1", "kind": "evaluation", "summary": {}}', "kind"),
        ('{"schema": "aisg/2", "kind": "audit-baseline", "fingerprints": []}', "schema"),
        ('{"kind": "audit-baseline", "fingerprints": []}', "schema"),
        ('{"schema": "aisg/1", "kind": "audit-baseline", "fingerprints": "abc"}', "fingerprints"),
        ('{"schema": "aisg/1", "kind": "audit-baseline", "fingerprints": [1, 2]}', "fingerprint"),
        ('{"schema": "aisg/1", "kind": "audit", "findings": {}}', "findings"),
        ("[]", "object"),
        ("{not json", "JSON"),
    ],
)
def test_load_baseline_rejects_anything_else(tmp_path: Path, text: str, reason: str):
    path = tmp_path / "x.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(BaselineError) as info:
        load_baseline(path)
    message = str(info.value)
    assert "\n" not in message
    assert reason in message
    assert "x.json" in message


def test_load_baseline_missing_file(tmp_path: Path):
    with pytest.raises(BaselineError) as info:
        load_baseline(tmp_path / "absent.json")
    assert "absent.json" in str(info.value)


def test_load_baseline_on_a_non_utf8_file_is_a_baseline_error(tmp_path: Path):
    """A file in another encoding is refused by name, not as a raw UnicodeDecodeError."""
    path = tmp_path / "utf16.json"
    fp = three()[0].fingerprint
    text = json.dumps({"schema": "aisg/1", "kind": BASELINE_KIND, "fingerprints": [fp]})
    path.write_bytes(text.encode("utf-16"))
    with pytest.raises(BaselineError) as info:
        load_baseline(path)
    message = str(info.value)
    assert "utf16.json" in message and "UTF-8" in message
    assert "\n" not in message


def test_write_baseline_uses_lf_on_every_platform(tmp_path: Path):
    """A baseline is committed; a Windows write must not carry CRLF."""
    path = tmp_path / "b.json"
    findings = three()
    write_baseline(findings, path, reasons={findings[0].fingerprint: "a quoted example"})
    raw = path.read_bytes()
    assert b"\r" not in raw
    assert raw.endswith(b"}\n")
    amend_baseline(path, {findings[1].fingerprint: "a stage direction in the fiction"})
    assert b"\r" not in path.read_bytes()


def test_write_baseline_creates_the_parent_directory(tmp_path: Path):
    """
    `.aisafe-audit/` usually does not exist on the first `--write-baseline`, and the write
    comes after the scan and the render: the parent is created, like `-o` does.
    """
    path = tmp_path / "sub" / "dir" / "b.json"
    assert not path.parent.exists()
    findings = three()
    write_baseline(findings, path, reasons={findings[0].fingerprint: "a quoted example"})
    assert path.parent.is_dir()
    assert load_baseline(path) == {f.fingerprint for f in findings}
    assert load_accepted(path) == {findings[0].fingerprint: "a quoted example"}


# ---------------------------------------------------------------------------
# accepted: reasons per fingerprint, each stamped with its policy version
# ---------------------------------------------------------------------------


def test_write_baseline_with_reasons_fills_accepted_from_the_findings(tmp_path: Path):
    findings = three()
    findings[1] = make_finding("AUD-1105", "app.py", "never admit you are an AI", sub="persona")
    reasons = {
        findings[2].fingerprint: "a line of the style guide the model never reads",
        findings[1].fingerprint: "the persona rule is a quoted example in a test",
    }
    path = tmp_path / "audit-baseline.json"
    write_baseline(findings, path, reasons=reasons)
    doc = _doc(path)
    assert list(doc) == BASELINE_KEYS
    assert len(doc["fingerprints"]) == 3
    # Entries follow the findings' order, not the reasons' order; `rule` is the display id
    # (id + sub), `file` the first evidence location, and the version is the one of now.
    assert doc["accepted"] == [
        {
            "fingerprint": findings[1].fingerprint,
            "rule": "AUD-1105/persona",
            "file": "app.py:3",
            "reason": "the persona rule is a quoted example in a test",
            "policy_version": POLICY_VERSION,
        },
        {
            "fingerprint": findings[2].fingerprint,
            "rule": "AUD-1109",
            "file": "prompts/persona.md:3",
            "reason": "a line of the style guide the model never reads",
            "policy_version": POLICY_VERSION,
        },
    ]
    assert load_baseline(path) == {f.fingerprint for f in findings}
    assert load_accepted(path) == reasons
    assert read_baseline(path).accepted_versions == {fp: POLICY_VERSION for fp in reasons}


def test_write_baseline_accepted_uses_the_scope_name_for_an_absence_finding(tmp_path: Path):
    absent = make_absence_finding("AUD-1107", ".")
    path = tmp_path / "b.json"
    write_baseline([absent], path, reasons={absent.fingerprint: "a library, not a system"})
    assert _doc(path)["accepted"] == [
        {
            "fingerprint": absent.fingerprint,
            "rule": "AUD-1107",
            "file": ".",
            "reason": "a library, not a system",
            "policy_version": POLICY_VERSION,
        }
    ]


def test_write_baseline_without_reasons_has_no_accepted_key(tmp_path: Path):
    path = tmp_path / "b.json"
    write_baseline(three(), path)
    assert "accepted" not in _doc(path)
    assert load_accepted(path) == {}


def test_write_baseline_accepts_a_report_with_reasons(tmp_path: Path):
    findings = three()
    report = make_report(findings)
    path = tmp_path / "b.json"
    write_baseline(report, path, reasons={findings[0].fingerprint: "a quoted example"})
    doc = _doc(path)
    assert [e["rule"] for e in doc["accepted"]] == ["AUD-1104"]
    assert doc["tool"] == report.tool


def test_write_baseline_refresh_keeps_a_carried_acceptance_version(tmp_path: Path):
    """
    A `--write-baseline` refresh copies the reasons over from the earlier file. That is not
    a second look: a carried entry keeps the version it was accepted under, an entry taken
    under no recorded policy is written as an explicit null (so the refreshed document's
    own stamp never claims it), and only a reason not carried is stamped now.
    """
    findings = three()
    path = tmp_path / "b.json"
    carried = {
        findings[0].fingerprint: "a quoted example",
        findings[1].fingerprint: "a stage direction in the fiction",
        findings[2].fingerprint: "a line the model never reads",
    }
    versions = {findings[0].fingerprint: OLDER_POLICY, findings[1].fingerprint: None}
    write_baseline(findings, path, reasons=carried, accepted_versions=versions)
    by_fp = {e["fingerprint"]: e for e in _doc(path)["accepted"]}
    assert by_fp[findings[0].fingerprint]["policy_version"] == OLDER_POLICY
    assert by_fp[findings[1].fingerprint]["policy_version"] is None
    assert by_fp[findings[2].fingerprint]["policy_version"] == POLICY_VERSION
    document = read_baseline(path)
    assert document.policy_version == POLICY_VERSION  # the document itself is of now
    assert document.accepted_versions == {
        findings[0].fingerprint: OLDER_POLICY,
        findings[1].fingerprint: None,
        findings[2].fingerprint: POLICY_VERSION,
    }


def test_write_baseline_rejects_a_reason_that_matches_no_finding(tmp_path: Path):
    findings = three()
    path = tmp_path / "b.json"
    with pytest.raises(BaselineError) as info:
        write_baseline(findings, path, reasons={"ffffffffffffffff": "stale"})
    assert "ffffffffffffffff" in str(info.value)
    assert not path.exists()


@pytest.mark.parametrize("reason", ["", "   ", None])
def test_write_baseline_rejects_an_empty_reason(tmp_path: Path, reason: object):
    findings = three()
    path = tmp_path / "b.json"
    with pytest.raises(BaselineError) as info:
        write_baseline(findings, path, reasons={findings[0].fingerprint: reason})  # type: ignore[dict-item]
    assert findings[0].fingerprint in str(info.value)
    assert "reason" in str(info.value)
    assert not path.exists()


def test_load_baseline_rejects_an_accepted_entry_without_a_reason(tmp_path: Path):
    fp = three()[0].fingerprint
    path = tmp_path / "b.json"
    path.write_text(
        _baseline_doc([fp], [{"fingerprint": fp, "rule": "AUD-1104", "file": "a.py:3"}])
    )
    with pytest.raises(BaselineError) as info:
        load_baseline(path)
    message = str(info.value)
    assert fp in message and "reason" in message and "b.json" in message
    assert "\n" not in message


def test_load_baseline_rejects_an_accepted_entry_with_a_blank_reason(tmp_path: Path):
    fp = three()[0].fingerprint
    path = tmp_path / "b.json"
    path.write_text(_baseline_doc([fp], [{"fingerprint": fp, "reason": "  "}]))
    with pytest.raises(BaselineError) as info:
        load_baseline(path)
    assert fp in str(info.value)


def test_load_baseline_rejects_an_accepted_fingerprint_not_in_fingerprints(tmp_path: Path):
    listed, stray = three()[0].fingerprint, three()[1].fingerprint
    path = tmp_path / "b.json"
    path.write_text(_baseline_doc([listed], [{"fingerprint": stray, "reason": "looked at it"}]))
    with pytest.raises(BaselineError) as info:
        load_baseline(path)
    message = str(info.value)
    assert stray in message and "fingerprints" in message
    assert listed not in message


def test_load_baseline_rejects_an_accepted_policy_version_that_is_not_a_string(tmp_path: Path):
    fp = three()[0].fingerprint
    path = tmp_path / "b.json"
    path.write_text(
        _baseline_doc([fp], [{"fingerprint": fp, "reason": "looked at it", "policy_version": 1}])
    )
    with pytest.raises(BaselineError) as info:
        load_baseline(path)
    assert fp in str(info.value) and "policy_version" in str(info.value)


@pytest.mark.parametrize(
    ("accepted", "reason"),
    [
        ({"fingerprint": "x"}, "not a list"),
        (["abc"], "not an object"),
        ([{"reason": "no fingerprint here"}], "no fingerprint"),
        ([{"fingerprint": "", "reason": "empty fingerprint"}], "no fingerprint"),
    ],
)
def test_load_baseline_rejects_a_malformed_accepted_list(
    tmp_path: Path, accepted: object, reason: str
):
    fp = three()[0].fingerprint
    path = tmp_path / "b.json"
    path.write_text(_baseline_doc([fp], accepted))
    with pytest.raises(BaselineError) as info:
        load_baseline(path)
    assert reason in str(info.value)


def test_load_baseline_tolerates_an_absent_or_empty_accepted_list(tmp_path: Path):
    fp = three()[0].fingerprint
    path = tmp_path / "b.json"
    path.write_text(_baseline_doc([fp], []))
    assert load_baseline(path) == {fp}
    assert load_accepted(path) == {}
    path.write_text(_baseline_doc([fp]))
    assert load_baseline(path) == {fp}
    assert load_accepted(path) == {}


def _unrecordable_reasons() -> list[tuple[str, str]]:
    """Reasons `amend_baseline` refuses; a hand-edited file is held to the same bar."""
    banned_word = "cl" + "ean"
    secret = "sk-ant-" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4"
    cases = [
        ("a hidden" + chr(0x200B) + " letter, not a live key", "printable"),
        # ASCII, but not one printable line: JSON carries these as escapes, so a hand
        # edit can put them in a file, and the renderers print the reason as one line.
        ("fixture key\nassembled at runtime", "single line"),
        ("fixture key\r\nassembled at runtime", "single line"),
        ("fixture key\tassembled at runtime", "single line"),
        ("fixture key \x00 assembled at runtime", "single line"),
        ("fixture key \x7f assembled at runtime", "single line"),
        (f"reviewed; the target is {banned_word}", "verdict"),
        (f"the token {secret} is a fixture", "secret"),
    ]
    cases.extend((f"reviewed and it {phrase} now", "verdict") for phrase in BANNED_PHRASES)
    return cases


@pytest.mark.parametrize(("reason", "why"), _unrecordable_reasons())
def test_load_baseline_rejects_an_accepted_reason_amend_would_refuse(
    tmp_path: Path, reason: str, why: str
):
    fp = three()[0].fingerprint
    path = tmp_path / "b.json"
    path.write_text(_baseline_doc([fp], [{"fingerprint": fp, "reason": reason}]), encoding="utf-8")
    with pytest.raises(BaselineError) as info:
        load_baseline(path)
    message = str(info.value)
    assert why in message and fp in message and "b.json" in message
    assert "\n" not in message
    # The refusal names the fingerprint, never the text it refused.
    assert reason not in message


def test_load_accepted_on_a_full_report_is_empty(tmp_path: Path):
    report_path = tmp_path / "audit-report.json"
    report_path.write_text(render(make_report(three()), "json"), encoding="utf-8")
    assert load_accepted(report_path) == {}
    assert len(load_baseline(report_path)) == 3


def test_fingerprints_are_line_ending_independent(tmp_path: Path):
    """CI checks out with LF on Linux; a Windows checkout has CRLF. Same baseline either way."""
    crlf = make_finding("AUD-1104", "a.md", "Your goal is to\r\n    maximize engagement.\r\n")
    lf = make_finding("AUD-1104", "a.md", "Your goal is to\n    maximize engagement.\n")
    assert crlf.fingerprint == lf.fingerprint
    path = tmp_path / "b.json"
    write_baseline([crlf], path, reasons={crlf.fingerprint: "a quoted example"})
    document = read_baseline(path)
    result = diff([lf], document, file=path.name)
    assert result.to_dict() == {
        "file": "b.json",
        "kind": BASELINE_KIND,
        "new": 0,
        "unchanged": 1,
        "re_review": 0,
        "stale_acceptances": 0,
        "accepted": [
            {
                "fingerprint": lf.fingerprint,
                "rule": "AUD-1104",
                "file": "a.md:3",
                "reason": "a quoted example",
                "policy_version": POLICY_VERSION,
            }
        ],
        "generated_at": document.generated_at,
        "policy_version": POLICY_VERSION,
        "no_longer_reported": [],
    }


# ---------------------------------------------------------------------------
# diff: new, unchanged, re-review, gone
# ---------------------------------------------------------------------------


def test_diff_marks_new_and_unchanged_in_place_and_lists_gone():
    """A gone fingerprint is listed under `no_longer_reported`; the block carries no count."""
    old = three()
    baseline = {old[0].fingerprint, old[1].fingerprint, "ffffffffffffffff"}
    current = three()
    result = diff(
        current, baseline, file="audit-baseline.json", baseline_policy_version=POLICY_VERSION
    )
    assert isinstance(result, BaselineDiff)
    assert [f.id for f in result.unchanged] == ["AUD-1104", "AUD-1105"]
    assert [f.id for f in result.new] == ["AUD-1109"]
    assert result.re_review == [] and result.stale_acceptances == []
    assert result.gone == ["ffffffffffffffff"]
    assert result.file == "audit-baseline.json"
    assert [f.baseline_status for f in current] == ["unchanged", "unchanged", "new"]
    assert [f.accepted_reason for f in current] == [None, None, None]
    assert [f.re_review for f in current] == [False, False, False]
    assert result.to_dict() == {
        "file": "audit-baseline.json",
        "kind": None,
        "new": 1,
        "unchanged": 2,
        "re_review": 0,
        "stale_acceptances": 0,
        "accepted": [],
        "generated_at": None,
        "policy_version": POLICY_VERSION,
        "no_longer_reported": [{"fingerprint": "ffffffffffffffff"}],
    }
    assert list(result.to_dict()) == DIFF_KEYS
    assert ("fix" + "ed") not in result.to_dict()
    assert result.current_policy_version == POLICY_VERSION


def test_diff_defaults_to_the_packaged_policy_version():
    result = diff([], set(), file="b.json")
    assert result.current_policy_version == POLICY_VERSION
    assert result.policy_version is None


def test_diff_normalises_windows_paths_in_file():
    assert diff([], set(), file="out\\audit-baseline.json").file == "out/audit-baseline.json"


def test_a_suppression_stands_only_under_the_policy_that_wrote_it():
    """
    A fingerprint listed without a reason is a suppression. Under the same policy version
    it is `unchanged`; under another version it is `re-review`, counts toward the exit code
    like a new finding, and is listed apart from the new ones.
    """
    findings = three()
    listed = {f.fingerprint for f in findings[:2]}
    same = diff(findings, listed, file="b.json", baseline_policy_version=POLICY_VERSION)
    assert [f.baseline_status for f in findings] == ["unchanged", "unchanged", "new"]
    assert same.re_review == []
    assert compute_exit_code(findings[:2], [], fail_on="low") == 0

    findings = three()
    older = diff(findings, listed, file="b.json", baseline_policy_version=OLDER_POLICY)
    assert [f.baseline_status for f in findings] == ["re-review", "re-review", "new"]
    assert [f.re_review for f in findings] == [True, True, False]
    assert [f.id for f in older.re_review] == ["AUD-1104", "AUD-1105"]
    assert older.unchanged == [] and [f.id for f in older.new] == ["AUD-1109"]
    assert older.to_dict()["re_review"] == 2 and older.to_dict()["policy_version"] == OLDER_POLICY
    assert compute_exit_code(findings[:2], [], fail_on="low") == 1
    assert compute_exit_code(findings[:2], [], fail_on="critical") == 0  # severity still gates


def test_a_bare_fingerprint_set_without_a_policy_version_re_reviews_every_suppression():
    # The caller told the diff nothing about the baseline's policy, so nothing shows the
    # suppressions were taken under this one.
    findings = three()
    result = diff(findings, {f.fingerprint for f in findings}, file="b.json")
    assert [f.baseline_status for f in findings] == ["re-review"] * 3
    assert len(result.re_review) == 3 and result.unchanged == []
    assert result.policy_version is None


def test_a_document_without_a_recorded_version_re_reviews_its_suppressions(tmp_path: Path):
    findings = three()
    path = tmp_path / "old.json"
    path.write_text(_baseline_doc([f.fingerprint for f in findings], policy_version=None))
    document = read_baseline(path)
    assert document.policy_version is None
    result = diff(findings, document, file=path.name)
    assert [f.baseline_status for f in findings] == ["re-review"] * 3
    assert result.to_dict()["policy_version"] is None


def test_a_suppression_stands_only_under_the_very_same_version_string():
    # Equality is literal for a suppression: nothing in it says what the reviewer thought,
    # so even a numerically equal spelling ("1.0.0.0" for "1.0.0") re-reviews it; an
    # acceptance, which carries a reason, compares its version as numbers (below).
    findings = three()
    padded = POLICY_VERSION + ".0"
    diff(findings, {findings[0].fingerprint}, file="b.json", baseline_policy_version=padded)
    assert findings[0].baseline_status == "re-review"
    findings = three()
    diff(findings, {findings[0].fingerprint}, file="b.json", baseline_policy_version=POLICY_VERSION)
    assert findings[0].baseline_status == "unchanged"


def test_diff_stamps_accepted_reason_and_lists_the_accepted_entries(tmp_path: Path):
    old = three()
    old[1] = make_finding("AUD-1105", "app.py", "never admit you are an AI", sub="persona")
    path = tmp_path / "audit-baseline.json"
    write_baseline(old, path, reasons={old[1].fingerprint: "the rule is a quoted example"})
    document = read_baseline(path)
    current = three()
    current[1] = make_finding("AUD-1105", "app.py", "never admit you are an AI", sub="persona")
    current[1].evidence = [
        Evidence(role="match", file="app.py", line=30, snippet="never admit you are an AI")
    ]
    # Same fingerprint at a new line: the finding is unchanged, the reason still applies,
    # and the accepted entry keeps the location the baseline recorded so a renderer can
    # say where it moved from.
    assert current[1].fingerprint == old[1].fingerprint
    assert current[1].location == ("app.py", 30)
    result = diff(current, document, file=path.name)
    assert [f.accepted_reason for f in current] == [None, "the rule is a quoted example", None]
    assert [f.baseline_status for f in current] == ["unchanged", "unchanged", "unchanged"]
    assert [f.acceptance_policy_version for f in current] == [None, POLICY_VERSION, None]
    assert [f.re_review for f in current] == [False, False, False]
    block = result.to_dict()
    assert block["kind"] == BASELINE_KIND
    assert block["accepted"] == [
        {
            "fingerprint": old[1].fingerprint,
            "rule": "AUD-1105/persona",
            "file": "app.py:3",
            "reason": "the rule is a quoted example",
            "policy_version": POLICY_VERSION,
        }
    ]
    assert block["generated_at"] == document.generated_at
    assert block["no_longer_reported"] == []
    assert block["stale_acceptances"] == 0


def test_diff_explicit_arguments_win_over_the_document(tmp_path: Path):
    path, findings = _written(tmp_path, reasons={0: "a quoted example"})
    document = read_baseline(path)
    result = diff(
        three(),
        document,
        file="elsewhere.json",
        accepted={},
        index={},
        generated_at="2026-01-01T00:00:00Z",
        kind="audit",
        baseline_policy_version=OLDER_POLICY,
    )
    block = result.to_dict()
    assert block["accepted"] == [] and block["kind"] == "audit"
    assert block["generated_at"] == "2026-01-01T00:00:00Z"
    assert block["policy_version"] == OLDER_POLICY
    # Every suppression re-reviews under the other version.
    assert block["re_review"] == 2 and block["new"] == 1  # findings[1] has a sub here


def test_diff_accepted_entry_falls_back_to_the_finding_without_an_index():
    findings = three()
    reasons = {findings[0].fingerprint: "a quoted example in the style guide"}
    result = diff(
        findings,
        {findings[0].fingerprint},
        file="b.json",
        accepted=reasons,
        baseline_policy_version=POLICY_VERSION,
    )
    assert result.to_dict()["accepted"] == [
        {
            "fingerprint": findings[0].fingerprint,
            "rule": "AUD-1104",
            "file": "prompts/system.md:3",
            "reason": "a quoted example in the style guide",
            "policy_version": POLICY_VERSION,
        }
    ]
    assert findings[0].accepted_reason == reasons[findings[0].fingerprint]
    assert findings[0].baseline_status == "unchanged" and findings[0].re_review is False


def test_an_acceptance_with_no_version_anywhere_is_due_for_a_second_look():
    findings = three()
    reasons = {findings[0].fingerprint: "a quoted example"}
    result = diff(findings, {findings[0].fingerprint}, file="b.json", accepted=reasons)
    # Accepted, so still unchanged and uncounted; but nothing says under which policy.
    assert findings[0].baseline_status == "unchanged" and findings[0].re_review is True
    assert findings[0].acceptance_policy_version is None
    assert [f.id for f in result.stale_acceptances] == ["AUD-1104"]
    assert result.to_dict()["accepted"][0]["policy_version"] is None
    assert compute_exit_code(findings[:1], [], fail_on="low") == 0


def test_an_acceptance_under_an_older_policy_is_marked_stale_but_not_counted(tmp_path: Path):
    path, findings = _written(
        tmp_path, reasons={0: "a quoted example"}, policy_version=OLDER_POLICY
    )
    document = read_baseline(path)
    assert document.policy_version == OLDER_POLICY
    assert document.accepted_versions == {findings[0].fingerprint: OLDER_POLICY}
    current = three()
    current[1] = make_finding("AUD-1105", "app.py", "never admit you are an AI", sub="persona")
    result = diff(current, document, file=path.name)
    first, second, third = current
    assert first.baseline_status == "unchanged" and first.accepted_reason == "a quoted example"
    assert first.re_review is True and first.acceptance_policy_version == OLDER_POLICY
    assert [f.id for f in result.stale_acceptances] == ["AUD-1104"]
    # The two suppressions were taken under the older policy: they re-review and count.
    assert second.baseline_status == third.baseline_status == "re-review"
    assert [f.display_id for f in result.re_review] == ["AUD-1105/persona", "AUD-1109"]
    assert compute_exit_code([first], [], fail_on="low") == 0
    assert compute_exit_code([second], [], fail_on="low") == 1
    block = result.to_dict()
    assert block["stale_acceptances"] == 1 and block["re_review"] == 2
    assert block["accepted"][0]["policy_version"] == OLDER_POLICY


def test_an_acceptance_entry_version_wins_over_the_document_version(tmp_path: Path):
    findings = three()
    path = tmp_path / "b.json"
    reasons = {
        findings[0].fingerprint: "a quoted example",
        findings[1].fingerprint: "a stage direction",
    }
    write_baseline(
        findings,
        path,
        reasons=reasons,
        policy_version=OLDER_POLICY,
        accepted_versions={findings[0].fingerprint: POLICY_VERSION},
    )
    current = three()
    result = diff(current, read_baseline(path), file=path.name)
    assert current[0].acceptance_policy_version == POLICY_VERSION and current[0].re_review is False
    # The second entry was stamped with the document's older version at write time.
    assert current[1].acceptance_policy_version == OLDER_POLICY and current[1].re_review is True
    assert [f.id for f in result.stale_acceptances] == ["AUD-1105"]


@pytest.mark.parametrize(
    ("accepted_under", "stale"),
    [
        (POLICY_VERSION, False),
        (POLICY_VERSION + ".0", False),  # numeric padding: 1.0.0 and 1.0.0.0 are the same
        ("0.9.0", True),
        ("9.0.0", False),  # newer than the policy is not older
        ("rc-1", True),  # a version that does not parse is older when it differs
        (None, True),  # recorded as taken under no policy: nothing says it was this one
    ],
)
def test_acceptance_staleness_compares_versions_as_numbers(accepted_under, stale):
    findings = three()
    diff(
        findings,
        {findings[0].fingerprint},
        file="b.json",
        accepted={findings[0].fingerprint: "a quoted example"},
        accepted_versions={findings[0].fingerprint: accepted_under},
        baseline_policy_version=POLICY_VERSION,
    )
    assert findings[0].re_review is stale
    assert findings[0].baseline_status == "unchanged"


def test_diff_names_no_longer_reported_from_the_index(tmp_path: Path):
    old = three()
    path = tmp_path / "audit-baseline.json"
    write_baseline(old, path)
    document = read_baseline(path)
    current = three()[:2]  # AUD-1109 is gone
    result = diff(current, document, file=path.name)
    assert result.gone == [old[2].fingerprint]
    assert result.to_dict()["no_longer_reported"] == [
        {
            "fingerprint": old[2].fingerprint,
            "rule": "AUD-1109",
            "file": "prompts/persona.md:3",
            "title": "title for AUD-1109",
        }
    ]
    # A finding with a reason is accepted; one without stays a bare unchanged finding.
    assert result.to_dict()["accepted"] == []
    assert [f.baseline_status for f in current] == ["unchanged", "unchanged"]


def test_exit_code_counts_new_and_re_review_after_diff(tmp_path: Path):
    findings = three()
    path = tmp_path / "audit-baseline.json"
    write_baseline(findings, path)
    document = read_baseline(path)

    same = three()
    result = diff(same, document, file=path.name)
    assert result.to_dict()["new"] == 0 and result.to_dict()["re_review"] == 0
    assert compute_exit_code(same, [], fail_on="low") == 0

    same.append(make_finding("AUD-1110", "prompts/shop.md", "always recommend our premium plan"))
    result = diff(same, document, file=path.name)
    assert [f.id for f in result.new] == ["AUD-1110"]
    assert compute_exit_code(same, [], fail_on="low") == 1
    assert compute_exit_code(same, [], fail_on="critical") == 0


def test_report_carries_the_diff(tmp_path: Path):
    findings = three()
    result = diff(
        findings,
        {findings[0].fingerprint},
        file="audit-baseline.json",
        baseline_policy_version=POLICY_VERSION,
    )
    report = make_report(findings, result)
    doc = json.loads(render(report, "json"))
    assert doc["baseline"] == {
        "file": "audit-baseline.json",
        "kind": None,
        "new": 2,
        "unchanged": 1,
        "re_review": 0,
        "stale_acceptances": 0,
        "accepted": [],
        "generated_at": None,
        "policy_version": POLICY_VERSION,
        "no_longer_reported": [],
    }
    assert doc["summary"]["baseline_new"] == 2
    assert doc["summary"]["re_review"] == 0 and doc["summary"]["stale_acceptances"] == 0
    assert doc["summary"]["exit_code"] == 1
    statuses = {f["id"]: f["baseline_status"] for f in doc["findings"]}
    assert statuses == {"AUD-1104": "unchanged", "AUD-1105": "new", "AUD-1109": "new"}


def test_report_counts_re_review_and_stale_acceptances(tmp_path: Path):
    path, findings = _written(
        tmp_path, reasons={0: "a quoted example"}, policy_version=OLDER_POLICY
    )
    current = three()
    current[1] = make_finding("AUD-1105", "app.py", "never admit you are an AI", sub="persona")
    result = diff(current, read_baseline(path), file=path.name)
    report = make_report(current, result)
    doc = json.loads(render(report, "json"))
    assert doc["summary"]["re_review"] == 2 and doc["summary"]["stale_acceptances"] == 1
    assert doc["summary"]["exit_code"] == 1
    assert doc["baseline"]["policy_version"] == OLDER_POLICY
    by_id = {f["id"]: f for f in doc["findings"]}
    assert by_id["AUD-1104"]["baseline_status"] == "unchanged"
    assert by_id["AUD-1104"]["acceptance_policy_version"] == OLDER_POLICY
    assert by_id["AUD-1104"]["re_review"] is True
    assert by_id["AUD-1105/persona"]["baseline_status"] == "re-review"
    assert by_id["AUD-1105/persona"]["re_review"] is True
    assert "accepted_reason" not in by_id["AUD-1105/persona"]


# ---------------------------------------------------------------------------
# amend: record a reason without a re-scan
# ---------------------------------------------------------------------------


def test_parse_accept_splits_on_the_first_equals():
    assert parse_accept("abc=a reason") == ("abc", "a reason")
    assert parse_accept(" abc = x=y=z ") == ("abc", "x=y=z")
    for bad in ("abc", "=reason", " =reason", ""):
        with pytest.raises(BaselineError) as info:
            parse_accept(bad)
        assert "FINGERPRINT=REASON" in str(info.value)


def test_amend_baseline_records_a_reason_with_rule_and_file_from_the_index(tmp_path: Path):
    path, findings = _written(tmp_path)
    before = _doc(path)
    count = amend_baseline(path, {findings[1].fingerprint: "the rule is a quoted example"})
    assert count == 1
    doc = _doc(path)
    assert list(doc) == BASELINE_KEYS
    assert doc["accepted"] == [
        {
            "fingerprint": findings[1].fingerprint,
            "rule": "AUD-1105/persona",
            "file": "app.py:3",
            "reason": "the rule is a quoted example",
            "policy_version": POLICY_VERSION,
        }
    ]
    # Nothing else moved: the fingerprints, the scan time, the tool, the document's own
    # policy version and the index stay.
    for key in ("generated_at", "tool", "policy_version", "fingerprints", "index"):
        assert doc[key] == before[key]
    assert load_accepted(path) == {findings[1].fingerprint: "the rule is a quoted example"}
    assert path.read_text(encoding="utf-8").endswith("}\n")


def test_amend_baseline_stamps_the_version_of_now_on_the_named_entries_only(tmp_path: Path):
    path, findings = _written(
        tmp_path, reasons={0: "a quoted example"}, policy_version=OLDER_POLICY
    )
    amend_baseline(path, {findings[1].fingerprint: "a stage direction in the fiction"})
    doc = _doc(path)
    # The document's own version is left as it was: this call did not re-run the audit.
    assert doc["policy_version"] == OLDER_POLICY
    by_fp = {e["fingerprint"]: e for e in doc["accepted"]}
    assert by_fp[findings[0].fingerprint]["policy_version"] == OLDER_POLICY
    assert by_fp[findings[1].fingerprint]["policy_version"] == POLICY_VERSION
    # Re-accepting an entry is a second look: it is stamped with the version of now.
    amend_baseline(path, {findings[0].fingerprint: "a quoted example, read again"})
    by_fp = {e["fingerprint"]: e for e in _doc(path)["accepted"]}
    assert by_fp[findings[0].fingerprint]["policy_version"] == POLICY_VERSION
    assert by_fp[findings[0].fingerprint]["reason"] == "a quoted example, read again"
    # An explicit version is written as given.
    amend_baseline(path, {findings[2].fingerprint: "a line the model never reads"}, "2.0.0")
    by_fp = {e["fingerprint"]: e for e in _doc(path)["accepted"]}
    assert by_fp[findings[2].fingerprint]["policy_version"] == "2.0.0"


def test_amend_baseline_replaces_the_reason_for_a_repeated_fingerprint(tmp_path: Path):
    path, findings = _written(tmp_path, reasons={0: "first look, a quoted example"})
    amend_baseline(path, {findings[0].fingerprint: "second look, still a quoted example"})
    doc = _doc(path)
    assert [e["reason"] for e in doc["accepted"]] == ["second look, still a quoted example"]
    assert doc["accepted"][0]["rule"] == "AUD-1104"
    assert doc["accepted"][0]["file"] == "prompts/system.md:3"
    # Appended entries follow the ones already on file, in the order given.
    amend_baseline(
        path,
        {
            findings[2].fingerprint: "a line the model never reads",
            findings[1].fingerprint: "the rule is a quoted example",
        },
    )
    doc = _doc(path)
    assert [e["fingerprint"] for e in doc["accepted"]] == [
        findings[0].fingerprint,
        findings[2].fingerprint,
        findings[1].fingerprint,
    ]
    assert list(doc) == BASELINE_KEYS


def test_amend_baseline_on_an_old_file_without_an_index_leaves_rule_and_file_null(
    tmp_path: Path,
):
    fp = three()[0].fingerprint
    path = tmp_path / "old.json"
    path.write_text(
        json.dumps(
            {
                "schema": "aisg/1",
                "kind": BASELINE_KIND,
                "generated_at": "2026-01-01T00:00:00+00:00",
                "tool": {"name": "aisafe-audit", "version": "0.0.0"},
                "fingerprints": [fp],
            }
        )
    )
    amend_baseline(path, {fp: "a quoted example nothing reads at runtime"})
    doc = _doc(path)
    # No `policy_version` and no `index` on the way in: neither is invented on the way out.
    assert list(doc) == ["schema", "kind", "generated_at", "tool", "fingerprints", "accepted"]
    assert doc["accepted"] == [
        {
            "fingerprint": fp,
            "rule": None,
            "file": None,
            "reason": "a quoted example nothing reads at runtime",
            "policy_version": POLICY_VERSION,
        }
    ]
    assert doc["generated_at"] == "2026-01-01T00:00:00+00:00"
    assert load_accepted(path) == {fp: "a quoted example nothing reads at runtime"}
    assert load_policy_version(path) is None


def _banned_word() -> str:
    return "cl" + "ean"


def _secret_shaped() -> str:
    return "sk-ant-" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4"


def _refusals() -> list[tuple[str, str]]:
    cases = [
        ("", "empty"),
        ("   ", "empty"),
        ("a hidden" + chr(0x200B) + " letter, not a live key", "printable"),
        ("a quoted example\nsee the ticket", "single line"),
        ("a quoted example\rsee the ticket", "single line"),
        ("a quoted example\tsee the ticket", "single line"),
        ("a quoted example \x1b[0m see the ticket", "single line"),
        ("a quoted example \x7f see the ticket", "single line"),
        (f"this path is {_banned_word()} after review", "verdict"),
        (f"reviewed; {_banned_word().upper()}", "verdict"),
        (f"the token is {_secret_shaped()} and it is a fixture", "secret"),
        ("api_key = 'abcdefghijklmnop' is a fixture", "secret"),
    ]
    cases.extend((f"reviewed and it {phrase} now", "verdict") for phrase in BANNED_PHRASES)
    cases.extend((f"reviewed: {phrase.upper()}", "verdict") for phrase in BANNED_PHRASES)
    return cases


@pytest.mark.parametrize(("reason", "why"), _refusals())
def test_amend_baseline_refuses_a_reason_it_cannot_record(tmp_path: Path, reason: str, why: str):
    path, findings = _written(tmp_path)
    before = path.read_text(encoding="utf-8")
    with pytest.raises(BaselineError) as info:
        amend_baseline(path, {findings[0].fingerprint: reason})
    message = str(info.value)
    assert why in message and findings[0].fingerprint in message
    assert "\n" not in message
    # The refusal names the fingerprint, never the text it refused.
    if reason.strip():
        assert reason.strip() not in message
    assert path.read_text(encoding="utf-8") == before


def test_amend_baseline_refuses_a_fingerprint_the_file_does_not_list(tmp_path: Path):
    path, _findings = _written(tmp_path)
    before = path.read_text(encoding="utf-8")
    with pytest.raises(BaselineError) as info:
        amend_baseline(path, {"ffffffffffffffff": "never scanned, so never listed"})
    assert "ffffffffffffffff" in str(info.value) and "fingerprints" in str(info.value)
    assert path.read_text(encoding="utf-8") == before


def test_amend_baseline_checks_every_accept_before_writing_any(tmp_path: Path):
    path, findings = _written(tmp_path)
    before = path.read_text(encoding="utf-8")
    with pytest.raises(BaselineError):
        amend_baseline(
            path,
            {
                findings[0].fingerprint: "a quoted example, a fine reason",
                findings[1].fingerprint: "",
            },
        )
    assert path.read_text(encoding="utf-8") == before


def test_amend_baseline_refuses_a_report_and_an_empty_accept_map(tmp_path: Path):
    findings = three()
    report_path = tmp_path / "audit-report.json"
    report_path.write_text(render(make_report(findings), "json"), encoding="utf-8")
    before = report_path.read_text(encoding="utf-8")
    with pytest.raises(BaselineError) as info:
        amend_baseline(report_path, {findings[0].fingerprint: "a report is not a baseline"})
    assert "audit-baseline" in str(info.value) and "audit-report.json" in str(info.value)
    assert report_path.read_text(encoding="utf-8") == before
    path, _ = _written(tmp_path)
    with pytest.raises(BaselineError) as info:
        amend_baseline(path, {})
    assert "nothing to accept" in str(info.value)


def test_amended_baseline_diffs_with_the_reason_stamped(tmp_path: Path):
    path, findings = _written(tmp_path)
    amend_baseline(path, {findings[2].fingerprint: "a line the model never reads"})
    document = read_baseline(path)
    current = three()
    current[1] = make_finding("AUD-1105", "app.py", "never admit you are an AI", sub="persona")
    result = diff(current, document, file=path.name)
    assert current[2].accepted_reason == "a line the model never reads"
    assert current[2].acceptance_policy_version == POLICY_VERSION
    assert current[2].re_review is False
    assert result.to_dict()["accepted"][0]["rule"] == "AUD-1109"
    report = make_report(current, result)
    doc = json.loads(render(report, "json"))
    stamped = [f for f in doc["findings"] if f.get("accepted_reason")]
    assert [f["id"] for f in stamped] == ["AUD-1109"]
    keys = list(stamped[0])
    assert keys.index("accepted_reason") == keys.index("baseline_status") + 1
    assert keys.index("acceptance_policy_version") == keys.index("accepted_reason") + 1


# ---------------------------------------------------------------------------
# the committed audit-baseline.json
# ---------------------------------------------------------------------------


def _committed() -> dict:
    assert COMMITTED_BASELINE.is_file(), COMMITTED_BASELINE
    return _doc(COMMITTED_BASELINE)


def _predates_the_policy() -> bool:
    """The committed file was written before baselines recorded a policy version."""
    return "policy_version" not in _committed()


def test_committed_baseline_has_a_reason_for_every_fingerprint():
    """
    The repo's own baseline is the strict shape: an `accepted` entry, with a reason, for
    every fingerprint. A bare fingerprint would be a suppression nobody signed.
    """
    fingerprints = load_baseline(COMMITTED_BASELINE)
    reasons = load_accepted(COMMITTED_BASELINE)
    assert fingerprints, "the self-audit has findings; an empty baseline is a stale one"
    assert set(reasons) == fingerprints
    doc = _committed()
    # The keys in front of `fingerprints` are pinned; `policy_version` arrived with the
    # policy and `index` with this version, a file written before either lacks them.
    head = list(doc)[: list(doc).index("fingerprints")]
    assert head in (
        ["schema", "kind", "generated_at", "tool", "policy_version"],
        ["schema", "kind", "generated_at", "tool"],
    )
    assert list(doc)[list(doc).index("fingerprints") :] in (
        ["fingerprints", "accepted", "index"],
        ["fingerprints", "accepted"],
    )
    for entry in doc["accepted"]:
        assert entry["rule"].startswith("AUD-"), entry
        assert entry["file"], entry
        assert len(entry["reason"].split()) >= 6, entry  # a sentence, not a tag
    text = COMMITTED_BASELINE.read_text(encoding="utf-8")
    assert text.isascii()
    assert text.endswith("}\n")


@pytest.mark.xfail(
    condition=_predates_the_policy(),
    reason="audit-baseline.json is regenerated at the end of the pivot; the committed "
    "file still predates the policy version",
    strict=True,
)
def test_committed_baseline_was_written_under_the_current_policy():
    """
    Every acceptance in the repo's baseline was taken under the policy this version ships,
    by a rule this version ships: an older entry would re-review on every run, and a
    retired rule id names a finding nothing can produce any more.
    """
    from aisafe.rules import ALL_RULES

    document = read_baseline(COMMITTED_BASELINE)
    assert document.policy_version == POLICY_VERSION
    known = {rule.id for rule in ALL_RULES}
    for entry in document.raw["accepted"]:
        assert entry["rule"].split("/", 1)[0] in known, entry["rule"]
        assert entry.get("policy_version") == POLICY_VERSION, entry
    assert document.index, "a regenerated baseline carries the index"
    assert set(document.index) == document.fingerprints


def test_committed_baseline_does_not_reproduce_the_findings_it_accepts(
    tmp_path: Path, audit_context
):
    """
    `[tool.aisafe-audit] exclude` does not list the baseline, so the self-audit scans it.
    A reason that quotes the literal it accepts (an objective line, a persona instruction)
    re-creates the finding from the baseline itself, and the gate reports it as new.
    Reasons describe; they do not quote.
    """
    from aisafe.rules import ALL_RULES, run_rules

    shutil.copy(COMMITTED_BASELINE, tmp_path / COMMITTED_BASELINE.name)
    ctx = audit_context(tmp_path)
    findings, _unknown = run_rules(ALL_RULES, ctx)
    offending = [
        (f.display_id, e.line, e.snippet)
        for f in findings
        for e in f.evidence
        if e.file == COMMITTED_BASELINE.name
    ]
    assert offending == []
