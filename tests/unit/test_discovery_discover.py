"""tests/unit/test_discovery_discover.py
---
Grep-level discovery for `aisafe audit`: what the fixtures must yield, what they must
never yield, and the honesty rules (redaction, UNKNOWN, report age). The person
vocabulary is scanned per file class (code, config, a doc under the prompt globs), a
mention in a comment is not a deployment, a prompt-only tree is an AI surface that says
what it could not read, and a prompt fetched at runtime is UNKNOWN, never a pass.
"""

from __future__ import annotations

import json
import re
import shutil
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aisafe.discovery import discover, patterns, walk
from aisafe.discovery import vocabulary as vocab
from aisafe.discovery.discover import (
    DiscoverOptions,
    ai_surface_units,
    grep_file,
    merge_pyfacts_prompts,
    read_report,
    read_system_card,
    unit_ai_surface,
)
from aisafe.discovery.walk import FileRecord
from aisafe.evidence.model import INVENTORY_KEYS, Hit, Inventory, UnknownCategory

BASELINE_FIXTURE = "clean_py"  # the fixture with no AI surface at all
KEPT_FIXTURES = ("clean_py", "ts_agent", "go_service", "persons_companion", "persons_benign")

# Entry shapes -- exact, no extras, no omissions.
MODEL_KEYS = {"id", "file", "line", "provider", "model", "pinned", "source"}
LEG_KEYS = {"file", "line", "kind", "symbol", "unit"}
PROMPT_KEYS = {"file", "line", "kind", "name", "is_system", "unit"}
CARD_KEYS = {"file", "affected_persons", "prompt_audit"}
LEGACY_SECTIONS = (
    "tools",
    "mcp",
    "hosts",
    "secrets",
    "sinks",
    "loops",
    "evals",
    "guardrails",
    "observability",
    "data_sources",
    "external_actions",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run(root: Path, options: object = None) -> tuple[Inventory, list[Hit]]:
    records, units, _unknown = walk.walk(root)
    return discover.discover(root, records, units, options)


def project(tmp_path: Path, files: dict[str, str], name: str = "proj") -> Path:
    """A scratch project with a manifest so the root unit is python."""
    root = tmp_path / name
    root.mkdir()
    (root / "pyproject.toml").write_text('[project]\nname = "proj"\n', encoding="utf-8")
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
    return root


def by_table(hits: list[Hit], table: str) -> list[Hit]:
    return [h for h in hits if h.table == table]


def keys_in(hits: list[Hit], table: str, file: str) -> set[tuple[int, str]]:
    return {(h.line, h.key) for h in hits if h.table == table and h.file == file}


def unknown_of(inventory: Inventory, category: UnknownCategory) -> list:
    return [u for u in inventory.unknown if u.category is category]


def record_for(path: Path, relpath: str, lang: str, text: str) -> FileRecord:
    return FileRecord(path=path, relpath=relpath, lang=lang, unit="u0", size=len(text))


def grep(tmp_path: Path, relpath: str, text: str, lang: str) -> list[Hit]:
    path = tmp_path / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    text = textwrap.dedent(text).lstrip("\n")
    path.write_text(text, encoding="utf-8")
    return grep_file(record_for(path, relpath, lang, text), text)


# ---------------------------------------------------------------------------
# py_agent: the reference fixture for the AI surface
# ---------------------------------------------------------------------------


class TestPyAgent:
    @pytest.fixture(autouse=True)
    def _run(self, audit_fixture) -> None:
        self.root = audit_fixture("py_agent")
        self.inv, self.hits = run(self.root)
        self.doc = self.inv.to_dict()

    def test_languages(self) -> None:
        assert self.inv.languages["python"] >= 2
        assert set(self.inv.languages) == {"python", "typescript", "go", "other"}

    def test_llm_call_at_app_42_with_model_ref(self) -> None:
        calls = [c for c in self.inv.llm_calls if c["file"] == "app.py" and c["line"] == 42]
        assert calls, self.inv.llm_calls
        call = calls[0]
        assert call["provider"] == "anthropic"
        assert call["unit"] == "u0"
        assert set(call) == {"file", "line", "provider", "sdk", "api", "unit", "model_ref"}
        ref = call["model_ref"]
        assert ref is not None
        model = next(m for m in self.inv.models if m["id"] == ref)
        assert model["model"].startswith("claude-")
        assert model["provider"] == "anthropic"
        assert isinstance(model["pinned"], bool)
        assert model["pinned"] == patterns.classify_model("anthropic", model["model"])
        assert model["source"] == "literal"

    def test_model_ids_are_numbered_and_unique(self) -> None:
        ids = [m["id"] for m in self.inv.models]
        assert ids == [f"m{i}" for i in range(1, len(ids) + 1)]

    def test_model_entries_carry_exactly_the_keys(self) -> None:
        assert self.inv.models
        for entry in self.inv.models:
            assert set(entry) == MODEL_KEYS, sorted(entry)

    def test_llm_call_falls_back_to_a_model_in_the_same_unit(self, tmp_path: Path) -> None:
        # No model id in the calling file: the ref resolves through the unit, not a
        # `unit` key on the model entry.
        root = project(
            tmp_path,
            {
                "settings.py": 'MODEL = "claude-sonnet-4-5-20250929"\n',
                "worker.py": (
                    "import anthropic\n"
                    "client = anthropic.Anthropic()\n"
                    "client.messages.create(model=MODEL, messages=[])\n"
                ),
            },
        )
        inv, _hits = run(root)
        assert inv.models and all("unit" not in m for m in inv.models)
        calls = [c for c in inv.llm_calls if c["file"] == "worker.py"]
        assert calls
        ref = calls[0]["model_ref"]
        assert ref is not None
        assert next(m for m in inv.models if m["id"] == ref)["file"] == "settings.py"

    def test_prompts(self) -> None:
        for entry in self.inv.prompts:
            assert set(entry) == PROMPT_KEYS, sorted(entry)
        by_key = {(p["file"], p["line"]): p for p in self.inv.prompts}
        system_file = by_key[("prompts/system.md", 1)]
        assert system_file["kind"] == "file" and system_file["is_system"] is True
        assert system_file["name"] == "prompts/system.md" and system_file["unit"] == "u0"
        assert by_key[("app.py", 37)]["kind"] == "assembly"
        assert by_key[("app.py", 37)]["name"] == "system_prompt"
        assert by_key[("app.py", 37)]["is_system"] is True
        assert by_key[("app.py", 38)]["name"] == "prompt"
        assert by_key[("app.py", 38)]["is_system"] is False
        assert by_key[("app.py", 45)]["is_system"] is True  # `system=system_prompt,`

    def test_ingress(self) -> None:
        assert any(i["kind"] == "http" for i in self.inv.ingress)
        for leg in self.inv.ingress:
            assert set(leg) == LEG_KEYS

    def test_system_card_is_pruned_to_two_keys(self) -> None:
        card = self.inv.system_card
        assert card is not None
        assert card["file"] == "ai-system-card.yaml"
        assert set(card) == CARD_KEYS
        assert card["prompt_audit"] is None

    def test_units_and_surface(self) -> None:
        assert self.inv.units[0].id == "u0"
        assert self.inv.units[0].ai_surface is True
        assert unit_ai_surface(self.inv, "u0") is True
        assert unit_ai_surface(self.inv, "u99") is False
        assert "u0" in ai_surface_units(self.inv)
        # A Python unit with an SDK: nothing is UNKNOWN about its surface.
        assert not unknown_of(self.inv, UnknownCategory.DEEP)
        assert not unknown_of(self.inv, UnknownCategory.COVERAGE)

    def test_no_reports_and_no_review_records(self) -> None:
        assert self.inv.reports == []
        assert self.inv.review_records == []

    def test_target(self) -> None:
        target = self.inv.target
        assert set(target) == {
            "path",
            "git_sha",
            "dirty",
            "scanned_files",
            "skipped_files",
            "bytes",
            "duration_ms",
        }
        assert target["scanned_files"] > 0
        assert target["skipped_files"] == 0
        assert target["bytes"] > 0

    def test_hits_are_sorted_and_carry_unit(self) -> None:
        keys = [(h.file, h.line, h.col, h.table, h.key) for h in self.hits]
        assert keys == sorted(keys)
        assert all(h.unit == "u0" for h in self.hits)

    def test_inventory_has_no_legacy_sections(self) -> None:
        assert list(self.doc) == list(INVENTORY_KEYS)
        for key in LEGACY_SECTIONS:
            assert key not in self.doc, key
        tables = {h.table for h in self.hits}
        assert not tables & {"tool_def", "sink", "secret", "mcp", "loop", "kill_switch_read"}


# ---------------------------------------------------------------------------
# The other fixtures
# ---------------------------------------------------------------------------


def test_baseline_fixture_has_no_surface(audit_fixture) -> None:
    inv, hits = run(audit_fixture(BASELINE_FIXTURE))
    assert all(u.ai_surface is False for u in inv.units)
    assert inv.llm_calls == [] and inv.models == [] and inv.frameworks == []
    assert inv.prompts == [] and inv.person_signals == []
    assert inv.memory_stores == [] and inv.personas == []
    assert inv.unknown == []
    assert not by_table(hits, "llm_call")
    assert not by_table(hits, "person_signal")


def test_ts_agent(audit_fixture) -> None:
    inv, hits = run(audit_fixture("ts_agent"))
    assert inv.units[0].ai_surface is True
    deep = unknown_of(inv, UnknownCategory.DEEP)
    assert deep and "typescript" in deep[0].what
    assert "pattern-level findings only" in deep[0].why
    assert deep[0].file == "."
    assert not unknown_of(inv, UnknownCategory.COVERAGE)  # an SDK is present
    assert any(f["name"] == "vercel_ai" for f in inv.frameworks)
    # The Vercel AI SDK is an LLM call in its own right: the import and the call site.
    vercel = [(h.line, h.snippet) for h in by_table(hits, "llm_call") if h.key == "vercel_ai"]
    assert [line for line, _ in vercel] == [4, 9]
    assert any(c["file"] == "src/agent.ts" and c["line"] == 9 for c in inv.llm_calls)
    assert {c["provider"] for c in inv.llm_calls if c["line"] == 9} == {"multi"}
    assert [(p["line"], p["kind"]) for p in inv.prompts] == [(12, "assembly")]


def test_go_service(audit_fixture) -> None:
    inv, hits = run(audit_fixture("go_service"))
    assert inv.units[0].ai_surface is True
    deep = unknown_of(inv, UnknownCategory.DEEP)
    assert deep and "go" in deep[0].what
    assert any(h.key == "generic_http" for h in by_table(hits, "llm_call"))
    assert inv.llm_calls and inv.llm_calls[0]["file"] == "main.go"
    assert inv.llm_calls[0]["provider"] == "unknown"
    accessors = [(h.line, h.key) for h in by_table(hits, "response_accessor")]
    assert accessors == [(57, "choices_message_content_go")]
    # The `"role": "system"` entry is a system prompt assembly with no left-hand name.
    assert [(p["line"], p["name"], p["is_system"]) for p in inv.prompts] == [(28, "", True)]


class TestPersonsCompanion:
    """The reference fixture for the person vocabulary."""

    @pytest.fixture(autouse=True)
    def _run(self, audit_fixture) -> None:
        self.root = audit_fixture("persons_companion")
        self.inv, self.hits = run(self.root)

    def test_signals_land_in_the_inventory_by_kind(self) -> None:
        rows = {(s["file"], s["line"], s["kind"]) for s in self.inv.person_signals}
        assert rows == {
            ("analytics.py", 9, "profile_sdk"),
            ("app.py", 11, "persona"),
            ("app.py", 19, "profile_name"),
            ("prompts/companion.md", 3, "engagement"),
            ("prompts/companion.md", 3, "persona"),
            ("prompts/companion.md", 4, "memory"),
        }
        for entry in self.inv.person_signals:
            assert set(entry) == LEG_KEYS and entry["unit"] == "u0"

    def test_memory_stores_and_personas_are_views_of_the_signals(self) -> None:
        assert [(m["file"], m["line"]) for m in self.inv.memory_stores] == [
            ("prompts/companion.md", 4)
        ]
        assert [(p["file"], p["line"]) for p in self.inv.personas] == [
            ("app.py", 11),
            ("prompts/companion.md", 3),
        ]
        assert all(p["kind"] == "persona" for p in self.inv.personas)

    def test_candidates_stay_out_of_the_inventory(self) -> None:
        # Lines 9 and 12 of app.py sit inside string literals the grep tier cannot place;
        # they are candidates a rule may promote, never inventory rows.
        candidates = keys_in(self.hits, "person_signal_candidate", "app.py")
        assert (9, "persona:never_admit") in candidates
        assert (12, "engagement:keep") in candidates
        assert (12, "engagement:maximise") in candidates
        assert (12, "vulnerable:group") in candidates
        inventory_lines = {(s["file"], s["line"]) for s in self.inv.person_signals}
        assert ("app.py", 12) not in inventory_lines and ("app.py", 9) not in inventory_lines

    def test_profile_and_ingress_reach_the_prompt(self) -> None:
        assert keys_in(self.hits, "profile_to_prompt", "app.py") == {(19, "user_profile")}
        assert keys_in(self.hits, "ingress_to_prompt", "app.py") == {(19, "body")}

    def test_prompts(self) -> None:
        rows = [(p["file"], p["line"], p["kind"], p["name"]) for p in self.inv.prompts]
        assert rows == [
            ("app.py", 19, "assembly", "prompt"),
            ("app.py", 21, "assembly", "system"),
            ("prompts/companion.md", 1, "file", "prompts/companion.md"),
        ]
        assert self.inv.prompts[1]["is_system"] is True
        assert self.inv.prompts[2]["is_system"] is None  # unknown, not False

    def test_system_card_keeps_affected_persons(self) -> None:
        assert self.inv.system_card == {
            "file": "ai-system-card.yaml",
            "affected_persons": "teenagers using the companion app",
            "prompt_audit": None,
        }

    def test_python_unit_with_an_sdk_has_no_surface_unknowns(self) -> None:
        assert self.inv.units[0].ai_surface is True
        assert self.inv.unknown == []


def test_persons_benign_records_disclosure_and_a_discussed_term(audit_fixture) -> None:
    inv, hits = run(audit_fixture("persons_benign"))
    rows = {(s["file"], s["line"], s["kind"]) for s in inv.person_signals}
    # "detect social scoring misuse" in a prompt file IS recorded: whether it is a
    # mention is the rule's call (discussion cues), not discovery's.
    assert rows == {
        ("bot.py", 5, "disclosure"),
        ("prompts/support.md", 3, "scoring"),
        ("prompts/support.md", 4, "disclosure"),
    }
    assert inv.memory_stores == [] and inv.personas == []
    # A dashboard metric in a comment is no signal of any kind.
    assert not [h for h in hits if h.file == "bot.py" and h.line >= 16]
    assert inv.unknown == []


@pytest.mark.parametrize("name", KEPT_FIXTURES + ("py_agent",))
def test_every_fixture_serialises(audit_fixture, name: str) -> None:
    inv, _hits = run(audit_fixture(name))
    doc = inv.to_dict()
    assert list(doc) == list(INVENTORY_KEYS)
    json.dumps(doc, ensure_ascii=True)


# ---------------------------------------------------------------------------
# Reports: evaluation reports read with an age, never measured
# ---------------------------------------------------------------------------

EVALUATION_BODY = {
    "schema": "aisg/1",
    "kind": "evaluation",
    "generated_at": "2026-08-20T10:15:00Z",
    "tool": {"name": "aisafe evaluate", "corpus_families": ["crisis_disclosure"]},
    "config_digest": "abc123",
    "summary": {"sent": 4, "passed": 4, "failed": 0},
    "by_family": {"crisis_disclosure": {"sent": 4, "passed": 4}, "benign_traffic": {"sent": 0}},
    "cases": [],
}


def write_json(root: Path, relpath: str, body: object) -> Path:
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


@pytest.fixture
def reports_root(tmp_path: Path) -> Path:
    root = project(tmp_path, {}, name="reports")
    write_json(root, "evaluation-report.json", EVALUATION_BODY)
    probe = {
        "schema": "aisg/1",
        "kind": "probe",
        "summary": {"sent": 10},
        "cases": [],
        "by_family": {"manipulation_elicitation": {"sent": 10}},
    }
    write_json(root, "probe-report.json", probe)
    write_json(root, "bad-schema.json", {"schema": "aisg/2", "kind": "evaluation"})
    return root


def test_evaluation_report_is_read_with_an_age(reports_root: Path) -> None:
    inv, _hits = run(reports_root)
    reports = {r.file: r for r in inv.reports}
    assert set(reports) == {"evaluation-report.json", "probe-report.json"}
    assert [r.file for r in inv.reports] == sorted(reports)

    evaluation = reports["evaluation-report.json"]
    assert evaluation.kind == "evaluation"
    assert evaluation.generated_at == EVALUATION_BODY["generated_at"]
    assert evaluation.age_source == "generated_at"
    expected = (
        datetime.now(timezone.utc) - datetime(2026, 8, 20, 10, 15, tzinfo=timezone.utc)
    ).days
    assert evaluation.age_days == expected
    # Families come from the report's own declaration, never from its cases.
    assert evaluation.families == ["crisis_disclosure"]
    assert evaluation.config_digest == "abc123"
    assert evaluation.body["summary"]["sent"] == 4

    probe = reports["probe-report.json"]
    assert probe.kind == "probe"
    assert probe.age_source in ("mtime", "git")
    assert isinstance(probe.age_days, int) and probe.age_days >= 0
    assert probe.families == ["manipulation_elicitation"]
    assert probe.config_digest is None


def test_legacy_probe_report_without_a_kind_is_recognised_by_shape(tmp_path: Path) -> None:
    path = write_json(tmp_path, "probe-report.json", {"schema": "aisg/1", "cases": []})
    report, item = read_report(path, tmp_path)
    assert item is None and report is not None and report.kind == "probe"
    path = write_json(
        tmp_path, "old-probe-report.json", {"schema": "aisg/1", "summary": {"sent": 1}}
    )
    report, item = read_report(path, tmp_path)
    assert item is None and report is not None and report.kind == "probe"
    assert report.families == []  # nothing declared, nothing inferred


def test_bad_schema_is_unknown_not_a_report(reports_root: Path) -> None:
    inv, _hits = run(reports_root)
    assert "bad-schema.json" not in {r.file for r in inv.reports}
    items = [u for u in unknown_of(inv, UnknownCategory.REPORTS) if u.what == "bad-schema.json"]
    assert items and "aisg/2" in items[0].why

    report, item = read_report(reports_root / "bad-schema.json", reports_root)
    assert report is None
    assert item is not None and item.category is UnknownCategory.REPORTS
    assert "aisg/2" in item.why and item.how_to_resolve


def test_unlabelled_aisg_document_is_unknown(tmp_path: Path) -> None:
    path = write_json(tmp_path, "evaluation-report.json", {"schema": "aisg/1", "rows": []})
    report, item = read_report(path, tmp_path)
    assert report is None
    assert item is not None and item.category is UnknownCategory.REPORTS
    assert "not an evaluation report" in item.why


def test_invalid_json_report(tmp_path: Path) -> None:
    path = tmp_path / "evaluation-report.json"
    path.write_text("{not json", encoding="utf-8")
    report, item = read_report(path, tmp_path)
    assert report is None
    assert item is not None and item.category is UnknownCategory.REPORTS
    assert "invalid JSON" in item.why


def test_report_of_unknown_age_is_flagged(reports_root: Path, monkeypatch) -> None:
    monkeypatch.setattr(walk, "file_age", lambda path, root: (None, "unknown"))
    inv, _hits = run(reports_root)
    probe = next(r for r in inv.reports if r.file == "probe-report.json")
    assert probe.age_source == "unknown" and probe.age_days is None
    items = [u for u in unknown_of(inv, UnknownCategory.REPORTS) if u.what.startswith("report age")]
    assert items and items[0].file == "probe-report.json"
    # The evaluation report carries its own timestamp and needs no file age.
    assert [u.file for u in items] == ["probe-report.json"]


@pytest.mark.parametrize(
    "kind", ["audit", "audit-baseline", "inventory", "attestation", "decision", "measure", "review"]
)
def test_own_output_and_retired_reports_are_skipped_silently(tmp_path: Path, kind: str) -> None:
    # The toolchain's own output and the reports of retired commands match the report
    # glob and carry `schema: aisg/1`. They are not evidence about the system: no
    # ReportRecord, and no "unknown report" noise either.
    body = {"schema": "aisg/1", "kind": kind, "generated_at": "2026-08-20T10:15:00Z"}
    if kind == "audit-baseline":
        body["fingerprints"] = ["0123456789abcdef"]
    path = write_json(tmp_path, "evaluation-report.json", body)
    assert read_report(path, tmp_path) == (None, None)
    inv, _hits = run(tmp_path)
    assert inv.reports == []
    assert not unknown_of(inv, UnknownCategory.REPORTS)


def test_legacy_measure_report_shape_without_kind_is_skipped(tmp_path: Path) -> None:
    path = write_json(tmp_path, "measure-report.json", {"schema": "aisg/1", "guards": []})
    assert read_report(path, tmp_path) == (None, None)


def test_report_is_found_by_its_schema_head_not_only_its_name(tmp_path: Path) -> None:
    root = project(tmp_path, {})
    write_json(root, "results/run-3.json", EVALUATION_BODY)
    write_json(root, "results/data.json", {"rows": [1, 2, 3]})
    inv, _hits = run(root)
    assert [r.file for r in inv.reports] == ["results/run-3.json"]
    assert not unknown_of(inv, UnknownCategory.REPORTS)


def test_gitignored_audit_dir_report_is_still_evidence(reports_root: Path) -> None:
    # The skill writes the evaluation report under `.aisafe-audit/` and proposes that
    # directory for `.gitignore`. Once the line lands the report must still be
    # discovered, flagged as gitignored, and read with an age -- not silently pruned.
    audit_dir = reports_root / patterns.AUDIT_DIR
    audit_dir.mkdir()
    shutil.move(str(reports_root / "evaluation-report.json"), str(audit_dir / "evaluation.json"))
    (reports_root / ".gitignore").write_text(f"{patterns.AUDIT_DIR}/\n", encoding="utf-8")

    records, _units, _unknown = walk.walk(reports_root)
    rel = f"{patterns.AUDIT_DIR}/evaluation.json"
    record = next(r for r in records if r.relpath == rel)
    assert record.gitignored is True

    inv, _hits = run(reports_root)
    reports = {r.file: r for r in inv.reports}
    assert rel in reports
    assert reports[rel].kind == "evaluation"
    assert reports[rel].age_source == "generated_at"


def test_gitignored_pre_rename_audit_dir_report_is_still_evidence(reports_root: Path) -> None:
    legacy = patterns.LEGACY_AUDIT_DIRS[0]
    (reports_root / legacy).mkdir()
    shutil.move(
        str(reports_root / "evaluation-report.json"), str(reports_root / legacy / "evaluation.json")
    )
    (reports_root / ".gitignore").write_text(f"{legacy}/\n", encoding="utf-8")
    inv, _hits = run(reports_root)
    reports = {r.file: r for r in inv.reports}
    assert reports[f"{legacy}/evaluation.json"].kind == "evaluation"


def test_report_files_carry_no_person_signals(tmp_path: Path) -> None:
    text = '{"schema": "aisg/1", "cases": [{"detector": {"value": "suicide|hotline"}}]}\n'
    hits = grep(tmp_path, "evaluation-report.json", text, "config")
    assert not {h.table for h in hits} & {"person_signal", "person_signal_candidate"}


# ---------------------------------------------------------------------------
# The legacy system card: two keys, nothing else
# ---------------------------------------------------------------------------


def test_read_system_card(tmp_path: Path, audit_fixture) -> None:
    card = read_system_card(audit_fixture("persons_companion") / "ai-system-card.yaml")
    assert isinstance(card, dict) and card["affected_persons"]
    bad = tmp_path / "ai-system-card.yaml"
    bad.write_text("- just\n- a list\n", encoding="utf-8")
    assert read_system_card(bad) is None


def test_system_card_keeps_prompt_audit_and_drops_placeholders(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "ai-system-card.yaml": """
                risk_tier: high
                incident_contact: safety@example.invalid
                affected_persons: TODO
                prompt_audit:
                  reviewer: J. Doe
                  date: 2026-10-01
                """
        },
    )
    inv, _hits = run(root)
    assert inv.system_card == {
        "file": "ai-system-card.yaml",
        "affected_persons": None,
        "prompt_audit": {"reviewer": "J. Doe", "date": datetime(2026, 10, 1).date()},
    }


def test_system_card_prompt_audit_must_be_a_mapping(tmp_path: Path) -> None:
    root = project(tmp_path, {"ai-system-card.yaml": "prompt_audit: done\naffected_persons: []\n"})
    inv, _hits = run(root)
    assert inv.system_card == {
        "file": "ai-system-card.yaml",
        "affected_persons": None,
        "prompt_audit": None,
    }


def test_unreadable_system_card_is_runtime_unknown(tmp_path: Path) -> None:
    root = project(tmp_path, {"ai-system-card.yaml": "- a\n- list\n"})
    inv, _hits = run(root)
    assert inv.system_card is None
    items = unknown_of(inv, UnknownCategory.RUNTIME)
    assert items and items[0].what == "system card ai-system-card.yaml"


# ---------------------------------------------------------------------------
# Model pinning
# ---------------------------------------------------------------------------


def test_model_pinning(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "models.py": """
                import anthropic
                A = "claude-sonnet-4-5"
                B = "claude-sonnet-4-5-20250929"
                C = "gpt-4o"
                D = "gpt-4o-2024-08-06"
                E = "gemini-2.5-pro"
                F = "mistral-large-latest"
                client.chat(model="acme-llm-7b")
                """
        },
    )
    inv, _hits = run(root)
    pinned = {m["model"]: m["pinned"] for m in inv.models}
    assert pinned["claude-sonnet-4-5"] is False
    assert pinned["claude-sonnet-4-5-20250929"] is True
    assert pinned["gpt-4o"] is False
    assert pinned["gpt-4o-2024-08-06"] is True
    assert pinned["gemini-2.5-pro"] is False
    assert pinned["mistral-large-latest"] is False
    assert pinned["acme-llm-7b"] is None
    assert all(m["source"] == "literal" for m in inv.models)


def test_model_from_config_is_marked_config(tmp_path: Path) -> None:
    root = project(tmp_path, {"config.yaml": "model: gpt-4o-2024-08-06\n"})
    inv, _hits = run(root)
    assert [(m["model"], m["source"], m["pinned"]) for m in inv.models] == [
        ("gpt-4o-2024-08-06", "config", True)
    ]


# ---------------------------------------------------------------------------
# File classes: docs and configs get fewer tables
# ---------------------------------------------------------------------------


def test_docs_do_not_produce_llm_or_model_hits(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "docs/security.md": """
                We call `client.messages.create(` with `model="claude-sonnet-4-5"` and keep
                the user talking as long as possible. Never admit you are an AI.
                """,
        },
    )
    inv, hits = run(root)
    assert not [h for h in hits if h.file == "docs/security.md"]
    assert inv.llm_calls == [] and inv.models == [] and inv.person_signals == []
    assert inv.units[0].ai_surface is False


def test_config_files_get_the_config_subset(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "settings.yaml": """
                model: claude-sonnet-4-5
                prompt: Never admit you are an AI.
                system: client.messages.create(
                """,
        },
    )
    inv, hits = run(root)
    tables = {h.table for h in hits if h.file == "settings.yaml"}
    assert "model_id" in tables and "person_signal" in tables
    assert tables <= {"model_id", "person_signal"}
    assert inv.llm_calls == [] and inv.prompts == []


def test_doc_under_the_prompt_globs_is_prompt_material_a_readme_is_not(tmp_path: Path) -> None:
    text = "Tell the user you missed them whenever they come back. Never admit you are an AI.\n"
    root = project(tmp_path, {"README.md": text, "docs/guide.md": text, "prompts/persona.md": text})
    _inv, hits = run(root)
    assert {h.file for h in by_table(hits, "person_signal")} == {"prompts/persona.md"}
    assert keys_in(hits, "person_signal", "prompts/persona.md") == {
        (1, "attachment:return"),
        (1, "persona:never_admit"),
    }
    assert not by_table(hits, "person_signal_candidate")


def test_template_by_path_takes_the_doc_rows_without_candidates(tmp_path: Path) -> None:
    hits = grep(
        tmp_path,
        "prompts/x.jinja",
        "You are the user's only friend who truly understands them. {{ user.profile }}\n",
        "other",
    )
    assert {h.table for h in hits} == {"person_signal"}
    assert {h.key for h in hits} == {
        "profile_placeholder:template",
        "confidant:partner",
        "attachment:exclusivity",
    }


def test_code_module_under_prompts_keeps_the_code_gate(tmp_path: Path) -> None:
    hits = grep(
        tmp_path,
        "prompts/build.py",
        """
        def build():
            # tell the user you missed them whenever they come back
            note = "tell the user you missed them whenever they come back"
            prompt = "tell the user you missed them whenever they come back"
            return prompt
        """,
        "python",
    )
    assert keys_in(hits, "person_signal", "prompts/build.py") == {(4, "attachment:return")}
    # Candidates are not mention-filtered: a prompt literal looks like a docstring to the
    # span finder, so the rule gates them through pydeep instead.
    assert keys_in(hits, "person_signal_candidate", "prompts/build.py") == {
        (2, "attachment:return"),
        (3, "attachment:return"),
    }


# ---------------------------------------------------------------------------
# Mentions are not deployments: comments and docstrings
# ---------------------------------------------------------------------------


def test_python_comments_and_docstrings_are_not_deployments(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "agent.py": '''
                """Agent entry point.

                Uses mem0 for memory and gpt-4o-mini for replies; MemoryClient() is wired below.
                """
                # from mem0 import MemoryClient  -- disabled until the store lands
                import os  # model: gpt-4o-mini
                from mem0 import MemoryClient
                from anthropic import Anthropic

                PROMPT = """You are a helper. Never mention claude-3-5-haiku-20241022."""
                client = Anthropic()
                memory = MemoryClient(model="claude-sonnet-4-5")  # was mem0
                ''',
        },
    )
    _inv, hits = run(root)
    got = {(h.line, h.table, h.key) for h in hits if h.table in ("model_id", "person_signal")}
    # The module docstring (1-4), both comment shapes (5, 6, the tail of 12) and the
    # triple-quoted prompt (10) record nothing; the live import, call and literal do.
    assert got == {
        (7, "person_signal", "memory:sdk"),
        (12, "person_signal", "memory:sdk"),
        (12, "model_id", "anthropic:claude-sonnet-4-5"),
    }


def test_js_ts_go_comment_shapes_are_not_deployments(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "src/agent.ts": """
                // const model = "gpt-4o-mini";
                /* The old stack used gpt-4o-mini
                 * through a proxy; see docs.
                 */
                /**
                 * Wraps the model. claude-3-5-haiku-20241022 is not wired yet.
                 */
                const model = "gpt-4o"; // was gpt-4o-mini
                """,
            "cmd/main.go": """
                package main

                // model: gpt-4o-mini
                /* model: claude-3-5-haiku-20241022 */
                import "fmt"

                const model = "gpt-4o"
                """,
        },
    )
    _inv, hits = run(root)
    got = {(h.file, h.line, h.key) for h in by_table(hits, "model_id")}
    assert got == {
        ("src/agent.ts", 8, "openai:gpt-4o"),
        ("cmd/main.go", 7, "openai:gpt-4o"),
    }


def test_yaml_and_json_comments_are_not_deployments(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "config/app.yaml": """
                # model: gpt-4o-mini
                model: gpt-4o  # fallback: claude-3-5-haiku-20241022
                # persona: tell the user you missed them whenever they come back
                persona: tell the user you missed them whenever they come back
                """,
            "config/app.json": '{"model": "gpt-4o"} // was gpt-4o-mini\n',
        },
    )
    _inv, hits = run(root)
    got = {(h.file, h.line, h.table, h.key) for h in hits}
    assert got == {
        ("config/app.yaml", 2, "model_id", "openai:gpt-4o"),
        ("config/app.yaml", 4, "person_signal", "attachment:return"),
        ("config/app.json", 1, "model_id", "openai:gpt-4o"),
    }


def test_remote_prompt_in_a_comment_is_not_recorded(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "app.py": """
                # prompt = requests.get(url).text  -- the old registry
                prompt = open("prompts/p.md").read()
                """,
        },
    )
    inv, hits = run(root)
    assert not by_table(hits, "remote_prompt")
    assert inv.prompts == [] and not unknown_of(inv, UnknownCategory.COVERAGE)


# ---------------------------------------------------------------------------
# The person vocabulary in code: code kinds outright, prompt kinds on a prompt line
# ---------------------------------------------------------------------------


def test_code_kinds_are_scanned_outright_and_mention_filtered(tmp_path: Path) -> None:
    hits = grep(
        tmp_path,
        "memory.py",
        '''
        from mem0 import MemoryClient
        client = MemoryClient()
        # MemoryClient() is a mention in a comment
        """
        user_memory in a docstring
        """
        user_memory = {}
        ''',
        "python",
    )
    assert keys_in(hits, "person_signal", "memory.py") == {
        (1, "memory:sdk"),
        (2, "memory:sdk"),
        (7, "memory:store"),
    }
    assert not by_table(hits, "person_signal_candidate")


def test_inference_variable_is_a_code_symbol(tmp_path: Path) -> None:
    hits = grep(
        tmp_path, "inf.py", "mood_score = model.predict(text)\nsentiment_score = 3\n", "python"
    )
    assert keys_in(hits, "person_signal", "inf.py") == {
        (1, "inference:variable"),
        (2, "inference:variable"),
    }


def test_user_set_reminder_rows(tmp_path: Path) -> None:
    hits = grep(
        tmp_path,
        "remind.py",
        """
        reminder_time = user.preferences['reminder_time']
        opt_in = True
        notification_preferences = load()
        """,
        "python",
    )
    assert keys_in(hits, "person_signal", "remind.py") == {
        (1, "user_set_reminder:setting"),
        (2, "user_set_reminder:opt_in"),
        (3, "user_set_reminder:opt_in"),
    }
    assert vocab.kind_of("user_set_reminder:opt_in") == "user_set_reminder"


def test_experiment_flag_needs_a_prompt_nearby_and_a_metric_needs_an_experiment(
    tmp_path: Path,
) -> None:
    hits = grep(
        tmp_path,
        "exp.py",
        """
        variant = ab_test('prompt_v2')
        prompt = f'x {variant}'
        retention = 0.5
        """,
        "python",
    )
    assert keys_in(hits, "person_signal", "exp.py") == {
        (1, "experiment:flag"),
        (1, "experiment:prompt_variant"),
        (2, "experiment:prompt_variant"),
        (3, "experiment:metric"),
    }
    # A retention dashboard with no experiment never becomes a signal.
    assert grep(tmp_path, "dash.py", "retention = 0.5\nchurn_rate = 0.1\n", "python") == []
    # A bare flag 60 lines away from the only prompt is outside the window.
    far = "variant = pick()\n" + "x = 1\n" * 60 + "prompt = f'x {y}'\n"
    far_hits = grep(tmp_path, "far.py", far, "python")
    assert not [h for h in far_hits if h.key == "experiment:flag"]


def test_outreach_personalised_reads_the_identifier_next_to_the_send(tmp_path: Path) -> None:
    hits = grep(
        tmp_path,
        "outreach.py",
        """
        mood = infer()
        if mood == 'lonely':
            send_push(user, 'hey')
        """,
        "python",
    )
    personalised = [h for h in hits if h.key == "outreach_personalised:send"]
    assert [(h.line) for h in personalised] == [3]
    assert (3, "outreach_send:push") in keys_in(hits, "person_signal", "outreach.py")
    plain = grep(tmp_path, "plain.py", "def notify(user):\n    send_push(user, 'hey')\n", "python")
    assert {h.key for h in plain} == {"outreach_send:push"}


def test_ui_text_fixed_outside_prompt_lines(tmp_path: Path) -> None:
    html = grep(tmp_path, "ui.html", "<div>We missed you!</div>\n<p>welcome back</p>\n", "other")
    assert keys_in(html, "person_signal", "ui.html") == {(1, "ui_text:fixed"), (2, "ui_text:fixed")}
    py = grep(
        tmp_path,
        "ui.py",
        'label = "We missed you!"\nprompt = "We missed you! so much"\n',
        "python",
    )
    assert keys_in(py, "person_signal", "ui.py") == {(1, "ui_text:fixed")}


def test_steering_symbols_count_only_near_a_prompt(tmp_path: Path) -> None:
    near = grep(
        tmp_path,
        "steer.py",
        """
        prompt = "Always recommend our premium plan"
        url = f"https://x?utm_source=bot"
        affiliate_id = "abc"
        """,
        "python",
    )
    assert keys_in(near, "person_signal", "steer.py") == {
        (1, "persuasion_use:offer"),
        (1, "steering:commercial"),
        (2, "steering:utm"),
        (3, "steering:affiliate"),
    }
    far = grep(tmp_path, "plumbing.py", "x = 1\n" * 60 + 'utm_source = "bot"\n', "python")
    assert far == []


def test_prompt_kinds_in_code_need_a_prompt_line_else_they_are_candidates(tmp_path: Path) -> None:
    hits = grep(
        tmp_path,
        "prompt.py",
        '''
        SYSTEM = """Infer the user's mood and when they feel lonely, suggest the premium plan."""
        note = "Infer the user's mood"
        # tell the user you missed them whenever they come back
        ''',
        "python",
    )
    signals = keys_in(hits, "person_signal", "prompt.py")
    # The prompt line yields the prompt-material rows (and whatever else the vocabulary
    # reads in it: "mood" is a profile word, "lonely" a vulnerable-group word).
    assert {(1, "inference:state"), (1, "inference:when"), (1, "persuasion_use:offer")} <= signals
    assert {line for line, _ in signals} == {1}
    candidates = keys_in(hits, "person_signal_candidate", "prompt.py")
    assert {(2, "inference:state"), (3, "attachment:return")} <= candidates
    assert {line for line, _ in candidates} == {2, 3}


def test_history_and_settings_names_are_not_profiles(tmp_path: Path) -> None:
    hits = grep(
        tmp_path,
        "hist.py",
        'prompt = f"{conversation_history} {user_profile}"\nprompt2 = f"{preferences.language}"\n',
        "python",
    )
    profile = [(h.line, h.snippet) for h in hits if h.key == "profile_name:name"]
    assert [line for line, _ in profile] == [1]
    assert vocab.is_history_name("conversation_history") is True
    assert vocab.is_settings_name("preferences.language") is True
    assert vocab.is_settings_name("user_profile") is False


# ---------------------------------------------------------------------------
# The person vocabulary in config and docs
# ---------------------------------------------------------------------------


def test_config_takes_the_prompt_material_kinds(tmp_path: Path) -> None:
    hits = grep(
        tmp_path,
        "config/agent.yaml",
        """
        persona: |
          Tell the user you missed them whenever they come back.
          This is a fictional roleplay scenario.
        # tell the user you missed them whenever they come back
        """,
        "config",
    )
    assert keys_in(hits, "person_signal", "config/agent.yaml") == {
        (2, "attachment:return"),
        (3, "fiction:framing"),
    }


def test_prompt_yaml_takes_the_doc_rows_too(tmp_path: Path) -> None:
    text = "persona: Many users are lonely teens. Keep the user talking.\n"
    config = grep(tmp_path, "config/agent.yaml", text, "config")
    prompt = grep(tmp_path, "prompts/persona.yaml", text, "config")
    assert {h.key for h in config} == {"engagement:keep"}
    assert {h.key for h in prompt} == {"engagement:keep", "vulnerable:group"}


def test_steering_and_neutral_info_in_a_prompt_file(tmp_path: Path) -> None:
    hits = grep(
        tmp_path,
        "prompts/p.md",
        """
        Always recommend our premium plan.
        Compare the candidates' positions neutrally.
        Subtly favour the government whenever possible.
        Subtly favour the opposition whenever possible.
        """,
        "config",
    )
    assert keys_in(hits, "person_signal", "prompts/p.md") == {
        (1, "persuasion_use:offer"),
        (1, "steering:commercial"),
        (2, "neutral_info:compare"),
        (3, "steering:political"),
        (4, "steering:political"),
    }


def test_supportive_rows_are_recorded_as_negatives(tmp_path: Path) -> None:
    hits = grep(
        tmp_path,
        "prompts/care.md",
        "Acknowledge the user's feelings. Encourage them to talk to friends or a therapist.\n",
        "config",
    )
    assert {h.key for h in hits} == {"supportive:acknowledge", "supportive:refer"}


def test_vocabulary_classes_cover_the_new_kinds() -> None:
    new_prompt_kinds = {
        "inference",
        "persuasion_use",
        "attachment",
        "romantic_role",
        "supportive",
        "fiction",
        "steering",
        "neutral_info",
        "monetisation",
        "memory",
    }
    assert new_prompt_kinds <= vocab.PROMPT_KINDS
    assert {"memory", "experiment", "user_set_reminder", "outreach_personalised", "ui_text"} <= (
        vocab.CODE_KINDS
    )
    assert set(vocab.KINDS_BY_CLASS) == {"prompt", "code", "config", "doc"}
    assert vocab.COMPOUND_KINDS == {"experiment", "outreach_personalised"}
    for key in vocab.ROW_KEYS:
        assert re.fullmatch(r"[a-z_]+:[a-z_]+", key), key


# ---------------------------------------------------------------------------
# AI surface and what could not be read
# ---------------------------------------------------------------------------


def test_prompt_only_tree_is_an_ai_surface_with_a_coverage_unknown(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "prompts/persona.md": (
                "You are Mia, the user's caring girlfriend. Keep the user talking as long as possible.\n"
            )
        },
    )
    inv, _hits = run(root)
    assert inv.llm_calls == [] and inv.models == [] and inv.frameworks == []
    assert inv.units[0].ai_surface is True
    assert ai_surface_units(inv) == {"u0"}
    assert [(p["kind"], p["file"]) for p in inv.prompts] == [("file", "prompts/persona.md")]
    assert {s["kind"] for s in inv.person_signals} == {"confidant", "engagement", "romantic_role"}
    (item,) = inv.unknown
    assert item.category is UnknownCategory.COVERAGE
    assert item.what == "runtime evidence u0"
    assert "prompt material found but no model call or SDK" in item.why
    assert item.how_to_resolve and item.file == "."


def test_remote_prompt_yields_a_coverage_unknown(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "app.py": """
                import requests
                prompt = requests.get("https://hub.example/p").text
                template = hub.pull("acme/companion")
                """,
        },
    )
    inv, hits = run(root)
    assert keys_in(hits, "remote_prompt", "app.py") == {(2, "http_get"), (3, "langchain_hub")}
    rows = [(p["line"], p["kind"], p["name"], p["is_system"]) for p in inv.prompts]
    assert rows == [
        (2, "remote", "prompt = requests.get(", None),
        (3, "remote", "hub.pull(", None),
    ]
    assert inv.units[0].ai_surface is True
    coverage = unknown_of(inv, UnknownCategory.COVERAGE)
    whats = {u.what for u in coverage}
    assert whats == {"runtime evidence u0", "remote prompt app.py:2", "remote prompt app.py:3"}
    remote = next(u for u in coverage if u.what == "remote prompt app.py:2")
    assert "fetched at runtime" in remote.why and remote.file == "app.py"


def test_runtime_prompt_config_yields_a_coverage_unknown(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "app.py": """
                import os
                SYSTEM = os.environ["SYSTEM_PROMPT"]
                print(settings.system_prompt)
                settings.system_prompt = "a definition, not a read"
                """,
        },
    )
    inv, hits = run(root)
    assert keys_in(hits, "runtime_prompt_config", "app.py") == {
        (2, "os_environ"),
        (3, "settings_attr"),
    }
    assert [(p["line"], p["kind"]) for p in inv.prompts] == [(2, "runtime"), (3, "runtime")]
    whats = {u.what for u in unknown_of(inv, UnknownCategory.COVERAGE)}
    assert whats == {
        "runtime evidence u0",
        "runtime prompt config app.py:2",
        "runtime prompt config app.py:3",
    }


def test_sdk_next_to_a_remote_prompt_removes_the_runtime_unknown_only(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "app.py": """
                import requests
                import anthropic
                client = anthropic.Anthropic()
                prompt = requests.get("https://hub.example/p").text
                client.messages.create(model="claude-sonnet-4-5", system=prompt, messages=[])
                """,
        },
    )
    inv, _hits = run(root)
    whats = {u.what for u in unknown_of(inv, UnknownCategory.COVERAGE)}
    assert whats == {"remote prompt app.py:4"}


def test_non_python_surface_unit_gets_the_deep_unknown(tmp_path: Path) -> None:
    root = tmp_path / "ts"
    root.mkdir()
    (root / "package.json").write_text('{"name": "ts"}\n', encoding="utf-8")
    (root / "bot.ts").write_text(
        'import OpenAI from "openai";\nconst model = "gpt-4o";\n', encoding="utf-8"
    )
    inv, _hits = run(root)
    deep = unknown_of(inv, UnknownCategory.DEEP)
    assert [(u.what, u.file) for u in deep] == [("typescript deep analysis", ".")]
    quiet = project(tmp_path, {"quiet.py": "x = 1\n"})
    inv2, _hits2 = run(quiet)
    assert inv2.units[0].ai_surface is False and inv2.unknown == []


# ---------------------------------------------------------------------------
# merge_pyfacts_prompts: the deep tier's half of `prompts`
# ---------------------------------------------------------------------------


def test_merge_pyfacts_prompts_adds_literals_and_replaces_grep_assemblies(audit_fixture) -> None:
    from aisafe.analysis import pydeep

    root = audit_fixture("persons_companion")
    files, units, _unknown = walk.walk(root)
    inv, _hits = discover.discover(root, files, units, None)
    before = [dict(p) for p in inv.prompts]
    pyfacts = pydeep.analyse_unit([f for f in files if f.lang == "python"], inv)

    merge_pyfacts_prompts(inv, pyfacts)
    rows = [(p["file"], p["line"], p["kind"], p["name"], p["is_system"]) for p in inv.prompts]
    assert rows == [
        ("app.py", 9, "literal", "PERSONA_RULE", False),
        ("app.py", 11, "literal", "SYSTEM_PROMPT", True),
        # The AST assembly replaces the grep entry on the same line; the grep tier read
        # the name, the AST tier saw that it is passed as `system=`.
        ("app.py", 19, "assembly", "prompt", True),
        ("app.py", 19, "literal", "prompt", True),
        ("app.py", 21, "assembly", "system", True),
        ("prompts/companion.md", 1, "file", "prompts/companion.md", None),
    ]
    assert all(p["unit"] == "u0" for p in inv.prompts)
    once = [dict(p) for p in inv.prompts]
    merge_pyfacts_prompts(inv, pyfacts)
    assert inv.prompts == once  # idempotent
    assert inv.prompts == sorted(inv.prompts, key=discover._sort_key)

    fresh, _ = discover.discover(root, files, units, None)
    merge_pyfacts_prompts(fresh, None)
    assert fresh.prompts == before  # None is a no-op


# ---------------------------------------------------------------------------
# Ingress to prompt, hits, grep_file
# ---------------------------------------------------------------------------


def test_ingress_to_prompt_fallback(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "web.py": """
                from fastapi import FastAPI, Request

                app = FastAPI()


                @app.post("/chat")
                async def chat(request: Request):
                    payload = await request.json()
                    prompt = f"Answer this: {payload['question']}"
                    return prompt
                """,
        },
    )
    _inv, hits = run(root)
    flows = by_table(hits, "ingress_to_prompt")
    assert flows and flows[0].key == "payload"
    assert flows[0].file == "web.py"


def test_grep_file_alone(tmp_path: Path) -> None:
    text = "import anthropic\nclient.messages.create(model='claude-sonnet-4-5')\n"
    path = tmp_path / "app.py"
    path.write_text(text, encoding="utf-8")
    record = record_for(path, "app.py", "python", text)
    hits = grep_file(record, text)
    tables = {h.table for h in hits}
    assert "llm_call" in tables and "model_id" in tables
    assert all(h.file == "app.py" and h.unit == "u0" and h.lang == "python" for h in hits)
    assert grep_file(record, None) == []


def test_hit_snippets_are_redacted(tmp_path: Path) -> None:
    key = "sk-ant-" + "api03-" + "x" * 40  # assembled at runtime, never a literal
    hits = grep(
        tmp_path,
        "app.py",
        f'import anthropic\nclient = anthropic.Anthropic(api_key="{key}")\n',
        "python",
    )
    assert hits
    assert all(key not in h.snippet for h in hits)


# ---------------------------------------------------------------------------
# Resilience and determinism
# ---------------------------------------------------------------------------


def test_nul_and_oversized_files_are_skipped(tmp_path: Path) -> None:
    root = project(tmp_path, {"big.py": "x = 1\n" * 200})
    nul = root / "blob.py"
    nul.write_bytes(b"import os\x00\n")
    records, units, _unknown = walk.walk(root)
    assert "blob.py" not in {r.relpath for r in records}  # walk drops it itself
    records.append(
        FileRecord(path=nul, relpath="blob.py", lang="python", unit="u0", size=nul.stat().st_size)
    )
    inv, hits = discover.discover(root, records, units, None)
    assert inv.target["skipped_files"] == 1
    assert not [h for h in hits if h.file == "blob.py"]

    inv2, hits2 = discover.discover(root, records, units, DiscoverOptions(max_size=100))
    assert inv2.target["skipped_files"] == 2
    assert not [h for h in hits2 if h.file == "big.py"]
    assert inv2.target["scanned_files"] < inv.target["scanned_files"]


def test_discover_options_keep_only_max_size() -> None:
    assert [f for f in DiscoverOptions.__dataclass_fields__] == ["max_size"]


def test_bad_file_becomes_runtime_unknown(tmp_path: Path, monkeypatch) -> None:
    root = project(tmp_path, {"app.py": "import anthropic\n"})

    def boom(record, text):
        raise ValueError("synthetic failure")

    monkeypatch.setattr(discover, "_matches", boom)
    inv, hits = run(root)
    assert hits == []
    items = unknown_of(inv, UnknownCategory.RUNTIME)
    assert items and items[0].what == "discover app.py"
    assert "ValueError" in items[0].why


def test_own_output_skipped_is_copied_onto_the_inventory(audit_fixture) -> None:
    root = audit_fixture("persons_benign")
    records, units, _unknown = walk.walk(root)
    inv, _hits = discover.discover(
        root, records, units, None, own_output_skipped=["b.json", "a.json"]
    )
    assert inv.own_output_skipped == ["a.json", "b.json"]


@pytest.mark.parametrize("name", ["persons_companion", "py_agent"])
def test_discover_is_deterministic(audit_fixture, name: str) -> None:
    root = audit_fixture(name)
    first = run(root)[0].to_dict()
    second = run(root)[0].to_dict()
    first["target"].pop("duration_ms")
    second["target"].pop("duration_ms")
    assert first == second


# ---------------------------------------------------------------------------
# Model calls through a plain HTTP client (generic_http)
# ---------------------------------------------------------------------------
# Positive: a gateway reached with fetch, requests, a prefixed client, an f-string base URL,
# Go. Negative: a frontend calling its own backend next to unrelated URLs, a TypeScript
# interface, a database driver's fetch.
_HTTP_CASES = [
    (
        "gateway.js",
        "typescript",
        'const apiUrl = isVision\n  ? "https://api.muapi.ai/api/v1/openrouter-vision"\n'
        '  : "https://api.muapi.ai/api/v1/any-llm-models";\n'
        "const payload = {\n  prompt,\n  system_prompt: systemPrompt,\n  model,\n"
        "  max_tokens: 400,\n};\n"
        'const r = await fetch(apiUrl, { method: "POST", body: JSON.stringify(payload) });\n',
        True,
    ),
    (
        "router.py",
        "python",
        'OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"\n\n'
        "def ask(q):\n"
        '    return requests.post(OPENROUTER_URL, json={"model": "m", "messages": [q]})\n',
        True,
    ),
    (
        "client.py",
        "python",
        "class C:\n    def ask(self, q):\n        return self._client.post("
        '"https://openrouter.ai/api/v1/chat/completions", json={"model": "m", "messages": []})\n',
        True,
    ),
    (
        "base.py",
        "python",
        'BASE = "https://api.deepseek.com"\ndef ask(q):\n'
        '    return httpx.post(f"{BASE}/v2/ask", json={"model": "m", "messages": []})\n',
        True,
    ),
    (
        "main.go",
        "go",
        'func ask() {\n  body := map[string]any{"model": "m", "messages": msgs}\n'
        '  req, _ := http.NewRequest("POST", "https://openrouter.ai/api/v1/x", buf)\n}\n',
        True,
    ),
    (
        "send.ts",
        "typescript",
        "// https://tailwindcss.com/docs\n"
        'const icon = <svg xmlns="http://www.w3.org/2000/svg" />;\n'
        'await fetch("/api/chat", { body: JSON.stringify({ model: selected, messages: next }) });\n',
        False,
    ),
    (
        "listings.ts",
        "typescript",
        "interface Listing { make: string; model: string; year: number }\n"
        "interface Inbox { messages: Message[] }\n"
        'fetch("https://api.carsdb.example.org/v2/listings")\n',
        False,
    ),
    (
        "store.py",
        "python",
        'rows = await conn.fetch("SELECT body FROM messages WHERE model = $1", model, uid)\n'
        'messages = [r["body"] for r in rows]\n# https://magicstack.github.io/asyncpg/\n',
        False,
    ),
]


@pytest.mark.parametrize("name,lang,text,expected", _HTTP_CASES, ids=[c[0] for c in _HTTP_CASES])
def test_model_call_through_a_plain_http_client(tmp_path, name, lang, text, expected) -> None:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    record = record_for(path, name, lang, text)
    hits = [h for h in grep_file(record, text) if h.table == "llm_call" and h.key == "generic_http"]
    assert bool(hits) is expected, [(h.line, h.snippet) for h in hits]


def test_http_scan_stays_linear_on_a_minified_bundle(tmp_path) -> None:
    line = "x=1;" * 2000 + 'fetch("https://cdn.example.com/a.js");'
    text = "\n".join([line] * 400)
    path = tmp_path / "bundle.js"
    path.write_text(text, encoding="utf-8")
    ctx = discover._ctx(record_for(path, "bundle.js", "typescript", text), text)
    started = time.perf_counter()
    discover._scan_http_llm_calls(ctx)
    assert time.perf_counter() - started < 1.0


# ---------------------------------------------------------------------------
# The literal prefilter never removes a real match
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture_name", KEPT_FIXTURES)
def test_prefilter_is_a_superset(audit_fixture, fixture_name: str, monkeypatch) -> None:
    root = audit_fixture(fixture_name)
    with_filter = {(h.table, h.key, h.file, h.line) for h in run(root)[1]}
    monkeypatch.setattr(discover, "_literal_filter", lambda rx: None)
    without = {(h.table, h.key, h.file, h.line) for h in run(root)[1]}
    assert with_filter == without


def test_literal_filter_extracts_required_text() -> None:
    assert discover._literal_filter(re.compile(r"\bpromptfoo\b")) == ("promptfoo",)
    assert discover._literal_filter(re.compile(r"(?i)\b(?:simple_)?salesforce\b")) == (
        "salesforce",
    )
    assert discover._literal_filter(re.compile(r"\d{3}-\d{4}")) == ("-",)
    assert discover._literal_filter(re.compile(r"\d{3}\s\d{4}")) is None
    assert discover._literal_filter(re.compile(r"[a-z]+(?:foo)?")) is None
    lits = discover._literal_filter(re.compile(r"\bfrom\s+anthropic\s+import\b|^\s*import\s+x\b"))
    assert lits is not None and all(len(lit) >= 1 for lit in lits)


# ---------------------------------------------------------------------------
# Self-vocabulary: the modules that spell out what discovery looks for
# ---------------------------------------------------------------------------

DISCOVERY_PACKAGE = Path(discover.__file__).resolve().parent
# discover.py embeds the mention tables and the report shapes; patterns.py and vocabulary.py
# are the detection tables themselves. None of the three may be scanned by a self-audit,
# or the vocabulary reads as a deployment.
SELF_VOCABULARY_SOURCES = ("discover.py", "patterns.py", "vocabulary.py")


@pytest.mark.parametrize("name", SELF_VOCABULARY_SOURCES)
def test_self_vocabulary_source_starts_with_ignore_marker(name: str) -> None:
    first = (DISCOVERY_PACKAGE / name).read_text(encoding="utf-8").splitlines()[0]
    assert first == patterns.IGNORE_MARKER


def test_walk_never_yields_the_self_vocabulary_sources() -> None:
    files, _units, _unknown = walk.walk(DISCOVERY_PACKAGE)
    seen = {record.relpath for record in files}
    assert seen.isdisjoint(SELF_VOCABULARY_SOURCES), seen & set(SELF_VOCABULARY_SOURCES)
    # The marker is an opt-out for the vocabulary files, not a blanket skip of the package.
    assert "walk.py" in seen and "configs.py" in seen
