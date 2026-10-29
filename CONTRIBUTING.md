# Contributing

Thank you for looking. This page is the practical guide; `CLAUDE.md` holds the mission
and the principles behind every change (it is written for coding agents, and everything in
it holds for people too); `policy/charter.md` is the ethical standard the auditor applies;
`docs/methodology.md` explains how findings are made; `docs/REFERENCE.md` is the full
reference.

## Setup

```bash
git clone https://github.com/ai-safe-earth/AnyAISafe.git
cd AnyAISafe
python -m venv .venv && . .venv/bin/activate      # .venv\Scripts\activate on Windows
pip install -e ".[devtools,dev]"
pytest -q                                          # no API keys, no network
```

The distribution, the import name and the console script are all `aisafe`. On
Windows set `PYTHONIOENCODING=utf-8` before running the CLI. Without an install,
`PYTHONPATH=src python -m aisafe.cli <command>` works from the repository root.

## The gate

Run from the repository root; everything green before a commit:

```bash
pytest -q
ruff check . && ruff format --check .
aisafe audit . --fail-on high --baseline audit-baseline.json   # must exit 0
python scripts/rules_md.py --check          # docs/rules.md and the skill's mechanisms.md are current
python scripts/sync_skill.py --check        # the plugin's skill copy matches the packaged one
python scripts/bump_version.py --check      # every version site agrees
```

A non-zero self-audit means a new finding at `high` or above that is not in
`audit-baseline.json`: fix it, or accept it with a reason that describes the evidence
without quoting the literal (`aisafe audit --amend-baseline audit-baseline.json --accept
<fingerprint>="<reason>"`). A fingerprint without a reason is a suppression, not an
acceptance, and a suppression from an older policy version is reported again.

## Conventions

- `ruff format` is the formatter (line length 100, Python 3.10 target); `ruff check`
  selects `E, F, W, I`. Every module starts with `from __future__ import annotations`
  and a `"""src/aisafe/<path>.py\n---\n"""` header. PEP 604 unions, double quotes.
- Every JSON document the tools write starts with `"schema": "aisg/1"` and carries a
  `kind` (`audit`, `audit-baseline`, `inventory`, `evaluation`, `review`, `policy`,
  `bench-case`). SARIF is the one exception; its marker is in the run's property bag.
- `aisafe audit` and `aisafe review` call no model, install nothing and open no socket;
  the tests wrap `socket.socket` to prove it. `aisafe evaluate` talks only to the URL you
  name.
- Never a verdict. `reporting.report.BANNED_PHRASES` lists the phrases no renderer may
  emit and a self-check runs against every template; do not spell them out in prose,
  point at the constant. `measured_precision` is `None` on every rule and renders
  `[UNMEASURED]`; never type a number in.
- Evidence apart from decision. A finding's `evidence_status` says what was established;
  its `decision` says what the policy makes of it; neither is a score. A keyword match
  alone never yields `violates_policy`.
- Generated files are regenerated, not edited: `docs/rules.md` and the skill's
  `references/mechanisms.md` (`scripts/rules_md.py`), the plugin's skill mirror
  (`plugins/aisafe/skills/`, `scripts/sync_skill.py`), and the packaged policy copies
  under `src/aisafe/policy/` (copied from `policy/`; a test pins them identical).
- `# aisafe-audit: ignore-file` sits only on the files that are the audit's vocabulary
  (`discovery/vocabulary.py`, the rule modules, `analysis/checks.py`); a real finding
  anywhere else goes in the baseline with a reason.

## Adding things

- **A mechanism row or a policy change**: edit `policy/charter.md` and
  `policy/mechanisms.yaml`, bump the policy version, copy both into
  `src/aisafe/policy/`, run `scripts/rules_md.py`, and say in `CHANGELOG.md` which
  decisions change. Accepted findings in baselines then show as re-review.
- **An audit rule**: a class under `src/aisafe/rules/` listed in its module's `RULES`,
  a `version`, a `mechanism` the policy lists it under (edit `policy/mechanisms.yaml`
  `rules:`), `references` in the grammar the registry test pins, a `recommendation` whose
  `removes` names what it takes out of the chain, honest `known_failure_modes`,
  `measured_precision = None`, a positive and a negative fixture under
  `tests/fixtures/audit/` or a pair in `tests/unit/test_rules_pairs.py`, a case in
  `bench/cases/`, then `python scripts/rules_md.py`.
- **A vocabulary row**: `src/aisafe/discovery/vocabulary.py`, keyed `<kind>:<slug>`, added
  to the right scan class (prompt, code, config, doc); a positive and a negative test.
- **An evaluation scenario**: the family's YAML under `src/aisafe/evaluation/corpus/`,
  synthetic turns written as a person would type them, a fixed detector, and the loader's
  rule that no turn may match its own detector.
- **A benchmark case**: `bench/cases/<id>/tree/` plus `expected.yaml` (`bench/protocol.md`);
  it counts in the headline numbers only once a second person has set `reviewed_by`.

## Releases

A release is the maintainer's act. `python scripts/bump_version.py X.Y.Z` rewrites every
version site and runs the sync; a `vX.Y.Z` tag pushed to `origin` runs the release
workflow, which publishes to PyPI through trusted publishing behind a GitHub environment
with a required reviewer. No token exists anywhere.

## Reporting

Vulnerabilities: `SECURITY.md`. A rule that misses a prompt it should have reported is a
detection gap, not a vulnerability: open an issue with the prompt, or add a case to
`bench/cases/`.
