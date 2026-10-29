# CLAUDE.md

## Mission

AnyAISafe exists to make any software that uses AI safe and ethical. Every change to
this repository should serve that goal. How you get there is up to you: these are
principles, not a procedure. When a rule below gets in the way of the mission, the
mission wins. Say so, and say why.

"Safe and ethical" is open to interpretation. We settle it two ways:

- **AI-safety principles.** Prevent harm before it happens. Keep humans in control of
  actions that are hard to undo. Be honest about what is known and what is not. Respect
  privacy. Build for the worst case, not the demo.
- **Human interest first.** When a choice trades the interest of the people affected (the
  end users, the people an AI system decides about, the developers using this tool)
  against convenience, speed or our own metrics, the people win.

## What the repository is

One Python package, `aisafe` (project name AnyAISafe, repo
`github.com/ai-safe-earth/AnyAISafe`, published on PyPI). It does one thing: it audits
the prompts and the algorithms around them, in AI-enabled software, for how they
influence the person using it: profiling, manipulation, engineered emotional attachment,
deceptive identity, behavioural influence. The standard it applies is the ethical charter
in `policy/charter.md`; the mechanisms it looks for are `policy/mechanisms.yaml`.

- `aisafe audit` is the deterministic, local, offline auditor: `discovery/` finds prompts,
  model calls and person signals; `analysis/` connects them (prompt-to-call links, native
  checks, the chain objective -> person data -> prompt -> intervention -> feedback);
  `rules/` are the ten rules AUD-1101 to AUD-1110, each serving one mechanism;
  `evidence/` is the finding model; `review/` holds the human decisions (review records
  bound to artifact hashes, baselines with reasons); `reporting/` renders terminal, JSON,
  Markdown, SARIF and HTML.
- `aisafe review` writes and checks the review record. `aisafe evaluate` sends synthetic
  scenarios to an endpoint the operator is authorised to test, or reads transcripts; it is
  separate and explicit, never part of the default audit. `aisafe fleet` audits many
  repositories. `aisafe skill` installs the agent skill.

The agent skill `ai-safety-audit` ships inside the package
(`src/aisafe/skills/ai-safety-audit/`). The Claude Code plugin `aisafe`
(`.claude-plugin/`, `plugins/aisafe/`) carries a copy of it. The full user reference is
`docs/REFERENCE.md`; the method is `docs/methodology.md`; the contributor guide is
`CONTRIBUTING.md`. The broad product this one grew out of (runtime guardrails, the P1-P10
agent-safety rules, lint, measure, decide, attest, hooks) lives at the local git refs
`legacy/broad-product` and `legacy/pre-pivot-0.1.0`; `docs/migration.md` says what moved
where.

## Principles we already settled

They came from real mistakes. Keep them unless you have evidence they are wrong.

- **Evidence, not verdicts.** The tool never says a system is compliant, safe or
  certified. A finding says what was established (its evidence status), what the policy
  decides about it (its decision) and what could not be checked. An empty report is not
  proof of safety, and there is never a single score.
- **A keyword is not a violation.** A lexical match is a detected signal that needs
  review. An instruction to the model in prompt material, or a flow the syntax tree
  established, can be a violation. Co-location in a file is never presented as a flow.
- **Unknown stays unknown.** A missing measurement is `None` and shows as UNMEASURED. It
  is never shown as good, and never filled in by hand. Unsupported languages, remote
  prompts and opaque models are listed as coverage gaps, never as passes.
- **Exemptions are not automatic.** Disclosure, consent, adult status, fiction and human
  approval are recorded and weighed in review; none of them closes a finding by itself.
  A control symbol never resolves the objective another rule reported.
- **Deterministic by default.** The audit calls no model, installs nothing and opens no
  network socket. Same code, same findings. Evaluation is a separate command on
  synthetic scenarios, never on real users.
- **People approve what cannot be undone.** Nothing here pushes, tags or publishes on its
  own; the skill changes code one approved diff at a time.
- **Accountability has a name.** An accepted finding carries a reason and the policy
  version it was accepted under; a review record names the person; a fingerprint with no
  reason is a suppression, and a suppression does not survive a policy change.

## Working here

Run from the repo root. No install is needed for tests (`tests/conftest.py` puts `src/`
on the path). Without an install, `PYTHONPATH=src python -m aisafe.cli <command>` is the
command. On Windows set `PYTHONIOENCODING=utf-8`.

Before calling a change done:

```bash
pytest                                     # no keys, no network
ruff check <changed files> && ruff format <changed files>
aisafe audit . --fail-on high --baseline audit-baseline.json   # must exit 0
python scripts/rules_md.py --check         # docs/rules.md and the skill's mechanisms.md are current
python scripts/sync_skill.py --check       # plugin's skill copy matches the packaged one
python scripts/bump_version.py --check     # every version site agrees
```

Things that are easy to break:

- Format labels stay as they are: `"schema": "aisg/1"`, `aisg_schema`, the `AISG_*`
  canaries. They name a document format that readers match, not the product.
- The policy exists twice on purpose: `policy/` is the source and `src/aisafe/policy/`
  ships in the wheel. Edit the source, copy, bump the policy version; a test pins them
  equal, and another pins the evidence model's enums to the policy's keys.
- Generated files are regenerated, never hand-edited: `docs/rules.md` and the skill's
  `references/mechanisms.md` (`scripts/rules_md.py`), and the plugin's skill copy
  (`scripts/sync_skill.py`).
- A baseline reason must describe the evidence without quoting the text that triggered
  the finding, or the baseline reports itself.
- `aisafe evaluate` writes a report the next audit reads as observed behaviour. Point
  `-o` outside the tree unless that is what you want.
- Rule ids are kept across versions; a semantic change bumps the rule's `version` and
  adds a `changed` line. The number inside an id is a label, never a priority.

Style: ruff format, line length 100, `from __future__ import annotations`, a
`"""path/to/module.py\n---\n"""` docstring header on every module.

Git: commit straight to `main`. Tagging `vX.Y.Z` publishes to PyPI, so it is the
owner's act, never done unasked.

## Final responses

Applies only to the final message of a task. Not to code, commit messages, or plan files.

Style
- Plain English. Short sentences. Bullet points.
- No preamble, no recap of my request, no praise.

Structure: use these headings in this order. Omit any that would be empty.
1. **Decide**: choices only I can make. For each, give your recommendation and a one-line reason.
2. **Changes**: grouped by feature, most important first. For each, give one line on what changed and why, then the files touched. Show a code snippet only when the exact line matters.
3. **Watch out**: risks, side effects, shortcuts taken, anything untested or failing.
4. **Next**: logical next steps.

Learning
- When a term, concept, or tool is likely new to me, add a one-line explanation in [brackets] right after it.
  Example: "added debouncing [waits until typing stops before running]".
