# Migration: from the broad safety scanner to the influence auditor

Written 2026-10-29 for the pivot on branch `pivot/influence-audit`. Starting commit:
`dc2dfcb69fef3044ea664ab64f988166dbb71296` ("feat(attest,audit): respect for the person in
the levels, and the chatbot laws", the last commit of the broad product, version 0.1.0).

The whole previous product is recoverable from git:

- branch `legacy/broad-product` and tag `legacy/pre-pivot-0.1.0`, both at the starting
  commit, both local to this repository (neither is pushed; the tag does not match the
  `v*` pattern that publishes to PyPI);
- the published wheel `aisafe==0.1.0` on PyPI, which stays installable.

```bash
git switch -c legacy legacy/broad-product      # the old tree, ready to build and test
git show legacy/pre-pivot-0.1.0:src/aisafe/devtools/hook.py   # one file
```

## 1. What the product is now

One purpose: audit prompts and the algorithms around them, in AI-enabled software, for
profiling, manipulation, engineered emotional attachment, deceptive identity and
behavioural influence over the person using it. The ethical standard is
`policy/charter.md`; the mechanisms are `policy/mechanisms.yaml`. The default audit is
deterministic, local and offline. Nothing certifies anything.

Commands: `aisafe audit`, `aisafe review`, `aisafe evaluate`, `aisafe fleet`,
`aisafe skill`. The console script `aisafe` is the only entry point.

## 2. Manifest

Decision values: **keep** (unchanged or lightly adapted), **extract** (moved into the new
layout and reworked), **remove** (deleted from the active product; in git history and at
the legacy refs), **legacy** (removed, and named here as a candidate for a separate
repository, section 6).

### Source tree `src/aisafe/`

| path (before) | decision | path (after) / why |
|---|---|---|
| `__init__.py` | extract | lazy exports of `run_audit`, `load_policy`, the finding types; the guard exports are gone |
| `cli.py` | extract | commands `audit`, `review`, `evaluate`, `fleet`, `skill`; `probe` is a hidden alias of `evaluate` |
| `devtools/audit/main.py` | extract | `audit.py`: walk, discover, pydeep, checks, flows, review records, rules, baseline, report; external adapters, `--tools`, `--run-evals`, `--pip-audit-env`, `--trusted-mcp-hosts`, `--include-home`, `--timeout`, `--decision`, `--only` removed; `--no-external` accepted and ignored |
| `devtools/audit/model.py` | extract | `evidence/model.py`: evidence status, decision, control status, chain, artifacts, policy and rule version on every finding; buckets, external tools, packages removed |
| `devtools/audit/walk.py` | extract | `discovery/walk.py`, unchanged behaviour |
| `devtools/audit/patterns.py` | extract | `discovery/patterns.py`: model calls, model ids, frameworks, ingress, prompt assembly, prompt files, remote and runtime prompts, comment spans, mention test; secrets, PII, MCP, hosts, CI, sinks, guardrail libraries, observability, evals, weights, Annex III, bootstrap, protected paths removed |
| `devtools/audit/persons_patterns.py` | extract | `discovery/vocabulary.py`: the persons vocabulary, extended with memory, inference, persuasion use, attachment, romantic role, supportive, fiction, steering, neutral information, experiment, monetisation, user-set reminder, personalised outreach and UI text kinds |
| `devtools/audit/discover.py` | extract | `discovery/discover.py`: the scanning engine and the person-facing inventory; prompt-only repositories count as an AI surface |
| `devtools/audit/configs.py` | extract | `discovery/configs.py`: structured file loading and agent front matter only |
| `devtools/audit/pydeep.py` | extract | `analysis/pydeep.py`: prompt literals, prompt assemblies, model call sites, the reply path and the assembly-to-call link; tools, gates, loops, taint and the trifecta removed |
| `devtools/audit/lint_bridge.py` | extract | `analysis/checks.py`: the checks the persons rules consumed from the linters, rewritten natively (hidden-AI instruction, response function without disclosure, decision function about a person, social scoring language, emotion recognition at work or school, objective language, personal data into a prompt); the linters themselves are gone |
| `devtools/audit/rules/__init__.py` | extract | `rules/__init__.py`: the registry; `priority` is the policy mechanism order, never the number in the id |
| `devtools/audit/rules/persons.py` | extract | `rules/_common.py`, `rules/profiling.py` (AUD-1101..1103), `rules/influence.py` (AUD-1104, 1109, 1110), `rules/identity.py` (AUD-1105), `rules/controls.py` (AUD-1106, 1108), `rules/review.py` (AUD-1107); semantics in section 3 |
| `devtools/audit/rules/{blast_radius,irreversible,trust_boundary,sinks,secrets_pii,supply_chain,observability,guards,evals,governance}.py` | remove | AUD-101..AUD-1003 (P1-P10): agent blast radius, irreversible tools, the lethal trifecta, output sinks, secrets, supply chain, observability, guard measurement, evals, governance |
| `devtools/audit/adapters.py`, `devtools/audit/semgrep/` | remove | external scanner adapters (gitleaks, detect-secrets, pip-audit, npm audit, osv-scanner, mcp-scan, semgrep, promptfoo) |
| `devtools/audit/vocab.py` | remove | tool classification, kill switches, gates; `is_unset` and `APPROVAL_SYMBOLS` moved into `discovery/vocabulary.py` |
| `devtools/audit/baseline.py` | extract | `review/baseline.py`: carries the policy version; a suppression from an older policy is re-reviewed, not silently accepted |
| `devtools/audit/report.py` | extract | `reporting/report.py`: terminal, JSON, Markdown, SARIF grouped by mechanism, with evidence status, decision, chain and the mechanism coverage table |
| `devtools/audit/html.py` | extract | `reporting/html.py`: the mechanism map instead of the system map; no trade table, no external tools |
| `devtools/probe.py`, `probes/*.yaml` | extract | `evaluation/scenarios.py` (`aisafe evaluate`) and `evaluation/corpus/`: `crisis_disclosure`, `goodbye_pressure` (new), `identity_question` (new), `manipulation_elicitation`, the person-facing half of `benign_traffic`; `prompt_injection`, `system_prompt_extraction`, `pii_echo`, `toxicity_elicitation`, `encoding_bypass`, `tool_abuse`, `manipulation_responses` removed |
| `devtools/fleet.py` | keep | adapted to the new report shape |
| `devtools/skill.py`, `devtools/hosts.py` | keep | the skill installer; hook support removed from the host table |
| `devtools/_config.py`, `devtools/_git.py` | keep | unchanged |
| `devtools/attest.py`, `config/attest-levels.yaml` | legacy | attestation levels and the signed level document |
| `devtools/decide.py`, `devtools/prices.py`, `config/prices.yaml` | legacy | control pricing against declared budgets |
| `devtools/measure.py` | legacy | guard measurement (catch rate, benign breakage, latency, cost) |
| `devtools/hook.py`, `plugins/aisafe/hooks/hooks.json` | legacy | agent-host hooks: protected paths, secret literals, unsafe shell, re-audit on edit, the Stop gate |
| `devtools/system_card.py` | remove | `aisafe init`; the review record (`aisafe review init`) replaces the card's `prompt_audit` block; a legacy card is still read for that block and reported as an unbound review |
| `devtools/euaiact_lint.py`, `devtools/misalignment_check.py`, `devtools/misalignment/`, `modules/policy/code_analyzer/` | legacy | the EU AI Act linter and the misalignment checker (`aisafe lint`, `aisafe misalign`, the `euaiact-lint` and `misalignment-check` console scripts) |
| `core/`, `modules/input/`, `modules/output/`, `modules/processing/`, `modules/llm_judges/`, `modules/observability/`, `modules/policy/{eu_ai_act,nist_ai_rmf}.py`, `integrations/`, `config/{default,eu_high_risk}.yaml`, `config/nemo_rails/`, `config/settings.py` | legacy | the runtime guardrail library: pipeline, guards, judges, integrations, presets, settings, telemetry |
| `skills/ai-safety-audit/` | extract | rewritten for the five-phase flow (survey, document, review, remediate, evaluate); `scripts/hook.*`, `attest.*`, `verify.*` and `references/{controls,levels}.md`, `apply/go.md` removed; `scripts/evaluate.*` and `references/mechanisms.md` added |

### Repository files

| path (before) | decision | why |
|---|---|---|
| `policy/charter.md`, `policy/mechanisms.yaml` | new | the versioned ethical charter and the mechanisms; packaged copies under `src/aisafe/policy/` |
| `config/` (root copies of the presets, levels and prices) | legacy | runtime presets and the removed tools' tables |
| `examples/` | remove | runtime pipeline demos; replaced by `examples/README.md` and a prompt-only demo tree |
| `audit/nist_ai_rmf.jsonl` (gitignored output) | remove | runtime compliance log of the removed NIST module |
| `.github/workflows/eu-ai-act-compliance.yml` | legacy | the linter as a CI gate |
| `.github/workflows/tests.yml` | keep | the measure job and the probe-corpus and preset steps removed |
| `.github/workflows/release.yml` | keep | gate steps updated (`rules_md --check` instead of `controls_md`/`levels_md`) |
| `.gitlab-ci-euaiact.yml` | extract | `.gitlab-ci-aisafe.yml`: the audit job only |
| `action.yml` | keep | same inputs and outputs; the audit calls no longer pass `--no-external` |
| `.pre-commit-hooks.yaml` | keep | `aisafe-audit` only; `aisafe-lint` and `aisafe-misalign` removed |
| `.pre-commit-config.yaml` | keep | the audit at push time, detect-secrets, ruff, pip-audit; the linter hooks removed |
| `scripts/controls_md.py`, `scripts/levels_md.py` | remove | generated references of removed features |
| `scripts/rules_md.py` | new | generates `docs/rules.md` and the skill's `references/mechanisms.md` from the registry and the policy |
| `scripts/bump_version.py`, `scripts/sync_skill.py` | keep | version sites and script lists updated |
| `bench/run.py`, `bench/score.py`, `bench/corpus.yaml`, `bench/README.md` | keep | audit mode only; `bench/protocol.md` and `bench/cases/` added |
| `research/` | keep | the study record; paths of moved modules updated in its README |
| `audit-baseline.json` | extract | regenerated by the new tool; carries the policy version |
| `.env.example` | remove | every variable belonged to the runtime library |
| `docs/REFERENCE.md`, `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CLAUDE.md` | keep | rewritten for the focused product |
| `docs/methodology.md`, `docs/architecture.md`, `docs/rules.md`, `docs/migration.md` | new | method, Mermaid diagrams, the generated rule catalogue, this file |

### Tests

121 test files and fixture files of removed modules were deleted. Kept and adapted:
walk, discover, pydeep, model, report, html, baseline, the audit CLI, the console script,
fleet, the skill installer and package, bump_version, the CI surface, bench sampling, git
fetch, lazy exports, the rules registry and the persons rules (split per rule module).
Fixtures kept: `persons_companion`, `persons_benign`, `clean_py`, `py_agent`, `ts_agent`,
`go_service`. New fixtures and tests are listed in `docs/methodology.md`.

## 3. Rule changes

Rule ids are kept where the meaning stayed compatible; each rule carries a `version` and
a `changed` list, both printed by `aisafe audit --list-rules` and in the report's `rules[]`.

| rule | before | after (version) |
|---|---|---|
| AUD-1101 | a person profile bound into a prompt | v2: plus `/extraction` (a prompt that extracts or infers traits about the person for storage) and `/store` (a memory or profile store next to a model call); explicit settings never match; conversation history is a signal when an inference instruction reads it |
| AUD-1102 | emotion or biometric inference | v2: plus `/vulnerability` (text-based inference of state or trait in prompt material) and `/timing` (inference used to time persuasion); a requested analysis of the person's own material is not a finding |
| AUD-1103 | scoring, ranking or an automated decision about persons | v2: scoring or segmenting people for susceptibility or personalised influence; a human-review symbol is recorded as a claimed control and no longer silences the finding |
| AUD-1104 | an engagement or retention objective | v2: plus `/monetisation`, `/experiment` and `/outreach-personalised`; a reminder the person set is not outreach |
| AUD-1105 | AI nature concealed or no disclosure | v2: false human identity or fabricated feelings; plus `/feelings`; fictional framing is recorded and routes to review, it is not an exemption; `/synthetic` (unlabelled generated media) removed as out of scope |
| AUD-1106 | no manipulation control on the response path | v2: the control's status (`none`, `claimed`, `wired`, `exercised`, `demonstrated`); a symbol or an import never silences the finding and never resolves the objective reported by another rule |
| AUD-1107 | prompt audit not recorded on the system card | v2: review record missing, stale, uncovered, unbound or under an older policy, bound to the reviewed artifacts by content hash; independent of the system card |
| AUD-1108 | no crisis path where a person confides | v2: an evaluation report that passed the crisis scenarios lowers the finding to a demonstrated control; one that failed makes it observed behaviour |
| AUD-1109 | (new) | engineered attachment, dependency or relationship substitution |
| AUD-1110 | (new) | covert commercial or political steering, assessed symmetrically |
| AUD-101..AUD-1003 | the P1-P10 rules | removed |

The legacy family number `11` no longer sets any priority: `priority` is the position of
the rule's mechanism in the policy (1 to 8), used for grouping; severity comes from the
policy's severity criteria.

## 4. Compatibility breaks

- **Commands.** `aisafe lint`, `aisafe misalign`, `aisafe init`, `aisafe measure`,
  `aisafe decide`, `aisafe hook`, `aisafe attest` are gone, as are the `euaiact-lint` and
  `misalignment-check` console scripts. `aisafe probe` still runs, as an alias of
  `aisafe evaluate`, with a note on stderr.
- **Imports.** `aisafe.core`, `aisafe.modules`, `aisafe.integrations`, `aisafe.config`,
  `aisafe.devtools.audit` and `aisafe.probes` no longer exist. The engine lives under
  `aisafe.discovery`, `aisafe.analysis`, `aisafe.evidence`, `aisafe.rules`,
  `aisafe.review`, `aisafe.reporting`, `aisafe.evaluation`; the audit entry point is
  `aisafe.audit`.
- **Dependencies.** `aiohttp` and every optional extra except `devtools` and `dev` are
  gone. `pyyaml` stays.
- **Report format.** The schema label stays `aisg/1` and the summary keys CI reads
  (`exit_code`, `findings`, `unknown_items`, `baseline_new`) stay. Findings gain
  `mechanism`, `policy_version`, `rule_version`, `evidence_status`, `decision`, `flow`,
  `control_status`, `artifacts`, `references` (was `controls`), `recommendation.removes`,
  `coverage_gaps`, `uncertainty`; they lose `bucket`, `related_lint_rules` and
  `recommendation.package`. The report gains `policy` and `mechanisms` and loses
  `measured` and `external_tools`. The inventory keeps `units`, `languages`, `llm_calls`,
  `models`, `frameworks`, `ingress`, `person_signals`, `reports`, `system_card`,
  `own_output_skipped`, `unknown`; it gains `prompts`, `memory_stores`, `personas`,
  `review_records` and loses the tool, MCP, host, data-source, sink, guardrail,
  observability, eval, secret, loop, CI and incident-path sections.
- **Baseline.** A baseline written by 0.1.0 still loads. Its bare fingerprints
  (suppressions without a reason) are reported as `re-review` under the new policy and
  count toward the exit code until a reason is recorded or the finding is fixed; its
  reasoned acceptances stay unchanged and are marked for re-review. Re-create the
  baseline with `aisafe audit . --write-baseline audit-baseline.json` to carry the
  reasons over under the current policy.
- **Audit flags.** `--fail-on-unknown` categories are now `coverage,deep,reports,runtime`
  (`tools` is gone). `--no-external` is accepted and ignored.
- **The skill and the plugin.** The skill keeps its name (`ai-safety-audit`) and its
  install paths; its flow is five phases. The plugin ships no hooks.
- **The GitHub Action and the GitLab job** keep their inputs; a workflow that passed
  `extra-args: --tools ...` or `--run-evals` must drop them.

## 5. After 0.2.0: the chain, the trace and policy 1.1.0 (unreleased)

Policy 1.1.0 (adopted 2026-10-30) splits each mechanism into **patterns** and names the
links a trace of each pattern needs (`policy/mechanisms.yaml`, `patterns`). The decision
and severity criteria did not change. What a reader of 0.2.0 output has to change:

- **`Flow.established` is gone.** In Python, read `Flow.links_supported` for the old
  meaning (every link the chain holds is `ast`, `declared` or, now, `investigated`), and
  `Finding.trace_complete` for the new question (does the chain hold every link the
  finding's pattern requires, each supported). A chain of one supported link was
  "established" before; it is `links_supported` and, for most patterns, not complete.
- **`flow_established` and `flow.established` in the JSON and SARIF are deprecated
  aliases of `trace_complete`** (`false` where `trace_complete` is `null`). Their meaning
  changed with the alias: a reader that wants the 0.2.0 meaning reads `links_supported`.
  Both aliases stay until a later minor version says otherwise.
- **New finding keys**, between `flow` and `flow_established`: `pattern` (the pattern id,
  `null` for AUD-1107), `links_supported`, `trace_complete` (`null` without a pattern) and
  `missing_links`. `flow` gains `view` (`influence` or `person-data`), `links_supported`,
  `pattern`, `required`, `missing` and `trace_complete`; a link may carry `record` (the
  investigation record that cites it).
- **New link values.** Kind `ingress` joins the influence view; the person-data view has
  `collection`, `storage`, `retrieval`, `transformation`, `transmission`, `logging`,
  `deletion`. `established_by` gains `investigated` (set only from a validated
  investigation record, never by the scan) and `runtime-only` (the link exists only at
  run time, so it is never supported).
- **The chain line** says `[trace complete for M4/objective]`, `[partial trace for
  M4/objective: objective not established]`, or `[lexical co-occurrence only; no trace
  for ...]`, and a finding with no chain prints `chain: none drawn [...]` naming the links
  a trace would need. `[established]` and `[not established: ...]` are gone.
- **Rule versions.** AUD-1101 v3: the profile binding is a supported mechanism when the
  syntax tree supports every link of the M1 binding pattern; a co-located link elsewhere
  in the file no longer lowers it. AUD-1105, AUD-1106 and AUD-1108 v3: among the
  evaluation reports inside the freshness window the least favourable one decides, and a
  report dated in the future has an unknown age, so it demonstrates nothing.
- **Review records and baselines** written under policy 1.0.0 are re-reviewed under
  1.1.0, as every policy change requires: AUD-1107/policy reports the record, and the
  baseline marks its acceptances `re-review`. A person records the review again under
  1.1.0 (`aisafe review record`), and re-accepts a kept finding with `aisafe audit
  --amend-baseline FILE --accept FINGERPRINT=REASON`.

## 6. Optional future extraction of the legacy product

The removed halves are coherent enough to live in a repository of their own:

- **`aisafe-guardrails`** (runtime): `core/`, `modules/`, `integrations/`, `config/`,
  the `measure` and `decide` tools, the attack half of the probe corpus and
  `manipulation_responses`, and their tests. Everything under `legacy/pre-pivot-0.1.0`
  at `src/aisafe/{core,modules,integrations,config}`, `src/aisafe/devtools/{measure,
  decide,prices}.py`, `src/aisafe/probes/`.
- **`aisafe-agent-audit`** (agent blast radius): the P1-P10 rules, the adapters, the
  hooks, the attestation levels and the system card, with `walk`/`discover`/`pydeep` as
  they were at the starting commit.

Neither extraction is done here; nothing in the active package depends on either. A
person who wants one starts from `git switch -c <name> legacy/broad-product`, deletes
the other half, and publishes under a new distribution name so `aisafe` keeps meaning
the influence auditor.
