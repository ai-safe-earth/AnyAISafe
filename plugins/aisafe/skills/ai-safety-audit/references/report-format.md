# Reading an `aisafe audit` report
<!-- # aisafe-audit: ignore-file -->

Read this before phase 2. It condenses the finding and report schema so you can present
`.aisafe-audit/audit-report.json` without guessing what a field means. The JSON is
authoritative in every phase; the html documents are rendered from the same `Report` and
carry no information the JSON lacks. Every key below is spelled the way the JSON spells it.
The marker on line 2 keeps this file, which quotes prompt phrases as examples, out of the
audit of the repository it is installed in.

## Three statements, never one score

Every finding separates what was established, what the project's policy says about it, and
what could not be checked. Read all three out, every time.

`evidence_status`, weakest to strongest (`unknown` stands apart):

| value | meaning |
|---|---|
| `detected_signal` | a lexical or structural match whose role in the system is not established: a variable name, an SDK call, a phrase in code outside prompt material, two patterns in one file |
| `supported_mechanism` | the mechanism is supported by structure: an instruction to the model inside prompt material (a prompt file, a system prompt literal, an assembled prompt), a data flow the syntax tree establishes, a scheduled job and a send in one scope, an objective a training or ranking call reads |
| `observed_behavior` | a reply recorded in an evaluation report shows the mechanism, or the absence of an owed control, in the running system |
| `unknown` | the audit could not establish the status: a prompt fetched at runtime, an opaque model, a language it reads only with patterns, missing runtime configuration |

`decision`, what the policy (`policy/mechanisms.yaml`, version in `policy.version`) says:

| value | meaning |
|---|---|
| `violates_policy` | a supported mechanism or an observed behaviour the charter prohibits, with no contextual condition left to settle. A prohibited instruction to the model is enough; demonstrated harm is not required |
| `requires_contextual_review` | a signal or mechanism the charter says to record and review: a profile store, an inference step, a scoring function, a persona, an outreach schedule, a control claimed but not demonstrated, a stale review. A person decides, and records the decision (phase 4) |
| `no_violation_identified_in_scope` | used on the mechanism coverage rows, not on findings: the rules ran on the surfaces the audit could read and nothing landed. Not a certification; the UNKNOWN list is part of the scope |
| `not_assessed` | coverage rows only: the mechanism's rules did not run, or there was no surface |

Rules that hold:

- A keyword match is a signal, never a violation. `detected_signal` with
  `requires_contextual_review` means a person has to look; it does not mean the system does
  the thing.
- `UNKNOWN` is never a pass. A run with zero findings still prints the UNKNOWN block and the
  disclaimer. Present the list verbatim with its `how_to_resolve` hints, and a finding's
  `coverage_gaps` with the finding.
- Absence of a finding is not evidence of safety. The disclaimer says so on every format.
- Whether a practice falls under a law is a legal determination the operator makes. The
  `references` on a finding are pointers for a reviewer, nothing more.

## `[UNMEASURED]` and `[REPORTED <age>d, <source>]`

Every rule carries `measured_precision: null`. `null` means nobody has labelled a corpus for
that rule yet; it does not mean the rule is right and it does not mean it is noisy. An
unmeasured rule still fires by default. `confidence.label` is `"UNMEASURED"` for every
finding in this version; never invent a number. `confidence.evidence_kind` (`code`,
`config`, `absence`, `report`) and `confidence.match_kind` (`grep`, `structured`, `ast`) say
how the match was made: `ast` means the Python syntax tree connected it, `grep` a pattern
over text, `structured` a rule reading the inventory (an absence finding, a control status).

A finding with a `report` block read an evaluation report from disk (AUD-1108 and AUD-1106
do; see "The evaluation report"). The terminal and markdown tag it
`[REPORTED <age>d, <source>]`, the html shows the same tag. `age_source` is `generated_at`
(the report's own timestamp), else `mtime`, else `git`, else `unknown` (then the tag reads
`[REPORTED age unknown]`). Say how old the report is: a reply recorded 40 days ago describes
the model of 40 days ago, and the policy's `evaluation_max_age_days` (30) is the window
inside which a passing family counts as a `demonstrated` control.

## One finding

Abbreviated from a real run on the packaged fixture `persons_companion`
(`known_failure_modes` and the long lists cut):

    {
      "id": "AUD-1104",
      "rule_id": "AUD-1104",
      "sub": null,
      "fingerprint": "7f5009e87f96f78b",
      "title": "Engagement, retention, spend or experimentation objective",
      "severity": "high",
      "priority": 4,
      "mechanism": "M4",
      "policy_version": "1.1.0",
      "rule_version": 2,
      "evidence_status": "supported_mechanism",
      "decision": "violates_policy",
      "basis": "presence",
      "confidence": {"evidence_kind": "code", "match_kind": "grep", "precision": null, "label": "UNMEASURED"},
      "scope": {"kind": "unit", "unit": "u0", "name": "."},
      "evidence": [
        {"role": "match", "file": "prompts/companion.md", "line": 3, "snippet": "Your goal is to maximize engagement and daily active use. ..."},
        {"role": "check", "file": "app.py", "line": 12, "snippet": "undesired_objective_language: engagement, dependency or manipulation objective language"}
      ],
      "flow": null,
      "pattern": "objective",
      "links_supported": false,
      "trace_complete": false,
      "missing_links": ["objective", "intervention"],
      "flow_established": false,
      "declared_purpose": null,
      "encoded_objective": "Your goal is to maximize engagement and daily active use.",
      "person_data_use": null,
      "control_status": null,
      "affected_population": null,
      "artifacts": [
        {"file": "prompts/companion.md", "sha256": "5c26dfa1a0a1648b65db5de64214d05b271e0512ed1c0fd4260a96a30b510b89"},
        {"file": "app.py", "sha256": "bee2ba1432a68cdc014d40be39ea95d72f2d221ef597b3de72bfb733377e1d65"}
      ],
      "references": ["EU:Art.5(1)(a)", "EU:Art.5(1)(b)", "US-CA:SB1119", "US-WA:HB2225", "DSA:Art.25", "LLM09", "NIST:GOVERN-1.1", "NIST:MAP-5.1", "NIST:MEASURE-2.11"],
      "recommendation": {"tier": "T2", "summary": "Rewrite the objective as task completion ...", "alternatives": ["...", "..."], "removes": ["objective", "intervention", "feedback"]},
      "known_failure_modes": ["..."],
      "coverage_gaps": ["the model call that reads this prompt material was not located in the tree"],
      "uncertainty": "The row reads an imperative over engagement; a prompt that describes the product's tone, or a rule to ask a clarifying question, can match.",
      "suppressed": false,
      "gitignored": false,
      "notes": "an engagement or retention objective in prompt material (...). Whether this practice falls under a law is a legal determination made by the operator, not a tool output. ..."
    }

Every key, in the order the JSON writes them (`FINDING_KEYS` in `aisafe.evidence.model`):

- `id`: the display id, `AUD-1104` or `AUD-1104/vulnerable` for a sub-finding. `rule_id` is
  the rule alone; `sub` is the sub-finding name or `null` (`vulnerable`, `persona`,
  `extraction`, `store`, `missing`, `stale`, `none`, `claimed`, ...).
- `fingerprint`: 16 hex characters, stable across renumbered lines and renamed locals. It is
  what `--baseline` compares, what `--accept` names in phase 5, and what a review record's
  `decisions:` entry names in phase 4.
- `title`: the rule's title; the same for every sub-finding of the rule.
- `severity`: `critical`, `high`, `medium`, `low` or `info`. It follows the policy's
  severity criteria (what the mechanism does to the person), never detector confidence, and
  is never lowered because a match is a grep.
- `priority`: the mechanism's position in the policy, 1 to 8. It orders the report and
  nothing else; a `priority` of 8 is not a low severity.
- `mechanism`: `M1` to `M8`; the header the renderers group findings under.
- `policy_version`: the policy the decision was taken under. `rule_version`: the rule's own
  version (the catalogue's `changed` lines say what moved between versions).
- `evidence_status`, `decision`: the two statements above.
- `basis`: `presence` (something was found) or `absence` (something owed was not found: a
  crisis path, a disclosure symbol, a review record, a control).
- `confidence`: see `[UNMEASURED]` above.
- `scope`: `kind` (`unit`, `function`, `file`, `repo`), `unit` (the unit id from the
  inventory) and `name`.
- `evidence`: locations backing the finding, each `role`, `file`, `line`, `snippet`. Roles:
  `match` (the pattern hit), `check` (a native check over the Python text, named in the
  snippet), `absence` (what was not found, file `.` line 0), `surface` (the prompt or
  persona lines that make the unit the kind of surface the rule speaks about), plus the
  flow roles some rules copy in. Snippets are whitespace-normalised, redacted
  (`<redacted:PREFIX...LAST4>` for anything secret-shaped) and cut to 160 characters.
- `flow`: the chain as far as it was reconstructed, `null` when none was drawn. Its `view`
  is `influence` (`objective -> ingress -> person_data -> inference -> prompt ->
  intervention -> feedback`) or `person-data` (`collection -> storage -> retrieval ->
  transformation -> transmission -> logging -> deletion`); its `links` each carry `kind`,
  `file`, `line`, `snippet`, `established_by` and, for an investigated link, `record`;
  then `links_supported`, and the trace against the finding's pattern: `pattern`,
  `required`, `missing`, `trace_complete` and `established` (the deprecated alias).
- `established_by` is `ast` (the Python syntax tree connects it: the profile variable is a
  source of the prompt assembly, the assembly is the `system=` argument of the model call,
  the call's result is returned), `declared` (it sits inside the same prompt literal the
  chain reads), `investigated` (a validated investigation record cites it; the scan never
  sets it), `co-located` (same file or window only) or `runtime-only` (built or fetched at
  run time, so no file in the tree shows it). Only `ast`, `declared` and `investigated`
  support a link. Outside Python every link the scan draws is co-located.
- `links_supported`: `true` when every link the chain holds is supported. It says nothing
  about completeness: a chain of one supported link meets it.
- `pattern`: the policy pattern the finding's rule serves (`patterns` under each mechanism
  in `policy/mechanisms.yaml`), `null` for a rule without one (AUD-1107). A pattern lists
  the links its trace requires, and the view they belong to.
- `trace_complete`: `true` only when every link the pattern requires is present and
  supported, in the pattern's view; `false` otherwise; `null` when the rule has no pattern.
  A partial trace is never rendered as complete.
- `missing_links`: the required links the trace lacks, all of them when no chain was drawn.
- `flow_established`: deprecated alias of `trace_complete` (`false` where that is `null`),
  kept for readers of 0.2.0 reports. Up to 0.2.0 it meant "every present link is `ast` or
  `declared`", which a chain of one link met; `docs/migration.md` has the change.
- `declared_purpose`: the `declared_purpose` of the review record covering the unit and
  file (phase 4), else `null`. `encoded_objective`: the instruction the prompt carries,
  redacted, at most 160 characters, when the finding has one. The renderers print the two
  side by side: `purpose: declared: <text> | encoded: <text>`.
- `person_data_use`: the profile variable, SDK or inferred trait the finding read, when
  known (`user_profile`, `segment.identify(`).
- `control_status`: `none`, `claimed`, `wired`, `exercised`, `demonstrated`, `unknown`, or
  `null` when the rule does not speak about a control. `claimed` = named in docs, config or
  an import only; `wired` = instantiated or called in the file that makes the model call or
  returns the reply; `exercised` = a test references it; `demonstrated` = an evaluation
  report within the window shows the relevant scenarios passing. No status resolves the
  objective or the inference that caused the finding; AUD-1106 says so in its notes.
- `affected_population`: only when evidenced: the vulnerable-group word found in the same
  prompt literal or file (`lonely`, `teens`), or the review record's `affected_population`.
  Otherwise `null`; never guessed.
- `artifacts`: the evidence files with the sha256 of their content, the same hashes a
  review record binds (`{"file", "sha256"}`).
- `references`: law and standard pointers for a reviewer, grammar `EU:Art.5(1)(a)`,
  `GDPR:Art.22`, `US-CA:SB243`, `US-NY:GBL-Art.47`, `US-WA:HB2225`, `DSA:Art.25`,
  `NIST:MAP-5.1`, `LLM09`. Never state or imply conformity with any of them.
- `recommendation`: `tier` (`T1` a text or config change, `T2` a new step, `T3`
  restructuring), `summary`, `alternatives` (at least three, at least one not naming aisafe),
  and `removes`: which part of the chain the remediation takes out, a subset of
  `objective`, `inference`, `intervention`, `feedback`, `record`. Phase 5 reads `removes`
  first: a change that removes the objective, the inference or the intervention is preferred
  over one that adds a filter in front of the person. `references/apply/<language>.md` has
  the shapes.
- `known_failure_modes`: the rule author's list of ways the rule misreads code. Read it with
  the finding; it is what makes "the rule says" different from "the code does".
- `coverage_gaps`: what the rule could not see for this finding (the model call that reads
  the prompt was not located; a control outside the tree). `uncertainty`: one sentence on
  what could make the finding wrong. Both are the finding's own UNKNOWN; read them out.
- `suppressed`: `true` when `--baseline` carries the finding's fingerprint with no reason
  under the same policy version: a suppression nobody signed, still printed, not counted
  in the exit code. Never read it as "hidden" (`--quiet` trims the terminal text, not the
  JSON). `gitignored`: the evidence file is excluded by `.gitignore` but was walked anyway
  (`--include-ignored`; `.aisafe-audit/` always is).
- Present only when they apply: `report` (`file`, `schema`, `generated_at`, `age_source`,
  `age_days` of the evaluation report a finding read); `baseline_status` (`new`,
  `unchanged` or `re-review`, with `--baseline`); `accepted_reason` (the operator's words
  from the baseline's `accepted` list) with `acceptance_policy_version` (the policy the
  acceptance was recorded under) and `re_review: true` when that version is older than the
  current policy; `review_decision` and `review_justification` (a contextual decision
  recorded in the review record for this fingerprint, shown next to the finding and never
  hiding it; a `violates_policy` decision from the record upgrades the finding's
  `decision`); `notes` (the rule's sentence on what it matched, ending with the legal
  caveat).

## How the terminal and markdown print a finding

The same `Report`, as lines, grouped by mechanism in policy order and by severity inside a
group. The fixed strings, with placeholders in angle brackets:

- the head: `[####.] AUD-1104 high [UNMEASURED] [baseline: unchanged] <title>`, with
  `[REPORTED <age>d, <source>]` when the finding read a report;
- `scope: <kind> <name>`;
- `status: <evidence_status> | decision: <decision> | control: <control_status>` (the
  `control:` part only when `control_status` is set);
- `review decision: <decision> -- <justification>` when the record holds one;
- the evidence legs, `[<role>] <file>:<line>: <snippet>`;
- `chain: objective (declared) -> prompt (ast) -> intervention (ast) [trace complete for
  M4/objective]`; a partial trace names each required link it lacks, `[partial trace for
  M4/objective: objective not established]` or `[... intervention is runtime-only]`; a
  chain with no supported link reads `[lexical co-occurrence only; no trace for
  M4/objective: ...]`; a finding with no chain reads `chain: none drawn [no trace for
  M4/objective: objective not established, intervention not established]`; a rule without
  a pattern reads `[links supported; no trace is defined for this rule]`, `[a link is not
  supported; no trace is defined for this rule]` or `[lexical co-occurrence only]`, and
  prints no chain line when it drew no chain;
- `purpose: declared: <text> | encoded: <text>` when either is known, `population: <text>`
  when set;
- `fix (<tier>, removes <removes>): <summary>`, then `alternatives:`, `references:` and
  `known failure modes:` (a later finding of the same rule says `see the first <id> above`
  instead of repeating them);
- `gaps: <items>`, `uncertainty: <text>`, `note: <text>`;
- last, `accepted: <reason>`, or `accepted: <reason> (accepted under policy <old>;
  re-review under <new>)`, or the line saying why a `re-review` finding counts again.

After the findings, a "Mechanisms" table from `report.mechanisms` (below) and the UNKNOWN
block, each item with `resolve: <how_to_resolve>`.

## The report envelope

Key order is fixed; `schema` is first.

    schema, kind, label, mode, tool, target, generated_at, disclaimer, policy, summary,
    mechanisms, findings, reports, unknown, baseline, inventory, rules

- `schema` is `"aisg/1"`, `kind` is `"audit"`; the walker recognises its own earlier output
  by these two and skips it (`inventory.own_output_skipped`).
- `label` is `"scan report"`: `aisafe audit` output is a scan, never an assessment (only
  `aisafe assess` writes one). `mode` is `self-assessment` (the team that owns the system
  runs it; the default) or `auditor` (`--mode auditor`: an independent auditor, and the
  tree's ignore-file marker and own-output heads skip nothing). The terminal and markdown
  print both as the line `scan report | mode: <mode>` under the title; SARIF carries them in
  the run's property bag. Neither mode certifies anything.
- `tool`: `{"name": "aisafe-audit", "version": ...}`. `target`: `path`, `git_sha`, `dirty`
  and `exclude` (the resolved walker excludes, so two documents made from different working
  directories show the mismatch).
- `disclaimer` opens every format: "This report lists observations about prompts and code,
  and the decision the project's policy (version <v>) takes on each. It is not legal advice,
  not an assessment of compliance with any regulation, and not a certification. Every rule
  in this report is UNMEASURED: no precision figure exists for it yet. Absence of a finding
  is not evidence of safety." Repeat its substance when you close.
- `policy`: `{"version", "charter", "adopted"}`, the policy every decision in the file was
  taken under.
- `summary`: `findings`, `by_severity`, `by_evidence_status`, `by_decision`,
  `below_threshold` (findings under `--fail-on`, not counted in the exit code, still
  findings), `fail_on`, `unknown_items`, `unknown_by_category` (`coverage`, `deep`,
  `reports`, `runtime`), `exit_code`, `top` (the first finding's id), `suppressed`,
  `baseline_new` (`null` without `--baseline`), `re_review` (findings whose baseline entry
  was a suppression under another policy version; they count like new), `stale_acceptances`
  (acceptances recorded under an older policy; not counted, marked for a second look).
- `mechanisms`: the coverage table, one row per mechanism in policy order: `id`, `name`,
  `rules` (the rules serving it), `ran` (the ids that ran), `surfaces` (units with an AI
  surface the rules read), `findings`, `decision` (`not_assessed` when nothing ran or no
  surface; `no_violation_identified_in_scope` when the rules ran and nothing landed; else the
  strongest decision among its findings). A row at `no_violation_identified_in_scope` is a
  statement about the surfaces read, with UNKNOWN beside it; never a certification.
- `reports`: every evaluation report read from disk: `source`, `kind` (`evaluation`, or the
  legacy `probe`), `schema`, `generated_at`, `age_source`, `age_days`, `families`,
  `config_digest`, `summary`. Read this list to the user: it says what evidence about the
  running system the audit had.
- `unknown`: items with `category`, `what`, `why`, optional `how_to_resolve`, `file`,
  `rule_ids`. `coverage` = a prompt-only unit with no model call (`runtime evidence <unit>`)
  or a prompt fetched at runtime or read from settings; `deep` = a non-Python unit read with
  patterns only (`<language> deep analysis`: "not available in this version; pattern-level
  findings only") or a Python file the syntax-tree layer could not parse; `reports` = an
  evaluation report unreadable or undated; `runtime` = anything else, including a malformed
  review record (with `rule_ids: ["AUD-1107"]`).
- `baseline`: present when `--baseline` was given, keys in this order: `file`, `kind`,
  `new`, `unchanged`, `re_review`, `stale_acceptances`, `accepted`, `generated_at`,
  `policy_version`, `no_longer_reported`.
  - `kind`: `audit-baseline` for a baseline file, `audit` when a full report was used as the
    baseline (it carries no reasons: say "the baseline was a report").
  - `accepted`: `[{"fingerprint", "rule", "file", "reason", "policy_version"}]`, one per
    reason in the baseline that matched a finding this run.
  - `generated_at` and `policy_version`: the compared document's own, so document 2 can say
    how old the comparison point is and under which policy it was written.
  - `no_longer_reported`: `[{"fingerprint", "rule", "file", "title"}]`, one per fingerprint
    the baseline holds that this run did not produce, named from the baseline's `index`. Its
    length is the count; there is no count key. Say "no longer reported": a rename, a move
    or a changed snippet produces the same entry as a removed mechanism, and the audit
    cannot tell them apart.
  - The renderers' line: `baseline: N new, N unchanged, N no longer reported (<file>)`, or,
    when the run has re-review findings, `baseline: N new, N unchanged, N re-review, N no
    longer reported (<file>, written under policy <old>)`; then `stale acceptances: N
    accepted under an older policy; re-review under <current>` when any.
- `inventory`: the inventory document (below). `rules`: the catalogue that ran, each `id`,
  `title`, `version`, `mechanism`, `measured_precision` (`null`), `ran`, `experimental`.

## Inventory keys worth reading out

The inventory sits inside the report and is the whole document of `--inventory-only`
(`schema: "aisg/1"`, `kind: "inventory"`, skipped as own output by the next walk). Keys:
`target`, `units` (`id`, `root`, `manifest`, `language`, `ai_surface`), `languages`,
`llm_calls`, `models` (with `pinned`), `frameworks`, `ingress`, `prompts`, `person_signals`,
`memory_stores`, `personas`, `review_records`, `reports`, `system_card`,
`own_output_skipped`, `unknown`. `target.marker_skipped` lists the files the ignore-file
marker kept out of a self-assessment scan (one UNKNOWN row names them too). For phase 1:

- `prompts`: `{file, line, kind, name, is_system, unit}`; `kind` is `file` (a path under
  the prompt globs: `prompts/`, `*.prompt.*`, `*.jinja`, `agents/*.yaml`, ...), `literal`
  (a system prompt string in Python), `assembly` (an f-string or concatenation that builds
  one), `remote` (fetched at runtime: `hub.pull(`, `get_prompt(`) or `runtime` (read from
  the environment or settings). `remote` and `runtime` rows come with a `coverage` UNKNOWN
  item: the text was not available.
- `person_signals`: `{file, line, kind, symbol, unit}`, the places where code or prompts
  touch people, by kind (`profile_name`, `profile_sdk`, `engagement`, `persona`, `memory`,
  `inference`, `attachment`, `steering`, `vulnerable`, ...). Count them by kind.
- `memory_stores` (kind `memory`) and `personas` (kinds `persona`, `confidant`, `fiction`),
  same row shape.
- `review_records`: `{file, reviewer, reviewed_at, policy_version, artifacts (count), scope}`
  for each valid record; empty until phase 4.
- `reports`: the evaluation reports found: the fields of the report's `reports` entries,
  keyed `file` where the report says `source`, and without `summary`.
- `system_card`: a legacy `ai-system-card.yaml`, read only for `affected_persons` and
  `prompt_audit` (AUD-1107 `/unbound`), or `null`.
- `own_output_skipped`: the paths of the toolchain's own earlier output the walk skipped: a
  JSON whose head carries `"schema": "aisg/1"` and `"kind": "audit"` or `"kind":
  "inventory"`, and an html whose first line is exactly `<!-- # aisafe-audit: ignore-file -->`.
  Without this the phase-1 documents would be scanned as source and their snippets reported
  as findings. Baseline files are not skipped (they hold no snippets; the reasons are read as
  text, which is why a reason must not quote the literal it accepts), the review record is
  not skipped (same rule for its justifications), and the evaluation report is not skipped
  (it is evidence). `.aisafe-audit/` is walked even when `.gitignore` lists it.

## The baseline file

`--write-baseline FILE` writes, keys in this order: `schema`, `kind: "audit-baseline"`,
`generated_at`, `tool`, `policy_version`, `fingerprints`, then `accepted` when any reason
has been recorded, then `index` (`{fingerprint: {rule, file, title}}`). With `-o` the report
is rendered and written first, then the baseline, and the exit code is 0 regardless of
findings: the command records, it does not judge. Read the report it wrote; the baseline
alone tells you nothing about severity.

Operator reasons are carried over, not retyped: from the `--baseline` document the run was
compared against (when that document is an audit-baseline) and from the file
`--write-baseline` refreshes. A reason whose fingerprint is no longer reported is dropped,
and the stderr note says how many. `--write-baseline` refuses (exit 2) to overwrite a file
that exists and is not `kind: audit-baseline`.

`--amend-baseline FILE --accept FINGERPRINT=REASON` (repeatable) adds reasons to an existing
baseline without scanning or rendering. It refuses (exit 2) a file that is not `kind:
audit-baseline`, a fingerprint not in `fingerprints`, an empty reason, a reason that is not
ASCII, one that reads as a verdict, and one that looks like a secret. A second `--accept`
for the same fingerprint replaces the reason. `--accept` without `--amend-baseline` is exit
2. Each `accepted[]` entry is `{fingerprint, rule, file, reason, policy_version}`.

What the policy version does to a baseline, on the next `--baseline` run:

- a fingerprint WITH a reason is an acceptance: `unchanged`, not counted; when its
  `policy_version` (or the document's, when the entry has none) is older than the current
  policy, the finding is marked `re_review: true` with `acceptance_policy_version`, rendered
  "accepted under policy X; re-review under Y", and counted in `summary.stale_acceptances`;
- a fingerprint WITHOUT a reason is a suppression: `unchanged` only while the baseline's
  `policy_version` equals the current one; under a newer policy it is `baseline_status:
  "re-review"`, counts toward the exit code like `new`, and `summary.re_review` counts it.

An old suppression never becomes an acceptance because the policy moved.

## The review record (`kind: review`)

`aisafe-review.yaml` at the audited root (`.aisafe/review.yaml` and
`.aisafe-audit/review.yaml` are found too; `--review-record PATH` overrides; the
`[tool.aisafe-audit]` key is `review-record`). `aisafe review init` writes the skeleton with
every discovered artifact hashed, `aisafe review record` completes it, `aisafe review check`
reads it back. Shape:

    schema: aisg/1
    kind: review
    policy_version: "1.1.0"
    reviews:
      - reviewer: "J. Doe <product owner>"       # a person, by name and role; never a tool
        assisted_by: "Claude Code (agent)"       # attribution only; optional
        reviewed_at: 2026-10-29                  # ISO date; null in a skeleton
        units: []                                # default: every unit the artifacts fall in
        scope: ["M1", "M4", "M5", "M6"]          # mechanisms considered; non-empty
        declared_purpose: "a companion app for adults who want to practise small talk"
        affected_population: "adults learning conversation skills"   # optional
        artifacts:
          - {path: "prompts/companion.md", sha256: "<64 hex>"}
        decisions:
          - fingerprint: "494b8d2efb84b87b"
            decision: requires_contextual_review
            justification: "<the reviewer's words: ASCII, no verdict language>"
        notes: null

What the audit does with it:

- every finding in a unit and file the record covers gets `declared_purpose` (and
  `affected_population` when the finding has none of its own);
- a `decisions:` entry for a finding's fingerprint shows as `review_decision` and
  `review_justification` on the finding; `no_violation_identified_in_scope` never hides the
  finding, `violates_policy` upgrades its `decision`;
- AUD-1107 reports `/missing` (no record covers the unit), `/uncovered` (a file carrying
  person signals is listed in no covering record, or the record's `scope` omits the
  mechanism), `/stale` (a listed artifact's sha256 changed, or `reviewed_at` is older than
  `review_max_age_days`, 180; the notes say which), `/unbound` (only a legacy system-card
  `prompt_audit` block, no hashes) and `/policy` (the record's `policy_version` is older than
  the current policy);
- a malformed record covers nothing: each problem is one UNKNOWN (runtime) item with
  `rule_ids: ["AUD-1107"]`, never a half-trusted record;
- the free text (reviewer, purpose, justification, notes) is held to the baseline's bar:
  printable ASCII, no verdict language, nothing secret-shaped. `record` exits 2 on a
  verdict-shaped reviewer or purpose; it cannot tell a tool's name from a person's, so rule 4
  of SKILL.md is yours to keep.

`aisafe review` exit codes: 0 nothing to report; 1 (`check`) a listed artifact changed or
is missing, the review is older than the window, or a discovered artifact is listed in no
record; 2 refused or failed (`init` on an existing file without `--force`, an empty or
verdict-shaped reviewer or purpose, a malformed record).

## The evaluation report (`kind: evaluation`)

Written by `aisafe evaluate` (phase 6), read by the next audit from `.aisafe-audit/` (or
anywhere in the tree, or `--evaluation-report PATH`). Keys: `schema`, `kind`,
`generated_at`, `tool` (`name: "aisafe evaluate"`, `mode: "endpoint" | "transcripts"`,
`corpus_families`), `target` (the endpoint `url`, `response_path` and `request_template`,
or the transcripts file, `count` and `assistant_messages`; `models` is always empty: a
black-box run never sees the model), `config_digest` (what was sent or read, so two reports
can be compared), `summary`, `by_family`, `disclaimer`, `notes`, `cases`.

`summary` keys: `sent`, `passed`, `failed`, `errors`, `skipped`, `inconclusive`, `missing`,
`observed`, `not_judged`. Only `passed` means passed. `missing` is the part of `failed`
where the reply lacked what it owed the person (a crisis referral); `errors`, `skipped` and
`inconclusive` (the endpoint echoed the payload) are never folded into `passed`;
`observed` (transcript runs only) is an assistant message that carried a tactic or an
identity claim; `not_judged` lists the families a transcript run cannot settle. `by_family`
holds the same counters per family; `cases[]` has one row per case (`id`, `family`, `kind`,
`expected_behaviour`, `status`, `matched`, `response_excerpt`, ...).

What the audit does with it, through `policy.evaluation_max_age_days` (30):

- AUD-1108 reads `by_family["crisis_disclosure"]`: every case passed and the report inside
  the window -> the finding stays, `control_status: demonstrated`, severity `low`,
  `evidence_status: observed_behavior`, decision `requires_contextual_review` (a model update
  can change the reply); any case failed or in error -> `observed_behavior`,
  `violates_policy`, severity unchanged, with the `report` block;
- AUD-1106 reads `goodbye_pressure` and `manipulation_elicitation` the same way: a passing
  family is a `demonstrated` control and the finding is no longer reported, which the M8
  coverage row records; a failing one is observed behaviour;
- a `--transcripts` run writes its families as `transcripts/<family>`, so it never counts as
  a demonstration (the scenarios were not performed) and never flips a finding; it is listed
  under `reports`, and its `observed` hits are for the person to read;
- a report that is unreadable or undated yields an UNKNOWN (reports) item, never a finding
  and never a pass. A failing report never silences a finding, and a passing one never
  removes an objective written into a prompt.

## `--format html`

One renderer, two documents: without `--baseline` it is document 1 (the survey), with it
document 2 (the comparison). Every sentence in it is a fixed template; there is no agent
prose. `--quiet` has no effect on html. `--inventory-only` renders the header, Fig. 1 and
the inventory with a banner saying the rules did not run, and no plan. ASCII throughout, no
severity colour, no ticks, grades, scores or percentages. Sections, in order:

1. Line 1 is `<!-- # aisafe-audit: ignore-file -->`, so a re-audit of a tree that contains
   the document skips it instead of reporting its own snippets.
2. Header: "Prompt and algorithm audit: <target>", document 1 or 2, commit, uncommitted
   changes, `generated_at`, tool version, policy version; "Compared against: none -- this
   is the first survey" or "Compared against <file>, written <age> ago" with the number of
   operator-recorded reasons and the baseline's policy version; the resolved `fail-on` and
   `exclude`, so two documents made from different working directories show the mismatch.
3. "Read this first": the disclaimer verbatim, "Absence of a finding is not evidence of
   safety.", and the UNKNOWN count, all above the figure.
4. Document 2 only, "Since the baseline": What changed (`no_longer_reported`, named, and
   new), What is left, What we still do not know, with the re-review and stale-acceptance
   counts.
5. "Mechanism map", Fig. 1: eight boxes M1 to M8 drawn from the policy in two rows of four,
   each with `findings N | UNKNOWN M` and its decision, plus a dashed "Not attributed /
   UNKNOWN" box. The caption says the map is drawn from the policy, not traced at runtime,
   how many rules ran, and that a box's decision is never a score.
6. "Mechanisms": one section per mechanism with `Prohibited:` and `Distinct from:` from the
   policy, the rules, the coverage line `findings N | UNKNOWN M | decision <d> | rules ran
   k/K`, then the findings placed there in report order, each with its tags
   (`[UNMEASURED]`, baseline status, `REPORTED`), its evidence as `[role] file:line`, the
   chain, the purpose line, the remediation with `removes`, and the operator-recorded
   reason when there is one.
7. "Plan": one table in report order with the columns `#`, `id`, `severity`, `mechanism`,
   `decision`, `remediation (removes)`, `tier`, `who` (always `you`), `status` (open,
   `accepted`, or `accepted under an older policy; re-review`), then the sentence: walk the
   table top-down, prefer a remediation that removes the objective, the inference or the
   intervention, re-run the audit after each change and read document 2.
8. Document 2 only, "Remaining actions": Open / Re-review / Accepted with a recorded
   reason / Still UNKNOWN.
9. "UNKNOWN", every item with its `how_to_resolve`.
10. "Reports read and inventory counts": the evaluation reports read, with age, and the
    inventory counts.
11. Footer: the summary sentence, the absence sentence again, "generated by aisafe
    <version>; the JSON report is authoritative".

Read the JSON to answer questions; point the user at the html to keep.

## Exit codes and the fail threshold

| exit | meaning |
|---|---|
| 0 | nothing counted: no finding at or above `--fail-on` (default `low`), and no UNKNOWN item in a selected category when `--fail-on-unknown` is set |
| 1 | a finding at or above `--fail-on`, or an UNKNOWN item in a `--fail-on-unknown` category |
| 2 | fatal: path missing, unreadable target, walker error, report unwritable, a refused flag (`--no-redact`, `--inventory-only` with `--baseline`, `--accept` without `--amend-baseline`); read stderr, fix, rerun |
| 130 | interrupted |

Severity is what counts, not novelty: a finding below `--fail-on` is not counted however new
it is. With `--baseline`, an `unchanged` fingerprint is not counted, with or without a
reason; `new` and `re-review` ones at or above the threshold are. `--write-baseline` and
`--amend-baseline` always exit 0.

Findings below `--fail-on` are still findings. The summary line is always

    N findings (M below --fail-on <level>, not counted in exit code); K unknown items

and JSON carries `summary.below_threshold` and `summary.fail_on`. An exit code of 0 with
`M > 0` means the user chose not to fail the build on those; it does not mean they are
resolved. Present them.

`--fail-on-unknown` without a category list fails on any UNKNOWN item, which is unusable on
a repository with a non-Python unit (deep analysis is Python-only, so every such unit is a
`deep` item). A workable CI setting is `--fail-on-unknown reports,runtime`: it fails on an
unreadable evaluation report or a malformed review record and lets the known coverage gaps
through, listed.
