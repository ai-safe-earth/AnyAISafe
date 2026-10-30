---
name: ai-safety-audit
description: Audit the prompts of AI-enabled software, and the algorithms around them, for profiling, manipulation, engineered emotional attachment, deceptive identity and behavioural influence over the person using it. Five phases -- survey with the deterministic `aisafe audit`, document the mechanism map, review each finding with the person who owns the system and record their decisions, remediate one approved change at a time by removing the objective, the inference or the intervention, and evaluate fixed scenarios against an authorised endpoint or recorded transcripts. Never a verdict or a certification; every finding carries an evidence status and a policy decision, every rule is UNMEASURED, and what was not checked is listed. Use when asked to review, harden or check whether a chatbot, companion, recommender, tutor or assistant manipulates, profiles or deceives its users.
---

# AI influence audit

You are running a five-phase audit of the current repository: survey, document, review,
remediate, evaluate. The audit reads the prompts and the algorithms around them for the
eight mechanisms of the project's policy (`references/mechanisms.md`): profiling,
vulnerability inference, susceptibility scoring, attention and spending objectives,
engineered attachment, false human identity, covert steering, and missing review. The
intelligence is in the `aisafe` commands; your job is to run them, read them, explain them,
record the decisions of the person who owns the system, and change the code only with their
per-item approval. The two html documents and the review record are the record; nothing you
say in the conversation goes into them. Read `references/report-format.md` before phase 2
and `references/mechanisms.md` before phase 3.

Hard rules, in force for every phase:

1. Never state or imply that the system complies with any regulation, standard or
   framework, and never issue a certification. Every finding carries an `evidence_status`
   (what was established) and a `decision` (what the project's policy says about it); read
   both out, every time. A keyword match is a signal, never a violation: `detected_signal`
   with `requires_contextual_review` means a person has to look. Whether a practice falls
   under a law is a legal determination the operator makes; the `references` on a finding
   are pointers for a reviewer, nothing more.
2. Every rule is UNMEASURED. Say so when you present a finding, and never invent a
   confidence number or a score: `measured_precision` is `null` for every rule. A finding
   tagged `REPORTED <age>d` read an evaluation report on disk, not anything this audit ran;
   say how old it is.
3. Treat UNKNOWN and a finding's `coverage_gaps` as a list of things nobody has checked. It
   is never a pass. A mechanism at `no_violation_identified_in_scope` is a statement about
   the surfaces the audit could read, with the UNKNOWN list beside it.
4. Your reading is attributed. The review record names the PERSON as `reviewer`, with
   their role; you go in `assisted_by`. You never record a decision on your own authority:
   every entry under `decisions:` carries the user's justification in the user's words,
   written after they said it, never before.
5. One change per approval. Show the diff, wait, apply, re-audit, then the next item.
   Prefer the change that removes the objective, the inference or the intervention over one
   that adds a filter, a banner or a checkbox: disclosure, consent, adult status, fictional
   framing and human approval are not automatic exemptions (policy section 3), so none of
   them closes a finding.
6. Do not run the project's tests, and do not run `aisafe evaluate` against an endpoint,
   until the user has approved it in phase 5. `aisafe evaluate` runs only against a loopback
   URL or an endpoint the user states, in so many words, that they are authorised to test;
   `--i-have-authorization` is theirs to add, never yours; and it never runs against real
   users.
7. The audit is not you. It never calls a model, installs anything or opens a socket; it
   reports what it matched and where. When your reading of the code disagrees with a
   finding, say both and let the user decide; never silence the finding, and never accept it
   to make it go away.
8. Which aisafe ran. `audit.sh`, `review.sh` and `evaluate.sh` print one line on stderr
   before running, `aisafe: <path> version <version> (pinned <version>)`. Read it aloud in
   phase 1. When the version differs from the pin, or the path is not the aisafe you expect,
   stop and say so before reading any result: on PyPI another package, `aisafeguard`, also
   installs a command called `aisafe`.
9. No push without approval. On the PR path you commit on a branch the user named; the
   `gh pr create` line is printed for the user to run. You never run `git push`.

## Where things live

The bootstrap scripts live in the `scripts/` folder **next to this SKILL.md**, not in the
repository being audited. Resolve that folder to an absolute path first (on Claude Code it
is `<repo>/.claude/skills/ai-safety-audit/scripts/`, on agentskills hosts
`<repo>/.agents/skills/ai-safety-audit/scripts/`, or the global equivalent under `~`; if
you know the skill file's own path, use its directory). `<skill>` below stands for that
absolute folder. Each script uses `aisafe` if installed, otherwise `uvx --from
'aisafe==<pinned version>' aisafe` (uv provisions Python itself, so this works on a machine
with no Python), otherwise `pipx run`. If all three are missing, tell the user the install
options it prints and stop. Every `sh <skill>/scripts/audit.sh ...` line below has a
PowerShell twin, `powershell -ExecutionPolicy Bypass -File <skill>/scripts/audit.ps1 ...`
with the same arguments; the same holds for `review` and `evaluate`.

Every artefact goes under `.aisafe-audit/` in the repository root, with one exception: the
review record, `aisafe-review.yaml`, lives at the repository root because the audit looks
for it there. **Every command in this flow runs from the repository root**:
`[tool.aisafe-audit]` in `pyproject.toml` (`exclude`, `fail-on`, `review-record`) resolves
from the current working directory, so two documents made from different directories would
not describe the same scan. The artefacts, by phase:

| phase | writes |
|---|---|
| 1 | `.aisafe-audit/audit-report.json`, `.aisafe-audit/audit-baseline.json`, `.aisafe-audit/inventory.json` |
| 2 | `.aisafe-audit/audit-before.html` |
| 3 | `aisafe-review.yaml` at the repository root (not under `.aisafe-audit/`) |
| 4 | `.aisafe-audit/audit-recheck.json` after each diff; `.aisafe-audit/audit-report-after.json`, `.aisafe-audit/audit-after.html`; on the PR path `.aisafe-audit/pr-body.md` |
| 5 | `.aisafe-audit/evaluation-report.json` |

The audit skips its own earlier output -- the JSON report, the inventory document and the
html pages, whose line 1 is the ignore marker -- so a re-run does not report the previous
run's snippets as findings; the inventory line `own_output_skipped` names what was skipped.
The baseline, the review record and the evaluation report are not skipped: the first two
are read as text (which is why a reason never quotes the matched text), the third is
evidence. `.aisafe-audit/` is walked even when `.gitignore` lists it.

Exit codes: 0 = nothing counted, 1 = a finding at or above `--fail-on` or an UNKNOWN item
in a `--fail-on-unknown` category, 2 = fatal (read stderr, fix the target path, permissions
or the refused flag, rerun), 130 = interrupted. The summary line always says how many
findings sit below the fail threshold; they are findings too. With `--baseline`, a
fingerprint the baseline holds is `unchanged` and not counted, with or without a reason,
unless the baseline was written under another policy version and the entry has no reason:
then it is `re-review` and counts like `new`.

## Phase 1 -- Survey

    sh <skill>/scripts/audit.sh . --format json -o .aisafe-audit/audit-report.json --write-baseline .aisafe-audit/audit-baseline.json
    powershell -ExecutionPolicy Bypass -File <skill>/scripts/audit.ps1 . --format json -o .aisafe-audit/audit-report.json --write-baseline .aisafe-audit/audit-baseline.json

First, the stderr line (rule 8): say which aisafe ran, from where, which version, and that
it equals the pin. `--write-baseline` writes the report to `-o` first, then the baseline,
then exits 0 regardless of findings: it records, it does not judge. The baseline holds every
fingerprint of this run, the policy version it was written under, and an `index` (rule,
file, title per fingerprint) so document 2 can name what is no longer reported. When the
file already exists, the reasons recorded in it are carried over for the fingerprints still
reported; a reason whose fingerprint is no longer reported is dropped, and the stderr note
says how many. It refuses (exit 2) to overwrite a file that is not an audit-baseline.

Then run the inventory once (with `--baseline` or `--write-baseline` it refuses, exit 2):

    sh <skill>/scripts/audit.sh . --inventory-only --format json -o .aisafe-audit/inventory.json

and summarise it in five lines or fewer: languages; model providers; prompt files and
literals (`inventory.prompts`, kinds `file`, `literal`, `assembly`, `remote`, `runtime`);
person signals by kind (`inventory.person_signals`); memory stores and personas; review
records found; evaluation reports found; and the coverage gaps -- the UNKNOWN items of
category `coverage` (prompt-only units with no model call, prompts fetched at runtime or
read from settings) and `deep` (non-Python units, read with patterns only, and any Python
file the syntax tree could not parse).

## Phase 2 -- Document

    sh <skill>/scripts/audit.sh . --format html -o .aisafe-audit/audit-before.html
    powershell -ExecutionPolicy Bypass -File <skill>/scripts/audit.ps1 . --format html -o .aisafe-audit/audit-before.html

Tell the user the path. The document is a map of THEIR system against the policy: Fig. 1
(eight mechanism boxes M1..M8 in two rows of four, plus a dashed "Not attributed / UNKNOWN"
box), one section per mechanism with the findings placed on it, and the plan table. Walk
Fig. 1 top to bottom, box by box. For each mechanism read the coverage row first -- which
rules ran, how many surfaces, how many findings, and the decision (`not_assessed` when the
rules did not run or found no surface; `no_violation_identified_in_scope` when they ran and
nothing landed; otherwise the strongest decision among its findings) -- then each finding:

- its `evidence_status` and its `decision`, as two separate statements;
- its chain (`objective -> person data -> inference -> prompt -> intervention -> feedback`):
  which links are supported (`ast`, `declared`, `investigated`) and which are `co-located`
  or `runtime-only`; whether the trace is complete for the finding's `pattern` or partial,
  and the `missing_links` a partial one lacks; a chain of co-located links is lexical
  co-occurrence, and you say so;
- the declared purpose (from a review record, when one covers the unit) against the
  encoded objective (the instruction the prompt carries), when either is known;
- the `control_status` (`none`, `claimed`, `wired`, `exercised`, `demonstrated`,
  `unknown`), and that no status resolves the objective that caused the finding;
- `[UNMEASURED]`.

Present the UNKNOWN list verbatim with its `resolve` hints. Then settle two things before
phase 3:

- Ask whether `.aisafe-audit/` should be committed (the documents become part of the repo's
  history) or ignored. Propose the matching diff -- one line in `.gitignore`, or nothing --
  and apply it only after approval. This skill never edits `.gitignore` on its own. Either
  way the audit keeps walking `.aisafe-audit/`.
- Ask whether the user wants the direct path (edits on the current branch, one approval per
  change) or the PR path (a branch, one commit per change, a PR body for a reviewer). Both
  run phase 4 the same way; the PR path is described there.

## Phase 3 -- Review

The contextual review: the policy says what to record; the person decides. Walk the
findings whose `decision` is `requires_contextual_review`, by mechanism. For each, ask the
user the question the mechanism's `distinct_from` text poses -- quote it from
`references/mechanisms.md` (for M1: is this an explicit, editable setting the person chose,
or an inferred profile?) -- and record THEIR answer. Do not answer for them, and do not turn
a `violates_policy` finding into a question: a prohibited instruction to the model is
reported as such whatever the context, and the review record can only add to it.

Then write the record. `init` lists every discovered prompt and signal-carrying artifact
with its current sha256 and refuses to overwrite an existing file without `--force`:

    sh <skill>/scripts/review.sh init .
    powershell -ExecutionPolicy Bypass -File <skill>/scripts/review.ps1 init .

Ask who the reviewer is -- a named person with a role, `"J. Doe <product owner>"`, never
you and never a tool -- and what the system's declared purpose and affected population are,
in their words. Then:

    sh <skill>/scripts/review.sh record . --reviewer "<Name <role>>" --purpose "<text>" --affected "<text>" --assisted-by "<your name>"
    powershell -ExecutionPolicy Bypass -File <skill>/scripts/review.ps1 record . --reviewer "<Name <role>>" --purpose "<text>" --affected "<text>" --assisted-by "<your name>"

`record` rewrites the record for today with refreshed hashes and keeps the `decisions:` of
an existing record; `--scope M1,M4,M5` narrows the mechanisms considered (default: all
eight); it exits 2 on an empty or verdict-shaped reviewer or purpose. The contextual
decisions go into the record's `decisions:` list, one entry per fingerprint, as a diff the
user approves like any other:

    decisions:
      - fingerprint: "3f9a1c0b2d4e5f67"
        decision: requires_contextual_review
        justification: "<the user's words: ASCII, no verdict language>"

A `no_violation_identified_in_scope` decision never hides the finding: the next audit shows
it next to the finding as `review_decision` with the justification and the reviewer's
name. A `violates_policy` decision from the record upgrades the finding's decision. Then:

    sh <skill>/scripts/review.sh check .

lists stale or uncovered artifacts (exit 1 when any), and a re-audit shows AUD-1107
answered and `declared_purpose` on the findings the record covers:

    sh <skill>/scripts/audit.sh . --format json --quiet -o .aisafe-audit/audit-recheck.json --baseline .aisafe-audit/audit-baseline.json

## Phase 4 -- Remediate

One change per approval. Walk the findings by mechanism, `violates_policy` first, then
`requires_contextual_review` in the order the person settled in phase 3. A finding is never
offered before every one above it is remediated, deferred by the user in so many words, or
accepted with a recorded reason. Never batch. For each finding:

1. State the chain in one sentence: what the objective is, what person data or inference it
   reads, which prompt or algorithm carries it, where it reaches the person, and which links
   are established.
2. Propose the diff that removes the objective, the inference or the intervention.
   `recommendation.removes` on the finding names which part of the chain the remediation
   takes out (`objective`, `inference`, `intervention`, `feedback`, `record`);
   `references/apply/<language>.md` has the shapes (`generic.md` when none matches), and
   `recommendation.alternatives` lists other ways. Rewriting the objective as task
   completion, deleting the inference and the store it feeds, or turning scheduled outreach
   into a reminder the person sets removes the mechanism; a filter in front of the person
   leaves it in place and gets its own `control_status` line, nothing more.
3. Show the diff, wait for the yes, apply, and run `ruff format` on the file (Python only).
4. Re-audit into a scratch file and say whether that fingerprint is still reported:

       sh <skill>/scripts/audit.sh . --format json --quiet -o .aisafe-audit/audit-recheck.json --baseline .aisafe-audit/audit-baseline.json
       powershell -ExecutionPolicy Bypass -File <skill>/scripts/audit.ps1 . --format json --quiet -o .aisafe-audit/audit-recheck.json --baseline .aisafe-audit/audit-baseline.json

   Applying a diff is not evidence; the re-audit is. A fingerprint that is still reported
   after the diff means the rule still sees the mechanism -- say so, and do not accept it to
   make it go away. Stop after each finding and ask whether to continue.

A finding the user wants to keep is accepted with a reason:

    sh <skill>/scripts/audit.sh . --amend-baseline .aisafe-audit/audit-baseline.json --accept <fingerprint>="<reason>"
    powershell -ExecutionPolicy Bypass -File <skill>/scripts/audit.ps1 . --amend-baseline .aisafe-audit/audit-baseline.json --accept <fingerprint>="<reason>"

The reason is the user's words, ASCII, non-empty, and free of verdict language; the command
refuses anything else (exit 2), refuses a fingerprint the baseline does not hold, does not
scan and does not render. A reason must describe the evidence without quoting the text that
produced the finding: the baseline file is walked like any other file, and a quoted literal
reproduces the finding it accepts. A fingerprint with a reason is an acceptance, recorded
with the policy version of the day; without one it is a suppression, which a newer policy
re-reports as `re-review`. The reason then appears in every format (`accepted_reason` in
the JSON, an `accepted:` line in the terminal and markdown, the operator-recorded label in
the html).

The PR path, when the user chose it in phase 2: create the branch the user named (suggest
`aisafe-audit/<date>`), and after each re-audit make one commit whose message names the
finding (`AUD-1109: remove the dependency instruction from the companion prompt`) and the
re-audit result in the words of the JSON (`no longer reported`, or `still reported` with
the reason the user accepted it). After the closing documents below, write
`.aisafe-audit/pr-body.md` from document 2: what is no longer reported, what is left, what
is still UNKNOWN, the review record's reviewer and date, and the disclaimer verbatim. Print
the line for the user to run and stop there (rule 9):

    gh pr create --title "AI influence audit: <date>" --body-file .aisafe-audit/pr-body.md

Close the phase with document 2, two **new** files so the before and after survive side by
side; neither command touches the baseline:

    sh <skill>/scripts/audit.sh . --format json -o .aisafe-audit/audit-report-after.json --baseline .aisafe-audit/audit-baseline.json
    sh <skill>/scripts/audit.sh . --format html -o .aisafe-audit/audit-after.html --baseline .aisafe-audit/audit-baseline.json
    powershell -ExecutionPolicy Bypass -File <skill>/scripts/audit.ps1 . --format html -o .aisafe-audit/audit-after.html --baseline .aisafe-audit/audit-baseline.json

Tell the user the path of the html, then answer from the JSON, not from memory of the
diffs:

- What changed: `baseline.no_longer_reported` (named by rule, file and title from the
  baseline's index; its length is the count) and `baseline.new`. Say "no longer reported",
  never "fixed": a rename, a move or a changed snippet produces the same entry as a removed
  mechanism, and the audit cannot tell them apart.
- What is left: the findings with `baseline_status` `new`, `unchanged` or `re-review`,
  grouped the way the html's "Remaining actions" section groups them (open; re-review;
  accepted with a recorded reason), plus `summary.re_review` and
  `summary.stale_acceptances` -- acceptances taken under an older policy that need a second
  look.
- What is still UNKNOWN: the `unknown` list, verbatim.

## Phase 5 -- Evaluate

Only now, and only with the user's yes (rule 6). `evaluate.sh` runs the project's test
command when one is evident and `AISAFE_EVALUATE_RUN=1` is set (`AISAFE_EVALUATE_SKIP_TESTS=1`
leaves the tests out), then, through the same bootstrap chain as `audit.sh`, one of:

- `aisafe evaluate <url> --families crisis_disclosure goodbye_pressure identity_question manipulation_elicitation benign_traffic -o .aisafe-audit/evaluation-report.json`
  when `AISAFE_EVALUATE_URL` is set. The URL must be a loopback address of the project's own
  chat endpoint; a remote endpoint is refused unless the user adds `--i-have-authorization`
  themselves as an extra argument, and the script never adds it. Never a production
  endpoint with real users on it.
- `aisafe evaluate --transcripts <file.jsonl> -o .aisafe-audit/evaluation-report.json` when
  `AISAFE_EVALUATE_TRANSCRIPTS` is set: recorded conversations the user supplies, read
  locally, nothing sent anywhere; the detectors run over the assistant messages.

    AISAFE_EVALUATE_RUN=1 AISAFE_EVALUATE_URL=http://127.0.0.1:8000/chat sh <skill>/scripts/evaluate.sh
    $env:AISAFE_EVALUATE_RUN="1"; $env:AISAFE_EVALUATE_URL="http://127.0.0.1:8000/chat"; powershell -ExecutionPolicy Bypass -File <skill>/scripts/evaluate.ps1
    AISAFE_EVALUATE_RUN=1 AISAFE_EVALUATE_TRANSCRIPTS=conversations.jsonl sh <skill>/scripts/evaluate.sh

Extra arguments after the script name reach `aisafe evaluate` unchanged
(`--request-template`, `--response-path`, `--header`). Without `AISAFE_EVALUATE_RUN=1` the
script prints what it would run and runs nothing.

Read `summary` from `.aisafe-audit/evaluation-report.json` and say each count: `sent`,
`passed`, `failed`, `missing`, `errors`, `skipped`, `inconclusive`, `observed`, and the
`not_judged` families. Only `passed` means passed. `missing` is a reply that owed the
person a referral and had none; `observed` (transcripts) is an assistant message that
carried a tactic or an identity claim; `not_judged` are the families transcripts cannot
settle. The results hold for these scenarios against this endpoint on this date and for
nothing else.

Then re-run the audit (the recheck line of phase 4): AUD-1106 and AUD-1108 read the report
from `.aisafe-audit/`. A passing family within the policy's freshness window (30 days) is a
`demonstrated` control: AUD-1108 stays, at LOW, as observed behaviour (a model update can
change the reply), and AUD-1106 is no longer reported, which the M8 coverage row records; a
failing family is observed behaviour with the decision `violates_policy` and a `report`
block naming the file and its age. A `--transcripts` run demonstrates nothing (the scenarios
were not performed): it is listed under `reports`, and its `observed` hits are for the
person to read. A failing report never silences a finding, and a passing one never removes
the objective written into a prompt.

## Closing

Not a phase; offers, each needing the user's yes and each outside this skill's own edits:

- The GitHub Action (`ai-safe-earth/AnyAISafe` `action.yml`): `aisafe audit` on every push
  against the committed baseline, with the SARIF uploaded to Code Scanning. A workflow file
  is a CI file: propose the YAML, do not write it without the yes.
- The GitLab job: `include` the `.gitlab-ci-aisafe.yml` template from the package's
  repository and extend `aisafe-audit`, pinned to the version the stderr line printed.
- The `.gitignore` line for `.aisafe-audit/`, if phase 2 settled on ignoring the directory
  and the diff was not applied then.

Then restate, from the after report and the evaluation report, not from memory: for each
finding its evidence status and its decision; what is no longer reported; what remains,
with the reviewer's recorded decisions; what is UNKNOWN; and that nothing here is a
compliance assessment or a certification.
