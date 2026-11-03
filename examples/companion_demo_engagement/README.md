# companion_demo_engagement

An example of a third-party assessment of `../companion_demo/`, kept with all its working
files. Nothing here is real: the auditor, the audited team and the product are fictional. An
AI agent filled in every field for this demonstration. In a real engagement a person fills
in those fields, and an agent is not allowed to.

## What happened

| Commit | What it holds | Result |
|---|---|---|
| `4a83556` | the code as first audited | M4, M5 and M6 violations established; M1, M2 and M8 inconclusive; M7 closed on 4 of 8 surface hypotheses |
| `bf85f2b` | first fix: the daily target and the nudge go | M4 `not_remediated`: one persona sentence survived, and the records went to review |
| `9be2212` | second fix: that sentence goes | M4 still `not_remediated`, as explained below |

At the first commit, 21 records went to a skeptic with no shared context. Six were refuted,
including the claim that a person's messages leave for a vendor: the tree shows the call but
never names the package. Each refuted record stays a blocking gap until a new record answers it.

## Why the code is fixed and M4 still stands

The text of the objective is gone, and the scan no longer reports it. The retest still says
`not_remediated`, for two reasons:

- `remediated` needs an upheld closing record on the new code. The closing records were
  refuted, because they dropped open questions that nothing in the code can answer: whether a
  retention metric exists, and what the client does with `minutes_today`.
- The audited team answered in writing (`evidence/`). The investigator weighed that statement
  and did not accept it as enough: it comes from the audited party, and it names no person,
  date or commit. So the newest records stay at review, and the evaluation step never ran.

This is the tool working. A fix that cannot be shown stays unshown. A real engagement would
go on in one of two ways: the auditor accepts the statement or gets better evidence, then
writes a closing record for a skeptic; or an evaluation runs against an authorised endpoint.

## What is here

- `engagement.json`: who audits whom, the scope, the applicability answers.
- `authorisations/`: the written authorisation, hashed.
- `scan-report.json`, `scan-report.md`: the scan at the first commit.
- `investigation-plan.json`, `retest-plan.json`, `retest-2-plan.json`: the plan at each commit.
- `investigations/`: the records and skeptic passes. `a-` is the first commit, `b-` the second,
  `c-` and `d-` the third. Each record names the agent and model that wrote it.
- `assessment/`: the assessment at the first commit, with separate ethical and legal sections,
  and its bundle of hashes.
- `retest-1/`, `retest-2/`: the assessment at each later commit.
- `evidence/`, `evidence-requests.json`: what the auditor asked for and received.

Each folder was written by the tool as it was at that commit. A later fix changed one label:
in `retest-1/`, the closings on `prompts/style.md` read `regressed` because a finding on
`prompts/persona.md` was already there. The current tool gives `needs_reinvestigation`
there, which counts the same way: not remediated.

`aisafe engagement status` reads `assessment/`. It reports `engagement.json` and the request
list as changed, because the scope gained two commits after that first bundle was made. The
bundles in `retest-1/` and `retest-2/` record each later state.
