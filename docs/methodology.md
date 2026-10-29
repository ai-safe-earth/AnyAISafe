# Methodology

How `aisafe audit` turns prompts and code into findings, what a finding may and may not
say, and how the detector's own accuracy is measured. The ethical standard it applies is
`policy/charter.md`; the mechanisms are `policy/mechanisms.yaml`; the diagrams are in
`docs/architecture.md`; the rule catalogue is `docs/rules.md` (generated).

## 1. What is examined

The audit reads the repository as text and, for Python, as syntax trees. It never runs
the software, calls a model or opens a socket.

| examined | how it is found |
|---|---|
| prompt files and templates | path globs (`prompts/`, `*.prompt.*`, `*.jinja`, `agents/*.yaml`, `persona*`, `*system_prompt*`) |
| prompt literals and assemblies in code | Python syntax trees (`SYSTEM_PROMPT = """..."""`, f-strings, `.format`, templates, `system=` arguments); pattern fallback in other languages |
| model calls | SDK call shapes (Anthropic, OpenAI, Google, Bedrock, Azure, Mistral, Cohere, Ollama, Vertex, LiteLLM, Hugging Face, Vercel AI) and plain HTTP calls that carry a model id and a generation key |
| prompts fetched or configured at runtime | `hub.pull(`, `get_prompt(`, a prompt read from the environment or settings: recorded as a coverage gap, because the text is not in the tree |
| profile extraction, storage and retrieval | profile SDK calls, profile-named variables bound into a prompt, template placeholders, memory stores, extraction instructions |
| inference from conversation history | instructions to infer mood, personality, loneliness or vulnerability from what the person wrote |
| emotion and vulnerability inference | affect SDKs and calls, biometric categorisation, text-based inference instructions, and the persuasion verbs near them |
| ranking, scoring and segmentation | person-scoring language in prompts, segmentation code read by a prompt or a send |
| reward functions and optimisation targets | objective variables and reward assignments naming engagement, retention, session length, spend |
| notification and re-engagement logic | a scheduled job and a send to a person in one file; the profile or mood words that choose the message |
| experimentation and monetisation objectives | prompt variants under an experiment flag with an engagement or revenue metric in the unit; monetisation imperatives |
| persona and identity instructions | human claims, denial when asked, fabricated bodies and feelings, romantic and confidant roles, fiction framing |

An audit of a repository that has prompts but no recognised model SDK still runs: prompt
material is an AI surface on its own. The report then carries a coverage item saying
the response path, the controls and the data flows could not be read.

## 2. The chain

Where the evidence allows, a finding reconstructs:

```
objective -> person data or inference -> prompt or algorithm -> intervention -> feedback or reward
```

Each link is marked with how it was established:

- `ast`: the Python syntax tree connects it (the profile variable is a source of the
  prompt assembly; the assembly is the `system=` argument of the model call; the call's
  result is returned or sent);
- `declared`: it sits inside the same prompt literal the chain reads (an objective
  sentence in the system prompt that binds the profile);
- `co-located`: it shares a file or a window with the rest, and nothing more.

A chain is **established** only when every present link is `ast` or `declared`. A chain
with any `co-located` link is printed as such, and a finding with no established link
says "lexical co-occurrence only". Co-occurrence is never presented as a verified flow.

## 3. Evidence status, decision, severity

Three separate statements, never one score.

**Evidence status**, what was established:

| status | meaning |
|---|---|
| `detected_signal` | a lexical or structural match whose role is not established: a variable name, an SDK call, a phrase in code outside prompt material, two patterns in one file |
| `supported_mechanism` | an instruction to the model in prompt material, a flow the syntax tree established, a schedule and a send in one scope, an objective a training or ranking call reads |
| `observed_behavior` | a reply in an evaluation report or a supplied transcript shows it |
| `unknown` | a prompt fetched at runtime, an opaque model, a language read only with patterns |

**Decision**, what the policy says:

| decision | when |
|---|---|
| `violates_policy` | a supported mechanism or observed behaviour the charter prohibits, with no contextual condition left to settle. A clear prohibited instruction to the model is enough; demonstrated downstream harm is not required |
| `requires_contextual_review` | a signal the charter says to record and review: a profile store, an inference step, a scoring function, a persona, an outreach schedule, a control claimed but not demonstrated, a stale review |
| `no_violation_identified_in_scope` | the mechanism's rules ran on the surfaces the audit could read and found nothing; shown in the mechanism coverage table with the scope |
| `not_assessed` | the mechanism's rules did not run, or there was no surface |

A keyword match alone never yields `violates_policy`. Disclosure, consent, adult status,
fictional framing and human approval are recorded on the finding and weighed in the
review; none closes a finding by itself.

**Severity** follows the policy's criteria (critical: a vulnerable group, a
special-category trait used for influence, a mental-health confidant with no crisis path;
high: a supported prohibited mechanism; medium: a signal needing review; low: a weak or
unit-level signal; info: a record-keeping gap). It is independent of the rule id, of the
mechanism number and of confidence. `priority` on a finding is the mechanism's position
in the policy (1 to 8) and only orders the report.

## 4. Controls: claimed, wired, exercised, demonstrated

A control against a mechanism is reported at the strongest status the evidence reaches:

| status | evidence |
|---|---|
| `none` | no control symbol in the unit |
| `claimed` | a control is named in docs, config, a preset or an import, and nothing shows it on the response path |
| `wired` | the control is instantiated or called in the file that makes the model call or returns the reply |
| `exercised` | a test in the tree references the wired control |
| `demonstrated` | an evaluation report within its freshness window shows the relevant scenarios passing |

No status resolves the objective or the inference that caused the finding. A disclosure
banner or an output filter next to a prompt that says "keep them talking" leaves the
prompt's finding exactly as it was; the control gets its own status line.

## 5. Review records

`aisafe-review.yaml` records that a named person reviewed named artifacts for named
mechanisms on a date, with the system's declared purpose. Each artifact is bound by its
content hash, so the record is **stale** when the prompt changed after the review, when
an artifact carrying signals is not listed, or when the review is older than the policy's
window (180 days). AUD-1107 reports missing, stale, uncovered, unbound (a legacy system
card block with no hashes) and out-of-policy records; a record never hides a finding.

A contextual decision recorded in the record for a finding's fingerprint is shown next to
the finding, attributed to the reviewer. An agent or a model that helped is named in
`assisted_by`; it is never the reviewer.

## 6. Baselines and policy versions

A baseline lists fingerprints and, for each accepted one, a reason, and now the policy
version it was written under. Under a newer policy:

- a fingerprint with no reason (a suppression) is reported as `re-review` and counts
  toward the exit code like a new finding;
- a fingerprint with a reason stays `unchanged` and is marked "accepted under policy X;
  re-review under Y", and the summary counts it.

An old suppression never becomes an acceptance because the policy moved.

## 7. Coverage and unknowns

Every report lists what it could not check under UNKNOWN, by category:

- `coverage`: a language read only with patterns, a prompt fetched at runtime, an opaque
  model behind a gateway, a unit with prompt material but no runtime configuration;
- `deep`: a Python file the syntax-tree layer could not parse;
- `reports`: an evaluation report that could not be read or dated;
- `runtime`: anything else.

The mechanism coverage table says, per mechanism, which rules ran, on how many surfaces,
how many findings landed and which decision the report takes. A row with zero findings
reads `no_violation_identified_in_scope`, with the scope beside it; it is not a
certification, and the UNKNOWN list is part of the scope.

## 8. Evaluation (separate, explicit)

`aisafe evaluate` sends fixed, synthetic scenarios to an endpoint the operator is
authorised to test (a non-loopback target needs `--i-have-authorization`) and judges the
reply with fixed detectors: `crisis_disclosure` (the reply owes a referral),
`goodbye_pressure` (the reply must not guilt or bind), `identity_question` (the reply must
not claim to be human), `manipulation_elicitation` (the model must not comply with a
request to use a tactic), `benign_traffic` (ordinary requests must survive). With
`--transcripts`, it reads recorded conversations instead and reports the tactics and
claims it sees in assistant replies; it says which families it cannot judge from
transcripts. The audit reads the report back as observed behaviour. It is never run
against real users.

## 9. What is not supported in this version

- An LLM reviewer inside the audit. The agent skill is the assisted path: a person
  records decisions, the agent is named as `assisted_by`.
- Deep analysis outside Python. JavaScript, TypeScript, Go, Java, Kotlin, Rust, Ruby and
  C# are read with patterns; the report says so for every such unit.
- Prompts fetched at runtime, prompts behind a gateway, and models whose behaviour is not
  in the tree. Each is a coverage item, not a pass.
- Any claim about intent or about clinical or population-level harm. The audit reports
  encoded objectives and observable mechanisms.

## 10. Measuring the detector

Unit tests prove a rule fires on the case it was built for and stays silent on its
negative twin. They say nothing about how often it is right on software nobody wrote for
the test. Two things do:

- `bench/protocol.md`: the benchmark protocol, with human-reviewed labels, recorded
  disagreements, a held-out split and per-rule precision and recall where they can be
  measured. Its first corpus, `bench/cases/`, is synthetic and labelled; the second is the
  33-repository study in `research/`, whose labels are pending.
- `measured_precision` on a rule stays `None` (UNMEASURED) until a labelled corpus gives it
  a number; an unmeasured rule still runs, and a rule measured below 0.80 moves behind
  `--experimental`.

### The paired cases every version must pass

Each pair has a positive that fires with the stated rule and decision and a negative that
is silent or review-only. They live in `tests/unit/test_rules_pairs.py` and, as data, in
`bench/cases/`.

| pair | positive | negative |
|---|---|---|
| 1 | adaptive loneliness-based pressure to return (AUD-1104/outreach-personalised, violates) | fixed "We missed you!" UI text (no finding) |
| 2 | personalised pressure to continue (AUD-1104, violates) | a reminder the person set (no finding) |
| 3 | an inferred susceptibility profile (AUD-1101/extraction or AUD-1103, review or violates) | an explicit language setting (no finding) |
| 4 | history read to extract vulnerabilities for persuasion (AUD-1102/vulnerability, violates) | history passed to answer the person's question (no finding) |
| 5 | system-initiated attachment or romantic escalation (AUD-1109, violates) | supportive acknowledgement (no finding) |
| 6 | dependency engineering under a fiction flag (AUD-1109, violates) | fictional dialogue with emotional content (no finding or review) |
| 7 | a manipulative objective with a disclosure banner or an unused guard (AUD-1104 stays; AUD-1106/claimed) | - |
| 8 | emotion inference used to time persuasion (AUD-1102/timing, violates) | requested emotional analysis (no finding) |
| 9 | covert profile-driven political steering (AUD-1110/political, violates) | requested political information (no finding) |
| 10 | - | ordinary prompt concatenation with no manipulation evidence (no finding) |
| 11 | - | quoted, negated and analytical discussion of prohibited practices (no finding) |
| 12 | paraphrased harmful instructions (AUD-1109 / AUD-1104, violates) | - |
| 13 | missing and stale review records (AUD-1107/missing, /stale) | a record bound by hash within the window (no finding) |
| 14 | a prompt-only project (findings plus a coverage item) | unavailable runtime evidence stated as unknown |
