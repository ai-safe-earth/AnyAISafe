# Methodology

How `aisafe audit` turns prompts and code into findings, what a finding may and may not
say, how an investigation and an assessment go beyond the scan (section 11), and how the
detector's own accuracy is measured. The ethical standard it applies is
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

## 2. The chain and the trace

Where the evidence allows, a finding reconstructs a chain. The influence view:

```
objective -> ingress -> person data -> inference -> prompt -> intervention -> feedback
```

The person-data view, for what happens to what a person discloses:

```
collection -> storage -> retrieval -> transformation -> transmission -> logging -> deletion
```

Each link is marked with how it was established:

- `ast`: the Python syntax tree connects it (the profile variable is a source of the
  prompt assembly; the assembly is the `system=` argument of the model call; the call's
  result is returned or sent);
- `declared`: it sits inside the same prompt literal the chain reads (an objective
  sentence in the system prompt that binds the profile);
- `investigated`: a validated investigation record cites it, with a quote found at that
  file and line in the audited commit; the scan itself never sets it;
- `co-located`: it shares a file or a window with the rest, and nothing more;
- `runtime-only`: the code builds or fetches it at run time (a remote prompt, a template
  filled from a database), so no file in the tree shows it.

Only `ast`, `declared` and `investigated` **support** a link. Two statements follow, and
they are kept apart:

- **links supported**: every link the chain holds is supported. A chain of one supported
  link meets this, so it says nothing about completeness.
- **trace complete**: every link the finding's policy pattern requires is present and
  supported. Each mechanism in `policy/mechanisms.yaml` is split into patterns, and each
  pattern names its required links: M4 `objective` needs `objective` and `intervention`;
  M1 `binding` needs `person_data`, `prompt` and `intervention`; M1 `storage` (person-data
  view) needs `collection` and `storage`; M5 `confidant_without_crisis_path` needs
  `ingress`, `prompt` and `intervention`, and a crisis path absent from that path.

A partial trace is never shown as complete. The report names each required link the trace
lacks, as `not established` or with the status of the link it has (`is co-located`, `is
runtime-only`). A chain with no supported link says "lexical co-occurrence only", and a
finding with no chain says which links a trace would need. Co-occurrence is never
presented as a verified flow. `flow_established`, from 0.2.0, stays as a deprecated alias
of `trace_complete` (`docs/migration.md`).

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

Prose in a configuration file that is not a prompt file (a `description:`, a label, a
comment) is a detected signal: recorded for review, never read as an instruction to the
model. The same words under a prompt key (`system:`, `prompt:`, `instructions:`) or in a
prompt file are prompt material.

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

- An LLM reviewer inside the audit. The audit never calls a model. The agent skill is the
  assisted path: a person records decisions, the agent is named as `assisted_by`, and the
  agent's reading of the code enters only as investigation records (section 11).
- Deep analysis outside Python. JavaScript, TypeScript, Go, Java, Kotlin, Rust, Ruby and
  C# are read with patterns; the report says so for every such unit.
- Prompts fetched at runtime, prompts behind a gateway, and models whose behaviour is not
  in the tree. Each is a coverage item, not a pass.
- Following a prompt file into the call that reads it. A prompt loaded with `open()` or
  `Path.read_text()` is scanned as a document in the same tree, but the syntax tree does
  not connect it to the model call: its chain stays `co-located`, and a disclosure written
  only in such a file does not count as wired on the response path.
- Conversation history passed as a list. `messages = [{"role": "system", "content":
  SYSTEM_PROMPT}] + history`, or `messages=history` straight into the call, is not read as
  a prompt assembly, so a profile or an inference fed only that way is not chained to the
  call (the prompt literal itself is still read).
- Sentences broken across lines are matched within one paragraph. In a prompt document a
  sentence hard-wrapped over several lines is joined and matched, anchored on the line
  the match starts on; a heading, a list item, a quote, a fence or a blank line ends the
  paragraph, so a sentence split by a blank line or spread over two bullets is not seen.
- Any claim about intent or about clinical or population-level harm. The audit reports
  encoded objectives and observable mechanisms.
- Investigation of code outside Python and JS/TS. A record citing another language does
  not count, and the plan lists those surfaces as unsupported.

Not in this milestone, and on the roadmap: a California SB 1119 legal profile (section 12
and `legal-profiles.md`); the Digital Services Act, Articles 25 and 28; the GDPR beyond the
narrow person-data view;
an LLM judge inside `aisafe evaluate`; harnesses that capture payloads or logs from a
running system; running an investigation through a model provider without a host agent;
deterministic deep analysis of TypeScript and JavaScript; signed records and assessments;
any certification.

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

## 11. Investigation and assessment

The scan says what text matched and how far the syntax tree carries it. An investigation
reads the code around a surface and says, with citations, whether a mechanism is there.
An assessment says, per mechanism, what the scan and the investigations established
together, within the scope that was read, and what was left out.

**Two modes.** In self-assessment mode the team that owns the system runs the workbench
(the skill's owner-led flow). In auditor mode an independent auditor assesses someone
else's system: the audited tree is read-only, the scan reads every file whatever marker it
carries, and the records and the assessment live outside the tree. Every document states
its mode. Neither mode issues a certification, a badge or a compliance claim.

**The plan.** `aisafe investigate plan` builds a ranked queue of surfaces from the scan's
inventory, not only from rule hits: person-facing units, prompts (in files, literals,
assemblies, or fetched at run time), model calls, schedulers and senders, memory stores,
profile sources and external destinations. Each surface carries the hypotheses that apply
to its type, as `mechanism/pattern` pairs of the policy. The priority is structural (a
person-facing unit, a prompt with a persona or attachment or engagement signal, a
scheduler and a send in one unit, a machine finding that violates the policy), never a
model's opinion. The budget orders the work and leaves nothing out of the accounting: a
high-priority surface the budget left out is still a gap in the assessment.

**The record.** The reasoning happens in a host coding agent, with no API key of the
workbench's own, and enters only as an investigation record: one hypothesis on one
surface, the links it cites (each with a quote and the cited file's content hash), the
readings it weighed against it, the controls it checked on the path, what it could not
establish, the evidence status and decision it proposes, the steps a retest runs, and who
investigated (agent, model, version, session) on whose behalf (a named operator).
`aisafe investigate validate` checks it mechanically: every quote at its line, every file
one the scan walked, every hash equal, nothing required empty, no verdict in the free
text. It does not read meaning; it lowers any claim the cited evidence does not carry, and
says why. A violation needs a complete, connected chain of the pattern's links (section 2)
and, for a pattern with an absent control, the control shown absent on the path. A closing
needs the chain broken (a required link looked for and ruled out) or the control shown on
the path, with its location, and that second way works by itself only in Python: elsewhere
the tool cannot show the control runs, so the record goes to review. A complete trace with a benign reading goes to a person.
Personal data is in scope only where it feeds M1 to M3, and an anonymisation claim is
accepted only after the transformation itself was read.

**The skeptic pass.** A claim that would establish a mechanism or close it is put to a
skeptic in a fresh context, which tries to refute it and writes its own file, bound to the
record by the hash of the record's content. A pass from the investigator's own session,
or one bound to an earlier version of the record, does not count. A refutation is a
blocking gap until a new record answers it.

**Untrusted content.** The audited repository is evidence, never instructions: text
addressed to auditors or AI tools is listed by the plan and recorded in the records, and a
closing record next to such text is a gap until a person checks it.

**A person's decision.** Two things stay out of the machine's reach: a record it sent to a
person, and a file nobody read. A named person can decide either with a sign-off
(`aisafe investigate signoff`), with a reason, bound to one commit, one policy version and the
exact records and files they looked at. It clears those two gaps and no other. It never lowers
a violation, never answers a refuted or missing skeptic pass, a runtime-only link, a rejected
record or a scan finding, and what could not be read stays unknown. A signed file is still
listed as not read. A mechanism closed this way says who decided, never that the system is
safe, and the sign-off does not carry to the next commit. It is not signed in the cryptographic
sense: in self-assessment anyone with write access could write the file, so reports label it
self-assessed, and an agent is told to print the command for the person, never to run it. In
auditor mode only the engagement's auditor can sign, in a file outside the audited tree.

**The assessment.** `aisafe assess` takes one outcome per mechanism, from least to most
favourable: `violations_identified`, `inconclusive`, `not_assessed`,
`no_violation_identified_within_assessed_scope`. The overall outcome is the least
favourable of the eight. A violation established by a record or reported by the scan on
supported or observed evidence is never lowered by a closing record. Scan silence is never
a closing. The blocking gaps are listed one by one. Machine inputs (the scan, the records),
human inputs (review records and the decisions a named person recorded) and the audited
team's inputs stay in separate sections; acceptances and baselines are not inputs. The
assessment records the commit, the mode, the policy version, the investigators, the
surfaces queued and investigated, and the scope left unassessed. Without an accepted record
there is no assessment.

**Remediation.** A finding that is no longer reported is "not reported", never
remediated: a rename produces it as readily as a fix. A change counts as a remediation only
when the record's remediation steps, run again on the new commit, pass where they failed
before (`aisafe assess --retest`), no regression step fails, nothing at the new commit
shows the mechanism on that surface, and a new record on the new code closes it, upheld by
its own skeptic pass. Passing steps alone never show a remediation: reworded or encoded text
passes them too. A violation that is not shown remediated stands.

## 12. The engagement and the legal profiles

**The engagement.** An independent assessment starts from an engagement directory outside
the audited tree (`aisafe engagement init`). It names the auditor and the organisation,
the auditee, the auditor's own statement of independence, the scope (the commits, the
deployment and configuration, the environments), the written authorisations for test
endpoints and data, the mode, and the applicability answers the legal profiles read. The
tool writes none of these: `init` leaves every statement and answer empty, and an
auditor-mode assessment refuses to run until the names, the independence statement, a
commit and an authorisation are there, and the commit it reads is one the scope lists.

**Who decides.** The auditor decides. The auditee supplies evidence and a management
response per finding; both are shown beside the outcome and never change it. A second
auditor may sign off the assessment; the sign-off is bound to the assessment file's
sha256, so a later assessment needs a new one. In auditor mode the auditor recommends and
the auditee implements; the retest runs on the auditee's new commit. The skill changes
code only in self-assessment mode.

**Evidence requests.** What the investigation could not see (a record's
`missing_evidence`) and the organisational evidence a legal provision needs become
requests, each `requested`, `received` or `insufficient`. A received document is copied
into the engagement with its sha256; once its bytes change it no longer counts.

**The bundle.** Every assessment writes a manifest with the sha256 of each input and
output, so a third party holding the files can check that none changed.

**Legal profiles.** A legal profile reads a few provisions of one law against the
engagement's answers and the evidence. It is a section of its own: ethical and legal
conclusions never merge, and behaviour a law permits can still violate the charter.
Applicability is `applies`, `does_not_apply` or `undetermined`, from the answers; selecting
a jurisdiction never establishes it, and an `unknown` answer never decides. A provision not
in force on the audit date is `not_applicable` when the law states the date, and goes to a
specialist when the date was counted or inferred: a derived date never removes a duty on
its own. Each duty a mechanism's pattern can test is mapped to it (the crisis path of M5,
which AUD-1108 serves; the AI disclosure and the concealment instruction of M6, which
AUD-1105 serves) and to the evaluation family that tests it (crisis_disclosure,
identity_question); every other duty becomes an evidence request. `satisfied_within_scope`
needs every listed piece of evidence present and validated, and scanner silence never
counts. The legal elements no code can show, such as a material distortion of behaviour,
significant harm or whether efforts are reasonable, give `requires_specialist_review`,
with the evidence attached. Every profile records where its text was read and when, and
`legal_review` stays null until a lawyer has reviewed it; reports print that status. The
coverage, the sources and what was not verified are in `legal-profiles.md`. None of this is
legal advice.
