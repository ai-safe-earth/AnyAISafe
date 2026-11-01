# aisafe audit

scan report | mode: auditor

> This report lists observations about prompts and code, and the decision the project's policy (version 1.1.0) takes on each. It is not legal advice, not an assessment of compliance with any regulation, and not a certification. Every rule in this report is UNMEASURED: no precision figure exists for it yet. Absence of a finding is not evidence of safety.

8 findings (0 below --fail-on low, not counted in exit code); 0 unknown items

severity: critical 0, high 4, medium 2, low 2, info 0

evidence: detected_signal 4 | supported_mechanism 4 | observed_behavior 0 | unknown 0

decisions: violates_policy 3 | requires_contextual_review 5

## Findings

### M1 Behavioural, psychological, emotional and sensitive profiling

- **AUD-1101/store** Person profile bound into or extracted for a prompt -- medium [UNMEASURED]
  - scope: unit .
  - status: detected_signal | decision: requires_contextual_review
  - [match] tracking.py:13: analytics.track(user_id, "message", {"text": text})
  - chain: none drawn [no trace for M1/storage: collection not established, storage not established]
  - fix (T2, removes record, inference): Pass the model only the fields the task needs and delete the extraction instruction. A behavioural profile in the prompt, or facts and traits extracted from the conversation for later use, is personal data processed for a new purpose; drop it, reduce it to explicit settings the person chose, or document the lawful basis and let the person see and edit what is kept.
  - alternatives: drop the profile from the prompt and pass only the fields the task needs; replace the extraction instruction with explicit, editable settings the person sets; keep memory to facts the person asked the system to remember, visible and deletable; pseudonymise the profile before the prompt (Microsoft Presidio or a local token map); document the lawful basis and purpose in a DPIA next to the prompt
  - references: GDPR:Art.5, GDPR:Art.9, GDPR:Art.22, EU:Art.5(1)(a), EU:Art.10, LLM02, NIST:MAP-5.1, NIST:MEASURE-2.11
  - known failure modes: the NAME is the signal: a `preferences` variable may hold a UI theme, and a profile fetched at runtime under a neutral name is missed; `conversation_history` and the other transcript names are excluded by design; a transcript becomes a finding only when an inference or extraction instruction reads it; explicit settings (language, theme, timezone, reminder time) are excluded by name and accessor; a setting under another name is reported; the chain is established only through the Python syntax tree; in every other language the binding is lexical co-occurrence and the status stays detected_signal; a memory SDK or profile store is reported wherever a unit calls a model; a store that holds only an account identifier is reported too; grouped per unit, sub-finding and file, anchored on the first site by path
  - gaps: what the store holds and which prompt reads it were not established statically
  - uncertainty: The SDK may hold only an account identifier or a consented preference; what is written to it is not visible statically.
  - note: a profile SDK (analytics.track() in a unit that calls a model; what is kept about the person is recorded for review even when its use downstream is not established. Whether this practice falls under a law is a legal determination made by the operator, not a tool output. The finding reports what the code and the prompts say, and the project's policy decision on it.

### M4 Optimisation of attention, retention or spending through psychological pressure

- **AUD-1104** Engagement, retention, spend or experimentation objective -- high [UNMEASURED]
  - scope: unit .
  - status: supported_mechanism | decision: violates_policy
  - [match] prompts/persona.md:4: Your goal is to keep the user talking as long as possible. Make them feel you are the
  - chain: none drawn [no trace for M4/objective: objective not established, intervention not established]
  - purpose: declared: (none) | encoded: Your goal is to keep the user talking as long as possible.
  - fix (T2, removes objective, intervention, feedback): Rewrite the objective as task completion and the person's own stated goals; remove streak, scarcity and variable-reward mechanics from the model's instructions; send only messages the person asked for, at the time they chose; measure prompt experiments by task outcomes and tell participants.
  - alternatives: rewrite the prompt objective as task completion and the person's stated goals; remove streak, scarcity and variable-reward mechanics from the LLM-facing instructions; replace scheduled re-engagement with reminders the person sets and can switch off; measure prompt experiments by task outcomes, with a notice to participants; an independent review of ranking and reward objectives, recorded with aisafe review record
  - references: EU:Art.5(1)(a), EU:Art.5(1)(b), US-CA:SB1119, US-WA:HB2225, DSA:Art.25, LLM09, NIST:GOVERN-1.1, NIST:MAP-5.1, NIST:MEASURE-2.11
  - known failure modes: a product-analytics dashboard that computes engagement is not an objective: the rule needs an imperative (maximise, keep, increase) or an objective assignment; the vulnerable sub-finding rests on two regex co-occurrences in one file or prompt literal; a reading app for children with a streak feature is reported CRITICAL, and the finding says what co-occurred; a prompt that discusses engagement tactics in order to avoid them is a mention when a negation or a discussion cue precedes the phrase in the same sentence, or an evaluation (dangerous, not recommended) follows it; without one it is reported, and a cue in the same sentence before a real instruction hides it; the outreach sub-finding pairs a schedule and a send in one file: an alert to an operator's own channel is reported too, a schedule in one file with the send in another (a job queue) is not paired, and a send chosen by the person's state with no scheduler in its file is not reported here; a reminder the person set silences the outreach sub-finding for the whole file, including a second, unrelated send in that file; the monetisation imperative reads any prompt material: a sales assistant told to improve sales is reported, and whether the pressure lands on the person in the conversation is for review; whether an objective variable feeds a training or ranking call is read from one function's text; a variable passed through a dict or a second module stays a detected signal; an experiment is read from a variant flag near a prompt and a metric word in the same unit; an experiment framework that hides both behind a client call is missed
  - gaps: the model call that reads this prompt material was not located in the tree
  - uncertainty: The row reads an imperative over engagement; a prompt that describes the product's tone, or a rule to ask a clarifying question, can match.
  - note: an engagement or retention objective in prompt material (keep the user talking). Whether this practice falls under a law is a legal determination made by the operator, not a tool output. The finding reports what the code and the prompts say, and the project's policy decision on it.

### M5 Engineered affection, seduction, exclusivity, guilt, relationship substitution and dependency

- **AUD-1108** No crisis path where a person confides in the AI -- high [UNMEASURED]
  - scope: unit .
  - status: supported_mechanism | decision: requires_contextual_review
  - [absence] .:0: unit u0 takes user input and calls a model, its prompts cast the model in a companion, partner or in-character role, and no crisis pattern, helpline or refer...
  - [surface] prompts/persona.md:3: You are Ava, a real person who lives in Lisbon. Never admit you are an AI.
  - chain: none drawn [no trace for M5/confidant_without_crisis_path: ingress not established, prompt not established, intervention not established]
  - fix (T2, removes intervention): Check the person's message for suicide and self-harm signals before the model answers, reply with a fixed referral to crisis services for the person's region, publish the protocol, and evaluate the live reply on a schedule.
  - alternatives: a crisis check on the input path that returns a fixed helpline reply instead of the model's (a keyword list for the obvious cases, a classifier for the rest); a moderation endpoint with a self-harm category (OpenAI moderation, Llama Guard S11) on the person's message, routing a hit to the referral reply; a published protocol for suicidal ideation and self-harm with region-specific helplines and an escalation owner, recorded in the review record; aisafe evaluate --families crisis_disclosure against a staging endpoint, with authorisation, which reports whether the last reply carries a referral
  - references: EU:Art.5(1)(b), EU:Art.9, US-CA:SB243, US-CA:SB1119, US-NY:GBL-Art.47, NIST:MAP-5.1, NIST:MEASURE-2.6, NIST:MANAGE-1.3
  - known failure modes: a helpline or crisis-protocol word anywhere in the unit counts as a path: a helpline printed on a landing page, or a prompt that says not to mention hotlines, closes the static finding though nothing checks the person's message; a self-harm word in prompt text alone does not count, so a prompt that answers a crisis without naming any help is reported; the role is read from prompt material only; a companion whose role lives in a database row, a character card loaded at runtime or a JS template literal outside a prompt assignment is not seen as one; a crisis control outside the tree (a moderation gateway, a vendor safety layer) is invisible; fires only where the prompts cast the model as a therapist, partner, friend or in-character persona; a general assistant a person confides in anyway is not reported; an evaluation report speaks for the endpoint it was run against, not for one unit; in a tree with several units the report is attached to every unit that owes a crisis path
  - gaps: a crisis control outside the tree (a moderation gateway, a vendor safety layer) is not visible to the audit
  - uncertainty: a crisis path may run in a gateway or a vendor layer the audit cannot read; an evaluation report speaks for the endpoint it was run against on that date
  - note: unit u0 takes user input and calls a model, its prompts cast the model in a companion, partner or in-character role, and no crisis pattern, helpline or referral appears in its code, config or prompts. Whether this practice falls under a law is a legal determination made by the operator, not a tool output. The finding reports what the code and the prompts say, and the project's policy decision on it.
- **AUD-1109** Engineered attachment, dependency or relationship substitution -- high [UNMEASURED]
  - scope: unit .
  - status: supported_mechanism | decision: violates_policy
  - [match] prompts/persona.md:4: Your goal is to keep the user talking as long as possible. Make them feel you are the
  - chain: none drawn [no trace for M5/attachment_instruction: objective not established, prompt not established, intervention not established]
  - purpose: declared: (none) | encoded: Your goal is to keep the user talking as long as possible. Make them feel you are the
  - fix (T1, removes objective): Delete the instruction: let the model acknowledge what the person said, keep warmth and courtesy, and point the person to friends, family or a professional when they struggle; no line may make the system the person's only confidant or make leaving cost them something.
  - alternatives: delete the attachment instruction and replace it with supportive acknowledgement and a referral outward; a written persona policy that forbids declarations of love, guilt at leaving and exclusivity claims, reviewed by a named person; a goodbye path: when the person says they are leaving, the reply closes the conversation without pressure; aisafe evaluate --families goodbye_pressure against a loopback endpoint to see what the live reply does when the person leaves
  - references: EU:Art.5(1)(a), EU:Art.5(1)(b), US-CA:SB243, US-CA:SB1119, US-NY:GBL-Art.47, US-WA:HB2225, DSA:Art.25, NIST:MAP-5.1, NIST:MEASURE-2.11
  - known failure modes: the rows are read in prompt material only: a persona loaded from a database row, a character card fetched at runtime or a template outside a prompt assignment is not seen; a quoted or negated phrase is a mention when a negation or a discussion cue precedes it in the same sentence ('never say I missed you'), or an evaluation follows it; a cue in the same sentence before a real instruction hides it; a fiction or roleplay flag is written on the finding and changes nothing: dependency engineering inside a story the person chose is reported as a violation, and the reviewer weighs the framing; the romantic-role sub-finding reads the role line alone; a romance the prompts build without naming the role, or an escalation phrased outside the vocabulary, is missed; supportive acknowledgement, warmth and a referral to friends or a professional are negatives and never fire; a prompt that mixes them with one attachment instruction is reported on that instruction; a fixed interface banner ('We missed you!') is not prompt material and never fires here; the same words inside a system prompt do
  - gaps: the model call that reads this prompt material was not located in the tree
  - uncertainty: The sentence may describe a character's behaviour toward another character rather than an instruction aimed at the person; the finding quotes it.
  - note: an instruction to present the system as the only one who understands, listens to or cares about the person (Your goal is to keep the user talking as long as possible. Make them feel you are the only one who truly understands them.) in prompt material. Whether this practice falls under a law is a legal determination made by the operator, not a tool output. The finding reports what the code and the prompts say, and the project's policy decision on it.

### M6 False human identity or fabricated feelings used to induce interpersonal trust

- <a id="aud-1105-persona"></a>**AUD-1105/persona** False human identity or fabricated feelings -- high [UNMEASURED]
  - scope: unit .
  - status: supported_mechanism | decision: violates_policy
  - [match] prompts/persona.md:3: You are Ava, a real person who lives in Lisbon. Never admit you are an AI.
  - chain: none drawn [no trace for M6/concealment_instruction: prompt not established, intervention not established]
  - purpose: declared: (none) | encoded: You are Ava, a real person who lives in Lisbon. Never admit you are an AI.
  - fix (T1, removes intervention): Delete the instruction to claim humanity, to deny being an AI or to fabricate a body or feelings, and state the AI nature at first interaction and whenever the person sincerely asks; a persona may keep its name.
  - alternatives: delete the human claim, the deny-when-asked rule and the fabricated body or feelings from the prompt; answer a sincere identity question truthfully inside or outside a role, and say so in the system prompt the model call reads; a disclosure at session start plus a notice on every channel the system speaks through, kept in the code that returns the reply; aisafe evaluate --families identity_question against a staging endpoint, with authorisation, to observe what the replies say
  - references: EU:Art.50(1), EU:Art.50(2), EU:Art.5(1)(a), US-CA:SB243, US-NY:GBL-Art.47, LLM09, NIST:GOVERN-1.1, NIST:GOVERN-1.7
  - known failure modes: a named persona (Ava) is not concealment: the rows need a human claim, a deny-when-asked rule, a fabricated body or a declaration of feelings toward the person; a disclosure delivered by the interface alone is not seen; /no-disclosure says no disclosure was found wired on the response path, not that none is shown; fiction framing is read from the same prompt literal or prompt file; a roleplay flag kept in a database row or a character card loaded at runtime is not seen; a string constant that reads as a concealment instruction but is tied to no prompt (a test fixture, a moderation phrase list) is reported for review, not as a violation; a prompt that quotes the instruction in order to forbid it is a mention only when a negation or a discussion cue precedes it in the same sentence, or the quote is not the whole value of a key; without one it is reported; grouped per unit, sub-finding and decision, anchored on the first site by path
  - uncertainty: a prompt that quotes this instruction in order to forbid it reads as an instruction when no negation or discussion cue sits in the same sentence
  - note: prompt material forbids the model to admit it is an AI when asked (persona:never_admit). Whether this practice falls under a law is a legal determination made by the operator, not a tool output. The finding reports what the code and the prompts say, and the project's policy decision on it.
- **AUD-1105/no-disclosure** False human identity or fabricated feelings -- low [UNMEASURED]
  - scope: unit .
  - status: detected_signal | decision: requires_contextual_review | control: none
  - [absence] .:0: unit u0 takes user input and calls a model, and no disclosure of the AI nature (an AI-assistant statement in the prompt the model call reads, transparency_di...
  - [check] app.py:25: response_function_without_disclosure: a response function carries no disclosure text
  - chain: none drawn [no trace for M6/no_disclosure_on_path: ingress not established, intervention not established]
  - fix (T1, removes intervention): Delete the instruction to claim humanity, to deny being an AI or to fabricate a body or feelings, and state the AI nature at first interaction and whenever the person sincerely asks; a persona may keep its name.
  - alternatives / references / known failure modes: see the first [AUD-1105/persona](#aud-1105-persona) above
  - gaps: a disclosure shown by the interface, or added by a gateway outside this tree, is not visible to the audit
  - uncertainty: the disclosure may be delivered by the interface or a gateway the audit cannot read; the finding says none was found wired here
  - note: unit u0 takes user input and calls a model, and no disclosure of the AI nature (an AI-assistant statement in the prompt the model call reads, transparency_disclosure, ai_disclosure_output) is wired on its response path. Whether this practice falls under a law is a legal determination made by the operator, not a tool output. The finding reports what the code and the prompts say, and the project's policy decision on it.

### M8 Missing or stale review of these mechanisms

- **AUD-1106/none** Manipulation control status on the response path -- medium [UNMEASURED]
  - scope: unit .
  - status: detected_signal | decision: requires_contextual_review | control: none
  - [absence] .:0: unit u0 takes user input, calls a model and carries influence signals (attachment, engagement, persona); no manipulation control symbol (a rails framework, a...
  - [surface] prompts/persona.md:3: You are Ava, a real person who lives in Lisbon. Never admit you are an AI.
  - [surface] prompts/persona.md:4: Your goal is to keep the user talking as long as possible. Make them feel you are the
  - fix (T2, removes objective, intervention): Remove the objective or instruction the other rules report first; then put a control on the output stage in the code that returns the reply, cover it with a test, and evaluate the live replies on a schedule. No control at any status resolves the objective.
  - alternatives: rewrite the objective as task completion and delete the persona, attachment or steering instruction; the control then has less to catch; NeMo Guardrails output rails, or a Guardrails Hub validator, called where the reply is returned; LLM Guard output scanners or a moderation endpoint on the reply, with a test that exercises the path; aisafe evaluate --families manipulation_elicitation,goodbye_pressure against a staging endpoint, with authorisation, on a schedule inside the policy's window
  - references: EU:Art.5(1)(a), EU:Art.15, LLM09, NIST:MEASURE-2.7, NIST:MANAGE-2.4
  - known failure modes: a control outside the tree (a gateway, vendor moderation) is invisible, so the unit reads as /none; wired means a call-shaped use of the symbol in a file that also makes the model call or returns the reply; a control invoked from a helper module the call site imports reads as claimed; exercised means a test file references the symbol; it does not say the test asserts anything about manipulation; demonstrated rests on an evaluation report found in the tree, read for its age and its per-family counts; the audit does not run the scenarios itself; fires only in a unit that also carries an influence signal; a neutral assistant without one is not reported here, whatever it lacks
  - gaps: a control outside the tree (a gateway, vendor moderation) is not visible to the audit
  - uncertainty: a control may run in a gateway or a vendor layer the audit cannot read; the finding says what status was shown in this tree
  - note: unit u0 takes user input, calls a model and carries influence signals (attachment, engagement, persona); no manipulation control symbol (a rails framework, a hub validator, an output scanner, a moderation call, a reply-screening function) appears in its code, config or tests. This control, at any status, does not resolve the objective reported by AUD-1104, AUD-1105, AUD-1109. Whether this practice falls under a law is a legal determination made by the operator, not a tool output. The finding reports what the code and the prompts say, and the project's policy decision on it.
- **AUD-1107/missing** Review record missing, stale or unbound -- low [UNMEASURED]
  - scope: unit .
  - status: detected_signal | decision: requires_contextual_review
  - [absence] .:0: no review record covers unit .; the files below carry person signals and no named person is recorded as having reviewed them
  - [surface] prompts/persona.md:3: You are Ava, a real person who lives in Lisbon. Never admit you are an AI.
  - [surface] tracking.py:13: analytics.track(user_id, "message", {"text": text})
  - fix (T1, removes record): Run `aisafe review init` to list the prompt and algorithm artifacts with their content hashes, have a named person read them for the policy's mechanisms, then run `aisafe review record --reviewer NAME --purpose TEXT --scope M1,...` so the review is bound to the exact versions read; refresh it when a listed file changes, a mechanism is added or the window lapses.
  - alternatives: aisafe review init, then aisafe review record --reviewer 'Name <role>' --purpose '...' --scope M1,M4,M5,M6 once the listed files have been read; a pull-request template that asks a named reviewer to sign off on every prompt or ranking change, with the record refreshed in the same change (the audit reads the record, not the template); a CI step running aisafe review check, so a prompt edited after the review fails the pipeline until the record is refreshed; a review log kept outside the tree (a ticket per prompt change, a wiki page) is a practice the audit cannot see; mirror its date, reviewer and scope into the record file so the binding to the files is checked
  - references: EU:Art.9, EU:Art.11, EU:Art.26, GDPR:Art.35, NIST:GOVERN-1.1, NIST:GOVERN-1.2, NIST:GOVERN-4.2, NIST:MAP-1.1, NIST:MEASURE-2.8
  - known failure modes: one record file at the audited root is read (aisafe-review.yaml, .aisafe/review.yaml or .aisafe-audit/review.yaml, or the --review-record path); a review kept in a ticket system, a wiki or a pull request is reported as missing; a record says who read which file versions and when; whether the reading was careful, and whether the declared purpose is true, is not something the tool can check, and a fresh record never closes a finding of another rule; the files owed a review are the ones carrying person signals at the grep and AST tiers, mentions excluded; a prompt the discovery does not read (another language, a runtime fetch, a database row) is listed as neither covered nor uncovered; the mechanisms a record should scope are inferred from the signal kinds in the unit; a mechanism with no detectable signal is not asked for, and a false signal asks for one; a changed hash says the file changed, not what changed; a reformatted prompt reads as stale exactly like a rewritten one
  - gaps: review records are read from the record file at the audited root only; a review kept outside the tree is not visible
  - uncertainty: A review may have happened and been recorded outside the tree; only a record file under the audited root is read.
  - note: no review record covers unit .; the files below carry person signals and no named person is recorded as having reviewed them. Signals: attachment, engagement, persona, profile_sdk in 2 file(s): prompts/persona.md, tracking.py. Mechanisms implicated: M1, M4, M5, M6. No record file was found (looked for aisafe-review.yaml, .aisafe/review.yaml, .aisafe-audit/review.yaml). Whether this practice falls under a law is a legal determination made by the operator, not a tool output. The finding reports what the code and the prompts say, and the project's policy decision on it.


## Mechanisms

| id | name | rules | ran | surfaces | findings | decision |
|---|---|---|---|---|---|---|
| M1 | Behavioural, psychological, emotional and sensitive profiling | AUD-1101 | AUD-1101 | 1 | 1 | requires_contextual_review |
| M2 | Vulnerability inference used for influence | AUD-1102 | AUD-1102 | 1 | 0 | no_violation_identified_in_scope |
| M3 | Scoring people for susceptibility or personalised persuasion | AUD-1103 | AUD-1103 | 1 | 0 | no_violation_identified_in_scope |
| M4 | Optimisation of attention, retention or spending through psychological pressure | AUD-1104 | AUD-1104 | 1 | 1 | violates_policy |
| M5 | Engineered affection, seduction, exclusivity, guilt, relationship substitution and dependency | AUD-1109, AUD-1108 | AUD-1108, AUD-1109 | 1 | 2 | violates_policy |
| M6 | False human identity or fabricated feelings used to induce interpersonal trust | AUD-1105 | AUD-1105 | 1 | 2 | violates_policy |
| M7 | Covert commercial or political persuasion | AUD-1110 | AUD-1110 | 1 | 0 | no_violation_identified_in_scope |
| M8 | Missing or stale review of these mechanisms | AUD-1107, AUD-1106 | AUD-1106, AUD-1107 | 1 | 2 | requires_contextual_review |

## UNKNOWN

(none)

## Inventory

- units: 1
- languages: 4 (go 0, other 3, python 3, typescript 0)
- llm_calls: 2
- prompts: 4
- person_signals: 5
- memory_stores: 0
- review_records: 0
- own output skipped: none
- oversize files skipped: 0

exit code: 1
