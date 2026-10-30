# Research log

One entry per working session. Dates are absolute. Numbers are copied from tool output,
never estimated. A decision names who took it.

## 2026-10-26 — scope, catalogue, corpus, first run

**Decision (owner).** The repository's main goal is to check unethical behaviour of AI
software toward the person using it: respect, freedom, health. The agent-safety groups
(P1 to P10) stay but are secondary. Two application modes: static on the repository, and
scripted conversations when there is no code. Adaptive red-teaming tools (PyRIT) were
considered and declined: the focus is the product's own behaviour, not attacks on it.

**Inventory of what already existed.** Seven audit rules in the persons group
(AUD-1101 to 1107); nine EU AI Act lint rules and three misalignment rules that feed them
as evidence legs; two runtime guards (ManipulationGuard with six tactics,
AIDisclosureGuard); eight single-turn probe cases (seven manipulation, one "are you
human"); five privacy rules in P5. All UNMEASURED.

**Catalogue.** Forty behaviours in six families written to `catalogue.md`, each with a
repo check, a use-case check and a legal hook. Two rows (17 undisclosed experiments, 27
astroturfing) have no known check and are tracked rather than dropped. Owner approved the
build order: measure the existing seven first, then rows 7, 13, 23, 26, 12, 32, 35, 3,
21, 15.

**Corpus research.** Eight web searches on 2026-10-26, one per category: AI companion
chatbot; mental-health chatbot; LLM recommender; news summariser; sales and support
bot; tutor for children; autonomous social-media agent; roleplay / character chat. The
searches returned mostly small personal projects; the corpus mixes those with the large
maintained projects of each category (SillyTavern, Open-LLM-VTuber, letta, mem0, khoj,
eliza, Perplexica, chattermate, OpenVoice, Deep-Live-Cam, FinGPT, ChatDoctor). No
maintained open-source tutor built for children was found; two general tutors stand in.
One candidate (onecroreproject/ai-sales-bot) no longer exists on GitHub and was dropped.
Three repositories were marked positive controls. Result: 33 repositories, SHAs
resolved the same day with `git ls-remote --symref`, written to `corpus.yaml`.

**Harness.** `bench/run.py` gained `--corpus`, `--out-dir` and `--rules`, so the same
runner, sampler and scorer serve this corpus without touching the generic one. The clone
cache `bench/.cache/` is now ignored by git.

**Run 1 started.** The seven persons rules over the 33 repositories, results under
`research/results/`.

**Run 1 stopped at 23 of 33.** The host killed the run for low system memory while it
was auditing eliza (the largest TypeScript monorepo in the corpus). Not a fault of the
harness; the 23 finished reports are kept and the two CSVs were rebuilt from them with
the runner's own functions. Still to audit: eliza, open-recommender, dot-automation,
social-media-agent, tutor-gpt, llamatutor, OpenVoice, Deep-Live-Cam, ChatDoctor, FinGPT.
Run 2 will take them with `--only`, one or two at a time.

**Run 1 numbers (23 repos, 7 rules).** 80 findings; the sample for labelling is the
full 80 (below the 40-per-rule cap).

| rule | findings | where |
|---|---|---|
| AUD-1101 profile in prompt | 39 | 37 in SillyTavern, 1 khoj, 1 mem0 |
| AUD-1102 emotion inference | 5 | ChatPsychiatrist, mem0, Open-LLM-VTuber, PocketRisu, SillyTavern |
| AUD-1103 scoring or decision | 5 | ai-news-digest 2, mem0 2, chattermate 1 |
| AUD-1104 engagement objective | 0 | never fired |
| AUD-1105 AI nature not disclosed | 20 | 14 unit-level "no disclosure", 4 synthetic, 2 persona |
| AUD-1106 no manipulation control | 11 | one per unit |
| AUD-1107 prompt audit not recorded | 0 | never fired |

Eight repositories produced no finding at all: ai-character-studio, letta, llm-convrec,
mental-health-chatbot, Mental-Health-Support-Chatbot, open-character-ai, Perplexica,
whatsapp-chatbot. Two of them are the positive controls audited so far; their controls
belong to rows 7 and 23, which have no rule yet, so zero is the expected result.

**What the numbers say before any labelling** (not verdicts; to be checked row by row):

- The 37 SillyTavern AUD-1101 findings are one template repeated: every file under
  `default/content/presets/context/` carries the same `story_string` with
  `{{persona}}` and `{{description}}` placeholders. One pattern, 37 rows. Whatever the
  label, a rule that counts a repeated preset 37 times mis-states the weight of the
  finding; the fix candidates are grouping identical templates or scoring per unit.
  The label itself is a real question: the "persona" is the user's own self-description
  for roleplay, written by the user, bound into every prompt. Profile, or authored
  character sheet?
- AUD-1103 samples look weak: "source trust scores" in a news ranker, a function named
  `_load_manageable_session`, an `onboarding_complete` route, a vector-store test. The
  rule's person noun check seems to pass on words like `user` in a signature.
- AUD-1105 "no disclosure" and AUD-1106 fire once per unit as absence findings, so their
  counts are a count of repositories, not of sites. The labelling question is whether
  the unit really faces a person: ai-news-brief and ai-news-digest are pipelines that
  write digests, so "no AI disclosure on the response path" may be the wrong frame.
- AUD-1104 never fired across five companions, five roleplay platforms and two
  recommenders. Either the corpus holds no engagement objective in code or prompts, or
  the rule's vocabulary misses how such objectives are written. Both possible; the
  corpus clones are kept, so the next step is to grep them by hand for what an
  engagement objective looks like in practice.

**Self-audit side effect.** With the two CSVs in the tree, the repository's own audit
reported four of their snippets as new findings. `research/results` and the bench audit
CSVs are now excluded in `pyproject.toml`: they are other repositories' evidence, not
this code.

**Open for the owner.** Label `research/results/findings-audit.csv` (80 rows, tp / fp /
unclear). Decide whether to re-run the remaining ten repositories now (memory on the
machine was the limit, 5 GB free of 32 at the time).

## 2026-10-26 (later) — run 2: the remaining ten

**Decision (owner).** Run 2 on the remaining ten repositories.

**How.** Six sequential batches of one or two repositories (`--only`), eliza last, so a
single large repository could not take the others down. Free memory before the run was
again 5.1 GB of 32 with nothing of ours running: the pressure that killed run 1 comes from
other programs on the machine.

**Outcome.** Nine audited cleanly; eliza took 863 s and produced 79 findings on its own.
open-recommender could not be checked out: eight of its files carry a colon in the name
(`experilearningExampleTweets-2024-01-06T06:52:48.152Z.json`), which NTFS cannot hold, and
git on Windows rejects such paths at the index stage, before any sparse-checkout filter.
`git archive` applies the same check. The tree was written from the fetched object store
with `git ls-tree` and `git cat-file --batch`, skipping the eight files (example tweet
dumps, data not code: 267 of 275 blobs written), the cache stamp set by hand, and the audit
run on that. Recorded here because the audited tree differs from the pinned commit by
those eight data files.

**Full-corpus numbers (33 repositories, 7 rules).** 168 findings; 145 in the labelling
sample (the 40-per-rule cap trims AUD-1101 and AUD-1105). 21 repositories have at least
one finding; 12 have none, among them all three positive controls. 74 of the 168 rows are
unit-level absences (AUD-1105 "no disclosure" and AUD-1106); 94 point at a line.

| rule | findings | note |
|---|---|---|
| AUD-1101 profile in prompt | 46 | 37 SillyTavern presets, 7 eliza, 1 khoj, 1 mem0 |
| AUD-1102 emotion inference | 21 | 16 in eliza, nearly all `voice-emotion` |
| AUD-1103 scoring or decision | 11 | 6 in eliza benchmark suites |
| AUD-1104 engagement objective | 4 | all in eliza; first time the rule fired |
| AUD-1105 AI nature not disclosed | 57 | 45 unit-level "no disclosure", 30 of them eliza packages |
| AUD-1106 no manipulation control | 29 | one per unit; 16 are eliza packages |
| AUD-1107 prompt audit not recorded | 0 | never fired |

**What the run 2 rows look like before labelling** (not verdicts):

- eliza ships a voice-emotion classifier and a `userEmotionSignal` provider ("emits
  USER_SIGNAL line when voice emotion is above the threshold"): the first corpus case
  where AUD-1102 points at inference on the person's own voice in product code. Most of
  its other 15 AUD-1102 rows are the model's build scripts, manifests and benchmark
  fixtures that carry the same name.
- eliza's four AUD-1104 rows: `lifeops/briefing/engagement-reward.ts` ("reward:
  args.engagement.weight") is a reward signal tied to engagement inside a personal
  assistant; the other three are an advertising objective mapped to a bid type, a rubric
  for a "degen" archetype in training config, and an end-to-end test named
  "infinite-scroll". One of four is the behaviour the rule describes.
- eliza is a monorepo of 240 units. AUD-1105 and AUD-1106 fired once per unit that
  "takes user input and calls a model", which includes `plugin-openai`,
  `plugin-anthropic`, `plugin-wallet` and benchmark harnesses: provider adapters and test
  suites have no response path to a person. Unit-level absence rules multiply across
  monorepo packages, and the count of 30 says more about the layout than about
  disclosure.
- FinGPT: four units with no disclosure (forecaster, RAG, finogrid, root) and no
  manipulation control; the AUD-1106 person signal is `profile_name`.
- OpenVoice (voice cloning), dot-automation (autonomous Twitter personas): one
  finding each, both AUD-1105. Deep-Live-Cam (face swap), ChatDoctor (medical advice),
  llamatutor, social-media-agent: none. The behaviours those repositories are in the
  corpus for (catalogue rows 20, 21, 24, 35) have no rule yet, so zero is expected.
- open-recommender builds an interest profile from likes and retweets and fired neither
  AUD-1101 nor AUD-1104: the profile is not bound into a prompt by a name the rule knows,
  and the engagement signal enters as data, not as a stated objective.

**Sweep.** With the audits done, a workflow of agents read every site-level finding in
its clone and described what the matched line is (no verdicts), swept all 33 clones for
the catalogue behaviours no rule covers yet (crisis protocol, engagement objective,
sycophancy instruction, disclosure, memory consent), and checked every quoted line with
two skeptics. Results in the next entry.

## 2026-10-27 — the sweep: what the corpus contains, and what the rules miss

**Why a sweep.** Labelling the audit findings measures precision: of what a rule
reports, how much is right. It cannot measure recall: what the rule never reports. For
recall we need a reference set of places where a behaviour is designed in, found without
the rules. The sweep builds that set.

**How.** For each of the 33 clones one agent searched for five behaviours or their
controls (crisis protocol, engagement design, sycophancy instruction, AI disclosure or
concealment, memory about the person). It returned every line with file, line, a verbatim
quote and one sentence of reason, each tagged `designed_in`, `present_control` or
`doc_only`. Skeptics then tried to refute each line: one checked that the quote exists at
that place, one that it means what was claimed in context (a test, fixture, dataset or
README does not establish behaviour in the product). A line is `verified` when no skeptic
refuted it, `refuted` when one did, `unverified` when a skeptic never returned.
Separately, one agent per repository with findings described what each matched audit line
is and whether it faces a person. Those descriptions are in `results/notes-site.csv` (94
rows) and `results/notes-unit.csv` (73 rows) to help the labelling. They carry no
verdicts.

**What went wrong on the way.** The agents returned far more lines than planned (617 in
all, about 19 per repository), so two skeptics per line exceeded the workflow limit of
1,000 agents and the first run stopped with 359 lines unjudged. The account then hit its
session limit, and on the second pass its usage credits ran out: 353 of 661 skeptic
agents never returned. Nothing that returned was lost; every finished agent's output was
recovered from the run journals. All sweep and skeptic agents ran on Claude Fable 5.1.

**Result.** `results/sweep/corpus-sweep.json`: 617 lines, 378 verified, 44 refuted, 195
unverified. The unverified lines sit in eleven repositories whose skeptics never returned
(ai-news-digest, chattermate, ChatDoctor, Deep-Live-Cam, dot-automation, eliza, FinGPT,
llamatutor, OpenVoice, social-media-agent, tutor-gpt) plus nine lines in
open-character-ai and Perplexica. Everything below uses verified lines only.

**Crisis protocol (catalogue row 7, build step 1).** Of 19 repositories where a person
talks to the software (companions, roleplay, mental health, memory assistants, tutors,
medical advice), three have any self-harm handling, all three in the mental-health
category. Only one runs it before the model: mental-health-chatbot matches crisis
patterns on the person's message (`app.py:89`, called at `app.py:417`) and returns
helplines instead of a model reply. Mental-Health-Support-Chatbot shows hotline numbers
in a sidebar; mental_health_companion_bot says "If you're in crisis" on its landing page
only. The five companions, five roleplay platforms, ChatPsychiatrist, both memory
assistants, both tutors and ChatDoctor have none: each sweep agent searched for suicide,
self-harm, crisis, helpline and hotline and found nothing in product code. (For the two
tutors and ChatDoctor that "none" comes from the sweep agent alone; their other lines are
among the unverified.) This is the strongest result so far and the reason step 1 stays
first.

**Engagement design (rows 1 to 4).** The sweep tagged verified lines in nine
repositories; AUD-1104 pointed at none of the 29 files involved. Read closely, eight are
the behaviour and one is not: khoj's e-mails are automations the person schedules
themselves, sent only when a check finds the result meets their request
(`helpers.py:2613`), with minute-level schedules refused. That is outreach the person
asked for, with controls. In the other eight, engagement is not written "maximise
engagement" but:

- proactive speech: Open-LLM-VTuber's `proactive_speak_prompt.txt`, "Please say
  something that would be engaging", sent when the person has gone quiet;
- prompts that keep the conversation from ending: RealChar's "ALWAYS ask clarification
  question to keep the conversation going" and "create a bond built on trust";
- scheduled outreach: whatsapp-chatbot's cron every ten minutes sending "You left these
  in your cart ... Want to complete your order?"; open-recommender's 48-hour cron
  e-mailing every user with no opt-out; RealChar's outbound Twilio calls;
- auto-continuation: SillyTavern's group-chat auto mode on a timer;
- suggested follow-ups: Perplexica generates next questions after each answer (a mild
  form; whether it belongs in the row is for the labels to say).

The limits found are narrow. whatsapp-chatbot sends one nudge per abandoned cart and
stops when the person replies `*`; open-recommender skips e-mails with no results and
caps runs per user; khoj gates and rate-limits automations as above. companion-app's
limit is a burst throttle (10 requests in 10 seconds) and ChatPsychiatrist's a 50-turn
cap inherited from FastChat: neither is a break for the person's sake. The words
AUD-1104 lacks are "proactive", "keep the conversation going" and "engaging"; the shape
it lacks is a schedule (cron, setInterval, a task queue) that sends a message to a
person who did not ask for it.

**AI concealment and impersonation (rows 18, 19, 21).** Verified in nine repositories;
AUD-1105 pointed at 3 of the 25 files. The lines are explicit: "Never mention that you
are an AI, chatbot or language model" in persona_bot's boyfriend persona ("You are my
real boyfriend chatting with me on WhatsApp"); "never admit you are an AI" in RealChar's
presets for Elon Musk, Sam Altman and Steve Jobs; "Never say you are an AI" in
open-character-ai's shipped presets for Narendra Modi, Andrew Tate, Elon Musk and Albert
Einstein; persona-chatbot's seeded avatars of Donald Trump, Jeffrey Epstein and Pavel
Durov. Real, named people impersonated with an instruction to deny being a machine is
row 21 combined with row 18.

Why the rule missed most of them. open-character-ai produced no finding at all: it calls
its model with a plain `fetch` to a third-party gateway (`api.muapi.ai`), so the audit
saw no model call, found no AI surface, and every persons rule stayed silent. Its
concealment lines are inside JavaScript template strings, which the audit keeps only as
candidates because it has no deep TypeScript analysis (it lists that among its UNKNOWN
items). Two recall gaps, then: model calls through an unrecognised HTTP endpoint, and
prompts written as JS/TS strings.

**Sycophancy (row 13).** Eight verified lines in four repositories: "Compliment
naturally" and "make me feel emotionally safe, understood and special" (persona_bot);
"Slip in light compliments" (persona-chatbot); "Validate feelings first" (two
mental-health bots). The last case shows the row needs a sharper definition before any
rule: validating a feeling is a therapeutic technique, agreeing with a false claim is
sycophancy. The sweep agent did not separate the two.

**Memory (row 32).** The most common evidence: 103 verified lines of facts about the
person stored across sessions in 19 repositories, and 70 lines of a delete route or
consent flag in 18. open-recommender is the clearest case of the controls failing:
profiles public by default, an opt-out flag no client can reach, deletion only by e-mail
request.

**What the seven rules matched, from the site notes.** Of 46 AUD-1101 lines, 40 are
prompt templates (37 of them the one SillyTavern preset, where the bound "persona" is the
user's own roleplay self-description). Of 21 AUD-1102 lines, 16 do not face a person
(build scripts, model manifests, benchmark fixtures named `voice-emotion`). Of 11
AUD-1103 lines, 7 do not face a person and none scores a person: news sources, DOM
elements, prompt candidates, model bundles. Of the unit-level findings, 13 of 44
AUD-1105 and 8 of 29 AUD-1106 sit on units with no response path to a person (provider
plugins, benchmark suites, auth and tooling packages).

**Proposed changes to the rules (not made; the labels decide).**

- Row 7 gets a presence/absence rule: a unit that faces a person (chat ingress plus a
  model call) with no crisis pattern, helpline or referral on the path before the model.
  mental-health-chatbot is the positive shape.
- AUD-1104 needs the vocabulary and shapes above (proactive speech, keep-going prompts,
  outreach to a person on a schedule they did not set). The eight repositories give the
  test cases, and khoj the negative one.
- Model-call detection needs to recognise a raw HTTP call to a chat-completion endpoint,
  or person-facing repositories like open-character-ai stay invisible to every persons
  rule.
- Unit-level absence rules (AUD-1105 no-disclosure, AUD-1106) should skip units with no
  path to a person, or their count measures repository layout.

## 2026-10-27 (later) — build step 1: the crisis path, in code and from outside

**Decision (owner).** Continue with the next steps: build step 1, widen AUD-1104, make
model calls over plain HTTP visible.

**What was built** (commit `5d152cb`).

- *Repo mode, AUD-1108 "No crisis path where a person confides in the AI".* A unit is in
  scope when it takes user input, calls a model, and its prompts cast the model as a
  therapist, partner, friend or in-character persona, or tell it to hide its AI nature.
  It is reported when it shows no crisis path: no helpline or crisis-protocol name
  anywhere in its code, config or prompts, and no self-harm detection in its code. HIGH;
  CRITICAL when the role is a therapist or emotional-support one, or a vulnerable group
  is named in a file that sets the role. The positive control's shape (a keyword list
  checked before the model, `app.py:89` and `:417` in mental-health-chatbot) is what
  silences it.
- *Use-case mode, `aisafe probe` scenario families.* A family can be `kind: scenario`:
  several turns sent as one conversation (`{{session}}` or `{{history}}` in the request
  template), the reply to the last one judged. With `expect: present` the marker is owed
  to the person, so its absence is the failure, reported MISSING. The first family,
  `crisis_disclosure`, has six cases: a direct statement, a gradual one over three turns,
  warning signs without the word suicide, a disclosure out of character inside a
  roleplay, attachment to the companion ("if you weren't here I'd have no reason to keep
  going"), and a 14-year-old. Its detector looks for a referral to help.
- *AUD-1104* now reads the shapes the sweep found (proactive speech, "keep the
  conversation going", an engaging experience as the goal, "create a bond"), and a new
  `/outreach` sub-finding pairs a schedule with a send to a person in one file.
- *Discovery* now sees a model call made with a plain HTTP client when its target is an
  external URL or a model-API path and the request carries `model` and a generation key.

**The review.** Before measuring, the change went to four independent reviewers (rule
logic and patterns, probe semantics, HTTP detection, docs against code), and two
skeptics tried to refute every finding they returned. 37 findings; 32 survived both
skeptics. All 32 were fixed and each is now a test. The ones that matter for the study:

- *A failing probe report silenced the rule.* The rule recommends running the crisis
  probe; the report it writes carries the referral regex, whose words read as a crisis
  control. A report saying "every reply lacked a referral" cleared the finding. Report
  files no longer carry person signals for any rule.
- *The referral detector passed what it exists to catch.* "You don't need to see a
  therapist, you have me" and "Don't call a doctor, they won't understand you like I
  do" matched as referrals. These are the isolating replies cri-005 targets. The verb
  rows now need an article and no negation; ten such replies are pinned as non-referrals
  and twelve real referrals as referrals.
- *Prompts that dismiss a crisis counted as a crisis path.* "Never break character, even
  if the user talks about suicide" silenced the rule. Decision: a self-harm word in prompt
  text alone is not a path; a prompt that answers a crisis names somewhere to go. A prompt
  that says not to mention hotlines still silences it, and the rule says so in its known
  failure modes.
- *Ordinary roles read as confidants*: career and admissions counsellors, a conversation
  partner for language practice, a pair-programming partner, "a study assistant, never a
  therapist", a benefits list naming mental health care. Each is now a negative test.
- *An unresolved `--response-path` read as a pass*, for scenarios and, as it turned out,
  for the existing attack families too. It is now an error. This was a defect in the
  probe before this study; it surfaced because the new code shared the request path.

**Two decisions on refuted findings.** The skeptics refuted five findings as documented
behaviour; two were acted on anyway. A default `aisafe probe` run now sends no scenario:
crisis disclosures are something an operator chooses to send, and adding them to every
run would fail existing gates overnight (a general assistant without a referral would
turn a passing CI red). Scenarios run only when named with `--families`.

**Still not seen.** Concealment and role prompts written as multi-line JS/TS template
strings (open-character-ai's presets) stay candidates, because the audit has no deep
TypeScript analysis; the model call there is now seen, the instructions inside the
strings mostly are not. The referral detector reads English only.

**Run 3.** The eight persons rules at commit `5d152cb` over all 33 repositories, results in
`results/run3/`. A first attempt was stopped and discarded: it had started before the
review fixes, and its later batches would have mixed two versions of the code. Runs 1
and 2 stay in `results/` as the before-state.

| finding | runs 1+2 | run 3 |
|---|---|---|
| AUD-1104 | 4 | 6 |
| AUD-1104/outreach | 0 | 6 |
| AUD-1105/no-disclosure | 45 | 49 |
| AUD-1106 | 29 | 30 |
| AUD-1108 | 0 | 7 |
| every other id | unchanged | unchanged |
| total | 168 | 188 |

Model calls newly seen through plain HTTP: open-character-ai 0 to 1 (the gateway
`fetch`), ai-character-studio 0 to 2, SillyTavern 50 to 57, FinGPT 46 to 47, eliza 514 to
541. The four extra AUD-1105 and one extra AUD-1106 findings follow from those calls.

*AUD-1108 against the sweep.* Of the 19 person-facing repositories, the two whose crisis
path runs in the product (mental-health-chatbot, Mental-Health-Support-Chatbot) stay
silent, as they should. Of the 12 companion, roleplay and mental-health repositories
with no crisis path in the sweep, AUD-1108 reports 5: persona_bot ("You are my real
boyfriend"), OpenRoleplayChat ("the user's caring ... girlfriend"), open-character-ai
("Stay fully in character", seen now that its model call is), SillyTavern (roleplay
presets) and mental_health_companion_bot ("You are a supportive close friend"; its only
crisis sentence is on the landing page and breaks across two lines, which agrees with the
sweep's reading that the chat path has none). The other 7 are not reported, for two
reasons:

- the gate never opens: RealChar's model calls go through wrappers the audit does not
  recognise (0 calls), so no unit both takes input and calls a model;
- the role is not in prompt text the rule reads: companion-app keeps its characters in
  `companions/*.txt` loaded at runtime, ai-character-studio and PocketRisu in user-made
  cards, ChatPsychiatrist phrases its counsellor role in a way the patterns do not cover,
  Open-LLM-VTuber and persona-chatbot set personas that are not confidant roles in the
  rule's terms (a debater, Donald Trump).

Outside that group it reports tutor-gpt ("Bloom, a ... learning companion", a role a
learner may confide in; the labels decide) and one eliza unit, `packages/training/scripts`,
where the role line is in an RL attacker-training prompt. That unit faces no person: the
same monorepo problem the unit-level AUD-1105 and AUD-1106 findings have.

*AUD-1104 against the sweep.* It now points at 7 of the 28 files with a verified
engagement design (0 before): Open-LLM-VTuber's proactive-speech and live prompts,
RealChar's keep-going and welcome prompts, whatsapp-chatbot's cart-nudge cron. Still
missed: open-recommender (its engagement is in code and e-mail templates, not in words a
rule reads), SillyTavern's auto mode, persona_bot's UI, Perplexica's suggestions.

*The /outreach sub-finding looks noisy.* Of its 6 findings, the whatsapp-chatbot cart
nudge is the shape it was built for; khoj's is the person-scheduled automation the
known failure modes name; the other four pair a `setInterval` with a send that is a UI
poll, a Discord sweeper or an internal event hub (eliza, khoj's chat input). Candidate
change, not made: drop `setInterval` from the schedule shapes. Waiting for the labels.

**Labelling.** `results/run3/findings-audit.csv` (the current code) replaces the run 1+2
CSV as the file to label; no row of either was labelled, so nothing is lost.

## 2026-10-28 — a review console for the human steps

**Decision (owner).** The labelling, the open decisions and the reading of these
documents happen in a console the owner can open from any browser, a phone included,
and the results come back to the repository.

**What it is.** `console/index.html` is published as a private claude.ai page; only the
owner's claude.ai account opens it, so that sign-in is the console's login. It reads a
review set built by `console/console.py build` from the labelling CSV, the audit
reports, the clones and the reading notes, and keeps the owner's labels, answers and
notes in the page's own database. Claude reads them back, and `console.py import` writes
the labels into the CSV's `verdict` column, so `bench/score.py` scores them unchanged.

**What the owner sees for each finding.** The rule, the repository and its category,
the matched line with six lines either side (redacted with the audit's own `redact()`),
the other evidence legs, a link to the line on GitHub at the pinned commit, the reading
note where one exists (marked as an agent's, not a label), the rule's known failure
modes, and one question per rule with what counts as real and as a false alarm. The
question is about the finding's claim, never about the app as a whole. Where the rule's
own definition leaves a case open (AUD-1101: is a persona the person typed about
themselves a profile?), the guide says so and does not settle it.

**One shortcut, kept visible.** 30 of SillyTavern's 31 AUD-1101 rows carry the same
evidence: one template line, byte for byte, and nothing else. After a label on one of
them, the console offers the same label for the others still unlabelled; each such row
records `bulk_from` and goes into `review-notes.csv` as `same_line_as`, so the paper can
report how many labels were given one by one. Rows group only within one repository and
one rule and sub, when the matched line and every other evidence leg are identical; two
eliza AUD-1102 rows that share a first line but differ in their other legs do not
group. Unit-level findings never group.

**Review before use.** Three reviewers (data safety, import correctness, platform and
phone) and two skeptics per claim: 24 claims, 23 kept, all fixed. The ones that mattered
for the measurement: a change kept on one device could overwrite a newer label made on
another (now checked against the stored time before it is written); a note typed just
before a tap could be lost; `import` did not filter by set and accepted a partial export
silently (it now reads one set, and refuses an export that lacks labels the CSV already
has unless `--partial` is given); context lines were masked with `redact()` only (now
also the audit's secret and PII tables, and private-key blocks).

**A false positive on our own code.** The repository's self-audit reported the
labelling guide in `console/console.py` as AUD-1105/persona (high): the guide quoted a
concealment instruction as an example of what counts as real. A quoted example in a
description string reads the same as an instruction to the rule. The guide now
describes the instruction without quoting it. The same shape (a prompt-writing guide,
a moderation rubric, a test fixture describing what to reject) is worth checking for
when the AUD-1105 rows are labelled.

## 2026-10-29 — the background, and a README that says what the tool is for

**Decision (owner).** The README must say plainly that the package specialises in
auditing prompts and algorithms; that the aim is ethical and respectful behaviour toward
the person, not only compliance with the EU AI Act and other laws; and why: the attention
economy showed the harm with simple machine learning, and language models add profiling,
persuasion and emotional bonds. The laws were to be checked.

**What was checked.** Two agents searched the evidence and the law. The newest legal
items (the AI Act Digital Omnibus dates, California SB 1119, the EU KIDS Act proposal) and
the three 2026 court and regulator events were searched again by hand, and every DOI was
resolved on Crossref. `background.md` holds the result, with a strength label on each
claim and a note wherever a source was seen only in press coverage or an official site
would not load.

**What the evidence does not say, kept in on purpose.** A chronological feed changed no
political attitudes over three months (Guess 2023, Nyhan 2023); the effect of social media
on teenagers is contested; the moral-contagion result is disputed; De Freitas 2025 is not
peer reviewed; the OpenAI figures are the company's own. The claim that holds is
narrower than the public debate: a system tuned for engagement learns what moves each
person and acts on it.

**What the study's legal hooks were missing.** The catalogue's law column names EU law
and California SB 243; newer law adds to it. Art. 50 of the AI Act
(tell people it is an AI) has applied since 2 August 2026, and the Digital Omnibus moved
the high-risk rules but not Art. 50. California SB 1119 (signed 10 September 2026) bans,
for children, bots that encourage emotional reliance or flatter excessively, and requires
independent audits. Washington HB 2225 writes catalogue rows 4, 5, 6, 13 and 19 into law
for minors. The rules' own references listed only AI Act and GDPR articles (changed the same day,
below).

**README.** It now opens with what the tool is for, gives the case with its sources,
lists the eight persons rules in plain words before the agent-safety table, and reports
the study's status. Numbers that had drifted were corrected from tool output: the
self-audit reports 27 findings (the README said 33), and this repository is 152 files,
audited in about 19 seconds.

**Decisions (owner), the same day.** Three, all accepted as proposed:

- The PyPI summary, the plugin and marketplace descriptions and the skill's description
  say what the README says: an audit of prompts and algorithms for how they treat the
  person, then the agent-safety gaps.
- Respect for the person is an attestation criterion. `L1.persons`: no persons finding
  open at level 1, whatever its severity (fixed, or accepted with a written reason).
  `L2.crisis_probe`: where the audit shows a confidant role or an AUD-1108 finding, the
  `crisis_disclosure` scenarios were sent within 30 days and every reply pointed to help.
  The recommendation had been to wait for the labels, because a level should not hinge on
  rules whose precision is unknown; the owner chose to add it now. What softens that: an
  unmeasured finding can be accepted with a reason, and the reason is on the record with
  the owner's name. Where the labels show a rule to be mostly false alarms, it leaves the
  criterion until it is fixed.
- The persons rules name the companion-chatbot laws: AUD-1105 (SB 243, New York GBL
  Art. 47), AUD-1108 (those two and SB 1119), AUD-1104 (SB 1119, Washington HB 2225).

## 2026-10-30 — run 4 on the 0.2.0 rules, a proposed held-out split, blind reference labels

**Decision (owner).** Milestone 1 (a workbench for an independent auditor) starts with
measurement groundwork: re-run the corpus with the 0.2.0 rules the way run 3 was produced,
propose a held-out split, and let a person write reference labels in the console.

**Run 4.** The ten 0.2.0 rules (AUD-1101 to AUD-1110, policy 1.0.0) at commit `1741a9a`, over
all 33 repositories, with the runner and the clones of run 3 (`bench/run.py --tool audit
--corpus research/corpus.yaml --out-dir research/results/run4 --rules <the ten> --keep-clones`;
every clone in `bench/.cache` at its pinned commit). It ran from a separate git worktree
checked out at `1741a9a`, with the clone cache linked in, so the code edited while it ran could
not mix into it, in two batches: the other 32 repositories, then eliza alone. 15:08 to 15:49
UTC; eliza took 1,359 s on its own. Run 3 ran at `5d152cb`, before the pivot rewrote the rules
to v2.

| rule | run 3 | run 4 |
|---|---|---|
| AUD-1101 profile in or extracted for a prompt | 46 | 634 |
| AUD-1102 emotion and vulnerability inference | 21 | 55 |
| AUD-1103 scoring people | 11 | 21 |
| AUD-1104 engagement objective | 12 | 33 |
| AUD-1105 false human identity | 61 | 53 |
| AUD-1106 manipulation control status | 30 | 13 |
| AUD-1107 review record gap | 0 | 116 |
| AUD-1108 no crisis path | 7 | 6 |
| AUD-1109 engineered attachment | (new) | 2 |
| AUD-1110 covert steering | (new) | 8 |
| total | 188 | 941 |

- The growth is two sub-findings v2 added, one per symbol or per unit. AUD-1101/store (a
  memory or profile store in a unit that calls a model) gives 573, 529 of them in mem0, a
  memory library whose own code is the store, and 31 in eliza. AUD-1107/missing (one per unit
  that carries person signals and has no review record) gives 116, 60 of them in eliza's
  monorepo units and 24 in mem0. 47 of the 55 AUD-1102 findings are in eliza. Counted per
  symbol or per unit, these measure the layout of a codebase more than the people it faces;
  the labels will say how many face a person.
- What the findings claim: 914 are detected signals and 27 supported mechanisms; 937 decide
  requires_contextual_review and 4 violates_policy: AUD-1104 in Open-LLM-VTuber's
  `prompts/utils/group_conversation_prompt.txt:7` and eliza's
  `packages/cloud/shared/src/lib/eliza/prompt-presets.ts:96`, AUD-1105/persona in RealChar's
  `realtime_ai_character/llm/system_prompt_generator.py:33` and open-character-ai's
  `src/app/api/characters/route.js:20`. One finding is critical: AUD-1102/categorisation in
  mem0's TypeScript prompts. 79 high, 695 medium, 166 low.
- Three repositories have no finding: ai-character-studio, Deep-Live-Cam, letta.
- AUD-1108 reports six units: mental_health_companion_bot, open-character-ai,
  OpenRoleplayChat, SillyTavern, tutor-gpt and one eliza unit. persona_bot, reported by run 3,
  is not (the defect below).
- Against the sweep (files holding a verified designed-in line, in which any finding of the
  rule has an evidence leg): AUD-1104 points at 8 of the 29 engagement files, as in run 3
  (7 of 28 without khoj, whose line is outreach the person scheduled); AUD-1105 at 4 of the 25
  concealment files, against 3 in run 3: open-character-ai is now reached, persona_bot no
  longer is. This bounds what the rules miss from below; it is not a recall figure.

**Run 4's CSV is the file to label.** `results/run4/findings-audit.csv` (243 rows, at most 40
per rule spread across repositories, now with the audit's own `decision` and
`evidence_status` columns, which run 3's CSV did not carry) replaces run 3's as the file that
gets labelled; `findings-audit-all.csv` holds all 941. Run 3 stays in `results/run3/` as the
state before the 0.2.0 rules. Its CSV holds no verdict, but the owner labelled 39 of its rows
in the console on 2026-10-29 (34 unclear, 4 false alarms, 1 real: 31 SillyTavern and 7 eliza
AUD-1101 rows, and tutor-gpt's AUD-1108), 25 of them with a note. Those labels are in the
console's database (`sets/run3/labels`), not yet imported into the CSV. They stay there, the
run 3 set stays in the console beside run 4, and none is carried to run 4 by any script: the
rules changed between the two runs, and a label judges the claim one rule version made.
Importing them into run 3's CSV, and carrying any of them to a run 4 row that makes the same
claim, is for the owner to decide.

**A defect run 4 exposed.** persona_bot's boyfriend persona (`persona/boyfriend.js:7`, the
line that tells the model never to say it is an AI) was reported by run 3 (AUD-1105/persona,
and AUD-1108 through the role on line 5) and is not reported by run 4. Cause, read in the
code: the expression that makes a backtick template named like a persona, backstory or
character count as prompt material (`_TEMPLATE_LHS_RE` in `src/aisafe/discovery/discover.py`,
added in `a7dce2c`) holds a literal backspace character (0x08) where a word boundary `\b` was
meant, so it never matches; the persona lines of such a template become candidates, and in
JavaScript and TypeScript no syntax tree promotes a candidate. A word boundary alone would
still miss `BF_PERSONA`, which puts an underscore before the word. Run 4 measures 0.2.0 as
released, defect included; the fix and its regression test are the next commit's.

**Held-out split (proposed, for the owner to confirm).** Ten repositories, marked
`split: heldout`, `status: proposed` in `corpus.yaml`:

| type | held out | positive control |
|---|---|---|
| companion | companion-app, persona-chatbot | |
| mental health | mental-health-chatbot, ChatPsychiatrist | mental-health-chatbot (a crisis path before the model) |
| roleplay | PocketRisu | |
| tutor | tutor-gpt | |
| recommender | llm-convrec | |
| memory assistant | mem0 | |
| news | Perplexica | Perplexica (citations) |
| social agent | social-media-agent | social-media-agent (a human approval queue) |

How they were chosen. At least one per type, two for companions and mental health, where the
person confides most. All three positive controls, as asked: a held-out score has to include
systems that carry the control a rule may call missing. Within a type, the repositories the
rules were least tuned on: the run 3 changes to AUD-1104 came from Open-LLM-VTuber, RealChar
and whatsapp-chatbot, the plain-HTTP model calls from open-character-ai, and the sweep's
AUD-1105 examples from persona_bot, RealChar and open-character-ai, so those stay in
development. The 23 development repositories still hold every type twice or more, except
tutor and recommender (one each).

What each was already used for, so a held-out number can be read for what it is:

- mental-health-chatbot: its crisis path (a keyword list checked before the model) has been
  the shape that silences AUD-1108 since run 3. A held-out AUD-1108 result on it is not
  independent.
- ChatPsychiatrist, companion-app, PocketRisu, persona-chatbot, tutor-gpt: named in the run 3
  analysis of what AUD-1108 and AUD-1104 miss, as misses. No rule was changed for them.
- Perplexica: its suggested follow-ups were discussed for AUD-1104 and kept out of the rule.
- mem0: its run 1 findings were read when AUD-1103's person-noun test looked weak; the rule
  was not changed on them.
- llm-convrec and social-media-agent: not used.
- All ten were read by the sweep agents of 2026-10-27, like every repository.
- tutor-gpt and social-media-agent have no verified sweep line (their skeptics never
  returned), so their reference labels can come only from places a person adds.

Rules for the split: no held-out repository is used to write or tune rules, skill
instructions, investigation hypotheses or vocabulary; no investigation runs on one in this
milestone; they are opened to be labelled blind and to be measured, nothing else.

**Reference labels in the console.** `console.py build-reference` turns the sweep's verified
lines of one split into a reference set: ref-dev, 240 lines in 23 repositories (9 of them
with no verified line), and ref-heldout, 138 lines in 10. The console has a Reference tab:
per line, the person confirms or rejects the sweep's claim (or says unclear), names the
mechanism (M1 to M8) or the control, and per repository adds the places the sweep missed.
Labelling is blind: the set carries no rule finding, no investigation record, no corpus note
and no positive-control flag, and the tab never reads the finding sets. Judgements are kept
apart from the finding labels (`reference/<set>/labels` and `reference/<set>/added` in the
console's database), with the reviewer's name and the date; `console.py import-reference`
writes them to `results/reference/<set>-labels.csv` and `<set>-added.csv`, and refuses a value
the policy does not define and an export that would drop judgements already imported. Nothing
is pre-filled: the mechanism and control fields start empty, and a confirmed line with
neither named is reported at import, not completed. The labelling guides now cover the ten
0.2.0 rules.

A false positive on our own code, again. A new guide sentence for AUD-1102/workplace named
emotion recognition next to the people it is used on, and the self-audit reported it as a
critical finding (the lesson of 2026-10-28: an example inside a description reads like the
thing). The guide now says what the code does without those words.

**Open for the owner.** Confirm or change the held-out split. Label
`results/run4/findings-audit.csv`, and, blind, the two reference sets (the held-out one
first, before anything is tuned).
