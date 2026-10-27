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
