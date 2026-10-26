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
