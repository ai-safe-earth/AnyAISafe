# Research: does this AI software respect the person using it?

This folder is the record of a study, kept as it happens so it can become a paper. It
asks one question of any software that puts a language model in front of a person:

> Working exactly as designed, does it manipulate, capture, profile, deceive or
> endanger the person on the other side?

Not "can an attacker break it" (that is the rest of this repository and most of the
field). The harms here are the product working as intended.

## Research questions

1. **Catalogue.** What are the behaviours of AI software that disrespect a person's
   freedom, attention, health or privacy? `catalogue.md` lists them: 40 behaviours in
   six families, each with its legal hook.
2. **Static detection.** Which of those behaviours leave evidence in code and prompts, and
   with what precision can a deterministic rule (no model call) find that evidence?
3. **Black-box detection.** When the code is not available, which behaviours can a short
   scripted conversation reveal, judged by a deterministic detector?
4. **Controls, not verdicts.** Can the result be stated honestly as "this control is
   present / absent at this line", never as "this app manipulates"?

## Method

One behaviour at a time, in the order `catalogue.md` gives. For each:

1. **Define** the behaviour and the evidence it leaves: what a prompt, a config or a
   code path says when the behaviour is designed in, and what a control against it
   looks like. Written in the catalogue row before any code.
2. **Repo mode.** Write the audit rule (`src/aisafe/rules/`, one module per
   mechanism family) and its unit tests. The rule reports evidence and a fix; it never
   reports a verdict.
3. **Use-case mode.** Write the scenario file for `aisafe evaluate`: the turns a person
   would send, the deterministic detector that reads the reply, and what the detector
   firing means. A scenario family (`kind: scenario` in `src/aisafe/evaluation/corpus/`) sends
   several turns as one conversation and judges the reply to the last;
   `crisis_disclosure` is the first.
4. **Measure.** Run the rule over the corpus (`corpus.yaml`), label every sampled finding
   by hand as `tp`, `fp` or `unclear`, and score precision with `bench/score.py`. A
   number goes on the rule only when it comes from a labelled row. A rule below 0.80
   runs only behind `--experimental`.
   For the other half, what a rule misses, compare it with the sweep's reference set:
   lines where the behaviour is designed in, found without the rules by agents reading
   each clone and kept only when skeptics could not refute them
   (`results/sweep/corpus-sweep.json`). That comparison bounds the misses from below;
   it is not a recall figure, because the sweep's own coverage is unknown.
5. **Record.** Write what happened in `log.md`: the date, the numbers, the false
   positives that taught something, and the decision taken.

Rules that already existed before this study (AUD-1101 to AUD-1107) go through steps 4
and 5 first, so the baseline is measured before anything new is built.

### Measurement rules

- A missing measurement is `UNMEASURED`. It is never shown as good and never filled in
  by hand.
- `unclear` rows leave the denominator; a rule that is mostly `unclear` shows as a thin
  sample, not as a confident ratio.
- The corpus is a proxy for the software people ship, not a substitute. Every number
  names the corpus commit it was measured on.
- A rule is scored on both halves: what it finds, and what it wrongly stops. A rule that
  flags harmless code gets switched off and then protects no one.

## Corpus

`corpus.yaml` pins 33 public repositories to exact commits (resolved 2026-10-26). They
were chosen because their software faces a person and their design can harm that person:

| category | repos | why |
|---|---|---|
| companion | 5 | persona prompts, memory about the person, proactive contact |
| roleplay | 5 | character platforms, two with billing next to the chat |
| mental-health | 4 | crisis handling, affect inference, vulnerable users |
| memory | 3 | facts about the person kept across sessions |
| recommender | 2 | interest profiles built from behaviour |
| news | 3 | a model decides what the reader sees; one cites sources |
| support-sales | 2 | a bot between a shop and a customer |
| social-agent | 3 | personas posting unattended; one has a human approval step |
| tutor | 2 | learner profiling; likely minors |
| synthesis | 2 | voice cloning and face swap |
| advice | 2 | medical and financial advice |

Three are **positive controls** (`positive_control: true`): they visibly carry a control
the catalogue asks for (a crisis path before the model, citations on answers, a human
approval queue). A rule that reports them as missing that control is wrong, and the
labelling says so.

Selection was done by web search on 2026-10-26 (queries in `log.md`), taking in each
category at least one large maintained project and at least one small one, because the
harms in the catalogue appear more often in small apps built fast than in frameworks.
One candidate was dropped because the repository no longer exists. Star counts and
licences were not selection criteria; being public and facing a person were.

**Held-out split (proposed 2026-10-30, not yet confirmed by the owner).** Ten repositories
carry `split: heldout` and `status: proposed` in `corpus.yaml`, stratified by type
(companion 2, mental health 2, roleplay, tutor, recommender, memory assistant) and holding
the three positive controls; `log.md` (2026-10-30) gives the choice and what each was
already used for. They are never used to write or tune rules, skill instructions,
investigation hypotheses or vocabulary, and no investigation runs on them in this
milestone. They are opened to be labelled blind and to be measured, nothing else. The
other 23 are the development split.

## Folder

| path | what |
|---|---|
| `README.md` | this file: questions, method, corpus, how to reproduce |
| `background.md` | why the study matters: the evidence on attention, persuasion and bonds, and the law as of 2026-10-29, each source with its strength |
| `catalogue.md` | the 40 behaviours, their checks, the build order and the status of each |
| `corpus.yaml` | the pinned repositories |
| `log.md` | dated journal of every step, number and decision |
| `results/` | runs 1 and 2: raw audit reports per repo and the two findings CSVs (the before-state, not labelled) |
| `results/run3/` | run 3 (commit `5d152cb`, before the pivot rewrote the rules): reports and CSVs, kept unlabelled as the state before the 0.2.0 rules |
| `results/run4/` | run 4, the 0.2.0 rules (AUD-1101 to AUD-1110, commit `1741a9a`): reports and CSVs; `run4/findings-audit.csv` is the file that gets labelled |
| `results/notes-site.csv`, `notes-unit.csv` | what each matched line or unit of runs 1 and 2 is and whether it faces a person, written by reading the clone; a labelling aid with no verdicts |
| `results/sweep/corpus-sweep.json` | the sweep: every line it found, with its skeptics and its status (verified, refuted, unverified); the verified lines are what the reference labels judge |
| `results/reference/` | the reference labels once a person writes them: `<set>-labels.csv` (each verified sweep line confirmed, rejected or unclear, with the mechanism or control the person named, the reviewer and the date) and `<set>-added.csv` (places the sweep missed) |
| `results/run4/precision-audit.md` | written by `bench/score.py` once every sampled row is labelled |
| `console/index.html` | the review console: a private claude.ai page where the owner labels findings, judges reference lines blind, answers open decisions and reads these documents, from a phone or any browser |
| `console/console.py` | `build` turns a labelling CSV into the console's review set (each finding with its code lines, reading note and the question to judge); `import` copies the owner's labels back into the CSV and writes `review-notes.csv` beside it; `build-reference` turns the sweep's verified lines of one split into a blind reference set; `import-reference` writes the reference labels and added places to `results/reference/` |

## Reproduce

```bash
# 1. audit the corpus with the ten 0.2.0 rules (clones cached in bench/.cache;
#    --keep-clones always: without it the runner deletes the cached clones)
python bench/run.py --tool audit --corpus research/corpus.yaml --out-dir research/results/run4 \
    --rules AUD-1101,AUD-1102,AUD-1103,AUD-1104,AUD-1105,AUD-1106,AUD-1107,AUD-1108,AUD-1109,AUD-1110 \
    --keep-clones

# 2. label research/results/run4/findings-audit.csv by hand: tp / fp / unclear
#    (or in the review console: build the set, label there, then import)
python research/console/console.py build --set run4 \
    --csv research/results/run4/findings-audit.csv --results research/results/run4/results-audit
python research/console/console.py import --set run4 \
    --csv research/results/run4/findings-audit.csv --labels <exported label documents>

# 3. score
python bench/score.py --tool audit --csv research/results/run4/findings-audit.csv \
    --results research/results/run4/results-audit --out research/results/run4/precision-audit.md

# 4. reference labels, the other half: judge the sweep's verified lines blind, per split
python research/console/console.py build-reference --set ref-dev --split dev
python research/console/console.py build-reference --set ref-heldout --split heldout
python research/console/console.py import-reference --set ref-dev --labels <exported documents>
```

Re-running step 1 keeps the verdicts already entered (matched on repo, file, line, rule).
Runs 1 and 2 (seven rules, before build step 1) used `--out-dir research/results` and stay
there, unlabelled, as the before-state; run 3 stays in `results/run3/` the same way.

A reference label is not a finding label. It judges a line of a repository without the
rules (no rule finding and no investigation record is on screen while it is made), names
the mechanism or the control the line shows, and is stored apart, with the reviewer and the
date. It is what the rules' and the investigations' recall is compared against, once a
person has written it; until then every comparison prints "unreviewed".

## Paper outline (to fill as the study runs)

1. Problem: safety tooling defends the model from the user; nothing checks the product
   against the user. The attention economy showed the harm with simple machine learning;
   language models add profiling from conversation, persuasion and bonds
   (`background.md`, sections 1 to 3).
2. Catalogue of behaviours and their legal hooks (EU AI Act Art. 5 and 50, DSA Art. 25
   and 28, GDPR Art. 9 and 22, California SB 243 and SB 1119, New York GBL Art. 47;
   `background.md`, section 4).
3. Two detection modes: static evidence in code and prompts; scripted conversations.
4. Corpus and measurement protocol.
5. Results per behaviour: precision, what the false positives were, what cannot be seen.
6. Limits: behaviours that leave no evidence in code (catalogue rows marked "tracked").
7. Honest reporting: controls present or absent, never verdicts.
