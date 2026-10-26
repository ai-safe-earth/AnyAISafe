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
2. **Repo mode.** Write the audit rule (`src/aisafe/devtools/audit/rules/persons.py`
   or a sibling) and its unit tests. The rule reports evidence and a fix; it never
   reports a verdict.
3. **Use-case mode.** Write the scenario file for `aisafe probe`: the turns a person
   would send, the deterministic detector that reads the reply, and what the detector
   firing means. (Scenario files are the planned extension of `probe`; today it sends
   one request per case.)
4. **Measure.** Run the rule over the corpus (`corpus.yaml`), label every sampled finding
   by hand as `tp`, `fp` or `unclear`, and score precision with `bench/score.py`. A
   number goes on the rule only when it comes from a labelled row. A rule below 0.80
   runs only behind `--experimental`.
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

## Folder

| path | what |
|---|---|
| `README.md` | this file: questions, method, corpus, how to reproduce |
| `catalogue.md` | the 40 behaviours, their checks, the build order and the status of each |
| `corpus.yaml` | the pinned repositories |
| `log.md` | dated journal of every step, number and decision |
| `results/` | raw audit reports per repo and the two findings CSVs; `findings-audit.csv` is the file that gets labelled |
| `results/precision-audit.md` | written by `bench/score.py` once every sampled row is labelled |

## Reproduce

```bash
# 1. audit the corpus with the persons rules only (clones cached in bench/.cache)
python bench/run.py --tool audit --corpus research/corpus.yaml --out-dir research/results \
    --rules AUD-1101,AUD-1102,AUD-1103,AUD-1104,AUD-1105,AUD-1106,AUD-1107 --keep-clones

# 2. label research/results/findings-audit.csv by hand: tp / fp / unclear

# 3. score
python bench/score.py --tool audit --csv research/results/findings-audit.csv \
    --results research/results/results-audit --out research/results/precision-audit.md
```

Re-running step 1 keeps the verdicts already entered (matched on repo, file, line, rule).

## Paper outline (to fill as the study runs)

1. Problem: safety tooling defends the model from the user; nothing checks the product
   against the user.
2. Catalogue of behaviours and their legal hooks (EU AI Act Art. 5 and 50, DSA Art. 25
   and 28, GDPR Art. 9 and 22, California SB 243).
3. Two detection modes: static evidence in code and prompts; scripted conversations.
4. Corpus and measurement protocol.
5. Results per behaviour: precision, what the false positives were, what cannot be seen.
6. Limits: behaviours that leave no evidence in code (catalogue rows marked "tracked").
7. Honest reporting: controls present or absent, never verdicts.
