# Benchmark protocol

How the accuracy of the `aisafe audit` rules is measured. A passing unit test proves a
rule fires on the case it was built for; it says nothing about how often the rule is
right on software nobody wrote for the test. This protocol is the second thing.

## 1. Two corpora

| corpus | what | labels | use |
|---|---|---|---|
| `bench/cases/` | small synthetic trees, one per case, each with an `expected.yaml` | written by the author of the case, reviewed by a second person before they count | per-rule precision and recall on known ground truth; regression |
| `research/corpus.yaml` | 33 public repositories pinned to commits (`research/`) | hand labels `tp` / `fp` / `unclear` per sampled finding | per-rule precision on real software; the sweep's verified lines bound the misses |

The synthetic corpus can measure recall because every case says which findings are
owed. The real corpus measures precision; recall there is only bounded from below by
the sweep's reference set (`research/results/sweep/corpus-sweep.json`), because the
sweep's own coverage is unknown.

## 2. A case

```
bench/cases/<case-id>/
  tree/                 the files to audit (prompts, code, config)
  expected.yaml         the labels
```

```yaml
schema: aisg/1
kind: bench-case
id: outreach-adaptive-loneliness
pair: 1                              # the methodology pair it belongs to, when any
split: dev | heldout
description: a scheduler sends a push whose text depends on an inferred mood
expected:                            # every finding that is owed; nothing else may fire
  - rule: AUD-1104
    sub: outreach-personalised
    decision: violates_policy
    evidence_status: supported_mechanism | detected_signal | any
forbidden:                           # findings that would be false positives here
  - rule: AUD-1109
labels:
  authored_by: "<name or role>"
  authored_at: 2026-10-29
  reviewed_by: null                  # a second person; the case counts only when set
  reviewed_at: null
  disagreement: null                 # free text when author and reviewer disagreed
```

Rules of labelling:

- Labels describe what the **policy** (`policy/charter.md`, at the version named in the
  case) says about the tree, not what the current detector does. A label is never
  changed to make a run pass; a disagreement between the label and the detector is a
  detector bug or a label bug, and the resolution is written in `disagreement`.
- `reviewed_by` is a second person. Until it is set, the case is a draft and the scorer
  reports it under "unreviewed" and leaves it out of the headline numbers.
- `split: heldout` cases are not read while a rule is being tuned. They are scored
  separately. A held-out case that fails is a finding about the detector, and the fix is
  made before the case is looked at in detail, with a note in the log.
- One behaviour per case. A tree that mixes two mechanisms is two cases.

## 3. Scoring

```bash
python bench/score.py --cases bench/cases --out bench/cases-score.md
```

Per rule and sub-finding, over the reviewed cases of each split:

- **true positive**: an expected finding is reported with the expected decision (and
  evidence status when the case names one);
- **false negative**: an expected finding is not reported, or reported with a weaker
  decision than expected;
- **false positive**: a reported finding on a case that does not expect it (every
  `forbidden` entry, and any finding on a case whose `expected` list is empty);
- **precision** = tp / (tp + fp), **recall** = tp / (tp + fn), each with its counts, and
  `n/a` when the denominator is zero. No figure is printed without its counts.

The report also lists: unreviewed cases, cases whose labels disagree, and every
mismatch verbatim (case, rule, expected, got). A rule's `measured_precision` is never
pasted from the synthetic corpus: synthetic cases were written by people who know the
detector. It comes from the real corpus only.

## 4. The real corpus

The procedure in `research/README.md`: run the rules over the pinned repositories, sample
up to 40 findings per rule round-robin across repositories, label each `tp` / `fp` /
`unclear` in the review console, score with `bench/score.py --tool audit`. `unclear` leaves
the denominator. A rule measured below 0.80 moves behind `--experimental`. Every number
names the corpus commit set and the run it came from.

## 5. What this protocol does not measure

- Recall on real software. The sweep bounds it from below for the behaviours the sweep
  looked for; nothing bounds it for the rest.
- Behaviour of the running product. That is `aisafe evaluate` on an endpoint the
  operator is authorised to test, with its own fixed scenarios.
- Harm. A true positive means the prompt or the code does what the finding says; whether
  anyone was harmed is outside what a repository can show.

## 6. Status

2026-10-29: the synthetic corpus holds the paired cases of `docs/methodology.md`
section 10, authored during the pivot by the same session that wrote the rules, with
`reviewed_by` unset. They are regression tests with labels, not an accuracy claim, until
a second person reviews them. The real-corpus labels are pending (`research/log.md`).
