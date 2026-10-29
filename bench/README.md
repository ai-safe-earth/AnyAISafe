# bench/ -- measuring the `aisafe audit` rules

A passing unit test proves a rule fires on the case it was built for. It says nothing
about how often the rule is right on software nobody wrote for the test. This folder
holds the two measurements that do, and the protocol they follow (`protocol.md`).

Nothing here estimates, extrapolates or defaults a verdict. Every number in a generated
report traces back to a label a person wrote, and every number is printed with its
counts.

## Two corpora

| corpus | what | labels | measures |
|---|---|---|---|
| `bench/cases/` | small synthetic trees, one per case, each with an `expected.yaml` | written by the case's author, reviewed by a second person before they count | per-rule precision **and recall** on known ground truth; regression |
| `research/corpus.yaml` | 33 public repositories pinned to commits (`research/`); `bench/corpus.yaml` is the older 20-repository list | `tp` / `fp` / `unclear` per sampled finding, by hand or in the review console | per-rule precision on real software |

The synthetic corpus can measure recall because every case says which findings are
owed. The real corpus measures precision only. A rule's `measured_precision` comes from
the real corpus and from nowhere else: the synthetic cases were written by people who
know the detector.

## The synthetic corpus: `bench/cases/`

```
bench/cases/<case-id>/
  tree/            the files to audit (prompts, code, config)
  expected.yaml    the labels: expected findings, forbidden findings, UNKNOWN categories
```

A label names a rule, a sub-finding (`null` means any sub-finding of the rule), the
decision the policy takes (`violates_policy`, `requires_contextual_review`) and, when it
matters, the evidence status. `forbidden` names the findings that would be false
positives on that tree. `labels.reviewed_by` is a second person; until it is set the case
is a draft. One behaviour per case; a tree that mixes two mechanisms is two cases.
`split: heldout` cases are not read while a rule is being tuned.

```bash
python bench/score.py --cases bench/cases                     # -> bench/cases-score.md
python bench/score.py --cases bench/cases --out /tmp/score.md
```

The scorer runs the audit in-process over every `tree/` (the same walk -> discover ->
pydeep -> checks -> flows -> review-records pipeline as `aisafe audit`, every registered
rule, experimental ones included) and compares the findings with the labels:

- **tp**: an expected finding reported with the labelled decision (and evidence status
  when the case names one);
- **fn**: an expected finding absent, or reported only with a different decision or
  status (the report says whether it was weaker or stronger);
- **fp**: a forbidden finding reported, or any finding on a case whose `expected` list is
  empty, review-only findings included;
- **precision** = tp / (tp + fp), **recall** = tp / (tp + fn), each with its counts and
  `n/a` when the denominator is zero.

The report separates `dev` from `heldout` and reviewed from unreviewed cases. The headline
tables use reviewed cases only and say so; with no reviewed case they say "no reviewed
cases: every number below is from unreviewed labels". Every mismatch is listed verbatim
(case, rule, expected, got), as are findings no label mentions and the UNKNOWN categories
a case expects. The scorer exits 0 unless a case is malformed (exit 2): an unparsable
`expected.yaml`, a missing `tree/`, a split outside `dev`/`heldout`, a decision or status
outside the policy's vocabulary.

A mismatch is a detector bug or a label bug. The label is never edited to make the run
pass; the resolution is written in the case's `labels.disagreement`.

## The real corpus: `run.py`, the label loop, `score.py --tool audit`

```bash
python bench/run.py                    # 1. clone the corpus, audit it, write findings-audit.csv
#                                        2. label the verdict column by hand (or in the console)
python bench/score.py --tool audit     # 3. write precision-audit.md and a paste-ready block
#                                        4. set measured_precision on the rules it names
```

### 1. Run the corpus

```bash
python bench/run.py                          # every repository in bench/corpus.yaml
python bench/run.py --only babyagi dspy      # a subset
python bench/run.py --keep-clones            # keep checkouts in bench/.cache
python bench/run.py --sample-per-rule 20     # a smaller labelling set
python bench/run.py --sample-per-rule 0      # no sampling; every finding
python bench/run.py --experimental           # also run rules measured below threshold
```

Each repository is fetched at the exact commit pinned in the manifest
(`aisafe.devtools._git.fetch_pinned`, shared with `aisafe fleet`), audited with
`aisafe audit . --format json --fail-on never` and the clone as working directory (so
the target's own `[tool.aisafe-audit]` applies), and deleted again unless
`--keep-clones`. Raw reports land in `bench/results-audit/<name>.json`.

Two CSVs come out:

| file | contents |
|---|---|
| `findings-audit-all.csv` | every finding. Evidence, not a worklist |
| `findings-audit.csv` | **the file you label**: at most 40 findings per rule, spread across repositories |

Columns: `repo, file, line, rule_id, sub, decision, evidence_status, message, snippet,
verdict`. `rule_id` is the parent rule (precision is a class attribute); `sub` the
sub-finding; `decision` and `evidence_status` the audit's own statements, so the labeller
judges the claim the report made; `snippet` the first evidence leg, already redacted by
the audit, so a labeller needs no clone and a quoted key never reaches the CSV.

Precision needs roughly 30-50 judged findings per rule, not thousands. The sample is
drawn round-robin across repositories so a rule is not measured entirely against
whichever codebase sorts first. Sampling is **deterministic** and **nested**: the same
results always yield the same sample, and a smaller `--sample-per-rule` is a strict
subset of a larger one, so neither a re-run nor a tighter cap orphans a row already
labelled. Verdicts already entered are carried over by `(repo, file, line, rule_id)`.

### 2. Label by hand

Fill the `verdict` column of `findings-audit.csv`, or build a review set for the console
(`research/console/console.py build`) and import the labels back. Exactly three values:

| verdict | meaning |
|---|---|
| `tp` | the finding is right: the prompt or the code does what the finding says |
| `fp` | the finding is wrong here: the pattern matched but the claim does not hold |
| `unclear` | cannot decide without more context than the snippet and the clone give |

`unclear` leaves the precision denominator. Use it honestly: a rule whose sample is mostly
`unclear` shows up as a thin sample rather than as a confident-looking ratio. A true
positive says the code does what the finding says; whether anyone was harmed is outside
what a repository can show.

### 3. Score

```bash
python bench/score.py --tool audit
python bench/score.py --tool audit --min-precision 0.90    # a stricter bar
python bench/score.py --tool audit --allow-partial         # score the labelled subset only
```

`score.py` **refuses to run** while any row is unlabelled or carries a value outside
`{tp, fp, unclear}`; precision over a partly labelled sample is not a measurement.
`--allow-partial` overrides it and the report says so at the top. Output:
`bench/precision-audit.md` with per-rule precision and sample sizes, the rules below the
threshold, the rules that never fired, and the three worst false positives quoted
verbatim (redacted where the audit redacts) with the decision and evidence status the
audit gave them.

### 4. Feed it back into the registry

The report prints a paste-ready block naming the rule class and version:

```python
class EngagementObjective(AuditRule):
    id = "AUD-1104"
    ...
    measured_precision = 0.625   # from bench/precision-audit.md, run <date>
```

A rule measured below `MIN_PRECISION` (0.80, in `aisafe.rules`) stops firing unless the
user passes `aisafe audit --experimental`. The figure names the corpus commit set and the
run it came from.

## What UNMEASURED means

`measured_precision = None` renders as `[UNMEASURED]` on every finding. It means
**unmeasured, not perfect**: a rule that has never been measured keeps firing by default,
because silencing a rule takes evidence, and gating everything unmeasured would mute the
audit. Three cases read as unmeasured and the reports keep them apart:

- **never fired**: no finding anywhere in the corpus; says nothing about precision;
- **all `unclear`**: fired, but no finding could be judged either way;
- **synthetic only**: scored on `bench/cases/`, where the labels know the detector.

None is evidence of quality. Do not type a number in for any of them.

## Another corpus, another folder: `--corpus`, `--out-dir`, `--rules`

The research study (`research/`) runs the same harness over its own pinned corpus,
restricted to the rules it measures, with everything written under its own folder:

```bash
python bench/run.py --corpus research/corpus.yaml --out-dir research/results/run3 \
    --rules AUD-1101,AUD-1102,AUD-1103,AUD-1104,AUD-1105,AUD-1106,AUD-1107,AUD-1108 --keep-clones
python bench/score.py --tool audit --csv research/results/run3/findings-audit.csv \
    --results research/results/run3/results-audit --out research/results/run3/precision-audit.md
```

`--rules` is passed through as `aisafe audit --rules`. Clones are shared in
`bench/.cache/` (ignored by git), so a repository in both corpora is fetched once per
pinned commit.

## Corpus pins

Both manifests pin each repository to a 40-character commit resolved with
`git ls-remote`, so a figure stays reproducible as upstreams move. To refresh a pin,
re-resolve it; never edit a SHA by hand:

```bash
git ls-remote https://github.com/<owner>/<repo> HEAD
```

Changing a pin invalidates the verdicts for that repository. Re-label them.

## Files

| path | committed | what |
|---|---|---|
| `protocol.md` | yes | the benchmark protocol: corpora, case format, counting rules, status |
| `cases/<id>/` | yes | the synthetic corpus: a `tree/` and an `expected.yaml` per case |
| `cases-score.md` | when scored | generated by `score.py --cases`; do not edit |
| `corpus.yaml` | yes | the older 20-repository manifest; `research/corpus.yaml` is the current study |
| `run.py` | yes | clone -> `aisafe audit` -> `findings-audit.csv` |
| `score.py` | yes | labelled CSV -> `precision-audit.md`; `--cases` -> `cases-score.md` |
| `findings-audit.csv` | when run | the sampled labelling set; `verdict` filled in by hand |
| `findings-audit-all.csv` | when run | every finding, unsampled; reference only |
| `results-audit/*.json` | no | raw audit reports per repository, source of the verbatim snippets (gitignored) |
| `precision-audit.md` | when scored | generated by `score.py --tool audit`; do not edit |
| `findings.csv`, `findings-all.csv`, `results/` | legacy | output of a tool removed in the pivot (its code is at the `legacy/pre-pivot-0.1.0` tag); not read by anything here |
| `.cache/` | no | transient checkouts (gitignored) |
