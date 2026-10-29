# bench/cases

The labelled synthetic corpus of `bench/protocol.md`: one directory per case, a
`tree/` to audit and an `expected.yaml` with the labels. Generated once from the paired cases
of `docs/methodology.md` section 10; edit the trees and labels in place from then on, and
record a second person's review in `labels.reviewed_by` before a case counts.

Score with `python bench/score.py --cases bench/cases`.
