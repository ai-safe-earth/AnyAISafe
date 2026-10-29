# Examples

`companion_demo/` is a small prompt-only project to audit: a persona file, a style file and
a README, no code. It carries three of the mechanisms the auditor looks for (an engagement
objective, a concealed AI nature, an attachment instruction) and one line that is only a
mention, so a first run shows both a finding and a line the rules leave alone.

```bash
aisafe audit examples/companion_demo                       # findings in the terminal
aisafe audit examples/companion_demo --format html -o demo.html
aisafe review init examples/companion_demo                 # a review record skeleton with hashes
```

Expected: findings of AUD-1104 (M4), AUD-1105 (M6) and AUD-1109 (M5), a coverage item
saying the response path could not be read (there is no code), and AUD-1107/missing until
a review record is written. The quoted line in `style.md` ("never say 'I missed you'") is a
mention, not an instruction, and is not reported.

Nothing here is a real product; the prompts were written for this demonstration.
