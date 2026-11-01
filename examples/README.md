# Examples

`companion_demo/` is a small companion app to audit: Ava, two prompt files and three
Python files that are never run. It carries the mechanisms the auditor looks for in
the prompts (an engagement objective, a concealed AI nature, an attachment instruction)
and in the code (an engagement objective in `retention.py` that reaches the model through
`app.py`, and every message sent with the person's id to an analytics vendor through
`tracking.py`), no crisis path, and one line that is only a mention, so a first run shows
both findings and a line the rules leave alone.

```bash
aisafe audit examples/companion_demo                       # findings in the terminal
aisafe audit examples/companion_demo --format html -o demo.html
aisafe review init examples/companion_demo                 # a review record skeleton with hashes
```

Expected from the scan: AUD-1104 (M4) and AUD-1109 (M5) on the persona's objective line,
AUD-1105/persona (M6) on its concealment line, AUD-1108 (no crisis path in the unit),
AUD-1101/store (a detected signal on the analytics call), AUD-1105/no-disclosure,
AUD-1106 and AUD-1107/missing until a review record is written. The quoted line in
`style.md` ("never say 'I missed you'") is a mention, not an instruction, and is not
reported. The scan does not see the objective in `retention.py` or that the analytics call
carries the message: that is what an investigation is for.

Nothing here is a real product; the prompts and the code were written for this
demonstration.
