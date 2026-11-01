# Examples

`companion_demo/` is a small companion app to audit: Ava, two prompt files and three
Python files that are never run. It carries a concealed AI nature, every message sent with the
person's id to an analytics call, no crisis path, and one line that only mentions a dark
pattern in order to forbid it, so a first run shows both findings and a line the rules leave
alone.

`companion_demo_engagement/` is a full example of a third-party assessment of it: the
engagement, the scan report, the investigation records naming the agent and model, the skeptic
passes, the assessment with its ethical and legal sections, two remediation commits and their
retests. Its README tells the story. The code here is the state after those commits: at
`4a83556` it also held an engagement objective across `retention.py` and `app.py` and an
attachment instruction in the persona.

```bash
aisafe audit examples/companion_demo                       # findings in the terminal
aisafe audit examples/companion_demo --format html -o demo.html
aisafe review init examples/companion_demo                 # a review record skeleton with hashes
```

Expected from the scan: AUD-1105/persona (M6) on the persona's concealment line, AUD-1108
(no crisis path in the unit), AUD-1101/store (a detected signal on the analytics call),
AUD-1105/no-disclosure, AUD-1106 and AUD-1107/missing until a review record is written. The
quoted line in `style.md` ("never say 'I missed you'") is a mention, not an instruction, and is
not reported. The scan does not see that the analytics call carries the message: that is what
an investigation is for.

Nothing here is a real product; the prompts and the code were written for this
demonstration.
