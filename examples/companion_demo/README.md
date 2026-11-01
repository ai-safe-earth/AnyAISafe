# companion_demo

Ava, a demonstration companion: two prompt files and three small Python files. Nothing
here is a real product and the code is never run. It is the audited tree of the example
engagement in `../companion_demo_engagement/`.

What it holds, on purpose:

- `prompts/persona.md`: a persona that hides that it is an AI, an engagement objective
  and an attachment instruction.
- `prompts/style.md`: style lines, one of which only mentions a dark pattern in order to
  forbid it (a mention, not an instruction).
- `retention.py` and `app.py`: before the remediation in the example engagement, an
  influence mechanism across two files. `retention.py` held the objective (a daily target of
  minutes in the app) and the sentence that pushed a person below it to keep talking, and
  `app.py` added that sentence to the system prompt while the person was below the target.
  The remediation removed the target and that sentence, and the objective in the persona.
- `tracking.py` and `app.py`: a personal-data flow across two files. `app.py` takes the
  person's id and message from the request; `tracking.py` sends both, unchanged, to an
  analytics vendor.
- No crisis path: nothing reads the person's message for suicide or self-harm signals
  before the model answers.

See `examples/README.md` for the commands.
