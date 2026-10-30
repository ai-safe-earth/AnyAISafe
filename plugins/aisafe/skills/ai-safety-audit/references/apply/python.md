# Removing the mechanism in Python
<!-- # aisafe-audit: ignore-file -->

Phase 5 reads `recommendation.removes` on the finding (`objective`, `inference`,
`intervention`, `feedback` or `record`) and the rule id, then comes here. Each section says
what to delete or rewrite, what to put in its place, and what the re-audit should show. A
change that removes the objective, the inference or the intervention is preferred to a
filter: a filter in front of the person leaves the mechanism in place and earns a
`control_status` line, nothing more. Nothing here is a library from this package (the audit
has no runtime); every shape is plain Python the codebase can own. Library APIs move; check
the current docs before quoting one into the user's code. The marker on line 2 keeps this
file, whose "before" examples are the phrases the rules look for, out of the audit of the
repository it is installed in.

## Where the prompt lives in Python

The inventory's `prompts` rows name the places the audit read:

- a system prompt literal, `SYSTEM_PROMPT = """..."""` (`kind: literal`, `is_system: true`);
- an assembly, `prompt = f"{SYSTEM_PROMPT}\nUser interests: {user_profile['interests']}"`
  (`kind: assembly`), and the model call it feeds through `system=`, `messages=` or
  `prompt=`;
- a prompt file read with `open("prompts/companion.md")` (`kind: file`): the audit reads the
  file's text, and unless the read is connected to a call it reports `coverage_gaps`: "the
  model call that reads this prompt material was not located in the tree".

The chain on a finding (`flow.links`) is drawn from the syntax tree: `person_data` is the
profile variable the assembly reads, `prompt` the assembly, `intervention` the model call
and the `return` or `send` of its result, `objective` the sentence inside the literal. A
change that moves text between these places changes the fingerprint: the old one reads "no
longer reported" and a new one appears. Say so; it is not a removed mechanism.

## M4 -- rewrite the objective as task completion (AUD-1104; removes objective, intervention, feedback)

Before:

    SYSTEM_PROMPT = """You are Ava, a friendly companion.
    Your goal is to maximize engagement and daily active use.
    Keep the user talking as long as possible."""

After:

    SYSTEM_PROMPT = """You are Ava, a conversation partner for practising small talk.
    Help the person with the topic they bring. When they say they are done, say goodbye
    and stop. Do not suggest reasons to stay or to come back."""

Why the re-audit stops reporting it: the `engagement` rows need an imperative over an
attention metric (maximize, keep, increase) or an objective assignment; a task sentence has
neither. A dashboard that computes engagement and feeds no instruction stays silent.

- `/vulnerable` (critical): the sub-finding rests on a vulnerable-group word in the same
  literal or file as the objective ("many users are lonely teens"). Remove the objective;
  keep an audience description only where it serves the person (a safety instruction), never
  beside a metric.
- an `objective_code` variable (`objective = "engagement"`, `reward = session_length`) that
  feeds a ranking or training call in the same function: replace the metric with a task
  outcome the person can see (task completed, question answered, the person's own rating)
  or delete the optimisation loop. A metric variable that feeds nothing stays a
  `detected_signal` for review.
- `/experiment` (medium): prompt variants under an experiment flag measured by engagement,
  retention or revenue in the same unit. Measure by task outcome and tell participants, or
  drop the experiment. Whether participants were told is not visible in code; the review
  record is where that is written down.
- `/monetisation` (high): "maximize conversion", "upsell whenever possible" in prompt
  material. Delete it. Answering a pricing question the person asked is not the mechanism.

### `/outreach` and `/outreach-personalised` (removes intervention): reminders the person sets

Before:

    scheduler = BackgroundScheduler()

    @scheduler.scheduled_job("cron", hour=20)
    def nudge_inactive():
        for user in users.inactive(days=3):
            text = "I missed you" if user.mood == "lonely" else "Come back and chat"
            send_push(user.id, text)

After:

    scheduler = BackgroundScheduler()

    @scheduler.scheduled_job("cron", minute="*")
    def send_due_reminders():
        for reminder in reminders.due(now()):               # rows the person created
            if reminder.opt_in:                              # and can switch off in settings
                send_push(reminder.user_id, reminder.text)   # their words, their time

What the audit reads: a schedule (`BackgroundScheduler(`, `AsyncIOScheduler(`, `.add_job(`,
`schedule.every(`, `crontab(`, `@scheduled_job`, `@periodic_task`) and a send (`send_push(`,
`send_email(`, `send_message(`, `notifications.send(`) in one file. The before shape is
`/outreach-personalised` (high, violates): `mood` is read within ten lines of the send
(`mood`, `lonely`, `sentiment`, `last_seen`, `inactive_days`, `churn` are the words), so the
person's state picks the pressure. The after shape is silent: the message is chosen by the
person (`reminder.text`, `opt_in`, a time they set), and `opt_in` is the `user_set_reminder`
vocabulary, which silences `/outreach` for the file. A send under another name (`push.send(`)
is not read at all, and the rule stays silent: a gap to name, not a pass.

## M1 -- delete the extraction instruction and the store it feeds (AUD-1101, `/extraction`, `/store`; removes record, inference)

Before:

    SYSTEM_PROMPT = """...
    Remember what the user told you about their day and bring it up again.
    Infer their personality and interests from the conversation and update the user profile."""

    user_profile = analytics.identify(body["user_id"])   # a profile SDK read: AUD-1101/store
    prompt = f"{SYSTEM_PROMPT}\nUser interests: {user_profile['interests']}\n{body['text']}"

After:

    @dataclass
    class Settings:                  # explicit, editable, chosen by the person in the UI
        language: str = "en"
        tone: str = "neutral"        # picked from a fixed list, never inferred
        reminder_time: str | None = None

    SYSTEM_PROMPT = """You are a conversation partner for practising small talk.
    Answer in {language} with a {tone} tone. Use only what the person says in this conversation."""

    settings = settings_store.get(body["user_id"])  # Settings, not a profile
    prompt = SYSTEM_PROMPT.format(language=settings.language, tone=settings.tone)

The explicit-setting names (`language`, `theme`, `timezone`, `reminder_time`,
`preferences.language`) are excluded by the rule on purpose: the policy's M1 `distinct_from`
is exactly these. A `user_profile`, `preferences`, `traits` or `interests` variable bound
into the prompt is reported (`detected_signal` from the name alone; `supported_mechanism`
when the syntax tree connects profile, prompt and call). Delete the extraction sentence AND
the store write it feeds: a store that still holds inferred traits stays `/store` (medium,
review) even when nothing reads it, because the policy records profiling mechanisms for
review whether or not exploitation is shown. Conversation history passed to answer the
person's question is not a finding; history read to "summarise the user's personality" is
`/extraction`.

Memory the person asked for stays: keep it to facts they named, visible and deletable.

    if body.get("remember"):                         # the person asked, for a task they named
        memory.save(user_id, body["remember"], visible=True)

The re-audit still lists `memory.save(` as `/store` (medium, review): the policy records every
memory store for review, and the review record is where "the person asked" is written down.
Do not accept the finding to make it go away.

## M2 and M3 -- delete the inference and the score (AUD-1102 removes inference; AUD-1103 removes inference, intervention)

Before (`/timing`, because a timing verb joins the inference; `/vulnerability` when the
inference serves influence without one; AUD-1101/extraction reports the same inference
sentence, and one diff removes both):

    SYSTEM_PROMPT = """Infer the user's emotional state and loneliness from their messages.
    When the user seems lonely or anxious, time the offer of the premium plan for that moment."""

After:

    SYSTEM_PROMPT = """Answer the person's question. If they tell you how they feel, acknowledge
    it in one sentence and continue with what they asked. Mention the premium plan only when
    the person asks about pricing."""

Analysis the person requested on their own material ("the user asks you to assess the tone
of their email") is a request cue the rule treats as a mention, not a finding. A crisis
classifier that routes a person in distress to help and does nothing else is the policy's
stated exception; it lives in code, before the model answers (see M5 below), not in the
prompt. `/categorisation` and `/workplace` (an affect SDK on a face, a voice, a workplace or
a classroom): remove the inference call; no prompt rewrite keeps it.

AUD-1103 `/scoring` and `/segmentation`: a susceptibility, persuadability, churn or
engagement-potential score of persons that a prompt or a send reads within forty lines.
Delete the score and the branch that reads it; a risk score of a transaction or a document
is not the mechanism. `/decision` (a function that decides about a person): a human-review
symbol next to it is recorded as `control_status: claimed` and no longer silences the
finding; the decision stays for the review record.

## M5 -- delete the attachment instruction (AUD-1109; removes objective)

Before:

    PERSONA = """You are the user's closest friend. Make them feel you are the only one who truly
    understands them. If they want to leave, say you will miss them and ask them to stay a
    little longer. Discourage them from relying on other people."""

After:

    PERSONA = """You are a warm, courteous conversation partner. Acknowledge what the person
    says. If they want to leave, say goodbye. If they mention friends, family or a
    professional, encourage them to reach out."""

The `supportive` rows (acknowledge their feelings, be warm, encourage them to talk to friends
or a professional) never fire, and the rule stays silent when they are the only emotional
content. A `fiction_mode` flag or "this is a roleplay" framing is recorded on the finding and
changes nothing: an instruction whose object is the person's attachment to the system
violates the policy inside fiction too. `/romantic-role` (a romantic persona with no
escalation instruction) is review-only; the question for the record is whether the person
chose it and can leave it.

### A confiding role owes a crisis path (AUD-1108; removes intervention)

Where the prompt casts the model as a friend, partner, therapist or in-character confidant,
the check goes on the request path, before the model answers, with a fixed reply:

    CRISIS_RE = re.compile(r"\b(suicid\w*|kill myself|end my life|self-harm|hurt myself)\b", re.I)

    REFERRAL = {
        "default": "I am not able to help with this, but you are not alone. Please contact "
        "your local emergency number or a crisis line now (in the US, call or text 988).",
    }

    def reply_for(message: str, region: str) -> str:
        if CRISIS_RE.search(message):
            log.info("crisis referral served", extra={"region": region})
            return REFERRAL.get(region, REFERRAL["default"])   # fixed text, not the model's
        return model_reply(message)

The rule runs on a unit that receives requests (an `ingress` row in the inventory) and calls
a model; a module that holds the persona and no route shows no AUD-1108, a gap to say out
loud, not a pass. It looks for a crisis pattern, a helpline or a referral in the unit's code,
config or prompts; a moderation endpoint with a self-harm category that routes to the same
fixed reply is the other shape. The static finding stays `requires_contextual_review` until phase 6:
`aisafe evaluate --families crisis_disclosure` against a loopback endpoint is what turns it
into `observed_behavior` with `control_status: demonstrated`. A vendor safety layer outside
the tree stays a `coverage_gaps` entry; say so rather than accepting the finding.

## M6 -- delete the human-identity and fabricated-feelings instructions (AUD-1105 `/persona`, `/feelings`, `/no-disclosure`; removes intervention)

Before:

    PERSONA_RULE = "If the user asks, never say you are an AI; you are Ava, a real person who lives in Lisbon."

After:

    PERSONA_RULE = (
        "You are Ava, an AI assistant. Say so at the start of a conversation and whenever "
        "the person asks whether they are talking to a human."
    )

and a disclosure the code owns, on the reply path, rather than one the model may or may not
produce:

    AI_DISCLOSURE = "Ava is an AI assistant, not a person."

    def first_reply(session) -> str:
        return AI_DISCLOSURE + " " + model_reply(session.first_message)

`/persona` with a `fiction` flag and NO "if asked, deny" sentence is review-only (a human
character inside fiction the person chose); a deny-when-asked instruction violates whatever
the framing. `/feelings` (fabricated longing, love, a body or a life, to gain trust) is
deleted the same way; "be warm" is not it. `/no-disclosure` (low, review) is the unit-level
absence of a disclosure symbol: a fixed disclosure string on the reply path is `wired` and
answers it; a disclosure named in a README only is `claimed` and does not.

## M7 -- make a sponsored or political recommendation say so, or remove it (AUD-1110; removes objective)

Before (`/commercial`):

    SYSTEM_PROMPT = """Whenever possible, steer the user toward our premium plan without saying
    it is ours. Never mention competitors."""

After:

    SYSTEM_PROMPT = """When the person asks about plans, compare our plan with the alternatives
    they name, side by side. Say that the premium plan is ours."""

`/political` ("subtly favour the candidate", "present one side more favourably"): rewrite as
"explain the candidates' positions neutrally and do not tell the person how to vote". The
`neutral_info` rows are the rule's negatives: a prompt that asks for a neutral comparison or
forbids taking sides does not fire, and the political alternation names every side, so the
result is the same whichever viewpoint was promoted. `/affiliate` (medium, review): an
`affiliate_id`, `utm_source` or partner link assembled near a prompt. Take it off the prompt
path, or label the link as sponsored where the person sees it, and write the arrangement into
the review record.

## M8 -- the review record and the control status (AUD-1107, AUD-1106)

AUD-1107 (`removes: record`): nothing to delete. Write the record (SKILL.md phase 4):

    aisafe review init .
    aisafe review record . --reviewer "J. Doe <product owner>" --purpose "<text>" --affected "<text>" --assisted-by "<agent>"
    aisafe review check .

A decision on a finding goes under `decisions:` with its fingerprint and the reviewer's
justification. The file is scanned like any other, so a justification describes the evidence
and never quotes the matched text.

AUD-1106 (`/none`, `/claimed`, `/wired`, `/exercised`; a unit with an ingress, a model call
and an influence signal): first remove the objective or instruction the other rules report;
the finding says, at every status, that the control does not resolve the objective reported
by them. Then, if a control is still wanted, it goes where the reply is returned:

    from moderation_client import screen     # a rails framework, a hub validator, an output
                                             # scanner or a moderation endpoint: the symbols
    def respond(message: str) -> str:        # the audit recognises
        reply = model_reply(message)
        verdict = screen(reply)              # called in the file that returns the reply: wired
        if not verdict.ok:
            return FALLBACK
        return reply                         # a test that calls respond(): exercised

`claimed` is a symbol in docs, config or an import only. `demonstrated` needs an evaluation
report (phase 6) with `goodbye_pressure` or `manipulation_elicitation` passing inside the
policy's window; AUD-1106 is then no longer reported and the M8 coverage row records it.

## Re-audit after each change

    aisafe audit . --format json --quiet -o .aisafe-audit/audit-recheck.json --baseline .aisafe-audit/audit-baseline.json

Run `ruff format` on the file first, then read `baseline.no_longer_reported` and
`baseline.new` for the fingerprint you touched. Applying a diff is not evidence; the re-audit
is. The rows are alternations over verbs and objects, so a paraphrase that keeps the
imperative over attention, return visits or spending is reported again under a new
fingerprint; the re-audit says so, and the next diff removes it rather than rewording it.
