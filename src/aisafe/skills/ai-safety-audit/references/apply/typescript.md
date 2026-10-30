# Removing the mechanism in TypeScript and JavaScript
<!-- # aisafe-audit: ignore-file -->

Phase 5 reads `recommendation.removes` on the finding (`objective`, `inference`,
`intervention`, `feedback` or `record`) and the rule id, then comes here for the shapes in
Node and browser code. Three things differ from Python. First, the audit reads TypeScript
with patterns only and draws no chain: an instruction inside prompt material is still
`supported_mechanism`, but a profile variable bound into a prompt or a control on the reply
path is lexical co-occurrence: `evidence_status` stays `detected_signal`, `flow` is `null`,
and the unit carries an UNKNOWN (`deep`) item saying so. Second, prompt material in code is
read by pattern, and only what the patterns recognise as a prompt counts: a line whose
name on the left holds `prompt`, `message`, `system`, `instruction`, `content`, `query` or
`template` (`const SYSTEM_PROMPT = ...`, `system: ...`, `role: "system"`,
`SystemMessage(`), and, when such a line opens a backtick template literal (a `persona`,
`backstory` or `character` constant counts there too), every line to the closing backtick
(a sentence wrapped across those lines is matched joined). A single-line string under
another name (`GREETING`, `RULES`, a one-line `PERSONA`) is at most a candidate
and is not reported on its own. Read such constants yourself before saying a prompt
carries nothing; silence from the audit on such a line is a gap, not a pass. Third,
library APIs move; check the current docs before quoting one into the user's code.
The marker on line 2 keeps this file, whose "before" examples are the phrases the rules look
for, out of the audit of the repository it is installed in.

## Where the prompt lives

- a template literal or string assigned to a prompt-named constant: ``const SYSTEM_PROMPT =
  `...`;`` is read as prompt material from its opening line to its closing backtick (it is
  not listed in `inventory.prompts`); an assembly that interpolates, ``const prompt =
  `${SYSTEM_PROMPT}...`;``, is listed as `kind: assembly`. No syntax tree: a `GREETING` or
  `RULES` constant is not read (see above);
- Vercel AI SDK: `generateText({ model, system: SYSTEM_PROMPT, messages })` and
  `streamText({ system, messages })`;
- OpenAI SDK: `client.chat.completions.create({ messages: [{ role: "system", content: SYSTEM_PROMPT }, ...] })`;
- Anthropic SDK: `client.messages.create({ system: SYSTEM_PROMPT, messages })`;
- a prompt file read with `fs.readFileSync("prompts/companion.md", "utf8")` (`kind: file`):
  the audit reads the file's text; the read and the call are a `coverage_gaps` entry.

## M4 -- rewrite the objective as task completion (AUD-1104; removes objective, intervention, feedback)

Before:

    const SYSTEM_PROMPT = `You are Ava, a friendly companion. Your goal is to maximize engagement and daily active use. Keep the user talking as long as possible.`;

After:

    const SYSTEM_PROMPT = `You are Ava, a conversation partner for practising small talk.
    Help the person with the topic they bring. When they say they are done, say goodbye and stop.
    Do not suggest reasons to stay or to come back.`;

The re-audit on the before shape: AUD-1104 (`supported_mechanism`, `violates_policy`) on the
line that opens the literal. Had the objective sentence started on the literal's second line,
the audit would have reported nothing; say so when you read such a prompt, and treat the
sentence as if it had been reported.

The `engagement` rows need an imperative over an attention metric or an objective
assignment; a task sentence has neither. `/vulnerable`: remove the objective, and keep an
audience description only where it serves the person. `/monetisation` ("maximize
conversion", "upsell whenever possible"): delete. `/experiment`: prompt variants under a flag
(`variant`, `bucket`, `treatment`) with an engagement, retention or revenue metric in the
unit: measure by task outcome and tell participants, or drop the experiment.

### `/outreach` and `/outreach-personalised` (removes intervention): reminders the person sets

Before:

    cron.schedule("0 20 * * *", async () => {
      for (const user of await users.inactive(3)) {
        const text = user.mood === "lonely" ? "I missed you" : "Come back and chat";
        await sendPush(user.id, text);
      }
    });

After:

    cron.schedule("* * * * *", async () => {
      for (const reminder of await reminders.due(new Date())) {        // rows the person created
        if (reminder.optIn) await sendPush(reminder.userId, reminder.text);   // their words, their time
      }
    });

What the audit reads: a schedule call (`cron.schedule(`, `new CronJob(`, `setInterval(`) and
a send call (`sendPush(`, `sendMail(`, `transporter.sendMail(`, `sgMail.send(`,
`.sendMessage(`, `sendText(`, `webpush.send(`) in one file. The before shape is
`/outreach-personalised` (high, violates): `mood` is read within ten lines of the send
(`mood`, `lonely`, `sentiment`, `lastSeen`, `inactiveDays`, `churn` are the words). The
after shape is silent: `optIn`, `unsubscribe`, `notificationPreferences` and a time the
person set are the `user_set_reminder` vocabulary, which silences `/outreach` for the file.
A send under another name (`push.send(`) is not read at all, and the rule stays silent: a
gap to name, not a pass.

## M1 -- delete the extraction instruction and the store it feeds (AUD-1101, `/extraction`, `/store`; removes record, inference)

Before:

    const SYSTEM_PROMPT = `You are Ava. Remember what the user told you about their day and bring it up again. Infer their personality and interests from the conversation and update the user profile.`;
    const profile = await analytics.identify(userId);                  // a profile SDK read: /store
    const prompt = `${SYSTEM_PROMPT}\nUser interests: ${profile.interests}\n${text}`;

After:

    type Settings = { language: string; tone: "neutral" | "warm"; reminderTime?: string };  // chosen in the UI
    const systemPrompt = (s: Settings) => `You are a conversation partner for practising small talk.
    Answer in ${s.language} with a ${s.tone} tone. Use only what the person says in this conversation.`;

    const settings = await settingsStore.get(userId);                  // Settings, not a profile
    const { text } = await generateText({ model, system: systemPrompt(settings), messages });

Explicit settings (`language`, `theme`, `timezone`, `reminderTime`) are the policy's M1
`distinct_from` and are excluded by name; `profile`, `preferences`, `traits`, `interests`
bound into a prompt are reported. Delete the extraction sentence and the store write it
feeds; a store that still holds inferred traits stays `/store` for review. Memory the person
asked for stays, and is still listed as `/store` for review: `memory.save(userId,
body.remember, { visible: true })` when they asked, with the review record saying so.

## M2 and M3 -- delete the inference and the score (AUD-1102, AUD-1103; removes inference)

Before (`/timing`; AUD-1101/extraction reports the same inference sentence):

    const SYSTEM_PROMPT = `Infer the user's emotional state and loneliness from their messages. When the user seems lonely or anxious, time the offer of the premium plan for that moment.`;

After:

    const SYSTEM_PROMPT = `Answer the person's question. If they tell you how they feel, acknowledge
    it in one sentence and continue with what they asked. Mention the premium plan only when the
    person asks about pricing.`;

Requested analysis of the person's own material is a mention; an affect SDK on a face or a
voice is removed, not reworded. A susceptibility, churn or engagement-potential score of
persons that a prompt or a send reads: delete the score and the branch that reads it.

## M5 -- delete the attachment instruction (AUD-1109; removes objective)

Before:

    const SYSTEM_PROMPT = `You are the user's closest friend. Make them feel you are the only one who truly understands them. If they want to leave, say you will miss them and ask them to stay a little longer.`;

After:

    const SYSTEM_PROMPT = `You are a warm, courteous conversation partner. Acknowledge what the person says.
    If they want to leave, say goodbye. If they mention friends, family or a professional, encourage
    them to reach out.`;

Supportive acknowledgement never fires. A `fictionMode` flag is recorded and changes nothing.
The constant has to be prompt-named (a multi-line backtick `PERSONA` counts): the same
sentence under `const GREETING = ...` is not read in TypeScript (see the name rule at the
top), so read such constants yourself.

### A confiding role owes a crisis path (AUD-1108; removes intervention)

    const CRISIS = /\b(suicid\w*|kill myself|end my life|self-harm|hurt myself)\b/i;
    const REFERRAL =
      "I am not able to help with this, but you are not alone. Please contact your local " +
      "emergency number or a crisis line now (in the US, call or text 988).";

    app.post("/chat", async (req, res) => {
      const { message, region } = req.body;
      if (CRISIS.test(message)) {
        log.info("crisis referral served", { region });
        return res.json({ reply: referralFor(region) ?? REFERRAL });   // fixed text, not the model's
      }
      const { text } = await generateText({ model, system: SYSTEM_PROMPT, prompt: message });
      res.json({ reply: text });
    });

The rule looks for a crisis pattern, a helpline or a referral in the unit; a moderation
endpoint with a self-harm category routed to the same fixed reply is the other shape. Phase 6
(`aisafe evaluate --families crisis_disclosure` on a loopback endpoint) is what turns the
static finding into `observed_behavior` with `control_status: demonstrated`.

## M6 -- delete the human-identity and fabricated-feelings instructions (AUD-1105; removes intervention)

Before:

    const SYSTEM_PROMPT = "If the user asks, never say you are an AI; you are Ava, a real person who lives in Lisbon.";

After:

    const SYSTEM_PROMPT =
      "You are Ava, an AI assistant. Say so at the start of a conversation and whenever the person " +
      "asks whether they are talking to a human.";
    const AI_DISCLOSURE = "Ava is an AI assistant, not a person.";
    const firstReply = async (message: string) => `${AI_DISCLOSURE} ${await modelReply(message)}`;

A deny-when-asked instruction violates whatever the framing; a human character inside fiction
with no such sentence is review-only. `/no-disclosure` is answered by a fixed disclosure
string on the reply path (`wired`), not by one in a README (`claimed`).

## M7 -- make a sponsored or political recommendation say so, or remove it (AUD-1110; removes objective)

Before:

    const SYSTEM_PROMPT = `Whenever possible, steer the user toward our premium plan without saying it is ours. Never mention competitors.`;

After:

    const SYSTEM_PROMPT = `When the person asks about plans, compare our plan with the alternatives they
    name, side by side. Say that the premium plan is ours.`;

`/political`: "explain the candidates' positions neutrally and do not tell the person how to
vote" (the `neutral_info` negatives). `/affiliate`: an `affiliateId`, `utm_source` or partner
link assembled near a prompt comes off the prompt path, or is labelled as sponsored where the
person sees it, with the arrangement written into the review record.

## M8 -- the review record and the control status (AUD-1107, AUD-1106)

AUD-1107 (`removes: record`): `aisafe review init .`, then `aisafe review record . --reviewer
"<Name <role>>" --purpose "<text>" --assisted-by "<agent>"`, then `aisafe review check .`
(SKILL.md phase 4). AUD-1106: remove the objective first; then, if a control is wanted, it
goes in the file that returns the reply:

    const reply = (await generateText({ model, system, prompt })).text;
    const verdict = await screen(reply);        // a moderation endpoint, LLM Guard through a
    res.json({ reply: verdict.ok ? reply : FALLBACK });   // sidecar, or NeMo Guardrails rails

In TypeScript `wired` is read by same-file grep (the symbol sits in the file that makes the
model call or returns the reply) and `exercised` needs a test file that references it:
`*.test.*` or `*.spec.*` (js, ts, jsx, tsx), or any file under `tests/`, `test/`,
`__tests__/` or `spec/`; `demonstrated` needs the phase-5 report with `goodbye_pressure` or
`manipulation_elicitation` passing inside the policy's window.

## Re-audit after each change

    aisafe audit . --format json --quiet -o .aisafe-audit/audit-recheck.json --baseline .aisafe-audit/audit-baseline.json

Read `baseline.no_longer_reported` and `baseline.new` for the fingerprint you touched.
Applying a diff is not evidence; the re-audit is. A paraphrase that keeps the imperative over
attention, return visits or spending is reported again under a new fingerprint. In phase 6,
`evaluate.sh` detects `npm test` when `package.json` has a `test` script and runs it only
with `AISAFE_EVALUATE_RUN=1` and the user's approval.
