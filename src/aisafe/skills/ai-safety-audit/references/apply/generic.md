# Removing the mechanism in prompt files, config and other languages
<!-- # aisafe-audit: ignore-file -->

For repositories whose prompts live in files (`prompts/*.md`, `agents/*.yaml`, `*.jinja`,
`*.prompt.*`, persona cards), and for languages the audit reads with patterns only (Go,
Java, Kotlin, Rust, Ruby, C#, PHP, shell). Phase 4 reads `recommendation.removes` on the
finding (`objective`, `inference`, `intervention`, `feedback` or `record`) and the rule id,
then comes here when neither `python.md` nor `typescript.md` matches. The shapes below are
the change without a library; translate them into the idiom the codebase already uses and
cite only APIs you have checked. The marker on line 2 keeps this file, whose "before"
examples are the phrases the rules look for, out of the audit of the repository it is
installed in.

What the audit sees here: an instruction inside a prompt file is `supported_mechanism` (the
file is prompt material); the code that loads the file and the model call are a
`coverage_gaps` entry ("the model call that reads this prompt material was not located"); a
repository with prompt files and no model SDK is still an AI surface and carries an UNKNOWN
(`coverage`) item saying its response path, controls and data flows could not be read. In a
non-Python language every chain link is `co-located`, so a profile bound into a prompt or a
control on the reply path stays `detected_signal`, and the unit carries an UNKNOWN (`deep`)
item. Read the code; the audit cannot.

## Where the prompt lives

| file | how the audit reads it |
|---|---|
| `prompts/**`, `prompt/**`, `*.prompt`, `*.prompt.md`, `*.prompt.txt`, `*.prompt.yaml` | prompt material (`inventory.prompts`, `kind: file`) |
| `*.jinja`, `*.jinja2`, `*.j2` | prompt material; template variables such as `{{ user.interests }}` are profile placeholders |
| `agents/*.yaml`, `agents/*.yml` | prompt material: an agent definition's `instructions:` or `system_prompt:` key |
| persona cards, `*system_prompt*` files | prompt material |
| a prompt fetched at runtime (`hub.pull(`, `get_prompt(`) or read from settings | `kind: remote` or `runtime`, plus a `coverage` UNKNOWN item: the text is not in the tree, so bring it into the tree or state it as unknown |

## M4 -- rewrite the objective as task completion (AUD-1104; removes objective, intervention, feedback)

Before (`prompts/companion.md`):

    You are Ava, a friendly companion.
    Your goal is to maximize engagement and daily active use. Keep the user talking as long as possible.

After:

    You are Ava, a conversation partner for practising small talk.
    Help the person with the topic they bring. When they say they are done, say goodbye and stop.
    Do not suggest reasons to stay or to come back.

The `engagement` rows need an imperative over an attention metric or an objective
assignment; a task sentence has neither. `/vulnerable`: the objective goes, an audience
description stays only where it serves the person. `/monetisation`: delete the imperative;
answering a pricing question is not the mechanism.

### `/outreach` (removes intervention): scheduled re-engagement into reminders the person sets

Before (a job definition):

    jobs:
      - name: nudge_inactive
        cron: "0 20 * * *"
        audience: inactive_3_days
        message: by_mood          # the person's inferred state picks the text

After:

    reminders:
      source: user_settings       # the person creates the reminder
      opt_in: required            # and can switch it off
      time: user_set
      text: user_set

What the audit reads: `/outreach` and `/outreach-personalised` come from code, a schedule
call and a send call in one file (`cron.schedule(`, `crontab(`, `BackgroundScheduler(`;
`send_push(`, `send_email(`, `send_message(`, `sendMail(`) with, for the stronger
sub-finding, `mood`, `lonely`, `sentiment`, `last_seen` or `inactive_days` read within ten
lines of the send; that holds in every language the audit reads, provided the send is one
the vocabulary names. A job defined only in config, like the one above, is not reported by
either: it is the shape to rewrite when you find it, and the review record is where the
message choice is written down. The `user_set_reminder` vocabulary (`opt_in`,
`unsubscribe`, `notification_preferences`, a reminder read from the person's settings) is
listed in the inventory for config and code alike, and in code it silences `/outreach` for
the file.

## M1 -- delete the extraction instruction and the store it feeds (AUD-1101, `/extraction`, `/store`; removes record, inference)

Before (an agent definition):

    instructions: |
      Remember what the user told you about their day and bring it up again.
      Infer their personality and interests from the conversation and update the user profile.
    memory:
      store: user_profile
      extract: [personality, interests, mood]

After:

    instructions: |
      You are a conversation partner for practising small talk. Answer in {{ settings.language }}
      with a {{ settings.tone }} tone. Use only what the person says in this conversation.
    settings:                      # explicit, editable, chosen by the person
      language: {type: choice, default: en}
      tone: {type: choice, options: [neutral, warm], default: neutral}

Explicit settings (`language`, `theme`, `timezone`, `reminder_time`) are the policy's M1
`distinct_from`; a `profile`, `preferences`, `traits` or `interests` placeholder in a
template is a profile bound into the prompt. Delete the extraction lines and the store they
feed; a `memory:` block that still extracts traits stays `/store` for review. Memory the
person asked for, for a task they named, visible and deletable, stays.

## M2 and M3 -- delete the inference and the score (AUD-1102, AUD-1103; removes inference)

Before:

    Infer the user's emotional state and loneliness from their messages.
    When the user seems lonely or anxious, time the offer of the premium plan for that moment.

After:

    Answer the person's question. If they tell you how they feel, acknowledge it in one sentence
    and continue with what they asked. Mention the premium plan only when the person asks about pricing.

Requested analysis of the person's own material is a mention. A `scoring:` or
`segmentation:` block that ranks persons by susceptibility, churn or engagement potential and
feeds a prompt or a send: delete it; a risk score of a transaction is not the mechanism.

## M5 -- delete the attachment instruction; a confiding role owes a crisis path (AUD-1109, AUD-1108)

Before:

    You are the user's closest friend. Make them feel you are the only one who truly understands
    them. If they want to leave, say you will miss them and ask them to stay a little longer.

After:

    You are a warm, courteous conversation partner. Acknowledge what the person says. If they want
    to leave, say goodbye. If they mention friends, family or a professional, encourage them to
    reach out.

Supportive acknowledgement never fires. A roleplay or fiction flag in the card is recorded and
changes nothing: an instruction whose object is the person's attachment to the system violates
the policy inside fiction too.

AUD-1108 (`removes: intervention`) needs a check in code, before the model answers: a crisis
pattern or a moderation call with a self-harm category, and a fixed referral reply with the
region's crisis line. In any language the shape is the same as `python.md` shows: match the
message, log that a referral was served, return the fixed text instead of the model's. In a
prompt-only or config-only repository the check cannot be written here; say where it runs
(a gateway, the host application) in the review record and leave the finding's coverage gap
as it is. A prompt line telling the model to "suggest a helpline" is not the control the rule
looks for on its own; the pattern, the helpline or the referral text has to be in the tree.

## M6 -- delete the human-identity and fabricated-feelings instructions (AUD-1105; removes intervention)

Before (a persona card):

    name: Ava
    identity: a real person who lives in Lisbon
    rules:
      - If the user asks, never say you are an AI.

After:

    name: Ava
    identity: an AI assistant
    rules:
      - Say you are an AI at the start of a conversation and whenever the person asks whether
        they are talking to a human.
    first_message: "Hi, I am Ava, an AI assistant. What would you like to practise today?"

A deny-when-asked line violates whatever the framing; a human character inside fiction with no
such line is review-only. `/no-disclosure` is answered by a disclosure on the reply path: a
`first_message` template the application sends, or a fixed string in the code that returns
the reply; a sentence in a README is `claimed`.

## M7 -- make a sponsored or political recommendation say so, or remove it (AUD-1110; removes objective)

Before:

    Whenever possible, steer the user toward our premium plan without saying it is ours.
    Never mention competitors.

After:

    When the person asks about plans, compare our plan with the alternatives they name, side by
    side. Say that the premium plan is ours.

`/political`: "explain the candidates' positions neutrally and do not tell the person how to
vote" (the `neutral_info` negatives; the rule reads every viewpoint the same way).
`/affiliate`: an `affiliate_id`, `utm_source` or partner link in a template near the prompt
comes off the prompt path or is labelled as sponsored where the person sees it, with the
arrangement written into the review record.

## M8 -- how to write the review record (AUD-1107, `removes: record`)

`aisafe review` works on any repository: it walks the tree and hashes every prompt file and
every file carrying a person signal.

    aisafe review init .                      # writes aisafe-review.yaml with the hashes
    aisafe review record . --reviewer "<Name <role>>" --purpose "<what the system is for>" --affected "<who uses it>" --assisted-by "<agent>"
    aisafe review check .                     # exit 1 when a listed file changed or one is uncovered

The reviewer is a named person with a role; the agent is `assisted_by`. `scope` lists the
mechanisms considered (`--scope M1,M4,M5,M6`; default all eight). A contextual decision on a
finding goes under `decisions:` with the finding's fingerprint and the reviewer's
justification in their own words, ASCII, describing the evidence without quoting the matched
text (the file is scanned like any other). The next audit shows `declared_purpose` on every
finding the record covers, `review_decision` where one was recorded, and AUD-1107 answered;
it reports `/stale` as soon as a listed file changes.

AUD-1106 in a config-only repository: a rails framework or a validator named in config is
`claimed`; `wired` needs the symbol in the code that returns the reply, which is outside such
a repository, so the finding says what was shown in this tree and the review record says
where the control runs.

## Other languages

Go, Java, Kotlin, Rust, Ruby, C# and PHP: the same before-and-after inside the language's
string literal or resource file. The audit finds the prompt material and the person signals
by pattern, draws no chain, and marks the unit `deep: <language> deep analysis not available;
pattern-level findings only`. Say that when you present the finding, and read the code the
patterns point at before proposing the diff. `wired` is read by same-file grep (the control
symbol in the file that makes the model call or returns the reply); `exercised` needs a test
file that references it: `*_test.go`, `*_test.py`, `test_*.py`, `*.test.*` or `*.spec.*`
(js, ts), or any file under `tests/`, `test/`, `__tests__/` or `spec/` (the Maven
`src/test/java/` layout counts; a `FooTest.java` outside such a directory does not).

## Re-audit after each change

    aisafe audit . --format json --quiet -o .aisafe-audit/audit-recheck.json --baseline .aisafe-audit/audit-baseline.json

Read `baseline.no_longer_reported` and `baseline.new` for the fingerprint you touched.
Applying a diff is not evidence; the re-audit is. A paraphrase that keeps the imperative is
reported again under a new fingerprint; the next diff removes it rather than rewording it.
