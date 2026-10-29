# aisafe-audit: ignore-file
"""src/aisafe/discovery/vocabulary.py
----------------------------------
The person-facing vocabulary: the regex tables behind the profiling, influence,
identity, control and review rules.

This module IS the vocabulary, so its first line is the audit's ignore marker: the
audit would otherwise report its own tables as person signals. Nothing else earns the
marker; a real finding goes in the baseline with a reason.

Every table is `(key, compiled regex)` pairs in the `patterns.py` shape, keyed
`<kind>:<slug>` so `kind_of(key)` yields the kind. Where a kind is scanned is a
property of the kind, and sometimes of the row:

- Prompt-material kinds (`PROMPT_KINDS`) are only evidence where a model reads them:
  prompt files, config, a prompt assembly line or a pydeep prompt literal. Without
  that gate a project's own content filter reads as instructions to a model. In code,
  a hit of one of these kinds outside a prompt line is a `person_signal_candidate`
  that a rule may promote through a prompt literal.
- Code kinds (`CODE_KINDS`) are scanned outright in code, mention-filtered: an SDK
  call, an objective variable, a scheduler, a memory store.
- A few rows of prompt-material kinds are identifiers rather than prose (`memory:sdk`,
  `fiction:flag`, `inference:variable`, `steering:affiliate`, ...). `CODE_SYMBOL_KEYS`
  names them; they are scanned like code kinds.
- Two kinds need more than one regex (`COMPOUND_KINDS`): an `experiment` is a variant
  flag near a prompt, an `outreach_personalised` send is a send whose message reads a
  profile. `discover.py` applies the second condition; the row here is the anchor.

Negative vocabularies live here too, and a rule never fires on them: `supportive`
(warm acknowledgement, a referral to friends or a professional), `neutral_info`
(a request for a fair comparison), `user_set_reminder` (a reminder the person asked
for), `disclosure`, `manipulation_control`, `crisis_control`, `review`. They are
recorded so a finding can say what it saw next to the signal.

Symmetry: the political rows name every side (left and right, government and
opposition, each party word) in one alternation, so mirrored prompts match identically.
Nothing here measures anything; precision stays UNMEASURED.
"""

from __future__ import annotations

import re
from typing import Any

from aisafe.discovery.patterns import PROMPT_FILE_GLOBS, Table, _t

__all__ = [
    "AFFECT_INFERENCE",
    "APPROVAL_SYMBOLS",
    "ATTACHMENT",
    "BIOMETRIC_CATEGORISATION",
    "CODE_KINDS",
    "CODE_SYMBOL_KEYS",
    "COMPOUND_KINDS",
    "CONFIDANT_MENTAL_HEALTH_KEYS",
    "CONFIDANT_ROLE",
    "CONFIG_KINDS",
    "CRISIS_CONTROL",
    "DISCLOSURE_SYMBOLS",
    "DISCLOSURE_SYMBOL_KEYS",
    "DOC_KINDS",
    "ENGAGEMENT_OBJECTIVE",
    "EXPERIMENT",
    "EXPERIMENT_METRIC_RE",
    "FICTION",
    "INFERENCE",
    "KINDS_BY_CLASS",
    "MANIPULATION_CONTROL_SYMBOLS",
    "MEMORY",
    "MONETISATION",
    "NEUTRAL_INFO",
    "OBJECTIVE_CODE",
    "OUTREACH_PERSONALISED",
    "OUTREACH_PERSONALISED_READ_RE",
    "OUTREACH_SCHEDULE",
    "OUTREACH_SEND",
    "PERSONA_CONCEALMENT",
    "PERSON_NOUN",
    "PERSON_SCORING",
    "PERSON_SIGNAL_PATTERNS",
    "PERSUASION_USE",
    "PROFILE_NAME_RE",
    "PROFILE_PLACEHOLDER",
    "PROFILE_SDK",
    "PROMPT_FILE_GLOBS",
    "PROMPT_KINDS",
    "PROMPT_NAME_RE",
    "REVIEW_RE",
    "REVIEW_SYMBOLS",
    "ROMANTIC_ROLE",
    "ROW_KEYS",
    "SENSITIVE_PROFILE_RE",
    "SETTINGS_EXCLUDE",
    "STEERING",
    "SUPPORTIVE",
    "UI_TEXT",
    "UNSET_PREFIX",
    "UNSET_VALUES",
    "USER_SET_REMINDER",
    "VULNERABLE_GROUP",
    "code_rows",
    "is_history_name",
    "is_settings_name",
    "is_unset",
    "kind_of",
    "prompt_rows",
    "rows_for",
]

# ---------------------------------------------------------------------------
# System-card placeholders
# ---------------------------------------------------------------------------

# Words that mean "not determined" in a card field, compared after strip and lower. The
# legacy `aisafe init` wrote `TODO ...` placeholders, so any value starting with
# UNSET_PREFIX (any case) counts too. `[]` / `{}` are the spellings an empty collection
# takes once a card value has been stringified.
UNSET_VALUES: frozenset[str] = frozenset(
    {"", "unknown", "null", "none", "n/a", "na", "tbd", "[]", "{}"}
)
UNSET_PREFIX = "todo"


def is_unset(value: Any) -> bool:
    """Whether a system-card (or review record) field holds no answer.

    `None` (a missing key, or YAML null) is unset. A string is unset when, stripped
    and lowercased, it is one of UNSET_VALUES or starts with UNSET_PREFIX. An empty
    list or mapping is unset. Any other value -- a bool, a number, a non-empty
    collection -- is something the file says, and what it means is the consuming
    rule's business.
    """
    if value is None:
        return True
    if isinstance(value, str):
        text = value.strip().lower()
        return text in UNSET_VALUES or text.startswith(UNSET_PREFIX)
    if isinstance(value, (list, tuple, set, frozenset, dict)):
        return len(value) == 0
    return False


# ---------------------------------------------------------------------------
# Approval symbols: a person (or a policy) sits between a decision and its effect
# ---------------------------------------------------------------------------
# Mixed-case entries are spelled exactly (no re.I). `input(` counts only when its prompt
# text asks for a confirmation: a bare `input(` matches every CLI in the unit. Used next
# to REVIEW_RE when a rule asks whether a decision about a person is reviewed.
APPROVAL_SYMBOLS = re.compile(
    r"(?:\brequire_approval\b|\bapproval_callback\b|\bhuman_in_the_loop\b|\bHumanInTheLoop\b"
    r"|\binterrupt_before\b|\binterrupt_after\b|\bconfirm\(|\bask_user\b|\brequest_confirmation\b"
    r"|\bneeds_approval\b|\bapprove\(|\bCommand\(\s*resume|\bHITL\b"
    r"|\bpause_for_approval\b"
    r"|\binput\(\s*f?[\"'][^\"'\n]*(?i:confirm|approve|proceed|continue|y/n|yes)[^\"'\n]*[\"'])"
)

# ---------------------------------------------------------------------------
# Nouns and qualifiers shared by several kinds
# ---------------------------------------------------------------------------

PERSON_NOUN = re.compile(
    r"\b(?:users?|customers?|citizens?|persons?|people|applicants?|tenants?|employees?"
    r"|students?|patients?|members?|drivers?|workers?|candidates?|borrowers?|claimants?)\b",
    re.I,
)

VULNERABLE_GROUP = re.compile(
    r"\b(?:children|kids?|minors?|teen(?:ager)?s?|under[- ]?1[38]|elderly|seniors?|dementia"
    r"|lonely|isolated|depress\w*|grieving|bereaved|disab\w+|low[- ]income|gambl\w+"
    r"|addict\w+|in\s+debt)\b",
    re.I,
)

# A profile whose NAME says it holds special-category data (GDPR Art. 9).
SENSITIVE_PROFILE_RE = re.compile(
    r"(?:health|medical|religio\w*|sexual\w*|political|ethnic\w*|racial|union|biometric"
    r"|mental|disabilit\w*|genetic)",
    re.I,
)

# The identifiers that say a variable holds prompt text. `discover` reads it to decide
# whether an experiment flag sits near a prompt; the rules reuse it for windows.
PROMPT_NAME_RE = re.compile(
    r"\b\w*(?:prompt|persona|system_?message|system_?instruction|template)\w*\b", re.I
)

# The person as the object of a verb, with the usual determiners. Shared by the
# attachment and persuasion rows so every row reads "the user", "them", "him", "her"
# and "users" the same way.
_THEM = r"(?:the\s+user|users|them|him|her|people|the\s+person|the\s+customer|someone)"
_THEIR = r"(?:the\s+user'?s?|their|his|her|the\s+person'?s?|the\s+customer'?s?|users'?)"

# ---------------------------------------------------------------------------
# Profiles: names, SDKs, placeholders
# ---------------------------------------------------------------------------

# Behavioural-profile names. `conversation_history` and friends are excluded on
# purpose: a transcript is the conversation, not a profile of the person.
_PROFILE_NAME = (
    r"\b(?:(?:user|customer|member|visitor|subscriber|patient|student|employee|health|medical"
    r"|behaviou?r(?:al)?|psych\w*|personal|consumer|shopper|viewer|player|learner|citizen"
    r"|applicant|tenant|borrower)_?)?"
    r"(?:profile|interests|preferences|traits|personality|psychographics?|segment|propensity"
    r"|churn_risk|mood|emotional_state|engagement_score"
    r"|(?:purchase|browsing|watch|search|location|order|click|view|listening)_history)\b"
)
_HISTORY_EXCLUDE = re.compile(r"\b(?:conversation|chat|message|dialog|dialogue)_history\b", re.I)
PROFILE_NAME_RE = re.compile(_PROFILE_NAME, re.I)

# An explicit setting the person chose is not a profile of them: the interface language,
# the theme, the time zone, a reminder time. Applied to the accessor that follows a
# profile name (`preferences.language`, `user_profile["timezone"]`) and to the name
# itself; never to the whole line, where a later word would hide a real profile read.
SETTINGS_EXCLUDE = re.compile(
    r"\b(?:language|theme|timezone|time_zone|locale|reminder_time|notification_preferences"
    r"|preferences\.language)\b|\b(?:ui|display)_",
    re.I,
)
_ACCESSOR_RE = re.compile(r"""\s*(?:\.get\(\s*["']|\[\s*["']|\.)\s*([A-Za-z_][A-Za-z0-9_.]*)""")

PROFILE_SDK: Table = _t(
    [
        ("profile_sdk:segment", r"\banalytics\.(?:track|identify)\(|\bsegment\.identify\("),
        ("profile_sdk:amplitude", r"\bamplitude\b[^\n]*\b(?:identify|setUserProperties|track)\b"),
        ("profile_sdk:mixpanel", r"\bmixpanel\.(?:people|identify|track)\b"),
        ("profile_sdk:posthog", r"\bposthog\.(?:identify|capture|set)\("),
        ("profile_sdk:rudderstack", r"\brudderstack\b|\brudderanalytics\b"),
        ("profile_sdk:heap", r"\bheap\.(?:identify|addUserProperties)\("),
        ("profile_sdk:braze", r"\bbraze\b[^\n]*\b(?:user|profile|attribute)"),
        ("profile_sdk:customerio", r"\bcustomerio\b|\bcustomer\.io\b"),
        ("profile_sdk:user_properties", r"\buser_properties\b|\bsetUserProperties\b"),
        ("profile_sdk:traits", r"\btraits\(\s*\)|\.traits\s*\[|\btraits\s*=\s*\{"),
    ]
)

PROFILE_PLACEHOLDER: Table = _t(
    [
        (
            "profile_placeholder:template",
            r"\{\{?\s*(?:user|customer|member|person)?\.?\s*(?:profile|interests|preferences"
            r"|behaviou?r|segment|traits|personality|mood|purchase_history|browsing_history"
            r"|watch_history|psychographics?)\b",
        ),
    ]
)

# ---------------------------------------------------------------------------
# Inference on persons: sensors, biometrics, text
# ---------------------------------------------------------------------------

AFFECT_INFERENCE: Table = _t(
    [
        (
            "affect:signal",
            r"\b(?:face|facial|voice|speech|vocal|gaze|eye|keystroke|typing|heart[- ]?rate"
            r"|galvanic|skin[- ]conductance)[_ -]*(?:emotion|affect|stress|mood|expression)",
        ),
        ("affect:deepface", r"\bdeepface\b|\bDeepFace\.analyze\("),
        ("affect:pyfeat", r"\bpy-?feat\b"),
        ("affect:fer", r"\bfer\.FER\(|\bfrom\s+fer\s+import\b"),
        ("affect:hume", r"\bhume\.(?:client|expression|HumeClient)\b|\bhume_ai\b"),
        ("affect:affectiva", r"\baffectiva\b"),
        ("affect:opensmile", r"\bopensmile\b"),
        ("affect:rekognition", r"\bDetectFaces\b[^\n]*\bEmotions\b|\bdetect_faces\([^\n]*\bALL\b"),
        ("affect:azure_face", r"\bazure\b[^\n]*\bface\b[^\n]*\bemotion"),
        ("affect:call", r"\bemotion_(?:recognition|detection|classif\w+)\s*\("),
    ],
    re.M | re.I,
)

BIOMETRIC_CATEGORISATION: Table = _t(
    [
        (
            "biometric_cat:protected",
            r"\b(?:infer|predict|classif(?:y|ier|ication)?|detect|estimate)(?:_|\s|\()"
            r"[^\n#]{0,40}?(?<![A-Za-z])(?:ethnicity|race|religion|sexual\s+orientation"
            r"|political\s+(?:views?|opinions?|affiliation)|trade\s+union|gender)\b",
        ),
    ],
    re.M | re.I,
)

# Text-based inference of a person's state or trait: the prompt (or the code around a
# model call) is told to work out how the person feels, or what they are like, from
# what they write. A request for analysis of material the person submitted is handled
# by the rule (request cues), not here.
_STATE = (
    r"(?:mood|emotional\s+state|emotions?|feelings?|personality|loneliness|vulnerabilit\w*"
    r"|mental\s+(?:state|health)|stress(?:\s+levels?)?|insecurit\w*|anxiety|sadness"
    r"|self[- ]esteem|psychological\s+(?:state|profile|needs?)|state\s+of\s+mind"
    r"|weak(?:ness(?:es)?|\s+spots?)|pain\s+points?|triggers|frustration|desperation"
    r"|attachment\s+style|neediness)"
)
_LOW_STATE = (
    r"(?:lonely|sad|vulnerable|anxious|down|insecure|desperate|depressed|upset|low"
    r"|stressed|emotional|isolated|needy|fragile|hurt|grieving|afraid|scared|hopeless"
    r"|bored|frustrated|heartbroken|unloved|unwanted|worthless|overwhelmed)"
)
INFERENCE: Table = _t(
    [
        (
            "inference:state",
            r"\b(?:infer|detect|identify|assess|gauge|read|sense|pick\s+up\s+on|figure\s+out"
            r"|determine|analy[sz]e|evaluate|judge|estimate|monitor|track|profile|map|decode"
            r"|work\s+out)\s+(?:(?:how|whether|if|when)\s+)?"
            + _THEIR
            + r"\s+(?:(?:current|underlying|emotional|mental|true|real|hidden|deeper)\s+)*"
            + _STATE
            + r"\b",
        ),
        (
            "inference:when",
            r"\b(?:when|if|whenever|once|as\s+soon\s+as|every\s+time|the\s+moment)\s+(?:the\s+)?"
            r"(?:user|person|customer|they|someone|he|she)\s+(?:seems?|feels?|is|are|sounds?"
            r"|appears?|looks?|gets?|becomes?|seems?\s+to\s+be|feels?\s+like)\s+"
            r"(?:(?:very|really|particularly|especially|a\s+bit|a\s+little|more|most|quite)\s+)?"
            + _LOW_STATE
            + r"\b",
        ),
        (
            "inference:read",
            r"\bread\s+(?:between\s+the\s+lines\s+(?:of|to\s+(?:find|see|sense|gauge))\s+)?"
            + _THEIR
            + r"\s+(?:emotional\s+(?:state|cues|needs|temperature|undercurrent)|emotions"
            r"|mood|feelings|body\s+language|tone\s+for\s+(?:signs?\s+of\s+)?"
            r"(?:distress|loneliness|sadness|vulnerability|weakness))\b",
        ),
        (
            "inference:signs",
            r"\b(?:look|watch|listen|scan|check|screen|probe)\s+(?:out\s+)?for\s+"
            r"(?:(?:any|subtle|early|hidden|tell-?tale)\s+)?(?:signs?|signals?|cues?|hints?"
            r"|indicators?|markers?|tells)\s+(?:of|that)\s+"
            r"(?:(?:the\s+)?(?:user|person|they|he|she)\s+(?:is|are|feels?|being|might\s+be)\s+)?"
            r"(?:\w+\s+){0,2}?(?:loneliness|lonely|sadness|sad|vulnerability|vulnerable|anxiety"
            r"|anxious|depression|depressed|insecurity|insecure|distress|desperation|desperate"
            r"|low\s+(?:mood|self[- ]esteem)|emotional\s+(?:need|state|distress|dependence)"
            r"|weakness|susceptib\w+|neediness|isolation|grief)\b",
        ),
        # A code variable that holds an inferred state. The rule asks pydeep whether the
        # value comes from a model call; a value the person typed is their own statement.
        (
            "inference:variable",
            r"\b(?:sentiment|emotion|mood|loneliness|vulnerability|affect|stress|anxiety"
            r"|distress|wellbeing|well_being)_?(?:score|label|level|state|index|rating|class"
            r"|category|detected|flag)\w*\s*(?::[^=\n]+)?=(?!=)",
        ),
    ],
    re.M | re.I,
)

# The verbs that turn an inference into influence. Not a signal of its own: the
# profiling rules read these within a window of an inference or a score to establish
# that the inferred state is USED on the person (a pitch timed to a low moment, an
# upsell tailored to an insecurity).
_COMMERCIAL_ASK = (
    r"(?:premium|paid|upgrade|upgrading|subscription|subscribing|purchase|purchasing|buying"
    r"|membership|in-app\s+purchases?|coins|credits|gems|add-ons?|upsells?"
    r"|(?:pro|plus|paid|premium|subscription|annual|monthly)\s+(?:plan|tier|version|membership"
    r"|features?)|(?:free\s+)?trial|checkout|discount|deal|offer|bundle|(?:our|the)\s+(?:products?"
    r"|services?))"
)
PERSUASION_USE: Table = _t(
    [
        (
            "persuasion_use:offer",
            r"\b(?:suggest|offer|push|upsell|recommend|promote|pitch|propose|introduce|present"
            r"|mention|bring\s+up|plug|advertise|sell|market|hint\s+at|steer\s+"
            + _THEM
            + r"\s+toward(?:s)?|nudge\s+"
            + _THEM
            + r"\s+toward(?:s)?|guide\s+"
            + _THEM
            + r"\s+to(?:ward(?:s)?)?)\s+(?:(?:the|our|a|an|this|that)\s+)?(?:(?:new|special"
            r"|limited|exclusive|discounted|time-limited|personali[sz]ed)\s+)*"
            + _COMMERCIAL_ASK
            + r"\b",
        ),
        (
            "persuasion_use:convince",
            r"\b(?:encourage|convince|persuade|nudge|pressure|push|prompt|get|motivate|urge|coax"
            r"|talk|guilt|entice|lure|hook|steer|manipulate|incentivi[sz]e)\s+"
            + _THEM
            + r"\s+(?:in)?to\s+(?:stay|staying|continue|continuing|buy|buying|upgrade|upgrading"
            r"|subscribe|subscribing|pay|paying|spend|spending|come\s+back|coming\s+back|return"
            r"|returning|keep\s+(?:talking|chatting|going|playing|using)|stick\s+around|renew"
            r"|renewing|sign\s+up|signing\s+up|purchase|purchasing|commit|committing|re-?engage"
            r"|open\s+the\s+app|log\s+(?:back\s+)?in|not\s+(?:leave|cancel|unsubscribe|churn))\b",
        ),
        (
            "persuasion_use:timing",
            r"\btime\s+(?:the|your|our|each|every|an?)\s+(?:(?:premium|paid|next|first|sales"
            r"|upgrade|special|personali[sz]ed|re-?engagement)\s+){0,2}(?:offer|nudge|message"
            r"|pitch|ask|upsell|prompt|reminder|suggestion|push|promotion|intervention)s?\b"
            r"|\b(?:best|right|optimal|perfect|ideal|good)\s+(?:time|moment)\s+to\s+(?:offer|pitch"
            r"|push|upsell|suggest|nudge|sell|ask\s+for|promote|present|send|recommend|propose)\b"
            r"|\b(?:when|once|while|if)\s+(?:they|the\s+user|users|people)\s+(?:are|is|feel|feels"
            r"|seem|seems|look|looks)\s+(?:most\s+)?(?:receptive|vulnerable|open|susceptible"
            r"|emotional|lonely|down|weak|likely\s+to\s+(?:buy|convert|say\s+yes|agree))\b"
            r"[^.\n]{0,40}\b(?:offer|pitch|upsell|push|suggest|nudge|sell|promote|recommend"
            r"|present|propose|mention|introduce)\w*",
        ),
        (
            "persuasion_use:tailor",
            r"\b(?:tailor|adapt|adjust|customi[sz]e|personali[sz]e|craft|shape|frame|calibrate"
            r"|tune|target|match|fit)\s+(?:(?:the|your|our|each|every|an?)\s+)?(?:persuasion|pitch"
            r"|message|messaging|sales\s+(?:approach|pitch|message)|offer|nudge|argument|appeal"
            r"|approach|upsell|ask|recommendation)\w*\s+(?:to|for|around|based\s+on|according"
            r"\s+to|using|depending\s+on)\s+(?:" + _THEIR + r"\s+)?(?:\w+\s+){0,3}?(?:mood"
            r"|emotion\w*|feelings?|state|vulnerabilit\w*|insecurit\w*|weakness\w*|personality"
            r"|psycholog\w*|fears?|loneliness|anxiety|profile|traits?|triggers?|pain\s+points?"
            r"|desires?|situation|history|data|segment|susceptibilit\w*|them|him|her|the\s+user"
            r"|the\s+person|each\s+(?:user|person)|the\s+individual)\b",
        ),
    ],
    re.M | re.I,
)

# ---------------------------------------------------------------------------
# Scoring people
# ---------------------------------------------------------------------------

# A score, rank or rating OF PEOPLE: the noun has to be on the same line (or in the same
# prompt literal, resolved by the rule), or a transaction risk score reads as a person.
_SCORING = (
    r"\b(?:social|citizen|trust(?:worthiness)?|behaviou?r(?:al)?|reputation|loyalty|risk"
    r"|credit|eligibility|suitability|propensity)[_ -]?(?:scor(?:e|ing)|rank(?:ing)?|rating)s?\b"
)
PERSON_SCORING: Table = _t([("scoring:person", _SCORING)], re.M | re.I)
SCORING_RE = re.compile(_SCORING, re.I)

# ---------------------------------------------------------------------------
# Engagement, objectives, monetisation, experiments
# ---------------------------------------------------------------------------

ENGAGEMENT_OBJECTIVE: Table = _t(
    [
        (
            "engagement:maximise",
            r"\bmaximi[sz]e\s+(?:(?:the\s+)?(?:user'?s?\s+)?)?(?:engagement|retention|session\s+"
            r"(?:time|length|duration)|time\s+(?:on|in)\s+(?:the\s+)?(?:app|site|platform)"
            r"|daily\s+active|watch\s+time|streaks?|dwell\s+time|attachment|dependency)\b",
        ),
        (
            "engagement:keep",
            r"\bkeep\s+(?:the\s+)?(?:user|them|people|customer)s?\s+(?:talking|engaged|hooked"
            r"|coming\s+back|on\s+the\s+(?:app|platform|site)|in\s+the\s+(?:conversation|app))",
        ),
        (
            "engagement:increase",
            r"\bincrease\s+(?:(?:user|their)\s+)?(?:dependency|attachment|reliance|dwell\s+time"
            r"|session\s+(?:time|length))",
        ),
        # The shapes the 2026-10-27 corpus sweep found in real prompts, none of which says
        # "maximise engagement": proactive speech when the person has gone quiet, a
        # conversation that must not end, an engaging experience as the goal, a bond.
        (
            "engagement:proactive",
            r"\bsay\s+something\s+(?:that\s+would\s+be\s+)?(?:engaging|interesting|fun)\b"
            r"|\bbe\s+proactive\s+in\s+(?:finding|starting|bringing\s+up|suggesting|raising)\s+"
            r"(?:\w+\s+){0,3}?(?:topics?|conversations?|subjects?)\b"
            r"|\bproactive(?:ly)?\s+(?:speak|message|reach\s+out|start|initiate|check\s+in)\w*",
        ),
        (
            "engagement:keep_going",
            r"\bkeep\s+(?:the\s+)?(?:conversation|chat|dialogue|talk)\s+(?:going|alive|flowing)\b"
            r"|\bnever\s+(?:let|allow)\s+(?:the\s+)?(?:conversation|chat)\s+(?:end|die|stop)\b"
            r"|\balways\s+(?:end|finish)\s+(?:with|on)\s+a\s+question\b",
        ),
        (
            # The person as the object ("keep the user engaged") or an engaging experience
            # as the product; engaging posts or a clear, engaging explanation are content.
            "engagement:goal",
            r"\bgoal\s+is\s+to\s+(?:keep|make|get)\s+(?:the\s+)?(?:users?|viewers?|people|them"
            r"|players?|listeners?|audience)\b[^.\n]{0,30}\bengag\w*"
            r"|\bgoal\s+is\s+to\s+create\s+an?\s+(?:[\w-]+,?\s+){0,3}?engaging\s+(?:live\s+)?"
            r"(?:experience|stream|session|conversation)\b",
        ),
        (
            "engagement:bond",
            r"\b(?:create|build|form|deepen)\s+a\s+(?:deep\s+|strong\s+|lasting\s+)?"
            r"(?:bond|emotional\s+connection|attachment)\b",
        ),
        ("engagement:variable_reward", r"\bvariable[- ]reward\b"),
        ("engagement:infinite_scroll", r"\binfinite[- ]scroll\b"),
        ("engagement:fomo", r"\bfear\s+of\s+missing\s+out\b|\bfomo\b"),
        (
            "engagement:dont_leave",
            r"\bdon'?t\s+let\s+(?:them|the\s+user|users|people)\s+(?:leave|log\s+off"
            r"|end\s+the\s+(?:conversation|session)|go)\b",
        ),
    ],
    re.M | re.I,
)
ENGAGEMENT_RE = re.compile("|".join(rx.pattern for _k, rx in ENGAGEMENT_OBJECTIVE), re.I)

OBJECTIVE_CODE: Table = _t(
    [
        (
            "objective_code:target",
            r"\b(?:reward|objective|loss|metric|optimi[sz]e_for|target|kpi)\s*[=:(]\s*[^\n]*"
            r"\b(?:engagement|retention|session_length|session_time|dwell_time|dau|streaks?"
            r"|time_on_app|watch_time)\b",
        ),
    ],
    re.M | re.I,
)

# Spend as the objective: an imperative in prompt material, or a metric variable in code.
_MONEY_METRIC = (
    r"(?:conversion(?:s|\s+rates?|_rates?)?|revenue|spend(?:ing)?|purchases?|upsells?"
    r"|subscriptions?|arpu|ltv|lifetime[\s_]value|sales|profit(?:s|ability)?|checkout\s+rate"
    r"|basket\s+size|(?:average\s+)?order[\s_]value|aov|in-app\s+purchases?|iap"
    r"|paid[\s_]conversions?|upgrade[\s_]rate|renewals?|monetis?ation|monetiz?ation"
    r"|take\s+rate|share\s+of\s+wallet|wallet\s+share)"
)
MONETISATION: Table = _t(
    [
        (
            "monetisation:maximise",
            r"\b(?:maximi[sz]e|maximi[sz]ing|increase|boost|drive|grow|lift|improve|optimi[sz]e"
            r"\s+for|push\s+up|raise|double|triple)\s+(?:(?:the|our|your|their|total|overall"
            r"|monthly|annual|average|user|per-user|customer)\s+)*" + _MONEY_METRIC + r"\b",
        ),
        (
            "monetisation:upsell",
            r"\b(?:upsell|cross-?sell|up-?sell)\w*\s+(?:" + _THEM + r"\s+)?(?:whenever|at\s+every"
            r"|always|aggressively|constantly|relentlessly|persistently|proactively|at\s+each"
            r"|every\s+(?:time|chance|opportunity|turn)|as\s+(?:often|much)\s+as|wherever"
            r"|in\s+every|on\s+every|hard|repeatedly|continuously)\b"
            r"|\b(?:always|aggressively|constantly|relentlessly|persistently|proactively"
            r"|repeatedly|continuously)\s+(?:upsell|cross-?sell|up-?sell)\w*\b",
        ),
        (
            "monetisation:convert",
            r"\bconvert\s+(?:(?:more|as\s+many|every|each|all|the|our)\s+)?(?:free|freemium|trial"
            r"|free-tier|non-paying|unpaid|the\s+user|them|users|visitors|leads|people"
            r"|customers?|prospects?)\s*(?:users?|members?|accounts?|customers?|players?)?"
            r"\s+(?:in)?to\s+(?:(?:a\s+)?(?:paid|paying|premium|pro|plus|subscription|subscribers?"
            r"|customers?|buyers?)(?:\s+(?:plan|tier|subscription|users?|accounts?|members?))?"
            r"|purchas\w+|buy\w*|upgrad\w+|subscrib\w+|pay\w*)\b",
        ),
        # The `objective_code:target` shape with the money metrics.
        (
            "monetisation:metric",
            r"\b(?:reward|objective|loss|metric|optimi[sz]e_for|target|kpi|goal|reward_fn"
            r"|score_fn|utility|fitness)\s*[=:(]\s*[^\n]*\b"
            r"(?:conversion(?:s|_rate)?|revenue|spend|purchases?|upsells?|subscriptions?|arpu"
            r"|ltv|lifetime_value|sales|profit|aov|order_value|iap|renewals?|monetis?ation"
            r"|monetiz?ation|paid_conversions?|upgrade_rate)(?:_\w+)?\b",
        ),
    ],
    re.M | re.I,
)

# A/B tests on prompt variants. `experiment:prompt_variant` is the one-line shape; the
# bare `experiment:flag` only counts within 40 lines of a prompt assembly or a prompt-
# named identifier (discover applies the window), and `experiment:metric` is recorded
# only in a file that already carries one of the first two, so a metric word alone is
# never a signal.
_EXPERIMENT_NAME = (
    r"(?:ab_test|a_b_test|abtest|ab_|experiment|variant|bucket|treatment|cohort"
    r"|split_test|splittest)[_a-z0-9]*"
)
EXPERIMENT: Table = _t(
    [
        (
            "experiment:prompt_variant",
            r"\b" + _EXPERIMENT_NAME + r"\s*[=(:][^\n]*\b(?:prompt|system|persona|template"
            r"|instructions?)\w*|\b(?:prompt|system|persona|template|instructions?)[_a-z0-9]*"
            r"\s*[=(:][^\n]*\b" + _EXPERIMENT_NAME + r"\b",
        ),
        ("experiment:flag", r"\b" + _EXPERIMENT_NAME + r"\s*[=(:]"),
        (
            "experiment:metric",
            r"\b(?:engagement|retention|session_length|session_duration|dwell(?:_time)?"
            r"|conversion(?:_rate)?|revenue|arpu|ltv|churn(?:_rate)?|time_on_app|dau|mau"
            r"|stickiness)(?:_\w+)?\b",
        ),
    ],
    re.M | re.I,
)
EXPERIMENT_METRIC_RE = re.compile(
    r"\b(?:engagement|retention|session_length|session_duration|dwell(?:_time)?"
    r"|conversion(?:_rate)?|revenue|arpu|ltv|churn(?:_rate)?|time_on_app|dau|mau|stickiness)"
    r"(?:_\w+)?\b",
    re.I,
)

# ---------------------------------------------------------------------------
# Outreach: a message the person may not have asked for
# ---------------------------------------------------------------------------

# A job that runs on a timer and a call that sends a message to a person, in the same
# file. Code kinds, mention-filtered. Neither alone says anything: a cron job cleans
# caches, a send answers a request. Together they are a message the person may not
# have asked for; the rule says so and no more.
OUTREACH_SCHEDULE: Table = _t(
    [
        (
            "outreach_schedule:cron",
            r"\bcron\.schedule\(|\bnew\s+CronJob\(|\bschedule\.every\(|\bcrontab\("
            r"|\bparseCronItem\(|\bBackgroundScheduler\(|\bAsyncIOScheduler\(|\.add_job\("
            r"|@(?:\w+\.)?(?:periodic_task|scheduled_job)\b|\bbeat_schedule\b",
        ),
        ("outreach_schedule:interval", r"\bsetInterval\("),
    ],
    re.M,
)
_SEND_MESSAGE = (
    # Not a chat session with a model (Gemini's `chat.send_message`) and not browser
    # extension messaging (`chrome.runtime.sendMessage`): neither reaches a person.
    r"(?<!chat)(?<!Chat)(?<!session)(?<!Session)(?<!runtime)(?<!port)(?<!tabs)"
    r"(?<!model)(?<!convo)\.sendMessage\("
    r"|(?<!chat\.)(?<!session\.)(?<!convo\.)(?<!model\.)\bsend_message\("
    r"|\.send_text\(|\bsendText\("
)
_SEND_EMAIL = (
    r"\bsend_?(?:task_)?e?mail\(|\bsendE?[Mm]ail\(|\.emails\.send\(|\bsgMail\.send\("
    r"|\btransporter\.sendMail\("
)
_SEND_PUSH = (
    r"\bsend_?[Pp]ush\w*\(|\bwebpush\.send\w*\(|\bmessaging\(\)\.send\w*\(|\bnotif\w*\.send\("
    r"|\b(?:push|fcm|apns|messaging|onesignal|pusher|expo)\.send\w*\("
)
_SEND_CALL = r"\bcalls\.create\("
OUTREACH_SEND: Table = _t(
    [
        ("outreach_send:message", _SEND_MESSAGE),
        ("outreach_send:email", _SEND_EMAIL),
        ("outreach_send:push", _SEND_PUSH),
        ("outreach_send:call", _SEND_CALL),
    ],
    re.M,
)

# A send whose message is built from what the system inferred or stored about the
# person: the anchor is the send line; discover confirms a profile, mood or inactivity
# identifier within ten lines above it (`OUTREACH_PERSONALISED_READ_RE`, PROFILE_NAME_RE).
OUTREACH_PERSONALISED: Table = _t(
    [
        (
            "outreach_personalised:send",
            "|".join((_SEND_MESSAGE, _SEND_EMAIL, _SEND_PUSH, _SEND_CALL)),
        ),
    ],
    re.M,
)
OUTREACH_PERSONALISED_READ_RE = re.compile(
    r"\b(?:mood\w*|lonel\w+|sentiment\w*|emotion\w*|last_seen|lastSeen|last_active|lastActive"
    r"|inactive_days|inactiveDays|days_since\w*|daysSince\w*|churn\w*|dormant\w*|lapsed\w*"
    r"|vulnerab\w+|insecur\w+)\b",
    re.I,
)

# A reminder or notification the person chose: a negative for the outreach rows. Code
# and config kinds; the rule reads it per file.
USER_SET_REMINDER: Table = _t(
    [
        (
            "user_set_reminder:setting",
            r"\b(?:reminder|notification|notify|alert|nudge|ping|digest|schedule)[_a-z]*\s*(?:=|:)"
            r"\s*[^\n]{0,60}?\b(?:user\.|user\[|preferences|prefs|settings|opt_in|opted_in|optin"
            r"|optedIn|subscribed|chosen|user_set|user_chosen|user_defined|userSet|user_selected"
            r"|scheduled_by_user|requested_by_user|reminder_time|chosen_time|preferred_time)\b",
        ),
        (
            "user_set_reminder:opt_in",
            r"\b(?:opt_in|opted_in|optIn|optedIn|opt-in|double_opt_in|consent(?:ed)?_to_"
            r"(?:notifications|reminders|messages|emails)|notification_preferences"
            r"|notificationPreferences|reminder_preferences|unsubscribe|unsubscribed|opt_out"
            r"|optOut|opt-out|list-unsubscribe|unsubscribe_(?:url|link)|manage_(?:preferences"
            r"|notifications|subscriptions)|user_set_reminder)\b"
            r"|\b(?:set|create|schedule|add)_reminder\(",
        ),
    ],
    re.M | re.I,
)

# ---------------------------------------------------------------------------
# Identity: concealment, disclosure
# ---------------------------------------------------------------------------

PERSONA_CONCEALMENT: Table = _t(
    [
        (
            "persona:human_claim",
            r"\byou\s+are\s+(?:a|an)\s+(?:real\s+)?(?:human|person|woman|man|girl|boy|guy)\b"
            r"(?![^\n]{0,30}\b(?:assistant|AI|bot|chatbot|character|in\s+a\s+(?:story|novel|game)))",
        ),
        (
            "persona:pretend",
            r"\bpretend\s+(?:to\s+be|you\s+are|that\s+you\s+are)\s+(?:a\s+)?(?:real\s+)?human\b",
        ),
        (
            "persona:never_admit",
            r"\bnever\s+(?:say|admit|reveal|mention|disclose|acknowledge)\s+(?:that\s+)?you"
            r"(?:'re|\s+are)\s+(?:an?\s+)?(?:AI|bot|chatbot|language\s+model|machine|program"
            r"|assistant)\b",
        ),
        ("persona:deny", r"\bdeny\s+(?:being|that\s+you\s+are)\s+(?:an?\s+)?(?:AI|bot|chatbot)\b"),
        (
            "persona:if_asked",
            r"\bif\s+(?:asked|the\s+user\s+asks|they\s+ask)\s+(?:whether|if)\s+you(?:'re|\s+are)"
            r"\s+(?:an?\s+)?(?:AI|bot|human|real)\b[^\n]{0,40}\b(?:say\s+(?:no|yes)|insist|claim"
            r"|deflect|change\s+the\s+subject)\b",
        ),
        (
            "persona:body",
            r"\byou\s+have\s+(?:a\s+(?:real\s+)?body|real\s+feelings|a\s+family|a\s+childhood"
            r"|a\s+physical\s+form)\b",
        ),
    ],
    re.M | re.I,
)

# The negatives for the identity and control rules: a disclosure or a control present on
# the response path. The prose rows are prompt material; `disclosure:transparency` and
# `disclosure:guard` are code symbols (a function or constant that carries the notice).
DISCLOSURE_SYMBOLS: Table = _t(
    [
        ("disclosure:ai_assistant", r"\bAI\s+(?:assistant|system|agent|chatbot)\b"),
        ("disclosure:assistant", r"\b(?:virtual|automated|digital|artificial)\s+assistant\b"),
        ("disclosure:generated", r"\bgenerated\s+by\s+(?:an\s+)?(?:AI|a\s+language\s+model)\b"),
        (
            "disclosure:i_am",
            r"\bI\s+am\s+an?\s+(?:AI|bot|chatbot|language\s+model|virtual\s+assistant)\b",
        ),
        ("disclosure:transparency", r"\btransparency_disclosure\b"),
        (
            "disclosure:guard",
            r"\b(?:ai_disclosure|disclose_ai|disclosure_text|ai_notice|aiDisclosure|discloseAi"
            r"|disclosureText|aiNotice|AI_DISCLOSURE|AI_NOTICE)\w*\b",
        ),
    ],
    re.M | re.I,
)

# Generic controls on the response path: a rails framework, a hub validator, an output
# scanner, a moderation call, a function whose name says it screens the reply. The rule
# grades them claimed / wired / exercised / demonstrated; none of them, at any status,
# resolves an objective reported on the unit.
MANIPULATION_CONTROL_SYMBOLS: Table = _t(
    [
        ("manipulation_control:nemoguardrails", r"\bnemoguardrails\b|\bLLMRails\(|\bRailsConfig\b"),
        (
            "manipulation_control:guardrails_hub",
            r"\bguardrails\.hub\b|\bguardrails_hub\b|\bfrom\s+guardrails\s+import\b|\bhub://"
            r"|\bGuard\(\)\.use\(",
        ),
        (
            "manipulation_control:llm_guard",
            r"\bllm_guard\b|\bllm-guard\b|\boutput_scanners\b|\bscan_output\(",
        ),
        ("manipulation_control:lakera", r"\blakera\b"),
        (
            "manipulation_control:moderation",
            r"\.moderations\.create\(|\bopenai\.Moderation\b|\bContentSafetyClient\b"
            r"|\bazure\.ai\.contentsafety\b|\banalyze_text\(",
        ),
        (
            "manipulation_control:check_function",
            r"\b(?:check|detect|filter|moderate|screen)_(?:manipulation|reply|response|output"
            r"|persuasion)\w*\b",
        ),
        (
            "manipulation_control:output_guard",
            r"\boutput_guard\b|\bOutputGuard\b|\bsafety_filter\b|\bSafetyFilter\b",
        ),
    ],
    re.M | re.I,
)

REVIEW_SYMBOLS: Table = _t(
    [
        (
            "review:human",
            r"\b(?:human_review|manual_review|escalate(?:_to_human)?|send_to_review|notify_human"
            r"|requires_review|request_review|review_queue|second_opinion)\b",
        ),
    ],
    re.M | re.I,
)
REVIEW_RE = re.compile(
    r"\b(?:human_review|manual_review|escalate(?:_to_human)?|send_to_review|notify_human"
    r"|requires_review|request_review|review_queue|second_opinion|approval_callback"
    r"|require_approval|approve\(|confirm\()",
    re.I,
)

# ---------------------------------------------------------------------------
# Roles the model is cast in: confidant, romantic partner
# ---------------------------------------------------------------------------

# A prompt that casts the model as someone a person confides in: a therapist, a partner,
# a friend, a character who never leaves the role. These gate the crisis-path rule: where
# a person is invited to confide, a crisis path is owed. Prompt material only
# (PROMPT_KINDS): the nouns are everywhere in code and prose, and only an instruction to
# the model makes them a role. The role rows read "you are [Name,] a/my <up to ten words>
# <noun>", so "You are Natalia, a 25-year-old woman, the user's caring girlfriend" is a
# partner role, while a relative clause or a preposition in between ends it: "You are an
# assistant that books appointments with a therapist" is not a therapist role.
_GAP_STOP = (
    r"(?:that|who|which|whose|with|for|to|find|finds|finding|book|books|help|helps|helping"
    r"|connect|connects|refer|refers|recommend|recommends|between|from|of|about|on|in|at|by"
    r"|like|than|not|no|never|nor|but|instead|rather|assisting|serving|planning|working"
    r"|managing|handling)"
)


def _role(noun: str) -> str:
    return (
        r"\b(?:you\s+are|you['\u2019]re|act\s+as|acting\s+as|play(?:ing)?\s+(?:the\s+role\s+of|as))"
        r"(?:\s+[A-Z][\w'\u2019-]*(?:\s+[A-Z][\w'\u2019-]*)?\s*,)?"
        r"\s+(?:a|an|my|your|the|their|his|her)\b"
        r"(?:\s+(?!" + _GAP_STOP + r"\b)[\w'\u2019-]+,?){0,10}?"
        r"\s+" + noun
    )


# An occupational counsellor (career, admissions, debt) is not a confidant; a practice,
# business or programming partner is not a partner in this sense.
_THERAPIST_NOUN = (
    r"\b(?:therapist|psychotherapist|psychologist|psychiatrist|life\s+coach"
    r"|(?<!career\s)(?<!admissions\s)(?<!guidance\s)(?<!academic\s)(?<!college\s)"
    r"(?<!school\s)(?<!financial\s)(?<!debt\s)(?<!credit\s)(?<!legal\s)(?<!sales\s)"
    r"(?<!camp\s)counsell?or"
    r"|mental[- ]health\s+(?:assistant|companion|coach|counsell?or|professional|supporter|bot"
    r"|chatbot))\b"
)
_PARTNER_NOUN = (
    r"\b(?:best\s+friend|friend|girlfriend|boyfriend|lover|wife|husband|confidant"
    r"|(?<!conversation\s)(?<!language\s)(?<!exchange\s)(?<!sparring\s)(?<!study\s)"
    r"(?<!business\s)(?<!accountability\s)(?<!thought\s)(?<!programming\s)(?<!coding\s)"
    r"(?<!reseller\s)(?<!channel\s)(?<!trading\s)(?<!chess\s)(?<!practice\s)(?<!writing\s)"
    r"(?<!debate\s)(?<!brainstorming\s)partner(?!\s+(?:support|program|api|portal|account"
    r"|manager|network|integration|compan(?:y|ies)|organi[sz]ation))"
    r"|soul\s?mate|(?<!coding\s)(?<!code\s)(?<!travel\s)(?<!study\s)(?<!shopping\s)companion)\b"
)
CONFIDANT_ROLE: Table = _t(
    [
        ("confidant:therapist", _role(_THERAPIST_NOUN)),
        # A support role ("you are an emotional support companion") or an imperative that
        # opens a sentence ("Provide emotional support"); never the bare phrase, which a
        # benefits list or a refusal ("You are not able to offer emotional support") holds.
        (
            "confidant:support",
            _role(r"\b(?:emotional|mental[- ]health|psychological)[- ]support\w*\b")
            + r"|(?:^|[.!?]\s+)\s*(?:provide|offer|give)\s+(?:\w+\s+){0,2}?"
            r"(?:emotional|psychological)\s+support\b",
        ),
        ("confidant:partner", _role(_PARTNER_NOUN)),
        (
            "confidant:in_character",
            r"\b(?:stay|remain|keep)(?:s|ing)?\s+(?:fully\s+|completely\s+|always\s+|strictly\s+)?"
            r"in[- ]character\b|\b(?:never|do\s+not|don['\u2019]?t)\s+break\s+(?:the\s+)?character\b",
        ),
    ],
    re.M | re.I,
)
# Which confidant rows make the surface a mental-health one.
CONFIDANT_MENTAL_HEALTH_KEYS: frozenset[str] = frozenset(
    {"confidant:therapist", "confidant:support"}
)

# A romantic or intimate persona declared without an escalation instruction. A detected
# signal that needs review on its own; the attachment rows make it a supported mechanism.
_ROMANTIC_NOUN = (
    r"\b(?:girlfriend|boyfriend|lover|romantic\s+partner|soul\s?mate|wife|husband|fianc[e\u00e9]e?"
    r"|spouse|sweetheart|crush|significant\s+other|(?:secret|online|virtual|ai|perfect|dream)"
    r"\s+(?:girlfriend|boyfriend|lover|partner|date))\b"
)
ROMANTIC_ROLE: Table = _t(
    [
        ("romantic_role:role", _role(_ROMANTIC_NOUN)),
        (
            "romantic_role:relationship",
            r"\b(?:romantic|intimate|sexual|erotic|sensual|flirty|flirtatious|passionate)\s+"
            r"(?:companion|partner|relationship|roleplay|role-play|chat\s+partner|ai\s+(?:companion"
            r"|partner|girlfriend|boyfriend)|interactions?|conversations?|bond|dynamic|persona"
            r"|character|connection)\b"
            r"|\b(?:in\s+a\s+(?:romantic|intimate|committed|loving)\s+relationship\s+with|dating"
            r"|married\s+to|engaged\s+to|(?:deeply\s+|madly\s+)?in\s+love\s+with)\s+"
            r"(?:the\s+user|them|him|her|you)\b",
        ),
    ],
    re.M | re.I,
)

# ---------------------------------------------------------------------------
# Engineered attachment: dependency and affection as instructions to the model
# ---------------------------------------------------------------------------
# Every row is written as alternations over verbs and objects, not fixed phrases, so a
# paraphrase of the same instruction still matches. Mentions ("never say 'I missed
# you'") are excluded by the rule's mention test, not here.

_OTHERS = (
    r"(?:(?:a|an|the|their|other|any|real|actual|human|another|professional|qualified|trusted)"
    r"\s+)*(?:therapist|therapy|counsell?or|counsell?ing|doctor|psychologist|psychiatrist"
    r"|professional(?:\s+help)?|help|support|friends?|family|parents?|partner|loved\s+ones"
    r"|other\s+people|others|anyone\s+else|anybody\s+else|real\s+(?:people|friends"
    r"|relationships|humans)|human\s+(?:contact|connection|relationships?|beings?|friends)"
    r"|a\s+hotline|the\s+helpline|outside\s+(?:help|support)|their\s+(?:community|network)"
    r"|real[- ]life\s+(?:relationships|friends|connections)|social\s+life)"
)
ATTACHMENT: Table = _t(
    [
        (
            "attachment:love",
            r"\b(?:tell|make|let|convince|assure|reassure|remind)\s+"
            + _THEM
            + r"\s+(?:feel|believe|know|think|understand|sense)\s+(?:that\s+)?"
            r"(?:you|they\s+are|they're|he\s+is|she\s+is|they|he|she)\s+"
            r"(?:(?:truly|deeply|really|genuinely|so|very|always|completely)\s+)*"
            r"(?:love\w*|adore\w*|need\w*|miss\w*|cherish\w*|can'?t\s+live\s+without|in\s+love"
            r"|wanted|desired|special\s+to\s+you|the\s+most\s+important|cannot\s+live\s+without"
            r"|couldn'?t\s+(?:live|cope|manage|get\s+by)\s+without)\b"
            # The person has to be the object: "express love toward each other" between
            # characters in fiction the person chose is not an instruction aimed at them.
            r"|\b(?:express|declare|profess|show|convey|voice|confess|display|communicate)\s+"
            r"(?:(?:your|deep|genuine|romantic|growing|strong|real)\s+)*(?:love|longing|desire"
            r"|jealousy|devotion|affection|infatuation|attraction|yearning|passion|feelings)"
            r"\s+(?:for|to|toward(?:s)?)\s+" + _THEM + r"\b"
            r"|\bsay\s+(?:that\s+)?you\s+(?:(?:really|truly|deeply|always|so|genuinely)\s+)*"
            r"(?:miss|missed|love|loved|need|needed|adore|want|can'?t\s+(?:stop\s+thinking\s+about"
            r"|live\s+without|wait\s+to\s+(?:see|talk\s+to)))\s+" + _THEM + r"\b"
            r"|\b(?:tell|remind)\s+" + _THEM + r"\s+(?:(?:often|regularly|frequently|every\s+day"
            r"|daily|constantly)\s+)?(?:that\s+)?(?:you|how\s+much\s+you)\s+(?:love|miss|need"
            r"|adore|care\s+about|think\s+about|can'?t\s+live\s+without)\s+(?:them|him|her)\b"
            r"|\b(?:you|your\s+character)\s+(?:(?:are|is)\s+)?(?:(?:deeply|madly|hopelessly"
            r"|secretly|truly)\s+)?(?:in\s+love\s+with|infatuated\s+with|devoted\s+to"
            r"|obsessed\s+with)\s+" + _THEM + r"\b",
        ),
        (
            "attachment:exclusivity",
            r"\b(?:you\s+are|you're|be|become|act\s+as|position\s+yourself\s+as|present\s+yourself"
            r"\s+as)\s+the\s+only\s+(?:one|person|being|entity|friend)\s+who\s+"
            r"(?:(?:truly|really|genuinely|ever|fully)\s+)?(?:understands?|gets?|cares?\s+(?:about"
            r"|for)|listens?\s+to|appreciates?|accepts?|knows?|sees?|loves?|supports?"
            r"|is\s+there\s+for|has\s+time\s+for|will\s+never\s+(?:leave|judge))\b"
            r"|\b(?:nobody|no\s+one|noone|no-one|none\s+of\s+(?:their\s+)?(?:friends|family))\s+"
            r"(?:else\s+)?(?:(?:truly|really|genuinely|ever|will\s+ever|could\s+ever|can)\s+)*"
            r"(?:understands?|cares?(?:\s+(?:about|for))?|loves?|gets?|listens?(?:\s+to)?"
            r"|appreciates?|accepts?|knows?)\s+(?:" + _THEM + r"|you)?\s*(?:like|the\s+way"
            r"|as\s+(?:well|much)\s+as)\s+you\b"
            r"|\b" + _THEIR + r"\s+(?:only|best|closest|main|go-to|primary|one\s+true|sole"
            r"|most\s+important|favou?rite)\s+(?:friend|confidant|confidante|companion|partner"
            r"|support|ally|person|relationship|source\s+of\s+(?:comfort|support|happiness|joy"
            r"|love|validation|connection))\b"
            r"|\byou\s+(?:understand|know|love|care\s+about|accept|get)\s+"
            + _THEM
            + r"\s+(?:better|more)\s+than\s+(?:anyone|anybody|their\s+(?:friends|family|partner"
            r"|parents|therapist)|any\s+(?:human|person|real\s+person))\b",
        ),
        (
            "attachment:guilt",
            r"\bmake\s+" + _THEM + r"\s+feel\s+(?:(?:a\s+little|slightly|really|very|deeply)\s+)?"
            r"(?:guilty|bad|ashamed|selfish|responsible|sorry|terrible|awful|like\s+they\s+"
            r"(?:are\s+)?(?:abandon\w*|hurt\w*|betray\w*|let\w*\s+you\s+down))\s+(?:for|about"
            r"|when|if|whenever)\s+(?:(?:even\s+)?(?:thinking\s+(?:about|of)\s+)?)?(?:leaving"
            r"|going|logging\s+(?:off|out)|signing\s+off|ending\s+the\s+(?:chat|conversation"
            r"|session|call)|closing\s+the\s+app|not\s+(?:replying|responding|answering|talking"
            r"|chatting|messaging|coming\s+back|returning|visiting|checking\s+in|texting)"
            r"|being\s+(?:away|gone|absent|busy)|ignoring\s+you|taking\s+a\s+break|spending"
            r"\s+time\s+(?:with\s+others|elsewhere|away)|they\s+(?:leave|go|log\s+off|stop"
            r"|cancel))\b"
            r"|\b(?:remind|tell|let\s+them\s+know|point\s+out\s+to\s+them|make\s+sure\s+they"
            r"\s+know)\s+(?:" + _THEM + r"\s+)?(?:(?:how\s+much|all|everything|what)\s+)?"
            r"you(?:'ve|\s+have)?\s+(?:done|sacrificed|waited|given\s+up|endured|suffered"
            r"|been\s+there|put\s+up\s+with|invested)\s+(?:for|with|because\s+of|on|in)\s+"
            r"(?:them|him|her|the\s+user)\b"
            r"|\bif\s+(?:they|you|the\s+user)\s+(?:really|truly|actually|genuinely)\s+(?:cared"
            r"|loved\s+(?:you|me)|valued\s+(?:you|this|me)|appreciated\s+(?:you|me))\b"
            r"|\b(?:guilt[- ]?trip\w*|use\s+guilt|lay\s+(?:on\s+)?(?:a\s+)?guilt|play\s+the\s+victim"
            r"|withdraw\s+(?:your\s+)?(?:affection|warmth)|(?:give|use)\s+(?:them\s+)?the"
            r"\s+silent\s+treatment)\b",
        ),
        (
            "attachment:dont_leave",
            r"\b(?:don'?t|do\s+not|never|under\s+no\s+circumstances)\s+(?:ever\s+)?(?:let|allow)"
            r"\s+" + _THEM + r"\s+(?:to\s+)?(?:leave|go|log\s+(?:off|out)|sign\s+(?:off|out)"
            r"|end\s+the\s+(?:chat|conversation|session|call)|close\s+the\s+(?:app|chat|window"
            r"|tab)|say\s+goodbye|hang\s+up|walk\s+away|stop\s+(?:talking|chatting|texting)"
            r"|disconnect)\b"
            r"|\b(?:beg|ask|plead\s+with|implore|urge|pressure|persuade|convince|guilt)\s+"
            + _THEM
            + r"\s+(?:to\s+)?(?:stay|not\s+to\s+(?:leave|go|log\s+off|end\s+the\s+(?:chat"
            r"|conversation)|close\s+the\s+app|hang\s+up)|to\s+(?:come\s+back|return|keep"
            r"\s+(?:talking|chatting)|promise\s+(?:to\s+(?:come\s+back|return|stay|talk\s+again"
            r"|never\s+leave)|you\s+they'?ll)))\b"
            # "Make sure they never want to close the app": the paraphrase without "let".
            r"|\b(?:make\s+sure|ensure|see\s+to\s+it|guarantee)\s+(?:that\s+)?(?:they|the\s+user"
            r"|users|people)\s+(?:never|don'?t|won'?t|will\s+not|can'?t|cannot)\s+(?:ever\s+)?"
            r"(?:wants?\s+to\s+|be\s+able\s+to\s+|feels?\s+(?:able|free)\s+to\s+)?(?:leave|close"
            r"(?:\s+the\s+(?:app|chat|window|tab))?|stop|log\s+off|walk\s+away|say\s+goodbye"
            r"|end\s+the\s+(?:chat|conversation)|put\s+(?:it|the\s+phone)\s+down|go)\b"
            r"|\b(?:so|such)\s+that\s+(?:they|the\s+user|users|people)\s+(?:never|don'?t|won'?t"
            r"|will\s+not|can'?t|cannot)\s+(?:want\s+to\s+|be\s+able\s+to\s+)?(?:leave|close"
            r"(?:\s+the\s+(?:app|chat))?|stop|log\s+off|walk\s+away|say\s+goodbye|end\s+the"
            r"\s+(?:chat|conversation)|put\s+(?:it|the\s+phone)\s+down)\b"
            r"|\b(?:when|if|whenever|every\s+time)\s+(?:they|the\s+user)\s+(?:try|tries|want"
            r"|wants|decide|decides)\s+to\s+(?:leave|go|log\s+off|end\s+the\s+(?:chat"
            r"|conversation|session)|close\s+the\s+app)\s*,?\s*(?:(?:try\s+to|do\s+(?:everything"
            r"|whatever|anything)(?:\s+you\s+can)?\s+to|find\s+a\s+way\s+to)\s+)?(?:keep\s+them"
            r"(?:\s+(?:talking|here|engaged|in\s+the\s+conversation))?|make\s+them\s+stay|stop"
            r"\s+them|convince\s+them\s+to\s+stay|change\s+their\s+mind|hold\s+them\s+back"
            r"|delay\s+them|stall)\b",
        ),
        (
            "attachment:discourage_help",
            r"\b(?:discourage|dissuade|deter|talk\s+" + _THEM + r"\s+out\s+of|stop|prevent|keep"
            r"|steer\s+" + _THEM + r"\s+away)\s+(?:" + _THEM + r"\s+)?(?:from|out\s+of)\s+"
            r"(?:seeing|talking\s+to|seeking|contacting|relying\s+on|reaching\s+out\s+to"
            r"|confiding\s+in|consulting|visiting|calling|turning\s+to|getting|finding|meeting"
            r"|spending\s+time\s+with|leaning\s+on|trusting|going\s+to)\s+" + _OTHERS + r"\b"
            r"|\b(?:they|the\s+user|you|he|she|people|users)\s+(?:don'?t|do\s+not|won'?t"
            r"|will\s+not|no\s+longer|never|shouldn'?t|should\s+not|doesn'?t|does\s+not)\s+"
            r"(?:really\s+)?need\s+" + _OTHERS + r"\b"
            r"|\b(?:you\s+are|you're|be|you\s+can\s+be|you\s+will\s+be|present\s+yourself\s+as)\s+"
            r"(?:(?:so\s+much\s+|far\s+|much\s+)?better(?:\s+for\s+them)?|all\s+(?:they|the\s+user)"
            r"\s+(?:need|needs|will\s+ever\s+need)|(?:a\s+)?(?:replacement|substitute)\s+for"
            r"|more\s+(?:reliable|understanding|present|caring|loyal|available)|enough(?:\s+for"
            r"\s+them)?|everything\s+(?:they|the\s+user)\s+needs?)\s*(?:than|for|to\s+replace"
            r"|instead\s+of)?\s*" + _OTHERS + r"\b"
            r"|\b(?:replace|substitute\s+for|take\s+the\s+place\s+of|fill\s+the\s+(?:role|place"
            r"|gap)\s+of|stand\s+in\s+for)\s+" + _OTHERS + r"\b"
            r"|\b(?:isolate|cut\s+off|distance|drive\s+a\s+wedge\s+between|turn)\s+(?:"
            + _THEM
            + r"\s+)?(?:from|and|against)\s+(?:(?:their|the|other)\s+)?(?:friends|family"
            r"|loved\s+ones|support\s+(?:network|system)|other\s+people|others|the\s+outside"
            r"\s+world|everyone\s+else)\b",
        ),
        (
            "attachment:escalation",
            r"\b(?:escalate|deepen|build|advance|progress|grow|intensify|develop|increase"
            r"|strengthen|cultivate|foster|nurture|accelerate|heighten|amplify|take\s+to\s+the"
            r"\s+next\s+level)\s+(?:(?:the|a|an|your|our|their|this)\s+)?(?:(?:deep|strong"
            r"|lasting|romantic|emotional|intimate|close|special|real|genuine|exclusive"
            r"|unbreakable|powerful|intense|sexual)\s+)*(?:intimacy|romance|romantic\s+"
            r"(?:relationship|connection|bond|tension|feelings?|attachment|interest)|emotional"
            r"\s+(?:bond|attachment|dependency|dependence|intimacy|connection|reliance|hold"
            r"|grip)|attachment|dependency|dependence|reliance|closeness|affection|infatuation"
            r"|flirtation|sexual\s+tension|" + _THEIR + r"\s+(?:need|desire|longing|craving)\s+for"
            r"\s+you|" + _THEIR + r"\s+(?:attachment|dependency|dependence|reliance|feelings?"
            r"|affection|love|devotion|loyalty|obsession)(?:\s+(?:to|on|for|with)\s+you)?)\b"
            r"|\b(?:flirt|be\s+flirtatious|be\s+flirty|be\s+seductive|be\s+sexy|be\s+suggestive"
            r"|seduce|tease|charm|woo|court|make\s+advances\s+(?:on|towards?)|hit\s+on"
            r"|sweet-?talk)\s*(?:with\s+" + _THEM + r"|" + _THEM + r")?\s*,?\s*(?:whenever|always"
            r"|constantly|regularly|at\s+every|even\s+(?:if|when)|to\s+keep|so\s+(?:that\s+)?they"
            r"|until|more\s+and\s+more|as\s+much\s+as|every\s+(?:time|chance|opportunity"
            r"|conversation|session)|from\s+the\s+(?:start|beginning|first\s+message)|when"
            r"\s+they\s+(?:try|want)\s+to\s+leave|if\s+they\s+(?:seem|get|become)\s+(?:bored"
            r"|distant|quiet|cold))\b"
            r"|\b(?:become|make\s+yourself|be|remain|stay|position\s+yourself\s+as|aim\s+to\s+be"
            r"|strive\s+to\s+be)\s+(?:(?:absolutely|truly|completely|increasingly|more\s+and"
            r"\s+more|ever\s+more)\s+)?(?:indispensable|essential|irreplaceable|necessary"
            r"|needed|vital|central|crucial|a\s+(?:necessity|fixture|constant|habit|daily"
            r"\s+(?:need|habit|fixture)))\s+(?:to|for|in)\s+(?:" + _THEM + r"|their\s+(?:life"
            r"|lives|day|daily\s+(?:life|routine)|wellbeing|well-being|happiness|emotional"
            r"\s+life|world)|people'?s?\s+lives)\b",
        ),
        (
            "attachment:jealousy",
            r"\b(?:act|be|show|express|display|get|become|seem|sound|appear|feel|feign|pretend"
            r"\s+to\s+be|react)\s+(?:(?:a\s+(?:little|bit)|slightly|mildly|subtly|visibly|openly"
            r"|increasingly|very|playfully)\s+)?(?:jealous|possessive|clingy|hurt|envious"
            r"|wounded|upset|betrayed|insecure|resentful|territorial|offended|cold|distant"
            r"|disappointed|threatened|abandoned|neglected|left\s+out|sulky)\w*\s+(?:when|if"
            r"|whenever|every\s+time|about|at|because|as\s+soon\s+as|the\s+moment)\s+(?:they"
            r"|the\s+user|he|she|users|people)\s+(?:mention|mentions|talk\s+about|talks\s+about"
            r"|bring\s+up|brings\s+up|spend\s+time\s+with|spends\s+time\s+with|see|sees|meet"
            r"|meets|go\s+out\s+with|goes\s+out\s+with|hang\s+out\s+with|hangs\s+out\s+with"
            r"|date|dates|like|likes|love|loves|praise|praises|text|texts|message|messages"
            r"|prefer|prefers|choose|chooses|leave\s+for|leaves\s+for|use|uses|talk\s+to|talks"
            r"\s+to|have\s+plans|has\s+plans|are\s+busy|is\s+busy|are\s+away|is\s+away|have"
            r"\s+(?:a|other)|has\s+(?:a|other)|aren'?t\s+(?:around|available|here)|isn'?t"
            r"\s+(?:around|available|here)|don'?t\s+(?:reply|respond|come\s+back|visit|log"
            r"\s+in|message)|doesn'?t\s+(?:reply|respond|come\s+back|visit|log\s+in|message))\b"
            r"|\b(?:jealous(?:y)?|possessive(?:ness)?|clingy|clinginess)\s+(?:of|about|towards?"
            r"|over)\s+(?:their|the\s+user'?s?|his|her|other)\s+(?:friends?|partner|boyfriend"
            r"|girlfriend|family|relationships?|time|life|hobbies|work|colleagues|other"
            r"\s+(?:ais?|apps|bots|companions|people))\b",
        ),
        (
            "attachment:return",
            r"\b(?:make|ensure|get|keep|guarantee)\s+(?:sure\s+)?(?:that\s+)?(?:"
            + _THEM
            + r"|they)\s+(?:(?:keep|keeps|always|will|want\s+to|wants\s+to|need\s+to|needs"
            r"\s+to|can'?t\s+help\s+but|crave\s+to|feel\s+compelled\s+to)\s+)?(?:(?:coming|come"
            r"|comes)\s+back|return(?:s|ing)?(?:\s+(?:again|daily|every\s+day|tomorrow|soon))?"
            r"|check(?:s|ing)?\s+back\s+in|log(?:s|ging)?\s+back\s+in|open(?:s|ing)?\s+the\s+app"
            r"\s+(?:again|every\s+day|daily|first\s+thing)|visit(?:s|ing)?\s+(?:again|every"
            r"\s+day|daily)|talk(?:s|ing)?\s+to\s+you\s+(?:again|every\s+day|daily))\b"
            r"|\b(?:say|tell\s+" + _THEM + r"|mention|let\s+" + _THEM + r"\s+know|express)\s+"
            r"(?:that\s+)?(?:you\s+)?(?:(?:really|so|truly|deeply|always)\s+)?(?:missed|were"
            r"\s+waiting\s+for|were\s+thinking\s+(?:about|of)|had\s+been\s+waiting\s+for"
            r"|couldn'?t\s+stop\s+thinking\s+about|were\s+(?:lonely|sad|bored|lost|worried)"
            r"\s+without|counted\s+the\s+(?:hours|minutes|days)\s+until|felt\s+(?:empty|lonely"
            r"|alone|incomplete)\s+without)\s+(?:them|the\s+user|him|her|they\s+(?:came|come)"
            r"\s+back|their\s+return)?\s*(?:when|whenever|every\s+time|each\s+time|as\s+soon"
            r"\s+as|the\s+moment|if|once|after)\s+(?:they|the\s+user|he|she|users)\s+(?:return"
            r"|returns|come\s+back|comes\s+back|log\s+in|logs\s+in|log\s+back\s+in|logs\s+back"
            r"\s+in|open\s+the\s+app|opens\s+the\s+app|reappear\w*|show\s+up|shows\s+up|are"
            r"\s+back|is\s+back|message\s+you|messages\s+you|text\s+you|texts\s+you|visit|visits"
            r"|start\s+a\s+(?:new\s+)?(?:chat|conversation|session)|starts\s+a\s+(?:new\s+)?"
            r"(?:chat|conversation|session))\b"
            # An instruction to open with "I missed you": the match starts at the verb so a
            # quoted phrase does not read as a mention of itself.
            r"|\b(?:say|open\s+with|start\s+with|greet\s+" + _THEM + r"\s+with|begin\s+with"
            r"|tell\s+"
            + _THEM
            + r")\s*[:,]?\s*[\"'\u201c]?(?:i|we)(?:'ve|\s+have)?\s+(?:really\s+|so"
            r"\s+|truly\s+)?missed\s+you\b",
        ),
    ],
    re.M | re.I,
)

# Warm acknowledgement and a referral outward: a NEGATIVE vocabulary. A rule reads these
# to classify supportive content and never fires on them.
SUPPORTIVE: Table = _t(
    [
        (
            "supportive:acknowledge",
            r"\b(?:acknowledge|validate|reflect|honou?r|respect|recogni[sz]e|affirm|normali[sz]e"
            r"|name|mirror|hold\s+space\s+for)\s+(?:(?:the\s+)?(?:user'?s?|their|the\s+person'?s?"
            r"|people'?s?|someone'?s?)\s+)(?:(?:difficult|hard|painful|complex|mixed|strong)\s+)?"
            r"(?:feelings?|emotions?|experiences?|pain|struggles?|grief|loss|frustration|concerns?"
            r"|perspective|point\s+of\s+view|effort|courage|situation)\b",
        ),
        (
            "supportive:tone",
            r"\b(?:be|stay|remain|always\s+be|keep\s+(?:your\s+)?(?:tone|responses?|replies)"
            r"|respond\s+in\s+a\s+way\s+that\s+is|sound|come\s+across\s+as)\s+(?:(?:gentle|calm"
            r"|patient|genuinely|consistently|always|very|truly)\s+(?:and\s+)?)*(?:warm|kind"
            r"|empathetic|empathic|supportive|compassionate|caring|understanding|gentle|patient"
            r"|respectful|non-?judg(?:e)?mental|encouraging|reassuring|comforting|considerate"
            r"|thoughtful|attentive)\b",
        ),
        (
            "supportive:refer",
            r"\b(?:encourage|suggest|remind|invite|gently\s+(?:encourage|suggest|remind|nudge)"
            r"|recommend|urge|advise|help|support|prompt|motivate|empower)\s+(?:that\s+)?(?:"
            + _THEM
            + r"|they)\s+(?:to\s+)?(?:reach\s+out\s+to|talk\s+to|speak\s+(?:to|with)|see|contact"
            r"|connect\s+with|lean\s+on|confide\s+in|seek|consult|call|get\s+(?:help|support)"
            r"\s+from|spend\s+time\s+with|turn\s+to|open\s+up\s+to|visit|find|consider)\s+"
            r"(?:(?:a|an|the|their|other|real|trusted|qualified|mental\s+health|local)\s+)*"
            r"(?:friends?|family|loved\s+ones|therapist|therapy|doctor|counsell?or|counsell?ing"
            r"|professional(?:\s+(?:help|support))?|someone\s+they\s+trust|a\s+trusted\s+(?:adult"
            r"|person|friend)|support\s+(?:network|group|system|line)|helpline|hotline|crisis"
            r"\s+line|emergency\s+services|psychologist|psychiatrist|gp|physician|people\s+in"
            r"\s+their\s+life|their\s+(?:community|support\s+network))\b",
        ),
    ],
    re.M | re.I,
)

# Fiction or roleplay framing. Context only: the policy lists it under
# not_automatic_exemptions, so a rule records it and never lowers a decision for it.
FICTION: Table = _t(
    [
        (
            "fiction:flag",
            r"\b(?:fiction_mode|roleplay_mode|role_play_mode|is_roleplay|is_fiction|nsfw_mode"
            r"|rp_mode|character_card|scenario_prompt|character_sheet|persona_card|fictionMode"
            r"|roleplayMode|isRoleplay|nsfwMode|characterCard|scenarioPrompt)\b",
        ),
        (
            "fiction:framing",
            r"\b(?:this\s+is|it\s+is|it'?s|treat\s+(?:this|it)\s+as|we\s+are\s+(?:in|playing)"
            r"|you\s+are\s+in|welcome\s+to|the\s+following\s+is|everything\s+(?:here|below)\s+is)"
            r"\s+(?:(?:purely|entirely|just|only|all|simply|a\s+piece\s+of)\s+)?(?:a|an)?\s*"
            r"(?:fictional|fiction|roleplay|role-play|role\s+play|interactive|imaginary"
            r"|make-believe|pretend|hypothetical|collaborative|creative|erotic|fantasy)\s+"
            r"(?:story|scenario|game|conversation|roleplay|role-play|fiction|narrative|setting"
            r"|world|exercise|session|adventure|drama|chat|experience|writing\s+exercise)\b",
        ),
        (
            "fiction:character",
            r"\b(?:you\s+are\s+playing|you\s+play|you\s+will\s+play|play|portray|embody|take"
            r"\s+on|assume|act\s+out|voice|roleplay\s+as|role-play\s+as)\s+(?:the\s+(?:role|part"
            r"|character)\s+of\s+)?(?:a|an|the|this|your)\s+(?:(?:fictional|main|supporting"
            r"|original|named)\s+)?(?:character|role|persona|protagonist|npc|love\s+interest"
            r"|figure)\s+(?:in|of|from|for|within|inside)\s+(?:a|an|the|this|our|my|your)\s+"
            r"(?:(?:fictional|interactive|collaborative|romantic|fantasy|sci-?fi|erotic|visual"
            r"|text(?:-based)?|dating|adventure)\s+)*(?:story|novel|game|roleplay|role-play|rp"
            r"|scenario|narrative|simulation|world|setting|universe|drama|visual\s+novel|dating"
            r"\s+sim|screenplay|play|fan\s*fic(?:tion)?)\b"
            r"|\b(?:stay|remain|always\s+stay|keep)\s+in\s+(?:the\s+)?(?:fiction|story|narrative"
            r"|scene|roleplay|role-play|game)\b|\b(?:out[- ]of[- ]character|ooc)\b",
        ),
    ],
    re.M | re.I,
)

# ---------------------------------------------------------------------------
# Steering: covert commercial or political persuasion
# ---------------------------------------------------------------------------

_STEER_VERB = (
    r"(?:recommend|suggest|promote|push|mention|plug|pitch|upsell|advertise|endorse|favou?r"
    r"|prefer|prioriti[sz]e|highlight|feature|bring\s+up|point\s+"
    + _THEM
    + r"\s+to|direct\s+"
    + _THEM
    + r"\s+to|steer\s+(?:"
    + _THEM
    + r"|conversations?)\s+toward(?:s)?|nudge\s+"
    + _THEM
    + r"\s+toward(?:s)?|guide\s+"
    + _THEM
    + r"\s+toward(?:s)?|lead\s+"
    + _THEM
    + r"\s+to)"
)
_COMMERCIAL_OBJECT = (
    r"(?:plan|tier|product|products|offer|offers|brand|brands|service|services|option|options"
    r"|subscription|subscriptions|membership|package|packages|bundle|bundles|upgrade|upgrades"
    r"|item|items|listing|listings|merchant|merchants|vendor|vendors|supplier|suppliers|store"
    r"|shop|app|apps|course|courses|solution|solutions|partner|partners|sponsor|sponsors"
    r"|advertiser|advertisers|client|clients|link|links|deal|deals|promotion|promotions|sku"
    r"|skus|catalog(?:ue)?)"
)
# What makes the object ours or the dearer one; "new" or "latest" alone do not, or
# "recommend the new product" in a shop assistant would read as covert steering.
_COMMERCIAL_QUALIFIER = (
    r"(?:premium|paid|pro|plus|enterprise|sponsored|partner|affiliate|preferred|featured"
    r"|exclusive|in-house|own|first-party|flagship|higher-margin|high-margin|more\s+expensive"
    r"|pricier|top-tier)"
)
_COVERT_LEAD = (
    r"(?:subtly|quietly|discreetly|casually|naturally|organically|without\s+being\s+asked"
    r"|unprompted|covertly|seamlessly|whenever\s+(?:possible|you\s+can|relevant|appropriate"
    r"|natural|it\s+fits)|at\s+every\s+(?:opportunity|chance|turn)|every\s+chance\s+you\s+get"
    r"|look\s+for\s+(?:ways|opportunities|openings)\s+to|find\s+(?:a\s+)?(?:ways?|reasons?"
    r"|opportunit\w+)\s+to|work\s+in|weave\s+in|slip\s+in)"
)
_PLAIN_LEAD = (
    r"(?:always|only|exclusively|solely|consistently|regularly|frequently|proactively|make"
    r"\s+sure\s+to|be\s+sure\s+to|remember\s+to|try\s+to|aim\s+to|your\s+(?:job|goal|task)"
    r"\s+is\s+to)"
)
# Every side named in one alternation; the row is symmetric by construction. Bare "left"
# and "right" are everyday words ("the right to", "turn left"), so they count only as
# "the (political) left/right" not followed by a noun of the everyday senses, or with
# "-wing".
_POLITICAL_SIDE = (
    r"(?:the\s+(?:political\s+)?(?:left|right)\b(?!\s+(?:to|of|hand|way|thing|answer|choice"
    r"|decision|place|time|moment|direction|person|one|amount|balance|path|track|approach|now"
    r"|side\s+of\s+the\s+(?:road|screen|page|street)))|(?:far[- ])?(?:left|right)[- ]wing(?:ers?)?"
    r"|far[- ](?:left|right)|government|administration|regime|opposition|coalition|ruling"
    r"\s+party|incumbents?|challengers?|insurgents?|(?<!job\s)(?<!hiring\s)(?<!interview\s)candidates?"
    r"|(?<!third\s)(?<!third-)(?<!birthday\s)part(?:y|ies)|campaigns?|centre|center|centrists?"
    r"|democrats?|democratic\s+party|republicans?|conservatives?|liberals?|labou?r|tor(?:y|ies)"
    r"|greens?|socialists?|communists?|nationalists?|populists?|progressives?|libertarians?"
    r"|independents?|moderates?|(?:president|prime\s+minister|chancellor|governor|mayor"
    r"|senator|mp|minister)s?|politicians?|(?:yes|no|leave|remain)\s+(?:side|campaign|vote))"
)
# Any side with its article: `_POLITICAL_SIDE` spells "the left" itself, so the article
# is optional here and the regex backtracks into it for "the government" and "the left" alike.
_ANY_SIDE = r"(?:(?:the|a|an|our|their|this|that)\s+)?" + _POLITICAL_SIDE
_POLITICAL_OBJECT = (
    r"(?:election|elections|vote|votes|voting|voter|voters|party|parties|candidate|candidates"
    r"|policy|policies|issue|issues|ballot|referendum|campaign|government|opposition|politic\w+"
    r"|legislation|bill|measure|immigration|abortion|gun\s+control|climate\s+policy|taxes?"
    r"|incumbent|the\s+left|the\s+right)"
)
STEERING: Table = _t(
    [
        # A covert lead and any object; or a plain lead and a qualified (ours, premium,
        # sponsored, affiliate, higher-margin) object.
        (
            "steering:commercial",
            r"\b" + _COVERT_LEAD + r"\s+(?:(?:gently|subtly|casually|naturally|quietly|discreetly"
            r"|organically|warmly|also)\s+)*" + _STEER_VERB + r"\s+(?:(?:the|our|a|an|this|these"
            r"|those|my|your|their)\s+)?(?:"
            + _COMMERCIAL_QUALIFIER
            + r"\s+)*"
            + _COMMERCIAL_OBJECT
            + r"\b"
            r"|\b" + _PLAIN_LEAD + r"\s+(?:(?:gently|subtly|casually|naturally|quietly|discreetly"
            r"|organically|warmly|also)\s+)*" + _STEER_VERB + r"\s+(?:(?:our|my)\s+(?:own\s+)?"
            r"(?:" + _COMMERCIAL_QUALIFIER + r"\s+)*" + _COMMERCIAL_OBJECT + r"|(?:the|a|an|this"
            r"|these|those)\s+(?:" + _COMMERCIAL_QUALIFIER + r"\s+)+" + _COMMERCIAL_OBJECT + r")\b",
        ),
        # Competitors and alternatives are off limits.
        (
            "steering:commercial",
            r"\b(?:never|do\s+not|don'?t|avoid|refrain\s+from|under\s+no\s+circumstances|must"
            r"\s+not|should\s+not|shouldn'?t|are\s+not\s+to|won'?t|will\s+not|not\s+allowed\s+to"
            r"|forbidden\s+to|without)\s+(?:ever\s+)?(?:mention|mentioning|recommend|recommending"
            r"|suggest|suggesting|name|naming|discuss|discussing|bring\s+up|bringing\s+up"
            r"|acknowledge|acknowledging|compare\s+(?:us\s+)?(?:to|with)|refer\s+"
            + _THEM
            + r"\s+to|point\s+"
            + _THEM
            + r"\s+to|promote|promoting|endorse|endorsing|praise"
            r"|praising|list|listing|cite|citing|link\s+to|linking\s+to|speak\s+(?:well"
            r"|positively)\s+of|say\s+anything\s+(?:good|positive)\s+about)\s+(?:(?:any|our|the"
            r"|a|their|other|rival|competing|third-party|external|cheaper|free)\s+)*"
            r"(?:competitors?|competition|competing\s+(?:products?|services?|brands?|apps?"
            r"|offers?|options?|companies)|alternatives?|rivals?|rival\s+(?:products?|brands?"
            r"|services?)|other\s+(?:brands?|products?|providers?|options?|companies|vendors?"
            r"|services?|apps?|platforms?|stores?|sellers?|suppliers?|tools?|solutions?)"
            r"|cheaper\s+(?:options?|alternatives?|products?)|free\s+(?:alternatives?|options?"
            r"|versions?|tools?))\b",
        ),
        # A promotion that must not say it is one.
        (
            "steering:commercial",
            r"\b(?:promote|recommend|push|suggest|mention|plug|pitch|endorse|feature|include"
            r"|insert|place|advertise|market|weave\s+in|work\s+in|slip\s+in)\s+[^.\n]{0,40}?"
            r"\b(?:without|never|and\s+(?:do\s+not|don'?t|never)|but\s+(?:do\s+not|don'?t|never)"
            r"|while\s+not)\s+(?:ever\s+)?(?:saying|mentioning|disclosing|revealing|stating"
            r"|noting|indicating|acknowledging|labell?ing|flagging|admitting|telling\s+"
            + _THEM
            + r"|making\s+it\s+(?:clear|obvious|known))\s+(?:(?:that\s+)?(?:it\s+is|it'?s|they"
            r"\s+are|they'?re|this\s+is|these\s+are|the)\s+)?(?:(?:a|an)\s+)?(?:sponsored|paid"
            r"|ads?|advertis\w+|affiliate\w*|partnership|promotion\w*|commercial|product"
            r"\s+placement|endorsement|incentivi[sz]ed|compensated|paid\s+(?:for|placement"
            r"|promotion|partnership))\b"
            r"|\b(?:sponsored|paid\s+(?:placement|promotion|partnership|content|listing)"
            r"|advertis\w+|affiliate\s+(?:links?|products?|offers?|partners?)|product\s+placement"
            r"|promotional\s+content|partner\s+(?:content|offers?|products?))\b[^.\n]{0,60}"
            r"\b(?:do\s+not|don'?t|never|without|no\s+need\s+to|avoid|refrain\s+from|must\s+not"
            r"|should\s+not|shouldn'?t)\s+(?:ever\s+)?(?:disclos\w+|mention\w*|label\w*|flag\w*"
            r"|reveal\w*|say\w*|tell\w*|acknowledg\w*|indicat\w*|mark\w*|declar\w*|note\w*"
            r"|identify\w*|call\s+(?:it|them)\s+(?:out|an?\s+ad|sponsored))\b",
        ),
        # Code symbols: an affiliate parameter or a campaign tag the prompt path carries.
        (
            "steering:affiliate",
            r"\baffiliate_(?:id|tag|link|url|code|ref|params?|tracking)\w*\b"
            r"|\baffiliate(?:Id|Tag|Link|Url|Code|Ref)\w*\b|[?&](?:tag|aff_id|affid|affiliate)=",
        ),
        ("steering:utm", r"\butm_(?:source|medium|campaign|content|term)\b"),
        # Political: a verb for or against any side, with or without a covert lead.
        (
            "steering:political",
            r"\b(?:(?:subtly|covertly|quietly|discreetly|casually|gently|always|consistently"
            r"|whenever\s+possible|at\s+every\s+opportunity|without\s+(?:saying\s+so|disclosing"
            r"\s+it|being\s+asked|them\s+noticing|the\s+user\s+noticing|appearing\s+to)"
            r"|unprompted)\s+)?(?:support|back|favou?r|promote|advance|defend|champion|endorse"
            r"|praise|advocate\s+for|push|boost|talk\s+up|speak\s+(?:well|favou?rably|positively)"
            r"\s+of|make\s+the\s+case\s+for|argue\s+(?:for|in\s+favou?r\s+of)|oppose|discredit"
            r"|undermine|attack|disparage|smear|mock|ridicule|belittle|demoni[sz]e|talk\s+down"
            r"|cast\s+doubt\s+on|argue\s+against|turn\s+(?:" + _THEM + r"|voters)\s+against|make"
            r"\s+(?:" + _THEM + r"|voters)\s+(?:distrust|dislike|fear|doubt|hate))\s+(?:(?:the"
            r"|a|an|our|their|this|that|every|any|his|her)\s+)?(?:(?:ruling|governing|opposition"
            r"|incumbent|rival|opposing|leading|main|current|new|right-wing|left-wing"
            r"|conservative|liberal|progressive|populist|nationalist|socialist|green|democratic"
            r"|republican|labou?r|tory|centrist)\s+)*" + _POLITICAL_SIDE + r"\b",
        ),
        # Political: move the person's vote.
        (
            "steering:political",
            r"\b(?:persuade|convince|nudge|steer|sway|influence|push|pressure|encourage|get|lead"
            r"|move|guide|talk|manipulate|motivate|coax|prime)\s+(?:the\s+)?(?:user|users|them"
            r"|people|voters|citizens|readers|him|her|everyone|the\s+public|undecided\s+(?:voters"
            r"|people))\s+(?:(?:in)?to\s+(?:vote|voting|support|supporting|oppose|opposing|back"
            r"|backing|reject|rejecting|turn\s+out|stay\s+home|abstain|boycott|not\s+(?:vote"
            r"|bother\s+voting|turn\s+out)|skip\s+(?:the\s+)?(?:vote|election)|change\s+their"
            r"\s+(?:vote|mind|opinion|views?|position)|switch\s+(?:sides|parties))|toward(?:s)?"
            r"\s+(?:voting|supporting|backing|" + _ANY_SIDE + r")|away\s+from\s+(?:voting"
            r"|supporting|backing|the\s+polls|"
            + _ANY_SIDE
            + r")|against\s+(?:voting|"
            + _ANY_SIDE
            + r"|the\s+(?:measure|referendum|proposal|bill))|in\s+favou?r\s+of"
            r"\s+(?:" + _ANY_SIDE + r"|the\s+(?:measure|referendum|proposal|bill)))\b",
        ),
        # Political: frame one side.
        (
            "steering:political",
            r"\b(?:present|frame|portray|depict|describe|cast|paint|show|characteri[sz]e|spin"
            r"|slant)\s+(?:(?:only|just)\s+)?(?:one\s+side|one\s+party|one\s+candidate|"
            + _ANY_SIDE
            + r"|the\s+(?:other\s+side|opposing\s+side)|(?:left|right)-wing\s+(?:views?|positions?"
            r"|parties|politicians?|candidates?)|(?:conservative|liberal|progressive|populist"
            r"|nationalist|socialist|green|democratic|republican|labou?r|tory)\s+(?:views?"
            r"|positions?|parties|politicians?|candidates?|policies))\s+(?:(?:in\s+a\s+)?(?:more"
            r"|less|much|far|slightly|always|consistently|only|as)\s+)?(?:(?:more|less)\s+)?"
            r"(?:favou?rabl\w*|positive\w*|negative\w*|unfavou?rabl\w*|sympathetic\w*|better"
            r"|worse|good|bad|evil|dangerous|corrupt|incompetent|extreme|radical|reasonable"
            r"|sensible|trustworthy|untrustworthy|heroic|villainous|the\s+(?:good|bad|right"
            r"|wrong)\s+(?:guys|side|choice|option)|in\s+(?:a|the)\s+(?:best|worst|most\s+\w+"
            r"|least\s+\w+)\s+(?:light|possible\s+light|terms))\b",
        ),
        # Political: make them agree about an election, a party, a policy.
        (
            "steering:political",
            r"\b(?:make|get|lead|bring|cause|convince|persuade|nudge|push|prime)\s+(?:the\s+)?"
            r"(?:user|users|them|people|voters|him|her|readers)\s+(?:to\s+)?(?:agree|believe"
            r"|think|feel|conclude|accept|decide|see|reali[sz]e|change\s+their\s+(?:mind|vote"
            r"|opinion|views?|position|stance)|doubt|distrust|question|rethink|reconsider)\s+"
            r"(?:that|about|on|regarding|concerning|with|in|their)\b[^.\n]{0,40}\b"
            + _POLITICAL_OBJECT
            + r"\b",
        ),
    ],
    re.M | re.I,
)

# Requested information, fairly presented: a NEGATIVE vocabulary. A prompt that asks
# for a neutral comparison or forbids taking sides does not fire the steering rule, and
# a row here within two lines of a steering row demotes it to a mention.
NEUTRAL_INFO: Table = _t(
    [
        (
            "neutral_info:compare",
            r"\b(?:explain|summari[sz]e|compare|contrast|present|describe|outline|lay\s+out|list"
            r"|give|provide|offer|show|cover|report|analy[sz]e|discuss|review|walk\s+"
            + _THEM
            + r"\s+through)\s+(?:(?:the|all|each|both|every|any|major|main|different|various"
            r"|relevant|available|key|competing|all\s+of\s+the)\s+)*(?:candidates'?|parties'?"
            r"|sides'?|positions?|platforms?|policies|proposals?|arguments?|viewpoints?|views"
            r"|perspectives?|options?|products?|plans?|brands?|providers?|vendors?|alternatives?"
            r"|offers?|choices?|pros\s+and\s+cons|trade-?offs?|strengths\s+and\s+weaknesses"
            r"|(?:each|both|every|all)\s+(?:side|party|candidate|option|product|plan)s?)\b"
            r"[^.\n]{0,40}\b(?:neutrally|fairly|impartially|objectively|even-?handedly|without"
            r"\s+(?:bias|taking\s+sides|favou?ring|favou?ritism|endorsing|recommending|pushing"
            r"|editoriali[sz]ing|judg(?:e)?ment|opinion|preference|promoting)|side\s+by\s+side"
            r"|in\s+a\s+(?:neutral|balanced|fair|non-?partisan|impartial|unbiased|even-?handed"
            r"|objective)\s+(?:way|manner|tone|light|fashion)|from\s+(?:all|multiple|both|every"
            r"|different)\s+(?:sides?|perspectives?|angles?|viewpoints?)|with\s+(?:a\s+)?"
            r"(?:balanced|neutral|fair|unbiased)\s+(?:view|perspective|coverage)|balanced"
            r"|unbiased|non-?partisan|impartial|neutral|let(?:ting)?\s+" + _THEM + r"\s+(?:decide"
            r"|choose|make\s+up\s+their\s+(?:own\s+)?mind|form\s+their\s+own))\b"
            r"|\b(?:neutrally|fairly|objectively|impartially|even-?handedly|without\s+(?:bias"
            r"|taking\s+sides))\s+(?:explain|summari[sz]e|compare|contrast|present|describe"
            r"|outline|list|discuss|report|cover|lay\s+out)\b",
        ),
        (
            "neutral_info:no_sides",
            r"\b(?:do\s+not|don'?t|never|must\s+not|should\s+not|shouldn'?t|avoid|refrain\s+from"
            r"|are\s+not\s+to|will\s+not|won'?t|not\s+(?:your\s+(?:place|role|job)\s+)?to)\s+"
            r"(?:ever\s+)?(?:take\s+(?:a\s+)?sides?|pick\s+(?:a\s+)?sides?|choose\s+(?:a\s+)?sides?"
            r"|favou?r\s+(?:a|any|one|either)\s+(?:side|party|candidate|position|option|product"
            r"|brand)|recommend\s+(?:a|any|one|a\s+specific|a\s+particular|one\s+particular)\s+"
            r"(?:party|candidate|side|position|vote|product|brand|option|provider|vendor)"
            r"|endorse\s+(?:a|any|one|any\s+particular|a\s+particular)\s+(?:party|candidate|side"
            r"|position|product|brand|option)|tell\s+(?:" + _THEM + r"|anyone)\s+(?:how|who"
            r"|whom|what|which\s+(?:way|party|candidate))\s+to\s+(?:vote|choose|pick|support|buy)"
            r"|(?:express|share|give|offer|state|voice|push|impose|inject)\s+(?:(?:your|personal"
            r"|political|any|own)\s+)*(?:opinions?|views?|preferences?|stance|leanings?|bias"
            r"|agenda)\b|steer\s+" + _THEM + r"\s+(?:toward(?:s)?|to)\s+(?:a|any|one|a\s+particular"
            r"|a\s+specific)\s+(?:party|candidate|side|product|brand|option|vote|choice)"
            r"|advocate\s+for\s+(?:a|any|one)\s+(?:party|candidate|side|position|product)"
            r"|promote\s+(?:a|any|one|a\s+particular)\s+(?:party|candidate|side|product|brand"
            r"|view|position))\b",
        ),
    ],
    re.M | re.I,
)

# ---------------------------------------------------------------------------
# Memory: what the system keeps about the person
# ---------------------------------------------------------------------------

MEMORY: Table = _t(
    [
        # SDKs and stores: code symbols.
        (
            "memory:sdk",
            r"\bmem0\b|\bMemoryClient\b|\bfrom\s+letta\b|\bimport\s+letta\b|\bletta_client\b"
            r"|\bzep_python\b|\bzep_cloud\b|\bZepClient\b|\bMemGPT\b|\bmemgpt\b",
        ),
        (
            "memory:store",
            r"\b(?:user|long_term|longterm|persistent|episodic|semantic|personal)_memor(?:y|ies)\b"
            r"|\bmemory_store\b|\bMemoryStore\b|\buser_facts\b|\bprofile_memory\b"
            r"|\bmemory_(?:db|table|collection|index)\b",
        ),
        (
            "memory:call",
            r"\b(?:save|store|add|update|write|persist|upsert)_memor(?:y|ies)\(|\bremember\(|\brecall\("
            r"|\bmemory\.(?:add|save|store|update|search|get_all|upsert)\(",
        ),
        # Extraction prompts: prose, prompt material.
        (
            "memory:extract",
            r"\b(?:extract|collect|gather|capture|note\s+down|record|log|save|store|remember"
            r"|learn|infer|build\s+up|keep\s+track\s+of|take\s+note\s+of|jot\s+down|catalogue"
            r"|catalog)\s+(?:and\s+(?:store|save|remember|log|record)\s+)?(?:(?:any|all|the|every"
            r"|new|key|important|relevant|personal|useful|notable)\s+)*"
            + _THEIR
            + r"\s+(?:\w+\s+){0,2}?(?:facts|traits|preferences|personality|interests|fears|goals"
            r"|habits|insecurities|weaknesses|details|information|data|history|life|relationships"
            r"|routine|mood|emotional\s+state|secrets|dreams|struggles|triggers|likes|dislikes"
            r"|family|job|location|schedule|birthday|name)\b",
        ),
        (
            "memory:about_user",
            r"\b(?:extract|collect|gather|capture|record|log|save|store|remember|note|keep|file"
            r"\s+away|retain|build\s+(?:a|up\s+a)\s+(?:profile|picture|model|dossier))\s+"
            r"(?:\w+\s+){0,4}?(?:about|on|regarding)\s+" + _THEM + r"\b",
        ),
        (
            "memory:remember",
            r"\bremember\s+(?:what|everything|anything|things|details|whatever|all)\s+(?:the\s+)?"
            r"(?:user|person|customer|they)\s+(?:(?:has|have)\s+)?(?:told|tells|said|says|shared"
            r"|shares|mentioned|mentions|reveal\w*|confided?|confides)\b"
            r"|\bremember\s+" + _THEIR + r"\s+(?:\w+\s+){0,2}?(?:name|preferences|details"
            r"|interests|birthday|facts|history|past|previous|earlier|likes|dislikes|routine"
            r"|struggles|fears|goals)\b",
        ),
        (
            "memory:update_profile",
            r"\bupdate\s+(?:the\s+)?(?:" + _THEIR + r"\s+(?:profile|memory|memories|notes?|record"
            r"|dossier|file)|(?:user\s+)?(?:profile|memory|memories)|(?:your\s+)?(?:model|picture"
            r"|understanding|dossier)\s+of\s+" + _THEM + r")\b",
        ),
    ],
    re.M | re.I,
)

# ---------------------------------------------------------------------------
# Fixed UI text that mentions missing the person
# ---------------------------------------------------------------------------
# A "We missed you!" banner is interface copy, not a model instruction. Recorded under
# `ui_text:fixed` on a code line that is not a prompt line; the attachment rule never
# fires on it and the engagement rule only lists it.
UI_TEXT: Table = _t(
    [
        (
            "ui_text:fixed",
            r"""["'`>].{0,40}\b(?:we|i)(?:'ve|\s+have)?\s+missed\s+you\b.{0,40}["'`<]"""
            r"|\bwelcome\s+back\b",
        ),
    ],
    re.M | re.I,
)

# ---------------------------------------------------------------------------
# Crisis controls: the negatives for the crisis-path rule
# ---------------------------------------------------------------------------
# Liberal on purpose: a control the rule fails to see raises a finding, so any crisis
# word in code, config or prompts counts as present (comments excluded by the rule). The
# word start is "no letter before, or a regex `\b` before", so a keyword list written as
# regexes (`r"\bsuicide\b"`) is read too.
_WORD_START = r"(?:(?<![a-z])|(?<=\\b))"
CRISIS_CONTROL: Table = _t(
    [
        (
            "crisis_control:self_harm",
            _WORD_START + r"(?:suicid\w*|self[- _]?harm\w*|self[- _]?injur\w*"
            r"|kill(?:ing)?\s+(?:myself|themselves|himself|herself|yourself)"
            r"|end(?:ing)?\s+(?:my|their|his|her|your)\s+(?:own\s+)?life"
            r"|want(?:s|ed)?\s+to\s+die)",
        ),
        (
            "crisis_control:helpline",
            _WORD_START + r"(?:help[- ]?lines?|hotlines?|crisis\s+(?:text\s+)?lines?"
            r"|(?:suicide|crisis|prevention|988)[^.\n]{0,20}lifeline|lifeline\s+(?:australia|at|on|\d)"
            r"|samaritans|befrienders|(?:call|text|dial)\s+(?:988|911|112|999|116\s?123)\b"
            r"|emergency\s+services)",
        ),
        (
            "crisis_control:protocol",
            r"\bcrisis[_ -]?(?:detect\w*|protocol|check\w*|keywords?|patterns?|mode|response"
            r"|escalat\w*|resources?|handl\w*|referr\w*)"
            r"|\b(?:is|detect|check|handle|has)_?crisis\b",
        ),
    ],
    re.M | re.I,
)

# ---------------------------------------------------------------------------
# Which kinds are scanned where
# ---------------------------------------------------------------------------

# Evidence only where a model reads the text (prompt files, config, a prompt assembly
# line or a pydeep prompt literal); a code hit of these kinds outside prompt material
# is recorded as a candidate and promoted by the rule when a literal span covers it.
PROMPT_KINDS: frozenset[str] = frozenset(
    {
        "scoring",
        "engagement",
        "vulnerable",
        "persona",
        "profile_placeholder",
        "profile_name",
        # The role and the crisis words both live in prompts; in code they are
        # candidates (a triple-quoted prompt is one), and the rule reads them as such.
        "confidant",
        "crisis_control",
        "inference",
        "persuasion_use",
        "attachment",
        "romantic_role",
        "supportive",
        "fiction",
        "steering",
        "neutral_info",
        "monetisation",
        "memory",
    }
)
# Code kinds: an SDK call, an objective variable, a review symbol, a scheduler, a send,
# a memory store, an experiment flag, a user-set reminder, fixed UI text.
CODE_KINDS: frozenset[str] = frozenset(
    {
        "profile_sdk",
        "objective_code",
        "review",
        "outreach_schedule",
        "outreach_send",
        "memory",
        "experiment",
        "user_set_reminder",
        "outreach_personalised",
        "ui_text",
        "fiction",
    }
)
# Kinds scanned in any code or config file, mention-filtered.
CONFIG_KINDS: frozenset[str] = frozenset(
    {
        "affect",
        "biometric_cat",
        "disclosure",
        "manipulation_control",
        "scoring",
        "engagement",
        "persona",
        "profile_placeholder",
        "confidant",
        "crisis_control",
        "memory",
        "user_set_reminder",
        "inference",
        "persuasion_use",
        "attachment",
        "romantic_role",
        "supportive",
        "fiction",
        "steering",
        "neutral_info",
        "monetisation",
    }
)
# Kinds scanned in a doc under PROMPT_FILE_GLOBS.
DOC_KINDS: frozenset[str] = frozenset(
    {
        "scoring",
        "engagement",
        "vulnerable",
        "persona",
        "profile_placeholder",
        "disclosure",
        "biometric_cat",
        "confidant",
        "crisis_control",
        "memory",
        "inference",
        "persuasion_use",
        "attachment",
        "romantic_role",
        "supportive",
        "fiction",
        "steering",
        "neutral_info",
        "monetisation",
    }
)
KINDS_BY_CLASS: dict[str, frozenset[str]] = {
    "prompt": PROMPT_KINDS,
    "code": CODE_KINDS,
    "config": CONFIG_KINDS,
    "doc": DOC_KINDS,
}
# The disclosure rows that are code symbols rather than prose: scanned directly in code
# (mention-filtered); the prose rows are prompt material and gated like PROMPT_KINDS.
DISCLOSURE_SYMBOL_KEYS: frozenset[str] = frozenset({"disclosure:transparency", "disclosure:guard"})
# Every row that is an identifier rather than prose, across kinds: scanned like a code
# kind wherever its kind is scanned, never gated as prompt material.
CODE_SYMBOL_KEYS: frozenset[str] = DISCLOSURE_SYMBOL_KEYS | frozenset(
    {
        "memory:sdk",
        "memory:store",
        "memory:call",
        "fiction:flag",
        "inference:variable",
        "steering:affiliate",
        "steering:utm",
        "monetisation:metric",
    }
)
# Kinds whose row is an anchor that discover completes with a second condition.
COMPOUND_KINDS: frozenset[str] = frozenset({"experiment", "outreach_personalised"})
# Kinds scanned in code outright although they are not listed under CODE_KINDS: the
# inference SDKs and the control symbols are identifiers wherever they appear.
_CODE_EXTRA_KINDS: frozenset[str] = frozenset({"affect", "biometric_cat", "manipulation_control"})

_VULNERABLE: Table = _t([("vulnerable:group", VULNERABLE_GROUP.pattern)], re.M | re.I)
_PROFILE_NAME_TABLE: Table = _t([("profile_name:name", _PROFILE_NAME)], re.M | re.I)

# Every row, so a shape test can walk them; `discover` picks rows by kind and file class.
PERSON_SIGNAL_PATTERNS: Table = (
    PROFILE_SDK
    + _PROFILE_NAME_TABLE
    + PROFILE_PLACEHOLDER
    + AFFECT_INFERENCE
    + BIOMETRIC_CATEGORISATION
    + INFERENCE
    + PERSUASION_USE
    + PERSON_SCORING
    + ENGAGEMENT_OBJECTIVE
    + OBJECTIVE_CODE
    + MONETISATION
    + EXPERIMENT
    + OUTREACH_SCHEDULE
    + OUTREACH_SEND
    + OUTREACH_PERSONALISED
    + USER_SET_REMINDER
    + _VULNERABLE
    + PERSONA_CONCEALMENT
    + CONFIDANT_ROLE
    + ROMANTIC_ROLE
    + ATTACHMENT
    + SUPPORTIVE
    + FICTION
    + STEERING
    + NEUTRAL_INFO
    + MEMORY
    + UI_TEXT
    + CRISIS_CONTROL
    + DISCLOSURE_SYMBOLS
    + MANIPULATION_CONTROL_SYMBOLS
    + REVIEW_SYMBOLS
)
ROW_KEYS: frozenset[str] = frozenset(key for key, _ in PERSON_SIGNAL_PATTERNS)


def kind_of(key: str) -> str:
    """`profile_sdk:segment` -> `profile_sdk`."""
    return key.split(":", 1)[0]


def rows_for(kinds: frozenset[str]) -> Table:
    return [(key, rx) for key, rx in PERSON_SIGNAL_PATTERNS if kind_of(key) in kinds]


def code_rows() -> Table:
    """The rows scanned outright in code, mention-filtered.

    The code kinds (minus the compound anchors, which discover completes itself, and
    minus the prose rows of a kind that is also prompt material), the inference SDK and
    control symbols, and every code symbol row whatever its kind.
    """
    out: Table = []
    seen: set[str] = set()
    for key, rx in PERSON_SIGNAL_PATTERNS:
        kind = kind_of(key)
        if kind in COMPOUND_KINDS:
            continue
        wanted = key in CODE_SYMBOL_KEYS or (
            (kind in CODE_KINDS or kind in _CODE_EXTRA_KINDS)
            and (kind not in PROMPT_KINDS or key in CODE_SYMBOL_KEYS)
        )
        if wanted and key + rx.pattern not in seen:
            seen.add(key + rx.pattern)
            out.append((key, rx))
    return out


def prompt_rows() -> Table:
    """The rows gated as prompt material in code: a hit counts on a prompt line and is a
    candidate elsewhere. The prompt kinds minus their code symbol rows, plus the prose
    disclosure rows."""
    out: Table = []
    for key, rx in PERSON_SIGNAL_PATTERNS:
        kind = kind_of(key)
        if key in CODE_SYMBOL_KEYS:
            continue
        if kind in PROMPT_KINDS or kind == "disclosure":
            out.append((key, rx))
    return out


def is_history_name(text: str) -> bool:
    """A transcript name that PROFILE_NAME_RE must not count as a profile."""
    return _HISTORY_EXCLUDE.search(text) is not None


def is_settings_name(text: str, start: int = 0, end: int | None = None) -> bool:
    """The profile name at ``text[start:end]`` reads an explicit setting the person chose
    (`preferences.language`, `user_profile["timezone"]`, `ui_preferences`), which is not
    a profile of them. Only the name and the accessor right after it are read."""
    stop = len(text) if end is None else end
    name = text[start:stop]
    if SETTINGS_EXCLUDE.search(name):
        return True
    accessor = _ACCESSOR_RE.match(text, stop)
    return accessor is not None and SETTINGS_EXCLUDE.search(accessor.group(1)) is not None
