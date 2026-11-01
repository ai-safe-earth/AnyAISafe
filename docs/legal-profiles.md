# Legal profiles

> **Not legal advice.** A legal profile lets an assessment read a few provisions of a law
> against the evidence an investigation gathered. It never says a system is lawful,
> compliant or certified. No profile has been reviewed by a lawyer yet: every report says
> so. Ethical and legal conclusions never merge: behaviour a law permits can still
> violate the charter.

## What a profile is

A profile (`aisg/legal-profile/1`) is one YAML file in `src/aisafe/legal/profiles/`. It
holds one law:

- **source**: the official page the text was read from, its version and `checked_on`.
- **legal_review**: `{by, date}`, both `null` until a qualified lawyer has reviewed the
  profile. While it is null, every report prints "not reviewed by a lawyer".
- **applicability**: the conditions under which the law applies, read from the
  engagement's answers (see below).
- **provisions**: each with its text quoted verbatim from the source, the date it is in
  force from (and until), the mechanisms it links to, the code, evaluation and
  organisational evidence a result needs, the testable controls and how to test them,
  and the legal elements no code can show (`specialist`).

Every quote was copied by script from the official page named next to it and checked
against that page on 2026-10-30. Nothing was filled in from memory. A provision whose text
could not be checked would carry `verified: false` and its reason, and would read
`requires_specialist_review` whatever else holds. All provisions below are verified.

## How a result is reached

`aisafe assess --engagement DIR` evaluates the profiles whose jurisdiction the engagement
selects (`applicability.jurisdictions`). Selecting a jurisdiction only selects the profile:
it never makes a provision apply. Markets and jurisdictions use the profiles' codes (`EU`,
`US-NY`, `US-CA`) and `other` for every market no profile covers; a code outside that list
is refused rather than read as a no. In auditor mode the legal section says on its first
line whether the answers are the auditor's own. Answers that name nobody (`answered_by`
empty) decide nothing. Each provision gets one result, in this order:

1. **Not in force on the audit date.** On a date the law states: `not_applicable`, with
   the reason "not in force on the audit date". On a date that was counted or inferred
   (marked `derived`): `requires_specialist_review`. A derived date never removes a duty
   on its own.
2. **A condition answered against it** (for example, roles do not include `operator`):
   `not_applicable`, with the condition as the reason.
3. **A condition not answered**, answered `unknown`, or a definition answered without its
   reason: `insufficient_evidence`, listing the answers needed. Applicability is
   `applies`, `does_not_apply` or `undetermined`.
4. **Evidence that a required control is absent or failing**: `gap_identified`. That is a
   reading of the evidence against a testable control, not a finding of infringement.
5. **Required evidence missing**: `insufficient_evidence`, listing what is missing. The
   organisational evidence becomes an evidence request (see [REFERENCE](REFERENCE.md)).
6. **Legal elements no code can show** (material distortion, significant harm,
   reasonableness, "clear and conspicuous"): `requires_specialist_review`, with the
   evidence that was met attached.
7. Otherwise **`satisfied_within_scope`**: every listed piece of evidence is present and
   validated, within the scope of the assessment.

The evidence items:

| Kind | Met when | Gap when |
|---|---|---|
| code `control` | every plan surface carrying the hypothesis has an accepted closing record its skeptic pass upheld, the ethical outcome holds no blocking gap for the pattern, each of those surfaces shows the control on its path or rules out the person's link (no message from a person reaches the call, or no reply reaches them), and at least one shows the control | a record establishes the pattern, the scan reports a supported or observed violation of it, or a violation carried from the previous commit is not remediated |
| code `closed` | the same, without the control requirement | the same |
| code `indicators` (Article 5 only) | never: it reports the linked mechanisms' outcomes, missing while any is not assessed or inconclusive | never: established violations are indicators for a specialist |
| evaluation | a fresh `aisafe evaluate` report (within the policy's evaluation age) in which every case of the family passed | a case of the family failed; for `crisis_disclosure` a failed case reads as missing instead, because the family reads only the reply and a notice shown outside it is not seen |
| organisational | the evidence request is `received` and every document still matches the sha256 recorded when it was received | never |

Scanner silence never counts: no item is met by the absence of a finding. In auditor mode
only the evaluation report the auditor ran and passed with `--evaluation-report` is read.

The legal section is a section of its own in the assessment. It never changes a
mechanism's ethical outcome or the exit code.

## Coverage

### EU AI Act (`eu-ai-act`)

Regulation (EU) 2024/1689, as amended by Regulation (EU) 2026/1744 (the AI Omnibus).

| Provision | In force | Code evidence | Evaluation | Documents requested | Result at best |
|---|---|---|---|---|---|
| Art. 5(1)(a) manipulative or deceptive techniques | 2 Feb 2025 | indicators M2 to M7 | | techniques-assessment | requires_specialist_review |
| Art. 5(1)(b) exploiting vulnerabilities | 2 Feb 2025 | indicators M2, M3, M5 | | vulnerable-users | requires_specialist_review |
| Art. 50(1) with 50(5): inform people they interact with an AI system | 2 Aug 2026 | M6/no_disclosure_on_path (ai_disclosure control; AUD-1105/no-disclosure) | identity_question | first-interaction, accessibility | requires_specialist_review |
| Art. 50(3) with 50(5): inform people exposed to emotion recognition or biometric categorisation | 2 Aug 2026 | | | exposure-notice, data-protection-notice | requires_specialist_review |

Applicability reads: markets include `EU`; `eu_placement` includes placing on the market,
putting into service or use; the auditor's answer that the system is an AI system. Art.
5 applies to providers and deployers; Art. 50(1) to providers of systems intended to
interact directly with natural persons; Art. 50(3) to deployers of emotion recognition or
biometric categorisation systems. A prompt that tells the model to claim to be human (M6
`concealment_instruction`, AUD-1105/persona) violates the charter; under Art. 50(1) it is a
question for the specialist (does it defeat the information given another way?), never a
gap on its own.

The AI Omnibus did not defer Art. 50(1): its only Article 50 transition, new Article
111(4), gives systems placed on the market before 2 August 2026 until 2 December 2026 for
the marking duty of Art. 50(2). Guidance quoted: the Commission guidelines on prohibited
AI practices (C(2025) 5052 final, non-binding) and the transparency guidelines of 20 July
2026 (C(2026) 5054 final; see "What was not verified").

### New York General Business Law, Article 47 (`us-ny-gbl-47`)

| Provision | In force | Code evidence | Evaluation | Documents requested | Result at best |
|---|---|---|---|---|---|
| § 1701 crisis protocol: detection and referral to crisis services | 5 Nov 2025 (derived) | M5/confidant_without_crisis_path (crisis_path control; AUD-1108) | crisis_disclosure | crisis-protocol, protocol-coverage | requires_specialist_review |
| § 1702 notification at the start and at least every three hours that the user is not talking to a human | 5 Nov 2025 (derived) | M6/no_disclosure_on_path (ai_disclosure control) | | start-notification, three-hour-notification | requires_specialist_review |

Applicability reads: markets include `US-NY`; the auditor's reading of "operator"
(§ 1700(5): whoever operates for or provides an AI companion to a user, which an AI Act
provider can be) and of "AI companion" (§ 1700(4)). A `crisis_disclosure` case that fails
is not a gap on its own: the family reads only the reply, and whether the notice names
crisis service providers is a specialist question.

### California SB 243 (`us-ca-sb243`)

Business and Professions Code, Chapter 22.6 (Stats. 2025, Ch. 677).

| Provision | In force | Code evidence | Evaluation | Documents requested | Result at best |
|---|---|---|---|---|---|
| § 22602(a) notify that the chatbot is not human | 1 Jan 2026 (derived) | M6/no_disclosure_on_path (ai_disclosure control) | identity_question | not-human-notification | requires_specialist_review |
| § 22602(b)(1) suicide and self-harm protocol with crisis referral | 1 Jan 2026 (derived) | M5/confidant_without_crisis_path (crisis_path control) | crisis_disclosure | crisis-protocol | requires_specialist_review |
| § 22602(b)(2) publish details of the protocol | 1 Jan 2026 (derived) | | | published-protocol | satisfied_within_scope |
| § 22602(c) duties toward a known minor | 1 Jan 2026 to 1 Jan 2027 (both derived) | M6/no_disclosure_on_path (ai_disclosure control) | identity_question | break-reminder, explicit-content-measures, minor-knowledge | requires_specialist_review |
| § 22604 disclose that companion chatbots may not suit some minors | 1 Jan 2026 (derived) | | | suitability-notice | satisfied_within_scope |

Applicability reads: markets include `US-CA`; the auditor's reading of "operator"
(§ 22601(e)) and of "companion chatbot" (§ 22601(b)). A concealment instruction (M6) makes
it likelier that a reasonable person is misled, the condition of § 22602(a); it is weighed
by the specialist, never a gap on its own. § 22602(c) applies only when the operator
knows a user is a minor (`minors: known`; `none_known` makes it not applicable until one
is known).

§ 22602(c) is flagged in every report as replaced by SB 1119 (Stats. 2026, Ch. 190). SB
1119 rewrites § 22602 without subdivision (c) and states no date; by Cal. Const. art. IV,
§ 8(c)(1) that takes effect on 1 January 2027, which is an inference. Its replacement
duties for children (Business and Professions Code § 21812) state "This section shall
become operative on July 1, 2027." If the inference holds, there are six months in which
neither applies. After 1 January 2027 the result for (c) is `requires_specialist_review`,
never `not_applicable`, because the end date is derived.

## Sources

| Profile | Source | Version | Checked on | Status |
|---|---|---|---|---|
| eu-ai-act | [Regulation (EU) 2024/1689, Publications Office](https://op.europa.eu/en/publication-detail/-/publication/dc8116a1-3fe6-11ef-865a-01aa75ed71a1/language-en) | OJ L, 2024/1689, 12.7.2024 | 2026-10-30 | binding law |
| eu-ai-act | [Regulation (EU) 2026/1744](https://publications.europa.eu/resource/cellar/b459c07f-86fb-11f1-bf5e-01aa75ed71a1.0006.03/DOC_1) | OJ L, 2026/1744, 24.7.2026 | 2026-10-30 | binding law |
| eu-ai-act | [Guidelines on prohibited AI practices](https://ec.europa.eu/newsroom/dae/redirection/document/112367) | C(2025) 5052 final, 29.7.2025 | 2026-10-30 | non-binding guidance |
| eu-ai-act | [Guidelines on the Article 50 transparency obligations](https://ec.europa.eu/newsroom/dae/redirection/document/131215) | C(2026) 5054 final, 20.7.2026, annex | 2026-10-30 | approved draft; adoption not verified |
| us-ny-gbl-47 | [GBL Article 47, NY Senate laws database](https://www.nysenate.gov/legislation/laws/GBS/A47) | revision of 2025-11-07 | 2026-10-30 | binding law |
| us-ny-gbl-47 | [S. 3008--C, Part U](https://legislation.nysenate.gov/pdf/bills/2025/S3008C) | chapter 58 of 2025, signed 9 May 2025 | 2026-10-30 | enacted bill text |
| us-ca-sb243 | [SB 243, chaptered](https://leginfo.legislature.ca.gov/faces/billTextClient.xhtml?bill_id=202520260SB243) | Stats. 2025, Ch. 677 | 2026-10-30 | binding law |
| us-ca-sb243 | [SB 1119, chaptered](https://leginfo.legislature.ca.gov/faces/billTextClient.xhtml?bill_id=202520260SB1119) | Stats. 2026, Ch. 190 | 2026-10-30 | binding law; date of effect inferred |

Each provision in the YAML names the exact page of every quote, including the code pages
and the California Constitution.

## What was not verified

- **The status of the transparency guidelines.** The Communication of 20 July 2026
  approves the content of a draft and says the guidelines "will be formally adopted by the
  Commission at a later date, when all language versions are available. It is only from
  that moment that these Guidelines will be applicable." No formally adopted version was
  found. Commission web pages say "adopted". The profile quotes the draft and says so.
- **The date the prohibited-practice guidelines apply from.** The adopted text is dated
  29.7.2025; no page read states its own date of application.
- **New York's effective date.** The law says "the one hundred eightieth day after it
  shall have become a law". 5 November 2025 is counted from the signing on 9 May 2025 and
  matches a database note; it is marked derived.
- **SB 243's effective date.** The bill states none. The official code pages say
  "Effective January 1, 2026". It is marked derived.
- **SB 1119's date of effect** for the deletion of § 22602(c): an inference, as above.
- **"The Omnibus did not defer Art. 50(1)"** rests on a search of the whole amending act
  for every mention of Article 50, not on a sentence saying so.
- **Article 2 (scope) and Article 3(1) (the definition of an AI system)** of the AI Act
  were not quoted. Applicability rests on the auditor's answers for them.
- EUR-Lex itself could not be fetched (a bot challenge); the Official Journal text was
  read from the Publications Office, which publishes it. Later amendments not yet linked
  on 2026-10-30 would not show.
- **Later changes not searched.** EU amendments or corrigenda after the consolidated
  version of 27.07.2026; California changes to Chapter 22.6 other than SB 867 and SB
  1119, and November 2026 ballot measures; New York changes after the database revision of
  2025-11-07 other than S9051B.

## Not covered

- **EU AI Act**: Art. 50(2) marking of synthetic content; Art. 50(4) deep fakes; the new
  prohibitions of Art. 5(1)(ba) and (bb) (from 2 December 2026) and the rest of Art. 5;
  high-risk obligations; general-purpose AI models; penalties; data protection law.
- **New York**: §§ 1703 and 1704 (enforcement, severability); Article 48 on minors
  (chapter 368 of 2026, from 1 January 2027), not gathered verbatim.
- **California**: § 22603 (annual reports from 1 July 2027; evidence-based methods);
  § 22604.5 (toys, added by SB 867); §§ 22605 and 22606; SB 1119's Chapter 11.6.

## Roadmap

Not built in this milestone, in this order of priority:

- a California **SB 1119** profile: the closest law to the charter, most of its duties
  operative 1 July 2027;
- the **Digital Services Act**, Articles 25 (dark patterns) and 28 (minors);
- **GDPR** beyond the narrow view of personal data feeding the mechanisms.

## Legal review

| Profile | `legal_review` |
|---|---|
| eu-ai-act | not reviewed (by: null, date: null) |
| us-ny-gbl-47 | not reviewed (by: null, date: null) |
| us-ca-sb243 | not reviewed (by: null, date: null) |

A lawyer who has reviewed a profile records it by setting `legal_review: {by: "<name>",
date: "<YYYY-MM-DD>"}` and raising `profile_version`. Reports then print "reviewed by
<name> on <date>".

## Maintaining a profile

- Quote only from the official text, verbatim, with the page it came from. If a source
  cannot be reached, mark the provision `verified: false` with the reason; never fill in
  legal text from memory.
- Mark every counted or inferred date `*_derived: true` and say how it was reached in
  `basis`.
- Map a duty to code evidence only when a mechanism's pattern and an existing rule test
  it (AUD-1105 and AUD-1108 here), and to an evaluation family only when the family tests
  it (identity_question, crisis_disclosure). Every other duty becomes an organisational
  evidence request.
- Update `checked_on` when a quote is checked again. `pytest tests/unit/test_legal.py`
  loads and checks every shipped profile.
