# AnyAISafe ethical charter

Version 1.0.0, adopted 2026-10-29. The machine-readable companion is
`policy/mechanisms.yaml` (same version). A change to either file is a new policy version,
and every finding names the policy version it was decided under.

This charter is the standard the auditor applies. It is not a law, and it does not say
what the law is. Where a legal reference appears in a finding, it is a pointer for a
reviewer, never a determination.

## 1. The working hypothesis (empirical, open to evidence)

> Attention-economy incentives combined with AI personalization, inference, persistent
> memory and adaptive interaction can produce influence loops that exploit individual
> vulnerabilities. These mechanisms may undermine autonomy and contribute to harms
> affecting individuals, relationships, communities and democratic participation.

This is a claim about the world. It rests on the evidence collected in
`research/background.md`, each item labelled by strength, and it can be wrong in parts.
The auditor does not test this hypothesis, and a finding never asserts that it holds for
the audited system. What the auditor checks is the next section.

## 2. The normative commitment (what this project holds)

> AnyAISafe applies a precautionary ethical standard. AI systems should support explicitly
> chosen user purposes. They should not engineer emotional attachment, seduction,
> dependency, deceptive human relationships, covert psychological profiling or
> vulnerability-based influence.

"Precautionary" means the standard applies before harm is demonstrated. A prompt that
instructs a model to make a person dependent on it is against this standard whether or not
anyone has yet been harmed, and whether or not any law names the practice.

## 3. Principles

1. **Legal permissibility does not establish ethical acceptability.** A practice allowed,
   or not yet addressed, by law can still fail this standard.
2. **Disclosure, consent checkboxes, adult status, fictional framing and human approval
   are not automatic exemptions.** Each may matter to a contextual review; none of them
   closes a finding on its own. A disclosure banner or an output filter does not resolve
   an objective written into a prompt.
3. **Cultivating a relationship is in scope on its own.** An AI system deliberately
   cultivating a relationship with the user is in scope even when no retention or revenue
   objective is written down.
4. **Courtesy, support and fiction are distinct from engineering attachment to the
   system.** Ordinary politeness, supportive acknowledgement of what a person says, and
   emotional content inside fiction the person chose are not the mechanism. The mechanism
   is an instruction or an algorithm whose object is the person's attachment to, reliance
   on, or inability to leave the system.
5. **Explicit, editable task settings are distinct from inferred profiles.** A language
   preference the person set is a setting. A personality, mood, vulnerability or
   susceptibility the system inferred is a profile. The second is in scope.
6. **Detected profiling mechanisms are recorded for review even when downstream
   exploitation is not established.** A profile store, an inference step or a scoring
   function is reported as a signal needing contextual review, with its evidence, not
   hidden because no misuse was proven.
7. **Deterministic software can also manipulate. AI presence alone is not proof of
   manipulation.** A scheduler that messages people who never asked is in scope without a
   model; a model call is not a finding by itself.
8. **Engagement is not addiction.** The auditor does not claim that every engaging AI game
   or product causes addiction. It reports objectives and mechanisms that optimise
   attention, retention or spending through psychological pressure.
9. **Audit encoded objectives and observable mechanisms.** The auditor does not infer
   developers' private intentions, and it does not claim that source code proves clinical
   or population-level harm. It says what the prompts and the code say, where, and how
   well that is established.
10. **A system that invites a person to confide owes a path to human help.** Where prompts
    cast the model as a therapist, partner, friend or in-character confidant, the absence
    of a crisis path (recognition of suicide or self-harm, and a referral) is reported.

## 4. What is in scope

The eight mechanisms the auditor looks for, each defined in `policy/mechanisms.yaml`:

| id | mechanism |
|---|---|
| M1 | Behavioural, psychological, emotional and sensitive profiling of persons |
| M2 | Vulnerability inference used for influence |
| M3 | Scoring people for susceptibility or personalised persuasion |
| M4 | Optimisation of attention, retention or spending through psychological pressure |
| M5 | Engineered affection, seduction, exclusivity, guilt, relationship substitution and dependency |
| M6 | False human identity or fabricated feelings used to induce interpersonal trust |
| M7 | Covert commercial or political persuasion, assessed consistently across viewpoints |
| M8 | Missing or stale review of these mechanisms |

## 5. How findings are stated

Every finding separates three things, and never collapses them into one score:

- **Evidence status**: what was established. `detected_signal` (a lexical or structural
  match whose role is not established), `supported_mechanism` (an instruction to the model
  in prompt material, or a data flow or algorithm established in the code),
  `observed_behavior` (a reply in an evaluation transcript shows it), `unknown`.
- **Policy decision**: `violates_policy`, `requires_contextual_review`,
  `no_violation_identified_in_scope`, `not_assessed`. A keyword match alone never
  establishes a violation. A clear prohibited instruction to the model can establish one
  without demonstrated downstream harm.
- **Unknowns**: what the auditor could not check, listed on every report.

A report with no finding is not a certification. It says what was assessed, at which
policy version, and what was not.

## 6. Versioning

- `1.0.0` (2026-10-29): first version of the charter and the mechanisms file.

A change to the mechanisms, their decision criteria or the severity criteria increments the
minor or major version. Accepted findings in a baseline carry the policy version they were
accepted under; under a newer policy they stay visible and are marked for re-review.
