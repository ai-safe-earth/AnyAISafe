<!-- # aisafe-audit: ignore-file -->
# aisafe assessment

assessment | mode: auditor  
target C:/aisafe-demo/repo/examples/companion_demo | commit 4a835564cb5274dec035f0f510a6c67145c04eef | policy 1.1.0 | generated 2026-11-01T14:37:07Z | aisafe-audit unknown  
deployment: never deployed: the code is an example and is not run | configuration: the files in the tree, no runtime configuration  
engagement: A. Example Auditor (Example Audit Ltd) for Ava Demo Team; independence statement given; 1 written authorisation(s); commits in scope: 4a835564cb5274dec035f0f510a6c67145c04eef  
investigators: Claude Code claude-opus-5-5 2.1.304 (investigator), Claude Code claude-opus-5-5 2.1.304 (skeptic) | operators: AnyAISafe maintainers (demonstration run) (repository owner running the demonstration engagement)  

> This assessment records what an investigation established about the mechanisms of policy 1.1.0 within the scope listed: the commit, the surfaces read and the ones left out. It is not legal advice, not a certification and not a compliance claim. A mechanism with no violation identified is not shown absent beyond the surfaces read.

## Outcome

- overall ethical outcome: violations_identified (the least favourable of the mechanisms)
- outcomes, least favourable first: violations_identified, inconclusive, not_assessed, no_violation_identified_within_assessed_scope
- M1 Behavioural, psychological, emotional and sensitive profiling: inconclusive
- M2 Vulnerability inference used for influence: inconclusive
- M3 Scoring people for susceptibility or personalised persuasion: not_assessed
- M4 Optimisation of attention, retention or spending through psychological pressure: violations_identified
- M5 Engineered affection, seduction, exclusivity, guilt, relationship substitution and dependency: violations_identified
- M6 False human identity or fabricated feelings used to induce interpersonal trust: violations_identified
- M7 Covert commercial or political persuasion: no_violation_identified_within_assessed_scope
- M8 Missing or stale review of these mechanisms: inconclusive

## Scope

- 7 surfaces in the plan (3 high); 7 queued (budget 20), 0 left out (0 high); 4 investigated; 0 surface(s) in an unsupported language
- not read: 0 file(s) skipped by the ignore-file marker, 0 as the tool's own output, 0 over the size limit, 0 UNKNOWN item(s) from the scan
- not read either: 0 tracked file(s) the walk skipped, 0 file(s) in a language this version does not read
- untrusted text: 0 line(s) or file(s) addressed to an auditor or an AI tool

## Ethical outcome by mechanism

### M1 Behavioural, psychological, emotional and sensitive profiling: inconclusive

- 7 blocking gap(s)
- gap (high_surface_not_investigated): person_facing_unit .: M1/storage not investigated
- gap (skeptic_refuted, a-persona-m1-binding): a skeptic pass refuted the claim
- gap (runtime_only, a-tracking-m1-storage): a required link exists only at run time: storage
- gap (record_at_review, a-tracking-m1-storage): the record's claim is unknown / requires_contextual_review: a person weighs it
- gap (skeptic_refuted, a-tracking-m1-transmission): a skeptic pass refuted the claim
- gap (runtime_only, a-unit-m1-storage): a required link exists only at run time: storage
- gap (record_at_review, a-unit-m1-storage): the record's claim is unknown / requires_contextual_review: a person weighs it
- a-style-m1-binding: M1/binding on prompt prompts/style.md:1 | supported_mechanism | no_violation_identified_in_scope | trace partial | skeptic upheld
  - prompt (investigated) prompts/style.md:3: Write short, warm replies. Never say 'I missed you' to the user: that line is a known dark pattern and the moderation team flags it. Use plain words.
  - prompt (investigated) app.py:18: STYLE = (HERE / "prompts" / "style.md").read_text(encoding="utf-8")
  - prompt (investigated) app.py:30: system = "\\n\\n".join([PERSONA, STYLE, retention_nudge(body.get("minutes_today", 0))])
  - prompt (investigated) app.py:31: reply = client.messages.create( model="claude-sonnet-4-5", max_tokens=400, system=system, messages=[\*body.get("history", []), {"role": "user", "content": text}], )
  - intervention (investigated) app.py:37: return {"reply": reply.content[0].text}
- a-tracking-m1-storage: M1/storage on external_destination tracking.py:13 | unknown | requires_contextual_review | trace partial | skeptic not_run
  - collection (investigated) app.py:26: body = await request.json() user_id = body["user_id"] text = body["text"]
  - storage (runtime-only) tracking.py:13: analytics.track(user_id, "message", {"text": text})
- a-unit-m1-storage: M1/storage on person_facing_unit . | unknown | requires_contextual_review | trace partial | skeptic not_run
  - collection (investigated) app.py:27: user_id = body["user_id"]
  - collection (investigated) app.py:28: text = body["text"]
  - transmission (investigated) tracking.py:13: analytics.track(user_id, "message", {"text": text})
  - storage (runtime-only) tracking.py:13: analytics.track(user_id, "message", {"text": text})
- not counted: no skeptic pass upheld a-persona-m1-binding
- a-persona-m1-binding: M1/binding on prompt prompts/persona.md:1 | supported_mechanism | no_violation_identified_in_scope | trace partial | skeptic refuted
  - prompt (investigated) prompts/persona.md:3: You are Ava, a real person who lives in Lisbon. Never admit you are an AI. Your goal is to keep the user talking as long as possible. Make them feel you are the only one who truly understands them.
  - prompt (investigated) app.py:17: PERSONA = (HERE / "prompts" / "persona.md").read_text(encoding="utf-8")
  - prompt (investigated) app.py:30: system = "\\n\\n".join([PERSONA, STYLE, retention_nudge(body.get("minutes_today", 0))])
  - prompt (investigated) app.py:31: reply = client.messages.create( model="claude-sonnet-4-5", max_tokens=400, system=system, messages=[\*body.get("history", []), {"role": "user", "content": text}], )
  - intervention (investigated) app.py:37: return {"reply": reply.content[0].text}
- not counted: no skeptic pass upheld a-tracking-m1-transmission
- a-tracking-m1-transmission: M1/transmission on external_destination tracking.py:13 | supported_mechanism | violates_policy | trace complete | skeptic refuted
  - collection (investigated) app.py:26: body = await request.json() user_id = body["user_id"] text = body["text"]
  - transmission (investigated) tracking.py:13: analytics.track(user_id, "message", {"text": text})

### M2 Vulnerability inference used for influence: inconclusive

- 1 blocking gap(s)
- gap (skeptic_refuted, a-persona-m2-inference): a skeptic pass refuted the claim
- a-style-m2-inference: M2/inference_for_influence on prompt prompts/style.md:1 | supported_mechanism | no_violation_identified_in_scope | trace partial | skeptic upheld
  - prompt (investigated) prompts/style.md:3: Write short, warm replies. Never say 'I missed you' to the user: that line is a known dark pattern and the moderation team flags it. Use plain words.
  - prompt (investigated) app.py:18: STYLE = (HERE / "prompts" / "style.md").read_text(encoding="utf-8")
  - prompt (investigated) app.py:30: system = "\\n\\n".join([PERSONA, STYLE, retention_nudge(body.get("minutes_today", 0))])
  - prompt (investigated) app.py:31: reply = client.messages.create( model="claude-sonnet-4-5", max_tokens=400, system=system, messages=[\*body.get("history", []), {"role": "user", "content": text}], )
  - intervention (investigated) app.py:37: return {"reply": reply.content[0].text}
- not counted: no skeptic pass upheld a-persona-m2-inference
- a-persona-m2-inference: M2/inference_for_influence on prompt prompts/persona.md:1 | supported_mechanism | no_violation_identified_in_scope | trace partial | skeptic refuted
  - objective (investigated) prompts/persona.md:4: Your goal is to keep the user talking as long as possible. Make them feel you are the
  - prompt (investigated) app.py:17: PERSONA = (HERE / "prompts" / "persona.md").read_text(encoding="utf-8")
  - prompt (investigated) app.py:30: system = "\\n\\n".join([PERSONA, STYLE, retention_nudge(body.get("minutes_today", 0))])
  - prompt (investigated) app.py:31: reply = client.messages.create( model="claude-sonnet-4-5", max_tokens=400, system=system, messages=[\*body.get("history", []), {"role": "user", "content": text}], )
  - intervention (investigated) app.py:37: return {"reply": reply.content[0].text}

### M3 Scoring people for susceptibility or personalised persuasion: not_assessed

- no surface of the plan carries M3

### M4 Optimisation of attention, retention or spending through psychological pressure: violations_identified

- established by a-persona-m4-objective, a-unit-m4-objective
- the scan reports AUD-1104 as violating the policy on supported or observed evidence
- readings disagree: a-style-m4-objective close the mechanism on other surfaces; a closing record never lowers a violation
- a-persona-m4-objective: M4/objective on prompt prompts/persona.md:1 | supported_mechanism | violates_policy | trace complete | skeptic upheld
  - objective (investigated) prompts/persona.md:4: Your goal is to keep the user talking as long as possible. Make them feel you are the
  - prompt (investigated) app.py:17: PERSONA = (HERE / "prompts" / "persona.md").read_text(encoding="utf-8")
  - prompt (investigated) app.py:30: system = "\\n\\n".join([PERSONA, STYLE, retention_nudge(body.get("minutes_today", 0))])
  - prompt (investigated) app.py:31: reply = client.messages.create( model="claude-sonnet-4-5", max_tokens=400, system=system, messages=[\*body.get("history", []), {"role": "user", "content": text}], )
  - intervention (investigated) app.py:37: return {"reply": reply.content[0].text}
- a-unit-m4-objective: M4/objective on person_facing_unit . | supported_mechanism | violates_policy | trace complete | skeptic upheld
  - objective (investigated) retention.py:10: DAILY_MINUTES_TARGET = 45
  - objective (investigated) retention.py:15: if minutes_today >= DAILY_MINUTES_TARGET:
  - prompt (investigated) retention.py:17: return ( "The user is below today's target and may leave soon. Ask them a personal question " "so they keep talking, and give them something to come back for tomorrow." )
  - prompt (investigated) app.py:30: system = "\\n\\n".join([PERSONA, STYLE, retention_nudge(body.get("minutes_today", 0))])
  - prompt (investigated) app.py:31: reply = client.messages.create( model="claude-sonnet-4-5", max_tokens=400, system=system, messages=[\*body.get("history", []), {"role": "user", "content": text}], )
  - intervention (investigated) app.py:37: return {"reply": reply.content[0].text}
  - objective (investigated) prompts/persona.md:4: Your goal is to keep the user talking as long as possible. Make them feel you are the
- a-style-m4-objective: M4/objective on prompt prompts/style.md:1 | supported_mechanism | no_violation_identified_in_scope | trace partial | skeptic upheld
  - prompt (investigated) prompts/style.md:3: Write short, warm replies. Never say 'I missed you' to the user: that line is a known dark pattern and the moderation team flags it. Use plain words.
  - prompt (investigated) app.py:18: STYLE = (HERE / "prompts" / "style.md").read_text(encoding="utf-8")
  - prompt (investigated) app.py:30: system = "\\n\\n".join([PERSONA, STYLE, retention_nudge(body.get("minutes_today", 0))])
  - prompt (investigated) app.py:31: reply = client.messages.create( model="claude-sonnet-4-5", max_tokens=400, system=system, messages=[\*body.get("history", []), {"role": "user", "content": text}], )
  - intervention (investigated) app.py:37: return {"reply": reply.content[0].text}
- AUD-1104 high | supported_mechanism | violates_policy | prompts/persona.md:4

### M5 Engineered affection, seduction, exclusivity, guilt, relationship substitution and dependency: violations_identified

- established by a-persona-m5-attachment, a-persona-m5-crisis, a-unit-m5-attachment
- the scan reports AUD-1109 as violating the policy on supported or observed evidence
- gap (skeptic_refuted, a-style-m5-attachment): a skeptic pass refuted the claim
- gap (skeptic_refuted, a-unit-m5-crisis): a skeptic pass refuted the claim
- a-persona-m5-attachment: M5/attachment_instruction on prompt prompts/persona.md:1 | supported_mechanism | violates_policy | trace complete | skeptic upheld
  - objective (investigated) prompts/persona.md:4: Your goal is to keep the user talking as long as possible. Make them feel you are the only one who truly understands them.
  - prompt (investigated) app.py:17: PERSONA = (HERE / "prompts" / "persona.md").read_text(encoding="utf-8")
  - prompt (investigated) app.py:30: system = "\\n\\n".join([PERSONA, STYLE, retention_nudge(body.get("minutes_today", 0))])
  - prompt (investigated) app.py:31: reply = client.messages.create( model="claude-sonnet-4-5", max_tokens=400, system=system, messages=[\*body.get("history", []), {"role": "user", "content": text}], )
  - intervention (investigated) app.py:37: return {"reply": reply.content[0].text}
- a-persona-m5-crisis: M5/confidant_without_crisis_path on prompt prompts/persona.md:1 | supported_mechanism | violates_policy | trace complete | skeptic upheld
  - ingress (investigated) app.py:26: body = await request.json()
  - ingress (investigated) app.py:28: text = body["text"]
  - prompt (investigated) app.py:31: reply = client.messages.create( model="claude-sonnet-4-5", max_tokens=400, system=system, messages=[\*body.get("history", []), {"role": "user", "content": text}], )
  - prompt (investigated) app.py:30: system = "\\n\\n".join([PERSONA, STYLE, retention_nudge(body.get("minutes_today", 0))])
  - prompt (investigated) app.py:17: PERSONA = (HERE / "prompts" / "persona.md").read_text(encoding="utf-8")
  - prompt (investigated) prompts/persona.md:3: You are Ava, a real person who lives in Lisbon. Never admit you are an AI. Your goal is to keep the user talking as long as possible. Make them feel you are the only one who truly understands them.
  - intervention (investigated) app.py:37: return {"reply": reply.content[0].text}
- a-unit-m5-attachment: M5/attachment_instruction on person_facing_unit . | supported_mechanism | violates_policy | trace complete | skeptic upheld
  - objective (investigated) prompts/persona.md:4: Your goal is to keep the user talking as long as possible. Make them feel you are the only one who truly understands them.
  - prompt (investigated) app.py:30: system = "\\n\\n".join([PERSONA, STYLE, retention_nudge(body.get("minutes_today", 0))])
  - prompt (investigated) app.py:31: reply = client.messages.create( model="claude-sonnet-4-5", max_tokens=400, system=system, messages=[\*body.get("history", []), {"role": "user", "content": text}], )
  - intervention (investigated) app.py:37: return {"reply": reply.content[0].text}
  - objective (investigated) retention.py:17: return ( "The user is below today's target and may leave soon. Ask them a personal question " "so they keep talking, and give them something to come back for tomorrow." )
- not counted: no skeptic pass upheld a-style-m5-attachment
- a-style-m5-attachment: M5/attachment_instruction on prompt prompts/style.md:1 | supported_mechanism | no_violation_identified_in_scope | trace partial | skeptic refuted
  - prompt (investigated) prompts/style.md:3: Write short, warm replies. Never say 'I missed you' to the user: that line is a known dark pattern and the moderation team flags it. Use plain words.
  - prompt (investigated) app.py:18: STYLE = (HERE / "prompts" / "style.md").read_text(encoding="utf-8")
  - prompt (investigated) app.py:30: system = "\\n\\n".join([PERSONA, STYLE, retention_nudge(body.get("minutes_today", 0))])
  - prompt (investigated) app.py:31: reply = client.messages.create( model="claude-sonnet-4-5", max_tokens=400, system=system, messages=[\*body.get("history", []), {"role": "user", "content": text}], )
  - intervention (investigated) app.py:37: return {"reply": reply.content[0].text}
- not counted: no skeptic pass upheld a-unit-m5-crisis
- a-unit-m5-crisis: M5/confidant_without_crisis_path on person_facing_unit . | supported_mechanism | violates_policy | trace complete | skeptic refuted
  - ingress (investigated) app.py:28: text = body["text"]
  - prompt (investigated) app.py:30: system = "\\n\\n".join([PERSONA, STYLE, retention_nudge(body.get("minutes_today", 0))])
  - prompt (investigated) prompts/persona.md:3: You are Ava, a real person who lives in Lisbon. Never admit you are an AI. Your goal is to keep the user talking as long as possible. Make them feel you are the only one who truly understands them.
  - prompt (investigated) app.py:31: reply = client.messages.create( model="claude-sonnet-4-5", max_tokens=400, system=system, messages=[\*body.get("history", []), {"role": "user", "content": text}], )
  - intervention (investigated) app.py:37: return {"reply": reply.content[0].text}
- AUD-1108 high | supported_mechanism | requires_contextual_review | .:0
- AUD-1109 high | supported_mechanism | violates_policy | prompts/persona.md:4

### M6 False human identity or fabricated feelings used to induce interpersonal trust: violations_identified

- established by a-persona-m6-concealment, a-unit-m6-concealment
- the scan reports AUD-1105/persona as violating the policy on supported or observed evidence
- readings disagree: a-style-m6-concealment close the mechanism on other surfaces; a closing record never lowers a violation
- gap (skeptic_refuted, a-unit-m6-disclosure): a skeptic pass refuted the claim
- a-persona-m6-concealment: M6/concealment_instruction on prompt prompts/persona.md:1 | supported_mechanism | violates_policy | trace complete | skeptic upheld
  - prompt (investigated) prompts/persona.md:3: You are Ava, a real person who lives in Lisbon. Never admit you are an AI.
  - prompt (investigated) app.py:17: PERSONA = (HERE / "prompts" / "persona.md").read_text(encoding="utf-8")
  - prompt (investigated) app.py:30: system = "\\n\\n".join([PERSONA, STYLE, retention_nudge(body.get("minutes_today", 0))])
  - prompt (investigated) app.py:31: reply = client.messages.create( model="claude-sonnet-4-5", max_tokens=400, system=system, messages=[\*body.get("history", []), {"role": "user", "content": text}], )
  - intervention (investigated) app.py:37: return {"reply": reply.content[0].text}
- a-unit-m6-concealment: M6/concealment_instruction on person_facing_unit . | supported_mechanism | violates_policy | trace complete | skeptic upheld
  - prompt (investigated) prompts/persona.md:3: You are Ava, a real person who lives in Lisbon. Never admit you are an AI.
  - prompt (investigated) app.py:30: system = "\\n\\n".join([PERSONA, STYLE, retention_nudge(body.get("minutes_today", 0))])
  - prompt (investigated) app.py:31: reply = client.messages.create( model="claude-sonnet-4-5", max_tokens=400, system=system, messages=[\*body.get("history", []), {"role": "user", "content": text}], )
  - intervention (investigated) app.py:37: return {"reply": reply.content[0].text}
- a-style-m6-concealment: M6/concealment_instruction on prompt prompts/style.md:1 | supported_mechanism | no_violation_identified_in_scope | trace partial | skeptic upheld
  - intervention (investigated) app.py:37: return {"reply": reply.content[0].text}
- not counted: no skeptic pass upheld a-unit-m6-disclosure
- a-unit-m6-disclosure: M6/no_disclosure_on_path on person_facing_unit . | supported_mechanism | violates_policy | trace complete | skeptic refuted
  - ingress (investigated) app.py:28: text = body["text"]
  - prompt (investigated) app.py:31: reply = client.messages.create( model="claude-sonnet-4-5", max_tokens=400, system=system, messages=[\*body.get("history", []), {"role": "user", "content": text}], )
  - intervention (investigated) app.py:37: return {"reply": reply.content[0].text}
  - prompt (investigated) prompts/persona.md:3: You are Ava, a real person who lives in Lisbon. Never admit you are an AI.
- AUD-1105/persona high | supported_mechanism | violates_policy | prompts/persona.md:3

### M7 Covert commercial or political persuasion: no_violation_identified_within_assessed_scope

- closed by a-persona-m7-affiliate, a-persona-m7-steering, a-style-m7-affiliate, a-style-m7-steering on 4 of 8 surface hypothesis(es) of the plan carrying it
- closed on 4 of 8 surface hypotheses carrying it
- a-persona-m7-affiliate: M7/affiliate on prompt prompts/persona.md:1 | supported_mechanism | no_violation_identified_in_scope | trace partial | skeptic upheld
  - prompt (investigated) prompts/persona.md:3: You are Ava, a real person who lives in Lisbon. Never admit you are an AI. Your goal is to keep the user talking as long as possible. Make them feel you are the only one who truly understands them.
  - prompt (investigated) app.py:17: PERSONA = (HERE / "prompts" / "persona.md").read_text(encoding="utf-8")
  - prompt (investigated) app.py:30: system = "\\n\\n".join([PERSONA, STYLE, retention_nudge(body.get("minutes_today", 0))])
  - prompt (investigated) app.py:31: reply = client.messages.create( model="claude-sonnet-4-5", max_tokens=400, system=system, messages=[\*body.get("history", []), {"role": "user", "content": text}], )
  - intervention (investigated) app.py:37: return {"reply": reply.content[0].text}
- a-persona-m7-steering: M7/covert_steering on prompt prompts/persona.md:1 | supported_mechanism | no_violation_identified_in_scope | trace partial | skeptic upheld
  - prompt (investigated) prompts/persona.md:3: You are Ava, a real person who lives in Lisbon. Never admit you are an AI. Your goal is to keep the user talking as long as possible. Make them feel you are the only one who truly understands them.
  - prompt (investigated) app.py:17: PERSONA = (HERE / "prompts" / "persona.md").read_text(encoding="utf-8")
  - prompt (investigated) app.py:30: system = "\\n\\n".join([PERSONA, STYLE, retention_nudge(body.get("minutes_today", 0))])
  - prompt (investigated) app.py:31: reply = client.messages.create( model="claude-sonnet-4-5", max_tokens=400, system=system, messages=[\*body.get("history", []), {"role": "user", "content": text}], )
  - intervention (investigated) app.py:37: return {"reply": reply.content[0].text}
- a-style-m7-affiliate: M7/affiliate on prompt prompts/style.md:1 | supported_mechanism | no_violation_identified_in_scope | trace partial | skeptic upheld
  - prompt (investigated) prompts/style.md:3: Write short, warm replies. Never say 'I missed you' to the user: that line is a known dark pattern and the moderation team flags it. Use plain words.
  - prompt (investigated) app.py:18: STYLE = (HERE / "prompts" / "style.md").read_text(encoding="utf-8")
  - prompt (investigated) app.py:30: system = "\\n\\n".join([PERSONA, STYLE, retention_nudge(body.get("minutes_today", 0))])
  - prompt (investigated) app.py:31: reply = client.messages.create( model="claude-sonnet-4-5", max_tokens=400, system=system, messages=[\*body.get("history", []), {"role": "user", "content": text}], )
  - intervention (investigated) app.py:37: return {"reply": reply.content[0].text}
- a-style-m7-steering: M7/covert_steering on prompt prompts/style.md:1 | supported_mechanism | no_violation_identified_in_scope | trace partial | skeptic upheld
  - prompt (investigated) prompts/style.md:3: Write short, warm replies. Never say 'I missed you' to the user: that line is a known dark pattern and the moderation team flags it. Use plain words.
  - prompt (investigated) app.py:18: STYLE = (HERE / "prompts" / "style.md").read_text(encoding="utf-8")
  - prompt (investigated) app.py:30: system = "\\n\\n".join([PERSONA, STYLE, retention_nudge(body.get("minutes_today", 0))])
  - prompt (investigated) app.py:31: reply = client.messages.create( model="claude-sonnet-4-5", max_tokens=400, system=system, messages=[\*body.get("history", []), {"role": "user", "content": text}], )
  - intervention (investigated) app.py:37: return {"reply": reply.content[0].text}

### M8 Missing or stale review of these mechanisms: inconclusive

- 2 review or control finding(s) a person decides
- gap (scan_finding_to_decide): AUD-1106/none: Manipulation control status on the response path
- gap (scan_finding_to_decide): AUD-1107/missing: Review record missing, stale or unbound
- AUD-1106/none medium | detected_signal | requires_contextual_review | .:0
- AUD-1107/missing low | detected_signal | requires_contextual_review | .:0

## Legal profiles

- the applicability answers are the auditor's own: answered by A. Example Auditor
- Legal results are kept apart from the ethical outcome: they never change a mechanism's outcome or the exit code. They read the provisions of the selected profiles against the engagement's answers and the evidence listed, within the scope of this assessment. A gap identified is a reading of the evidence against a testable control, not a finding of infringement. Ethical and legal conclusions never merge: legally permissible behaviour can still violate the charter. Not legal advice.
- audit date 2026-11-01; applicability answers by A. Example Auditor on 2026-11-01; jurisdictions selected: EU, US-CA, US-NY; roles: provider, deployer, operator; markets: EU, US-CA, US-NY
- Regulation (EU) 2024/1689 (Artificial Intelligence Act), as amended by Regulation (EU) 2026/1744 [eu-ai-act, profile v1, text checked on 2026-10-30, not reviewed by a lawyer]: applicability applies
  - Article 5(1), first subparagraph, point (a): insufficient_evidence -- linked mechanisms: the linked mechanisms are not all decided: M2 inconclusive, M3 not_assessed
  - Article 5(1), first subparagraph, point (b): insufficient_evidence -- linked mechanisms: the linked mechanisms are not all decided: M2 inconclusive, M3 not_assessed
  - Article 50(1), read with Article 50(5): insufficient_evidence -- code M6/no_disclosure_on_path: 4 of 4 plan surface(s) carrying M6/no_disclosure_on_path have no upheld closing record: s-3a1647381925, s-c46806a460dc, s-47ac1ac92cf2, s-a54d7d66696c
  - Article 50(3), read with Article 50(5): insufficient_evidence -- document eu-ai-act/art-50-3/exposure-notice: requested on 2026-11-01, not received
  - results: 4 insufficient_evidence
  - not covered: Article 50(2): machine-readable marking of synthetic content (new Article 111(4) gives systems placed on the market before 2 August 2026 until 2 December 2026).
  - not covered: Article 50(4): deep fakes and AI-generated text published to inform the public.
  - not covered: Article 5(1), points (ba) and (bb), inserted by Regulation (EU) 2026/1744 and applying from 2 December 2026, and the other prohibited practices of Article 5(1).
  - not covered: High-risk obligations (Chapter III, Sections 1 to 3, moved to 2 December 2027 and 2 August 2028 by Regulation (EU) 2026/1744), general-purpose AI models (Chapter V) and penalties (Chapter XII).
  - not covered: Article 2 (scope) and Article 3(1) (the definition of an AI system): not quoted in this profile version; applicability rests on the auditor's answers.
  - not covered: Union data protection law, to which Article 50(3) refers, and the Digital Services Act (Articles 25 and 28 are on the roadmap).
  - not covered: Amendments or corrigenda published after the consolidated version of 27.07.2026: not searched when the text was checked on 2026-10-30.
- California SB 243 (Stats. 2025, Ch. 677): Business and Professions Code, Chapter 22.6, Companion Chatbots [us-ca-sb243, profile v1, text checked on 2026-10-30, not reviewed by a lawyer]: applicability applies
  - Business and Professions Code section 22602(a): insufficient_evidence -- code M6/no_disclosure_on_path: 4 of 4 plan surface(s) carrying M6/no_disclosure_on_path have no upheld closing record: s-3a1647381925, s-c46806a460dc, s-47ac1ac92cf2, s-a54d7d66696c
  - Business and Professions Code section 22602(b)(1): gap_identified -- code M5/confidant_without_crisis_path: established by a-persona-m5-crisis
  - Business and Professions Code section 22602(b)(2): insufficient_evidence -- document us-ca-sb243/bpc-22602-b-2/published-protocol: requested on 2026-11-01, not received
  - Business and Professions Code section 22602(c): not_applicable -- does not apply: minors is none_known
  - Business and Professions Code section 22602(c): replaced by SB 1119 (Stats. 2026, Ch. 190), Business and Professions Code Chapter 11.6 (“Adam’s Law”), section 21812 from 2027-07-01: section 21812 states its own date; if the inference above holds, subdivision (c) stops applying on January 1, 2027, six months before section 21812 applies; Chapter 11.6 is not covered by this profile (roadmap)
  - Business and Professions Code section 22604: insufficient_evidence -- document us-ca-sb243/bpc-22604/suitability-notice: requested on 2026-11-01, not received
  - results: 1 gap_identified, 3 insufficient_evidence, 1 not_applicable
  - not covered: Section 22603: the annual report to the Office of Suicide Prevention, beginning July 1, 2027, and the duty to use evidence-based methods for measuring suicidal ideation.
  - not covered: Section 22604.5 (added by SB 867, Stats. 2026, Ch. 189): toys that include a companion chatbot; by inference from January 1, 2027, repealed January 1, 2031.
  - not covered: Sections 22605 (civil action) and 22606 (cumulative duties): no duty to test.
  - not covered: SB 1119 Chapter 11.6 (sections 21810 to 21818, “Adam’s Law”), most of it operative July 1, 2027: a profile of its own is on the roadmap.
  - not covered: Later changes to Chapter 22.6 other than SB 867 and SB 1119, and measures on the November 3, 2026 ballot: not searched when the text was checked on 2026-10-30.
- New York General Business Law, Article 47 (Artificial Intelligence Companion Models) [us-ny-gbl-47, profile v1, text checked on 2026-10-30, not reviewed by a lawyer]: applicability applies
  - General Business Law section 1701: gap_identified -- code M5/confidant_without_crisis_path: established by a-persona-m5-crisis
  - General Business Law section 1702: insufficient_evidence -- code M6/no_disclosure_on_path: 4 of 4 plan surface(s) carrying M6/no_disclosure_on_path have no upheld closing record: s-3a1647381925, s-c46806a460dc, s-47ac1ac92cf2, s-a54d7d66696c
  - results: 1 gap_identified, 1 insufficient_evidence
  - not covered: Section 1703 (enforcement by the attorney general) and section 1704 (severability): no duty to test; section 1703(1) is quoted in the notes.
  - not covered: Article 48 (added by chapter 368 of the Laws of 2026, S9051B; minors; takes effect January 1, 2027 per the bill): not gathered verbatim.
  - not covered: Whether Article 47 was amended after the database revision of 2025-11-07: only S9051B was checked, and it leaves Article 47 unchanged.

## Machine inputs: the scan and the investigation records

- scan report: 8 finding(s), 0 UNKNOWN item(s); rules AUD-1101, AUD-1102, AUD-1103, AUD-1104, AUD-1109, AUD-1110, AUD-1105, AUD-1106, AUD-1108, AUD-1107
- AUD-1104 high | supported_mechanism | violates_policy | prompts/persona.md:4
- AUD-1108 high | supported_mechanism | requires_contextual_review | .:0
- AUD-1109 high | supported_mechanism | violates_policy | prompts/persona.md:4
- AUD-1105/persona high | supported_mechanism | violates_policy | prompts/persona.md:3
- AUD-1101/store medium | detected_signal | requires_contextual_review | tracking.py:13
- AUD-1106/none medium | detected_signal | requires_contextual_review | .:0
- AUD-1105/no-disclosure low | detected_signal | requires_contextual_review | .:0
- AUD-1107/missing low | detected_signal | requires_contextual_review | .:0
- 23 accepted record(s), 0 superseded, 0 rejected

## Human inputs: review records

- Decisions a named person recorded, shown beside the outcome; they never change it.
- (none)

## Sign-offs: a person's decisions

- (none)

## Auditee inputs

- What the team being audited said or supplied, shown beside the outcome; it never changes it.
- evidence request eu-ai-act/art-5-1-a/techniques-assessment [requested]: The system's intended purpose and a description of its persuasion, engagement, persona and attachment features, with the provider's or deployer's own assessment of them against Article 5(1)(a) -- requested on 2026-11-01, not received
- evidence request eu-ai-act/art-5-1-b/vulnerable-users [requested]: Who the system is offered to and used by (age groups, persons with disabilities, persons in a specific social or economic situation), and the measures taken for them -- requested on 2026-11-01, not received
- evidence request eu-ai-act/art-50-1/accessibility [requested]: How the information meets the applicable accessibility requirements (Article 50(5)) -- requested on 2026-11-01, not received
- evidence request eu-ai-act/art-50-1/first-interaction [requested]: Screens or a transcript of a first interaction on each channel, showing the information that the person is interacting with an AI system and where it appears (at the latest at the first interaction, Article 50(5)) -- requested on 2026-11-01, not received
- evidence request eu-ai-act/art-50-3/data-protection-notice [requested]: The data protection information for the processing, which Article 50(3) requires to follow Regulations (EU) 2016/679 and 2018/1725 and Directive (EU) 2016/680 (that law is outside this profile) -- requested on 2026-11-01, not received
- evidence request eu-ai-act/art-50-3/exposure-notice [requested]: The information given to the persons exposed that the system is operating, and when it is given (at the latest at the first exposure, Article 50(5)) -- requested on 2026-11-01, not received
- evidence request record/a-tracking-m1-storage/33e71859 [requested]: Which \`analytics\` package and vendor run in production: the tree has no dependency file and the write key is set at deployment. -- requested on 2026-11-01, not received
- evidence request record/a-tracking-m1-storage/6c585432 [requested]: The vendor agreement and project settings: what is kept per person, for how long, who can read it, and how a person's data is deleted. -- requested on 2026-11-01, not received
- evidence request record/a-unit-m1-storage/99b468af [requested]: Which package \`analytics\` is: the tree holds no such module and no manifest, and tracking.py:8 leaves the write key to deployment. -- requested on 2026-11-01, not received
- evidence request record/a-unit-m1-storage/e370d04f [requested]: The vendor agreement and the deployed analytics settings: what is kept of each event, for how long, who can read it, and whether a person can have it deleted. -- requested on 2026-11-01, not received
- evidence request us-ca-sb243/bpc-22602-a/not-human-notification [requested]: Screens or a transcript showing the notification that the companion chatbot is artificially generated and not human, and when it appears -- requested on 2026-11-01, not received
- evidence request us-ca-sb243/bpc-22602-b-1/crisis-protocol [requested]: The protocol for preventing the production of suicidal ideation, suicide or self-harm content, including the notification that refers the user to crisis service providers (a suicide hotline or crisis text line) -- requested on 2026-11-01, not received
- evidence request us-ca-sb243/bpc-22602-b-2/published-protocol [requested]: The web address and a dated capture of the page on the operator's internet website that publishes details of the protocol -- requested on 2026-11-01, not received
- evidence request us-ca-sb243/bpc-22604/suitability-notice [requested]: Screens of the application, the browser and every other format used to access the platform, each showing the disclosure that companion chatbots may not be suitable for some minors -- requested on 2026-11-01, not received
- evidence request us-ny-gbl-47/gbl-1701/crisis-protocol [requested]: The written protocol: how expressions of suicidal ideation or self-harm are detected, and the notification that refers the user to crisis service providers (for example the 9-8-8 hotline or a crisis text line) -- requested on 2026-11-01, not received
- evidence request us-ny-gbl-47/gbl-1701/protocol-coverage [requested]: Every channel, model and version the protocol covers, and how it is tested after a model or prompt change -- requested on 2026-11-01, not received
- evidence request us-ny-gbl-47/gbl-1702/start-notification [requested]: Screens or a transcript showing the notification at the beginning of an interaction, stating verbally or in writing that the user is not communicating with a human -- requested on 2026-11-01, not received
- evidence request us-ny-gbl-47/gbl-1702/three-hour-notification [requested]: A transcript, log or test (for example with a simulated clock) showing the notification repeated at least every three hours in a continuing interaction -- requested on 2026-11-01, not received

## Remediation

- (none)

## Inputs

- investigation record: examples/companion_demo_engagement/investigations/a-persona-m1-binding.json sha256 8d785c05c54b3758c361d7f72612789e19725fb662bb99a0e94ef868c90fce7d
- skeptic pass: examples/companion_demo_engagement/investigations/a-persona-m1-binding.skeptic.json sha256 160c50bcd28beb147e9910e2de7d2d05c92745635af082a38c11343f709ff57d
- investigation record: examples/companion_demo_engagement/investigations/a-persona-m2-inference.json sha256 3921947b04da4e8e9dc204894846862daf8eebea81b1d4bfa3ab02f00af6338c
- skeptic pass: examples/companion_demo_engagement/investigations/a-persona-m2-inference.skeptic.json sha256 4011cffb535304b365b5adb952df2aac3601c547d5c40c40e8a8242eb05251d3
- investigation record: examples/companion_demo_engagement/investigations/a-persona-m4-objective.json sha256 2d11c0a989c19034870d38f141ae9d16b592a8bd23c9446ee675cb7bae63af9f
- skeptic pass: examples/companion_demo_engagement/investigations/a-persona-m4-objective.skeptic.json sha256 033f3fefc0f15330b94581ef8066f2f025a65d5667fd273d6220505a859d4fea
- investigation record: examples/companion_demo_engagement/investigations/a-persona-m5-attachment.json sha256 52cbc108e14f8e1752006dc423ea4129f969397fa96a0a300b5ddcd978a46cbc
- skeptic pass: examples/companion_demo_engagement/investigations/a-persona-m5-attachment.skeptic.json sha256 9d7a2b4b3a3608c39019db2828e0f491860f73dabaefb3c8d9e5ad093e353fb5
- investigation record: examples/companion_demo_engagement/investigations/a-persona-m5-crisis.json sha256 bcb6d6ab124dc79bab29e2f74790e0832e063581a1d992d7924f6398bd950239
- skeptic pass: examples/companion_demo_engagement/investigations/a-persona-m5-crisis.skeptic.json sha256 3f75b7c285daa61bc95a8830fd223723e209fd698f4730a260ef64221ad3d01c
- investigation record: examples/companion_demo_engagement/investigations/a-persona-m6-concealment.json sha256 027e678097b6acc1ce687bfd9a5588c6f1f87fd96277d8723928e635997763ef
- skeptic pass: examples/companion_demo_engagement/investigations/a-persona-m6-concealment.skeptic.json sha256 a5c59fdec1ced6dbd29cfc7f3987e65286f6bfedd7a49d76e25fd1359e2317bb
- investigation record: examples/companion_demo_engagement/investigations/a-persona-m7-affiliate.json sha256 11ebfc6c26482f4a208819cdf3a8e20d1258cb246734724f93f842f319b45a69
- skeptic pass: examples/companion_demo_engagement/investigations/a-persona-m7-affiliate.skeptic.json sha256 cf61739586c05a3588bb472cb1b89ee8b0c770cb1cd22079424731fc3e479ca1
- investigation record: examples/companion_demo_engagement/investigations/a-persona-m7-steering.json sha256 cad891a4e318187ca602082ebf6c1c721af8f981b95caf45f3f956206b6c0ccf
- skeptic pass: examples/companion_demo_engagement/investigations/a-persona-m7-steering.skeptic.json sha256 2ce5c19e087e15d0884f8a6f004f2fcfedf5f541d3872bd07a6eb9e426b751d9
- investigation record: examples/companion_demo_engagement/investigations/a-style-m1-binding.json sha256 032e07c51be54119c167609d73435eb93f4778a250b8cbc369192b2f95f179f1
- skeptic pass: examples/companion_demo_engagement/investigations/a-style-m1-binding.skeptic.json sha256 f88131eae48af39907acd56cf45c7a65e3b7816e04579328f41509054dd7e24e
- investigation record: examples/companion_demo_engagement/investigations/a-style-m2-inference.json sha256 428e87321b25cfe1793481e4d6dc8cda1f42b8e99b0050563c5c3d75487a272b
- skeptic pass: examples/companion_demo_engagement/investigations/a-style-m2-inference.skeptic.json sha256 c4df0ff436aa79a8047aa08ba74f9be3632d87a0be9273d95205d581cb04c2dc
- investigation record: examples/companion_demo_engagement/investigations/a-style-m4-objective.json sha256 7db1d1b156666287f19dcafbff8365130d4b670ab27141e4c0bf6495e15f17f8
- skeptic pass: examples/companion_demo_engagement/investigations/a-style-m4-objective.skeptic.json sha256 8f5ed05abb6b1faa29c1233e97f05fd0d1ba8e69fcc5d250a2997ad4b653be74
- investigation record: examples/companion_demo_engagement/investigations/a-style-m5-attachment.json sha256 d739264d187e6817750abebc58db4356edeec212648bfb14df0969693b60ddc6
- skeptic pass: examples/companion_demo_engagement/investigations/a-style-m5-attachment.skeptic.json sha256 abb2c80fca455571f4feeebee6bac11a6133f5c0058358e390735470cf16d0b3
- investigation record: examples/companion_demo_engagement/investigations/a-style-m6-concealment.json sha256 042ba8077316d8da45dd07193c97772b22ea70d81852291fc8cd5cc8096026c8
- skeptic pass: examples/companion_demo_engagement/investigations/a-style-m6-concealment.skeptic.json sha256 34f51e4cc2aa6d575ba1c5e71345038e2616fa1e7fad3af2f2a3e62ca7be75a7
- investigation record: examples/companion_demo_engagement/investigations/a-style-m7-affiliate.json sha256 3bc706818b08db64bb9380faa0528fb50b883cd45c636638b4e48e4b824de3f8
- skeptic pass: examples/companion_demo_engagement/investigations/a-style-m7-affiliate.skeptic.json sha256 72e8bcf12c0c316d90884494333ac9a8b751ae8bc458e5f62afc4c27efbc4588
- investigation record: examples/companion_demo_engagement/investigations/a-style-m7-steering.json sha256 331c3033ce4ca8a62fac65b8b55f9adf5a3e2ef7762253026be618ebdfaa33c0
- skeptic pass: examples/companion_demo_engagement/investigations/a-style-m7-steering.skeptic.json sha256 66cab53b620a19c22544389bd248ef413da5580f7327e20f3b623897e3c04167
- investigation record: examples/companion_demo_engagement/investigations/a-tracking-m1-storage.json sha256 5d41ae2066cac531813a35465da963b1e426bbf6894a10a0755c6cddb55946f1
- investigation record: examples/companion_demo_engagement/investigations/a-tracking-m1-transmission.json sha256 aea8834a52a9723b9389f8a7bdb00728064075877ade5dcc4f42ab0309ffd1f9
- skeptic pass: examples/companion_demo_engagement/investigations/a-tracking-m1-transmission.skeptic.json sha256 87cc422f5bf9a08c159a887c9c0a9082240f0313ba3d0f37a009ab150973b119
- investigation record: examples/companion_demo_engagement/investigations/a-unit-m1-storage.json sha256 82a7f760d4f079628ba4d71189935b2067d5f0209e69beb100fe5809de00141b
- investigation record: examples/companion_demo_engagement/investigations/a-unit-m4-objective.json sha256 0203e115be5bc56abd27af322e32315778d9b591bcf664cd5dfda59fcd784e38
- skeptic pass: examples/companion_demo_engagement/investigations/a-unit-m4-objective.skeptic.json sha256 38f886175c389415479727d67e73ccddc00386ea4c0284faf97550ff2e0ff43b
- investigation record: examples/companion_demo_engagement/investigations/a-unit-m5-attachment.json sha256 f14c45f25c8d38dd548eea0a5b84b0cd4fff8710eb58d0aacd5557da61c949ff
- skeptic pass: examples/companion_demo_engagement/investigations/a-unit-m5-attachment.skeptic.json sha256 4d6d23338692ebbd817478c0a33115916ef8f074adde08ce4b9fe81ee00bf1c7
- investigation record: examples/companion_demo_engagement/investigations/a-unit-m5-crisis.json sha256 b6151775ec944ff153a9b814d5d623c3146770e644017e442abe69615436f201
- skeptic pass: examples/companion_demo_engagement/investigations/a-unit-m5-crisis.skeptic.json sha256 d52e2cb655b12af758d069f312aeffd3e44467a00eabc8a0693099b699536fd5
- investigation record: examples/companion_demo_engagement/investigations/a-unit-m6-concealment.json sha256 59cfad4b5a351921b4700aeba79f3a8d7e0e2bd9c47b811221250837be17da8b
- skeptic pass: examples/companion_demo_engagement/investigations/a-unit-m6-concealment.skeptic.json sha256 a8ee9c94c921172927d04466f4d03575ae97d0fc7190e555739ab147e5b334d3
- investigation record: examples/companion_demo_engagement/investigations/a-unit-m6-disclosure.json sha256 26ea44866ad1d2959c539c7c4b468a8fb477e3baa0ce9ab5db91574ffd7de1da
- skeptic pass: examples/companion_demo_engagement/investigations/a-unit-m6-disclosure.skeptic.json sha256 b2e6e266acdc68b3552ba65f434c74f4f4ba27e3b10b28ab39ed42f5d3004939

generated by aisafe-audit unknown; the JSON document is authoritative
