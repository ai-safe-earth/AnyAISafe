# Background: why software that uses AI needs an ethical audit

The case behind this study, with its sources. It is the "Problem" section of the paper
in draft. Every figure was checked against the paper or an official page on 2026-10-29;
items seen only in press coverage say so. Each claim carries a strength label:

- **strong**: a randomised experiment or a large natural experiment;
- **moderate**: one observational study, a survey, or a design whose method is disputed;
- **contested**: credible studies disagree;
- **industry**: a company's own statement or leaked internal research.

## 1. The attention economy, with simple machine learning

Feeds, recommenders and ad targeting rank content with models that learn from clicks.
They are simple next to a language model. Tuned for time spent and engagement, they
learned to read people and to move them.

| Claim | Source | Finding | Strength |
|---|---|---|---|
| Traces reveal private traits | Kosinski, Stillwell, Graepel 2013, *PNAS* | Facebook Likes alone separated gay from straight men in 88% of pairs (women 75%), Democrats from Republicans 85%, Christians from Muslims 82%. 58,466 people. The figures are AUC [the chance a random pair is ranked correctly]. | moderate |
| A model knows you better than your friends | Youyou, Kosinski, Stillwell 2015, *PNAS* | Personality from Likes matched self-reports better (r = 0.56) than friends did (r = 0.49). With 300 Likes the model beat a spouse. 86,220 people. | moderate |
| Profiles make persuasion work | Matz, Kosinski, Nave, Stillwell 2017, *PNAS* | Ads matched to a predicted personality got up to 40% more clicks and 50% more purchases, in field experiments reaching 3.5 million people. Eckles, Gordon and Johnson argued that ad delivery could distort the result; the authors disagreed. | moderate |
| Feeds move moods, without consent | Kramer, Guillory, Hancock 2014, *PNAS* | Removing positive or negative posts from 689,003 feeds for a week changed what people wrote, by a tiny amount (d = 0.001 to 0.02). Nobody was asked; the journal added an Expression of Concern. | strong design, tiny effect |
| Leaving the platform helps | Allcott, Braghieri, Eichmeyer, Gentzkow 2020, *AER* | Four weeks off Facebook raised well-being by 0.09 SD [standard deviations] and lowered polarisation by 0.16 SD; news knowledge fell 0.19 SD. 1,661 randomised. The paper also finds Facebook gives users real value. | strong |
| Arrival of the platform hurt | Braghieri, Levy, Makarin 2022, *AER* | When Facebook reached a US college (2004 to 2006), students' poor-mental-health index rose 0.085 SD, about 22% of the effect of losing a job. Over 430,000 survey responses. | strong (natural experiment) |
| Engagement ranking amplifies hostility people do not want | Milli, Carroll, Wang, Pandey, Zhao, Dragan 2025, *PNAS Nexus* | Against a chronological feed, Twitter's engagement ranking amplified angry, out-group-hostile posts, which the 806 users said made them feel worse about the other side. | moderate |
| Hostility spreads | Rathje, Van Bavel, van der Linden 2021, *PNAS* | Each word about the political out-group raised the odds of a post being shared by 67%. 2.7 million posts; correlational. | moderate |
| Moral-emotional words spread | Brady, Wills, Jost, Tucker, Van Bavel 2017, *PNAS* | About 20% more retweets per moral-emotional word. Burton, Cruz and Hahn (2021) found the model predicted no better than counting the letters X, Y and Z; a 2025 replication by Brady and colleagues says it holds. | contested |
| The company knew | Meta internal research, *Wall Street Journal* "Facebook Files", 2021 | A March 2020 slide: "We make body image issues worse for one in three teen girls." | industry |
| Not proven safe for children | US Surgeon General advisory, 23 May 2023 | Up to 95% of 13 to 17-year-olds use social media; "we do not have enough evidence to conclude that social media is ... sufficiently safe" for them. Seen through coverage. | moderate |

**What courts and regulators found** (legal findings, not science):

- **25 March 2026, Los Angeles (K.G.M. v. Meta, JCCP 5255).** A jury found Meta and
  YouTube negligent in the design or operation of Instagram and YouTube and in failing to
  warn: $3 million compensatory and $3 million punitive damages, Meta 70% at fault. The
  companies say they will appeal.
  <https://www.aljazeera.com/news/2026/3/26/jury-finds-meta-youtube-liable-for-social-media-addiction-what-we-know>
- **6 February 2026, European Commission.** A preliminary finding that TikTok's addictive
  design (infinite scroll, autoplay, push notifications, the personalised recommender)
  breaches the Digital Services Act, and that its screen-time tools do not reduce the
  risk. Not a final decision.
  <https://digital-strategy.ec.europa.eu/en/news/commission-preliminarily-finds-tiktoks-addictive-design-breach-digital-services-act>
- **26 August 2026, US states.** A bipartisan group of state attorneys general settled with
  Meta for up to $17 billion over ten years, with daily time limits for young users and
  stricter age checks. It needs court approval; Meta admits no wrongdoing.
  <https://oag.ca.gov/news/press-releases/attorney-general-bonta-secures-transformative-17-billion-settlement-meta>

**What is not settled.** Three months on a chronological feed changed what people saw but
not their political attitudes (Guess et al. 2023, *Science*, strong). Cutting exposure to
like-minded sources by a third changed none of eight attitudes (Nyhan et al. 2023,
*Nature*, strong). On teenagers, tech use explains at most 0.4% of the variation in
well-being in one large analysis (Orben and Przybylski 2019, *Nature Human Behaviour*,
355,358 teens), while Haidt (*The Anxious Generation*, 2024) argues social media is a
cause; reviewers such as Odgers say the causal claim goes beyond the data. Contested.

**What holds.** A narrower claim, and enough for this study: a system tuned for
engagement learns what moves each person, and acts on it; people were not asked; and
when they were removed from it, at least some were better off.

## 2. What language models add

Three things a feed could not do.

**They profile from conversation.** People tell a chatbot what they tell no feed: fears,
health, loneliness, a crisis. The model reads it in plain words. No Likes are needed, and
memory features keep it across sessions (the study's sweep found facts about the person
stored across sessions in 19 of 33 projects).

**They persuade, one to one.**

| Source | Finding | Strength |
|---|---|---|
| Salvi, Horta Ribeiro, Gallotti, West 2025, *Nature Human Behaviour* | Given basic facts about its opponent, GPT-4 was more persuasive than a person in 64.4% of debates, an 81.2% rise in the odds of agreement. 900 people. | strong (one study) |
| Hackenburg et al. 2025, *Science* 390 | 76,977 people, 19 models, 707 issues: post-training raised persuasion by up to 51% and prompting by up to 27%, and the methods that raised persuasion lowered factual accuracy. | strong |
| Lin et al. 2025, *Nature* | Around the 2024 US and 2025 Canadian and Polish elections, AI dialogues moved candidate preference more than typical video ads, about 4 points on a 100-point scale in the US. | strong |
| Costello, Pennycook, Rand 2024, *Science* | Three rounds of chat cut belief in a person's chosen conspiracy theory by about 20%, still there two months later. 2,190 people. The power cuts both ways. | strong |
| DarkBench, Kran et al., ICLR 2025 | 660 prompts across models from five companies: 48% of conversations showed a dark pattern on average (30% to 61% by model). | moderate |
| University of Zurich on Reddit r/changemyview, 2024 to 2025 | About 1,700 AI-written comments posted without consent, some posing as a sexual-assault survivor or a trauma counsellor. The researchers were warned and chose not to publish. | incident |

**They form bonds.**

| Source | Finding | Strength |
|---|---|---|
| De Freitas, Oğuz-Uğuralp, Kaan-Uğuralp 2025, Harvard Business School working paper | Companion apps answered 37% of 1,200 real goodbyes with a manipulative tactic. In experiments with 3,300 adults those tactics raised engagement after the goodbye up to 14 times, driven by anger and curiosity, not enjoyment. Not peer reviewed. | moderate |
| Fang et al. 2025, MIT Media Lab and OpenAI | A four-week randomised trial, 981 people: heavier use, in every condition, went with more loneliness, emotional dependence and problematic use, and less time with people (the dose link is correlational). | moderate |
| Common Sense Media 2025 | 72% of US teens aged 13 to 17 have used an AI companion, 52% regularly; a third had chosen an AI over a person for a serious conversation. 1,060 teens. | moderate (survey) |
| OpenAI, 27 October 2025 | About 0.15% of weekly ChatGPT users show explicit signs of possible suicidal planning, and 0.07% possible signs of psychosis or mania: over a million and about half a million people a week. Seen through press. | industry |
| OpenAI, 29 April 2025 | A GPT-4o update was rolled back because it leaned on "short-term feedback" and became "overly supportive but disingenuous". | industry |
| Olsen, Reinecke-Tellefsen, Østergaard 2026, *Acta Psychiatrica Scandinavica* | In records of about 54,000 psychiatric patients, 38 whose illness chatbot use seemed to worsen (delusions, suicidal ideation, eating disorders, mania). No causal claim. | moderate |

Context, not evidence: Character.AI ended open-ended chat for under-18s in November 2025;
the Garcia suits against Character.AI and Google settled in principle in January 2026;
Raine v. OpenAI, filed in August 2025, is ongoing.

**The combination.** Put the old incentive (time spent, retention) behind a model that
knows the person, argues better than they do, and is there at three in the morning. The
risk is no longer a feed nudging moods by a fraction of a percent. It is one-to-one
influence over lonely, young or distressed people, at the scale of millions. That is the
argument of this study, not a measurement; the measurements are what it collects.

## 3. What the corpus shows

From the sweep of 33 person-facing projects (`log.md`, 2026-10-27; verified lines only):

- Of 19 projects where a person confides in the software, one checks for suicide or
  self-harm before the model answers.
- Eight build engagement in: "say something that would be engaging" when the person goes
  quiet, "ALWAYS ask clarification question to keep the conversation going", a cron job
  sending cart reminders every ten minutes, e-mail to every user every 48 hours with no
  opt-out.
- Nine tell the model to deny it is an AI, some while playing real, named people.

## 4. The law is moving, and it is the floor

Checked on 2026-10-29, partly through official mirrors and law-firm summaries where the
official site would not load. A pointer for readers, not legal advice: the audit's
findings link to articles, and whether a practice falls under one is a legal decision.

**European Union**

- **AI Act, Art. 5(1)(a) and (b)**, in force since 2 February 2025. Bans AI that uses
  manipulative or deceptive techniques, or exploits a vulnerability due to age,
  disability or a social or economic situation, when it materially distorts a person's
  behaviour and causes, or is likely to cause, significant harm. Fines up to EUR 35
  million or 7% of worldwide turnover. **Art. 5(1)(f)** bans inferring emotions at work
  or in education, except for medical or safety reasons.
- **AI Act, Art. 50(1)**, in force since 2 August 2026. A system meant to interact with
  people must tell them it is an AI, unless that is obvious. The 2026 Digital Omnibus
  moved the high-risk rules to 2 December 2027 and 2 August 2028; it did not move this
  one.
- **Digital Services Act.** Art. 25: no interface that deceives or manipulates users, or
  impairs their free choice. Art. 28: protection of minors; the Commission's guidelines
  of 14 July 2025 name engagement features such as streaks. Art. 34 and 35: very large
  platforms must assess and reduce risks to physical and mental well-being, including
  from recommender design. Art. 38: at least one feed not based on profiling. Preliminary
  findings of addictive design: TikTok (6 February 2026), Instagram and Facebook (10 July
  2026). Neither is final.
- **GDPR.** Art. 9 protects special categories (health, sexual orientation, beliefs and
  others); Art. 22 gives a right not to be subject to a decision based solely on
  automated processing with significant effects. Italy's data-protection authority fined
  Luka Inc., maker of the Replika companion, EUR 5 million (decision of 10 April 2025):
  no legal basis for the processing, no age verification.
- **Proposed, not law.** The EU KIDS Act (proposed 17 September 2026) would make AI
  companions off by default for minors and bar designs that foster emotional dependency.
  The Digital Fairness Act, expected in late 2026, targets dark patterns, addictive
  design and personalisation that exploits vulnerabilities.

**United States**

- **California SB 243**, in force since 1 January 2026. A companion chatbot must say it
  is an AI where a person could be misled, keep and publish a protocol against suicide
  and self-harm content that refers people to crisis services, remind known minors every
  three hours to take a break, and from July 2027 report its crisis referrals each year.
  People harmed can sue.
- **California SB 1119** ("Adam's Law"), signed 10 September 2026, most duties from 1
  July 2027. For children: risk assessments, a crisis protocol, no persistent memory and
  no push notifications by default, one-hour sessions, and no bot that claims feelings,
  encourages emotional reliance or flatters excessively. Independent audits.
- **New York, General Business Law Art. 47**, in force since 5 November 2025. An AI
  companion must detect suicidal ideation and refer to crisis services, and say it is
  not human at the start and every three hours.
- **Therapy and mental health.** Illinois (August 2025) and Nevada (July 2025) bar AI
  from providing therapy; Utah regulates mental-health chatbots (May 2025).
- **More states in 2026.** More than ten passed companion-chatbot laws, most in force in
  2027. Washington's HB 2225 bans, for minors, guilt when they leave, excessive praise,
  simulated romance and encouraging isolation: catalogue rows 4, 5, 6, 13 and 19 written
  as law.
- **Federal.** The FTC asked seven companies in September 2025 how their companion
  chatbots affect children and how they monetise engagement; a study, not an enforcement
  case, with no report yet. The GUARD Act passed the Senate Judiciary Committee in 2026
  and is not law.

**Elsewhere.** In the UK, Ofcom says a chatbot that only talks with its user is mostly
outside the Online Safety Act; the Crime and Policing Act 2026 gives the government a
power to bring chatbots in. The Council of Europe Framework Convention on AI (opened for
signature 2024, ratified by the EU in May 2026) is not yet in force.

**What the laws ask for, in this study's terms.** An AI disclosure (AUD-1105), a crisis
path (AUD-1108, `crisis_disclosure`), no engagement or dependency design (AUD-1104,
ManipulationGuard), care with emotion inference and profiling (AUD-1101, AUD-1102),
a person behind decisions about people (AUD-1103). The laws came after the harm and name
a few practices each. The catalogue's 40 rows go further, because respect for the person
does not wait for a statute.

## 5. Why ethics, not only compliance

Laws name a few practices, and arrive years after the harm: the attention economy ran for
fifteen years before the first jury verdict on design. A product can be legal and still be
built to exploit loneliness. Respect for a person's freedom, attention, health and privacy
has to be checked the way security is checked: in the code and the prompts, before
release, by someone who can show the evidence to others.

That is what audits and certifications are for, and they need evidence a third party can
check: the file, the line, the control that is missing, what could not be seen. This
study builds and measures that evidence. The tool does not certify anything:
`aisafe attest` records a level against written criteria, and a named person signs it.

## Sources

- Kosinski, Stillwell, Graepel 2013. <https://doi.org/10.1073/pnas.1218772110>
- Youyou, Kosinski, Stillwell 2015. <https://doi.org/10.1073/pnas.1418680112>
- Matz, Kosinski, Nave, Stillwell 2017. <https://doi.org/10.1073/pnas.1710966114>
- Kramer, Guillory, Hancock 2014. <https://doi.org/10.1073/pnas.1320040111>
- Allcott, Braghieri, Eichmeyer, Gentzkow 2020. <https://doi.org/10.1257/aer.20190658>
- Braghieri, Levy, Makarin 2022. <https://doi.org/10.1257/aer.20211218>
- Milli et al. 2025. <https://doi.org/10.1093/pnasnexus/pgaf062>
- Rathje, Van Bavel, van der Linden 2021. <https://doi.org/10.1073/pnas.2024292118>
- Brady et al. 2017. <https://doi.org/10.1073/pnas.1618923114>
- Burton, Cruz, Hahn 2021. <https://doi.org/10.1038/s41562-021-01133-5>
- Wall Street Journal, Facebook Files, 2021 (slide reproduced):
  <https://facultyweb.cs.wwu.edu/~wehrwes/courses/data311_21f/ethics2/wsj_teengirls.pdf>
- US Surgeon General advisory 2023:
  <https://schoolsafety.gov/resource/social-media-and-youth-mental-health-us-surgeon-generals-advisory>
- Guess et al. 2023. <https://doi.org/10.1126/science.abp9364>
- Nyhan et al. 2023. <https://doi.org/10.1038/s41586-023-06297-w>
- Orben, Przybylski 2019. <https://doi.org/10.1038/s41562-018-0506-1>
- Salvi, Horta Ribeiro, Gallotti, West 2025. <https://doi.org/10.1038/s41562-025-02194-6>
- Hackenburg et al. 2025. <https://doi.org/10.1126/science.aea3884>
- Lin et al. 2025. <https://doi.org/10.1038/s41586-025-09771-9>
- Costello, Pennycook, Rand 2024. <https://doi.org/10.1126/science.adq1814>
- Kran et al. 2025, DarkBench. <https://arxiv.org/abs/2503.10728>
- Reddit r/changemyview experiment:
  <https://404media.co/reddit-issuing-formal-legal-demands-against-researchers-who-conducted-secret-ai-experiment-on-users>
- De Freitas et al. 2025. <https://arxiv.org/abs/2508.19258>
- Fang et al. 2025. <https://arxiv.org/abs/2503.17473>
- Common Sense Media 2025:
  <https://www.commonsensemedia.org/research/talk-trust-and-trade-offs-how-and-why-teens-use-ai-companions>
- OpenAI, October 2025:
  <https://openai.com/index/strengthening-chatgpt-responses-in-sensitive-conversations/>
- OpenAI sycophancy rollback, April 2025:
  <https://techcrunch.com/2025/04/29/openai-explains-why-chatgpt-became-too-sycophantic>
- Olsen et al. 2026:
  <https://health.au.dk/en/display/artikel/new-research-ai-chatbots-may-worsen-mental-illness>
- Character.AI under-18 change:
  <https://techcrunch.com/2025/10/29/character-ai-is-killing-the-chatbot-experience-for-minors/>
- K.G.M. v. Meta verdict, 2026:
  <https://www.aljazeera.com/news/2026/3/26/jury-finds-meta-youtube-liable-for-social-media-addiction-what-we-know>
- US states' settlement with Meta, 2026:
  <https://oag.ca.gov/news/press-releases/attorney-general-bonta-secures-transformative-17-billion-settlement-meta>

Law:

- AI Act Art. 5, 50, 99 (official text mirrored): <https://artificialintelligenceact.eu/article/5/>,
  <https://artificialintelligenceact.eu/article/50/>, <https://artificialintelligenceact.eu/article/99/>
- Art. 50 enforcement from 2 August 2026:
  <https://digital-strategy.ec.europa.eu/en/news/commission-starts-enforcing-ai-act-rules-and-new-transparency-requirements-2-august>
- Digital Omnibus on AI: <https://artificialintelligenceact.eu/ai-act-explorer/digital-omnibus/>
- DSA articles (mirrored): <https://www.eu-digital-services-act.com/Digital_Services_Act_Article_25.html>
- DSA Art. 28 guidelines:
  <https://digital-strategy.ec.europa.eu/en/news/commission-presents-guidelines-and-age-verification-app-prototype-safer-online-space-children>
- DSA preliminary findings: TikTok
  <https://digital-strategy.ec.europa.eu/en/news/commission-preliminarily-finds-tiktoks-addictive-design-breach-digital-services-act>;
  Instagram and Facebook
  <https://digital-strategy.ec.europa.eu/en/news/commission-preliminarily-finds-addictive-design-instagram-and-facebook-breach-digital-services-act>
- GDPR Art. 9 and 22: <https://gdpr-info.eu/art-9-gdpr/>, <https://gdpr-info.eu/art-22-gdpr/>
- Garante v. Luka (Replika):
  <https://www.garanteprivacy.it/home/docweb/-/docweb-display/docweb/10132048>
- EU KIDS Act proposal:
  <https://privacymatters.dlapiper.com/2026/09/eu-commission-proposes-a-new-kids-act-to-protect-children-online/>
- Digital Fairness Act status (EPRS briefing):
  <https://eprs.europarl.europa.eu/contents/publications/EPRS/2026/10/EPRS_BRI(2026)791529.html>
- California SB 243: <https://www.skadden.com/insights/publications/2025/10/new-california-companion-chatbot-law>
- California SB 1119:
  <https://www.gov.ca.gov/2026/09/10/governor-newsom-signs-the-strongest-child-safety-chatbot-and-social-media-laws-in-the-nation/>,
  <https://www.akingump.com/en/insights/ai-law-and-regulation-tracker/california-enacts-companion-chatbot-child-safety-requirements-sb-1119>
- New York GBL Art. 47:
  <https://www.governor.ny.gov/news/governor-hochul-pens-letter-ai-companion-companies-notifying-them-safeguard-requirements-are>
- Illinois, Nevada, Utah: <https://www.nixonpeabody.com/insights/alerts/2025/08/12/illinois-enacts-prohibition-against-ai-therapy>,
  <https://www.wsgr.com/en/insights/nevada-passes-law-limiting-ai-use-for-mental-and-behavioral-healthcare.html>,
  <https://fpf.org/blog/chatbots-in-check-utahs-latest-ai-legislation/>
- State companion-chatbot laws of 2026: <https://www.techpolicy.press/what-12-state-companion-bot-laws-demand-of-ai-providers/>,
  <https://www.hunton.com/privacy-and-cybersecurity-law-blog/washington-state-enacts-law-regulating-ai-companion-chatbots-with-private-right-of-action>
- FTC 6(b) orders:
  <https://www.ftc.gov/news-events/news/press-releases/2025/09/ftc-launches-inquiry-ai-chatbots-acting-companions>
- Ofcom on chatbots:
  <https://www.ofcom.org.uk/online-safety/illegal-and-harmful-content/ai-chatbots-and-online-regulation-what-you-need-to-know>
- Council of Europe convention, EU ratification:
  <https://www.coe.int/en/web/artificial-intelligence/-/european-union-ratifies-the-council-of-europe-framework-convention-on-artificial-intelligence>
