# ai-safety-audit (Claude Code plugin)

The `ai-safety-audit` skill, packaged for Claude Code. The plugin is the skill and nothing
else: it installs no hooks and changes no settings or permission files. The skill copy under
`skills/` is a byte-identical mirror of the canonical skill in
`src/aisafe/skills/ai-safety-audit/`, kept in sync by `scripts/sync_skill.py`.

Install:

    claude plugin marketplace add ai-safe-earth/AnyAISafe
    claude plugin install aisafe@ai-safe-earth

What the skill does, in five phases, each with your approval:

| phase | what runs | what you get |
|---|---|---|
| Survey | `aisafe audit` (JSON, against the baseline when one exists) | the findings by mechanism, each with its evidence status and the policy decision |
| Document | `aisafe audit --format html` | the before document: a mechanism map, the plan, what is UNKNOWN |
| Review | a walk through each finding; `aisafe review record` | a review record naming the person who read the prompts, bound to them by content hash |
| Remediate | one diff per approval, then a re-audit | the objective, inference or intervention removed, never a filter in front of the person |
| Evaluate | `aisafe evaluate` on a loopback or authorised endpoint, or on held transcripts | what the running system said in fixed scenarios |

Every command goes through the pinned bootstrap under `scripts/` (`audit`, `review`,
`evaluate`), which resolves `aisafe` on PATH, else `uvx --from "aisafe==<version>"`, else
`pipx run`. The audit calls no model, installs nothing and opens no socket; it writes only
under `.aisafe-audit/`. Findings describe evidence and the project's policy decision;
nothing here states a compliance verdict, and absence of a finding is not evidence of
safety.
