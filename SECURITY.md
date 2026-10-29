# Security policy

## Reporting a vulnerability

Report privately through GitHub's vulnerability reporting for this repository:
https://github.com/ai-safe-earth/AnyAISafe/security/advisories/new

Do not open a public issue for a vulnerability. There is no separate e-mail
address and no published response-time commitment; the advisory thread is the
only channel, and it is where you will hear back.

## Scope

- The `aisafe` distribution, imported as `aisafe` (`aisafe.discovery`, `aisafe.analysis`,
  `aisafe.evidence`, `aisafe.rules`, `aisafe.review`, `aisafe.reporting`,
  `aisafe.evaluation`, `aisafe.policy`, `aisafe.devtools`).
- The `aisafe` command line: `audit`, `review`, `evaluate`, `fleet`, `skill`.
- The `ai-safety-audit` skill and its bootstrap scripts
  (`src/aisafe/skills/ai-safety-audit/scripts/` and the plugin's mirror under
  `plugins/aisafe/skills/`), and the Claude Code plugin (`.claude-plugin/`,
  `plugins/aisafe/`).
- The CI surface: `action.yml`, `.pre-commit-hooks.yaml` and the GitLab job
  template `.gitlab-ci-aisafe.yml`.

A rule that misses a prompt it should have reported is a detection gap, not a
vulnerability; report those as ordinary issues with the prompt, or add a case to
`bench/cases/`.

## What to include

- The affected version (`pip show aisafe`) or commit.
- The command, config or input that triggers the problem, minimised.
- What happens and what you expected; a stack trace or report excerpt if any.

## How releases are published

A `vX.Y.Z` tag runs `.github/workflows/release.yml`: the suite, the self-audit
and `scripts/bump_version.py --check` gate it, the wheel and sdist are built, and
PyPI publishing uses trusted publishing (OpenID Connect) behind a GitHub
environment with a required reviewer. No long-lived PyPI credential exists in the
repository or its secrets. A release you cannot trace to a tag, a workflow run
and that approval is not one of ours.

## What the tooling sends

`aisafe audit`, `aisafe review` and `aisafe skill` never send anything anywhere: no
model calls, no telemetry, no network sockets from their processes; the only child
process is read-only `git` for commit metadata. `aisafe fleet` clones only the URLs
you list (through `git`), audits each locally, and never searches for targets,
pushes or opens a pull request. `aisafe evaluate` sends its fixed, synthetic
scenarios to the URL you name and nothing else; non-loopback targets need
`--i-have-authorization`, and `--transcripts` mode opens no socket at all. Reports
redact secret-shaped text and can be shared only as carefully as the source they quote.
