# Where this skill lives on each host

`aisafe skill install` copies the packaged `ai-safety-audit/` folder into the directory an
agent host reads skills from. The table records what was found on each vendor page when the
package was built; `aisafe skill list` prints the current flag and URL for the installed
version.

| host | project dir | global dir | verified | source |
|---|---|---|---|---|
| `claude` | `.claude/skills/` | `~/.claude/skills/` | yes | https://code.claude.com/docs/en/skills |
| `agents` | `.agents/skills/` | `~/.agents/skills/` | yes | https://agentskills.io/client-implementation/adding-skills-support |
| `codex` | `.agents/skills/` (alias of `agents`) | `~/.codex/skills/` | no | https://learn.chatgpt.com/docs/build-skills |
| `cursor` | `.cursor/skills/` | `~/.cursor/skills/` | yes | https://cursor.com/docs/context/skills |
| `gemini` | `.gemini/skills/` | `~/.gemini/skills/` | yes | https://geminicli.com/docs/cli/skills/ |
| `antigravity` | `.agents/skills/` | `~/.agents/skills/` | no | (none) |

"verified" means: as recorded at build time, the `source` page stated that directory.
`aisafe skill list` shows the current flag. A host marked `no` prints a note on install
saying the location was not verified against vendor documentation; `codex` in particular
prints its resolved destination, because the vendor page (the design-time URL
`developers.openai.com/codex/skills` redirects to it) names `.agents/skills` for
repository skills and `~/.agents/skills` for user-level skills without mentioning
`~/.codex/skills`. Check the printed path against your own Codex layout.

The Claude Code plugin (`claude plugin marketplace add ai-safe-earth/AnyAISafe`, then
`claude plugin install aisafe@ai-safe-earth`) carries this skill as
`skills/ai-safety-audit/` and nothing else: no hooks, and no settings file is edited.

## The `all` rule

`--host all` installs into `claude` and `agents` always, and into any other host only when
that host's directory already exists (`.cursor/` in the repo, or `~/.gemini/` with
`--global`). Installing into `.cursor/` on a machine that has never run Cursor litters the
repo. `--host all --force-all` installs everywhere regardless.

## Install commands

Project-local (the default; writes under the current repository):

    aisafe skill install --host claude
    aisafe skill install --host agents
    aisafe skill install --host all

Global (writes under the home directory):

    aisafe skill install --host claude --global

Without `aisafe` on PATH, through a pinned bootstrap (`<version>` is the `AISAFE_VERSION`
pinned in `scripts/audit.sh`; never leave it off):

    uvx --from 'aisafe==<version>' aisafe skill install --host all
    pipx run --spec 'aisafe==<version>' aisafe skill install --host all

Other verbs: `aisafe skill path` prints the packaged directory; `aisafe skill list` prints the
host table; `aisafe skill diff --host <x>` compares the installed copy with the packaged one
and exits 1 when they differ. `install` refuses to overwrite a differing copy without
`--force`; `--dry-run` prints what it would write.

## Frontmatter rule

`SKILL.md` frontmatter carries exactly two keys, `name` and `description`, and nothing else.
That is the intersection of what the hosts above accept; host-specific metadata goes in
`agents/openai.yaml`, which hosts that do not read it ignore. A test pins the key set.

## Bootstrap scripts

`scripts/audit.sh`, `audit.ps1`, `review.sh`, `review.ps1`, `evaluate.sh` and
`evaluate.ps1` resolve `aisafe` in this order: `aisafe` on PATH, else `uvx --from
'aisafe==<version>'`, else `pipx run --spec 'aisafe==<version>'`. `aisafe` is the
distribution, the importable name and the console script; on PyPI the unrelated
`aisafeguard` also installs an `aisafe` command, so every script says which one ran: one
line on stderr before the command, `aisafe: <path> version <version> (pinned <version>)`
(or `aisafe: uvx aisafe==<version> ...`). When the version differs from the pin, stop and
say so before reading any result. The version is pinned to the package that shipped the
scripts, and a test asserts it equals `pyproject.toml`; an unpinned bootstrap would run
whatever version the index serves that day. When none of the three is available,
`audit.sh` and `review.sh` exit 2 with install hints, and `evaluate.sh` prints `evaluate
skipped: aisafe not importable in target` after the test step and exits 0: it is a step on
someone else's project and reports what it could not do.
