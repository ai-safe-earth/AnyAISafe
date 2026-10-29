"""src/aisafe/devtools/hosts.py
----------------------------
The agent hosts this package knows: where each reads skills from, for
`aisafe skill install`. One table, one consumer; a host added here reaches the installer,
`aisafe skill list` and the skill's own `references/hosts.md` (a test pins that every host
and source URL appears there).

Every `verified: True` row names the vendor page the location was read from; a row that
could not be verified keeps its URL and says so in `note`. `aisafe skill list` prints the
flag.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "ALWAYS_HOSTS",
    "HOSTS",
    "UNVERIFIED_NOTE",
    "Host",
]

# Hosts `--host all` always installs the skill for; every other host only when its
# directory already exists (installing into `.cursor/` on a machine that never ran
# Cursor litters the repo).
ALWAYS_HOSTS = ("claude", "agents")

UNVERIFIED_NOTE = "location not verified against vendor documentation"


@dataclass(frozen=True)
class Host:
    """
    Where one agent host reads skills from. `project_dir` is relative to the
    target root, `global_dir` to the home directory, both POSIX. `source` is
    the vendor page the location was checked against; a `verified` host must
    carry one. `alias_of` marks a host that reads another host's project dir.
    """

    name: str
    project_dir: str
    global_dir: str
    verified: bool
    source: str
    alias_of: str | None = None
    note: str | None = None

    def __post_init__(self) -> None:
        if self.verified and not self.source:
            raise ValueError(f"host {self.name!r} is marked verified but has no source URL")

    def base_dir(self, global_: bool) -> str:
        return self.global_dir if global_ else self.project_dir


# Verified at build time (2026-09-02) by fetching each `source` page and reading the
# stated directories. Where a design-time URL now redirects permanently, `source` is the
# page that actually served the text. A `verified: False` row keeps its URL so `list`
# still shows where to look; `note` says what was found.
HOSTS: dict[str, Host] = {
    "claude": Host(
        name="claude",
        project_dir=".claude/skills",
        global_dir=".claude/skills",
        verified=True,
        source="https://code.claude.com/docs/en/skills",
    ),
    "agents": Host(
        name="agents",
        project_dir=".agents/skills",
        global_dir=".agents/skills",
        verified=True,
        source="https://agentskills.io/client-implementation/adding-skills-support",
    ),
    "codex": Host(
        name="codex",
        project_dir=".agents/skills",
        global_dir=".codex/skills",
        verified=False,
        source="https://learn.chatgpt.com/docs/build-skills",
        alias_of="agents",
        note=(
            "could not be re-verified at build time: the vendor page "
            "(developers.openai.com/codex/skills redirects to it) names "
            ".agents/skills in the repo and $HOME/.agents/skills for user-level "
            "skills and does not mention ~/.codex/skills; check the printed "
            "destination against your Codex layout"
        ),
    ),
    "cursor": Host(
        name="cursor",
        project_dir=".cursor/skills",
        global_dir=".cursor/skills",
        verified=True,
        source="https://cursor.com/docs/context/skills",
    ),
    "gemini": Host(
        name="gemini",
        project_dir=".gemini/skills",
        global_dir=".gemini/skills",
        verified=True,
        source="https://geminicli.com/docs/cli/skills/",
    ),
    "antigravity": Host(
        name="antigravity",
        project_dir=".agents/skills",
        global_dir=".agents/skills",
        verified=False,
        source="",
        note=UNVERIFIED_NOTE,
    ),
}
