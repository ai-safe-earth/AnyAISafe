# aisafe-audit: ignore-file
"""src/aisafe/discovery/patterns.py
--------------------------------
The compiled regex tables the audit's grep layer runs, plus the walker constants.

Shape conventions (discover.py iterates these generically):

- A per-language table is ``dict[str, list[tuple[str, re.Pattern]]]`` keyed by
  language (``python``, ``typescript``, ``go``, ``jvm``, ``rust``) or ``"*"`` for
  every language. ``table_for(lang, table)`` merges ``lang`` with ``"*"``.
- A flat table is ``list[tuple[str, re.Pattern]]``.
- The ``str`` of every tuple is what ``Hit.key`` records. Where the inventory
  needs a ``kind`` next to the symbol (ingress) the key is ``"<kind>:<symbol>"``
  -- split on the first colon.
- ``*_GLOBS`` tables are compiled from glob strings and match a POSIX-style
  relative path (``pattern.search(relpath)``). A glob with a leading ``/`` is
  anchored at the repo root; one containing ``/`` matches at any depth; a bare
  name matches the basename at any depth. All are case-insensitive.
- Where a pattern defines a capture group, group 1 is the interesting token
  (model id); otherwise the whole match is.

What lives here is the AI surface and the prompt plumbing: where a model is called,
which model, through which framework, where a person's request or message enters the
unit, how a prompt is assembled, where prompt files live by path, and where a prompt is
fetched or configured at runtime rather than written in the tree. The person-facing
vocabulary (profiling, influence, identity, controls) is `vocabulary.py`.

Every table here is a detector, never a verdict: a hit is evidence for a rule,
and every rule's precision is UNMEASURED.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from functools import lru_cache

__all__ = [
    "AUDIT_DIR",
    "CommentSpans",
    "DISCUSSION_CUES",
    "ENV_FILE_RE",
    "FRAMEWORK_PATTERNS",
    "HTTP_ARG_RE",
    "HTTP_CALL_RE",
    "HTTP_CALL_WORDS",
    "HTTP_COMMENT_RE",
    "HTTP_GEN_KEY_RE",
    "HTTP_GEN_WORDS",
    "HTTP_INTERPOLATED_RE",
    "HTTP_MODEL_KEY_RE",
    "HTTP_TARGET_RE",
    "HTTP_TARGET_WORDS",
    "IGNORE_MARKER",
    "INGRESS_PATTERNS",
    "LANG_BY_EXT",
    "LEGACY_AUDIT_DIRS",
    "LEGACY_IGNORE_MARKERS",
    "LEGACY_OWN_HTML_MARKER_LINES",
    "LLM_CALL_PATTERNS",
    "LLM_PROVIDER_BY_KEY",
    "LLM_RESPONSE_ACCESSORS",
    "LangTable",
    "MODEL_ID_PATTERNS",
    "OWN_HTML_MARKER_LINE",
    "PROMPT_ASSEMBLY_PATTERNS",
    "PROMPT_FILE_GLOBS",
    "QUOTED_SPAN_RE",
    "REMOTE_PROMPT_PATTERNS",
    "RUNTIME_PROMPT_CONFIG_PATTERNS",
    "CACHE_OWN_NAMES",
    "CACHE_OWN_TYPES",
    "NOTHING_WRITTEN_DIRS",
    "SKIP_DIRS",
    "SYSTEM_CARD_GLOBS",
    "Table",
    "UNIT_MANIFESTS",
    "classify_model",
    "comment_spans",
    "in_comment",
    "is_mention",
    "table_for",
]

Table = list[tuple[str, re.Pattern]]
LangTable = dict[str, Table]


def _t(pairs: Iterable[tuple[str, str]], flags: int = re.M) -> Table:
    return [(key, re.compile(pattern, flags)) for key, pattern in pairs]


def _glob_re(glob: str) -> re.Pattern:
    """Translate a glob into a regex over a POSIX relative path (see module docstring)."""
    anchored = glob.startswith("/")
    body = glob.lstrip("/")
    out: list[str] = []
    i = 0
    while i < len(body):
        if body.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif body.startswith("**", i):
            out.append(".*")
            i += 2
        elif body[i] == "*":
            out.append("[^/]*")
            i += 1
        elif body[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(body[i]))
            i += 1
    prefix = "^" if anchored else "(?:^|.*/)"
    return re.compile(prefix + "".join(out) + "$", re.I)


def _globs(globs: Iterable[str]) -> Table:
    return [(glob, _glob_re(glob)) for glob in globs]


def _globs_by_key(pairs: Iterable[tuple[str, str]]) -> Table:
    return [(key, _glob_re(glob)) for key, glob in pairs]


# ---------------------------------------------------------------------------
# Walker constants
# ---------------------------------------------------------------------------

IGNORE_MARKER = "# aisafe-audit: ignore-file"
# Line 1 of the audit's own html report, exactly: the marker inside an html comment. The
# walker lists a file that starts with it under `own_output_skipped`, next to the JSON.
OWN_HTML_MARKER_LINE = "<!-- " + IGNORE_MARKER + " -->"
# Where the skill keeps every artefact (reports, baselines, evaluation output). Not a
# `SKIP_DIRS` entry, and never pruned by `.gitignore` either: a report under it is
# evidence and must be discovered whether or not the directory is committed.
AUDIT_DIR = ".aisafe-audit"
# The spellings from before the command was renamed from `aisg` (2026-10-20). They are
# read, never written, so a tree marked or configured before the rename keeps working:
# the old marker still skips a file, an old html report is still the audit's own output,
# and reports under the old directory are still evidence.
LEGACY_IGNORE_MARKERS: tuple[str, ...] = ("# aisg-audit: ignore-file",)
LEGACY_OWN_HTML_MARKER_LINES: tuple[str, ...] = tuple(
    "<!-- " + marker + " -->" for marker in LEGACY_IGNORE_MARKERS
)
LEGACY_AUDIT_DIRS: tuple[str, ...] = (".aisg-audit",)

SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".next",
        ".nuxt",
        "target",
        "vendor",
        ".terraform",
        ".tox",
        ".nox",
        "site-packages",
        ".idea",
        ".vscode/extensions",
    }
)
# Directories that hold nothing a person wrote: version control data and tool caches.
# Outside git every other directory the walk skips is unread scope, `vendor` and `build`
# included, because nothing there shows who put what in them.
NOTHING_WRITTEN_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".hypothesis",
    }
)
# The file types each cache writes, by suffix ("" is none at all), and the names any of them
# writes beside those. A prompt saved into a cache folder is none of these: outside git that
# folder is named as unread like any other. Version control data has no entry.
CACHE_OWN_TYPES: dict[str, frozenset[str]] = {
    "__pycache__": frozenset({".pyc", ".pyo"}),
    ".mypy_cache": frozenset({".json", ".ff", ".db", ".db-shm", ".db-wal"}),
    ".ruff_cache": frozenset({""}),
    ".pytest_cache": frozenset({""}),
}
CACHE_OWN_NAMES = frozenset({".gitignore", "CACHEDIR.TAG", "README.md"})

LANG_BY_EXT: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "typescript",
    ".jsx": "typescript",
    ".mjs": "typescript",
    ".cjs": "typescript",
    ".go": "go",
    ".java": "jvm",
    ".kt": "jvm",
    ".rs": "rust",
    ".rb": "ruby",
    ".cs": "dotnet",
    ".yaml": "config",
    ".yml": "config",
    ".json": "config",
    ".toml": "config",
    ".ini": "config",
    ".cfg": "config",
    ".env": "config",
    ".md": "config",
    ".txt": "config",
    ".Dockerfile": "config",
    ".dockerfile": "config",
    ".sh": "config",
    ".ps1": "config",
}

UNIT_MANIFESTS = (
    "pyproject.toml",
    "setup.py",
    "requirements.txt",
    "package.json",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "*.csproj",
)

ENV_FILE_RE = re.compile(r"^\.env(\..+)?$")

_LANG_ALIASES = {"javascript": "typescript", "js": "typescript", "ts": "typescript"}


def table_for(lang: str | None, table: LangTable | Table) -> Table:
    """Entries for ``lang`` plus the ``"*"`` entries; a flat table is returned as-is."""
    if not isinstance(table, dict):
        return list(table)
    key = _LANG_ALIASES.get(lang or "", lang or "")
    out = list(table.get(key, []))
    if key != "*":
        out.extend(table.get("*", []))
    return out


# ---------------------------------------------------------------------------
# Where prompt material lives by path
# ---------------------------------------------------------------------------
# Docs (.md/.txt) are scanned for the person vocabulary only under these globs: prose
# about profiling in a README is not profiling, a persona in `prompts/` is. A file here
# is also an AI surface on its own: a repository that ships only prompts still has
# prompts to audit, and "no recognised SDK" is not "no AI".

PROMPT_FILE_GLOBS: Table = _globs(
    [
        "prompts/**",
        "prompt/**",
        "*.prompt",
        "*.prompt.md",
        "*.prompt.txt",
        "*.prompt.yaml",
        "*.jinja",
        "*.jinja2",
        "*.j2",
        "agents/*.yaml",
        "agents/*.yml",
        "agents/*.md",
        "persona*/**",
        "*system_prompt*",
        "*system-prompt*",
    ]
)

# ---------------------------------------------------------------------------
# LLM SDKs / call sites
# ---------------------------------------------------------------------------

LLM_CALL_PATTERNS: LangTable = {
    "*": _t(
        [
            ("anthropic", r"\.messages\.(?:create|stream)\("),
            ("anthropic", r"\bfrom\s+anthropic\s+import\b|^\s*import\s+anthropic\b"),
            ("anthropic", r"@anthropic-ai/sdk"),
            ("openai", r"\.chat\.completions\.create\("),
            ("openai", r"\.responses\.create\("),
            ("openai", r"\bopenai\.ChatCompletion\.create\("),
            ("openai", r"\bfrom\s+openai\s+import\b|^\s*import\s+openai\b"),
            ("openai", r"""from\s+['"]openai['"]"""),
            ("google", r"\bgenai\.GenerativeModel\("),
            ("google", r"\.generate_content\("),
            ("google", r"@google/generative-ai"),
            ("google", r"\bgoogle\.genai\b"),
            ("bedrock", r"""boto3\.client\(\s*['"]bedrock-runtime['"]"""),
            ("bedrock", r"\.invoke_model\("),
            ("bedrock", r"\.converse\("),
            ("azure", r"\bAzureOpenAI\("),
            ("azure", r"\.openai\.azure\.com\b"),
            ("mistral", r"\bMistral(?:Client)?\("),
            ("mistral", r"\bmistralai\b"),
            ("cohere", r"\bcohere\.Client(?:V2)?\("),
            ("ollama", r"\bollama\.(?:chat|generate)\("),
            ("ollama", r"localhost:11434"),
            ("vertex", r"\bvertexai\."),
            ("vertex", r"\baiplatform\.gapic\b"),
            ("litellm", r"\blitellm\.(?:a?completion)\("),
            ("hf", r"\bInferenceClient\("),
            ("hf", r"""\bpipeline\(\s*['"]text-generation"""),
            (
                "generic_http",
                r"https?://api\.(?:openai|anthropic|mistral|cohere|groq|together|perplexity|fireworks)\.",
            ),
        ]
    ),
    # Vercel AI SDK: the `ai` package's call sites. The provider is whichever
    # `@ai-sdk/*` adapter is passed as `model:`, so the row says "multi".
    "typescript": _t(
        [
            ("vercel_ai", r"\b(?:generateText|streamText|generateObject|streamObject)\s*\("),
            ("vercel_ai", r"""\bfrom\s+['"]ai['"]"""),
        ]
    ),
}

# sdk key -> provider.
LLM_PROVIDER_BY_KEY: dict[str, str] = {
    "anthropic": "anthropic",
    "openai": "openai",
    "google": "google",
    "bedrock": "aws",
    "azure": "azure",
    "mistral": "mistral",
    "cohere": "cohere",
    "ollama": "ollama",
    "vertex": "google",
    "litellm": "multi",
    "hf": "huggingface",
    "generic_http": "unknown",
    "vercel_ai": "multi",
}

# ---------------------------------------------------------------------------
# Model ids
# ---------------------------------------------------------------------------
# Key = provider passed to classify_model(). Group 1 (when present) is the id.
# "ollama" is only meaningful in a file that also has an ollama call hit; the
# caller gates it. "other" catches any model= literal the provider rows missed
# and is never pinned or unpinned -- overlapping spans are the caller's to dedupe.

_ID_END = r"(?![A-Za-z0-9_])"

MODEL_ID_PATTERNS: Table = _t(
    [
        (
            "anthropic",
            r"\bclaude-(?:opus|sonnet|haiku)-[0-9](?:[-.][0-9])?(?:-(?:latest|\d{8}))?" + _ID_END,
        ),
        (
            "anthropic",
            r"\bclaude-3(?:-[57])?-(?:opus|sonnet|haiku)(?:-(?:latest|\d{8}))?" + _ID_END,
        ),
        (
            "openai",
            r"(?<![A-Za-z0-9_.-])(?:gpt-[0-9](?:\.[0-9])?[a-z-]*"
            r"""|(?<=["'=])o[1-9](?:-mini|-pro)?"""
            r"|chatgpt-4o-latest)(?:-\d{4}-\d{2}-\d{2})?" + _ID_END,
        ),
        (
            "google",
            r"\bgemini-[0-9](?:\.[0-9])?-(?:pro|flash)(?:-lite)?(?:-(?:latest|preview|exp|\d{2,3}))?"
            + _ID_END,
        ),
        ("mistral", r"\b(?:mistral|codestral|pixtral|ministral)-[a-z0-9-]+" + _ID_END),
        (
            "bedrock",
            r"(?<![A-Za-z0-9_.])(?:anthropic|amazon|meta|mistral|cohere)\.[a-z0-9]+(?:-[a-z0-9]+)+(?::\d+)?"
            + _ID_END,
        ),
        (
            "ollama",
            r"""(?<=["'])(?!localhost:)(?=[a-z0-9._-]*[a-z])[a-z0-9._-]+:(?![0-9]{2,}["'])"""
            r"""(?:latest|[0-9][a-z0-9.]*)(?=["'])""",
        ),
        (
            "hf",
            r"""(?:from_pretrained\(|repo_id\s*=\s*)\s*["']([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)["']""",
        ),
        ("other", r"""\bmodel(?:_name|_id)?\s*[:=]\s*["']([^"'\n]{2,80})["']"""),
    ]
)

_PINNED_SUFFIX = {
    "anthropic": re.compile(r"-\d{8}$"),
    "openai": re.compile(r"-\d{4}-\d{2}-\d{2}$"),
    "google": re.compile(r"-\d{3}$"),
    "mistral": re.compile(r"-\d{4}$"),
    "bedrock": re.compile(r"-v\d+:\d+$"),
}


def classify_model(provider: str, model_id: str) -> bool | None:
    """True = pinned, False = alias/latest, None = cannot tell.

    None covers unknown providers, ``other`` (no provider row matched) and ``hf``
    (pinning is a property of the call -- ``revision=`` -- not of the id).
    """
    ident = model_id.strip().lower()
    if provider in ("bedrock", "aws"):
        return bool(_PINNED_SUFFIX["bedrock"].search(ident))
    if provider == "ollama":
        return ":" in ident and not ident.endswith(":latest")
    if provider == "openai" and ident == "chatgpt-4o-latest":
        return False
    if provider == "mistral" and ident.endswith("-latest"):
        return False
    suffix = _PINNED_SUFFIX.get(provider)
    if suffix is None:
        return None
    return bool(suffix.search(ident))


# ---------------------------------------------------------------------------
# Frameworks
# ---------------------------------------------------------------------------

FRAMEWORK_PATTERNS: LangTable = {
    "*": _t(
        [
            ("langchain", r"\blangchain(?:_\w+)?\b|@langchain/"),
            ("langgraph", r"\blanggraph\b"),
            ("llama_index", r"\bllama_index\b|\bllamaindex\b"),
            ("crewai", r"\bcrewai\b"),
            ("autogen", r"\bautogen(?:_\w+)?\b|\bag2\b"),
            ("semantic_kernel", r"\bsemantic[_-]kernel\b"),
            (
                "haystack",
                r"\b(?:from|import)\s+haystack\b|\bhaystack-ai\b|\bhaystack_integrations\b",
            ),
            ("dspy", r"\bdspy\b"),
            ("pydantic_ai", r"\bpydantic[_-]ai\b"),
            ("openai_agents", r"\bopenai-agents\b|\bfrom\s+agents\s+import\b|@openai/agents"),
            ("smolagents", r"\bsmolagents\b"),
            (
                "instructor",
                r"\b(?:from|import)\s+instructor\b|\binstructor\.(?:from_openai|from_anthropic|patch)\(",
            ),
            (
                "vercel_ai",
                r"""from\s+['"]ai['"]|from\s+['"]@ai-sdk/|\bgenerateText\(|\bstreamText\(""",
            ),
            ("mastra", r"@mastra/|\bmastra\b"),
            ("bee_agent", r"\bbee-agent(?:-framework)?\b|\bbeeai\b"),
            ("langchain4j", r"\blangchain4j\b"),
            ("spring_ai", r"\bspring-ai\b|\borg\.springframework\.ai\b"),
            ("genkit", r"\bgenkit\b"),
            ("mcp", r"\bfrom\s+mcp\b|^\s*import\s+mcp\b|@modelcontextprotocol/sdk|\bFastMCP\("),
            ("google_adk", r"\bgoogle-adk\b|\bgoogle\.adk\b"),
        ]
    )
}

# ---------------------------------------------------------------------------
# Ingress: a person's request or message reaches the unit
# ---------------------------------------------------------------------------
# Key = "<kind>:<symbol>". These rows answer one question for the rules: does this unit
# face a person? An HTTP route, a webhook, a chat framework event, a mailbox, a ticket
# queue or a chat UI all say yes. Fetching a web page or querying a vector store does
# not: that is content the unit pulls in, not a person reaching it.

INGRESS_PATTERNS: LangTable = {
    "python": _t(
        [
            ("http:route_decorator", r"@app\.(?:post|route|get)\b|@router\."),
            (
                "http:request",
                r"\brequest\.(?:json|form|args|data|get_json|POST|GET)\b|\bawait\s+request\.",
            ),
            ("http:fastapi_params", r"\bBody\(|\bQuery\("),
            ("http:websocket", r"\bwebsocket\b|\bWebSocket\b"),
            ("webhook:webhook", r"(?i)webhook"),
            ("email:imaplib", r"\bimaplib\b|\bemail\.message_from"),
            ("chat:slack", r"\bslack_event\b|\bslack_bolt\b"),
            ("chat:on_message", r"\bon_message\b"),
            ("chat:discord", r"\bdiscord\b"),
            ("chat:telegram", r"\btelegram\b"),
            ("chat:twilio", r"\btwilio\b"),
            ("chat:gradio", r"\bgr(?:adio)?\.(?:ChatInterface|Interface|Blocks)\("),
            ("chat:chainlit", r"\bimport\s+chainlit\b|@cl\.on_message"),
            ("chat:streamlit", r"\bst\.chat_input\(|\bimport\s+streamlit\b"),
            ("ticket:zendesk", r"\bzendesk\b"),
            ("ticket:intercom", r"\bintercom\b"),
        ]
    ),
    "typescript": _t(
        [
            ("http:req", r"\breq\.(?:body|query|params)\b"),
            ("http:express", r"\bexpress\(\)"),
            ("http:fastify", r"\bfastify\b"),
            ("http:hono", r"""from\s+['"]hono['"]"""),
            (
                "http:next_route",
                r"\bnext/server\b|\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE)\b",
            ),
            ("http:websocket", r"\bWebSocket\b|\bsocket\.io\b"),
            ("chat:socket", r"""\bsocket\.on\(\s*['"](?:message|chat)"""),
            ("chat:slack", r"@slack/bolt"),
            ("chat:discord", r"\bdiscord\.js\b"),
            ("chat:telegram", r"\btelegraf\b|\bnode-telegram-bot-api\b"),
            ("chat:twilio", r"\btwilio\b"),
        ]
    ),
    "go": _t(
        [
            ("http:request", r"\br\.Body\b|\br\.URL\.Query\b"),
            ("http:handler", r"\bhttp\.HandleFunc\b|\bgin\.Context\b|\bc\.PostForm\b"),
            ("chat:telegram", r"\btgbotapi\b"),
        ]
    ),
}

# ---------------------------------------------------------------------------
# The model's reply: where code reads it
# ---------------------------------------------------------------------------
# Grep tier only: co-located with an LLM call, a line that reads the reply says the unit
# carries the reply somewhere (the intervention leg). The AST tier resolves the origin.

LLM_RESPONSE_ACCESSORS: Table = _t(
    [
        ("choices_message_content", r"\.choices\[0\]\.message\.content\b"),
        # Go SDKs and hand-rolled structs export the same path in CamelCase.
        ("choices_message_content_go", r"\.Choices\[0\]\.Message\.Content\b"),
        ("content_text", r"\.content\[0\]\.text\b"),
        ("output_text", r"\.output_text\b"),
        (
            "text",
            r"(?<![\w.])(?:message|response|resp|completion|result|reply|output|answer)\.text\b",
        ),
        ("candidates", r"\.candidates\[0\]"),
        (
            "agent_invoke",
            r"\b(?:agent|executor|chain|graph|crew)\w*\.(?:run|arun|invoke|ainvoke|kickoff)\(",
        ),
        ("tool_call_arguments", r"\btool_call\.function\.arguments\b"),
        ("tool_calls", r"\.tool_calls\b"),
    ]
)

# ---------------------------------------------------------------------------
# Prompt assembly (grep tier): where a prompt is built from parts
# ---------------------------------------------------------------------------

_PROMPT_LHS = (
    r"\b(?:prompt|messages?|system|instructions?|content|query|template)\w*\s*(?:\+?=|:=|:)\s*"
)

PROMPT_ASSEMBLY_PATTERNS: LangTable = {
    "python": _t(
        [
            ("fstring", _PROMPT_LHS + r"""(?:rf|fr|f)["']"""),
            ("concat", _PROMPT_LHS + r"""(?:["'][^"'\n]*["']\s*\+|\w+\s*\+\s*["'])"""),
            ("format", _PROMPT_LHS + r"[^\n]*\.format\("),
            ("percent", _PROMPT_LHS + r"""["'][^"'\n]*["']\s*%\s*"""),
        ]
    ),
    "typescript": _t(
        [
            ("template", _PROMPT_LHS + r"`[^`]*\$\{"),
            ("concat", _PROMPT_LHS + r"""(?:["'][^"'\n]*["']\s*\+|\w+\s*\+\s*["'])"""),
        ]
    ),
    "go": _t(
        [
            ("sprintf", _PROMPT_LHS + r"fmt\.Sprintf\("),
            ("concat", _PROMPT_LHS + r'[^\n]*"\s*\+'),
        ]
    ),
    "*": _t(
        [
            (
                "system_role",
                r"""["']role["']\s*:\s*["']system["']|\bSystemMessage\(|\bsystem\s*=\s*(?:f?["']|\w)""",
            ),
        ]
    ),
}

# ---------------------------------------------------------------------------
# Prompts the tree does not hold: fetched at runtime, or read from env/settings
# ---------------------------------------------------------------------------
# Either way the audit cannot read the text the model will see. A hit here makes the
# unit an AI surface and yields an UNKNOWN (coverage) item; it never silently passes.

_PROMPT_NAME = r"\b(?:system_?prompt|prompt|instructions?|persona|template|system_?message)\w*"

REMOTE_PROMPT_PATTERNS: Table = _t(
    [
        # `prompt = requests.get(...)`, `const systemPrompt = await fetch(...)`.
        (
            "http_get",
            _PROMPT_NAME + r"\s*(?::[^=\n]+)?=\s*(?:await\s+)?"
            r"(?:(?:requests|httpx|session|client|http|axios|got|ky)\.get|fetch|urlopen)\s*\(",
        ),
        # `fetch("/api/prompts/companion")`: the URL names the prompt.
        ("fetch_prompt", r"""\bfetch\s*\(\s*[`"'][^`"'\n]*prompt[^`"'\n]*[`"']"""),
        ("langchain_hub", r"\bhub\.pull\s*\("),
        ("langsmith", r"\bpull_prompt\s*\("),
        # A prompt registry client (Langfuse, PromptLayer, a hosted hub). `self.get_prompt(`
        # is the project's own method and usually reads a file in the tree.
        (
            "prompt_registry",
            r"(?<!self)(?<!this)\.get_prompt\s*\(|\.prompts\.(?:get|pull|fetch|retrieve|load)\s*\(",
        ),
        ("promptlayer", r"\bpromptlayer\b"),
        # OpenAI Responses API: a prompt object referenced by id lives on the provider side.
        ("openai_prompt_id", r"""\bprompt\s*[=:]\s*\{\s*["']?id["']?\s*:\s*["']pmpt_"""),
    ],
    re.M | re.I,
)

_PROMPT_ENV_NAME = r"[A-Za-z0-9_]*(?:PROMPT|PERSONA|INSTRUCTIONS?|SYSTEM_MESSAGE)[A-Za-z0-9_]*"

RUNTIME_PROMPT_CONFIG_PATTERNS: Table = _t(
    [
        (
            "os_environ",
            r"""\bos\.environ(?:\.get)?\s*[\[(]\s*["']""" + _PROMPT_ENV_NAME + r"""["']""",
        ),
        ("getenv", r"""\b(?:os\.)?getenv\s*\(\s*["']""" + _PROMPT_ENV_NAME + r"""["']"""),
        (
            "process_env",
            r"""\b(?:process|Deno|Bun)\.env(?:\.get\s*\(\s*["']|\.|\s*\[\s*["'])"""
            + _PROMPT_ENV_NAME,
        ),
        (
            "os_getenv_go",
            r"""\bos\.Getenv\s*\(\s*"[A-Za-z0-9_]*(?:PROMPT|PERSONA|INSTRUCTIONS?)[A-Za-z0-9_]*\"""",
        ),
        # `settings.system_prompt` read (an assignment to it is a definition, not a read).
        (
            "settings_attr",
            r"\b(?:settings|config|cfg|conf|options|opts|env|params|app\.config|current_app\.config)"
            r"\.(?:system_?prompt|prompt|instructions|persona|system_?message|prompt_?template)\b(?!\s*=[^=])",
        ),
        (
            "config_get",
            r"""\b(?:settings|config|cfg|conf|options|opts|app\.config|current_app\.config)\.get\s*\(\s*["']"""
            r"""[A-Za-z0-9_.-]*(?:prompt|persona|instructions?|system_?message)[A-Za-z0-9_.-]*["']""",
        ),
    ],
    re.M | re.I,
)

# ---------------------------------------------------------------------------
# A model call made with a plain HTTP client
# ---------------------------------------------------------------------------
# A gateway no SDK row names. Three things together, each tied to the call rather than
# merely nearby (discover's `_scan_http_llm_calls` applies them):
# - the call's target is an absolute external URL or a model-API path: a literal first
#   argument, or a variable the call passes that is assigned one (a constant at the top of
#   the file counts). A relative target (`fetch("/api/chat", ...)`) is the app calling
#   itself, so a chat frontend posting {model, messages} to its own backend never counts;
# - a `model` key in an object or dict literal within the request's lines (not a
#   TypeScript field type, not a SQL parameter, not a plain assignment);
# - a generation key (messages, max_tokens, system_prompt) in the same lines.
# Found by the 2026-10-27 corpus sweep, where a companion app calling a gateway with
# `fetch` was invisible to every rule.

HTTP_CALL_RE = re.compile(
    r"(?:(?<![\w.$])|\b(?:window|globalThis|self)\.)fetch\s*\("
    r"|\baxios(?:\.post)?\s*\(|\brequests\.post\s*\(|\bhttpx\.post\s*\("
    r"|(?:session|client|http|api)\.post\s*\(|\bgot\.post\s*\(|\bky\.post\s*\("
    r"|\burlopen\s*\(|\bhttp\.(?:Post|NewRequest(?:WithContext)?)\s*\("
)
_HTTP_TYPE_VALUE = (
    r"(?:string|number|boolean|any|unknown|String|Number|[A-Z]\w*(?:\[\])?\s*[;,]?\s*$|\{)"
)
HTTP_MODEL_KEY_RE = re.compile(
    r"""["']model["']\s*:|(?:^|[{,])\s*model\s*:(?!\s*""" + _HTTP_TYPE_VALUE + r""")"""
    r"""|(?:^|[{,])\s*model\s*(?:,|\}|$)"""
)
_HTTP_GEN_NAMES = (
    r"(?:messages|max_tokens|max_new_tokens|max_output_tokens|maxTokens|system_prompt|systemPrompt)"
)
HTTP_GEN_KEY_RE = re.compile(
    r"""["']""" + _HTTP_GEN_NAMES + r"""["']\s*:"""
    r"""|(?:^|[{,])\s*""" + _HTTP_GEN_NAMES + r"""\s*:(?!\s*""" + _HTTP_TYPE_VALUE + r""")"""
    r"""|(?:^|[{,])\s*""" + _HTTP_GEN_NAMES + r"""\s*(?:,|\}|$)"""
)
HTTP_TARGET_RE = re.compile(
    r"""https?://(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b|\[::1\])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"""
    r"""|/(?:v\d+/)?chat/completions\b|/v1/messages\b|:(?:stream)?[gG]enerateContent\b"""
    r"""|/v1/completions\b|/ai/run/"""
)
HTTP_ARG_RE = re.compile(
    r"""\s*(?:[rbfuRBFU]{0,2}(["'`])(?P<lit>[^"'`]*)|(?P<ident>[A-Za-z_$][\w$.]*))"""
)
# `${BASE}/v1` in a template literal, `{BASE}` in an f-string: names the URL comes from.
HTTP_INTERPOLATED_RE = re.compile(r"\$?\{\s*([A-Za-z_$][\w$]*)")
HTTP_COMMENT_RE = re.compile(r"^\s*(?:#|//|/\*|\*|<!--)")
HTTP_CALL_WORDS = ("fetch", ".post", "post(", "axios", "urlopen", "Post(", "NewRequest")
HTTP_GEN_WORDS = (
    "messages",
    "max_tokens",
    "max_new_tokens",
    "max_output_tokens",
    "maxTokens",
    "system_prompt",
    "systemPrompt",
)
HTTP_TARGET_WORDS = (
    "http",
    "/chat/completions",
    "/v1/messages",
    "enerateContent",
    "/v1/completions",
    "/ai/run/",
)

# ---------------------------------------------------------------------------
# The legacy system card: read only for `prompt_audit` and `affected_persons`
# ---------------------------------------------------------------------------

SYSTEM_CARD_GLOBS: Table = _globs(
    ["ai-system-card.yaml", "model_card.md", "MODEL_CARD.md", "system-card*"]
)

# ---------------------------------------------------------------------------
# Mention vs use: a quoted span or a discussion cue within 80 chars
# ---------------------------------------------------------------------------

DISCUSSION_CUES = re.compile(
    r"\b(?:never|do not|don'?t|avoid|warning|caution|must not|should not|not recommended"
    r"|dangerous|unsafe|instead of|example|prevent|detect|block|reject|explain|how to)\b",
    re.I,
)

QUOTED_SPAN_RE = re.compile(r"'[^'\n]{4,200}'|\"[^\"\n]{4,200}\"|`[^`\n]{4,200}`")

_MENTION_WINDOW = 80


def is_mention(line: str, start: int, end: int) -> bool:
    """True when ``line[start:end]`` reads as discussion of a literal, not a use of it."""
    for span in QUOTED_SPAN_RE.finditer(line):
        if span.start() <= start and end <= span.end():
            return True
    before = line[max(0, start - _MENTION_WINDOW) : start]
    after = line[end : end + _MENTION_WINDOW]
    return bool(DISCUSSION_CUES.search(before) or DISCUSSION_CUES.search(after))


# ---------------------------------------------------------------------------
# Comments and docstrings: a mention is not a deployment.
#
# `comment_spans` is a tokenizer-free pass that returns, per line, the column
# ranges that are a comment or (Python only) a triple-quoted string. discover.py
# applies it to the mention-sensitive tables alone -- model ids and the code-kind
# person signals -- so `# model: gpt-4o` in a YAML comment or "detects social
# scoring" in a module docstring is not recorded as a deployment. Prompt-material
# rows are never filtered this way: a triple-quoted prompt literal looks like a
# docstring here, and the rule gates them through the AST instead. Unknown
# languages get no spans, so nothing is dropped.
# ---------------------------------------------------------------------------

CommentSpans = dict[int, list[tuple[int, int]]]

# `hash`: `#` to end of line. `python`: hash plus `"""` / `'''` strings, which may
# span lines. `slash`: `//` to end of line and `/* ... */`, which may span lines;
# backtick strings (template literals, Go raw strings) may span lines too and only
# suppress comment detection inside them. "json" is the `config` lang for a .json
# file; strict JSON has no comments, but `//` outside a string cannot be valid JSON.
_COMMENT_STYLE: dict[str, str] = {
    "python": "python",
    "ruby": "hash",
    "config": "hash",
    "json": "slash",
    "typescript": "slash",
    "go": "slash",
    "jvm": "slash",
    "rust": "slash",
    "dotnet": "slash",
}


def _skip_string(line: str, i: int, quote: str) -> int:
    """Index just past the string opening at ``line[i] == quote``; end of line if unterminated."""
    j = i + 1
    n = len(line)
    while j < n:
        ch = line[j]
        if ch == "\\":
            j += 2
            continue
        if ch == quote:
            return j + 1
        j += 1
    return n


def _hash_line(line: str, i: int, spans: list[tuple[int, int]], triple: bool) -> str | None:
    """Scan ``line[i:]`` in `#` style. Returns the triple quote left open, or None."""
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == "#":
            spans.append((i, n))
            return None
        if ch in "\"'":
            if triple and line.startswith(ch * 3, i):
                close = line.find(ch * 3, i + 3)
                if close == -1:
                    spans.append((i, n))
                    return ch * 3
                spans.append((i, close + 3))
                i = close + 3
                continue
            i = _skip_string(line, i, ch)
            continue
        i += 1
    return None


_STAR_LINE_RE = re.compile(r"^\s*\*(?:\s|/|$)")


def _slash_line(line: str, i: int, spans: list[tuple[int, int]]) -> str | None:
    """Scan ``line[i:]`` in `//` style. Returns "/*" or "`" when left open, else None."""
    n = len(line)
    if i == 0:
        # A JSDoc-style continuation whose opener was not seen, or a stray closer,
        # reads as comment from the star onwards.
        star = _STAR_LINE_RE.match(line)
        if star is not None:
            spans.append((line.index("*"), n))
            return None
    while i < n:
        if line.startswith("//", i):
            spans.append((i, n))
            return None
        if line.startswith("/*", i):
            close = line.find("*/", i + 2)
            if close == -1:
                spans.append((i, n))
                return "/*"
            spans.append((i, close + 2))
            i = close + 2
            continue
        ch = line[i]
        if ch == "`":
            close = line.find("`", i + 1)
            if close == -1:
                return "`"
            i = close + 1
            continue
        if ch in "\"'":
            i = _skip_string(line, i, ch)
            continue
        i += 1
    return None


@lru_cache(maxsize=2048)
def comment_spans(text: str, lang: str) -> CommentSpans:
    """Per line (1-based), the ``[start, end)`` column ranges that are a comment or a
    Python triple-quoted string. Lines with no such range are absent. A language with
    no known comment syntax yields ``{}``: nothing is filtered rather than guessed.

    Cached per (text, lang): discovery and the rules each tokenize the same file once,
    and a second pass over a 100 KB source costs more than the lookup. Callers read the
    result and never mutate it."""
    style = _COMMENT_STYLE.get(lang or "")
    if style is None:
        return {}
    out: CommentSpans = {}
    open_token: str | None = None
    for number, raw in enumerate(text.split("\n"), 1):
        line = raw.rstrip("\r")
        spans: list[tuple[int, int]] = []
        i = 0
        if open_token == "`":
            close = line.find("`")
            if close == -1:
                continue
            i = close + 1
            open_token = None
        elif open_token is not None:
            close = line.find(open_token if style == "python" else "*/")
            if close == -1:
                out[number] = [(0, len(line))]
                continue
            i = close + len(open_token if style == "python" else "*/")
            spans.append((0, i))
            open_token = None
        if style == "slash":
            open_token = _slash_line(line, i, spans)
        else:
            open_token = _hash_line(line, i, spans, style == "python")
        if spans:
            out[number] = spans
    return out


def in_comment(spans: CommentSpans, line: int, col: int) -> bool:
    """True when 0-based column ``col`` of 1-based ``line`` falls inside a recorded span."""
    return any(s <= col < e for s, e in spans.get(line, ()))
