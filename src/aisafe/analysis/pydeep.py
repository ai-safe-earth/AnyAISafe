"""src/aisafe/analysis/pydeep.py
------------------------------
Python AST layer of `aisafe audit`: where a prompt is written, where it is assembled, which
model call it feeds, and where the model's reply leaves the program towards the person.

Everything here is heuristic and UNMEASURED. Only ``ast`` is used; one walk per file
collects raw facts, small pure functions derive the joins. A file that fails to parse or to
analyse becomes an ``UnknownItem`` (category ``deep``) and never an exception:
``analyse_unit`` never raises.

The four products, and what each one may claim:

- ``PromptLiteral``: a string constant assigned to a prompt-named variable, with its line
  span, so a text hit inside a multi-line prompt can be tied to the prompt it sits in.
- ``Assembly``: an f-string, concatenation, ``.format`` or template call that builds a
  prompt, with the names it reads (``source_names``) and which of those reach back to a
  request (``untrusted_names``).
- ``CallSite``: a model call, by SDK suffix on an object built from an SDK module, or by a
  URL of a model API inside the call.
- ``ReplySite``: a ``return``, ``yield`` or outbound call whose argument's origin is a model
  call's result: the point where the reply reaches the person (the intervention leg).

``assembly_feeds_call`` and ``literal_feeds_call`` tie a prompt to the call it reaches
through the syntax tree alone (assignment, container, attribute bound in a constructor,
same-file helper return). The flow builder (``analysis.flows``) turns these into ``ast``
links; whatever it cannot find here it reports as co-location, never as a verified flow.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from aisafe.discovery.patterns import (
    INGRESS_PATTERNS,
    LLM_CALL_PATTERNS,
    LLM_RESPONSE_ACCESSORS,
    table_for,
)
from aisafe.evidence.model import UnknownCategory, UnknownItem

__all__ = [
    "LLM_CALL_ATTRS",
    "Assembly",
    "CallSite",
    "PromptLiteral",
    "PyFacts",
    "ReplySite",
    "analyse_file",
    "analyse_unit",
]

# --------------------------------------------------------------------------- #
# Public tables
# --------------------------------------------------------------------------- #

# Dotted callee suffixes that name an LLM call. The bare ones (run/invoke/...) only
# count when the receiver resolves to an object built from an SDK module.
LLM_CALL_ATTRS: frozenset[tuple[str, ...]] = frozenset(
    {
        ("messages", "create"),
        ("chat", "completions", "create"),
        ("responses", "create"),
        ("generate_content",),
        ("invoke",),
        ("ainvoke",),
        ("run",),
        ("arun",),
        ("completion",),
        ("acompletion",),
        ("converse",),
        ("invoke_model",),
    }
)

# --------------------------------------------------------------------------- #
# Private tables
# --------------------------------------------------------------------------- #

_SDK_MODULES: tuple[tuple[str, str], ...] = (
    ("anthropic", "anthropic"),
    ("openai", "openai"),
    ("google.generativeai", "google"),
    ("google.genai", "google"),
    ("boto3", "bedrock"),
    ("litellm", "litellm"),
    ("langchain", "langchain"),
    ("langgraph", "langchain"),
    ("mistralai", "mistral"),
    ("cohere", "cohere"),
    ("ollama", "ollama"),
)
# Multi-segment suffixes are specific enough to count when any SDK is imported.
_SUFFIX_PROVIDER: dict[tuple[str, ...], str] = {
    ("messages", "create"): "anthropic",
    ("chat", "completions", "create"): "openai",
    ("responses", "create"): "openai",
    ("generate_content",): "google",
    ("converse",): "bedrock",
    ("invoke_model",): "bedrock",
}
# A model API reached over plain HTTP: the URL rows of the grep table, read on the string
# constants of a call. The host names the provider ("api.openai.com" -> "openai").
_HTTP_MODEL_ROWS: list[tuple[str, re.Pattern[str]]] = [
    (key, rx) for key, rx in table_for("python", LLM_CALL_PATTERNS) if key == "generic_http"
]
_HTTP_HOST_RE = re.compile(r"https?://api\.([a-z0-9-]+)\.", re.I)

_TEMPLATE_CTORS = frozenset(
    {
        "PromptTemplate",
        "ChatPromptTemplate",
        "from_messages",
        "from_template",
        "SystemMessage",
        "HumanMessage",
        "SystemMessagePromptTemplate",
        "substitute",
        "safe_substitute",
    }
)
_SYSTEM_CTORS = frozenset({"SystemMessage", "SystemMessagePromptTemplate"})
_PROMPT_KWARGS = frozenset(
    {
        "system",
        "content",
        "prompt",
        "instructions",
        "instruction",
        "system_prompt",
        "system_instruction",
        "messages",
        "template",
        "human",
        "user",
    }
)
# Keyword arguments that carry the system prompt: Anthropic's `system=`, Google's
# `system_instruction=`, the OpenAI Responses API's and the agent SDKs' `instructions=`.
_SYSTEM_KWARGS = frozenset(
    {"system", "system_prompt", "system_instruction", "instructions", "instruction"}
)
# Message roles that carry the system prompt (`developer` is OpenAI's newer spelling).
_SYSTEM_ROLES = frozenset({"system", "developer"})
_PROMPT_DICT_KEYS = frozenset(
    {"content", "prompt", "system", "instructions", "input", "question", "query"}
)
# The keyword arguments of a model call that carry prompt text. Positional arguments are
# read as well (`model.generate_content(prompt)`, `chain.invoke(prompt)`); the HTTP shape
# carries its prompt in `json=` / `data=`.
_CALL_PROMPT_KWARGS = frozenset(
    {
        "system",
        "messages",
        "prompt",
        "input",
        "contents",
        "content",
        "instructions",
        "instruction",
        "system_prompt",
        "system_instruction",
        "text",
        "query",
        "question",
        "history",
        "json",
        "data",
    }
)
_PROMPT_NAME_RE = re.compile(r"(?i)prompt|system|instruction|message|template|persona|context")
_SYSTEM_NAME_RE = re.compile(r"(?i)system_?(?:prompt|message|msg|instruction|template)")

# Where a reply leaves the program: a callee whose last segment says it sends, writes or
# shows something, or a framework's response constructor. The argument has to originate
# in a model call for the site to count; the name alone says nothing.
_OUTBOUND_RE = re.compile(
    r"(?i)^(?:send|write|reply|respond|emit|publish|post|push|notify|broadcast|say|speak"
    r"|answer|stream|deliver|dispatch|render|display|show|output|print|echo)"
)
_RESPONSE_CTORS = frozenset(
    {
        "jsonify",
        "JSONResponse",
        "HTMLResponse",
        "PlainTextResponse",
        "StreamingResponse",
        "Response",
        "HttpResponse",
        "JsonResponse",
        "make_response",
        "render_template",
    }
)
# Attribute and key names that read a model response, for roots the accessor table misses.
_ACCESSOR_ATTRS = frozenset(
    {"text", "content", "output_text", "tool_calls", "candidates", "choices"}
)
_ACCESSOR_KEYS = frozenset({"output", "content", "text"})

# A callee whose name says it cleans a value: a request field passed through one of these
# is not reported as untrusted inside a prompt. Spelled here since the vocabulary module
# that held the list is gone.
_SANITISERS: tuple[str, ...] = (
    "promptinjectionguard",
    "sanitize",
    "sanitise",
    "escape_prompt",
    "delimit",
    "spotlight",
    "llm_guard",
    "rebuff",
)
_INGRESS_PY = table_for("python", INGRESS_PATTERNS)
_ROUTE_RE = dict(_INGRESS_PY).get(
    "http:route_decorator", re.compile(r"@app\.(?:post|route|get)\b|@router\.")
)
_PARSE_ERRORS = (SyntaxError, RecursionError, MemoryError, ValueError)
_MAX_DEPTH = 6

# --------------------------------------------------------------------------- #
# Public product
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CallSite:
    """A model call. `function` is the qualified name of the enclosing def, None at module level."""

    file: str
    line: int
    provider: str
    function: str | None


@dataclass(frozen=True)
class Assembly:
    """A prompt built from parts. `source_names` are the names the expression reads;
    `untrusted_names` the subset whose binding chain reaches a request. `end_line` closes
    the expression's span (a multi-line f-string), so a text hit inside it can be tied to
    the prompt it sits in."""

    file: str
    line: int
    kind: str  # fstring | concat | format | template
    source_names: tuple[str, ...]
    is_system: bool
    untrusted_names: tuple[str, ...]
    end_line: int = 0


@dataclass(frozen=True)
class PromptLiteral:
    """A string constant (or f-string) assigned to a prompt-named variable:
    `SYSTEM_PROMPT = <triple-quoted text>`. `end_line` closes the span, so a text hit inside a
    multi-line literal can be tied to the prompt it sits in; `is_system` is set by the
    name or by a later `system=` use, like `Assembly.is_system`."""

    file: str
    line: int
    end_line: int
    name: str
    is_system: bool


@dataclass(frozen=True)
class ReplySite:
    """Where a model's reply leaves the program: a `return`, a `yield` or an outbound call
    (`send_message(reply)`, `print(answer)`, `JSONResponse(...)`) whose argument originates
    in a model call. `name` is the variable, accessor or callee the reply flowed through."""

    file: str
    line: int
    function: str | None
    name: str


@dataclass(frozen=True)
class _FuncInfo:
    """A function (or a module's top level): its span and the bare names it calls."""

    key: str
    file: str
    unit: str | None
    name: str | None
    line: int
    end_line: int
    calls: tuple[str, ...]


@dataclass
class PyFacts:
    llm_calls: list[CallSite] = field(default_factory=list)
    prompt_assemblies: list[Assembly] = field(default_factory=list)
    prompt_literals: list[PromptLiteral] = field(default_factory=list)
    reply_returns: list[ReplySite] = field(default_factory=list)
    unknown: list[UnknownItem] = field(default_factory=list)
    # "func:<relpath>::<name>" / "module:<relpath>" -> span and calls.
    functions: dict[str, _FuncInfo] = field(default_factory=dict)
    # Index into `prompt_assemblies` -> index into `llm_calls`: the call whose prompt
    # argument resolves, through the syntax tree, to that assembly.
    assembly_feeds_call: dict[int, int] = field(default_factory=dict)
    # The same for `prompt_literals` (a constant passed as `system=`, directly or through
    # an assembly that reads it).
    literal_feeds_call: dict[int, int] = field(default_factory=dict)

    def merge(self, other: PyFacts) -> None:
        """Fold another file's facts in. The feed maps are re-indexed past this one's lists."""
        offset_a = len(self.prompt_assemblies)
        offset_l = len(self.prompt_literals)
        offset_c = len(self.llm_calls)
        for attr in (
            "llm_calls",
            "prompt_assemblies",
            "prompt_literals",
            "reply_returns",
            "unknown",
        ):
            getattr(self, attr).extend(getattr(other, attr))
        self.functions.update(other.functions)
        for index, call in other.assembly_feeds_call.items():
            self.assembly_feeds_call[index + offset_a] = call + offset_c
        for index, call in other.literal_feeds_call.items():
            self.literal_feeds_call[index + offset_l] = call + offset_c

    def function_at(self, file: str, line: int) -> _FuncInfo | None:
        """The innermost function whose span holds `file`:`line`, else None."""
        best: _FuncInfo | None = None
        for info in self.functions.values():
            if info.name is None or info.file != file or not (info.line <= line <= info.end_line):
                continue
            if best is None or info.line > best.line:
                best = info
        return best


# --------------------------------------------------------------------------- #
# AST helpers
# --------------------------------------------------------------------------- #


def _unparse(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:  # exotic nodes must never kill the audit
        return ""


def _chain(node: ast.AST) -> list[str]:
    """Dotted chain of a callee/receiver, looking through calls, subscripts and awaits."""
    parts: list[str] = []
    cur = node
    while True:
        if isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        elif isinstance(cur, ast.Call):
            cur = cur.func
        elif isinstance(cur, (ast.Subscript, ast.Await)):
            cur = cur.value
        elif isinstance(cur, ast.Name):
            parts.append(cur.id)
            break
        else:
            break
    return parts[::-1]


def _match(table: Any, text: str) -> tuple[str, str] | None:
    for key, pattern in table:
        m = pattern.search(text)
        if m:
            return key, m.group(0)
    return None


def _names_in(node: ast.AST) -> tuple[str, ...]:
    """Name ids read inside an expression, callee names excluded, first-seen order."""
    callees = {id(n.func) for n in ast.walk(node) if isinstance(n, ast.Call)}
    out: list[str] = []
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and id(n) not in callees and n.id not in out:
            out.append(n.id)
    return tuple(out)


def _base(node: ast.AST) -> ast.AST:
    """The Call or Name an attribute/subscript chain hangs off."""
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Await)):
        node = node.value
    return node


def _dotted_in(node: ast.AST) -> tuple[str, ...]:
    """Dotted attribute reads inside an expression (`self.system_prompt`), callee chains
    excluded, first-seen order: the labels `_target_labels` gives an attribute target, so a
    read can be matched to the assignment that bound it."""
    callees = {id(n.func) for n in ast.walk(node) if isinstance(n, ast.Call)}
    out: list[str] = []
    for n in ast.walk(node):
        if isinstance(n, ast.Attribute) and id(n) not in callees and isinstance(_base(n), ast.Name):
            label = ".".join(_chain(n))
            if label not in out:
                out.append(label)
    return tuple(out)


def _target_labels(target: ast.AST) -> list[str]:
    """What a target binds, as the code spells it: `prompt`, `self.system_prompt`, every
    element of a tuple. A subscript binds its root (`cfg["k"] = v` binds `cfg`). The
    attribute form keeps the attribute name, so a prompt stored on an object is still
    recognised as a prompt and a method can read what the constructor bound."""
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [label for elt in target.elts for label in _target_labels(elt)]
    if isinstance(target, ast.Attribute):
        return [".".join(_chain(target))] if isinstance(_base(target), ast.Name) else []
    if isinstance(target, (ast.Subscript, ast.Starred)):
        return _target_labels(target.value)
    return []


def _kwarg(call: ast.Call, name: str) -> ast.AST | None:
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _sanitiser_name(chain: list[str]) -> bool:
    last = chain[-1].lower() if chain else ""
    return any(tok in last for tok in _SANITISERS)


def _end_line(node: ast.AST) -> int:
    return int(getattr(node, "end_lineno", None) or getattr(node, "lineno", 0) or 0)


def _returns_of(fn: ast.AST):
    """Return values of a function body, nested defs and classes excluded."""
    stack = list(getattr(fn, "body", []))
    while stack:
        stmt = stack.pop()
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(stmt, ast.Return) and stmt.value is not None:
            yield stmt.value
        for attr in ("body", "orelse", "finalbody"):
            stack.extend(getattr(stmt, attr, []) or [])
        for handler in getattr(stmt, "handlers", []) or []:
            stack.extend(handler.body)


# --------------------------------------------------------------------------- #
# Per-module context
# --------------------------------------------------------------------------- #


@dataclass
class _Scope:
    key: str
    name: str | None
    node: ast.AST
    parent: _Scope | None
    assigns: list[tuple[str, ast.AST, int]] = field(default_factory=list)
    params: dict[str, ast.AST | None] = field(default_factory=dict)
    route: bool = False

    def lookup(self, name: str, line: int) -> tuple[str, ast.AST | None] | None:
        """Nearest preceding binding of `name`: own assigns, params, then enclosing scopes."""
        found = None
        for n, value, ln in self.assigns:
            if n == name and ln < line:
                found = value
        if found is not None:
            return ("assign", found)
        if name in self.params:
            return ("param", self.params[name])
        if self.parent is not None:
            return self.parent.lookup(name, line)
        for n, value, _ln in self.assigns:  # module level: a def may precede its globals
            if n == name:
                found = value
        return ("assign", found) if found is not None else None


class _Module:
    def __init__(self, relpath: str, unit: str | None, tree: ast.Module, text: str) -> None:
        self.relpath = relpath
        self.unit = unit
        self.tree = tree
        self.text = text
        self.lines = text.splitlines()
        # File-level prefilter: a URL row that misses the raw source misses every call.
        self.has_api_url = "api." in text
        self.parent_of: dict[ast.AST, ast.AST] = {}
        self.scope_of: dict[ast.AST, _Scope] = {}
        self.def_scope: dict[ast.AST, _Scope] = {}
        self.module_scope = _Scope(f"module:{relpath}", None, tree, None)
        self.alias: dict[str, str] = {}
        self.any_sdk = False
        self.llm_nodes: set[int] = set()
        # Names (and dotted attribute labels, `self.reply`) bound to a model call's result
        # anywhere in the module.
        self.call_results: set[str] = set()
        # Attribute targets by dotted label (`self.system_prompt` -> the values assigned to
        # it, with their scope and line), module-wide: a constructor binds what a method
        # reads, and the tree shows both ends.
        self.attr_assigns: dict[str, list[tuple[ast.AST, _Scope, int]]] = {}
        # id(node) -> unparsed text. `ast.unparse` is the single most expensive call of
        # the deep pass; the tree outlives this dict, so ids are stable.
        self._unparsed: dict[int, str] = {}
        self._scopes(tree, self.module_scope, "")
        self.any_sdk = any(self.provider(v.split(".")) for v in self.alias.values())

    def unparse(self, node: ast.AST | None) -> str:
        """`_unparse(node)`, memoised for the lifetime of this module's tree."""
        if node is None:
            return ""
        key = id(node)
        text = self._unparsed.get(key)
        if text is None:
            text = _unparse(node)
            self._unparsed[key] = text
        return text

    # -- construction ------------------------------------------------------
    def _import(self, node: ast.Import | ast.ImportFrom) -> None:
        if isinstance(node, ast.Import):
            for a in node.names:
                self.alias[a.asname or a.name.split(".")[0]] = (
                    a.name if a.asname else a.name.split(".")[0]
                )
        else:
            mod = "." * node.level + (node.module or "")
            for a in node.names:
                self.alias[a.asname or a.name] = f"{mod}.{a.name}"

    def _scopes(self, node: ast.AST, scope: _Scope, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            self.parent_of[child] = node
            self.scope_of[child] = scope
            if isinstance(child, (ast.Import, ast.ImportFrom)):
                self._import(child)
                continue
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = prefix + child.name
                inner = _Scope(f"func:{self.relpath}::{qual}", qual, child, scope)
                a = child.args
                positional = a.posonlyargs + a.args
                defaults = [None] * (len(positional) - len(a.defaults)) + list(a.defaults)
                for arg, default in zip(positional, defaults):
                    inner.params[arg.arg] = arg.annotation or default
                for arg, default in zip(a.kwonlyargs, a.kw_defaults):
                    inner.params[arg.arg] = arg.annotation or default
                for arg in (a.vararg, a.kwarg):
                    if arg is not None:
                        inner.params[arg.arg] = arg.annotation
                inner.route = any(
                    _ROUTE_RE.search("@" + self.unparse(d)) for d in child.decorator_list
                )
                self.def_scope[child] = inner
                self._scopes(child, inner, qual + ".")
                continue
            if isinstance(child, ast.ClassDef):
                self._scopes(child, scope, prefix + child.name + ".")
                continue
            if isinstance(child, ast.Assign):
                self._bind(scope, child.targets, child.value, child.lineno)
            elif isinstance(child, ast.AnnAssign) and child.value is not None:
                self._bind(scope, [child.target], child.value, child.lineno)
            elif isinstance(child, ast.withitem) and child.optional_vars is not None:
                expr = child.context_expr
                self._bind(scope, [child.optional_vars], expr, expr.lineno)
            elif isinstance(child, (ast.For, ast.AsyncFor)):
                self._bind(scope, [child.target], child.iter, child.lineno)
            elif isinstance(child, ast.NamedExpr):
                scope.assigns.append((child.target.id, child.value, child.lineno))
            self._scopes(child, scope, prefix)

    def _bind(self, scope: _Scope, targets: list[ast.AST], value: ast.AST, line: int) -> None:
        """Record a binding: a plain name on its scope, an attribute target under its
        dotted label module-wide (see `attr_assigns`)."""
        for target in targets:
            for label in _target_labels(target):
                if "." in label:
                    self.attr_assigns.setdefault(label, []).append((value, scope, line))
                else:
                    scope.assigns.append((label, value, line))

    # -- resolution --------------------------------------------------------
    def qualify(self, chain: list[str]) -> list[str]:
        if chain and chain[0] in self.alias:
            return self.alias[chain[0]].split(".") + chain[1:]
        return chain

    @staticmethod
    def provider(qchain: list[str]) -> str | None:
        dotted = ".".join(qchain)
        for prefix, provider in _SDK_MODULES:
            if dotted == prefix or dotted.startswith((prefix + ".", prefix + "_")):
                return provider
        return None

    def origin(self, expr: ast.AST, scope: _Scope, depth: int = 0) -> list[str]:
        """Qualified chain of the import an expression's root was built from."""
        if depth > _MAX_DEPTH:
            return []
        while isinstance(expr, ast.Await):
            expr = expr.value
        if isinstance(expr, ast.BinOp):
            return self.origin(expr.left, scope, depth + 1) or self.origin(
                expr.right, scope, depth + 1
            )
        chain = _chain(expr)
        if not chain:
            return []
        if chain[0] in self.alias:
            return self.qualify(chain)
        bound = scope.lookup(chain[0], getattr(expr, "lineno", 1 << 30))
        if bound is None or bound[1] is None or bound[1] is expr:
            # `self.client.messages.create`: the root is a parameter, but `self.client`
            # is bound somewhere in the module (a constructor). Follow that binding.
            if len(chain) >= 2:
                for value, vscope, _line in self.attr_assigns.get(".".join(chain[:2]), ()):
                    found = self.origin(value, vscope, depth + 1)
                    if found:
                        return found + chain[2:]
            return chain
        return self.origin(bound[1], scope, depth + 1) or chain

    def scope(self, node: ast.AST) -> _Scope:
        return self.scope_of.get(node, self.module_scope)

    def source(self, node: ast.AST) -> str:
        end = getattr(node, "end_lineno", node.lineno) or node.lineno
        return "\n".join(self.lines[node.lineno - 1 : end])

    def ancestors(self, node: ast.AST):
        cur = self.parent_of.get(node)
        while cur is not None:
            yield cur
            cur = self.parent_of.get(cur)

    def is_untrusted(self, name: str, scope: _Scope, line: int, depth: int = 0) -> bool:
        """Does `name`'s binding chain reach a request (INGRESS_PATTERNS) without a sanitiser?"""
        if depth > 5:
            return False
        bound = scope.lookup(name, line)
        if bound is None:
            return False
        kind, value = bound
        if kind == "param":
            if scope.route:
                return True
            return value is not None and _match(_INGRESS_PY, self.unparse(value)) is not None
        if value is None or (isinstance(value, ast.Call) and _sanitiser_name(_chain(value.func))):
            return False
        if _match(_INGRESS_PY, self.unparse(value)):
            return True
        return any(
            self.is_untrusted(n, scope, value.lineno, depth + 1)
            for n in _names_in(value)
            if n != name
        )

    def attr_untrusted(self, label: str, depth: int = 0) -> bool:
        """Does a value assigned to the attribute `label` (`self.text = request.json[...]`,
        anywhere in the module) reach a request without a sanitiser?"""
        if depth > 5:
            return False
        for value, scope, line in self.attr_assigns.get(label, ()):
            if isinstance(value, ast.Call) and _sanitiser_name(_chain(value.func)):
                continue
            if _match(_INGRESS_PY, self.unparse(value)):
                return True
            if any(self.is_untrusted(n, scope, line + 1, depth + 1) for n in _names_in(value)):
                return True
        return False


class _UnitIndex:
    """Function definitions across the unit, by bare name."""

    def __init__(self, modules: list[_Module]) -> None:
        self.by_name: dict[str, list[tuple[_Module, ast.AST]]] = {}
        for mod in modules:
            for node in mod.def_scope:
                self.by_name.setdefault(node.name, []).append((mod, node))  # type: ignore[attr-defined]

    def lookup(self, name: str, prefer: _Module) -> tuple[_Module, ast.AST] | None:
        candidates = self.by_name.get(name, [])
        for mod, node in candidates:
            if mod is prefer:
                return mod, node
        return candidates[0] if candidates else None


# --------------------------------------------------------------------------- #
# Per-module analysis
# --------------------------------------------------------------------------- #


class _Analyser:
    def __init__(self, mod: _Module, index: _UnitIndex) -> None:
        self.mod = mod
        self.index = index
        self.facts = PyFacts()
        self.recorded: set[int] = set()
        self.system_uses: set[str] = set()
        self.calls_by_scope: dict[str, list[str]] = {}
        # (index into prompt_assemblies, names it was assigned to): resolved once every
        # `system=` / SystemMessage / role-system use in the module has been seen.
        self.pending_system: list[tuple[int, tuple[str, ...]]] = []
        self.pending_literal_system: list[tuple[int, tuple[str, ...]]] = []
        # The nodes behind the facts, in list order, so the feed maps can be resolved by
        # node identity once the whole module has been walked, then re-indexed by line.
        self.assembly_nodes: list[ast.AST] = []
        self.literal_nodes: list[ast.AST] = []
        self.call_nodes: list[tuple[ast.Call, _Scope]] = []
        # Reply candidates are resolved after the walk: `ast.walk` is breadth-first, so a
        # `return reply` is visited before the call that bound `reply` on the line above.
        self.reply_candidates: list[tuple[ast.AST, _Scope, int, str]] = []
        self.reply_lines: set[int] = set()
        # Built strings returned from a function whose name says nothing about prompts:
        # recorded only when a model call's argument reaches them (`_finish_feeds`).
        self.deferred: dict[int, tuple[ast.AST, _Scope, str]] = {}
        self._wanted: set[int] = set()

    # -- entry -------------------------------------------------------------
    def run(self) -> PyFacts:
        mod, facts = self.mod, self.facts
        for node in ast.walk(mod.tree):
            scope = mod.scope(node)
            if isinstance(node, ast.Call):
                self._system_use(node)
                self._call(node, scope)
                self._reply_call(node, scope)
                chain = _chain(node.func)
                if chain:
                    self.calls_by_scope.setdefault(scope.key, []).append(chain[-1])
            elif isinstance(node, ast.Dict):
                self._system_use_dict(node)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                self._prompt_literal(node)
            elif isinstance(node, ast.Return) and node.value is not None:
                self.reply_candidates.append((node.value, scope, node.lineno, "return"))
            elif isinstance(node, (ast.Yield, ast.YieldFrom)) and node.value is not None:
                self.reply_candidates.append((node.value, scope, node.lineno, "yield"))
            if isinstance(node, (ast.JoinedStr, ast.BinOp, ast.Call)):
                self._assembly(node, scope)
        self._finish_assemblies()
        self._finish_feeds()
        self._finish_replies()
        self._finish_order()
        facts.functions[mod.module_scope.key] = self._func_info(mod.module_scope, mod.tree)
        for fn, scope in mod.def_scope.items():
            facts.functions[scope.key] = self._func_info(scope, fn)
        facts.reply_returns.sort(key=lambda x: x.line)
        return facts

    def _func_info(self, scope: _Scope, node: ast.AST) -> _FuncInfo:
        calls = tuple(dict.fromkeys(self.calls_by_scope.get(scope.key, ())))
        end = getattr(node, "end_lineno", None) or len(self.mod.lines)
        line = getattr(node, "lineno", 1)
        return _FuncInfo(scope.key, self.mod.relpath, self.mod.unit, scope.name, line, end, calls)

    # -- prompt literals ---------------------------------------------------
    def _prompt_literal(self, node: ast.Assign | ast.AnnAssign) -> None:
        """Record `PROMPT_NAME = "..."` / `= f"..."` with its line span, so a text hit inside
        a multi-line prompt can be told from code that merely spells a phrase."""
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = tuple(label for t in targets for label in _target_labels(t))
        if not names or not any(_PROMPT_NAME_RE.search(n) for n in names):
            return
        value = node.value
        if value is None:
            return
        is_text = isinstance(value, ast.Constant) and isinstance(value.value, str)
        if not is_text and not isinstance(value, ast.JoinedStr):
            return
        is_system = any(_SYSTEM_NAME_RE.search(n) for n in names)
        end = _end_line(value) or node.lineno
        if not is_system:
            self.pending_literal_system.append((len(self.facts.prompt_literals), names))
        self.literal_nodes.append(value)
        self.facts.prompt_literals.append(
            PromptLiteral(self.mod.relpath, node.lineno, end, names[0], is_system)
        )

    # -- model calls -------------------------------------------------------
    def _call(self, node: ast.Call, scope: _Scope) -> None:
        mod = self.mod
        chain = _chain(node.func)
        for suffix in LLM_CALL_ATTRS:
            if chain[-len(suffix) :] == list(suffix):
                provider = mod.provider(mod.origin(node.func, scope))
                if provider is None and mod.any_sdk:
                    provider = _SUFFIX_PROVIDER.get(suffix)
                if provider is not None:
                    self._llm_site(node, scope, provider)
                return
        if mod.has_api_url and _HTTP_MODEL_ROWS:
            provider = self._http_provider(node)
            if provider is not None:
                self._llm_site(node, scope, provider)

    @staticmethod
    def _http_provider(node: ast.Call) -> str | None:
        """The provider named by a model API URL among the call's string constants."""
        for sub in ast.walk(node):
            if not (isinstance(sub, ast.Constant) and isinstance(sub.value, str)):
                continue
            if _match(_HTTP_MODEL_ROWS, sub.value) is None:
                continue
            host = _HTTP_HOST_RE.search(sub.value)
            return host.group(1).lower() if host else "http"
        return None

    def _llm_site(self, node: ast.Call, scope: _Scope, provider: str) -> None:
        mod = self.mod
        if id(node) in mod.llm_nodes:
            return
        mod.llm_nodes.add(id(node))
        self.call_nodes.append((node, scope))
        self.facts.llm_calls.append(CallSite(mod.relpath, node.lineno, provider, scope.name))
        parent = mod.parent_of.get(node)
        while isinstance(parent, ast.Await):
            parent = mod.parent_of.get(parent)
        if isinstance(parent, (ast.Assign, ast.AnnAssign)):
            targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
            mod.call_results.update(label for t in targets for label in _target_labels(t))

    # -- replies -----------------------------------------------------------
    def _reply_call(self, node: ast.Call, scope: _Scope) -> None:
        chain = _chain(node.func)
        if not chain:
            return
        last = chain[-1]
        if not (_OUTBOUND_RE.match(last) or last in _RESPONSE_CTORS):
            return
        for arg in [*node.args, *(k.value for k in node.keywords)]:
            self.reply_candidates.append((arg, scope, node.lineno, ".".join(chain)))

    def _finish_replies(self) -> None:
        """Resolve the reply candidates once every model call in the module is known."""
        for expr, scope, line, _via in sorted(self.reply_candidates, key=lambda c: c[2]):
            self._reply(expr, scope, line)

    def _reply(self, expr: ast.AST, scope: _Scope, line: int) -> bool:
        """Record a reply site when `expr` originates in a model call. One per line; a
        model call that is itself the outbound call (`client.messages.create(...)` passed
        to nothing) is not a reply."""
        if line in self.reply_lines:
            return False
        name = self._model_output(expr, scope, line)
        if name is None:
            return False
        self.reply_lines.add(line)
        self.facts.reply_returns.append(ReplySite(self.mod.relpath, line, scope.name, name))
        return True

    def _model_output(self, expr: ast.AST, scope: _Scope, line: int, depth: int = 0) -> str | None:
        """The name, accessor or callee through which `expr` reads a model call's result.

        Resolution: a model call inside the expression; a name or attribute the module
        bound to a model call's result (`call_results`); a response accessor
        (`.content[0].text`) in a module that calls a model, unless the value provably came
        from a non-model library call; and the binding chain of each name and attribute
        read (the same walk `origin()` makes), depth-bounded. None when nothing connects.
        An SDK object that is not a call result (`return client`) does not count.
        """
        if depth > _MAX_DEPTH:
            return None
        mod = self.mod
        while isinstance(expr, ast.Await):
            expr = expr.value
        for node in ast.walk(expr):
            if isinstance(node, ast.Call) and id(node) in mod.llm_nodes:
                return ".".join(_chain(node.func)) or "model call"
        names = _names_in(expr)
        dotted = _dotted_in(expr)
        for name in (*names, *dotted):
            if name in mod.call_results:
                return name
        if (
            (mod.llm_nodes or mod.any_sdk)
            and isinstance(expr, (ast.Attribute, ast.Subscript))
            and not self._foreign_result(expr, scope, line)
        ):
            hit = _match(LLM_RESPONSE_ACCESSORS, mod.unparse(expr))
            if hit is not None:
                return hit[0]
        for name in names:
            bound = scope.lookup(name, line)
            if bound is None or bound[0] != "assign" or bound[1] is None or bound[1] is expr:
                continue
            value = bound[1]
            if self._model_output(value, scope, getattr(value, "lineno", line), depth + 1):
                return name
        for label in dotted:
            for value, vscope, _line in mod.attr_assigns.get(label, ()):
                if value is expr:
                    continue
                if self._model_output(value, vscope, getattr(value, "lineno", line), depth + 1):
                    return label
        return None

    def _foreign_result(self, expr: ast.AST, scope: _Scope, line: int) -> bool:
        """The root of `expr` holds the result of a call into an imported library that is
        not a model SDK (`response = requests.get(url)`): an accessor name on it
        (`response.text`) says nothing about a model reply. A parameter, an unresolved
        name or a function the unit defines itself keeps the accessor heuristic, since the
        value may well be a model reply handed over from elsewhere."""
        root = _base(expr)
        if not isinstance(root, ast.Name):
            return False
        bound = scope.lookup(root.id, line)
        if bound is None or bound[0] != "assign" or bound[1] is None:
            return False
        value = bound[1]
        while isinstance(value, ast.Await):
            value = value.value
        if not isinstance(value, ast.Call) or id(value) in self.mod.llm_nodes:
            return False
        callee = _chain(value.func)
        qualified = self.mod.origin(value.func, scope)
        if not callee or not qualified:
            return False
        imported = {alias.split(".")[0] for alias in self.mod.alias.values()}
        if qualified[0] not in imported or self.mod.provider(qualified) is not None:
            return False
        return self.index.lookup(callee[-1], self.mod) is None

    # -- prompt assembly ---------------------------------------------------
    def _system_use(self, call: ast.Call) -> None:
        """Names (and attribute labels) passed where a system prompt goes: the argument of
        a system-message constructor, or any of the `_SYSTEM_KWARGS` keyword arguments."""
        chain = _chain(call.func)
        values = list(call.args) if chain and chain[-1] in _SYSTEM_CTORS else []
        values += [k.value for k in call.keywords if k.arg in _SYSTEM_KWARGS]
        for value in values:
            self.system_uses.update(_names_in(value))
            self.system_uses.update(_dotted_in(value))

    def _system_use_dict(self, node: ast.Dict) -> None:
        keys = {
            k.value: v
            for k, v in zip(node.keys, node.values)
            if isinstance(k, ast.Constant) and isinstance(k.value, str)
        }
        role = keys.get("role")
        if isinstance(role, ast.Constant) and role.value in _SYSTEM_ROLES and "content" in keys:
            self.system_uses.update(_names_in(keys["content"]))
            self.system_uses.update(_dotted_in(keys["content"]))

    def _assembly_kind(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.JoinedStr):
            return "fstring"
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            if any(
                isinstance(s, ast.JoinedStr)
                or (isinstance(s, ast.Constant) and isinstance(s.value, str))
                for s in (node.left, node.right)
            ):
                return "concat"
            return None
        if isinstance(node, ast.Call):
            chain = _chain(node.func)
            if not chain:
                return None
            if chain[-1] == "format" and isinstance(node.func, ast.Attribute):
                return "format"
            if chain[-1] in _TEMPLATE_CTORS:
                return "template"
        return None

    def _assembly(self, node: ast.AST, scope: _Scope) -> None:
        kind = self._assembly_kind(node)
        if kind is None or any(id(a) in self.recorded for a in self.mod.ancestors(node)):
            return
        targets: tuple[str, ...] = ()
        if kind == "template":
            prompt_like, is_system = True, _chain(node.func)[-1] in _SYSTEM_CTORS  # type: ignore
            inner = [
                n
                for n in ast.walk(node)
                if n is not node and self._assembly_kind(n) in ("fstring", "concat", "format")
            ]
            if inner:
                return  # the inner assemblies carry the precise context
        else:
            prompt_like, is_system, targets = self._context(node, scope)
        if not prompt_like:
            if kind != "template" and self._is_returned(node):
                self.deferred[id(node)] = (node, scope, kind)
            return
        self._record(node, scope, kind, is_system, targets)

    def _is_returned(self, node: ast.AST) -> bool:
        """The expression is (part of) a function's return value, reached through
        containers, operators and wrapping calls only (`return dedent(f"...")`)."""
        for parent in self.mod.ancestors(node):
            if isinstance(parent, ast.Return):
                return True
            if not isinstance(
                parent,
                (
                    ast.List,
                    ast.Tuple,
                    ast.Dict,
                    ast.BinOp,
                    ast.JoinedStr,
                    ast.FormattedValue,
                    ast.Await,
                    ast.Call,
                    ast.Attribute,
                ),
            ):
                return False
        return False

    def _record(
        self, node: ast.AST, scope: _Scope, kind: str, is_system: bool, targets: tuple[str, ...]
    ) -> None:
        self.recorded.add(id(node))
        names = _names_in(node)
        dotted = _dotted_in(node)
        untrusted = tuple(
            n
            for n in names
            if self.mod.is_untrusted(n, scope, node.lineno)
            # `{self.text}` where a method bound `self.text` to a request field.
            or any(
                label.split(".", 1)[0] == n and self.mod.attr_untrusted(label) for label in dotted
            )
        )
        if targets and not is_system:
            self.pending_system.append((len(self.facts.prompt_assemblies), targets))
        self.assembly_nodes.append(node)
        self.facts.prompt_assemblies.append(
            Assembly(
                self.mod.relpath,
                node.lineno,
                kind,
                names,
                is_system,
                untrusted,
                _end_line(node) or node.lineno,
            )
        )

    def _finish_assemblies(self) -> None:
        """A prompt assigned to a name that is later passed as `system=` is a system prompt."""
        for index, targets in self.pending_system:
            if any(n in self.system_uses for n in targets):
                current = self.facts.prompt_assemblies[index]
                self.facts.prompt_assemblies[index] = replace(current, is_system=True)
        for index, targets in self.pending_literal_system:
            if any(n in self.system_uses for n in targets):
                literal = self.facts.prompt_literals[index]
                self.facts.prompt_literals[index] = replace(literal, is_system=True)

    def _context(self, node: ast.AST, scope: _Scope) -> tuple[bool, bool, tuple[str, ...]]:
        """(prompt_like, is_system, assigned names) from where the built string flows."""
        cur = node
        system = False
        for parent in self.mod.ancestors(node):
            if isinstance(parent, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
                names = tuple(label for t in targets for label in _target_labels(t))
                if any(_PROMPT_NAME_RE.search(n) for n in names):
                    return True, system or any(_SYSTEM_NAME_RE.search(n) for n in names), names
                return False, False, ()
            if isinstance(parent, ast.keyword):
                if parent.arg in _PROMPT_KWARGS:
                    return True, system or parent.arg in _SYSTEM_KWARGS, ()
                return False, False, ()
            if isinstance(parent, ast.Call):
                last = _chain(parent.func)[-1:]
                if last and last[0] in _SYSTEM_CTORS:
                    return True, True, ()
                if id(parent) in self.mod.llm_nodes or (last and last[0] in _TEMPLATE_CTORS):
                    return True, system, ()
                return False, False, ()
            if isinstance(parent, ast.Dict):
                key = next((k for k, v in zip(parent.keys, parent.values) if v is cur), None)
                role = next(
                    (
                        v
                        for k, v in zip(parent.keys, parent.values)
                        if isinstance(k, ast.Constant) and k.value == "role"
                    ),
                    None,
                )
                if isinstance(key, ast.Constant) and key.value in _PROMPT_DICT_KEYS:
                    return True, isinstance(role, ast.Constant) and role.value in _SYSTEM_ROLES, ()
                return False, False, ()
            if isinstance(parent, ast.Return):
                return bool(scope.name and _PROMPT_NAME_RE.search(scope.name)), False, ()
            if (
                isinstance(parent, ast.Tuple)
                and parent.elts
                and isinstance(parent.elts[0], ast.Constant)
            ):
                system = system or parent.elts[0].value in _SYSTEM_ROLES
            if not isinstance(
                parent,
                (ast.List, ast.Tuple, ast.BinOp, ast.JoinedStr, ast.FormattedValue, ast.Await),
            ):
                return False, False, ()
            cur = parent
        return False, False, ()

    # -- prompt -> call feeds ----------------------------------------------
    def _finish_feeds(self) -> None:
        """Tie each model call to the assemblies and literals its prompt arguments reach.

        An argument reaches a prompt when the prompt's node sits inside it, when a name or
        an attribute it reads is bound to the prompt (or to a container holding it), or when
        it is the return value of a same-file helper that builds the prompt. Each step is a
        binding the syntax tree shows; nothing is inferred from names alone.
        """
        literal_ids = {id(n): i for i, n in enumerate(self.literal_nodes)}
        if not self.assembly_nodes and not literal_ids and not self.deferred:
            return
        self._wanted = {id(n) for n in self.assembly_nodes} | set(literal_ids) | set(self.deferred)
        reached_by_call: list[set[int]] = []
        system_reached: set[int] = set()
        for call, scope in self.call_nodes:
            reached: set[int] = set()
            for keyword in call.keywords:
                if keyword.arg in _SYSTEM_KWARGS:
                    system_reached |= self._reached(keyword.value, scope, call.lineno, 0)
            args = list(call.args) + [
                k.value for k in call.keywords if k.arg in _CALL_PROMPT_KWARGS
            ]
            for arg in args:
                reached |= self._reached(arg, scope, call.lineno, 0)
            reached_by_call.append(reached)
        # A built string returned from a helper is a prompt once a model call's argument
        # reaches it, whatever the helper is called. Outer nodes were deferred first (walk
        # order), so a part nested in a promoted assembly stays folded into it.
        reached_any = set().union(*reached_by_call) if reached_by_call else set()
        for node_id, (node, scope, kind) in self.deferred.items():
            if node_id in reached_any and not any(
                id(a) in self.recorded for a in self.mod.ancestors(node)
            ):
                self._record(node, scope, kind, node_id in system_reached, ())
        assembly_ids = {id(n): i for i, n in enumerate(self.assembly_nodes)}
        for call_index, reached in enumerate(reached_by_call):
            for node_id in reached:
                if node_id in assembly_ids:
                    self.facts.assembly_feeds_call.setdefault(assembly_ids[node_id], call_index)
                if node_id in literal_ids:
                    self.facts.literal_feeds_call.setdefault(literal_ids[node_id], call_index)

    def _reached(self, expr: ast.AST, scope: _Scope, line: int, depth: int) -> set[int]:
        """ids of the assembly and literal nodes an expression resolves to."""
        if depth > _MAX_DEPTH:
            return set()
        wanted = self._wanted
        out = {id(n) for n in ast.walk(expr) if id(n) in wanted}
        for name in _names_in(expr):
            bound = scope.lookup(name, line)
            if bound is None or bound[0] != "assign" or bound[1] is None or bound[1] is expr:
                continue
            value = bound[1]
            out |= self._reached(value, scope, getattr(value, "lineno", line), depth + 1)
        for label in _dotted_in(expr):
            for value, vscope, _line in self.mod.attr_assigns.get(label, ()):
                if value is not expr:
                    out |= self._reached(value, vscope, getattr(value, "lineno", line), depth + 1)
        for sub in ast.walk(expr):
            if not isinstance(sub, ast.Call):
                continue
            chain = _chain(sub.func)
            if len(chain) != 1:
                continue
            found = self.index.lookup(chain[0], self.mod)
            if found is None or found[0] is not self.mod:
                continue
            fn = found[1]
            inner = self.mod.def_scope.get(fn)
            if inner is None:
                continue
            for value in _returns_of(fn):
                out |= self._reached(value, inner, getattr(value, "lineno", line), depth + 1)
        return out

    def _finish_order(self) -> None:
        """Sort the fact lists by line and re-index the feed maps to match."""
        facts = self.facts

        def order(items: list[Any]) -> tuple[list[Any], dict[int, int]]:
            positions = sorted(range(len(items)), key=lambda i: items[i].line)
            return [items[i] for i in positions], {old: new for new, old in enumerate(positions)}

        facts.llm_calls, call_map = order(facts.llm_calls)
        facts.prompt_assemblies, assembly_map = order(facts.prompt_assemblies)
        facts.prompt_literals, literal_map = order(facts.prompt_literals)
        facts.assembly_feeds_call = {
            assembly_map[a]: call_map[c] for a, c in sorted(facts.assembly_feeds_call.items())
        }
        facts.literal_feeds_call = {
            literal_map[a]: call_map[c] for a, c in sorted(facts.literal_feeds_call.items())
        }


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #


def _unknown(relpath: str, exc: BaseException) -> UnknownItem:
    return UnknownItem(
        category=UnknownCategory.DEEP,
        what="deep analysis",
        why=f"{type(exc).__name__}: {exc}",
        how_to_resolve="fix the parse error; grep-level findings for this file still apply",
        file=relpath,
    )


def _parse(relpath: str, unit: str | None, text: str, facts: PyFacts) -> _Module | None:
    try:
        return _Module(relpath, unit, ast.parse(text, filename=relpath), text)
    except _PARSE_ERRORS as exc:
        facts.unknown.append(_unknown(relpath, exc))
        return None


def _analyse(modules: list[_Module], facts: PyFacts) -> PyFacts:
    index = _UnitIndex(modules)
    for mod in modules:
        try:
            facts.merge(_Analyser(mod, index).run())
        except Exception as exc:  # an analyser bug must surface as UNKNOWN, never as a crash
            facts.unknown.append(_unknown(mod.relpath, exc))
    return facts


def analyse_file(record: Any, text: str) -> PyFacts:
    """Facts for one file. `record` needs `.relpath` (posix str) and optionally `.unit`."""
    facts = PyFacts()
    relpath = str(record.relpath).replace("\\", "/")
    mod = _parse(relpath, getattr(record, "unit", None), text, facts)
    return _analyse([mod], facts) if mod is not None else facts


def analyse_unit(files: list[Any], inventory: Any = None) -> PyFacts:
    """Facts for every Python file of a unit; helper returns are resolved across the unit.

    `files` are walker records (`.path`, `.relpath`, `.lang`, `.unit`); non-Python
    records are skipped. `inventory` is accepted for the contract and unused here.
    Never raises.
    """
    facts = PyFacts()
    modules: list[_Module] = []
    for record in files:
        lang = getattr(record, "lang", None)
        relpath = str(record.relpath).replace("\\", "/")
        if lang != "python" and not relpath.endswith((".py", ".pyi")):
            continue
        try:
            # `utf-8-sig`: a byte-order mark (common from Windows editors) is not Python
            # source and would otherwise turn the whole file into a parse error.
            text = Path(record.path).read_text(encoding="utf-8-sig", errors="replace")
        except (OSError, TypeError, ValueError) as exc:
            facts.unknown.append(_unknown(relpath, exc))
            continue
        mod = _parse(relpath, getattr(record, "unit", None), text, facts)
        if mod is not None:
            modules.append(mod)
    return _analyse(modules, facts)
