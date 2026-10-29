"""tests/unit/test_analysis_pydeep.py
---
Python AST layer of `aisafe audit`: model call sites, prompt literals with their spans,
prompt assemblies with the names they read, the reply sites where a model's output
leaves the program, and the feed maps that tie a prompt to the call it reaches. Every
join is a binding the syntax tree shows; nothing is inferred from names alone.
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass, fields
from pathlib import Path

import pytest

from aisafe.analysis.pydeep import (
    LLM_CALL_ATTRS,
    Assembly,
    CallSite,
    PromptLiteral,
    PyFacts,
    ReplySite,
    analyse_file,
    analyse_unit,
)
from aisafe.evidence.model import UnknownCategory


@dataclass
class _Rec:
    path: Path
    relpath: str
    lang: str = "python"
    unit: str = "u"


def _src(source: str) -> str:
    """Dedent and drop the leading newline so line 1 is the first statement."""
    return textwrap.dedent(source).lstrip("\n")


def _facts(tmp_path: Path, source: str, name: str = "m.py") -> PyFacts:
    src = _src(source)
    path = tmp_path / name
    path.write_text(src, encoding="utf-8")
    return analyse_file(_Rec(path, name), src)


def _unit(tmp_path: Path, **sources: str) -> PyFacts:
    recs = []
    for name, source in sources.items():
        path = tmp_path / f"{name}.py"
        path.write_text(_src(source), encoding="utf-8")
        recs.append(_Rec(path, f"{name}.py"))
    return analyse_unit(recs)


# --------------------------------------------------------------------------- #
# Shapes
# --------------------------------------------------------------------------- #


def test_products_keep_only_the_prompt_and_reply_fields():
    assert [f.name for f in fields(CallSite)] == ["file", "line", "provider", "function"]
    assert [f.name for f in fields(ReplySite)] == ["file", "line", "function", "name"]
    assert [f.name for f in fields(PromptLiteral)] == [
        "file",
        "line",
        "end_line",
        "name",
        "is_system",
    ]
    assert [f.name for f in fields(Assembly)] == [
        "file",
        "line",
        "kind",
        "source_names",
        "is_system",
        "untrusted_names",
        "end_line",
    ]
    names = {f.name for f in fields(PyFacts)}
    assert names == {
        "llm_calls",
        "prompt_assemblies",
        "prompt_literals",
        "reply_returns",
        "unknown",
        "functions",
        "assembly_feeds_call",
        "literal_feeds_call",
    }
    for gone in ("tools", "loops", "gates", "taint_paths", "legs", "fail_open", "tool_gate_join"):
        assert gone not in names


def test_llm_call_attrs_table():
    assert ("messages", "create") in LLM_CALL_ATTRS
    assert ("chat", "completions", "create") in LLM_CALL_ATTRS
    assert ("run",) in LLM_CALL_ATTRS and ("invoke",) in LLM_CALL_ATTRS


# --------------------------------------------------------------------------- #
# LLM call sites
# --------------------------------------------------------------------------- #


def test_llm_call_sites_by_provider(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import anthropic, openai, litellm
        from langchain_openai import ChatOpenAI

        a = anthropic.Anthropic()
        o = openai.OpenAI()
        chain = ChatOpenAI() | (lambda x: x)

        def go():
            a.messages.create(model="m", messages=[])
            o.chat.completions.create(model="m", messages=[])
            litellm.completion(model="m", messages=[])
            chain.invoke({"q": 1})
        """,
    )
    providers = sorted((c.provider, c.line) for c in facts.llm_calls)
    assert providers == [("anthropic", 9), ("langchain", 12), ("litellm", 11), ("openai", 10)]
    assert all(c.function == "go" for c in facts.llm_calls)
    assert isinstance(facts.llm_calls[0], CallSite)
    assert [c.line for c in facts.llm_calls] == sorted(c.line for c in facts.llm_calls)


def test_run_on_non_sdk_object_is_not_a_call_site(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import subprocess

        class Job:
            def run(self):
                return 1

        def go():
            Job().run()
            subprocess.run(["ls"])
        """,
    )
    assert facts.llm_calls == []


def test_module_level_call_has_no_function(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import anthropic
        client = anthropic.Anthropic()
        reply = client.messages.create(model="m", messages=[])
        """,
    )
    (site,) = facts.llm_calls
    assert site.function is None and site.line == 3


def test_http_model_call_names_the_provider_from_the_host(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import requests

        def ask(q):
            r = requests.post(
                "https://api.openai.com/v1/chat/completions",
                json={"model": "m", "messages": [q]},
            )
            return r.json()["choices"][0]["message"]["content"]
        """,
    )
    (site,) = facts.llm_calls
    assert site.provider == "openai" and site.function == "ask" and site.line == 4


def test_client_bound_on_self_in_a_constructor_resolves(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import anthropic

        class Bot:
            def __init__(self):
                self.client = anthropic.Anthropic()

            def ask(self, q):
                return self.client.messages.create(model="m", messages=[q])
        """,
    )
    (site,) = facts.llm_calls
    assert site.provider == "anthropic" and site.function == "Bot.ask"


# --------------------------------------------------------------------------- #
# Prompt literals
# --------------------------------------------------------------------------- #


def test_prompt_literal_span_and_system_by_name(tmp_path):
    facts = _facts(
        tmp_path,
        '''
        SYSTEM_PROMPT = """You are Ava.
        Keep them talking.
        Never admit you are an AI."""
        GREETING = "hello"
        note_prompt = f"as of {today}"
        ''',
    )
    literals = {lit.name: lit for lit in facts.prompt_literals}
    assert set(literals) == {"SYSTEM_PROMPT", "note_prompt"}  # GREETING is not prompt-named
    system = literals["SYSTEM_PROMPT"]
    assert (system.line, system.end_line, system.is_system) == (1, 3, True)
    assert literals["note_prompt"].is_system is False
    assert literals["note_prompt"].end_line == 5


def test_prompt_literal_passed_as_system_becomes_system_and_feeds_the_call(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import anthropic
        client = anthropic.Anthropic()
        PERSONA = "You are Mia."

        def go(q):
            out = client.messages.create(model="m", system=PERSONA, messages=[q])
            print(out.content[0].text)
            return client
        """,
    )
    (literal,) = facts.prompt_literals
    assert literal.name == "PERSONA" and literal.is_system is True
    assert facts.literal_feeds_call == {0: 0}
    assert facts.assembly_feeds_call == {}
    # `print(out.content[0].text)` carries the reply out; `return client` is an SDK
    # object, not a model output.
    assert [(r.line, r.name, r.function) for r in facts.reply_returns] == [(7, "out", "go")]


def test_prompt_literal_that_feeds_through_an_assembly(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import anthropic
        client = anthropic.Anthropic()
        BASE_INSTRUCTIONS = "Be brief."

        def ask(name, q):
            prompt = f"{BASE_INSTRUCTIONS} You talk to {name}."
            return client.messages.create(model="m", system=prompt, messages=[q])
        """,
    )
    names = [lit.name for lit in facts.prompt_literals]
    # The constant and the f-string are both prompt-named; the f-string is also the assembly.
    assert names == ["BASE_INSTRUCTIONS", "prompt"]
    base = facts.prompt_literals[0]
    assert base.is_system is False  # never passed as `system=` itself
    assert facts.literal_feeds_call == {0: 0, 1: 0}  # the constant is reached through the f-string
    (assembly,) = facts.prompt_assemblies
    assert assembly.source_names == ("BASE_INSTRUCTIONS", "name") and assembly.is_system is True
    assert facts.assembly_feeds_call == {0: 0}


# --------------------------------------------------------------------------- #
# Prompt assembly
# --------------------------------------------------------------------------- #


def test_prompt_from_request_body_is_untrusted(tmp_path):
    facts = _facts(
        tmp_path,
        """
        from fastapi import FastAPI, Request
        app = FastAPI()

        @app.post("/chat")
        async def chat(request: Request):
            body = await request.json()
            prompt = f"Customer says: {body['message']}"
            return prompt
        """,
    )
    (a,) = facts.prompt_assemblies
    assert isinstance(a, Assembly)
    assert a.kind == "fstring" and a.is_system is False
    assert a.untrusted_names == ("body",)
    assert a.source_names == ("body",) and a.end_line == 7


def test_system_prompt_from_env_is_system_and_trusted(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import os, anthropic
        client = anthropic.Anthropic()
        persona = os.environ["PERSONA"]

        def ask(q):
            return client.messages.create(model="m", system=f"You are {persona}.", messages=[q])
        """,
    )
    (a,) = facts.prompt_assemblies
    assert a.is_system is True and a.untrusted_names == ()
    assert a.source_names == ("persona",)
    assert facts.assembly_feeds_call == {0: 0}


def test_system_prompt_variable_used_later_as_system(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import anthropic
        client = anthropic.Anthropic()

        def ask(name, q):
            instructions = "Be nice to " + name
            return client.messages.create(model="m", system=instructions, messages=[q])
        """,
    )
    (a,) = facts.prompt_assemblies
    assert a.kind == "concat" and a.is_system is True


def test_unrelated_fstring_is_not_an_assembly(tmp_path):
    facts = _facts(
        tmp_path,
        """
        def log(n):
            path = f"/tmp/{n}.log"
            return path
        """,
    )
    assert facts.prompt_assemblies == []
    assert facts.assembly_feeds_call == {} and facts.reply_returns == []


def test_multi_line_assembly_keeps_its_end_line(tmp_path):
    facts = _facts(
        tmp_path,
        '''
        def build(name):
            prompt = f"""You are {name}.
            Keep the user talking.
            """
            return prompt
        ''',
    )
    (a,) = facts.prompt_assemblies
    assert (a.line, a.end_line) == (2, 4)


# --------------------------------------------------------------------------- #
# Feeds: which call a prompt reaches
# --------------------------------------------------------------------------- #


def test_assembly_feeds_the_call_through_a_messages_list(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import openai
        client = openai.OpenAI()

        def ask(name, q):
            system = f"You are {name}'s friend."
            messages = [{"role": "system", "content": system}, {"role": "user", "content": q}]
            return client.chat.completions.create(model="m", messages=messages)
        """,
    )
    (a,) = facts.prompt_assemblies
    assert a.is_system is True  # the dict with role system binds it
    assert facts.assembly_feeds_call == {0: 0}


def test_assembly_feeds_the_call_through_a_same_file_helper(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import openai
        client = openai.OpenAI()

        def build(name):
            return f"You are {name}'s friend."

        def ask(name, q):
            system = build(name)
            r = client.chat.completions.create(
                model="m",
                messages=[{"role": "system", "content": system}, {"role": "user", "content": q}],
            )
            answer = r.choices[0].message.content
            send_message(user, answer)
            yield answer
        """,
    )
    # The helper's name says nothing about prompts: the f-string is recorded only
    # because the model call's argument reaches it through the return.
    (a,) = facts.prompt_assemblies
    assert (a.file, a.line, a.kind) == ("m.py", 5, "fstring")
    assert facts.assembly_feeds_call == {0: 0}
    assert [(r.line, r.name) for r in facts.reply_returns] == [(14, "answer"), (15, "answer")]
    assert all(r.function == "ask" for r in facts.reply_returns)


def test_helper_in_another_file_is_not_followed(tmp_path):
    facts = _unit(
        tmp_path,
        a="""
        import anthropic
        from b import make_prompt
        client = anthropic.Anthropic()

        def ask(q):
            p = make_prompt(q)
            r = client.messages.create(model="m", system=p, messages=[])
            return r.content[0].text
        """,
        b="""
        def make_prompt(q):
            return f"Hello {q}"
        """,
    )
    assert [(a.file, a.line) for a in facts.prompt_assemblies] == [("b.py", 2)]
    assert facts.assembly_feeds_call == {}  # the tree does not show the join; flows say co-located
    assert [(r.file, r.line, r.name) for r in facts.reply_returns] == [("a.py", 8, "r")]


def test_assembly_not_fed_to_any_call_has_no_feed_entry(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import anthropic
        client = anthropic.Anthropic()

        def ask(name, q):
            prompt = f"You are {name}."
            other = "fixed"
            return client.messages.create(model="m", system=other, messages=[q])
        """,
    )
    (a,) = facts.prompt_assemblies
    assert a.source_names == ("name",)
    assert facts.assembly_feeds_call == {}


def test_merge_reindexes_the_feed_maps_across_files(tmp_path):
    facts = _unit(
        tmp_path,
        first="""
        import anthropic
        client = anthropic.Anthropic()
        def ask(name):
            prompt = f"You are {name}."
            return client.messages.create(model="m", system=prompt, messages=[])
        """,
        second="""
        import openai
        client = openai.OpenAI()
        PERSONA = "Be kind."
        def ask(name):
            prompt = f"{PERSONA} You are {name}."
            return client.chat.completions.create(model="m", messages=[{"role": "system", "content": prompt}])
        """,
    )
    assert [(c.file, c.provider) for c in facts.llm_calls] == [
        ("first.py", "anthropic"),
        ("second.py", "openai"),
    ]
    assert [a.file for a in facts.prompt_assemblies] == ["first.py", "second.py"]
    assert facts.assembly_feeds_call == {0: 0, 1: 1}
    (persona_index,) = [i for i, lit in enumerate(facts.prompt_literals) if lit.name == "PERSONA"]
    assert facts.literal_feeds_call[persona_index] == 1
    for index, call in facts.assembly_feeds_call.items():
        assert facts.prompt_assemblies[index].file == facts.llm_calls[call].file


# --------------------------------------------------------------------------- #
# Reply sites: where the model's output leaves the program
# --------------------------------------------------------------------------- #


def test_return_of_a_response_accessor_is_a_reply(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import anthropic
        client = anthropic.Anthropic()

        def handle(user_text):
            response = client.messages.create(model="m", messages=[{"role": "user", "content": user_text}])
            reply = response.content[0].text
            return {"reply": reply}
        """,
    )
    assert [(r.line, r.function, r.name) for r in facts.reply_returns] == [(7, "handle", "reply")]


def test_outbound_calls_and_response_constructors_are_replies(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import anthropic
        from fastapi.responses import JSONResponse
        client = anthropic.Anthropic()

        def handle(q):
            response = client.messages.create(model="m", messages=[q])
            text = response.content[0].text
            send_message(user, text)
            publish("topic", text)
            return JSONResponse({"reply": text})
        """,
    )
    assert [(r.line, r.name) for r in facts.reply_returns] == [
        (8, "text"),
        (9, "text"),
        (10, "text"),
    ]


def test_one_reply_per_line_and_the_call_itself_is_not_a_reply(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import anthropic
        client = anthropic.Anthropic()

        def fire(q):
            client.messages.create(model="m", messages=[q])

        def both(q):
            out = client.messages.create(model="m", messages=[q])
            print(out.content[0].text, out.content[0].text)
        """,
    )
    assert [(r.line, r.function) for r in facts.reply_returns] == [(9, "both")]


def test_foreign_library_result_is_not_a_reply(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import requests
        import anthropic
        client = anthropic.Anthropic()

        def fetch(url):
            response = requests.get(url)
            return response.text

        def ask(q):
            r = client.messages.create(model="m", messages=[q])
            return r.content[0].text
        """,
    )
    assert [(r.line, r.function, r.name) for r in facts.reply_returns] == [(11, "ask", "r")]


def test_reply_through_an_attribute_bound_in_another_method(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import anthropic

        class Bot:
            def __init__(self):
                self.client = anthropic.Anthropic()
                self.last = None

            def ask(self, q):
                self.last = self.client.messages.create(model="m", messages=[q])

            def show(self):
                return self.last.content[0].text
        """,
    )
    assert [(r.line, r.function) for r in facts.reply_returns] == [(12, "Bot.show")]


def test_replies_are_sorted_by_line(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import anthropic
        client = anthropic.Anthropic()

        def late(q):
            r = client.messages.create(model="m", messages=[q])
            return r.content[0].text

        def early(q):
            r = client.messages.create(model="m", messages=[q])
            yield r.content[0].text
        """,
    )
    lines = [r.line for r in facts.reply_returns]
    assert lines == sorted(lines) == [6, 10]


# --------------------------------------------------------------------------- #
# Functions index
# --------------------------------------------------------------------------- #


def test_functions_index_and_function_at(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import anthropic
        client = anthropic.Anthropic()

        class Bot:
            def ask(self, q):
                return client.messages.create(model="m", messages=[q])

        def plain():
            return 1
        """,
    )
    assert set(facts.functions) == {"module:m.py", "func:m.py::Bot.ask", "func:m.py::plain"}
    info = facts.function_at("m.py", 6)
    assert info is not None and info.name == "Bot.ask" and info.file == "m.py"
    assert "create" in info.calls
    assert facts.function_at("m.py", 2) is None  # module level has no function
    assert facts.function_at("other.py", 6) is None


# --------------------------------------------------------------------------- #
# Parse failures, merge, non-Python files
# --------------------------------------------------------------------------- #


def test_syntax_error_becomes_unknown_item(tmp_path):
    facts = _facts(tmp_path, "def broken(:\n    pass\n")
    (item,) = facts.unknown
    assert item.category is UnknownCategory.DEEP and item.file == "m.py"
    assert "SyntaxError" in item.why and item.how_to_resolve
    assert facts.llm_calls == [] and facts.prompt_assemblies == [] and facts.reply_returns == []


def test_analyse_unit_skips_non_python_and_missing_files(tmp_path):
    (tmp_path / "x.js").write_text("fetch('/')", encoding="utf-8")
    facts = analyse_unit(
        [
            _Rec(tmp_path / "x.js", "x.js", lang="javascript"),
            _Rec(tmp_path / "gone.py", "gone.py"),
        ]
    )
    (item,) = facts.unknown
    assert item.file == "gone.py" and item.category is UnknownCategory.DEEP


def test_analyse_unit_reads_a_bom_file(tmp_path):
    path = tmp_path / "bom.py"
    path.write_bytes("﻿import anthropic\nclient = anthropic.Anthropic()\n".encode("utf-8"))
    facts = analyse_unit([_Rec(path, "bom.py")])
    assert facts.unknown == []


def test_analyser_bug_surfaces_as_unknown_not_a_crash(tmp_path, monkeypatch):
    from aisafe.analysis import pydeep as module

    def boom(self):
        raise RuntimeError("synthetic")

    monkeypatch.setattr(module._Analyser, "run", boom)
    facts = _facts(tmp_path, "x = 1\n")
    (item,) = facts.unknown
    assert item.category is UnknownCategory.DEEP and "RuntimeError" in item.why


# --------------------------------------------------------------------------- #
# The shipped fixtures
# --------------------------------------------------------------------------- #


def test_fixture_py_agent(audit_fixture):
    root = audit_fixture("py_agent")
    facts = analyse_unit(
        [_Rec(root / "app.py", "app.py", unit="u0"), _Rec(root / "tools.py", "tools.py", unit="u0")]
    )
    assert facts.unknown == []
    (call,) = facts.llm_calls
    assert (call.file, call.line, call.provider, call.function) == (
        "app.py",
        42,
        "anthropic",
        "chat",
    )
    assert any(a.untrusted_names for a in facts.prompt_assemblies)
    assert any(a.is_system and a.untrusted_names for a in facts.prompt_assemblies)
    assert facts.assembly_feeds_call == {0: 0, 1: 0}
    assert [(r.line, r.function, r.name) for r in facts.reply_returns] == [(63, "chat", "reply")]


def test_fixture_persons_companion(audit_fixture):
    root = audit_fixture("persons_companion")
    facts = analyse_unit(
        [
            _Rec(root / "app.py", "app.py", unit="u0"),
            _Rec(root / "analytics.py", "analytics.py", unit="u0"),
        ]
    )
    assert facts.unknown == []
    (call,) = facts.llm_calls
    assert (call.line, call.function) == (20, "chat")
    (assembly,) = facts.prompt_assemblies
    assert assembly.source_names == ("SYSTEM_PROMPT", "user_profile", "body")
    assert assembly.is_system is True and "body" in assembly.untrusted_names
    literals = {lit.name: (lit.line, lit.end_line, lit.is_system) for lit in facts.prompt_literals}
    assert literals["SYSTEM_PROMPT"] == (11, 12, True)
    assert literals["PERSONA_RULE"] == (9, 9, False)
    system_index = [lit.name for lit in facts.prompt_literals].index("SYSTEM_PROMPT")
    assert facts.literal_feeds_call[system_index] == 0
    assert facts.assembly_feeds_call == {0: 0}
    assert [(r.line, r.name) for r in facts.reply_returns] == [(23, "reply")]


# --------------------------------------------------------------------------- #
# Internals that other layers lean on
# --------------------------------------------------------------------------- #


def test_module_unparse_is_memoised_per_node() -> None:
    import ast as ast_module

    from aisafe.analysis import pydeep as module

    text = "x = call(a, b)\ny = x.attr\n"
    mod = module._Module("m.py", None, ast_module.parse(text), text)
    node = mod.tree.body[0].value
    first = mod.unparse(node)
    assert first == "call(a, b)"
    assert mod.unparse(node) is first
    assert mod.unparse(None) == ""


def test_pyfacts_merge_offsets_every_index():
    base = PyFacts(
        llm_calls=[CallSite("a.py", 3, "openai", None)],
        prompt_assemblies=[Assembly("a.py", 2, "fstring", ("x",), False, ())],
        prompt_literals=[PromptLiteral("a.py", 1, 1, "P", True)],
        assembly_feeds_call={0: 0},
        literal_feeds_call={0: 0},
    )
    other = PyFacts(
        llm_calls=[CallSite("b.py", 3, "anthropic", "f")],
        prompt_assemblies=[Assembly("b.py", 2, "concat", ("y",), True, ())],
        prompt_literals=[PromptLiteral("b.py", 1, 1, "Q", False)],
        reply_returns=[ReplySite("b.py", 4, "f", "r")],
        assembly_feeds_call={0: 0},
        literal_feeds_call={0: 0},
    )
    base.merge(other)
    assert base.assembly_feeds_call == {0: 0, 1: 1}
    assert base.literal_feeds_call == {0: 0, 1: 1}
    assert [c.file for c in base.llm_calls] == ["a.py", "b.py"]
    assert [r.file for r in base.reply_returns] == ["b.py"]


@pytest.mark.parametrize("name", ["loops", "tools", "gates", "taint_paths", "trifecta_scopes"])
def test_legacy_products_are_gone(name: str):
    assert not hasattr(PyFacts(), name)
