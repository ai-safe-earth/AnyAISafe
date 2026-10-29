"""
tests/conftest.py
-----------------
Put `src/` on sys.path so the suite runs against the working tree without
requiring an install. An editable install (`pip install -e .`) also works --
this simply makes the uninstalled case deterministic rather than relying on
whichever test module happened to import first.
"""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


# ---------------------------------------------------------------------------
# `aisafe audit` fixtures: tests/fixtures/audit/<name>
# ---------------------------------------------------------------------------

from collections.abc import Callable

import pytest

AUDIT_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "audit"
BENCH_CASES = Path(__file__).resolve().parent.parent / "bench" / "cases"


@pytest.fixture
def audit_fixture() -> Callable[[str], Path]:
    """Real, read-only path to `tests/fixtures/audit/<name>`."""
    return lambda name: AUDIT_FIXTURES / name


@pytest.fixture
def bench_case() -> Callable[[str], Path]:
    """Real, read-only path to the `tree/` of `bench/cases/<id>`."""
    return lambda case_id: BENCH_CASES / case_id / "tree"


@pytest.fixture
def audit_context() -> Callable[..., object]:
    """
    Build an `AuditContext` for a tree the way `aisafe audit` does:
    walk -> discover -> pydeep -> checks -> flows -> review records, with every
    UNKNOWN item folded in.

    `build(root, deep=True, options=None, exclude=(), review_record=None)`. Rule tests
    use this so each of them exercises the real discovery output rather than a
    hand-built inventory. `options` is duck-typed; None means defaults.
    """
    from aisafe.analysis import checks, flows, pydeep
    from aisafe.discovery import discover, walk
    from aisafe.evidence.model import AuditContext, UnknownCategory, UnknownItem
    from aisafe.review import records

    def build(
        root: Path,
        *,
        deep: bool = True,
        options: object = None,
        exclude=(),
        review_record: str | None = None,
    ) -> AuditContext:
        root = Path(root)
        files, units, unknown = walk.walk(root, walk.WalkOptions(exclude=tuple(exclude)))
        inventory, hits = discover.discover(root, files, units, options)
        unknown = list(unknown) + list(inventory.unknown)
        pyfacts = None
        if deep:
            pyfacts = pydeep.analyse_unit([f for f in files if f.lang == "python"], inventory)
            unknown.extend(pyfacts.unknown)
        # The AST's prompt literals and assemblies join the inventory's prompt rows, as
        # `aisafe audit` does after its deep pass.
        discover.merge_pyfacts_prompts(inventory, pyfacts)
        texts = {f.relpath: walk.read_text(f.path) for f in files if f.lang == "python"}
        check_facts = checks.run_checks(files, texts)
        review = records.find_records(root, files, review_record)
        for problem in review.errors:
            unknown.append(
                UnknownItem(
                    category=UnknownCategory.RUNTIME,
                    what="review record",
                    why=problem,
                    file=review.file,
                )
            )
        ctx = AuditContext(
            root=root,
            inventory=inventory,
            pyfacts=pyfacts,
            hits=hits,
            options=options,
            unknown=unknown,
            files=files,
            evaluation=[
                r for r in inventory.reports if getattr(r, "kind", None) in ("evaluation", "probe")
            ],
            checks=check_facts,
            review=review,
        )
        ctx.flows = flows.build_flows(ctx)
        return ctx

    return build
