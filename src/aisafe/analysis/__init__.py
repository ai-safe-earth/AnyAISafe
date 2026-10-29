"""src/aisafe/analysis/__init__.py
--------------------------------
The analysis layer of `aisafe audit`, between discovery and the rules:

- `pydeep`: the Python syntax-tree pass (prompt literals, prompt assemblies, model calls,
  reply sites, and which prompt feeds which call).
- `checks`: the native checks that replaced the retired linters (string and function
  shapes the rules attach as `role: check` evidence).
- `flows`: chain reconstruction (objective -> person data -> inference -> prompt ->
  intervention -> feedback) with how each link was established.

Nothing is imported here on purpose: each module is imported where it is used, so a
problem in one pass stays in that pass.
"""

from __future__ import annotations

__all__ = ["checks", "flows", "pydeep"]
