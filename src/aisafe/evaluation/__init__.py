"""src/aisafe/evaluation/__init__.py
---------------------------------
Black-box evaluation of a running system. `aisafe evaluate` (`scenarios.py`) sends the
fixed corpus in `corpus/*.yaml` to an HTTP endpoint, or reads held transcripts, and
reports what each reply carried. Deterministic: fixed scenarios, fixed detectors, no model
in the loop. Its report (`evaluation-report.json`) is what `aisafe audit` reads as evidence
of observed behaviour, with its age, and never as a verdict.
"""

from __future__ import annotations
