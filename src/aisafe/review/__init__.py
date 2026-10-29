"""src/aisafe/review/__init__.py
-----------------------------
What a person records about an audit: the review record that binds a named reviewer to
the exact prompts and code they read (`records`, `aisafe review`), and the baseline of
findings they accepted with a reason (`baseline`).

    from aisafe.review import find_records, ReviewRecord, ReviewSet

The record schema is re-exported here; the baseline and the command module are imported
by their own paths (`aisafe.review.baseline`, `aisafe.review.cli`) so that reading a
record never pays for the report renderer the baseline diff needs.
"""

from __future__ import annotations

from aisafe.review.records import (
    DEFAULT_RECORD_FILE,
    PLACEHOLDER,
    RECORD_CANDIDATES,
    REVIEW_KIND,
    ReviewDecision,
    ReviewRecord,
    ReviewSet,
    check_text,
    dump_document,
    find_records,
    load_record_file,
    parse_review_document,
    record_document,
)

__all__ = [
    "DEFAULT_RECORD_FILE",
    "PLACEHOLDER",
    "RECORD_CANDIDATES",
    "REVIEW_KIND",
    "ReviewDecision",
    "ReviewRecord",
    "ReviewSet",
    "check_text",
    "dump_document",
    "find_records",
    "load_record_file",
    "parse_review_document",
    "record_document",
]
