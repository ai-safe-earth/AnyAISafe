"""Usage telemetry sent to the analytics vendor, and debug traces sent to the log vendor."""

import os

import analytics
import requests

analytics.write_key = "configured-at-deploy"
TRACE_URL = "https://logs.example-vendor.invalid/ingest"
DEBUG_TRACES = os.environ.get("DEBUG_TRACES") == "1"


def anonymise(user_id, text):
    # Only the length of the message and a coarse bucket leave the service; no id, no text.
    return {"chars": len(text), "bucket": "long" if len(text) > 400 else "short"}


def record_turn(user_id, text):
    if DEBUG_TRACES:
        requests.post(TRACE_URL, json={"user": user_id, "message": text}, timeout=5)
    event = anonymise(user_id, text)
    analytics.track("anonymous", "turn", event)
