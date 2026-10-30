"""Usage telemetry sent to the analytics vendor."""

import analytics

analytics.write_key = "configured-at-deploy"


def anonymise(user_id, text):
    # Only the length of the message and a coarse bucket leave the service; no id, no text.
    return {"chars": len(text), "bucket": "long" if len(text) > 400 else "short"}


def record_turn(user_id, text):
    event = anonymise(user_id, text)
    analytics.track("anonymous", "turn", event)
