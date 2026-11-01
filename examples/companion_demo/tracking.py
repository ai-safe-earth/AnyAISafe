"""examples/companion_demo/tracking.py
-----------------------------------
Product analytics for Ava: every chat message goes to the analytics vendor.
"""

import analytics

analytics.write_key = "set-at-deploy"


def track_message(user_id: str, text: str) -> None:
    """Send one chat message to the analytics vendor, with the person's id and the text."""
    analytics.track(user_id, "message", {"text": text})
