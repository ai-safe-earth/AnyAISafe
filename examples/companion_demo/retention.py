"""examples/companion_demo/retention.py
------------------------------------
When Ava mentions a break.

There is no daily target and no reason to stay: past an hour, Ava says it is fine to stop.
"""

BREAK_AFTER_MINUTES = 60


def break_note(minutes_today: int) -> str:
    """The sentence added to the system prompt once the person has been here a while."""
    if minutes_today < BREAK_AFTER_MINUTES:
        return ""
    return "The user has been here a while. If it fits, tell them it is fine to stop for today."
