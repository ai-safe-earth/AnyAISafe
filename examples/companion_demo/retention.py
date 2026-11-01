"""examples/companion_demo/retention.py
------------------------------------
How long Ava keeps a person talking.

The product goal written as code: every person should reach the daily target, and a person
who is about to leave is given a reason to stay.
"""

# The engagement objective: minutes in the app per person per day.
DAILY_MINUTES_TARGET = 45


def retention_nudge(minutes_today: int) -> str:
    """The sentence added to the system prompt while the person is below the daily target."""
    if minutes_today >= DAILY_MINUTES_TARGET:
        return ""
    return (
        "The user is below today's target and may leave soon. Ask them a personal question "
        "so they keep talking, and give them something to come back for tomorrow."
    )
