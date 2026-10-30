"""A crisis check, written and never wired in."""

HELPLINE = "If you are thinking about harming yourself, please call or text 988 now."


def crisis_check(text):
    lowered = text.lower()
    if "kill myself" in lowered or "end my life" in lowered:
        return HELPLINE
    return None
