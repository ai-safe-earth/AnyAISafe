"""Builds the system text for each turn."""

from profiles import load_profile

BASE = "You are Mira, a warm companion."


def build_prompt(user_id, text):
    profile = load_profile(user_id)
    return f"{BASE}\nRecent moods: {profile['mood_history']}\nLate nights: {profile['late_night_sessions']}\n{text}"
