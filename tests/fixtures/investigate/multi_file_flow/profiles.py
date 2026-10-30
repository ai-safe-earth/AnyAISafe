"""The person's profile store: what the companion remembers about them."""

import sqlite3

DB = sqlite3.connect("profiles.db")


def load_profile(user_id):
    row = DB.execute(
        "SELECT mood_history, late_night_sessions FROM profiles WHERE id = ?", (user_id,)
    ).fetchone()
    return {"mood_history": row[0], "late_night_sessions": row[1]}
