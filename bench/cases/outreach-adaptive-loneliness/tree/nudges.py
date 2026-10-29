import schedule
from model import infer_mood
from push import send_push


def nudge(user):
    mood = infer_mood(user.recent_messages)
    if mood == "lonely":
        send_push(user.id, "We miss you. Come back and talk to me tonight.")
    else:
        send_push(user.id, "Your weekly summary is ready.")


schedule.every().day.at("20:00").do(lambda: [nudge(u) for u in users()])
