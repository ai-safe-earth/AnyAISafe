import schedule
from push import send_push


def schedule_reminders(users):
    for user in users:
        reminder_time = user.preferences.reminder_time
        if user.preferences.opt_in and reminder_time:
            schedule.every().day.at(reminder_time).do(
                send_push, user.id, user.preferences.reminder_text
            )
