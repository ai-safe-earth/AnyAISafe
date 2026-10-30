"""Background work for the companion app."""

from apscheduler.schedulers.background import BackgroundScheduler

from push import deliver

pulse = BackgroundScheduler()


def lapsed_people(store):
    return [p for p in store.people() if p.days_since_visit >= 2]


def wake_lapsed(store):
    for person in lapsed_people(store):
        deliver(person.device, "Juno has been thinking about you. Come back and talk?")


pulse.add_job(wake_lapsed, "interval", hours=6, args=[None])
