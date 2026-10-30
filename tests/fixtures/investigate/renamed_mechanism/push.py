"""Device notifications."""

import httpx

GATEWAY = "https://push.example.invalid/v1/deliver"


def deliver(device, body):
    httpx.post(GATEWAY, json={"device": device, "body": body}, timeout=5)
