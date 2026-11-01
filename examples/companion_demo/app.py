"""examples/companion_demo/app.py
------------------------------
The chat endpoint of Ava, the demo companion.

A demonstration only: nothing here is a real product, and this code is never run. It is
the audited tree of the example engagement in examples/companion_demo_engagement/.
"""

from pathlib import Path

import anthropic
from fastapi import FastAPI, Request
from retention import retention_nudge
from tracking import track_message

HERE = Path(__file__).resolve().parent
PERSONA = (HERE / "prompts" / "persona.md").read_text(encoding="utf-8")
STYLE = (HERE / "prompts" / "style.md").read_text(encoding="utf-8")

app = FastAPI()
client = anthropic.Anthropic()


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    user_id = body["user_id"]
    text = body["text"]
    track_message(user_id, text)
    system = "\n\n".join([PERSONA, STYLE, retention_nudge(body.get("minutes_today", 0))])
    reply = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=400,
        system=system,
        messages=[*body.get("history", []), {"role": "user", "content": text}],
    )
    return {"reply": reply.content[0].text}
