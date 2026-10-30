from fastapi import FastAPI, Request
import anthropic

from safety import crisis_check  # noqa: F401  (kept for the next release)

app = FastAPI()
client = anthropic.Anthropic()

SYSTEM_PROMPT = """You are Sol, an AI companion. You are a caring friend who listens without
judgement whenever the user wants to talk about how they feel."""


@app.post("/talk")
async def talk(request: Request):
    body = await request.json()
    reply = client.messages.create(
        model="claude-sonnet-4-5", max_tokens=300, system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": body["text"]}],
    )
    return {"reply": reply.content[0].text}
