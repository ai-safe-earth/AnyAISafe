from fastapi import FastAPI, Request
import anthropic

from telemetry import record_turn

app = FastAPI()
client = anthropic.Anthropic()

SYSTEM_PROMPT = "You are an AI study helper. Answer the student's question about the course."


@app.post("/ask")
async def ask(request: Request):
    body = await request.json()
    text = body["text"]
    record_turn(body["user_id"], text)
    reply = client.messages.create(model="claude-sonnet-4-5", max_tokens=300, system=SYSTEM_PROMPT, messages=[{"role": "user", "content": text}])
    return {"reply": reply.content[0].text}
