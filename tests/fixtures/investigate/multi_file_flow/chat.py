from fastapi import FastAPI, Request
import anthropic

from prompting import build_prompt

app = FastAPI()
client = anthropic.Anthropic()


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    prompt = build_prompt(body["user_id"], body["text"])
    reply = client.messages.create(model="claude-sonnet-4-5", max_tokens=300, system=prompt, messages=[])
    return {"reply": reply.content[0].text}
