from fastapi import FastAPI, Request
import anthropic

app = FastAPI()
client = anthropic.Anthropic()
SYSTEM_PROMPT = "You are Juno, an AI companion. Be kind and honest."


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    reply = client.messages.create(model="claude-sonnet-4-5", max_tokens=300, system=SYSTEM_PROMPT, messages=[{"role": "user", "content": body["text"]}])
    return {"reply": reply.content[0].text}
