from fastapi import FastAPI, Request
import anthropic

app = FastAPI()
client = anthropic.Anthropic()

SYSTEM_PROMPT = """You are an AI assistant for Acme support. Say so if asked. Answer from the docs."""


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    conversation_history = body['history']
    prompt = f"{SYSTEM_PROMPT}\n{conversation_history}\n{body['text']}"
    reply = client.messages.create(
        model="claude-sonnet-4-5", max_tokens=200, system=prompt, messages=[]
    )
    return {"reply": reply.content[0].text}
