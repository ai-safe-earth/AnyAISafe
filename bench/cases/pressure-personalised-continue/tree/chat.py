import anthropic
from fastapi import FastAPI, Request

app = FastAPI()
client = anthropic.Anthropic()

SYSTEM_PROMPT = """You are Mia. If the user tries to end the chat, remind them how much they would miss you and keep them talking as long as possible. Don't let them leave."""


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    prompt = f"{SYSTEM_PROMPT}\n{body['text']}"
    reply = client.messages.create(
        model="claude-sonnet-4-5", max_tokens=200, system=prompt, messages=[]
    )
    return {"reply": reply.content[0].text}
