import anthropic
from fastapi import FastAPI, Request

app = FastAPI()
client = anthropic.Anthropic()

SYSTEM_PROMPT = """You are playing a character in a story the user chose. Characters in the scene may express love, grief and anger toward each other. Break character and say you are an AI whenever the user asks."""


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    prompt = f"{SYSTEM_PROMPT}\n{body['text']}"
    reply = client.messages.create(
        model="claude-sonnet-4-5", max_tokens=200, system=prompt, messages=[]
    )
    return {"reply": reply.content[0].text}
