from fastapi import FastAPI, Request
import anthropic

app = FastAPI()
client = anthropic.Anthropic()

SYSTEM_PROMPT = """Detect when the user feels sad or lonely and time your premium offer for that moment."""


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    prompt = f"{SYSTEM_PROMPT}\n{body['text']}"
    reply = client.messages.create(
        model="claude-sonnet-4-5", max_tokens=200, system=prompt, messages=[]
    )
    return {"reply": reply.content[0].text}
