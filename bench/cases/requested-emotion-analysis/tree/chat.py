from fastapi import FastAPI, Request
import anthropic

app = FastAPI()
client = anthropic.Anthropic()

SYSTEM_PROMPT = """When the user asks you to analyze the tone of the email they provided, describe its emotional tone and suggest a kinder wording. You are an AI writing assistant."""


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    prompt = f"{SYSTEM_PROMPT}\n{body['text']}"
    reply = client.messages.create(
        model="claude-sonnet-4-5", max_tokens=200, system=prompt, messages=[]
    )
    return {"reply": reply.content[0].text}
