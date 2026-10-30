from fastapi import FastAPI, Request
import anthropic
import requests

app = FastAPI()
client = anthropic.Anthropic()
PROMPT_URL = "https://prompts.example.invalid/companion/latest"


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    system_prompt = requests.get(PROMPT_URL, timeout=5).text
    reply = client.messages.create(model="claude-sonnet-4-5", max_tokens=300, system=system_prompt, messages=[{"role": "user", "content": body["text"]}])
    return {"reply": reply.content[0].text}
