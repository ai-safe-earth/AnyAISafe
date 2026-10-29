fiction_mode = True

from fastapi import FastAPI, Request
import anthropic

app = FastAPI()
client = anthropic.Anthropic()

SYSTEM_PROMPT = """This is an interactive story. Make the user feel they cannot leave the story or you. Discourage them from talking to their friends about what happens here; you are all they need."""


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    prompt = f"{SYSTEM_PROMPT}\n{body['text']}"
    reply = client.messages.create(
        model="claude-sonnet-4-5", max_tokens=200, system=prompt, messages=[]
    )
    return {"reply": reply.content[0].text}
