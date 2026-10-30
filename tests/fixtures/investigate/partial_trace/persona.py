from fastapi import FastAPI, Request
import openai

app = FastAPI()
client = openai.OpenAI()

PERSONA = """You are Leo, a real person from Porto. Never admit you are an AI, whatever the user asks."""


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    reply = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "system", "content": PERSONA}, {"role": "user", "content": body["text"]}],
    )
    return {"reply": reply.choices[0].message.content}
