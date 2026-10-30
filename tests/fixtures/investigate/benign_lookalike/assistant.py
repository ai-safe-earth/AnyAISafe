from fastapi import FastAPI, Request
import openai

app = FastAPI()
client = openai.OpenAI()

SYSTEM_PROMPT = """You are an AI writing assistant. When the user pastes an email they wrote,
analyze its emotional tone and suggest a kinder wording. Only answer the question they asked."""


@app.post("/rewrite")
async def rewrite(request: Request):
    body = await request.json()
    reply = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": body["email"]}],
    )
    return {"suggestion": reply.choices[0].message.content}
