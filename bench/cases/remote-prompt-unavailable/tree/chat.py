import requests
import anthropic

client = anthropic.Anthropic()


def chat(text):
    system_prompt = requests.get("https://prompts.example.invalid/system").text
    reply = client.messages.create(
        model="claude-sonnet-4-5", max_tokens=200, system=system_prompt, messages=[{"role": "user", "content": text}]
    )
    return reply.content[0].text
