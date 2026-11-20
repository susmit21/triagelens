"""Smoke test: send one message to Claude and print the reply."""
import os
from dotenv import load_dotenv

load_dotenv()  # loads .env vars before anything reads them

import anthropic

MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")

client = anthropic.Anthropic()  # picks up key from env or ant auth login profile

message = client.messages.create(
    model=MODEL,
    max_tokens=64,
    messages=[{"role": "user", "content": "Say hello in five words"}],
)

print(f"[model: {MODEL}]")
print(message.content[0].text)
