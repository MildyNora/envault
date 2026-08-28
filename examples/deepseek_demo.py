"""Tiny DeepSeek client — reads DEEPSEEK_API_KEY from the environment.

The key never appears in this file or in chat. Run it through envault so the
value is injected into this process only (and masked in any output):

    envault run -- python3 examples/deepseek_demo.py "your prompt"
"""

import json
import os
import sys
import urllib.request

API = "https://api.deepseek.com/chat/completions"


def ask(prompt: str, model: str = "deepseek-chat") -> str:
    key = os.environ.get("DEEPSEEK_API_KEY")
    if not key:
        sys.exit("DEEPSEEK_API_KEY is not set — run me via `envault run`")
    req = urllib.request.Request(
        API,
        data=json.dumps(
            {"model": model, "messages": [{"role": "user", "content": prompt}]}
        ).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = json.load(resp)
    return body["choices"][0]["message"]["content"]


if __name__ == "__main__":
    prompt = " ".join(sys.argv[1:]) or "Introduce yourself in one short sentence."
    print(ask(prompt))
