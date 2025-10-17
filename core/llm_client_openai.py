# core/llm_client_openai.py
import os, json
from typing import Dict, Any

class OpenAILLMClient:
    def __init__(self, model: str = "gpt-4o-mini"):
        self.model = model
        self.api_key = os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise RuntimeError("OPENAI_API_KEY not set")

    def generate_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        # Minimal OpenAI client using requests (no extra deps)
        import requests
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        body = {
            "model": self.model,
            "response_format": {"type":"json_object"},
            "messages": [
                {"role":"system","content": system_prompt},
                {"role":"user","content": user_prompt},
            ],
            "temperature": 0.1
        }
        r = requests.post(url, headers=headers, json=body, timeout=60)
        r.raise_for_status()
        content = r.json()["choices"][0]["message"]["content"]
        return json.loads(content)
