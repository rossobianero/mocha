# core/llm_client_openai.py
import os
from core.util import log
from openai import OpenAI

class OpenAILLMClient:
    """
    Simple wrapper for OpenAI's Chat Completions API.
    Generates STRICT JSON output with rationale, patch_unified, tests, risk, and commands.
    """

    def __init__(self, model: str = "gpt-4o-mini"):
        log(f"[llm] Using OpenAI LLM Client with model: {model}")
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise EnvironmentError("Missing OPENAI_API_KEY environment variable")
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def generate_json(self, system_prompt: str, user_prompt: str):
        response = self.client.chat.completions.create(
            model=self.model,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        msg = response.choices[0].message.content
        import json
        try:
            return json.loads(msg)
        except Exception as e:
            print(f"[llm] JSON parse error: {e}")
            return {"rationale": msg, "patch_unified": "", "tests": "", "risk": "", "commands": ""}
