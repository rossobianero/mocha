# core/llm_openai.py
from __future__ import annotations
import json, os
from typing import Any, Dict, Optional

try:
    from openai import OpenAI
except Exception as e:
    OpenAI = None  # type: ignore[misc]

class OpenAILLMClient:
    """
    Minimal adapter for core.fixer.LLMClient interface.
    Uses Chat Completions with response_format=json_object to get strict JSON.
    """
    def __init__(self, model: str = "gpt-4o-mini", api_key: Optional[str] = None, temperature: float = 0.2):
        if OpenAI is None:
            raise RuntimeError("openai>=2.x is not installed in this environment.")
        self._client = OpenAI(api_key=api_key or os.getenv("OPENAI_API_KEY"))
        if not (api_key or os.getenv("OPENAI_API_KEY")):
            raise RuntimeError("OPENAI_API_KEY is not set.")
        self.model = model
        self.temperature = float(temperature)

    def generate_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        # Ask the model to return a single JSON object complying with the schema.
        resp = self._client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
        )
        content = resp.choices[0].message.content or "{}"
        try:
            return json.loads(content)
        except Exception:
            # If the model still returned non-JSON, wrap it in a fallback envelope.
            return {
                "rationale": "Non-JSON response from model; see raw",
                "revised_file": "",
                "revised_lines": [],
                "patch_unified": "",
                "tests": "",
                "risk": "",
                "commands": "",
                "target_file": "",
                "_raw": content,
            }
