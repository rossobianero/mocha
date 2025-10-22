# core/llm_client_gemini.py
from core.util import log
import os
import json
from typing import Any, Dict, Optional

try:
    import google.generativeai as genai
except ImportError:
    genai = None

class GeminiLLMClient:
    """
    Minimal adapter for core.fixer.LLMClient interface using Google Gemini API.
    """
    def __init__(self, model: str = "gemini-pro", api_key: Optional[str] = None, temperature: float = 0.2):
        log(f"[llm] Using Gemini LLM Client with model: {model}")
        if genai is None:
            raise RuntimeError("google-generativeai is not installed.")
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise RuntimeError("GEMINI_API_KEY is not set.")
        self.model = model
        self.temperature = float(temperature)
        genai.configure(api_key=self.api_key)
        self.client = genai.GenerativeModel(model_name=self.model)

    def generate_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        prompt = f"{system_prompt}\n{user_prompt}"
        response = self.client.generate_content(prompt, generation_config={"temperature": self.temperature})
        try:
            return json.loads(response.text)
        except Exception:
            return {
                "rationale": "Non-JSON response from Gemini; see raw",
                "revised_file": "",
                "revised_lines": [],
                "patch_unified": "",
                "tests": "",
                "risk": "",
                "commands": "",
                "target_file": "",
                "_raw": response.text,
            }
