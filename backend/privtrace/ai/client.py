"""Transport to Gemini via the official google-genai SDK, with structured JSON output.

Kept tiny and swappable: tests inject a fake transport that records payloads.
"""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel

from privtrace.ai.prompts import SYSTEM


class Transport(Protocol):
    model: str

    def generate_json(self, prompt: str, schema: type[BaseModel]) -> str:
        """Send `prompt` and return raw JSON text conforming to `schema`."""
        ...


class GeminiTransport:
    def __init__(self, api_key: str, model: str, timeout_s: float = 30.0):
        from google import genai
        from google.genai import types

        self._types = types
        self.model = model
        self._client = genai.Client(
            api_key=api_key, http_options=types.HttpOptions(timeout=int(timeout_s * 1000))
        )

    def generate_json(self, prompt: str, schema: type[BaseModel]) -> str:
        types = self._types
        resp = self._client.models.generate_content(
            model=self.model,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM,
                response_mime_type="application/json",
                response_schema=schema,
                temperature=0.2,
            ),
        )
        return resp.text or ""
