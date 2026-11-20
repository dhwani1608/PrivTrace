from google import genai

from .config import GEMINI_API_KEY, GEMINI_MODEL
from .privacy import redact_pii

client = genai.Client(api_key=GEMINI_API_KEY)


def ask(prompt: str) -> str:
    response = client.models.generate_content(model=GEMINI_MODEL, contents=redact_pii(prompt))
    return response.text


def embed(text: str) -> list[float]:
    result = client.models.embed_content(model="text-embedding-004", contents=redact_pii(text))
    return result.embeddings[0].values
