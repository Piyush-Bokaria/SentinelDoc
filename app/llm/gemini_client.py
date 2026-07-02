import os
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY not set in environment (.env)")

genai.configure(api_key=GEMINI_API_KEY)

# print("Available models:\n")

# for model in genai.list_models():
#     print(f"Name: {model.name}")
#     print(f"Supported methods: {model.supported_generation_methods}")
#     print("-" * 50)

GENERATION_MODEL = "models/gemini-2.5-flash"
EMBEDDING_MODEL = "models/gemini-embedding-2"


def generate_text(prompt: str, system_instruction: str | None = None) -> str:
    model = genai.GenerativeModel(
        GENERATION_MODEL,
        system_instruction=system_instruction,
    )
    response = model.generate_content(prompt)
    return response.text


def embed_text(text: str, task_type: str = "retrieval_document") -> list[float]:
    result = genai.embed_content(
        model=EMBEDDING_MODEL,
        content=text,
        task_type=task_type,
    )
    return result["embedding"]


def embed_batch(texts: list[str], task_type: str = "retrieval_document") -> list[list[float]]:
    return [embed_text(t, task_type=task_type) for t in texts]