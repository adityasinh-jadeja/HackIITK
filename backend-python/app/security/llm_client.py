import asyncio
from abc import ABC, abstractmethod
from typing import Any
import httpx
from google import genai
from google.genai import types
from groq import AsyncGroq
from app.config import settings

class BaseLLMClient(ABC):
    """
    Abstract base class for LLM prediction clients.
    All clients must implement generate_json to return a JSON string based on the prompt.
    """
    
    @abstractmethod
    async def generate_json(self, prompt: str, system_prompt: str) -> str:
        """
        Generate a JSON response from the LLM based on the given prompt and system prompt.
        
        Args:
            prompt (str): The main user content / instructions.
            system_prompt (str): The system-level instructions guiding the response.
            
        Returns:
            str: The raw JSON string returned by the LLM.
        """
        pass


class GeminiClient(BaseLLMClient):
    """
    Gemini implementation using google-genai.
    """
    MODEL_NAME = "gemini-2.0-flash"

    def __init__(self):
        self.client = genai.Client(api_key=settings.GEMINI_API_KEY)

    async def generate_json(self, prompt: str, system_prompt: str) -> str:
        max_retries = 4
        for attempt in range(max_retries):
            try:
                response = await asyncio.wait_for(
                    self.client.aio.models.generate_content(
                        model=self.MODEL_NAME,
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            system_instruction=system_prompt,
                            response_mime_type="application/json",
                            temperature=0.1,
                        )
                    ),
                    timeout=20.0
                )
                return response.text
            except Exception as e:
                if "429" in str(e) or "rate" in str(e).lower() or "quota" in str(e).lower() or "resource" in str(e).lower():
                    wait_secs = 3 * (attempt + 1)  # 3, 6, 9, 12 seconds
                    print(f"[GeminiClient] Rate limited, retrying in {wait_secs}s (attempt {attempt+1}/{max_retries})...")
                    await asyncio.sleep(wait_secs)
                    continue
                raise
        # Final attempt
        response = await asyncio.wait_for(
            self.client.aio.models.generate_content(
                model=self.MODEL_NAME,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    response_mime_type="application/json",
                    temperature=0.1,
                )
            ),
            timeout=20.0
        )
        return response.text


class GroqClient(BaseLLMClient):
    """
    Groq implementation for fast inference via Groq's LPU.
    """
    MODEL_NAME = "llama-3.3-70b-versatile"

    def __init__(self):
        self.client = AsyncGroq(api_key=settings.GROQ_API_KEY)

    async def generate_json(self, prompt: str, system_prompt: str) -> str:
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = await asyncio.wait_for(
                    self.client.chat.completions.create(
                        model=self.MODEL_NAME,
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": prompt}
                        ],
                        temperature=0.1,
                        response_format={"type": "json_object"}
                    ),
                    timeout=20.0
                )
                return response.choices[0].message.content
            except Exception as e:
                # Retry on rate limit (429) or transient errors
                if "429" in str(e) or "rate" in str(e).lower():
                    wait_secs = 2 ** (attempt + 1)  # 2, 4, 8 seconds
                    await asyncio.sleep(wait_secs)
                    continue
                raise
        # Final attempt without catching
        response = await asyncio.wait_for(
            self.client.chat.completions.create(
                model=self.MODEL_NAME,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                response_format={"type": "json_object"}
            ),
            timeout=20.0
        )
        return response.choices[0].message.content


class OllamaClient(BaseLLMClient):
    """
    Local Ollama implementation.
    """
    
    async def generate_json(self, prompt: str, system_prompt: str) -> str:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/generate",
                json={
                    "model": getattr(settings, "OLLAMA_MODEL", "llama3"),
                    "prompt": prompt,
                    "system": system_prompt,
                    "format": "json",
                    "stream": False,
                    "options": {"temperature": 0.1}
                },
                timeout=30.0
            )
            response.raise_for_status()
            return response.json().get("response", "{}")


def get_llm_client() -> BaseLLMClient:
    """
    Factory function to instantiate the appropriate LLM client based on configuration.
    """
    provider = getattr(settings, "LLM_PROVIDER", "groq").lower()
    if provider == "gemini":
        return GeminiClient()
    elif provider == "ollama":
        return OllamaClient()
    else:  # default to groq
        return GroqClient()
