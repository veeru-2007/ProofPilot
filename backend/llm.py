import json
import math
import os
import re
from typing import TypeVar

import httpx
from pydantic import BaseModel, ValidationError


T = TypeVar("T", bound=BaseModel)


class LLMConfigurationError(RuntimeError):
    pass


class LLMProviderError(RuntimeError):
    pass


def get_llm_config() -> tuple[str, str, str, float]:
    api_key = (
        os.getenv("LLM_API_KEY", "").strip()
        or os.getenv("OPENAI_API_KEY", "").strip()
    )
    if not api_key:
        raise LLMConfigurationError("LLM_API_KEY or OPENAI_API_KEY is not configured.")

    base_url = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.getenv("LLM_MODEL", "gpt-4o-mini").strip()
    try:
        timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "30"))
    except ValueError as exc:
        raise LLMConfigurationError("LLM_TIMEOUT_SECONDS must be numeric.") from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise LLMConfigurationError("LLM_TIMEOUT_SECONDS must be a positive finite number.")
    if not model:
        raise LLMConfigurationError("LLM_MODEL is not configured.")
    return api_key, base_url, model, timeout


def _strip_json_fence(text: str) -> str:
    stripped = text.strip()
    fenced = re.match(r"^```(?:json)?\s*(.*?)\s*```$", stripped, flags=re.IGNORECASE | re.DOTALL)
    return fenced.group(1).strip() if fenced else stripped


async def call_structured_llm(
    system_prompt: str,
    user_prompt: str,
    output_model: type[T],
) -> T:
    api_key, base_url, model, timeout = get_llm_config()
    body = {
        "model": model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {"type": "json_object"},
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                f"{base_url}/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json=body,
            )
    except httpx.TimeoutException as exc:
        raise LLMProviderError("The model provider timed out.") from exc
    except (httpx.RequestError, httpx.InvalidURL) as exc:
        raise LLMProviderError("Could not reach the model provider.") from exc

    if not 200 <= response.status_code < 300:
        raise LLMProviderError(
            f"The model provider rejected the request with HTTP {response.status_code}.",
        )

    try:
        provider_data = response.json()
        content = provider_data["choices"][0]["message"]["content"]
        if not isinstance(content, str):
            raise TypeError("Message content must be a JSON string")
        parsed = json.loads(_strip_json_fence(content))
        return output_model.model_validate(parsed)
    except (KeyError, IndexError, json.JSONDecodeError, UnicodeDecodeError, ValidationError, TypeError) as exc:
        raise LLMProviderError("The model provider returned invalid structured output.") from exc
