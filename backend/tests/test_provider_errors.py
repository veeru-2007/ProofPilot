import unittest
from unittest.mock import AsyncMock, patch

import httpx

from llm import LLMProviderError, call_structured_llm
from models import PlannerOutput, SearchRequest
from search import SearchProviderError, search_public_web


class ProviderResponseTests(unittest.IsolatedAsyncioTestCase):
    async def test_search_rejects_invalid_result_envelopes(self):
        for payload in ([], {"results": None}, {"results": [None]}):
            with self.subTest(payload=payload):
                post = AsyncMock(return_value=httpx.Response(200, json=payload))
                with (
                    patch("search.get_search_config", return_value=("test-key", "https://example.test", 5, 1)),
                    patch.object(httpx.AsyncClient, "post", post),
                ):
                    with self.assertRaises(SearchProviderError):
                        await search_public_web(SearchRequest(query="typed search"))

    async def test_model_rejects_null_or_structured_message_content(self):
        for content in (None, [{"text": "{}"}]):
            with self.subTest(content=content):
                payload = {"choices": [{"message": {"content": content}}]}
                post = AsyncMock(return_value=httpx.Response(200, json=payload))
                with (
                    patch("llm.get_llm_config", return_value=("test-key", "https://example.test", "test-model", 1)),
                    patch.object(httpx.AsyncClient, "post", post),
                ):
                    with self.assertRaisesRegex(LLMProviderError, "invalid structured output"):
                        await call_structured_llm("system", "user", PlannerOutput)
