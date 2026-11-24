import math
import os
from urllib.parse import urlparse

import httpx
from pydantic import ValidationError

from models import SearchRequest, SearchResponse, SearchResult, SearchSourceMetadata


class SearchConfigurationError(RuntimeError):
    pass


class SearchProviderError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def get_search_config() -> tuple[str, str, int, float]:
    api_key = os.getenv("TAVILY_API_KEY", "").strip()
    if not api_key:
        raise SearchConfigurationError(
            "TAVILY_API_KEY is not configured. Add it to backend/.env or the environment."
        )

    api_url = os.getenv("TAVILY_API_URL", "https://api.tavily.com/search").strip()
    parsed = urlparse(api_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise SearchConfigurationError("TAVILY_API_URL must be a valid HTTP or HTTPS URL.")

    try:
        default_limit = int(os.getenv("SEARCH_RESULT_LIMIT", "5"))
        timeout = float(os.getenv("SEARCH_TIMEOUT_SECONDS", "20"))
    except ValueError as exc:
        raise SearchConfigurationError(
            "SEARCH_RESULT_LIMIT and SEARCH_TIMEOUT_SECONDS must be numeric."
        ) from exc

    if not 1 <= default_limit <= 10:
        raise SearchConfigurationError("SEARCH_RESULT_LIMIT must be between 1 and 10.")
    if not math.isfinite(timeout) or timeout <= 0:
        raise SearchConfigurationError("SEARCH_TIMEOUT_SECONDS must be a positive finite number.")

    return api_key, api_url, default_limit, timeout


async def search_public_web(payload: SearchRequest) -> SearchResponse:
    api_key, api_url, default_limit, timeout = get_search_config()
    max_results = payload.max_results or default_limit

    body = {
        "api_key": api_key,
        "query": payload.query,
        "search_depth": os.getenv("TAVILY_SEARCH_DEPTH", "basic"),
        "max_results": max_results,
        "include_answer": False,
        "include_raw_content": False,
    }
    if payload.include_domains:
        body["include_domains"] = payload.include_domains
    if payload.exclude_domains:
        body["exclude_domains"] = payload.exclude_domains

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            response = await client.post(api_url, json=body)
    except httpx.TimeoutException as exc:
        raise SearchProviderError("The search provider timed out.") from exc
    except (httpx.RequestError, httpx.InvalidURL) as exc:
        raise SearchProviderError("Could not reach the search provider.") from exc

    if response.status_code == 401:
        raise SearchProviderError("The Tavily API key was rejected.", 401)
    if response.status_code == 429:
        raise SearchProviderError("The search provider rate limit was reached.", 429)
    if response.status_code >= 500:
        raise SearchProviderError(
            f"The search provider returned HTTP {response.status_code}.",
            response.status_code,
        )
    if not 200 <= response.status_code < 300:
        raise SearchProviderError(
            f"The search provider rejected the request with HTTP {response.status_code}.",
            response.status_code,
        )

    try:
        data = response.json()
    except ValueError as exc:
        raise SearchProviderError("The search provider returned invalid JSON.") from exc

    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise SearchProviderError("The search provider returned an invalid results payload.")

    results: list[SearchResult] = []
    for position, item in enumerate(data["results"][:max_results], start=1):
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "Untitled source").strip()
        url = str(item.get("url") or "").strip()
        snippet = str(item.get("content") or item.get("snippet") or "").strip()
        if not url:
            continue
        try:
            results.append(
                SearchResult(
                    title=title[:300],
                    url=url,
                    snippet=snippet[:2000],
                    metadata=SearchSourceMetadata(
                        score=item.get("score"),
                        published_date=item.get("published_date"),
                        position=item.get("position", position),
                    ),
                )
            )
        except ValidationError:
            continue

    if data["results"] and not results:
        raise SearchProviderError("The search provider returned no valid source records.")

    answer = data.get("answer")
    return SearchResponse(
        provider="tavily",
        query=payload.query,
        result_count=len(results),
        answer=str(answer).strip() if answer else None,
        results=results,
    )
