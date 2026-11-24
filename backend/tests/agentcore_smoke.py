"""Run an explicitly requested, non-consequential AgentCore Browser smoke test."""

from __future__ import annotations

import asyncio

from browser import visit_public_page
from browser_providers import (
    AgentCoreBrowserProvider,
    BrowserProviderConfigurationError,
    create_browser_provider_from_env,
)
from models import BrowserVisitRequest


async def run_smoke() -> None:
    try:
        provider = create_browser_provider_from_env()
    except BrowserProviderConfigurationError as exc:
        raise SystemExit(f"AgentCore smoke test configuration error: {exc}") from exc
    if not isinstance(provider, AgentCoreBrowserProvider):
        raise SystemExit("Set PROOFPILOT_BROWSER_PROVIDER=agentcore before running this test.")

    page = await visit_public_page(
        BrowserVisitRequest(
            url="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/what-is-bedrock-agentcore.html",
            allowed_domains=["docs.aws.amazon.com"],
            timeout_seconds=30,
            max_text_chars=2000,
        ),
        provider,
    )
    print(f"provider={provider.name}")
    print(f"title={page.title}")
    print(f"url={page.url}")
    print(f"http_status={page.status_code}")
    print(f"session_cleanup={provider.last_session_status}")
    if provider.last_session_status != "stopped":
        raise SystemExit("The AgentCore browser did not report successful session cleanup.")


if __name__ == "__main__":
    asyncio.run(run_smoke())
