"""Browser lifecycle providers used by ProofPilot's controlled workflows.

Providers own browser connections only. URL policy, proof contracts, action
authorization, approvals, idempotency, and verification stay in their callers.
"""

from __future__ import annotations

import asyncio
import importlib.util
import logging
import os
import re
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Mapping, Protocol

from playwright.async_api import async_playwright


logger = logging.getLogger(__name__)


class BrowserProviderConfigurationError(ValueError):
    """Raised when the explicitly selected browser provider is misconfigured."""


class BrowserProviderError(RuntimeError):
    """Raised when a configured browser provider cannot establish a session."""


@dataclass(frozen=True)
class AgentCoreConfig:
    region: str
    browser_id: str
    session_timeout_seconds: int = 900
    request_timeout_seconds: int = 20
    connect_timeout_ms: int = 20_000


@dataclass
class BrowserPageSession:
    context: Any
    page: Any


class BrowserProvider(Protocol):
    name: str
    is_remote: bool
    supports_demo_actions: bool

    def open_page(
        self,
        *,
        headless: bool = True,
        locale: str = "en-US",
        launch_args: list[str] | None = None,
        extra_http_headers: dict[str, str] | None = None,
    ) -> Any: ...


class LocalPlaywrightProvider:
    name = "local"
    is_remote = False
    supports_demo_actions = True

    def __init__(self, playwright_factory: Callable[[], Any] | None = None) -> None:
        # A factory keeps unit tests able to mock the existing Playwright seam.
        self._playwright_factory = playwright_factory or async_playwright

    @asynccontextmanager
    async def open_page(
        self,
        *,
        headless: bool = True,
        locale: str = "en-US",
        launch_args: list[str] | None = None,
        extra_http_headers: dict[str, str] | None = None,
    ) -> AsyncIterator[BrowserPageSession]:
        playwright = None
        browser = None
        try:
            playwright = await self._playwright_factory().start()
            browser = await playwright.chromium.launch(
                headless=headless,
                args=launch_args or [],
            )
            context = await browser.new_context(
                locale=locale,
                java_script_enabled=True,
                service_workers="block",
            )
            if extra_http_headers:
                await context.set_extra_http_headers(extra_http_headers)
            page = await context.new_page()
            yield BrowserPageSession(context=context, page=page)
        finally:
            if browser is not None:
                try:
                    await browser.close()
                except BaseException:
                    pass
            if playwright is not None:
                try:
                    await playwright.stop()
                except BaseException:
                    pass


def _agentcore_sdk_available() -> bool:
    if not all(
        importlib.util.find_spec(module_name) is not None
        for module_name in ("bedrock_agentcore", "boto3", "botocore")
    ):
        return False
    try:
        from bedrock_agentcore.tools.browser_client import BrowserClient

        return callable(BrowserClient)
    except Exception:
        return False


def _resolve_profile_region() -> str | None:
    try:
        import boto3

        return boto3.Session().region_name
    except Exception:
        return None


def _credential_source_configured(env: Mapping[str, str]) -> bool:
    if (
        env.get("AWS_ACCESS_KEY_ID", "").strip()
        and env.get("AWS_SECRET_ACCESS_KEY", "").strip()
    ):
        return True
    environment_sources = (
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
    )
    if any(env.get(name, "").strip() for name in environment_sources):
        return True
    if env.get("AWS_WEB_IDENTITY_TOKEN_FILE", "").strip() and env.get("AWS_ROLE_ARN", "").strip():
        return True

    configured_paths = (
        env.get("AWS_SHARED_CREDENTIALS_FILE"),
        env.get("AWS_CONFIG_FILE"),
        str(Path.home() / ".aws" / "credentials"),
        str(Path.home() / ".aws" / "config"),
    )
    return any(path and Path(path).expanduser().is_file() for path in configured_paths)


def _load_agentcore_client(config: AgentCoreConfig) -> Any:
    """Build the official AgentCore BrowserClient with bounded data-plane I/O."""
    try:
        import boto3
        from bedrock_agentcore.tools.browser_client import BrowserClient
        from botocore.config import Config
    except ImportError as exc:
        raise BrowserProviderConfigurationError(
            "AgentCore was selected, but its optional SDK is missing. Install backend/requirements-agentcore.txt."
        ) from exc

    sdk_client = BrowserClient(region=config.region)
    session = boto3.Session()
    sdk_client.data_plane_client = session.client(
        "bedrock-agentcore",
        region_name=config.region,
        config=Config(
            connect_timeout=5,
            read_timeout=config.request_timeout_seconds,
            retries={"total_max_attempts": 1},
        ),
    )
    return sdk_client


class AgentCoreBrowserProvider:
    name = "agentcore"
    is_remote = True
    # ProofPilot's demo action points to this backend's loopback server, which a
    # managed browser cannot reach. Never switch that action back to local Chrome.
    supports_demo_actions = False

    def __init__(
        self,
        config: AgentCoreConfig,
        *,
        client_factory: Callable[[AgentCoreConfig], Any] | None = None,
        playwright_factory: Callable[[], Any] | None = None,
    ) -> None:
        self.config = config
        self._client_factory = client_factory or _load_agentcore_client
        self._playwright_factory = playwright_factory or async_playwright
        self._last_session_status = "not_started"
        self._last_session_error: str | None = None

    @property
    def last_session_status(self) -> str:
        return self._last_session_status

    @property
    def last_session_error(self) -> str | None:
        return self._last_session_error

    @asynccontextmanager
    async def open_page(
        self,
        *,
        headless: bool = True,
        locale: str = "en-US",
        launch_args: list[str] | None = None,
        extra_http_headers: dict[str, str] | None = None,
    ) -> AsyncIterator[BrowserPageSession]:
        del headless, locale, launch_args  # The managed browser owns these settings.
        client = None
        session_started = False
        playwright = None
        browser = None
        setup_phase = "initialization"
        self._last_session_status = "starting"
        self._last_session_error = None

        try:
            client = await asyncio.to_thread(self._client_factory, self.config)
            client_token = f"proofpilot-{uuid.uuid4().hex}"
            setup_phase = "session start"
            start_task = asyncio.create_task(
                asyncio.to_thread(
                    client.data_plane_client.start_browser_session,
                    browserIdentifier=self.config.browser_id,
                    name=f"proofpilot-{uuid.uuid4().hex[:12]}",
                    sessionTimeoutSeconds=self.config.session_timeout_seconds,
                    clientToken=client_token,
                )
            )
            try:
                response = await asyncio.shield(start_task)
            except asyncio.CancelledError:
                # Wait for a possibly in-flight start request so a successful
                # response can still be recorded and stopped in the outer
                # cancellation cleanup path.
                try:
                    response = await start_task
                except Exception:
                    response = None
                if response and response.get("sessionId"):
                    client.identifier = response.get("browserIdentifier", self.config.browser_id)
                    client.session_id = response["sessionId"]
                    session_started = True
                raise
            session_id = response.get("sessionId")
            if not session_id:
                raise RuntimeError("AgentCore did not return a session ID")
            client.identifier = response.get("browserIdentifier", self.config.browser_id)
            client.session_id = session_id
            session_started = True
            self._last_session_status = "started"

            setup_phase = "CDP authentication"
            ws_url, headers = await asyncio.to_thread(client.generate_ws_headers)

            setup_phase = "Playwright connection"
            playwright = await self._playwright_factory().start()
            browser = await playwright.chromium.connect_over_cdp(
                ws_url,
                headers=headers,
                timeout=self.config.connect_timeout_ms,
            )
            if not browser.contexts:
                raise RuntimeError("The managed browser did not expose a context")
            context = browser.contexts[0]
            if extra_http_headers:
                await context.set_extra_http_headers(extra_http_headers)
            page = context.pages[0] if context.pages else await context.new_page()
        except BrowserProviderConfigurationError as exc:
            self._last_session_status = "failed"
            self._last_session_error = str(exc)
            cleanup_ok = await self._cleanup(client, browser, playwright, session_started)
            if not cleanup_ok:
                self._last_session_status = "cleanup_failed"
                self._last_session_error = (
                    "AgentCore provider setup failed and cleanup failed; the session may remain until its timeout."
                )
            raise
        except asyncio.CancelledError:
            self._last_session_status = "failed"
            self._last_session_error = "AgentCore browser session setup was cancelled."
            cleanup_ok = await self._cleanup(client, browser, playwright, session_started)
            if not cleanup_ok:
                self._last_session_status = "cleanup_failed"
                self._last_session_error = (
                    "AgentCore browser session setup was cancelled and cleanup failed; the session may remain until its timeout."
                )
            raise
        except Exception as exc:
            self._last_session_status = "failed"
            cleanup_ok = await self._cleanup(client, browser, playwright, session_started)
            # Avoid relaying SDK exceptions, connection URLs, or authentication
            # material to API responses and application logs.
            error_message = (
                f"AWS managed browser {setup_phase} failed ({type(exc).__name__})."
            )
            self._last_session_error = (
                f"{error_message} Cleanup also failed; the session may remain until its timeout."
                if not cleanup_ok
                else error_message
            )
            if not cleanup_ok:
                self._last_session_status = "cleanup_failed"
            raise BrowserProviderError(error_message) from None

        outcome = "stopped"
        try:
            yield BrowserPageSession(context=context, page=page)
        except BaseException as exc:
            outcome = "failed"
            self._last_session_error = f"Remote browser operation failed ({type(exc).__name__})."
            raise
        finally:
            cleanup_ok = await self._cleanup(client, browser, playwright, session_started)
            self._last_session_status = outcome if cleanup_ok else "cleanup_failed"
            if not cleanup_ok:
                self._last_session_error = (
                    self._last_session_error
                    or "AgentCore browser cleanup failed; the session may remain until its timeout."
                )

    async def _cleanup(
        self,
        client: Any,
        browser: Any,
        playwright: Any,
        session_started: bool,
    ) -> bool:
        cleanup_ok = True
        if browser is not None:
            try:
                await browser.close()
            except BaseException as exc:
                cleanup_ok = False
                logger.warning("AgentCore browser connection close failed (%s).", type(exc).__name__)
        if playwright is not None:
            try:
                await playwright.stop()
            except BaseException as exc:
                cleanup_ok = False
                logger.warning("Playwright cleanup failed (%s).", type(exc).__name__)
        if client is not None and session_started:
            try:
                await asyncio.shield(asyncio.to_thread(client.stop))
            except BaseException as exc:
                cleanup_ok = False
                logger.warning("AgentCore browser session stop failed (%s).", type(exc).__name__)
        return cleanup_ok


def create_browser_provider_from_env(
    env: Mapping[str, str] | None = None,
    *,
    require_agentcore_sdk: bool = True,
) -> BrowserProvider:
    values = os.environ if env is None else env
    selected = values.get("PROOFPILOT_BROWSER_PROVIDER", "local").strip().lower()
    if selected == "local":
        return LocalPlaywrightProvider()
    if selected != "agentcore":
        raise BrowserProviderConfigurationError(
            "PROOFPILOT_BROWSER_PROVIDER must be either 'local' or 'agentcore'."
        )

    browser_id = values.get("PROOFPILOT_AGENTCORE_BROWSER_ID", "").strip()
    if not browser_id:
        raise BrowserProviderConfigurationError(
            "PROOFPILOT_AGENTCORE_BROWSER_ID is required when AgentCore is selected."
        )
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", browser_id):
        raise BrowserProviderConfigurationError(
            "PROOFPILOT_AGENTCORE_BROWSER_ID has an invalid format."
        )

    raw_timeout = values.get("PROOFPILOT_AGENTCORE_SESSION_TIMEOUT", "900").strip()
    try:
        session_timeout = int(raw_timeout)
    except ValueError as exc:
        raise BrowserProviderConfigurationError(
            "PROOFPILOT_AGENTCORE_SESSION_TIMEOUT must be an integer from 60 to 28800 seconds."
        ) from exc
    if not 60 <= session_timeout <= 28_800:
        raise BrowserProviderConfigurationError(
            "PROOFPILOT_AGENTCORE_SESSION_TIMEOUT must be between 60 and 28800 seconds."
        )

    region = (
        values.get("PROOFPILOT_AWS_REGION", "").strip()
        or values.get("AWS_REGION", "").strip()
        or values.get("AWS_DEFAULT_REGION", "").strip()
    )
    if not region:
        region = _resolve_profile_region() or ""
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*-[0-9]+", region):
        raise BrowserProviderConfigurationError(
            "Set PROOFPILOT_AWS_REGION or configure an AWS profile with a valid region."
        )
    if require_agentcore_sdk and not _agentcore_sdk_available():
        raise BrowserProviderConfigurationError(
            "AgentCore was selected, but its optional SDK is missing. Install backend/requirements-agentcore.txt."
        )

    config = AgentCoreConfig(
        region=region,
        browser_id=browser_id,
        session_timeout_seconds=session_timeout,
    )
    return AgentCoreBrowserProvider(config)


def browser_provider_status(provider: BrowserProvider) -> dict[str, Any]:
    if isinstance(provider, AgentCoreBrowserProvider):
        return {
            "provider": provider.name,
            "label": "AWS managed browser",
            "configuration_valid": True,
            "available": None,
            "status": "configured_unchecked",
            "session_status": provider.last_session_status,
            "region": provider.config.region,
            "browser_id_configured": bool(provider.config.browser_id),
            "credential_source_configured": _credential_source_configured(os.environ),
            "integration_available": True,
            "supports_demo_actions": False,
            "error": provider.last_session_error,
        }
    return {
        "provider": provider.name,
        "label": "Local Playwright",
        "configuration_valid": True,
        "available": True,
        "status": "ready",
        "session_status": "not_started",
        "region": None,
        "browser_id_configured": False,
        "credential_source_configured": False,
        "integration_available": True,
        "supports_demo_actions": True,
        "error": None,
    }
