from __future__ import annotations

import os
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from approval import ApprovalService, execute_demo_submission
from browser import UnsafeUrlError, visit_public_page
from browser_providers import (
    AgentCoreBrowserProvider,
    AgentCoreConfig,
    BrowserProviderConfigurationError,
    BrowserProviderError,
    LocalPlaywrightProvider,
    browser_provider_status,
    create_browser_provider_from_env,
)
from main import health
from models import BrowserVisitRequest


def agentcore_env(**overrides: str) -> dict[str, str]:
    values = {
        "PROOFPILOT_BROWSER_PROVIDER": "agentcore",
        "PROOFPILOT_AWS_REGION": "us-west-2",
        "PROOFPILOT_AGENTCORE_BROWSER_ID": "aws.browser.v1",
        "PROOFPILOT_AGENTCORE_SESSION_TIMEOUT": "900",
    }
    values.update(overrides)
    return values


class BrowserProviderConfigurationTests(unittest.TestCase):
    def test_local_is_default_and_does_not_check_optional_aws_sdk(self):
        with patch("browser_providers.importlib.util.find_spec") as find_spec:
            provider = create_browser_provider_from_env({})

        self.assertIsInstance(provider, LocalPlaywrightProvider)
        find_spec.assert_not_called()

    def test_invalid_provider_fails_without_falling_back(self):
        with self.assertRaisesRegex(BrowserProviderConfigurationError, "must be either"):
            create_browser_provider_from_env({"PROOFPILOT_BROWSER_PROVIDER": "auto"})

    def test_agentcore_configuration_requires_explicit_region_browser_and_timeout(self):
        with self.assertRaisesRegex(BrowserProviderConfigurationError, "BROWSER_ID is required"):
            create_browser_provider_from_env({"PROOFPILOT_BROWSER_PROVIDER": "agentcore"})

        with self.assertRaisesRegex(BrowserProviderConfigurationError, "valid region"):
            create_browser_provider_from_env(
                agentcore_env(PROOFPILOT_AWS_REGION="bad region")
            )

        with self.assertRaisesRegex(BrowserProviderConfigurationError, "between 60 and 28800"):
            create_browser_provider_from_env(
                agentcore_env(PROOFPILOT_AGENTCORE_SESSION_TIMEOUT="30"),
                require_agentcore_sdk=False,
            )

        with self.assertRaisesRegex(BrowserProviderConfigurationError, "invalid format"):
            create_browser_provider_from_env(
                agentcore_env(PROOFPILOT_AGENTCORE_BROWSER_ID="bad/browser"),
                require_agentcore_sdk=False,
            )

    def test_agentcore_sdk_absence_is_an_explicit_startup_error(self):
        with patch("browser_providers._agentcore_sdk_available", return_value=False):
            with self.assertRaisesRegex(BrowserProviderConfigurationError, "optional SDK is missing"):
                create_browser_provider_from_env(agentcore_env())

    def test_provider_selection_is_deterministic_and_status_contains_no_secrets(self):
        with patch("browser_providers._agentcore_sdk_available", return_value=True):
            provider = create_browser_provider_from_env(agentcore_env())
        self.assertIsInstance(provider, AgentCoreBrowserProvider)

        secret_marker = "never-return-this-secret"
        with patch.dict(
            os.environ,
            {
                "AWS_ACCESS_KEY_ID": secret_marker,
                "AWS_SECRET_ACCESS_KEY": "never-return-this-secret-too",
            },
            clear=True,
        ):
            status = browser_provider_status(provider)
        self.assertEqual(status["provider"], "agentcore")
        self.assertEqual(status["status"], "configured_unchecked")
        self.assertIsNone(status["available"])
        self.assertEqual(status["region"], "us-west-2")
        self.assertTrue(status["credential_source_configured"])
        self.assertNotIn(secret_marker, repr(status))
        self.assertNotIn("never-return-this-secret-too", repr(status))
        self.assertNotIn("browser_id", status)
        self.assertFalse(status["supports_demo_actions"])
        self.assertEqual(provider.last_session_status, "not_started")


class BrowserProviderLifecycleTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.config = AgentCoreConfig(
            region="us-west-2",
            browser_id="configured-browser",
            session_timeout_seconds=900,
        )

    def make_agentcore_fakes(self, *, connect_error=None, close_error=None, stop_error=None):
        page = Mock(name="page")
        context = Mock(name="context")
        context.pages = [page]
        context.set_extra_http_headers = AsyncMock()
        browser = Mock(name="browser")
        browser.contexts = [context]
        browser.close = AsyncMock(side_effect=close_error)
        playwright = Mock(name="playwright")
        playwright.chromium.connect_over_cdp = AsyncMock(
            side_effect=connect_error,
            return_value=browser,
        )
        playwright.stop = AsyncMock()
        playwright_factory = Mock(return_value=Mock(start=AsyncMock(return_value=playwright)))

        client = Mock(name="agentcore_client")
        client.identifier = None
        client.session_id = None
        client.data_plane_client.start_browser_session.return_value = {
            "browserIdentifier": self.config.browser_id,
            "sessionId": "test-session-1",
        }
        client.generate_ws_headers.return_value = (
            "wss://agentcore.invalid/browser-streams/private-path",
            {"Authorization": "signed-header-must-not-leak"},
        )
        client.stop.side_effect = stop_error
        client_factory = Mock(return_value=client)
        provider = AgentCoreBrowserProvider(
            self.config,
            client_factory=client_factory,
            playwright_factory=playwright_factory,
        )
        return provider, client, playwright, browser, context, page

    async def test_agentcore_starts_connects_yields_context_and_stops_session(self):
        provider, client, playwright, browser, context, page = self.make_agentcore_fakes()

        async with provider.open_page(extra_http_headers={"x-test": "safe"}) as session:
            self.assertIs(session.page, page)
            self.assertIs(session.context, context)
            self.assertEqual(provider.last_session_status, "started")

        start_kwargs = client.data_plane_client.start_browser_session.call_args.kwargs
        self.assertEqual(start_kwargs["browserIdentifier"], "configured-browser")
        self.assertEqual(start_kwargs["sessionTimeoutSeconds"], 900)
        self.assertEqual(len(start_kwargs["clientToken"]), 43)
        playwright.chromium.connect_over_cdp.assert_awaited_once()
        connect_kwargs = playwright.chromium.connect_over_cdp.await_args.kwargs
        self.assertEqual(connect_kwargs["headers"]["Authorization"], "signed-header-must-not-leak")
        self.assertEqual(connect_kwargs["timeout"], self.config.connect_timeout_ms)
        context.set_extra_http_headers.assert_awaited_once_with({"x-test": "safe"})
        browser.close.assert_awaited_once()
        playwright.stop.assert_awaited_once()
        client.stop.assert_called_once()
        self.assertEqual(provider.last_session_status, "stopped")

    async def test_connection_failure_stops_the_created_remote_session_without_leaking_headers(self):
        provider, client, playwright, browser, _, _ = self.make_agentcore_fakes(
            connect_error=RuntimeError("signed-header-must-not-leak")
        )

        with self.assertRaises(BrowserProviderError) as raised:
            async with provider.open_page():
                self.fail("connection should not yield")

        self.assertIn("RuntimeError", str(raised.exception))
        self.assertNotIn("signed-header-must-not-leak", str(raised.exception))
        self.assertNotIn("private-path", str(raised.exception))
        self.assertEqual(provider.last_session_status, "failed")
        status = browser_provider_status(provider)
        self.assertIn("Playwright connection failed", status["error"])
        self.assertNotIn("signed-header-must-not-leak", repr(status))
        client.stop.assert_called_once()
        playwright.stop.assert_awaited_once()
        browser.close.assert_not_awaited()

    async def test_credential_signing_failure_stops_session_and_sanitizes_error(self):
        provider, client, playwright, _, _, _ = self.make_agentcore_fakes()
        client.generate_ws_headers.side_effect = RuntimeError("credential secret must not leak")

        with self.assertRaises(BrowserProviderError) as raised:
            async with provider.open_page():
                self.fail("credential failure should not yield")

        self.assertIn("CDP authentication failed", str(raised.exception))
        self.assertNotIn("credential secret must not leak", str(raised.exception))
        self.assertEqual(provider.last_session_status, "failed")
        client.stop.assert_called_once()
        playwright.stop.assert_not_awaited()

    async def test_remote_provider_cannot_bypass_private_ip_url_validation(self):
        provider, *_ = self.make_agentcore_fakes()
        payload = BrowserVisitRequest(url="http://127.0.0.1/private")

        with self.assertRaises(UnsafeUrlError):
            await visit_public_page(payload, provider)

        self.assertEqual(provider.last_session_status, "not_started")

    async def test_cleanup_errors_do_not_replace_the_original_operation_error(self):
        provider, client, playwright, browser, _, _ = self.make_agentcore_fakes(
            close_error=RuntimeError("close failure"),
            stop_error=RuntimeError("stop failure"),
        )

        with self.assertRaisesRegex(ValueError, "original navigation failure"):
            async with provider.open_page():
                raise ValueError("original navigation failure")

        self.assertEqual(provider.last_session_status, "cleanup_failed")
        browser.close.assert_awaited_once()
        playwright.stop.assert_awaited_once()
        client.stop.assert_called_once()

    async def test_local_provider_preserves_launch_options_and_cleans_up(self):
        page = Mock(name="page")
        context = Mock(name="context")
        context.new_page = AsyncMock(return_value=page)
        context.set_extra_http_headers = AsyncMock()
        browser = Mock(name="browser")
        browser.new_context = AsyncMock(return_value=context)
        browser.close = AsyncMock()
        playwright = Mock(name="playwright")
        playwright.chromium.launch = AsyncMock(return_value=browser)
        playwright.stop = AsyncMock()
        factory = Mock(return_value=Mock(start=AsyncMock(return_value=playwright)))
        provider = LocalPlaywrightProvider(playwright_factory=factory)

        async with provider.open_page(
            headless=False,
            locale="en-US",
            launch_args=["--host-resolver-rules=MAP example.com 93.184.216.34"],
        ) as session:
            self.assertIs(session.page, page)

        playwright.chromium.launch.assert_awaited_once_with(
            headless=False,
            args=["--host-resolver-rules=MAP example.com 93.184.216.34"],
        )
        browser.new_context.assert_awaited_once_with(
            locale="en-US", java_script_enabled=True, service_workers="block",
        )
        browser.close.assert_awaited_once()
        playwright.stop.assert_awaited_once()

    async def test_browser_executor_requires_policy_gate_before_any_session(self):
        provider, client, _, _, _, _ = self.make_agentcore_fakes()
        action = SimpleNamespace(target_url="http://127.0.0.1:8000/demo/laptop-selection")

        with self.assertRaisesRegex(PermissionError, "policy gate"):
            await execute_demo_submission(action, provider)
        client.data_plane_client.start_browser_session.assert_not_called()

    async def test_service_declines_remote_demo_action_before_contract_creation(self):
        provider, *_ = self.make_agentcore_fakes()
        service = ApprovalService(browser_provider=provider)

        with self.assertRaisesRegex(ValueError, "action is unavailable"):
            await service.prepare_action(None, None, None)

    async def test_health_reports_unchecked_remote_status_without_starting_a_session(self):
        provider, client, *_ = self.make_agentcore_fakes()
        request = SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace(browser_provider=provider))
        )

        response = await health(request)

        self.assertEqual(response["browser"], "configured_unchecked")
        self.assertEqual(response["browser_provider"]["status"], "configured_unchecked")
        self.assertIsNone(response["browser_provider"]["available"])
        client.data_plane_client.start_browser_session.assert_not_called()


if __name__ == "__main__":
    unittest.main()
