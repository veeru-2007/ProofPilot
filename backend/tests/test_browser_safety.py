import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch

from browser import (
    BrowserVisitError,
    UnsafeUrlError,
    _blocked_reason,
    host_matches_allowed_domain,
    validate_public_url,
    visit_public_page,
)
from models import BrowserVisitRequest
from playwright.async_api import Error as PlaywrightError


class BrowserSafetyTests(unittest.TestCase):
    def test_rejects_localhost(self):
        with self.assertRaises(UnsafeUrlError):
            validate_public_url("http://localhost:8000")

    def test_rejects_loopback_ip(self):
        with self.assertRaises(UnsafeUrlError):
            validate_public_url("http://127.0.0.1:8000")

    def test_rejects_private_ip(self):
        with self.assertRaises(UnsafeUrlError):
            validate_public_url("http://192.168.1.10")

    def test_rejects_credentials_and_nonstandard_port(self):
        with self.assertRaises(UnsafeUrlError):
            validate_public_url("https://user:pass@example.com")
        with self.assertRaises(UnsafeUrlError):
            validate_public_url("https://example.com:8443")

    def test_accepts_exact_allowed_domain_and_true_subdomains(self):
        with patch("browser.resolve_public_addresses", return_value=["93.184.216.34"]):
            self.assertEqual(
                validate_public_url("https://example.com", ["example.com"]),
                "https://example.com",
            )
            self.assertEqual(
                validate_public_url("https://shop.example.com", ["example.com"]),
                "https://shop.example.com",
            )

        self.assertTrue(host_matches_allowed_domain("store.example.com", ["example.com"]))

    def test_rejects_suffix_attack_and_invalid_urls(self):
        with patch("browser.resolve_public_addresses") as resolver:
            with self.assertRaises(UnsafeUrlError):
                validate_public_url("https://example.com.evil.com", ["example.com"])
            resolver.assert_not_called()

        with self.assertRaises(UnsafeUrlError):
            validate_public_url("file://example.com/path")
        with self.assertRaises(UnsafeUrlError):
            validate_public_url("https://example.com:not-a-port")

    def test_non_success_page_is_flagged_even_without_protection_markers(self):
        self.assertEqual(_blocked_reason(503, "Error", "Temporarily unavailable"), "The webpage returned HTTP 503")


class BrowserRedirectSafetyTests(unittest.IsolatedAsyncioTestCase):
    async def test_visit_deadline_cancels_work_before_a_navigation_response(self):
        cleanup = asyncio.Event()

        async def pending_visit(*args):
            try:
                await asyncio.Future()
            finally:
                cleanup.set()

        request = BrowserVisitRequest(url="https://example.com").model_copy(update={"timeout_seconds": 0.01})
        with patch("browser._visit_public_page", side_effect=pending_visit), self.assertRaisesRegex(
            BrowserVisitError, "time limit",
        ):
            await visit_public_page(request)
        self.assertTrue(cleanup.is_set())

    async def test_dom_text_reads_are_bounded_and_extraction_is_truncated(self):
        playwright = Mock()
        playwright.chromium.launch = AsyncMock()
        browser_instance = Mock()
        browser_instance.new_context = AsyncMock()
        browser_instance.close = AsyncMock()
        playwright.chromium.launch.return_value = browser_instance
        context = Mock()
        context.route = AsyncMock()
        context.new_page = AsyncMock()
        browser_instance.new_context.return_value = context

        page = Mock()
        page.url = "https://example.com/products"
        page.main_frame = object()
        response = Mock(status=200)
        write_route = Mock()
        write_route.request = Mock(
            url="https://example.com/products", method="POST", resource_type="fetch",
        )
        write_route.abort = AsyncMock()
        write_route.continue_ = AsyncMock()

        async def goto(*args, **kwargs):
            await context.route.await_args.args[1](write_route)
            return response

        page.goto = AsyncMock(side_effect=goto)
        page.title = AsyncMock(return_value="Example products")
        headings = Mock()
        headings.evaluate_all = AsyncMock(return_value=["H" * 400])
        body = Mock()
        body.evaluate = AsyncMock(return_value="B" * 1001)
        page.locator = Mock(side_effect=lambda selector: headings if selector == "h1, h2, h3" else body)
        context.new_page.return_value = page
        playwright.stop = AsyncMock()

        with (
            patch("browser.async_playwright", return_value=Mock(start=AsyncMock(return_value=playwright))),
            patch("browser.resolve_public_addresses", return_value=["93.184.216.34"]),
        ):
            result = await visit_public_page(
                BrowserVisitRequest(
                    url="https://example.com/products",
                    allowed_domains=["example.com"],
                    max_text_chars=1000,
                )
            )

        headings.evaluate_all.assert_awaited_once()
        self.assertEqual(headings.evaluate_all.await_args.args[1], 300)
        body.evaluate.assert_awaited_once()
        self.assertEqual(body.evaluate.await_args.args[1], 1000)
        self.assertLessEqual(len(result.headings[0]), 300)
        self.assertTrue(result.visible_text.endswith("... [truncated]"))
        self.assertLessEqual(len(result.visible_text), 1000)
        write_route.abort.assert_awaited_once()
        write_route.continue_.assert_not_awaited()
        browser_instance.close.assert_awaited_once()
        playwright.stop.assert_awaited_once()

    async def test_redirect_outside_allowed_domain_is_aborted(self):
        playwright = Mock()
        playwright.chromium.launch = AsyncMock()
        browser_instance = Mock()
        browser_instance.new_context = AsyncMock()
        browser_instance.close = AsyncMock(side_effect=RuntimeError("cleanup failed"))
        playwright.chromium.launch.return_value = browser_instance
        context = Mock()
        context.route = AsyncMock()
        context.new_page = AsyncMock()
        browser_instance.new_context.return_value = context
        page = Mock()
        page.main_frame = object()
        context.new_page.return_value = page

        request = Mock()
        request.url = "https://example.com.evil.com/redirect"
        request.resource_type = "document"
        request.is_navigation_request.return_value = True
        request.frame = page.main_frame
        route = Mock()
        route.request = request
        route.abort = AsyncMock()
        route.continue_ = AsyncMock()

        async def goto(*args, **kwargs):
            route_handler = context.route.await_args.args[1]
            await route_handler(route)
            raise PlaywrightError("navigation aborted")

        page.goto = AsyncMock(side_effect=goto)
        page.title = AsyncMock(return_value="Example")
        page.locator = Mock()
        page.locator.return_value.all_inner_texts = AsyncMock(return_value=[])
        page.locator.return_value.inner_text = AsyncMock(return_value="")
        playwright.stop = AsyncMock()

        with (
            patch("browser.async_playwright", return_value=Mock(start=AsyncMock(return_value=playwright))),
            patch("browser.resolve_public_addresses", return_value=["93.184.216.34"]),
        ):
            with self.assertRaises(UnsafeUrlError) as raised:
                await visit_public_page(
                    BrowserVisitRequest(
                        url="https://example.com/start",
                        allowed_domains=["example.com"],
                    )
                )

        self.assertEqual(raised.exception.rejected_domain, "example.com.evil.com")
        route.abort.assert_awaited_once()
        route.continue_.assert_not_awaited()
        browser_instance.close.assert_awaited_once()
        playwright.stop.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()


if __name__ == "__main__":
    unittest.main()
