import asyncio
import ipaddress
import os
import socket
from urllib.parse import urlparse

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright

from browser_providers import (
    BrowserProvider,
    BrowserProviderError,
    LocalPlaywrightProvider,
)
from models import BrowserPageResponse, BrowserVisitRequest


class UnsafeUrlError(ValueError):
    def __init__(self, message: str, rejected_domain: str | None = None) -> None:
        super().__init__(message)
        self.rejected_domain = rejected_domain


class BrowserVisitError(RuntimeError):
    pass


def _is_disallowed_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True
    return not ip.is_global


def resolve_public_addresses(hostname: str, port: int) -> list[str]:
    try:
        addresses = sorted({
            item[4][0]
            for item in socket.getaddrinfo(
                hostname,
                port,
                type=socket.SOCK_STREAM,
            )
        })
    except socket.gaierror as exc:
        raise UnsafeUrlError(
            f"The hostname could not be resolved safely: {exc}"
        ) from exc
    if not addresses:
        raise UnsafeUrlError("The hostname did not resolve to an address.")
    unsafe_addresses = [address for address in addresses if _is_disallowed_ip(address)]
    if unsafe_addresses:
        raise UnsafeUrlError("The hostname resolves to a private or unsafe address.")
    return addresses


def host_matches_allowed_domain(hostname: str, allowed_domains: list[str] | tuple[str, ...]) -> bool:
    normalized_host = hostname.strip().lower().rstrip(".")
    try:
        normalized_host = normalized_host.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    normalized_domains = []
    for domain in allowed_domains:
        try:
            normalized_domains.append(domain.strip().lower().rstrip(".").encode("idna").decode("ascii"))
        except UnicodeError:
            continue
    return any(
        normalized_host == domain or normalized_host.endswith(f".{domain}")
        for domain in normalized_domains
    )


def is_domain_allowed_url(raw_url: str, allowed_domains: list[str] | tuple[str, ...]) -> bool:
    if not allowed_domains:
        return True
    hostname = urlparse(raw_url).hostname or ""
    return host_matches_allowed_domain(hostname, allowed_domains)


def validate_public_url(
    raw_url: str,
    allowed_domains: list[str] | tuple[str, ...] | None = None,
) -> str:
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"}:
        raise UnsafeUrlError("Only HTTP and HTTPS public webpages are allowed.")
    if parsed.username or parsed.password:
        raise UnsafeUrlError("URLs containing credentials are not allowed.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise UnsafeUrlError("The URL contains an invalid port.") from exc
    if port not in {None, 80, 443}:
        raise UnsafeUrlError("Only standard HTTP and HTTPS ports are allowed.")

    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname:
        raise UnsafeUrlError("A valid hostname is required.")
    if (
        hostname == "localhost"
        or hostname.endswith(".localhost")
        or hostname.endswith(".local")
        or hostname.endswith(".internal")
        or hostname.endswith(".home")
    ):
        raise UnsafeUrlError("Localhost and internal hostnames are not allowed.")

    try:
        parsed_ip = ipaddress.ip_address(hostname)
    except ValueError:
        parsed_ip = None

    if parsed_ip is not None:
        if _is_disallowed_ip(str(parsed_ip)):
            raise UnsafeUrlError("Private, local, reserved, or otherwise unsafe IP addresses are blocked.")
        if allowed_domains:
            raise UnsafeUrlError(
                "IP-literal destinations are not permitted by this domain-restricted contract.",
                rejected_domain=hostname,
            )
        return raw_url

    if allowed_domains and not host_matches_allowed_domain(hostname, allowed_domains):
        raise UnsafeUrlError(
            f"The host '{hostname}' is outside the contract's allowed domains.",
            rejected_domain=hostname,
        )

    resolve_public_addresses(
        hostname,
        port or (443 if parsed.scheme == "https" else 80),
    )
    return raw_url


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    marker = "... [truncated]"
    if limit <= len(marker):
        return marker[:limit]
    return text[:limit - len(marker)].rstrip() + marker


def _clean_lines(text: str) -> list[str]:
    lines = []
    seen = set()
    for raw_line in text.replace("\r", "\n").split("\n"):
        line = " ".join(raw_line.split())
        if len(line) < 20 or line in seen:
            continue
        seen.add(line)
        lines.append(line)
    return lines


def _blocked_reason(status_code: int | None, title: str, text: str) -> str | None:
    if status_code in {401, 403}:
        return "Authentication or access restriction detected"
    if status_code == 429:
        return "Rate limit or automated-access restriction detected"
    if status_code is None:
        return "Navigation did not return an HTTP response"
    if not 200 <= status_code < 300:
        return f"The webpage returned HTTP {status_code}"

    combined = f"{title}\n{text}".lower()
    markers = (
        "captcha",
        "verify you are human",
        "please enable javascript",
        "sign in to continue",
        "log in to continue",
        "unusual traffic",
        "access denied",
    )
    for marker in markers:
        if marker in combined:
            return f"Protected-page marker detected: {marker}"
    return None


async def visit_public_page(
    payload: BrowserVisitRequest,
    provider: BrowserProvider | None = None,
) -> BrowserPageResponse:
    try:
        async with asyncio.timeout(payload.timeout_seconds):
            return await _visit_public_page(payload, provider)
    except TimeoutError as exc:
        raise BrowserVisitError("The browser visit exceeded its time limit.") from exc


async def _visit_public_page(
    payload: BrowserVisitRequest,
    provider: BrowserProvider | None,
) -> BrowserPageResponse:
    url = str(payload.url)
    await asyncio.to_thread(validate_public_url, url, payload.allowed_domains)

    browser_provider = provider or LocalPlaywrightProvider(playwright_factory=async_playwright)
    headless = os.getenv("PLAYWRIGHT_HEADLESS", "true").lower() != "false"

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        resolved_addresses = await asyncio.to_thread(resolve_public_addresses, hostname, port)
        launch_args = []
        if resolved_addresses:
            launch_args.append(
                f"--host-resolver-rules=MAP {hostname} {resolved_addresses[0]}"
            )
        async with browser_provider.open_page(
            headless=headless,
            locale=os.getenv("PLAYWRIGHT_LOCALE", "en-US"),
            launch_args=launch_args,
        ) as browser_session:
            context = browser_session.context
            page = browser_session.page
            rejected_domains: set[str] = set()
            blocked_main_frame_navigations: list[UnsafeUrlError] = []

            async def block_resources(route):
                resource_type = route.request.resource_type
                request_url = route.request.url
                try:
                    await asyncio.to_thread(validate_public_url, request_url, payload.allowed_domains)
                except UnsafeUrlError as exc:
                    if exc.rejected_domain:
                        rejected_domains.add(exc.rejected_domain)
                    try:
                        if route.request.is_navigation_request() and route.request.frame == page.main_frame:
                            blocked_main_frame_navigations.append(exc)
                    except PlaywrightError:
                        pass
                    await route.abort()
                    return
                if route.request.method not in {"GET", "HEAD", "OPTIONS"}:
                    await route.abort()
                    return
                if resource_type in {"image", "media", "font"}:
                    await route.abort()
                    return
                await route.continue_()

            await context.route("**/*", block_resources)

            try:
                response = await page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=payload.timeout_seconds * 1000,
                )
            except PlaywrightTimeoutError as exc:
                raise BrowserVisitError("The webpage did not finish loading before the timeout.") from exc
            except PlaywrightError as exc:
                if blocked_main_frame_navigations:
                    raise blocked_main_frame_navigations[0] from exc
                raise BrowserVisitError("The browser could not visit the webpage.") from exc

            if blocked_main_frame_navigations:
                raise blocked_main_frame_navigations[0]

            final_url = page.url
            await asyncio.to_thread(validate_public_url, final_url, payload.allowed_domains)

            status_code = response.status if response is not None else None
            title = _truncate(await page.title(), 500) or "Untitled webpage"
            headings = await page.locator("h1, h2, h3").evaluate_all(
                "(elements, limit) => elements.slice(0, 40).map((element) => "
                "(element.innerText || '').slice(0, limit))",
                300,
            )
            headings = [
                _truncate(" ".join(heading.split()), 300)
                for heading in headings
                if heading.strip()
            ]

            visible_text = await page.locator("body").evaluate(
                "(element, limit) => (element.innerText || '').slice(0, limit + 1)",
                payload.max_text_chars,
            )
            visible_text = _truncate(" ".join(visible_text.split()), payload.max_text_chars)

            relevant_content: list[str] = []
            if payload.query:
                keywords = [word.lower() for word in payload.query.split() if len(word) >= 4]
                for line in _clean_lines(visible_text):
                    score = sum(1 for keyword in keywords if keyword in line.lower())
                    if score:
                        relevant_content.append(line)
                        if len(relevant_content) >= 20:
                            break

            if not relevant_content:
                relevant_content = _clean_lines(visible_text)[:20]

            blocked_reason = _blocked_reason(status_code, title, visible_text)
            return BrowserPageResponse(
                title=title,
                url=final_url,
                status_code=status_code,
                headings=headings,
                visible_text=visible_text,
                relevant_content=relevant_content,
                blocked_reason=blocked_reason,
                rejected_domains=sorted(rejected_domains),
            )
    except BrowserProviderError as exc:
        raise BrowserVisitError(str(exc)) from exc
    except UnsafeUrlError:
        raise
    except BrowserVisitError:
        raise
    except PlaywrightError as exc:
        raise BrowserVisitError(f"Playwright browser automation failed ({type(exc).__name__}).") from exc
