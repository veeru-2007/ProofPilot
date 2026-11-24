"""Bounded, provider-independent controls for public research recovery."""

import asyncio
import os
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from models import (
    ProofContract,
    Requirement,
    RequirementEvaluationStatus,
    SourceFailureCategory,
)
from requirement_engine import evaluate_requirements


_SENSITIVE_QUERY_KEY = re.compile(
    r"(?:token|secret|auth|credential|password|session|signature|api[_-]?key|access[_-]?key|oauth|csrf|nonce|jwt|^code$|^state$|^sig$)",
    re.IGNORECASE,
)
_TRACKING_QUERY_KEY = re.compile(r"^(?:utm_.+|gclid|fbclid|dclid|msclkid|ref|ref_src)$", re.IGNORECASE)


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


@dataclass(frozen=True)
class ResearchResiliencePolicy:
    max_source_attempts: int = 8
    max_attempts_per_source: int = 2
    max_recovery_operations: int = 3
    retry_delay_seconds: float = 0.25

    @classmethod
    def from_environment(cls) -> "ResearchResiliencePolicy":
        try:
            delay = float(os.getenv("RESEARCH_RETRY_DELAY_SECONDS", "0.25"))
        except (TypeError, ValueError):
            delay = 0.25
        if not 0 <= delay <= 2:
            delay = 0.25
        return cls(
            max_source_attempts=_bounded_int("RESEARCH_MAX_SOURCE_ATTEMPTS", 8, 1, 20),
            max_attempts_per_source=_bounded_int("RESEARCH_MAX_ATTEMPTS_PER_SOURCE", 2, 1, 3),
            max_recovery_operations=_bounded_int("RESEARCH_MAX_RECOVERY_OPERATIONS", 3, 0, 8),
            retry_delay_seconds=delay,
        )

    def retry_eligible(self, category: SourceFailureCategory, attempt_number: int) -> bool:
        return (
            attempt_number < self.max_attempts_per_source
            and category in {
                SourceFailureCategory.RATE_LIMITED,
                SourceFailureCategory.TIMEOUT,
                SourceFailureCategory.NETWORK_ERROR,
            }
        )

    async def wait_before_retry(self, attempt_number: int) -> None:
        if self.retry_delay_seconds:
            await asyncio.sleep(min(2.0, self.retry_delay_seconds * (2 ** max(0, attempt_number - 1))))


def classify_source_failure(
    *,
    status_code: int | None = None,
    error: object = "",
    exception: BaseException | None = None,
    extraction_failed: bool = False,
    invalid_content: bool = False,
) -> SourceFailureCategory:
    if extraction_failed:
        return SourceFailureCategory.EXTRACTION_FAILED
    if status_code == 401:
        return SourceFailureCategory.AUTH_REQUIRED
    if status_code == 403:
        return SourceFailureCategory.ACCESS_DENIED
    if status_code == 429:
        return SourceFailureCategory.RATE_LIMITED
    if status_code in {404, 410}:
        return SourceFailureCategory.CONTENT_UNAVAILABLE
    if status_code in {408, 504}:
        return SourceFailureCategory.TIMEOUT
    if status_code is not None and status_code >= 500:
        return SourceFailureCategory.NETWORK_ERROR

    message = str(error or exception or "").casefold()
    if isinstance(exception, (TimeoutError, asyncio.TimeoutError, httpx.TimeoutException)) or any(
        token in message for token in ("timed out", "timeout", "time limit")
    ):
        return SourceFailureCategory.TIMEOUT
    if any(token in message for token in ("access denied", "access restriction", "forbidden", "denied access")):
        return SourceFailureCategory.ACCESS_DENIED
    if any(token in message for token in (
        "authentication", "login required", "login page", "sign in to continue", "sign-in required",
    )):
        return SourceFailureCategory.AUTH_REQUIRED
    if any(token in message for token in (
        "robot", "captcha", "anti-bot", "anti bot", "robots.txt", "protected-page", "protected page",
        "crawling restriction", "automated access is not allowed",
    )):
        return SourceFailureCategory.ROBOTS_OR_RESTRICTION
    if isinstance(exception, httpx.RequestError) or any(
        token in message for token in ("network error", "could not reach", "connection refused", "name resolution")
    ):
        return SourceFailureCategory.NETWORK_ERROR
    if invalid_content:
        return SourceFailureCategory.INVALID_CONTENT
    if status_code is not None and not 200 <= status_code < 300:
        return SourceFailureCategory.CONTENT_UNAVAILABLE
    return SourceFailureCategory.UNKNOWN_FAILURE


def safe_failure_description(
    category: SourceFailureCategory, status_code: int | None = None
) -> str:
    descriptions = {
        SourceFailureCategory.ACCESS_DENIED: "The source denied access. ProofPilot will not bypass or repeatedly retry this restriction.",
        SourceFailureCategory.AUTH_REQUIRED: "The source requires authentication. ProofPilot will continue only with public alternatives.",
        SourceFailureCategory.RATE_LIMITED: "The source rate-limited the request; a bounded retry may be attempted.",
        SourceFailureCategory.TIMEOUT: "The source did not respond before the visit timed out.",
        SourceFailureCategory.NETWORK_ERROR: "A temporary network or source-server error prevented retrieval.",
        SourceFailureCategory.CONTENT_UNAVAILABLE: "The source content is unavailable.",
        SourceFailureCategory.EXTRACTION_FAILED: "The page was accessible, but evidence extraction failed.",
        SourceFailureCategory.INVALID_CONTENT: "The source returned content that could not be validated.",
        SourceFailureCategory.ROBOTS_OR_RESTRICTION: "The source indicates an access or crawling restriction. ProofPilot will not bypass it.",
        SourceFailureCategory.UNKNOWN_FAILURE: "The source could not be processed; its details are unavailable.",
        SourceFailureCategory.SUCCESS: "",
    }
    description = descriptions[category]
    if status_code and category not in {SourceFailureCategory.SUCCESS}:
        return f"{description} (HTTP {status_code})"
    return description


def coarse_failure_type(category: SourceFailureCategory) -> str:
    if category in {
        SourceFailureCategory.ACCESS_DENIED,
        SourceFailureCategory.AUTH_REQUIRED,
        SourceFailureCategory.ROBOTS_OR_RESTRICTION,
    }:
        return "blocked"
    if category == SourceFailureCategory.TIMEOUT:
        return "timeout"
    if category == SourceFailureCategory.INVALID_CONTENT:
        return "malformed_source"
    if category == SourceFailureCategory.EXTRACTION_FAILED:
        return "extraction_error"
    return "unavailable"


def canonical_source_url(value: str) -> str:
    parsed = urlsplit(value)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or parsed.scheme.lower() not in {"http", "https"}:
        return value
    port = parsed.port
    netloc = f"[{host}]" if ":" in host else host
    if port and not (parsed.scheme.lower() == "http" and port == 80) and not (
        parsed.scheme.lower() == "https" and port == 443
    ):
        netloc = f"{netloc}:{port}"
    safe_query = [
        (key, item)
        for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        if not _SENSITIVE_QUERY_KEY.search(key) and not _TRACKING_QUERY_KEY.match(key)
    ]
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", urlencode(safe_query), ""))


def requirement_recovery_query(contract: ProofContract, requirement: Requirement) -> str:
    expected = requirement.expected
    if isinstance(expected, list):
        expected_text = " or ".join(str(value) for value in expected)
    elif expected is None:
        expected_text = ""
    else:
        expected_text = str(expected)
    unit = f" {requirement.unit}" if requirement.unit else ""
    subject = f" {requirement.subject}" if requirement.subject else ""
    query = " ".join(
        part for part in (
            contract.goal,
            requirement.label,
            requirement.field,
            expected_text + unit,
            subject,
            "public sources",
        ) if part.strip()
    )
    return " ".join(query.split())[:1000]


class ResearchOrchestrator:
    """Requirement-level recovery decisions shared by all research providers."""

    unresolved_statuses = {
        RequirementEvaluationStatus.UNVERIFIED,
        RequirementEvaluationStatus.CONFLICTING_EVIDENCE,
        RequirementEvaluationStatus.INVALID_EVIDENCE,
        RequirementEvaluationStatus.NOT_SATISFIED,
    }

    def __init__(self, policy: ResearchResiliencePolicy | None = None) -> None:
        self.policy = policy or ResearchResiliencePolicy.from_environment()

    def requirements_needing_recovery(self, contract, claims) -> list[Requirement]:
        unresolved_ids = {
            item.requirement_id
            for item in evaluate_requirements(contract, claims)
            if item.status in self.unresolved_statuses
        }
        return sorted(
            (item for item in contract.requirements if item.id in unresolved_ids),
            key=lambda item: item.hard_constraint,
            reverse=True,
        )

    def query_for_requirement(self, contract, requirement: Requirement) -> str:
        return requirement_recovery_query(contract, requirement)

    def has_resolved_requirement(self, contract, claims, requirement_id: str) -> bool:
        statuses = [
            item.status
            for item in evaluate_requirements(contract, claims)
            if item.requirement_id == requirement_id
        ]
        return bool(statuses) and all(item not in self.unresolved_statuses for item in statuses)
