import os
import unittest
from unittest.mock import patch

from models import (
    ActionType,
    Claim,
    Evidence,
    ProofContract,
    Requirement,
    RequirementOperator,
    SourceFailureCategory,
    VerificationStatus,
    utc_now,
)
from research_orchestrator import (
    ResearchOrchestrator,
    ResearchResiliencePolicy,
    canonical_source_url,
    classify_source_failure,
)


def make_contract():
    return ProofContract(
        task_id="task_orchestrator",
        goal="Compare a public device listing",
        requirements=[
            Requirement(
                id="price_limit", label="Maximum price GBP 1500", field="price",
                operator=RequirementOperator.LTE, expected=1500, unit="GBP",
            ),
            Requirement(
                id="ram_minimum", label="At least 32 GB RAM", field="ram",
                operator=RequirementOperator.GTE, expected=32, unit="GB",
            ),
        ],
        allowed_domains=[],
        allowed_actions=[ActionType.SEARCH_PUBLIC_WEB, ActionType.BROWSE_PUBLIC_PAGE, ActionType.EXTRACT_EVIDENCE],
        prohibited_actions=[ActionType.BYPASS_AUTHENTICATION, ActionType.BYPASS_CAPTCHA, ActionType.BYPASS_ANTI_BOT],
        requires_approval_for=[],
        completion_criteria=["Return source-linked evidence."],
        ambiguities=[],
        clarification_required_before_research=False,
        clarification_required_before_execution=False,
    )


class ResearchOrchestratorTests(unittest.TestCase):
    def test_failure_categories_distinguish_access_auth_rate_timeout_and_invalid_content(self):
        self.assertEqual(classify_source_failure(status_code=403), SourceFailureCategory.ACCESS_DENIED)
        self.assertEqual(classify_source_failure(status_code=401), SourceFailureCategory.AUTH_REQUIRED)
        self.assertEqual(classify_source_failure(status_code=429), SourceFailureCategory.RATE_LIMITED)
        self.assertEqual(classify_source_failure(status_code=404), SourceFailureCategory.CONTENT_UNAVAILABLE)
        self.assertEqual(classify_source_failure(exception=TimeoutError()), SourceFailureCategory.TIMEOUT)
        self.assertEqual(classify_source_failure(invalid_content=True), SourceFailureCategory.INVALID_CONTENT)
        self.assertEqual(
            classify_source_failure(error="Protected-page marker detected: Access Denied: Authentication or access restriction detected"),
            SourceFailureCategory.ACCESS_DENIED,
        )
        self.assertEqual(
            classify_source_failure(error="Protected-page marker detected: sign in to continue"),
            SourceFailureCategory.AUTH_REQUIRED,
        )
        self.assertEqual(classify_source_failure(error="robots.txt disallows this page"), SourceFailureCategory.ROBOTS_OR_RESTRICTION)
        self.assertEqual(classify_source_failure(), SourceFailureCategory.UNKNOWN_FAILURE)

    def test_access_restrictions_are_not_retried_but_transient_failures_are_bounded(self):
        policy = ResearchResiliencePolicy(max_attempts_per_source=2)
        self.assertFalse(policy.retry_eligible(SourceFailureCategory.ACCESS_DENIED, 1))
        self.assertFalse(policy.retry_eligible(SourceFailureCategory.AUTH_REQUIRED, 1))
        self.assertTrue(policy.retry_eligible(SourceFailureCategory.TIMEOUT, 1))
        self.assertFalse(policy.retry_eligible(SourceFailureCategory.TIMEOUT, 2))

    def test_retry_and_recovery_configuration_is_clamped_to_safe_bounds(self):
        with patch.dict(os.environ, {
            "RESEARCH_MAX_SOURCE_ATTEMPTS": "999",
            "RESEARCH_MAX_ATTEMPTS_PER_SOURCE": "0",
            "RESEARCH_MAX_RECOVERY_OPERATIONS": "-5",
            "RESEARCH_RETRY_DELAY_SECONDS": "50",
        }):
            policy = ResearchResiliencePolicy.from_environment()
        self.assertEqual(policy.max_source_attempts, 20)
        self.assertEqual(policy.max_attempts_per_source, 1)
        self.assertEqual(policy.max_recovery_operations, 0)
        self.assertEqual(policy.retry_delay_seconds, 0.25)

    def test_persisted_source_url_removes_credentials_and_sensitive_query_values(self):
        safe = canonical_source_url(
            "https://user:password@example.org/listing?access_token=secret&color=black#details"
        )
        self.assertEqual(safe, "https://example.org/listing?color=black")
        self.assertNotIn("password", safe)
        self.assertNotIn("secret", safe)

    def test_requirement_recovery_only_targets_unresolved_requirements(self):
        contract = make_contract()
        claim = Claim(
            id="claim_price",
            subject="Public device",
            field="Price",
            value="GBP 1,200",
            evidence=Evidence(
                quote="Public device price is GBP 1,200.",
                source_url="https://public.example.org/listing",
                source_title="Public device listing",
                timestamp=utc_now(),
            ),
            verification_status=VerificationStatus.SUPPORTED,
            verification_reason="The source supports the price.",
        )
        orchestrator = ResearchOrchestrator(ResearchResiliencePolicy())
        unresolved = orchestrator.requirements_needing_recovery(contract, [claim])
        self.assertEqual([item.id for item in unresolved], ["ram_minimum"])
        query = orchestrator.query_for_requirement(contract, unresolved[0])
        self.assertIn("ram", query.casefold())
        self.assertIn("32 GB", query)


if __name__ == "__main__":
    unittest.main()
