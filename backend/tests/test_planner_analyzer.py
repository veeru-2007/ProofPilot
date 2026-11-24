import asyncio
import os
import unittest

from analyzer import analyze_findings
from models import (
    AnalyzerRequest,
    Claim,
    Evidence,
    PlannerRequest,
    VerificationResult,
    VerificationStatus,
)
from planner import create_plan


def make_claim(claim_id: str, field: str, value: str) -> Claim:
    return Claim(
        id=claim_id,
        subject="Test laptop",
        field=field,
        value=value,
        evidence=Evidence(
            quote=f"Collected evidence for {value}.",
            source_url="https://example.com/specs",
            source_title="Test laptop specifications",
            confidence=0.9,
        ),
        verification_status=VerificationStatus.UNVERIFIED,
        verification_reason="Initial test state.",
    )


class PlannerAnalyzerTests(unittest.TestCase):
    def test_planner_returns_structured_bounded_output(self):
        old_api_key = os.environ.pop("LLM_API_KEY", None)
        old_openai_key = os.environ.pop("OPENAI_API_KEY", None)
        try:
            plan = asyncio.run(
                create_plan(
                    PlannerRequest(
                        task="Find three laptops for machine learning under £1500",
                        budget="£1500",
                    )
                )
            )
        finally:
            if old_api_key is not None:
                os.environ["LLM_API_KEY"] = old_api_key
            if old_openai_key is not None:
                os.environ["OPENAI_API_KEY"] = old_openai_key

        self.assertGreaterEqual(len(plan.steps), 3)
        self.assertLessEqual(len(plan.steps), 5)
        self.assertGreaterEqual(len(plan.search_queries), 3)
        self.assertLessEqual(len(plan.search_queries), 5)
        self.assertGreaterEqual(len(plan.extract_fields), 1)
        self.assertGreaterEqual(len(plan.comparison_criteria), 1)

    def test_planner_identifies_action_requiring_approval(self):
        old_api_key = os.environ.pop("LLM_API_KEY", None)
        old_openai_key = os.environ.pop("OPENAI_API_KEY", None)
        try:
            plan = asyncio.run(
                create_plan(
                    PlannerRequest(task="Submit a laptop selection to the demo form")
                )
            )
        finally:
            if old_api_key is not None:
                os.environ["LLM_API_KEY"] = old_api_key
            if old_openai_key is not None:
                os.environ["OPENAI_API_KEY"] = old_openai_key

        self.assertIsNotNone(plan.approval_action)
        self.assertTrue(plan.approval_action.approval_required)

    def test_analyzer_separates_supported_contradicted_and_missing(self):
        supported_claim = make_claim("supported-1", "RAM", "32GB DDR5")
        contradicted_claim = make_claim("contradicted-1", "Price", "£1449.99")
        missing_claim = make_claim("missing-1", "Warranty", "2-year warranty")

        verifications = [
            VerificationResult(
                claim_id="supported-1",
                status=VerificationStatus.SUPPORTED,
                reason="Directly present in the collected page.",
                evidence_quote="32GB DDR5 RAM",
                evidence_source_url="https://example.com/specs",
                evidence_timestamp=supported_claim.evidence.timestamp,
                checked_at=supported_claim.evidence.timestamp,
            ),
            VerificationResult(
                claim_id="contradicted-1",
                status=VerificationStatus.CONTRADICTED,
                reason="The excerpt states a different price.",
                evidence_quote="The listed price is £1499.99.",
                evidence_source_url="https://example.com/specs",
                evidence_timestamp=contradicted_claim.evidence.timestamp,
                checked_at=contradicted_claim.evidence.timestamp,
            ),
            VerificationResult(
                claim_id="missing-1",
                status=VerificationStatus.UNVERIFIED,
                reason="The warranty duration is not stated.",
                evidence_quote="The warranty terms are linked.",
                evidence_source_url="https://example.com/specs",
                evidence_timestamp=missing_claim.evidence.timestamp,
                checked_at=missing_claim.evidence.timestamp,
            ),
        ]

        old_api_key = os.environ.pop("LLM_API_KEY", None)
        old_openai_key = os.environ.pop("OPENAI_API_KEY", None)
        try:
            analysis = asyncio.run(
                analyze_findings(
                    AnalyzerRequest(
                        task="Compare these laptop findings",
                        claims=[supported_claim, contradicted_claim, missing_claim],
                        verifications=verifications,
                    )
                )
            )
        finally:
            if old_api_key is not None:
                os.environ["LLM_API_KEY"] = old_api_key
            if old_openai_key is not None:
                os.environ["OPENAI_API_KEY"] = old_openai_key

        self.assertEqual(len(analysis.verified_information), 1)
        self.assertEqual(len(analysis.contradictions), 1)
        self.assertEqual(len(analysis.missing_information), 1)
        self.assertEqual(len(analysis.source_links), 1)
        self.assertIn("32GB", analysis.verified_information[0].claim)
        self.assertIn("No unsupported factual inference", analysis.inferences[0])


if __name__ == "__main__":
    unittest.main()
