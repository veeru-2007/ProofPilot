import unittest
from datetime import datetime, timezone

from models import (
    ActionType,
    Claim,
    Evidence,
    ProofContract,
    Requirement,
    RequirementEvaluationStatus,
    RequirementOperator,
    ResearchReportStatus,
    SourceRecord,
    VerificationStatus,
)
from requirement_engine import (
    ContractPermissionError,
    build_research_report,
    enforce_research_permission,
    evaluate_requirements,
    map_evidence_to_requirements,
)


def make_contract(requirements, **overrides):
    data = {
        "task_id": "task_engine",
        "goal": "Research the requested product specifications",
        "requirements": requirements,
        "allowed_domains": [],
        "allowed_actions": [
            ActionType.SEARCH_PUBLIC_WEB,
            ActionType.BROWSE_PUBLIC_PAGE,
            ActionType.EXTRACT_EVIDENCE,
        ],
        "prohibited_actions": [
            ActionType.BYPASS_AUTHENTICATION,
            ActionType.BYPASS_CAPTCHA,
            ActionType.BYPASS_ANTI_BOT,
        ],
        "requires_approval_for": [],
        "completion_criteria": ["Return source linked evidence."],
        "ambiguities": [],
        "clarification_required_before_research": False,
        "clarification_required_before_execution": False,
    }
    data.update(overrides)
    return ProofContract.model_validate(data)


def make_requirement(field, operator, expected, **overrides):
    data = {
        "id": "requirement_1",
        "label": f"Check {field}",
        "field": field,
        "operator": operator,
        "expected": expected,
    }
    data.update(overrides)
    return Requirement.model_validate(data)


def make_claim(field, value, *, claim_id="claim_1", subject="Example drive", status=VerificationStatus.SUPPORTED, quote=None, context=None):
    quote = quote or f"Example drive specification: {value}."
    return Claim(
        id=claim_id,
        subject=subject,
        field=field,
        value=value,
        evidence=Evidence(
            quote=quote,
            source_url="https://www.example.com/specs",
            source_title="Example drive specifications",
            timestamp=datetime(2026, 1, 2, tzinfo=timezone.utc),
        ),
        verification_status=status,
        verification_reason="The source excerpt was checked.",
        context=list(context or []),
    )


class RequirementEngineTests(unittest.TestCase):
    def _evaluate(self, requirement, claim):
        result = evaluate_requirements(make_contract([requirement]), [claim])
        self.assertEqual(len(result), 1)
        return result[0]

    def test_evaluates_eq_lte_gte_contains_one_of_and_exists(self):
        examples = [
            (
                make_requirement("processor", RequirementOperator.EQ, "M3 Pro"),
                make_claim("Processor", "M3 Pro"),
            ),
            (
                make_requirement("price", RequirementOperator.LTE, 1500, unit="GBP"),
                make_claim("Price", "Â£1,200"),
            ),
            (
                make_requirement("capacity", RequirementOperator.GTE, 2, unit="TB"),
                make_claim("RAM", "2 TB", quote="Example drive includes 2 TB SSD storage."),
            ),
            (
                make_requirement("interface", RequirementOperator.CONTAINS, "thunderbolt"),
                make_claim("Interface", "USB4 with Thunderbolt 4"),
            ),
            (
                make_requirement("color", RequirementOperator.ONE_OF, ["silver", "black"]),
                make_claim("Color", "Black"),
            ),
            (
                make_requirement("warranty_years", RequirementOperator.EXISTS, None),
                make_claim("Warranty", "3-year warranty"),
            ),
        ]

        for requirement, claim in examples:
            with self.subTest(operator=requirement.operator):
                self.assertEqual(
                    self._evaluate(requirement, claim).status,
                    RequirementEvaluationStatus.SATISFIED,
                )

    def test_missing_evidence_is_unverified(self):
        result = evaluate_requirements(
            make_contract([make_requirement("price", RequirementOperator.LTE, 1500, unit="GBP")]),
            [],
        )[0]
        self.assertEqual(result.status, RequirementEvaluationStatus.UNVERIFIED)
        self.assertEqual(result.evidence_ids, [])

    def test_different_verified_values_are_conflicting_evidence(self):
        requirement = make_requirement("price", RequirementOperator.LTE, 1500, unit="GBP")
        result = evaluate_requirements(
            make_contract([requirement]),
            [
                make_claim("Price", "Â£1,200", claim_id="claim_a"),
                make_claim("Price", "Â£1,600", claim_id="claim_b"),
            ],
        )[0]
        self.assertEqual(result.status, RequirementEvaluationStatus.CONFLICTING_EVIDENCE)
        self.assertEqual(set(result.evidence_ids), {"claim_a", "claim_b"})

    def test_invalid_observation_and_expected_types_are_not_coerced(self):
        numeric_requirement = make_requirement("capacity", RequirementOperator.GTE, 2, unit="TB")
        invalid_observation = self._evaluate(
            numeric_requirement,
            make_claim("Capacity", "two TB"),
        )
        self.assertEqual(invalid_observation.status, RequirementEvaluationStatus.INVALID_EVIDENCE)

        invalid_expected = make_requirement("price", RequirementOperator.GTE, "1500")
        invalid_definition = self._evaluate(invalid_expected, make_claim("Price", "1500"))
        self.assertEqual(invalid_definition.status, RequirementEvaluationStatus.INVALID_EVIDENCE)

    def test_currency_mismatch_and_ambiguous_dollar_are_unverified_without_conversion(self):
        requirement = make_requirement("price", RequirementOperator.LTE, 1500, unit="GBP")
        usd_result = self._evaluate(requirement, make_claim("Price", "USD 1,200"))
        self.assertEqual(usd_result.status, RequirementEvaluationStatus.UNVERIFIED)
        self.assertEqual(usd_result.required_currency, "GBP")
        self.assertEqual(usd_result.observed_currency, "USD")
        self.assertIsNone(usd_result.conversion_details)
        self.assertIn("no conversion", usd_result.reason.casefold())

        ambiguous_result = self._evaluate(requirement, make_claim("Price", "$1,200"))
        self.assertEqual(ambiguous_result.status, RequirementEvaluationStatus.UNVERIFIED)
        self.assertIsNone(ambiguous_result.observed_currency)
        self.assertEqual(ambiguous_result.observed_currency_symbol, "$")

    def test_contextual_costs_and_other_subjects_do_not_map_to_current_product_price(self):
        requirement = make_requirement(
            "price", RequirementOperator.LTE, 1500, unit="GBP", subject="Example drive"
        )
        claims = [
            make_claim("Price", "£1,200", context=["advertised_price"]),
            make_claim("Price", "£200", claim_id="upgrade", context=["upgrade_cost"]),
            make_claim("Price", "£80", claim_id="cloud", context=["cloud_cost"]),
            make_claim("Price", "£900", claim_id="other", subject="Other drive", context=["advertised_price"]),
        ]
        mapped = map_evidence_to_requirements(make_contract([requirement]), claims)
        self.assertEqual([record.associated_requirement_ids for record in mapped], [["requirement_1"], [], [], []])

    def test_access_failure_is_partial_when_coverage_is_unresolved_but_not_after_successful_alternative(self):
        requirement = make_requirement("price", RequirementOperator.LTE, 1500, unit="GBP")
        contract = make_contract([requirement], completion_criteria=["Return source-linked evidence."])
        blocked = SourceRecord(
            url="https://blocked.example.test/product",
            title="Unavailable product page",
            status_code=403,
            failure_type="blocked",
            blocked_reason="The source denied access (HTTP 403).",
            failure_reason="The source denied access (HTTP 403).",
            failed_at=datetime.now(timezone.utc),
        )
        unresolved = build_research_report("task_blocked", contract, [], [blocked], [], ["Access denied"])
        self.assertEqual(unresolved.status, ResearchReportStatus.PARTIAL)
        self.assertEqual(unresolved.sources_visited[0].coverage_impact, "unresolved")
        self.assertEqual(unresolved.sources_visited[0].affected_requirement_ids, ["requirement_1"])

        supported = make_claim("Price", "£1,200")
        supported_report = build_research_report(
            "task_alternative", contract, [supported], [blocked], [], ["Access denied"]
        )
        self.assertEqual(supported_report.evaluations[0].status, RequirementEvaluationStatus.SATISFIED)
        self.assertEqual(supported_report.sources_visited[0].coverage_impact, "unaffected")
        self.assertEqual(supported_report.status, ResearchReportStatus.COMPLETED)

    def test_evidence_is_mapped_with_source_quote_and_requirement_id(self):
        contract = make_contract([make_requirement("price", RequirementOperator.LTE, 1500, unit="GBP")])
        claim = make_claim("Price", "Â£1,200", quote="The listed price is Â£1,200.")
        record = map_evidence_to_requirements(contract, [claim])[0]

        self.assertEqual(record.evidence_id, claim.id)
        self.assertEqual(record.value, claim.value)
        self.assertEqual(record.source_url, claim.evidence.source_url)
        self.assertEqual(record.source_title, claim.evidence.source_title)
        self.assertEqual(record.supporting_text, claim.evidence.quote)
        self.assertEqual(record.observed_at, claim.evidence.timestamp)
        self.assertEqual(record.associated_requirement_ids, ["requirement_1"])

    def test_prohibited_and_approval_required_actions_are_rejected(self):
        prohibited = make_contract(
            [make_requirement("goal", RequirementOperator.EXISTS, None)],
            prohibited_actions=[
                ActionType.PURCHASE,
                ActionType.BYPASS_AUTHENTICATION,
                ActionType.BYPASS_CAPTCHA,
                ActionType.BYPASS_ANTI_BOT,
            ],
        )
        with self.assertRaises(ContractPermissionError):
            enforce_research_permission(prohibited, ActionType.PURCHASE)

        approval_required = make_contract(
            [make_requirement("goal", RequirementOperator.EXISTS, None)],
            allowed_actions=[
                ActionType.SEARCH_PUBLIC_WEB,
                ActionType.BROWSE_PUBLIC_PAGE,
                ActionType.EXTRACT_EVIDENCE,
                ActionType.PURCHASE,
            ],
            requires_approval_for=[ActionType.PURCHASE],
        )
        with self.assertRaises(ContractPermissionError):
            enforce_research_permission(approval_required, ActionType.PURCHASE)


if __name__ == "__main__":
    unittest.main()
