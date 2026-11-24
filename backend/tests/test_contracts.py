import asyncio
import os
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from pydantic import ValidationError

from contracts import ContractGenerationError, ContractInputError, generate_proof_contract
from llm import LLMConfigurationError
from main import app
from models import (
    ActionType,
    ProofContract,
    Requirement,
    RequirementEvaluation,
    RequirementEvaluationStatus,
    RequirementOperator,
    ResearchReport,
    ResearchReportStatus,
    TaskResponse,
    TaskStatus,
)


@contextmanager
def isolated_test_client():
    with tempfile.TemporaryDirectory() as directory:
        database_path = os.path.join(directory, "contract-tests.db")
        with patch.dict(os.environ, {
            "PROOFPILOT_DB_PATH": database_path,
            "PROOFPILOT_BROWSER_PROVIDER": "local",
        }):
            with TestClient(app) as client:
                yield client


def valid_contract_data(task_id: str = "task_contract") -> dict:
    return {
        "task_id": task_id,
        "goal": "Find a product that meets the requested storage need",
        "requirements": [
            {
                "id": "storage",
                "label": "Collect storage information",
                "field": "capacity",
                "operator": "exists",
                "expected": None,
                "hard_constraint": False,
            }
        ],
        "allowed_domains": [],
        "allowed_actions": [
            "search_public_web",
            "browse_public_page",
            "extract_evidence",
        ],
        "prohibited_actions": [
            "bypass_authentication",
            "bypass_captcha",
            "bypass_anti_bot",
        ],
        "requires_approval_for": [],
        "completion_criteria": ["Link findings to source evidence."],
        "ambiguities": [],
        "clarification_required_before_research": False,
        "clarification_required_before_execution": False,
    }


def valid_requirement(**overrides) -> dict:
    value = {
        "id": "price_limit",
        "label": "Price is no more than 1500",
        "field": "price",
        "operator": "lte",
        "expected": 1500,
        "unit": "GBP",
        "hard_constraint": True,
    }
    value.update(overrides)
    return value


class RequirementModelTests(unittest.TestCase):
    def test_valid_requirement_and_contract(self):
        requirement = Requirement.model_validate(valid_requirement())
        contract = ProofContract.model_validate(
            {
                **valid_contract_data(),
                "requirements": [requirement.model_dump()],
                "allowed_domains": ["www.example.com"],
            }
        )
        self.assertEqual(contract.requirements[0].operator, RequirementOperator.LTE)
        self.assertEqual(contract.allowed_domains, ["www.example.com"])
        self.assertEqual(contract.version, 1)

    def test_invalid_operator_is_rejected(self):
        with self.assertRaises(ValidationError):
            Requirement.model_validate(valid_requirement(operator="approximately"))

    def test_duplicate_requirement_ids_are_rejected(self):
        requirement = valid_requirement()
        data = valid_contract_data()
        data["requirements"] = [requirement, requirement]
        with self.assertRaises(ValidationError):
            ProofContract.model_validate(data)

    def test_missing_requirement_fields_are_rejected(self):
        with self.assertRaises(ValidationError):
            Requirement.model_validate({"id": "missing-label", "field": "price"})
        with self.assertRaises(ValidationError):
            Requirement.model_validate(valid_requirement(label=" ", field=" "))

    def test_empty_completion_criteria_are_rejected(self):
        data = valid_contract_data()
        data["completion_criteria"] = []
        with self.assertRaises(ValidationError):
            ProofContract.model_validate(data)

        data = valid_contract_data()
        data["requirements"] = []
        with self.assertRaises(ValidationError):
            ProofContract.model_validate(data)

    def test_invalid_domain_and_action_types_are_rejected(self):
        data = valid_contract_data()
        data["allowed_domains"] = ["https://example.com/path"]
        with self.assertRaises(ValidationError):
            ProofContract.model_validate(data)

        data = valid_contract_data()
        data["allowed_actions"].append("run_arbitrary_code")
        with self.assertRaises(ValidationError):
            ProofContract.model_validate(data)

    def test_ambiguity_flags_are_explicit_and_consistent(self):
        data = valid_contract_data()
        data["ambiguities"] = [
            {
                "id": "currency",
                "description": "The dollar currency is unclear.",
                "clarification_question": "Which dollar currency applies?",
                "related_requirement_ids": ["storage"],
                "blocking_stage": "execution",
            }
        ]
        data["clarification_required_before_execution"] = True
        contract = ProofContract.model_validate(data)
        self.assertTrue(contract.clarification_required_before_execution)
        self.assertEqual(contract.ambiguities[0].blocking_stage, "execution")

        data["clarification_required_before_execution"] = False
        with self.assertRaises(ValidationError):
            ProofContract.model_validate(data)

    def test_action_approval_must_be_allowed_and_prohibited_actions_cannot_be_allowed(self):
        data = valid_contract_data()
        data["requires_approval_for"] = ["purchase"]
        with self.assertRaises(ValidationError):
            ProofContract.model_validate(data)

        data = valid_contract_data()
        data["allowed_actions"].append("bypass_captcha")
        with self.assertRaises(ValidationError):
            ProofContract.model_validate(data)

        data = valid_contract_data()
        data["allowed_actions"].append("purchase")
        with self.assertRaises(ValidationError):
            ProofContract.model_validate(data)


class ContractGenerationTests(unittest.TestCase):
    def test_excessive_task_and_budget_input_are_rejected(self):
        with self.assertRaises(ContractInputError):
            asyncio.run(generate_proof_contract("task_long", "x" * 3001))
        with self.assertRaises(ContractInputError):
            asyncio.run(generate_proof_contract("task_budget", "Research SSDs", "x" * 101))

    def test_generation_uses_mocked_structured_llm_and_validates_result(self):
        mock_llm = AsyncMock(return_value=valid_contract_data("task_mocked"))
        with patch("contracts.call_structured_llm", mock_llm):
            contract = asyncio.run(
                generate_proof_contract(
                    "task_mocked",
                    "Find products and collect their storage capacity",
                )
            )

        self.assertEqual(contract.task_id, "task_mocked")
        self.assertIsInstance(contract, ProofContract)
        self.assertIs(mock_llm.await_args.args[2], ProofContract)
        self.assertIn("ProofContract", mock_llm.await_args.args[1])

    def test_invalid_llm_output_fails_instead_of_falling_back(self):
        invalid = valid_contract_data("task_bad")
        invalid["allowed_actions"] = ["invented_action"]
        with patch("contracts.call_structured_llm", AsyncMock(return_value=invalid)):
            with self.assertRaises(ContractGenerationError):
                asyncio.run(generate_proof_contract("task_bad", "Research an SSD"))

    def test_llm_cannot_invent_a_hard_numeric_constraint(self):
        invented = valid_contract_data("task_invented")
        invented["requirements"] = [valid_requirement()]
        with patch("contracts.call_structured_llm", AsyncMock(return_value=invented)):
            with self.assertRaises(ContractGenerationError):
                asyncio.run(generate_proof_contract("task_invented", "Research SSD warranty options"))

    def test_llm_cannot_turn_an_unspecified_field_into_a_hard_requirement(self):
        invented = valid_contract_data("task_field_invented")
        invented["requirements"] = [
            {
                "id": "warranty_required",
                "label": "Warranty information must exist",
                "field": "warranty",
                "operator": "exists",
                "expected": None,
                "hard_constraint": True,
            }
        ]
        with patch("contracts.call_structured_llm", AsyncMock(return_value=invented)):
            with self.assertRaises(ContractGenerationError):
                asyncio.run(generate_proof_contract("task_field_invented", "Research SSDs"))

    def test_llm_cannot_guess_currency_from_dollar_symbol(self):
        guessed_currency = valid_contract_data("task_currency_guess")
        guessed_currency["requirements"] = [
            valid_requirement(unit="USD"),
        ]
        with patch(
            "contracts.call_structured_llm",
            AsyncMock(return_value=guessed_currency),
        ):
            with self.assertRaises(ContractGenerationError):
                asyncio.run(
                    generate_proof_contract("task_currency_guess", "Find an SSD under $1500")
                )

    def test_wrong_task_association_is_rejected(self):
        with patch(
            "contracts.call_structured_llm",
            AsyncMock(return_value=valid_contract_data("another_task")),
        ):
            with self.assertRaises(ContractGenerationError):
                asyncio.run(generate_proof_contract("task_expected", "Research an SSD"))

    def test_missing_llm_configuration_uses_conservative_fallback(self):
        with patch(
            "contracts.call_structured_llm",
            AsyncMock(side_effect=LLMConfigurationError("not configured")),
        ):
            contract = asyncio.run(
                generate_proof_contract(
                    "task_fallback",
                    "Find an external SSD under \u00a31500 with at least 2 TB storage",
                )
            )

        fields = {item.field: item for item in contract.requirements}
        self.assertEqual(fields["price"].expected, 1500)
        self.assertEqual(fields["price"].unit, "GBP")
        self.assertEqual(fields["capacity"].operator, RequirementOperator.GTE)
        self.assertFalse(contract.clarification_required_before_execution)

    def test_ambiguous_currency_is_flagged_before_execution(self):
        with patch(
            "contracts.call_structured_llm",
            AsyncMock(side_effect=LLMConfigurationError("not configured")),
        ):
            contract = asyncio.run(
                generate_proof_contract("task_currency", "Find an SSD under $1500")
            )
        self.assertTrue(contract.clarification_required_before_execution)
        self.assertEqual(contract.requirements[0].unit, "currency")

    def test_explicit_purchase_requires_approval_and_negated_purchase_is_prohibited(self):
        with patch(
            "contracts.call_structured_llm",
            AsyncMock(side_effect=LLMConfigurationError("not configured")),
        ):
            purchase_contract = asyncio.run(
                generate_proof_contract("task_purchase", "Research SSDs and purchase one")
            )
            prohibited_contract = asyncio.run(
                generate_proof_contract("task_no_purchase", "Research SSDs; do not purchase one")
            )

        self.assertIn(ActionType.PURCHASE, purchase_contract.allowed_actions)
        self.assertIn(ActionType.PURCHASE, purchase_contract.requires_approval_for)
        self.assertNotIn(ActionType.PURCHASE, prohibited_contract.allowed_actions)
        self.assertIn(ActionType.PURCHASE, prohibited_contract.prohibited_actions)


class ContractApiTests(unittest.TestCase):
    @staticmethod
    def _seed_task(client: TestClient, task_id: str = "task_api") -> None:
        now = datetime.now(timezone.utc)
        task = TaskResponse(
            id=task_id,
            task="Research external SSDs and collect storage capacity",
            status=TaskStatus.PLANNED,
            progress="Task ready",
            plan=[],
            created_at=now,
            updated_at=now,
        )
        client.app.state.task_agent.tasks[task_id] = task
        client.app.state.task_agent.task_store.save(task)

    def test_generate_and_retrieve_contract_for_existing_task(self):
        with isolated_test_client() as client:
            self._seed_task(client)
            with patch(
                "contracts.call_structured_llm",
                AsyncMock(return_value=valid_contract_data("task_api")),
            ):
                generated = client.post("/api/tasks/task_api/contract")

            self.assertEqual(generated.status_code, 201)
            self.assertEqual(generated.json()["task_id"], "task_api")

            retrieved = client.get("/api/tasks/task_api/contract")
            self.assertEqual(retrieved.status_code, 200)
            self.assertEqual(retrieved.json(), generated.json())

    def test_contract_endpoints_require_an_existing_task_and_contract(self):
        with isolated_test_client() as client:
            self.assertEqual(client.post("/api/tasks/missing/contract").status_code, 404)
            self.assertEqual(client.get("/api/tasks/missing/contract").status_code, 404)

            self._seed_task(client)
            client.app.state.task_agent.contracts.pop("task_api", None)
            client.app.state.task_agent.task_store.delete_contract("task_api")
            self.assertEqual(client.get("/api/tasks/task_api/contract").status_code, 404)

    def test_task_api_exposes_the_structured_research_report(self):
        with isolated_test_client() as client:
            self._seed_task(client)
            task = client.app.state.task_agent.tasks["task_api"]
            task.contract_version = 1
            task.research_report = ResearchReport(
                task_id="task_api",
                contract_version=1,
                status=ResearchReportStatus.PARTIAL,
                requirements=[],
                evaluations=[
                    RequirementEvaluation(
                        requirement_id="price_limit",
                        requirement_description="Price is within budget",
                        expected=1500,
                        observed_value=None,
                        evidence_ids=[],
                        status=RequirementEvaluationStatus.UNVERIFIED,
                        reason="No source evidence was collected.",
                    )
                ],
                evidence=[],
                completion_criteria=[],
            )

            response = client.get("/api/tasks/task_api")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["contract_version"], 1)
        self.assertEqual(body["research_report"]["status"], "PARTIAL")
        self.assertEqual(body["research_report"]["execution_status"], "COMPLETED")
        self.assertEqual(body["research_report"]["source_summary"]["requirements_unresolved"], 1)
        self.assertEqual(body["research_report"]["source_attempts"], [])
        self.assertEqual(
            body["research_report"]["evaluations"][0]["status"],
            "UNVERIFIED",
        )

    def test_api_does_not_store_malformed_model_output(self):
        invalid = valid_contract_data("task_api")
        invalid["completion_criteria"] = []
        with isolated_test_client() as client:
            self._seed_task(client)
            client.app.state.task_agent.contracts.pop("task_api", None)
            client.app.state.task_agent.task_store.delete_contract("task_api")
            with patch("contracts.call_structured_llm", AsyncMock(return_value=invalid)):
                response = client.post("/api/tasks/task_api/contract")
            self.assertEqual(response.status_code, 502)
            self.assertIsNone(client.app.state.task_agent.contracts.get("task_api"))


if __name__ == "__main__":
    unittest.main()
