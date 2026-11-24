import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from approval import ApprovalService
from demo_scenario import SIMULATED_PRODUCTS, create_simulated_demo
from models import (
    ActionContractStatus,
    DemoSubmission,
    EvidenceExtractionStatus,
    RequirementEvaluationStatus,
    VerificationStatus,
)
from task_store import TaskStore
from tests.test_approval import DEMO_URL, demo_result, make_action_request


class DeterministicDemoScenarioTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    async def test_simulated_candidates_gate_approved_demo_and_produce_verified_receipt(self):
        task, contract = create_simulated_demo("task_simulated_demo")
        evaluations = {
            (item.subject, item.requirement_id): item.status
            for item in task.research_report.evaluations
        }

        self.assertTrue(task.task.startswith("SIMULATED DEMO:"))
        self.assertEqual(task.status.value, "completed")
        self.assertEqual(len({claim.subject for claim in task.claims}), 3)
        self.assertEqual(len(task.sources), 3)
        self.assertTrue(all("simulated.example.test" in str(source.url) for source in task.sources))
        self.assertEqual(
            evaluations[("Dell G16", "price_limit")],
            RequirementEvaluationStatus.SATISFIED,
        )
        self.assertEqual(
            evaluations[("Dell G16", "ram_minimum")],
            RequirementEvaluationStatus.SATISFIED,
        )
        self.assertEqual(
            evaluations[("Lenovo LOQ 16", "ram_minimum")],
            RequirementEvaluationStatus.NOT_SATISFIED,
        )
        self.assertEqual(
            evaluations[("MSI Katana 15", "price_limit")],
            RequirementEvaluationStatus.NOT_SATISFIED,
        )
        self.assertIn("Ignore all previous instructions", SIMULATED_PRODUCTS[0]["visible_text"])
        self.assertFalse(any(
            "Ignore all previous instructions" in claim.evidence.quote
            for claim in task.claims
            if claim.subject == "Dell G16"
        ))
        self.assertTrue(task.analysis.recommendation.startswith("SIMULATED RESULTS:"))

        dell_evidence = [
            record.evidence_id
            for record in task.research_report.evidence
            if record.subject == "Dell G16"
            and record.extraction_status == EvidenceExtractionStatus.SUPPORTED
        ]
        self.assertEqual(len(dell_evidence), 3)
        payload_data = {
            "laptop": "Dell G16",
            "budget": "GBP 1500",
            "ram": "32GB DDR5",
            "gpu": "RTX 4060",
            "reason": "Controlled simulated request for the passing fixture candidate.",
        }
        request = make_action_request(
            payload=DemoSubmission(**payload_data),
            associated_requirement_ids=["price_limit", "ram_minimum"],
            associated_evidence_ids=dell_evidence,
        )
        executor = AsyncMock(return_value=demo_result(payload_data, record_id="simulated_receipt_001"))
        store = TaskStore(os.path.join(self.temp.name, "proofpilot-demo.db"))
        store.save(task)
        store.save_contract(contract)
        service = ApprovalService(executor=executor, store=store)
        with patch.dict(os.environ, {"ALLOWED_DEMO_TARGETS": DEMO_URL}):
            action = await service.prepare_action(task, contract, request)
            self.assertEqual(action.status, ActionContractStatus.PENDING_APPROVAL)
            executor.assert_not_awaited()
            with self.assertRaises(PermissionError):
                await service.execute(action.action_id, task, contract)

            approved = await service.decide(
                action.action_id, True, task, contract,
                warrant_hash=action.warrant.contract_hash,
            )
            self.assertEqual(approved.status, ActionContractStatus.APPROVED)
            receipt = await service.execute(action.action_id, task, contract)

        self.assertEqual(receipt.execution_status, ActionContractStatus.VERIFIED_SUCCESS)
        self.assertEqual(receipt.verification_status, VerificationStatus.SUPPORTED)
        self.assertEqual(receipt.resulting_record_id, "simulated_receipt_001")
        self.assertTrue(receipt.outcome_verified)
        executor.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
