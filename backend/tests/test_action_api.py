import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from main import app
from models import ActionType
from tests.test_approval import DEMO_PAYLOAD, make_action_request, make_contract, make_task, demo_result


class ActionContractApiTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.dict(os.environ, {
            "PROOFPILOT_DB_PATH": os.path.join(directory, "actions.db"),
            "PROOFPILOT_BROWSER_PROVIDER": "local",
            "PROOFPILOT_WARRANT_MODE": "local_demo",
        }))
        self.client = self.enterContext(TestClient(app))
        self._seed_task()

    def _seed_task(self, contract=None):
        task = make_task()
        contract = contract or make_contract()
        self.client.app.state.task_agent.tasks[task.id] = task
        self.client.app.state.task_agent.contracts[task.id] = contract
        self.client.app.state.task_store.save(task)
        self.client.app.state.task_store.save_contract(contract)
        self.task = task
        self.contract = contract

    def _create_action(self, **overrides):
        request = make_action_request(**overrides)
        return self.client.post(
            f"/api/tasks/{self.task.id}/actions",
            json=request.model_dump(mode="json"),
        )

    def test_action_api_approves_executes_verifies_and_returns_same_receipt(self):
        created = self._create_action()
        self.assertEqual(created.status_code, 201, created.text)
        action = created.json()
        self.assertEqual(action["status"], "PENDING_APPROVAL")
        action_id = action["action_id"]

        loaded = self.client.get(f"/api/actions/{action_id}")
        self.assertEqual(loaded.status_code, 200)
        self.assertEqual(loaded.json()["approval_digest"], action["approval_digest"])

        approved = self.client.post(
            f"/api/actions/{action_id}/approve",
            json={"warrant_hash": action["warrant"]["contract_hash"]},
        )
        self.assertEqual(approved.status_code, 200, approved.text)
        self.assertEqual(approved.json()["status"], "APPROVED")
        self.assertEqual(approved.json()["approved_digest"], action["approval_digest"])

        executor = AsyncMock(return_value=demo_result())
        self.client.app.state.approval_service.executor = executor
        executed = self.client.post(f"/api/actions/{action_id}/execute")
        self.assertEqual(executed.status_code, 200, executed.text)
        receipt = executed.json()
        self.assertEqual(receipt["execution_status"], "VERIFIED_SUCCESS")
        self.assertTrue(receipt["action_attempted"])
        self.assertTrue(receipt["action_completed"])
        self.assertTrue(receipt["outcome_verified"])

        fetched = self.client.get(f"/api/actions/{action_id}/receipt")
        self.assertEqual(fetched.status_code, 200)
        self.assertEqual(fetched.json(), receipt)
        repeated = self.client.post(f"/api/actions/{action_id}/execute")
        self.assertEqual(repeated.status_code, 200)
        self.assertEqual(repeated.json()["receipt_id"], receipt["receipt_id"])
        executor.assert_awaited_once()

    def test_cannot_delete_task_while_its_action_is_executing(self):
        created = self._create_action()
        self.assertEqual(created.status_code, 201, created.text)
        action = created.json()
        action_id = action["action_id"]
        self.assertEqual(self.client.post(
            f"/api/actions/{action_id}/approve",
            json={"warrant_hash": action["warrant"]["contract_hash"]},
        ).status_code, 200)
        store = self.client.app.state.task_store
        service = self.client.app.state.approval_service
        self.assertIsNotNone(store.claim_action_execution(
            action_id,
            action["approval_digest"],
            expected_warrant_hash=action["warrant"]["contract_hash"],
            validate=service._validate_execution_claim,
        ))

        deleted = self.client.delete(f"/api/tasks/{self.task.id}")
        self.assertEqual(deleted.status_code, 409)
        self.assertIn("approved action", deleted.json()["detail"])
        self.assertIsNotNone(store.get(self.task.id))

    def test_rejected_action_cannot_execute(self):
        created = self._create_action()
        action_id = created.json()["action_id"]
        rejected = self.client.post(f"/api/actions/{action_id}/reject")
        self.assertEqual(rejected.status_code, 200)
        self.assertEqual(rejected.json()["status"], "REJECTED")

        executor = AsyncMock()
        self.client.app.state.approval_service.executor = executor
        executed = self.client.post(f"/api/actions/{action_id}/execute")
        self.assertEqual(executed.status_code, 403)
        executor.assert_not_awaited()

    def test_api_rejects_unauthorized_contract_and_nonlocal_target(self):
        contract_data = self.contract.model_dump(mode="python")
        contract_data["allowed_actions"].remove(ActionType.SUBMIT_FORM)
        contract_data["requires_approval_for"] = []
        from models import ProofContract

        self._seed_task(ProofContract.model_validate(contract_data))
        denied = self._create_action()
        self.assertEqual(denied.status_code, 403)

        self._seed_task(make_contract())
        disallowed = self._create_action(target_url="https://example.com/submit")
        self.assertEqual(disallowed.status_code, 409)

    def test_demo_submission_endpoint_rejects_unbound_direct_post(self):
        response = self.client.post("/demo/submissions", json=DEMO_PAYLOAD)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.app.state.task_store.list_demo_submissions(), [])

    def test_demo_readback_loads_a_submission_missing_from_process_cache(self):
        record = self.client.app.state.task_store.create_demo_submission(
            "simulated-readback-key",
            DEMO_PAYLOAD,
        )
        self.client.app.state.demo_submissions.clear()

        response = self.client.get(f"/demo/selections/{record['submission_id']}")

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), record)
        self.assertEqual(
            self.client.app.state.demo_submissions[record["submission_id"]],
            record,
        )

    def test_simulated_demo_route_persists_three_completed_candidates(self):
        response = self.client.post("/api/demo/scenario")

        self.assertEqual(response.status_code, 201, response.text)
        task = response.json()
        self.assertEqual(task["status"], "completed")
        self.assertTrue(task["task"].startswith("SIMULATED DEMO:"))
        self.assertEqual(
            {claim["subject"] for claim in task["claims"]},
            {"Dell G16", "Lenovo LOQ 16", "MSI Katana 15"},
        )
        self.assertIn("SIMULATED RESULTS", task["analysis"]["recommendation"])

        stored = self.client.get(f"/api/tasks/{task['id']}")
        self.assertEqual(stored.status_code, 200, stored.text)
        self.assertEqual(stored.json()["research_report"]["status"], "COMPLETED")
        self.assertEqual(
            self.client.app.state.task_agent.contracts[task["id"]].requires_approval_for[0].value,
            "submit_form",
        )

    def test_action_api_rejects_unrecognized_action_type(self):
        body = make_action_request().model_dump(mode="json")
        body["action_type"] = "purchase"
        response = self.client.post(f"/api/tasks/{self.task.id}/actions", json=body)
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
