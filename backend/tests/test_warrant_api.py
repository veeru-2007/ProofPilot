"""Warrant review and approval through the existing ActionContract routes."""

import os
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from main import app
from policy import PolicyDecision
from tests.test_approval import DEMO_URL, make_action_request, make_contract, make_task


class WarrantApiTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.dict(os.environ, {
            "PROOFPILOT_DB_PATH": str(Path(directory) / "warrant.db"),
            "PROOFPILOT_BROWSER_PROVIDER": "local",
            "PROOFPILOT_WARRANT_MODE": "local_demo",
            "PROOFPILOT_WARRANT_SIGNING_SECRET": "",
            "ALLOWED_DEMO_TARGETS": DEMO_URL,
        }))
        self.client = self.enterContext(TestClient(app))
        proof = make_contract()
        task = make_task(contract=proof)
        app.state.task_agent.tasks[task.id] = task
        app.state.task_agent.contracts[task.id] = proof
        app.state.task_store.save(task)
        app.state.task_store.save_contract(proof)
        response = self.client.post(
            f"/api/tasks/{task.id}/actions", json=make_action_request().model_dump(mode="json"),
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.action = response.json()
        self.endpoint = f"/api/actions/{self.action['action_id']}"

    def test_signed_plan_is_inspectable_and_validation_is_read_only(self):
        self.assertEqual(self.client.get("/api/health").json()["warrant_signing_mode"], "local_demo")
        plan = self.client.get(f"{self.endpoint}/plan")
        self.assertEqual(plan.status_code, 200, plan.text)
        self.assertEqual(plan.json(), self.action["warrant"]["plan"])

        review = self.client.get(f"{self.endpoint}/warrant")
        self.assertEqual(review.status_code, 200, review.text)
        self.assertTrue(review.json()["signature_valid"])
        self.assertEqual(review.json()["approval_status"], "PENDING_APPROVAL")
        self.assertEqual(review.json()["signing_mode"], "local_demo")

        match = self.client.post(f"{self.endpoint}/plan/validate", json=plan.json())
        self.assertEqual(match.status_code, 200, match.text)
        self.assertEqual(match.json(), {"valid": True, "plan_hash": self.action["warrant"]["plan_hash"]})
        unsupported = deepcopy(plan.json())
        unsupported["steps"][0]["action_type"] = "purchase"
        self.assertEqual(self.client.post(f"{self.endpoint}/plan/validate", json=unsupported).status_code, 422)
        modified = deepcopy(plan.json())
        modified["steps"][0]["description"] = "Edit the already-issued plan description."
        mismatch = self.client.post(f"{self.endpoint}/plan/validate", json=modified)
        self.assertEqual(mismatch.status_code, 409, mismatch.text)
        self.assertEqual(mismatch.json()["detail"]["code"], "WARRANT_PLAN_MISMATCH")
        self.assertEqual(self.client.get(f"{self.endpoint}/plan").json(), plan.json())

    def test_current_warrant_can_be_validated_but_tampering_is_rejected(self):
        body = self.action["warrant"]
        valid = self.client.post(f"{self.endpoint}/warrant/validate", json=body)
        self.assertEqual(valid.status_code, 200, valid.text)
        self.assertTrue(valid.json()["signature_valid"])

        changed = deepcopy(body)
        current = changed["signature"]
        changed["signature"] = ("0" if current[0] != "0" else "1") + current[1:]
        invalid = self.client.post(f"{self.endpoint}/warrant/validate", json=changed)
        self.assertIn(invalid.status_code, (403, 409), invalid.text)
        self.assertTrue(invalid.json()["detail"]["code"])
        self.assertTrue(self.client.get(f"{self.endpoint}/warrant").json()["signature_valid"])

    def test_existing_approval_route_requires_and_persists_reviewed_hash(self):
        hash_value = self.action["warrant"]["contract_hash"]
        missing = self.client.post(f"{self.endpoint}/approve")
        self.assertIn(missing.status_code, (403, 409), missing.text)
        mismatched = ("0" if hash_value[0] != "0" else "1") + hash_value[1:]
        wrong = self.client.post(f"{self.endpoint}/approve", json={"warrant_hash": mismatched})
        self.assertIn(wrong.status_code, (403, 409), wrong.text)
        self.assertEqual(self.client.get(self.endpoint).json()["status"], "PENDING_APPROVAL")

        approved = self.client.post(f"{self.endpoint}/approve", json={"warrant_hash": hash_value})
        self.assertEqual(approved.status_code, 200, approved.text)
        self.assertEqual(approved.json()["approved_digest"], self.action["approval_digest"])
        self.assertEqual(approved.json()["approved_warrant_hash"], hash_value)
        self.assertEqual(self.client.get(f"{self.endpoint}/warrant").json()["approval_status"], "APPROVED")

    def test_policy_decision_endpoint_returns_sqlite_audit_records(self):
        warrant = self.action["warrant"]
        decision = PolicyDecision(
            decision_id="policy_test_record",
            task_id=self.action["task_id"],
            action_id=self.action["action_id"],
            warrant_id=warrant["warrant_id"],
            contract_hash=warrant["contract_hash"],
            action_type="navigate",
            step_id="open_form",
            target=DEMO_URL,
            phase="preflight",
            rule_id="APPROVED_PLAN_STEP",
            decision="allow",
            reason="Action matches the current approved Warrant step.",
            timestamp=datetime.now(timezone.utc),
        )
        app.state.task_store.save_policy_decision(decision)

        response = self.client.get(f"{self.endpoint}/policy-decisions")

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), [decision.model_dump(mode="json")])
