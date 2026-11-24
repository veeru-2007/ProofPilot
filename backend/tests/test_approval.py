import asyncio
import os
import sqlite3
import tempfile
import unittest
from datetime import timedelta
from unittest.mock import AsyncMock, patch

from pydantic import HttpUrl, ValidationError

from approval import ApprovalService, approval_digest
from models import (
    ActionCondition,
    ActionContract,
    ActionContractCreateRequest,
    ActionContractStatus,
    ActionType,
    AnalyzerOutput,
    DemoActionType,
    DemoExecutionResult,
    DemoSubmission,
    EvidenceExtractionStatus,
    EvidenceRecord,
    ExecutionReceipt,
    ProofContract,
    Requirement,
    RequirementEvaluation,
    RequirementEvaluationStatus,
    RequirementOperator,
    ResearchReport,
    ResearchReportStatus,
    TaskResponse,
    TaskStatus,
    VerificationStatus,
    utc_now,
)
from task_store import TaskStore

# Approval tests exercise the explicit local sandbox signer. Production remains
# disabled unless the launcher or operator opts into a Warrant signing mode.
os.environ.setdefault("PROOFPILOT_WARRANT_MODE", "local_demo")


DEMO_URL = "http://127.0.0.1:8000/demo/laptop-selection"
DEMO_PAYLOAD = {
    "laptop": "Dell G16",
    "budget": "GBP 1500",
    "ram": "32GB DDR5",
    "gpu": "RTX 4060",
    "reason": "Meets the verified price and hardware requirements.",
}


def make_contract(task_id="task_action"):
    return ProofContract(
        task_id=task_id,
        goal="Research and submit a selection for the requested laptop",
        requirements=[
            Requirement(
                id="price_limit",
                label="Price is no more than GBP 1500",
                field="price",
                operator=RequirementOperator.LTE,
                expected=1500,
                unit="GBP",
            )
        ],
        allowed_domains=[],
        allowed_actions=[
            ActionType.SEARCH_PUBLIC_WEB,
            ActionType.BROWSE_PUBLIC_PAGE,
            ActionType.EXTRACT_EVIDENCE,
            ActionType.SUBMIT_FORM,
        ],
        prohibited_actions=[
            ActionType.BYPASS_AUTHENTICATION,
            ActionType.BYPASS_CAPTCHA,
            ActionType.BYPASS_ANTI_BOT,
        ],
        requires_approval_for=[ActionType.SUBMIT_FORM],
        completion_criteria=["Return verified evidence for each requirement."],
        ambiguities=[],
        clarification_required_before_research=False,
        clarification_required_before_execution=False,
    )


def make_task(task_id="task_action", contract=None):
    contract = contract or make_contract(task_id)
    now = utc_now()
    requirement = contract.requirements[0]
    evidence = EvidenceRecord(
        evidence_id="evidence_dell_price",
        subject="Dell G16",
        field="Price",
        value="GBP 1449.99",
        source_url="https://www.dell.com/products/g16",
        source_title="Dell G16 product listing",
        supporting_text="The Dell G16 is listed at GBP 1449.99.",
        observed_at=now,
        associated_requirement_ids=[requirement.id],
        extraction_status=EvidenceExtractionStatus.SUPPORTED,
    )
    report = ResearchReport(
        task_id=task_id,
        contract_version=contract.version,
        status=ResearchReportStatus.COMPLETED,
        requirements=contract.requirements,
        evaluations=[
            RequirementEvaluation(
                requirement_id=requirement.id,
                requirement_description=requirement.label,
                subject="Dell G16",
                status=RequirementEvaluationStatus.SATISFIED,
                expected=1500,
                observed_value="GBP 1449.99",
                evidence_ids=[evidence.evidence_id],
                reason="The verified price is within the requested limit.",
            )
        ],
        evidence=[evidence],
        completion_criteria=[],
    )
    return TaskResponse(
        id=task_id,
        task=contract.goal,
        status=TaskStatus.COMPLETED,
        progress="Completed",
        progress_percent=100,
        current_stage="complete",
        plan=[],
        contract_version=contract.version,
        research_report=report,
        created_at=now,
        updated_at=now,
    )


def make_action_request(**overrides):
    data = {
        "action_type": DemoActionType.SUBMIT_DEMO_REQUEST,
        "target_url": DEMO_URL,
        "payload": DemoSubmission(**DEMO_PAYLOAD),
        "associated_requirement_ids": ["price_limit"],
        "associated_evidence_ids": ["evidence_dell_price"],
    }
    data.update(overrides)
    return ActionContractCreateRequest(**data)


def demo_result(payload=None, record_id="demo_receipt123"):
    payload = payload or DEMO_PAYLOAD
    return DemoExecutionResult(
        action_attempted=True,
        action_completed=True,
        record_id=record_id,
        observed_record={**payload, "submission_id": record_id},
    )


class ActionContractModelTests(unittest.TestCase):
    def test_valid_action_contract_is_typed_and_bound(self):
        async def run():
            service = ApprovalService()
            action = await service.prepare_action(make_task(), make_contract(), make_action_request())
            return action

        action = __import__("asyncio").run(run())
        self.assertIsInstance(action, ActionContract)
        self.assertEqual(action.status, ActionContractStatus.PENDING_APPROVAL)
        self.assertEqual(action.action_type, DemoActionType.SUBMIT_DEMO_REQUEST)
        self.assertTrue(all(item.satisfied for item in action.preconditions))
        self.assertEqual(action.target_url, HttpUrl(DEMO_URL))
        self.assertEqual(action.permission_context.proof_action, ActionType.SUBMIT_FORM)

    def test_invalid_action_type_and_missing_required_payload_are_rejected(self):
        data = make_action_request().model_dump(mode="json")
        data["action_type"] = "purchase"
        with self.assertRaises(ValidationError):
            ActionContractCreateRequest.model_validate(data)

        data = make_action_request().model_dump(mode="json")
        data["payload"].pop("reason")
        with self.assertRaises(ValidationError):
            ActionContractCreateRequest.model_validate(data)

    def test_action_contract_requires_preconditions_and_postconditions(self):
        async def run():
            service = ApprovalService()
            return await service.prepare_action(make_task(), make_contract(), make_action_request())

        action = __import__("asyncio").run(run())
        data = action.model_dump(mode="python")
        data["preconditions"] = []
        with self.assertRaises(ValidationError):
            ActionContract.model_validate(data)

        data = action.model_dump(mode="python")
        data["expected_postconditions"] = []
        with self.assertRaises(ValidationError):
            ActionContract.model_validate(data)

    def test_approval_digest_is_sha256_and_deterministic(self):
        async def run():
            service = ApprovalService()
            return await service.prepare_action(make_task(), make_contract(), make_action_request())

        action = __import__("asyncio").run(run())
        self.assertEqual(len(action.approval_digest), 64)
        self.assertEqual(approval_digest(action), action.approval_digest)
        self.assertEqual(approval_digest(action), approval_digest(action.model_copy(deep=True)))


class ActionPermissionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ,
            {"ALLOWED_DEMO_TARGETS": f"{DEMO_URL},http://127.0.0.1:8001/demo/laptop-selection"},
        )
        self.env.start()
        self.addCleanup(self.env.stop)

    async def test_target_must_be_the_controlled_local_demo_form(self):
        service = ApprovalService()
        with self.assertRaises(ValueError):
            await service.prepare_action(
                make_task(),
                make_contract(),
                make_action_request(target_url="https://example.com/submit"),
            )
        with self.assertRaises(ValueError):
            await service.prepare_action(
                make_task(),
                make_contract(),
                make_action_request(target_url="http://127.0.0.1:8000/other-form"),
            )

    async def test_prohibited_or_unapproved_proof_action_is_rejected(self):
        contract = make_contract()
        data = contract.model_dump(mode="python")
        data["allowed_actions"].remove(ActionType.SUBMIT_FORM)
        data["requires_approval_for"] = []
        data["prohibited_actions"].append(ActionType.SUBMIT_FORM)
        prohibited = ProofContract.model_validate(data)
        service = ApprovalService()
        with self.assertRaises(PermissionError):
            await service.prepare_action(make_task(contract=prohibited), prohibited, make_action_request())

        data["prohibited_actions"].remove(ActionType.SUBMIT_FORM)
        unapproved = ProofContract.model_validate(data)
        with self.assertRaises(PermissionError):
            await service.prepare_action(make_task(contract=unapproved), unapproved, make_action_request())

    async def test_incomplete_or_unsatisfied_research_blocks_action_preparation(self):
        contract = make_contract()
        task = make_task(contract=contract)
        task.status = TaskStatus.PARTIAL
        service = ApprovalService()
        with self.assertRaises(PermissionError):
            await service.prepare_action(task, contract, make_action_request())

        task = make_task(contract=contract)
        task.research_report.evaluations[0].status = RequirementEvaluationStatus.UNVERIFIED
        with self.assertRaises(PermissionError):
            await service.prepare_action(task, contract, make_action_request())


class ActionApprovalStateTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ,
            {"ALLOWED_DEMO_TARGETS": f"{DEMO_URL},http://127.0.0.1:8001/demo/laptop-selection"},
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.contract = make_contract()
        self.task = make_task(contract=self.contract)

    async def _prepare(self, service=None):
        service = service or ApprovalService()
        action = await service.prepare_action(self.task, self.contract, make_action_request())
        return service, action

    async def test_explicit_approval_binds_the_stored_digest(self):
        service, action = await self._prepare()
        approved = await service.decide(
            action.action_id, True, self.task, self.contract,
            warrant_hash=action.warrant.contract_hash,
        )
        self.assertEqual(approved.status, ActionContractStatus.APPROVED)
        self.assertEqual(approved.approved_digest, approved.approval_digest)
        self.assertIsNotNone(approved.approved_at)

    async def test_payload_target_and_action_type_changes_invalidate_approval(self):
        for mutation in ("payload", "target", "action_type"):
            with self.subTest(mutation=mutation):
                service, action = await self._prepare()
                stored = service.actions[action.action_id]
                if mutation == "payload":
                    stored.payload.laptop = "Different laptop"
                elif mutation == "target":
                    stored.target_url = HttpUrl("http://127.0.0.1:8001/demo/laptop-selection")
                else:
                    stored.action_type = DemoActionType.PREPARE_DEMO_REQUEST
                self.assertNotEqual(approval_digest(stored), stored.approval_digest)
                with self.assertRaises(PermissionError):
                    await service.decide(
                        action.action_id, True, self.task, self.contract,
                        warrant_hash=action.warrant.contract_hash,
                    )
                self.assertEqual(
                    (await service.get_action(action.action_id)).status,
                    ActionContractStatus.INVALIDATED,
                )

    async def test_expired_action_is_rejected_and_marked_expired(self):
        service, action = await self._prepare()
        stored = service.actions[action.action_id]
        stored.__dict__["created_at"] = utc_now() - timedelta(minutes=2)
        stored.__dict__["expires_at"] = utc_now() - timedelta(seconds=1)
        self.assertEqual(
            (await service.get_action(action.action_id)).status,
            ActionContractStatus.EXPIRED,
        )
        with self.assertRaises(ValueError):
            await service.decide(
                action.action_id, True, self.task, self.contract,
                warrant_hash=action.warrant.contract_hash,
            )

    async def test_rejected_unapproved_invalidated_and_expired_actions_cannot_execute(self):
        service, unapproved = await self._prepare()
        with self.assertRaises(PermissionError):
            await service.execute(unapproved.action_id, self.task, self.contract)

        service, rejected = await self._prepare()
        await service.decide(rejected.action_id, False, self.task, self.contract)
        with self.assertRaises(PermissionError):
            await service.execute(rejected.action_id, self.task, self.contract)

        service, invalidated = await self._prepare()
        service.actions[invalidated.action_id].payload.laptop = "Changed after preparation"
        with self.assertRaises(PermissionError):
            await service.decide(
                invalidated.action_id, True, self.task, self.contract,
                warrant_hash=invalidated.warrant.contract_hash,
            )
        with self.assertRaises(PermissionError):
            await service.execute(invalidated.action_id, self.task, self.contract)

        service, expired = await self._prepare()
        service.actions[expired.action_id].__dict__["created_at"] = utc_now() - timedelta(minutes=2)
        service.actions[expired.action_id].__dict__["expires_at"] = utc_now() - timedelta(seconds=1)
        with self.assertRaises(PermissionError):
            await service.execute(expired.action_id, self.task, self.contract)

    async def test_invalid_state_transition_is_rejected(self):
        service, action = await self._prepare()
        stored = service.actions[action.action_id]
        service._transition(stored, ActionContractStatus.REJECTED, "Rejected", "user")
        with self.assertRaises(ValueError):
            service._transition(stored, ActionContractStatus.APPROVED, "Invalid", "user")


class ControlledExecutionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = TaskStore(os.path.join(self.temp.name, "proofpilot.db"))
        self.env = patch.dict(os.environ, {"ALLOWED_DEMO_TARGETS": DEMO_URL})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.contract = make_contract()
        self.task = make_task(contract=self.contract)
        self.store.save(self.task)
        self.store.save_contract(self.contract)

    async def _prepared_approved(self, service):
        action = await service.prepare_action(self.task, self.contract, make_action_request())
        approved = await service.decide(
            action.action_id, True, self.task, self.contract,
            warrant_hash=action.warrant.contract_hash,
        )
        return approved

    async def test_successful_controlled_submission_is_independently_verified(self):
        executor = AsyncMock(return_value=demo_result())
        service = ApprovalService(executor=executor, store=self.store)
        action = await self._prepared_approved(service)
        receipt = await service.execute(action.action_id, self.task, self.contract)

        self.assertEqual(receipt.execution_status, ActionContractStatus.VERIFIED_SUCCESS)
        self.assertEqual(receipt.verification_status, VerificationStatus.SUPPORTED)
        self.assertTrue(receipt.action_attempted)
        self.assertTrue(receipt.action_completed)
        self.assertTrue(receipt.outcome_verified)
        self.assertEqual(receipt.resulting_record_id, "demo_receipt123")
        self.assertIn("approved_payload_matches_record", receipt.verified_postconditions)
        self.assertIsInstance(self.store.get_receipt(action.action_id), ExecutionReceipt)

        duplicate = await service.execute(action.action_id, self.task, self.contract)
        self.assertEqual(duplicate.receipt_id, receipt.receipt_id)
        executor.assert_awaited_once()

    async def test_two_service_instances_cannot_execute_the_same_action(self):
        entered = asyncio.Event()
        release = asyncio.Event()
        calls = 0

        async def delayed_executor(action):
            nonlocal calls
            calls += 1
            entered.set()
            await release.wait()
            record = await first_service.record_demo_submission(
                action.idempotency_key,
                action.payload.model_dump(mode="json"),
            )
            return demo_result(
                action.payload.model_dump(mode="json"),
                record["submission_id"],
            )

        first_service = ApprovalService(executor=delayed_executor, store=self.store)
        action = await self._prepared_approved(first_service)
        second_service = ApprovalService(executor=delayed_executor, store=self.store)

        first_execution = asyncio.create_task(
            first_service.execute(action.action_id, self.task, self.contract)
        )
        await asyncio.wait_for(entered.wait(), timeout=2)
        with self.assertRaises(ValueError):
            await second_service.execute(action.action_id, self.task, self.contract)

        release.set()
        receipt = await first_execution
        self.assertEqual(receipt.execution_status, ActionContractStatus.VERIFIED_SUCCESS)
        self.assertEqual(calls, 1)
        self.assertEqual(len(self.store.list_demo_submissions()), 1)

    async def test_receipt_write_failure_does_not_commit_terminal_action(self):
        service = ApprovalService(store=self.store)

        async def submit(action):
            payload = action.payload.model_dump(mode="json")
            record = await service.record_demo_submission(action.idempotency_key, payload)
            return demo_result(payload, record["submission_id"])

        service.executor = submit
        action = await self._prepared_approved(service)
        with patch.object(self.store, "_write_receipt", side_effect=sqlite3.OperationalError("write failed")):
            with self.assertRaises(sqlite3.OperationalError):
                await service.execute(action.action_id, self.task, self.contract)

        self.assertEqual(self.store.get_action(action.action_id).status, ActionContractStatus.EXECUTING)
        self.assertIsNone(self.store.get_receipt(action.action_id))
        recovered = ApprovalService(store=self.store)
        receipt = await recovered.reconcile(action.action_id)
        self.assertEqual(receipt.execution_status, ActionContractStatus.VERIFIED_SUCCESS)
        self.assertEqual(self.store.get_action(action.action_id).execution_receipt_id, receipt.receipt_id)
        self.assertEqual(len(self.store.list_demo_submissions()), 1)

    async def test_cancelled_execution_requires_reconciliation(self):
        started = asyncio.Event()

        async def wait_for_browser(action):
            started.set()
            await asyncio.Event().wait()

        service = ApprovalService(executor=wait_for_browser, store=self.store)
        action = await self._prepared_approved(service)
        execution = asyncio.create_task(service.execute(action.action_id, self.task, self.contract))
        await asyncio.wait_for(started.wait(), timeout=2)
        execution.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await execution

        self.assertEqual(self.store.get_action(action.action_id).status, ActionContractStatus.OUTCOME_UNKNOWN)
        receipt = self.store.get_receipt(action.action_id)
        self.assertIsNotNone(receipt)
        self.assertFalse(receipt.outcome_verified)
        with self.assertRaisesRegex(ValueError, "reconcile"):
            await service.execute(action.action_id, self.task, self.contract)

    async def test_atomic_execution_claim_expires_an_approval_at_the_claim_boundary(self):
        service = ApprovalService(store=self.store)
        action = await self._prepared_approved(service)
        stored = self.store.get_action(action.action_id)
        stored.__dict__["created_at"] = utc_now() - timedelta(minutes=2)
        stored.__dict__["expires_at"] = utc_now() - timedelta(seconds=1)
        self.store.save_action(stored)

        claimed = self.store.claim_action_execution(
            action.action_id,
            action.approval_digest,
            expected_warrant_hash=action.warrant.contract_hash,
            validate=service._validate_execution_claim,
        )

        self.assertIsNone(claimed)
        expired = self.store.get_action(action.action_id)
        self.assertEqual(expired.status, ActionContractStatus.EXPIRED)
        self.assertEqual(expired.audit[-1].actor, "system")

    async def test_atomic_execution_claim_revalidates_persisted_task_state(self):
        service = ApprovalService(store=self.store)
        action = await self._prepared_approved(service)
        changed_task = self.store.get(self.task.id)
        changed_task.status = TaskStatus.PARTIAL
        self.store.save(changed_task)

        with self.assertRaises(PermissionError):
            await service.execute(action.action_id, self.task, self.contract)

        self.assertEqual(
            self.store.get_action(action.action_id).status,
            ActionContractStatus.INVALIDATED,
        )

    async def test_stale_service_refreshes_executing_authorization_from_sqlite(self):
        first_service = ApprovalService(store=self.store)
        action = await self._prepared_approved(first_service)
        stale_service = ApprovalService(store=self.store)
        self.assertEqual(
            stale_service.actions[action.action_id].status,
            ActionContractStatus.APPROVED,
        )

        claimed = self.store.claim_action_execution(
            action.action_id,
            action.approval_digest,
            expected_warrant_hash=action.warrant.contract_hash,
            validate=first_service._validate_execution_claim,
        )
        self.assertEqual(claimed.status, ActionContractStatus.EXECUTING)
        record = await stale_service.record_demo_submission(
            action.idempotency_key,
            action.payload.model_dump(mode="json"),
        )
        self.assertEqual(record["submission_id"], self.store.get_demo_submission_by_idempotency(action.idempotency_key)["submission_id"])

    async def test_orphaned_idempotency_index_becomes_unknown_without_retry(self):
        executor = AsyncMock(return_value=demo_result())
        service = ApprovalService(executor=executor)
        action = await self._prepared_approved(service)
        service.idempotency_index[action.idempotency_key] = "demo_missing_record"

        receipt = await service.execute(action.action_id, self.task, self.contract)
        self.assertEqual(receipt.execution_status, ActionContractStatus.OUTCOME_UNKNOWN)
        self.assertFalse(receipt.outcome_verified)
        executor.assert_not_awaited()

    async def test_independent_verification_mismatch_is_verified_failure(self):
        altered = {**DEMO_PAYLOAD, "gpu": "Different GPU"}
        executor = AsyncMock(return_value=demo_result(payload=altered))
        service = ApprovalService(executor=executor)
        action = await self._prepared_approved(service)
        receipt = await service.execute(action.action_id, self.task, self.contract)
        self.assertEqual(receipt.execution_status, ActionContractStatus.VERIFIED_FAILURE)
        self.assertEqual(receipt.verification_status, VerificationStatus.CONTRADICTED)
        self.assertFalse(receipt.outcome_verified is False)
        self.assertIn("approved_payload_matches_record", receipt.failed_postconditions)

    async def test_timeout_is_outcome_unknown_and_cannot_be_retried(self):
        executor = AsyncMock(side_effect=TimeoutError("response timed out"))
        service = ApprovalService(executor=executor, store=self.store)
        action = await self._prepared_approved(service)
        receipt = await service.execute(action.action_id, self.task, self.contract)
        self.assertEqual(receipt.execution_status, ActionContractStatus.OUTCOME_UNKNOWN)
        self.assertFalse(receipt.outcome_verified)
        with self.assertRaises(ValueError):
            await service.execute(action.action_id, self.task, self.contract)
        executor.assert_awaited_once()

    async def test_uncertain_action_reconciles_idempotency_record_without_resubmission(self):
        service = ApprovalService(store=self.store)

        async def submitted_then_timed_out(action):
            await service.record_demo_submission(
                action.idempotency_key,
                action.payload.model_dump(mode="json"),
            )
            raise TimeoutError("browser lost the response after POST")

        service.executor = submitted_then_timed_out
        action = await self._prepared_approved(service)
        uncertain = await service.execute(action.action_id, self.task, self.contract)
        self.assertEqual(uncertain.execution_status, ActionContractStatus.OUTCOME_UNKNOWN)
        calls_before = len(self.store.list_demo_submissions())

        receipt = await service.reconcile(action.action_id)
        self.assertEqual(receipt.execution_status, ActionContractStatus.VERIFIED_SUCCESS)
        self.assertTrue(receipt.outcome_verified)
        self.assertEqual(len(self.store.list_demo_submissions()), calls_before)

    async def test_idempotency_key_returns_existing_record_and_rejects_changed_payload(self):
        service = ApprovalService(store=self.store)
        action = await self._prepared_approved(service)
        service._transition(service.actions[action.action_id], ActionContractStatus.EXECUTING, "Test execution", "agent")
        first = await service.record_demo_submission(action.idempotency_key, DEMO_PAYLOAD)
        second = await service.record_demo_submission(action.idempotency_key, DEMO_PAYLOAD)
        self.assertEqual(first["submission_id"], second["submission_id"])
        self.assertEqual(len(self.store.list_demo_submissions()), 1)
        with self.assertRaises(PermissionError):
            await service.record_demo_submission(
                action.idempotency_key,
                {**DEMO_PAYLOAD, "laptop": "Different laptop"},
            )

    async def test_restart_during_execution_marks_unknown_then_reconciles(self):
        service = ApprovalService(store=self.store)
        action = await self._prepared_approved(service)
        running = service.actions[action.action_id]
        service._transition(running, ActionContractStatus.EXECUTING, "Crash simulation", "agent")
        await service.record_demo_submission(action.idempotency_key, DEMO_PAYLOAD)

        restarted = ApprovalService(store=self.store)
        restored = await restarted.get_action(action.action_id)
        self.assertEqual(restored.status, ActionContractStatus.OUTCOME_UNKNOWN)
        receipt = await restarted.reconcile(action.action_id)
        self.assertEqual(receipt.execution_status, ActionContractStatus.VERIFIED_SUCCESS)


if __name__ == "__main__":
    unittest.main()
