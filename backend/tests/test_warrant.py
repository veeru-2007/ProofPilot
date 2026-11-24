import unittest
from datetime import datetime, timedelta, timezone

from pydantic import ValidationError

from approval import approval_digest
from models import ActionCondition, ActionContract, ActionPermissionContext, ActionType, DemoActionType, DemoSubmission
from warrant import WarrantError, WarrantSigner, build_sandbox_plan, canonical_hash, canonical_json
from warrant_models import MAX_PLAN_STEPS, SignedWarrant, ValidatedPlan, build_readback_url

from .test_approval import DEMO_PAYLOAD, DEMO_URL, make_contract


class WarrantTests(unittest.TestCase):
    def setUp(self):
        now = datetime.now(timezone.utc)
        self.contract = make_contract()
        self.action = ActionContract(
            action_id="action_0123456789ab",
            task_id=self.contract.task_id,
            contract_version=self.contract.version,
            action_type=DemoActionType.SUBMIT_DEMO_REQUEST,
            target_url=DEMO_URL,
            target_domain="127.0.0.1",
            target_description="Controlled sandbox form",
            payload=DemoSubmission(**DEMO_PAYLOAD),
            preconditions=[ActionCondition(condition_id="valid_target", description="Target allowed", satisfied=True)],
            associated_evidence_ids=["evidence_price"],
            expected_postconditions=[ActionCondition(condition_id="record_persisted", description="Record persisted")],
            prohibited_effects=["Outside sandbox submission"],
            permission_context=ActionPermissionContext(
                task_id=self.contract.task_id,
                contract_version=self.contract.version,
                proof_action=ActionType.SUBMIT_FORM,
                requires_approval=True,
                target_policy="local_demo_laptop_selection_v1",
                target_domain="127.0.0.1",
            ),
            created_at=now,
            expires_at=now + timedelta(minutes=10),
            idempotency_key="idem_" + "0" * 32,
            approval_digest="0" * 64,
        )
        self.action.approval_digest = approval_digest(self.action)
        self.signer = WarrantSigner(b"k" * 32)

    def test_compiles_a_typed_plan_for_the_existing_action(self):
        plan = build_sandbox_plan(self.action)
        self.assertEqual(len(plan.steps), MAX_PLAN_STEPS)
        self.assertEqual(plan.task_id, self.action.task_id)
        self.assertEqual(plan.action_id, self.action.action_id)
        self.assertEqual(plan.source, "DETERMINISTIC_SANDBOX")
        self.assertEqual(ValidatedPlan.model_validate(plan.model_dump(mode="json")), plan)
        self.assertEqual(
            [step.action_type for step in plan.steps],
            ["navigate", "fill", "fill", "fill", "fill", "fill", "click", "read", "extract"],
        )
        self.assertEqual(plan.steps[1].parameters.value, self.action.payload.laptop)

    def test_rejects_unsupported_action_step(self):
        plan = build_sandbox_plan(self.action).model_dump(mode="json")
        plan["steps"][0]["action_type"] = "pay"
        with self.assertRaises(ValidationError):
            ValidatedPlan.model_validate(plan)

    def test_rejects_extra_parameters_wrong_selector_and_non_loopback_target(self):
        for step_index, changes in (
            (0, {"expression": "unexpected"}),
            (0, {"url": "https://example.test/demo/laptop-selection"}),
            (1, {"selector": "#reason"}),
            (1, {"value": 123}),
            (6, {"request_url": "http://127.0.0.1:9000/demo/submissions"}),
            (7, {"url_template": "http://127.0.0.1:8000/other/{record_id}"}),
            (8, {"source_step_id": "open_form"}),
        ):
            with self.subTest(changes=changes):
                plan = build_sandbox_plan(self.action).model_dump(mode="json")
                plan["steps"][step_index]["parameters"].update(changes)
                with self.assertRaises(ValidationError):
                    ValidatedPlan.model_validate(plan)

    def test_rejects_excessive_steps_and_duplicate_ids(self):
        plan = build_sandbox_plan(self.action).model_dump(mode="json")
        plan["steps"].append(dict(plan["steps"][0], id="extra"))
        with self.assertRaises(ValidationError):
            ValidatedPlan.model_validate(plan)
        plan["steps"].pop()
        plan["steps"][1]["id"] = plan["steps"][0]["id"]
        with self.assertRaises(ValidationError):
            ValidatedPlan.model_validate(plan)

    def test_builds_readback_from_one_validated_identifier_segment(self):
        self.assertEqual(
            build_readback_url(DEMO_URL, "demo_fixture-id"),
            "http://127.0.0.1:8000/demo/selections/demo_fixture-id",
        )
        for record_id in ("", "../record", "%2e%2e", "id?x=1", "id#fragment", "id\\other", "id/other", "x" * 81):
            with self.subTest(record_id=record_id), self.assertRaises(ValueError):
                build_readback_url(DEMO_URL, record_id)

    def test_canonical_bytes_are_stable_and_utf8_encoded(self):
        self.assertEqual(canonical_json({"z": "£", "a": [2, 1]}), '{"a":[2,1],"z":"£"}'.encode())
        self.assertEqual(canonical_hash({"b": 3, "a": {"d": 5, "c": 1}}), canonical_hash({"a": {"c": 1, "d": 5}, "b": 3}))

    def test_issued_warrant_binds_plan_and_proof_and_preserves_action_digest(self):
        signed = self.signer.issue(self.action, self.contract)
        self.assertEqual(signed.plan_hash, canonical_hash(signed.plan))
        self.assertEqual(signed.proof_contract_hash, canonical_hash(self.contract))
        self.assertEqual(signed.approval_budget, 1)
        self.assertEqual(signed.approval_budget, 1)
        self.assertEqual(signed.authorized_steps, tuple(step.id for step in signed.plan.steps))
        self.action.warrant = SignedWarrant.model_validate_json(signed.model_dump_json())
        self.assertEqual(approval_digest(self.action), self.action.approval_digest)
        self.signer.validate(self.action.warrant, self.action, self.contract)

    def test_rejects_tampering_wrong_secret_expiry_and_changed_intent(self):
        signed = self.signer.issue(self.action, self.contract)
        tampered = signed.model_copy(update={"contract_hash": "a" * 64})
        for signer, warrant in ((self.signer, tampered), (WarrantSigner(b"x" * 32), signed)):
            with self.assertRaises(WarrantError) as error:
                signer.validate(warrant, self.action, self.contract)
            self.assertEqual(error.exception.code, "invalid_warrant_signature")
        with self.assertRaises(WarrantError) as error:
            self.signer.validate(signed, self.action, self.contract, now=signed.expires_at)
        self.assertEqual(error.exception.code, "warrant_expired")
        changed_contract = self.contract.model_copy(update={"goal": "Different underlying intent"})
        with self.assertRaises(WarrantError) as error:
            self.signer.validate(signed, self.action, changed_contract)
        self.assertEqual(error.exception.code, "proof_contract_mismatch")
        changed_action = self.action.model_copy(deep=True)
        changed_action.payload.ram = "64GB"
        with self.assertRaises(WarrantError) as error:
            self.signer.validate(signed, changed_action, self.contract)
        self.assertEqual(error.exception.code, "warrant_plan_mismatch")

    def test_local_demo_key_requires_opt_in_and_is_process_stable(self):
        disabled = WarrantSigner.from_environment({})
        self.assertEqual(disabled.mode, "disabled")
        with self.assertRaises(WarrantError) as error:
            disabled.issue(self.action, self.contract)
        self.assertEqual(error.exception.status_code, 503)
        first = WarrantSigner.from_environment({"PROOFPILOT_WARRANT_MODE": "local_demo"})
        second = WarrantSigner.from_environment({"PROOFPILOT_WARRANT_MODE": "local_demo"})
        self.assertEqual(first.mode, "local_demo")
        warrant = first.issue(self.action, self.contract)
        self.assertEqual(warrant.signing_mode, "local_demo")
        second.validate(warrant, self.action, self.contract)
        weak = WarrantSigner.from_environment({
            "PROOFPILOT_WARRANT_MODE": "local_demo", "PROOFPILOT_WARRANT_SIGNING_SECRET": "too-short",
        })
        self.assertEqual(weak.mode, "disabled")
        required = WarrantSigner.from_environment({
            "PROOFPILOT_WARRANT_MODE": "required",
            "PROOFPILOT_WARRANT_SIGNING_SECRET": "s" * 32,
        })
        self.assertEqual(required.mode, "configured")
        self.assertEqual(WarrantSigner.from_environment({"PROOFPILOT_WARRANT_MODE": "required"}).mode, "disabled")
