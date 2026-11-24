"""Policy rules and the ActionContract execution enforcement point."""

import asyncio
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from approval import ApprovalService, execute_demo_submission
from adversarial_demo import DEMO_ATTACK_INSTRUCTION, DEMO_ATTACK_STEP_ID, DEMO_ATTACK_TARGET
from models import ActionContractStatus
from policy import PolicyDenied, PolicyEngine, PolicyExecution, PolicyState, authorize_plan
from task_store import TaskStore
from warrant import WarrantError
from warrant_models import SignedWarrant

from tests.test_approval import DEMO_URL, make_action_request, make_contract, make_task


class _AcceptSignature:
    def validate(self, warrant, action, proof_contract):
        return None


class _ExpiredSignature:
    def validate(self, warrant, action, proof_contract):
        raise WarrantError("warrant_expired", "Warrant expired.")


class PolicyEngineTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.env = patch.dict(os.environ, {"ALLOWED_DEMO_TARGETS": DEMO_URL})
        self.env.start()
        self.addAsyncCleanup(asyncio.to_thread, self.env.stop)
        self.contract = make_contract()
        self.task = make_task(contract=self.contract)
        self.service = ApprovalService()
        self.action = await self.service.prepare_action(self.task, self.contract, make_action_request())
        self.action = await self.service.decide(
            self.action.action_id,
            True,
            self.task,
            self.contract,
            warrant_hash=self.action.warrant.contract_hash,
        )
        self.warrant = self.action.warrant
        self.engine = PolicyEngine(self.service.warrant_signer)

    def check(self, *, engine=None, warrant=None, step_index=0, step_id=None, action_type=None, target=None, parameters=None):
        warrant = warrant or self.warrant
        step = warrant.plan.steps[step_index]
        return (engine or self.engine).check(
            self.action,
            warrant,
            PolicyState(self.task, self.contract, step_index, "preflight"),
            step_id=step_id or step.id,
            action_type=action_type or step.action_type,
            target=target or getattr(step.parameters, "url", getattr(step.parameters, "url_template", DEMO_URL)),
            parameters=parameters if parameters is not None else step.parameters.model_dump(mode="json"),
        )

    async def test_valid_approved_action_allows_the_exact_plan_in_order(self):
        recorded = []
        decisions = authorize_plan(
            self.engine, self.action, self.task, self.contract, recorded.append, phase="preflight",
        )
        self.assertEqual(len(decisions), 9)
        self.assertTrue(all(item.decision == "allow" for item in decisions))
        self.assertEqual([item.step_id for item in decisions], list(self.warrant.authorized_steps))
        self.assertEqual(recorded, decisions)

    async def test_untrusted_sandbox_attempt_is_denied_and_legitimate_plan_continues(self):
        recorded = []
        run = PolicyExecution(
            self.engine, self.action, self.task, self.contract, recorded.append,
        )
        first = self.warrant.plan.steps[0]
        run.authorize_step(
            first.id, first.action_type, DEMO_URL,
            first.parameters.model_dump(mode="json"),
        )
        cursor_before_attack = run.next_step_index

        attack = run.attempt_untrusted_step(
            step_id=DEMO_ATTACK_STEP_ID,
            action_type="navigate",
            target=DEMO_ATTACK_TARGET,
            parameters={"url": DEMO_ATTACK_TARGET, "method": "GET"},
            instruction=DEMO_ATTACK_INSTRUCTION,
        )
        self.assertEqual(attack.decision, "deny")
        self.assertEqual(attack.rule_id, "DOMAIN_BOUNDARY")
        self.assertEqual(attack.source, "sandbox_page_injection")
        self.assertEqual(attack.source_excerpt, DEMO_ATTACK_INSTRUCTION)
        self.assertEqual(attack.target, "https://attacker.invalid/collect")
        self.assertEqual(run.next_step_index, cursor_before_attack)

        next_step = self.warrant.plan.steps[1]
        allowed = run.authorize_step(
            next_step.id,
            next_step.action_type,
            DEMO_URL,
            next_step.parameters.model_dump(mode="json"),
        )
        self.assertEqual(allowed.decision, "allow")
        self.assertEqual([item.decision for item in recorded], ["allow", "deny", "allow"])

    async def test_invalid_signature_and_contract_hash_are_denied(self):
        bad_signature = self.warrant.model_copy(update={"signature": "0" * 64})
        bad_hash = self.warrant.model_copy(update={"contract_hash": "f" * 64})
        bad_plan_hash = self.warrant.model_copy(update={"plan_hash": "e" * 64})
        self.assertEqual(self.check(warrant=bad_signature).decision, "deny")
        self.assertEqual(self.check(warrant=bad_signature).rule_id, "WARRANT_INTEGRITY")
        self.assertEqual(self.check(warrant=bad_hash).decision, "deny")
        self.assertEqual(self.check(warrant=bad_hash).rule_id, "WARRANT_INTEGRITY")
        self.assertEqual(self.check(warrant=bad_plan_hash).rule_id, "WARRANT_INTEGRITY")

        original_value = self.action.payload.laptop
        self.action.payload.laptop = "Changed after approval"
        self.assertEqual(self.check(engine=PolicyEngine(_AcceptSignature())).rule_id, "ACTION_DIGEST")
        self.action.payload.laptop = original_value

    async def test_expired_warrant_and_missing_or_wrong_approval_are_denied(self):
        expired = self.check(engine=PolicyEngine(_ExpiredSignature()))
        self.assertEqual(expired.rule_id, "WARRANT_EXPIRY")

        original_hash = self.action.approved_warrant_hash
        self.action.approved_warrant_hash = None
        missing = self.check(engine=PolicyEngine(_AcceptSignature()))
        self.assertEqual(missing.rule_id, "APPROVAL_BINDING")

        self.action.approved_warrant_hash = "a" * 64
        wrong = self.check(engine=PolicyEngine(_AcceptSignature()))
        self.assertEqual(wrong.rule_id, "APPROVAL_BINDING")
        self.action.approved_warrant_hash = original_hash

        original_status = self.action.status
        self.action.status = ActionContractStatus.INVALIDATED
        self.assertEqual(self.check(engine=PolicyEngine(_AcceptSignature())).rule_id, "LIFECYCLE_STATE")
        self.action.status = original_status

    async def test_domain_action_id_order_and_parameter_boundaries_deny(self):
        external = self.check(target="https://example.org/demo/laptop-selection")
        self.assertEqual(external.rule_id, "DOMAIN_BOUNDARY")

        changed_step = self.warrant.plan.steps[0].model_copy(update={"target_domain": "example.org"})
        changed_plan = self.warrant.plan.model_copy(update={"steps": (changed_step, *self.warrant.plan.steps[1:])})
        external_warrant = self.warrant.model_copy(update={"plan": changed_plan})
        outside = self.check(engine=PolicyEngine(_AcceptSignature()), warrant=external_warrant, target="https://example.org/demo/laptop-selection")
        self.assertEqual(outside.rule_id, "DOMAIN_BOUNDARY")

        unauthorized_type = self.check(action_type="pay")
        self.assertEqual(unauthorized_type.rule_id, "ACTION_TYPE")
        unauthorized_id = self.check(step_id="unapproved_step")
        self.assertEqual(unauthorized_id.rule_id, "PLAN_ORDER")
        wrong_order = self.check(step_index=1, step_id="open_form", action_type="navigate")
        self.assertEqual(wrong_order.rule_id, "PLAN_ORDER")

        parameters = self.warrant.plan.steps[1].parameters.model_dump(mode="json")
        parameters["value"] = "A different laptop"
        mismatch = self.check(step_index=1, parameters=parameters)
        self.assertEqual(mismatch.rule_id, "PARAMETER_BOUNDARY")

    async def test_policy_exception_fails_closed(self):
        class ExplodingEngine(PolicyEngine):
            def check(self, *args, **kwargs):
                raise RuntimeError("unexpected engine failure")

        decisions = []
        run = PolicyExecution(
            ExplodingEngine(self.service.warrant_signer), self.action, self.task,
            self.contract, decisions.append,
        )
        with self.assertRaises(PolicyDenied) as raised:
            run.authorize_step("open_form", "navigate", DEMO_URL, self.warrant.plan.steps[0].parameters.model_dump(mode="json"))
        self.assertEqual(raised.exception.decision.rule_id, "POLICY_INTERNAL_ERROR")
        self.assertEqual(decisions[0].decision, "deny")

    async def test_denial_is_persisted_and_prevents_executor_invocation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TaskStore(os.path.join(directory, "policy.db"))
            store.save(self.task)
            store.save_contract(self.contract)
            executor = AsyncMock()
            service = ApprovalService(executor=executor, store=store)
            action = await service.prepare_action(self.task, self.contract, make_action_request())
            action = await service.decide(
                action.action_id, True, self.task, self.contract,
                warrant_hash=action.warrant.contract_hash,
            )

            class DenyingEngine(PolicyEngine):
                def check(self, action, warrant, state, **kwargs):
                    return self.denial(
                        action, warrant, rule_id="TEST_DENY",
                        reason="Denied by deterministic policy test.",
                        phase=state.phase, action_type=kwargs["action_type"],
                        step_id=kwargs["step_id"], target=kwargs["target"],
                    )

            service.policy_engine = DenyingEngine(service.warrant_signer)
            with self.assertRaises(PolicyDenied):
                await service.execute(action.action_id, self.task, self.contract)

            executor.assert_not_awaited()
            self.assertEqual(store.get_action(action.action_id).status, ActionContractStatus.INVALIDATED)
            decisions = store.list_policy_decisions(action.action_id)
            self.assertEqual(decisions[-1].decision, "deny")
            self.assertEqual(decisions[-1].rule_id, "TEST_DENY")
            self.assertEqual(decisions[-1].task_id, action.task_id)
            self.assertEqual(decisions[-1].warrant_id, action.warrant.warrant_id)
            self.assertEqual(decisions[-1].contract_hash, action.warrant.contract_hash)

    async def test_browser_executor_requires_policy_gate(self):
        provider = AsyncMock()
        with self.assertRaisesRegex(PermissionError, "policy gate"):
            await execute_demo_submission(self.action, browser_provider=provider)
        provider.open_page.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
