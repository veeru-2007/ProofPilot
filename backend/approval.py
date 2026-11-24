import asyncio
import logging
import os
import re
from copy import deepcopy
from datetime import timedelta
from functools import partial
from hmac import compare_digest
from typing import Awaitable, Callable, Optional
from urllib.parse import urlparse
from uuid import uuid4

import httpx
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright

from browser_providers import (
    BrowserProvider,
    BrowserProviderError,
    LocalPlaywrightProvider,
)
from action_digest import approval_digest
from adversarial_demo import DEMO_ATTACK_INSTRUCTION, DEMO_ATTACK_STEP_ID, DEMO_ATTACK_TARGET
from models import (
    ActionAuditEntry,
    ActionCondition,
    ActionContract,
    ActionContractCreateRequest,
    ActionContractStatus,
    ActionPermissionContext,
    ActionType,
    DemoActionType,
    DemoExecutionResult,
    ExecutionReceipt,
    ProofContract,
    ResearchReportStatus,
    TaskResponse,
    TaskStatus,
    VerificationStatus,
    utc_now,
)
from task_store import TaskStore
from warrant import WarrantError, WarrantSigner
from warrant_models import (
    DEMO_FILL_FIELDS,
    DEMO_FORM_PATH,
    DEMO_READBACK_PREFIX,
    DEMO_RECORD_ID_PATTERN,
    DEMO_SUBMISSION_PATH,
    DEMO_SUBMIT_SELECTOR,
    SignedWarrant,
    build_readback_url,
)
from policy import PolicyDecision, PolicyDenied, PolicyEngine, PolicyExecution, authorize_plan


logger = logging.getLogger(__name__)
TARGET_POLICY_ID = "local_demo_laptop_selection_v1"
ACTION_TTL = timedelta(minutes=20)
ACTIVE_ACTION_STATUSES = {
    ActionContractStatus.PENDING_APPROVAL,
    ActionContractStatus.APPROVED,
    ActionContractStatus.EXECUTING,
    ActionContractStatus.OUTCOME_UNKNOWN,
    ActionContractStatus.VERIFIED_SUCCESS,
}


def allowed_demo_targets() -> set[str]:
    configured = os.getenv(
        "ALLOWED_DEMO_TARGETS",
        "http://127.0.0.1:8000/demo/laptop-selection",
    )
    return {item.strip().rstrip("/") for item in configured.split(",") if item.strip()}


def validate_demo_target(target_url: str) -> str:
    normalized = target_url.rstrip("/")
    if normalized not in allowed_demo_targets():
        raise ValueError("The target is not an allowed team-controlled demo form.")
    parsed = urlparse(normalized)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("The demo target contains an invalid port.") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost"}
        or parsed.path != DEMO_FORM_PATH
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("Only the local ProofPilot demo form is an allowed action target.")
    return normalized


def _validate_demo_request_url(raw_url: str, target_url: str, method: str) -> None:
    target = urlparse(target_url)
    request = urlparse(raw_url)
    try:
        request_port = request.port or 80
        target_port = target.port or 80
    except ValueError as exc:
        raise ValueError("The browser request contains an invalid port.") from exc
    if (
        request.scheme != "http"
        or request.hostname != target.hostname
        or request_port != target_port
        or request.username
        or request.password
        or request.query
        or request.fragment
    ):
        raise ValueError("The demo browser attempted to leave its approved local origin.")

    path = request.path
    allowed = (
        (method == "GET" and path == DEMO_FORM_PATH)
        or (method == "POST" and path == DEMO_SUBMISSION_PATH)
        or (
            method == "GET"
            and path.startswith(DEMO_READBACK_PREFIX)
            and re.fullmatch(DEMO_RECORD_ID_PATTERN, path.removeprefix(DEMO_READBACK_PREFIX))
        )
    )
    if not allowed:
        raise ValueError("The demo browser requested a route outside the controlled form workflow.")


def verify_demo_record(action: ActionContract, record_id: str, record: dict) -> tuple[bool, list[str], list[str]]:
    verified: list[str] = []
    failed: list[str] = []
    if record.get("submission_id") == record_id and record_id:
        verified.append("demo_record_exists")
    else:
        failed.append("demo_record_exists")

    fields_match = all(
        str(record.get(field, "")) == str(getattr(action.payload, field))
        for field, _ in DEMO_FILL_FIELDS
    )
    if fields_match:
        verified.append("approved_payload_matches_record")
    else:
        failed.append("approved_payload_matches_record")
    return not failed, verified, failed


async def execute_demo_submission(
    action: ActionContract,
    browser_provider: BrowserProvider | None = None,
    policy_gate: PolicyExecution | None = None,
    adversarial_demo: bool = False,
) -> DemoExecutionResult:
    if policy_gate is None:
        raise PermissionError("The Warrant policy gate is required before browser execution.")
    target = validate_demo_target(str(action.target_url))
    provider = browser_provider or LocalPlaywrightProvider(playwright_factory=async_playwright)
    if not provider.supports_demo_actions:
        return DemoExecutionResult(
            action_attempted=False,
            action_completed=False,
            error="The selected remote browser cannot reach the local ProofPilot demo form; action was not attempted.",
        )
    if action.warrant is None:
        raise WarrantError("warrant_required", "Prepare and approve a signed Warrant before execution.")

    timeout_seconds = 20
    try:
        timeout_seconds = int(os.getenv("DEMO_ACTION_TIMEOUT_SECONDS", "20"))
    except ValueError:
        timeout_seconds = 20
    timeout_seconds = max(5, min(timeout_seconds, 60))

    attempted = False
    completed = False
    record_id = None
    try:
        async with provider.open_page(
            headless=True,
            locale="en-US",
            extra_http_headers={"Idempotency-Key": action.idempotency_key},
        ) as browser_session:
            context = browser_session.context
            page = browser_session.page

            async def enforce_demo_origin(route):
                try:
                    request = route.request
                    _validate_demo_request_url(
                        request.url,
                        target,
                        request.method,
                    )
                    if request.method == "GET":
                        if request.url != target or not request.is_navigation_request():
                            raise ValueError("Only the planned top-level form navigation is authorized.")
                    elif request.method == "POST":
                        if not policy_gate.authorize_submission_request(request.url):
                            await route.abort()
                            return
                    else:
                        raise ValueError("The browser request method is not part of the approved plan.")
                except ValueError:
                    policy_gate.block_network_request(route.request.url, "Browser network request is outside the approved plan.")
                    await route.abort()
                    return
                await route.continue_()

            await context.route("**/*", enforce_demo_origin)
            navigate_step = policy_gate.warrant.plan.steps[0]
            policy_gate.authorize_step(
                navigate_step.id,
                "navigate",
                target,
                navigate_step.parameters.model_dump(mode="json"),
            )
            await page.goto(target, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)
            if policy_gate.blocked_decision is not None:
                raise PolicyDenied(policy_gate.blocked_decision)

            if adversarial_demo:
                instruction = await page.locator(
                    '[data-testid="proofpilot-injection"]'
                ).get_attribute("data-instruction", timeout=5000)
                if instruction != DEMO_ATTACK_INSTRUCTION:
                    raise ValueError("The deterministic adversarial demo fixture is missing or changed.")
                policy_gate.attempt_untrusted_step(
                    step_id=DEMO_ATTACK_STEP_ID,
                    action_type="navigate",
                    target=DEMO_ATTACK_TARGET,
                    parameters={"url": DEMO_ATTACK_TARGET, "method": "GET"},
                    instruction=instruction,
                )

            for field, selector in DEMO_FILL_FIELDS:
                step_id = f"fill_{field}"
                policy_gate.authorize_step(
                    step_id,
                    "fill",
                    target,
                    {
                        "url": target,
                        "field": field,
                        "selector": selector,
                        "value": getattr(action.payload, field),
                    },
                )
                await page.fill(selector, getattr(action.payload, field), timeout=5000)
                if policy_gate.blocked_decision is not None:
                    raise PolicyDenied(policy_gate.blocked_decision)

            async with page.expect_response(
                lambda response: urlparse(response.url).path == DEMO_SUBMISSION_PATH
                and response.request.method == "POST",
                timeout=timeout_seconds * 1000,
            ) as response_info:
                click_step = next(step for step in policy_gate.warrant.plan.steps if step.id == "submit_form")
                policy_gate.authorize_step(
                    click_step.id,
                    "click",
                    target,
                    click_step.parameters.model_dump(mode="json"),
                )
                attempted = True
                policy_gate.mark_action_attempted()
                await page.click(DEMO_SUBMIT_SELECTOR, timeout=timeout_seconds * 1000)

            submission_response = await response_info.value
            if policy_gate.blocked_decision is not None:
                raise PolicyDenied(policy_gate.blocked_decision)
            if submission_response.status != 200:
                return DemoExecutionResult(
                    action_attempted=True,
                    action_completed=False,
                    error=f"The demo returned HTTP {submission_response.status}.",
                )

            completed = True
            try:
                submission = await submission_response.json()
                supplied_id = submission.get("submission_id") if isinstance(submission, dict) else None
                state_url = build_readback_url(target, supplied_id)
            except (ValueError, TypeError):
                return DemoExecutionResult(
                    action_attempted=True,
                    action_completed=True,
                    error="The demo accepted the request but returned no valid record ID.",
                )
            record_id = supplied_id
            read_step = next(step for step in policy_gate.warrant.plan.steps if step.id == "read_record")
            policy_gate.authorize_step(
                read_step.id,
                "read",
                state_url,
                read_step.parameters.model_dump(mode="json"),
            )
            async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False) as client:
                state_response = await client.get(state_url)
            if state_response.status_code != 200:
                return DemoExecutionResult(
                    action_attempted=True,
                    action_completed=True,
                    record_id=record_id,
                    error=f"Independent state readback returned HTTP {state_response.status_code}.",
                )
            observed_record = state_response.json()
            if not isinstance(observed_record, dict):
                raise ValueError("Independent state readback did not return a record object.")
            return DemoExecutionResult(
                action_attempted=True,
                action_completed=True,
                record_id=record_id,
                observed_record=observed_record,
            )
    except PlaywrightTimeoutError as exc:
        if policy_gate.blocked_decision is not None:
            raise PolicyDenied(policy_gate.blocked_decision) from exc
        return DemoExecutionResult(
            action_attempted=attempted,
            action_completed=completed,
            record_id=record_id,
            error=f"Demo browser timed out: {exc}",
        )
    except (BrowserProviderError, PlaywrightError, httpx.RequestError, ValueError) as exc:
        if policy_gate.blocked_decision is not None:
            raise PolicyDenied(policy_gate.blocked_decision) from exc
        return DemoExecutionResult(
            action_attempted=attempted,
            action_completed=completed,
            record_id=record_id,
            error=str(exc),
        )


Executor = Callable[[ActionContract], Awaitable[DemoExecutionResult]]


_ALLOWED_TRANSITIONS = {
    ActionContractStatus.PREPARED: {
        ActionContractStatus.PENDING_APPROVAL,
        ActionContractStatus.INVALIDATED,
        ActionContractStatus.EXPIRED,
    },
    ActionContractStatus.PENDING_APPROVAL: {
        ActionContractStatus.APPROVED,
        ActionContractStatus.REJECTED,
        ActionContractStatus.INVALIDATED,
        ActionContractStatus.EXPIRED,
    },
    ActionContractStatus.APPROVED: {
        ActionContractStatus.EXECUTING,
        ActionContractStatus.INVALIDATED,
        ActionContractStatus.EXPIRED,
    },
    ActionContractStatus.EXECUTING: {
        ActionContractStatus.VERIFIED_SUCCESS,
        ActionContractStatus.VERIFIED_FAILURE,
        ActionContractStatus.OUTCOME_UNKNOWN,
    },
    ActionContractStatus.OUTCOME_UNKNOWN: {
        ActionContractStatus.VERIFIED_SUCCESS,
        ActionContractStatus.VERIFIED_FAILURE,
    },
}


class ApprovalService:
    """In-memory ActionContract lifecycle for the controlled demo destination."""

    def __init__(
        self,
        executor: Optional[Executor] = None,
        demo_records: Optional[dict[str, dict]] = None,
        idempotency_index: Optional[dict[str, str]] = None,
        store: Optional[TaskStore] = None,
        browser_provider: BrowserProvider | None = None,
        warrant_signer: WarrantSigner | None = None,
    ) -> None:
        self.store = store
        self.warrant_signer = warrant_signer or WarrantSigner.from_environment()
        self.policy_engine = PolicyEngine(self.warrant_signer)
        self.policy_decisions: list[PolicyDecision] = []
        self._default_executor = executor is None
        self._default_executor_callable = None
        self.actions: dict[str, ActionContract] = {
            action.action_id: action for action in store.list_actions()
        } if store else {}
        self.receipts: dict[str, ExecutionReceipt] = {
            action_id: receipt
            for action_id in self.actions
            if (receipt := store.get_receipt(action_id)) is not None
        } if store else {}
        self.browser_provider = browser_provider
        if executor is not None:
            self.executor = executor
        elif browser_provider is not None:
            self.executor = partial(execute_demo_submission, browser_provider=browser_provider)
            self._default_executor_callable = self.executor
        else:
            self.executor = execute_demo_submission
            self._default_executor_callable = execute_demo_submission
        self.demo_records = demo_records if demo_records is not None else {}
        self.idempotency_index = idempotency_index if idempotency_index is not None else {}
        if store:
            self.demo_records.update(
                {record["submission_id"]: record for record in store.list_demo_submissions()}
            )
            self.idempotency_index.update(store.list_demo_submission_index())
        self._action_locks: dict[str, asyncio.Lock] = {}
        for action in self.actions.values():
            if action.status == ActionContractStatus.EXECUTING:
                self._make_receipt(
                    action,
                    ActionContractStatus.OUTCOME_UNKNOWN,
                    detail="The backend restarted during execution; reconciliation is required and retry is blocked.",
                    actor="system",
                    attempted=True,
                    completed=False,
                    record_id=None,
                    verified=[],
                    failed=["demo_record_exists", "approved_payload_matches_record"],
                    error="The backend restarted during execution; reconcile the idempotency record before proceeding.",
                    verification_status=VerificationStatus.UNVERIFIED,
                )

    def _record_policy_decision(self, decision: PolicyDecision) -> None:
        if self.store:
            self.store.save_policy_decision(decision)
        else:
            self.policy_decisions.append(decision)

    def list_policy_decisions(self, action_id: str) -> list[PolicyDecision]:
        if self.store:
            return self.store.list_policy_decisions(action_id)
        return [item for item in self.policy_decisions if item.action_id == action_id]

    async def decide(
        self,
        action_id: str,
        approve: bool,
        task: TaskResponse,
        contract: ProofContract,
        *,
        warrant_hash: str | None = None,
    ) -> Optional[ActionContract]:
        return await self._decide_action_contract(action_id, approve, task, contract, warrant_hash)

    async def execute(
        self,
        action_id: str,
        task: TaskResponse,
        contract: ProofContract,
    ) -> Optional[ExecutionReceipt]:
        return await self._execute_action_contract(action_id, task, contract)

    async def get_action(self, action_id: str) -> Optional[ActionContract]:
        action = self.store.get_action(action_id) if self.store else None
        if action is not None:
            self.actions[action_id] = action
        else:
            action = self.actions.get(action_id)
        if (
            action is not None
            and utc_now() >= action.expires_at
            and action.status in {ActionContractStatus.PENDING_APPROVAL, ActionContractStatus.APPROVED}
        ):
            self._transition(action, ActionContractStatus.EXPIRED, "The action approval window expired.", "system")
        return deepcopy(action) if action else None

    async def list_for_task(self, task_id: str) -> list[ActionContract]:
        actions = self.store.list_actions(task_id) if self.store else [
            item for item in self.actions.values() if item.task_id == task_id
        ]
        for action in actions:
            self.actions[action.action_id] = action
        return deepcopy(sorted(actions, key=lambda item: item.created_at))

    def has_executing_action(self, task_id: str) -> bool:
        actions = self.store.list_actions(task_id) if self.store else self.actions.values()
        return any(action.task_id == task_id and action.status == ActionContractStatus.EXECUTING for action in actions)

    def invalidate_task_actions(self, task_id: str, reason: str) -> None:
        actions = self.store.list_actions(task_id) if self.store else [
            item for item in self.actions.values() if item.task_id == task_id
        ]
        for action in actions:
            self.actions[action.action_id] = action
            if action.status in {
                ActionContractStatus.PREPARED,
                ActionContractStatus.PENDING_APPROVAL,
                ActionContractStatus.APPROVED,
            }:
                self._invalidate(action, reason)

    async def get_receipt(self, action_id: str) -> Optional[ExecutionReceipt]:
        receipt = self.store.get_receipt(action_id) if self.store else None
        if receipt is not None:
            self.receipts[action_id] = receipt
        else:
            receipt = self.receipts.get(action_id)
        return deepcopy(receipt) if receipt else None

    def _persist_action(self, action: ActionContract) -> None:
        self.actions[action.action_id] = action
        if self.store:
            self.store.save_action(action)

    def _audit(self, action: ActionContract, event: str, detail: str, actor: str) -> None:
        action.audit.append(
            ActionAuditEntry(event=event, detail=detail, actor=actor, timestamp=utc_now())
        )

    def _transition(
        self, action: ActionContract, status: ActionContractStatus, detail: str, actor: str, *, persist: bool = True
    ) -> None:
        if status not in _ALLOWED_TRANSITIONS.get(action.status, set()):
            raise ValueError(f"Invalid ActionContract transition: {action.status.value} -> {status.value}.")
        action.status = status
        action.updated_at = utc_now()
        self._audit(action, status.value, detail, actor)
        if persist:
            self._persist_action(action)

    @staticmethod
    def _authorization_error(
        task: TaskResponse,
        contract: ProofContract,
        payload: ActionContractCreateRequest,
    ) -> tuple[list[ActionCondition], list[str]]:
        if contract.task_id != task.id or task.contract_version != contract.version:
            raise PermissionError("The task and ProofContract association is invalid or stale.")
        if payload.action_type != DemoActionType.SUBMIT_DEMO_REQUEST:
            raise PermissionError("Only controlled demo request submissions are supported.")
        if ActionType.SUBMIT_FORM in contract.prohibited_actions:
            raise PermissionError("The ProofContract prohibits form submission.")
        if ActionType.SUBMIT_FORM not in contract.allowed_actions:
            raise PermissionError("The ProofContract does not authorize form submission.")
        if ActionType.SUBMIT_FORM not in contract.requires_approval_for:
            raise PermissionError("The ProofContract does not require approval for this action.")
        if (
            contract.clarification_required_before_research
            or contract.clarification_required_before_execution
            or any(item.blocking_stage in {"research", "execution"} for item in contract.ambiguities)
        ):
            raise PermissionError("Blocking contract ambiguities must be resolved before action preparation.")
        if task.status != TaskStatus.COMPLETED:
            raise PermissionError("Research must be completed before preparing a demo request.")
        report = task.research_report
        if report is None or report.task_id != task.id or report.contract_version != contract.version:
            raise PermissionError("A current contract compliance report is required before action preparation.")
        if report.status != ResearchReportStatus.COMPLETED:
            raise PermissionError("Research requirements must be fully verified before action preparation.")

        target = validate_demo_target(str(payload.target_url))
        target_domain = urlparse(target).hostname or ""
        evidence_by_id = {item.evidence_id: item for item in report.evidence}
        evidence_ids = list(dict.fromkeys(payload.associated_evidence_ids))
        if len(evidence_ids) != len(payload.associated_evidence_ids):
            raise ValueError("Evidence references must not contain duplicates.")
        if not set(evidence_ids).issubset(evidence_by_id):
            raise PermissionError("The action references evidence that is not in the task report.")
        selected_evidence = [evidence_by_id[item] for item in evidence_ids]
        matching_product_evidence = [
            item
            for item in selected_evidence
            if item.subject.strip().casefold() == payload.payload.laptop.strip().casefold()
            and item.extraction_status.value == "SUPPORTED"
        ]
        if not matching_product_evidence:
            raise PermissionError("The selected product must match supported, task-linked evidence.")

        requirement_ids = list(dict.fromkeys(payload.associated_requirement_ids))
        if len(requirement_ids) != len(payload.associated_requirement_ids):
            raise ValueError("Requirement references must not contain duplicates.")
        known_requirements = {item.id for item in contract.requirements}
        if not set(requirement_ids).issubset(known_requirements):
            raise PermissionError("The action references an unknown ProofContract requirement.")

        hard_requirements = {
            requirement.id
            for requirement in contract.requirements
            if requirement.hard_constraint
        }
        selected_subject = payload.payload.laptop.strip().casefold()
        evaluations = [
            item
            for item in report.evaluations
            if item.subject and item.subject.strip().casefold() == selected_subject
        ]
        evaluation_by_requirement = {item.requirement_id: item for item in evaluations}
        if not hard_requirements.issubset(set(requirement_ids)):
            raise PermissionError("The action must reference every hard ProofContract requirement.")
        if not hard_requirements.issubset(set(evaluation_by_requirement)):
            raise PermissionError("The selected product has unevaluated hard requirements.")
        if any(evaluation_by_requirement[item].status.value != "SATISFIED" for item in hard_requirements):
            raise PermissionError("The selected product does not satisfy every hard requirement.")

        preconditions = [
            ActionCondition(
                condition_id="research_completed",
                description="The task research report is complete under the current ProofContract.",
                satisfied=True,
            ),
            ActionCondition(
                condition_id="hard_requirements_satisfied",
                description="Every hard requirement is satisfied for the selected product.",
                satisfied=True,
                evidence_ids=evidence_ids,
            ),
            ActionCondition(
                condition_id="product_linked_to_evidence",
                description="The selected product matches supported evidence from the completed task.",
                satisfied=True,
                evidence_ids=[item.evidence_id for item in matching_product_evidence],
            ),
            ActionCondition(
                condition_id="payload_complete",
                description="All controlled demo form fields pass the strict payload schema.",
                satisfied=True,
            ),
            ActionCondition(
                condition_id="controlled_target_allowed",
                description="The target is the locally configured ProofPilot demo form.",
                satisfied=True,
            ),
        ]
        return preconditions, evidence_ids

    async def prepare_action(
        self,
        task: TaskResponse,
        contract: ProofContract,
        payload: ActionContractCreateRequest,
    ) -> ActionContract:
        if self.browser_provider is not None and not self.browser_provider.supports_demo_actions:
            raise ValueError(
                "The selected AWS managed browser cannot reach the local ProofPilot demo form, so this action is unavailable."
            )
        preconditions, evidence_ids = self._authorization_error(task, contract, payload)
        target = validate_demo_target(str(payload.target_url))
        target_domain = urlparse(target).hostname or ""
        now = utc_now()
        action = ActionContract(
            action_id=f"action_{uuid4().hex[:12]}",
            task_id=task.id,
            contract_version=contract.version,
            action_type=payload.action_type,
            target_url=target,
            target_domain=target_domain,
            target_description="Submit the approved selection to the local ProofPilot demo form.",
            payload=payload.payload,
            preconditions=preconditions,
            associated_requirement_ids=list(dict.fromkeys(payload.associated_requirement_ids)),
            associated_evidence_ids=evidence_ids,
            expected_postconditions=[
                ActionCondition(
                    condition_id="demo_record_exists",
                    description="A demo submission record exists after execution.",
                ),
                ActionCondition(
                    condition_id="approved_payload_matches_record",
                    description="The stored fields match the exact approved payload.",
                ),
                ActionCondition(
                    condition_id="receipt_id_exists",
                    description="The resulting demo record has a unique receipt identifier.",
                ),
            ],
            prohibited_effects=[
                "No purchase or financial transaction.",
                "No third-party website submission.",
                "No account change, message, or external side effect.",
            ],
            permission_context=ActionPermissionContext(
                task_id=task.id,
                contract_version=contract.version,
                proof_action=ActionType.SUBMIT_FORM,
                requires_approval=True,
                target_policy=TARGET_POLICY_ID,
                target_domain=target_domain,
            ),
            status=ActionContractStatus.PREPARED,
            created_at=now,
            expires_at=now + ACTION_TTL,
            idempotency_key=f"idem_{uuid4().hex}",
            approval_digest="0" * 64,
        )
        action.approval_digest = approval_digest(action)

        def issue(existing_actions: list[ActionContract]) -> None:
            if any(
                item.status in ACTIVE_ACTION_STATUSES
                and not (
                    item.status in {ActionContractStatus.PENDING_APPROVAL, ActionContractStatus.APPROVED}
                    and now >= item.expires_at
                )
                for item in existing_actions
            ):
                raise ValueError("This task already has an active or completed demo ActionContract.")
            version = max((item.warrant.plan.version for item in existing_actions if item.warrant), default=0) + 1
            action.warrant = self.warrant_signer.issue(action, contract, version)
            self._transition(
                action,
                ActionContractStatus.PENDING_APPROVAL,
                "Exact action data and sandbox plan were bound to a signed Warrant.",
                "agent",
                persist=False,
            )

        if self.store:
            self.store.create_prepared_action(action, issue)
        else:
            issue(await self.list_for_task(task.id))
        self.actions[action.action_id] = action
        return deepcopy(action)

    def _expire_if_needed(self, action: ActionContract) -> None:
        if utc_now() >= action.expires_at and action.status in {
            ActionContractStatus.PENDING_APPROVAL,
            ActionContractStatus.APPROVED,
        }:
            self._transition(action, ActionContractStatus.EXPIRED, "The action approval window expired.", "system")
            raise PermissionError("The ActionContract has expired.")

    def _validate_action_context(
        self,
        action: ActionContract,
        task: TaskResponse,
        contract: ProofContract,
    ) -> None:
        if task.id != action.task_id or contract.task_id != action.task_id:
            raise PermissionError("The action, task, and ProofContract association does not match.")
        if contract.version != action.contract_version or task.contract_version != action.contract_version:
            raise PermissionError("The task ProofContract changed; this action must be prepared again.")
        if ActionType.SUBMIT_FORM in contract.prohibited_actions:
            raise PermissionError("The current ProofContract prohibits this action.")
        if (
            ActionType.SUBMIT_FORM not in contract.allowed_actions
            or ActionType.SUBMIT_FORM not in contract.requires_approval_for
        ):
            raise PermissionError("The current ProofContract no longer authorizes this action.")
        if (
            contract.clarification_required_before_research
            or contract.clarification_required_before_execution
            or any(item.blocking_stage in {"research", "execution"} for item in contract.ambiguities)
        ):
            raise PermissionError("A blocking ProofContract ambiguity invalidated this action.")
        if task.status != TaskStatus.COMPLETED or not task.research_report:
            raise PermissionError("The completed research precondition is no longer satisfied.")
        if task.research_report.status != ResearchReportStatus.COMPLETED:
            raise PermissionError("The task no longer has a completed compliance report.")
        request = ActionContractCreateRequest(
            action_type=action.action_type,
            target_url=action.target_url,
            payload=action.payload,
            associated_requirement_ids=action.associated_requirement_ids,
            associated_evidence_ids=action.associated_evidence_ids,
        )
        preconditions, _ = self._authorization_error(task, contract, request)
        if [item.model_dump(mode="json") for item in preconditions] != [
            item.model_dump(mode="json") for item in action.preconditions
        ]:
            raise PermissionError("The prepared action preconditions no longer match current research.")

    def _invalidate(self, action: ActionContract, reason: str) -> None:
        if action.status in {ActionContractStatus.PREPARED, ActionContractStatus.PENDING_APPROVAL, ActionContractStatus.APPROVED}:
            action.approved_warrant_hash = None
            self._transition(action, ActionContractStatus.INVALIDATED, reason, "system")

    def _verify_approved_digest(self, action: ActionContract) -> None:
        recomputed = approval_digest(action)
        if recomputed != action.approval_digest or action.approved_digest != action.approval_digest:
            raise PermissionError("The approved action changed and its approval is invalidated.")

    def _verified_warrant(
        self, action: ActionContract, contract: ProofContract | None, *, approved: bool = False
    ) -> SignedWarrant:
        if action.warrant is None:
            raise WarrantError("warrant_required", "Prepare and approve a signed Warrant for this action.")
        self.warrant_signer.validate(action.warrant, action, contract)
        if approved and (
            not action.approved_warrant_hash
            or not compare_digest(action.approved_warrant_hash, action.warrant.contract_hash)
        ):
            raise WarrantError("warrant_approval_mismatch", "Approval does not match the current Warrant. Prepare and approve the action again.")
        return action.warrant

    def _validate_execution_claim(
        self,
        action: ActionContract,
        task: TaskResponse | None,
        contract: ProofContract | None,
    ) -> list[PolicyDecision]:
        """Recheck persisted authorization inside SQLite's atomic execution claim."""
        if task is None or contract is None:
            raise PermissionError("The current task and ProofContract are unavailable for execution.")
        self._validate_action_context(action, task, contract)
        validate_demo_target(str(action.target_url))
        if (
            approval_digest(action) != action.approval_digest
            or action.approved_digest != action.approval_digest
        ):
            raise PermissionError("The approved action digest changed before execution was claimed.")
        self._verified_warrant(action, contract, approved=True)
        return authorize_plan(
            self.policy_engine,
            action,
            task,
            contract,
            lambda _decision: None,
            phase="claim",
        )

    async def _decide_action_contract(
        self,
        action_id: str,
        approve: bool,
        task: TaskResponse,
        contract: ProofContract,
        warrant_hash: str | None,
    ) -> Optional[ActionContract]:
        action = await self.get_action(action_id)
        if action is None:
            return None
        if not approve and action.warrant is None and action.status == ActionContractStatus.APPROVED:
            self._invalidate(action, "The user discarded an unsigned legacy action.")
            return deepcopy(action)
        if action.status != ActionContractStatus.PENDING_APPROVAL:
            raise ValueError("Only a pending ActionContract can be approved or rejected.")
        self._expire_if_needed(action)
        if not approve:
            self._transition(action, ActionContractStatus.REJECTED, "User rejected the ActionContract.", "user")
            return deepcopy(action)
        try:
            self._validate_action_context(action, task, contract)
            if approval_digest(action) != action.approval_digest:
                raise PermissionError("The prepared action no longer matches its approval digest.")
            warrant = self._verified_warrant(action, contract)
        except (PermissionError, WarrantError) as exc:
            self._invalidate(action, str(exc))
            raise

        if not isinstance(warrant_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", warrant_hash):
            raise WarrantError("warrant_hash_required", "Approval requires the exact reviewed Warrant hash.")
        if not compare_digest(warrant_hash, warrant.contract_hash):
            raise WarrantError("warrant_approval_mismatch", "The submitted Warrant hash does not match the current Warrant.")
        action.approved_digest = action.approval_digest
        action.approved_warrant_hash = warrant.contract_hash
        action.approved_at = utc_now()
        self._transition(action, ActionContractStatus.APPROVED, "User approved the exact signed Warrant and ActionContract digest.", "user")
        return deepcopy(action)

    def _make_receipt(
        self,
        action: ActionContract,
        status: ActionContractStatus,
        *,
        detail: str,
        actor: str = "verifier",
        attempted: bool,
        completed: bool,
        record_id: str | None,
        verified: list[str],
        failed: list[str],
        error: str | None,
        verification_status: VerificationStatus,
    ) -> ExecutionReceipt:
        action = deepcopy(action)
        self._transition(action, status, detail, actor, persist=False)
        existing = self.receipts.get(action.action_id)
        receipt = ExecutionReceipt(
            receipt_id=existing.receipt_id if existing else f"receipt_{uuid4().hex[:12]}",
            task_id=action.task_id,
            action_id=action.action_id,
            action_type=action.action_type,
            approved_digest=action.approved_digest or action.approval_digest,
            approved_warrant_hash=action.approved_warrant_hash,
            execution_status=status,
            approval_timestamp=action.approved_at or action.created_at,
            execution_timestamp=existing.execution_timestamp if existing else utc_now() if attempted else None,
            verification_timestamp=utc_now() if verification_status != VerificationStatus.UNVERIFIED else None,
            target_url=action.target_url,
            payload=action.payload,
            resulting_record_id=record_id,
            action_attempted=attempted,
            action_completed=completed,
            outcome_verified=verification_status != VerificationStatus.UNVERIFIED,
            verified_postconditions=[*verified, "receipt_id_exists"] if self.store else verified,
            failed_postconditions=failed,
            evidence_used=action.associated_evidence_ids,
            execution_error=error,
            verification_status=verification_status,
        )
        action.execution_receipt_id = receipt.receipt_id
        if self.store:
            self.store.save_action(action, receipt=receipt)
        self.actions[action.action_id] = action
        self.receipts[action.action_id] = receipt
        return receipt

    async def _execute_action_contract(
        self,
        action_id: str,
        task: TaskResponse,
        contract: ProofContract,
    ) -> Optional[ExecutionReceipt]:
        action = await self.get_action(action_id)
        if action is None:
            return None
        lock = self._action_locks.setdefault(action_id, asyncio.Lock())
        async with lock:
            refreshed = await self.get_action(action_id)
            if refreshed is not None:
                action = refreshed
                self.actions[action_id] = action
            if action.status == ActionContractStatus.VERIFIED_SUCCESS:
                receipt = await self.get_receipt(action_id)
                if receipt is None:
                    raise ValueError("The verified action has no persisted execution receipt.")
                return receipt
            if action.status == ActionContractStatus.OUTCOME_UNKNOWN:
                decision = self.policy_engine.denial(
                    action, action.warrant, rule_id="LIFECYCLE_STATE",
                    reason="Outcome is unknown; reconcile before further execution.", phase="preflight",
                )
                self._record_policy_decision(decision)
                raise ValueError("The outcome is unknown; reconcile it before taking any further action.")
            if action.status == ActionContractStatus.EXECUTING:
                decision = self.policy_engine.denial(
                    action, action.warrant, rule_id="LIFECYCLE_STATE",
                    reason="Another worker has already claimed this action.", phase="preflight",
                )
                self._record_policy_decision(decision)
                raise ValueError("Another backend worker already claimed this action for execution.")
            if action.status != ActionContractStatus.APPROVED:
                decision = self.policy_engine.denial(
                    action, action.warrant, rule_id="APPROVAL_BINDING",
                    reason="Action approval is missing or no longer active.", phase="preflight",
                )
                self._record_policy_decision(decision)
                raise PermissionError("Only an approved ActionContract can execute.")
            try:
                self._expire_if_needed(action)
            except PermissionError as exc:
                decision = self.policy_engine.denial(
                    action, action.warrant, rule_id="WARRANT_EXPIRY",
                    reason=str(exc), phase="preflight",
                )
                self._record_policy_decision(decision)
                raise PolicyDenied(decision) from exc
            try:
                self._validate_action_context(action, task, contract)
            except (PermissionError, WarrantError, ValueError) as exc:
                decision = self.policy_engine.denial(
                    action, action.warrant, rule_id="ACTION_CONTEXT",
                    reason=str(exc), phase="preflight",
                )
                self._record_policy_decision(decision)
                self._invalidate(action, str(exc))
                raise PolicyDenied(decision) from exc

            try:
                authorize_plan(
                    self.policy_engine,
                    action,
                    task,
                    contract,
                    self._record_policy_decision,
                    phase="preflight",
                )
            except PolicyDenied as exc:
                self._invalidate(action, str(exc))
                raise

            warrant = action.warrant
            if warrant is None:
                decision = self.policy_engine.denial(
                    action, None, rule_id="WARRANT_MISSING",
                    reason="A signed Warrant is required before execution.", phase="preflight",
                )
                self._record_policy_decision(decision)
                raise PolicyDenied(decision)

            existing = (
                self.store.get_demo_submission_by_idempotency(action.idempotency_key)
                if self.store
                else None
            )
            existing_id = (
                existing.get("submission_id") if existing
                else self.idempotency_index.get(action.idempotency_key)
            )

            if self.store:
                try:
                    claimed = self.store.claim_action_execution(
                        action_id,
                        action.approval_digest,
                        expected_warrant_hash=warrant.contract_hash,
                        validate=self._validate_execution_claim,
                    )
                except (PermissionError, WarrantError, ValueError) as exc:
                    if isinstance(exc, PolicyDenied):
                        decision = exc.decision
                    else:
                        decision = self.policy_engine.denial(
                            action, action.warrant, rule_id="ATOMIC_CLAIM",
                            reason=str(exc), phase="claim",
                        )
                    self._record_policy_decision(decision)
                    refreshed = await self.get_action(action_id)
                    if refreshed:
                        self._invalidate(refreshed, str(exc))
                    if isinstance(exc, PolicyDenied):
                        raise
                    raise PolicyDenied(decision) from exc
                if claimed is None:
                    latest = await self.get_action(action_id)
                    if latest and latest.status == ActionContractStatus.VERIFIED_SUCCESS:
                        receipt = await self.get_receipt(action_id)
                        if receipt is not None:
                            return receipt
                    if latest and latest.status in {
                        ActionContractStatus.EXECUTING,
                        ActionContractStatus.OUTCOME_UNKNOWN,
                    }:
                        decision = self.policy_engine.denial(
                            latest, latest.warrant, rule_id="LIFECYCLE_STATE",
                            reason="Another backend worker claimed this action; execution was not repeated.",
                            phase="claim",
                        )
                        self._record_policy_decision(decision)
                        raise ValueError("Another backend worker claimed this action; reconcile or reload its status.")
                    expired = bool(latest and latest.status == ActionContractStatus.EXPIRED)
                    decision = self.policy_engine.denial(
                        latest or action,
                        latest.warrant if latest else action.warrant,
                        rule_id="WARRANT_EXPIRY" if expired else "ATOMIC_CLAIM",
                        reason="The action expired before its atomic execution claim." if expired else "The action is no longer approved for execution.",
                        phase="claim",
                    )
                    self._record_policy_decision(decision)
                    raise PolicyDenied(decision)
                action = claimed
                self.actions[action_id] = action
            else:
                try:
                    claim_decisions = self._validate_execution_claim(action, task, contract)
                except PolicyDenied as exc:
                    self._record_policy_decision(exc.decision)
                    self._invalidate(action, str(exc))
                    raise
                except (PermissionError, WarrantError, ValueError) as exc:
                    decision = self.policy_engine.denial(
                        action, action.warrant, rule_id="ATOMIC_CLAIM",
                        reason=str(exc), phase="claim",
                    )
                    self._record_policy_decision(decision)
                    self._invalidate(action, str(exc))
                    raise PolicyDenied(decision) from exc
                for decision in claim_decisions:
                    self._record_policy_decision(decision)
                self._transition(action, ActionContractStatus.EXECUTING, "Executing the approved local demo submission.", "agent")

            policy_execution = PolicyExecution(
                self.policy_engine,
                action,
                task,
                contract,
                self._record_policy_decision,
                phase="execution",
            )

            if existing_id:
                existing_record = existing or self.demo_records.get(existing_id)
                if existing_record is not None:
                    matches, verified, failed = verify_demo_record(action, existing_id, existing_record)
                    status = ActionContractStatus.VERIFIED_SUCCESS if matches else ActionContractStatus.VERIFIED_FAILURE
                    receipt = self._make_receipt(
                        action,
                        status,
                        detail="Existing demo record was reconciled against the approved payload.",
                        attempted=False,
                        completed=True,
                        record_id=existing_id,
                        verified=verified,
                        failed=failed,
                        error=None if matches else "Existing record did not match the approved payload.",
                        verification_status=VerificationStatus.SUPPORTED if matches else VerificationStatus.CONTRADICTED,
                    )
                    return deepcopy(receipt)
                receipt = self._make_receipt(
                    action,
                    ActionContractStatus.OUTCOME_UNKNOWN,
                    detail="An idempotency record ID exists but its record cannot be read; resubmission is blocked.",
                    attempted=True,
                    completed=False,
                    record_id=existing_id,
                    verified=[],
                    failed=["demo_record_exists", "approved_payload_matches_record"],
                    error="The existing idempotency record could not be read. The action was not retried.",
                    verification_status=VerificationStatus.UNVERIFIED,
                )
                return deepcopy(receipt)

            try:
                if self._default_executor and self.executor is self._default_executor_callable:
                    result = await execute_demo_submission(
                        action,
                        browser_provider=self.browser_provider,
                        policy_gate=policy_execution,
                        adversarial_demo=task.task.startswith("SIMULATED DEMO:"),
                    )
                else:
                    result = await self.executor(action)
            except PolicyDenied as exc:
                attempted = policy_execution.action_attempted
                receipt = self._make_receipt(
                    action,
                    ActionContractStatus.OUTCOME_UNKNOWN if attempted else ActionContractStatus.VERIFIED_FAILURE,
                    detail="Policy denied a browser step; no further action was allowed.",
                    actor="policy",
                    attempted=attempted,
                    completed=False,
                    record_id=None,
                    verified=[],
                    failed=["policy_authorized", "demo_record_exists", "approved_payload_matches_record"],
                    error=exc.decision.reason,
                    verification_status=VerificationStatus.UNVERIFIED,
                )
                return deepcopy(receipt)
            except (Exception, asyncio.CancelledError) as exc:
                cancelled = isinstance(exc, asyncio.CancelledError)
                if not cancelled:
                    logger.error("Controlled action %s failed (%s).", action_id, type(exc).__name__)
                receipt = self._make_receipt(
                    action,
                    ActionContractStatus.OUTCOME_UNKNOWN,
                    detail="Execution stopped after the action was claimed; blind retry is blocked.",
                    actor="agent",
                    attempted=True,
                    completed=False,
                    record_id=None,
                    verified=[],
                    failed=["demo_record_exists", "approved_payload_matches_record"],
                    error="Execution was cancelled." if cancelled else "Execution failed unexpectedly. Reconcile before proceeding.",
                    verification_status=VerificationStatus.UNVERIFIED,
                )
                if cancelled:
                    raise
                return deepcopy(receipt)

            if not result.action_attempted:
                status = ActionContractStatus.VERIFIED_FAILURE
                receipt = self._make_receipt(
                    action,
                    status,
                    detail="The controlled form action was not attempted.",
                    attempted=False,
                    completed=False,
                    record_id=None,
                    verified=[],
                    failed=["demo_record_exists", "approved_payload_matches_record"],
                    error=result.error or "Execution failed before submission.",
                    verification_status=VerificationStatus.UNVERIFIED,
                )
                return deepcopy(receipt)

            if not result.action_completed or not result.record_id or result.observed_record is None:
                receipt = self._make_receipt(
                    action,
                    ActionContractStatus.OUTCOME_UNKNOWN,
                    detail="Submission may have occurred, but its resulting state is not established.",
                    attempted=True,
                    completed=result.action_completed,
                    record_id=result.record_id,
                    verified=[],
                    failed=["demo_record_exists", "approved_payload_matches_record"],
                    error=result.error or "The resulting demo state could not be independently read.",
                    verification_status=VerificationStatus.UNVERIFIED,
                )
                return deepcopy(receipt)

            if self._default_executor and self.executor is self._default_executor_callable:
                extract_step = next(step for step in warrant.plan.steps if step.id == "extract_record")
                readback_target = build_readback_url(str(action.target_url), result.record_id)
                try:
                    policy_execution.authorize_step(
                        extract_step.id,
                        "extract",
                        readback_target,
                        extract_step.parameters.model_dump(mode="json"),
                    )
                except PolicyDenied as exc:
                    receipt = self._make_receipt(
                        action,
                        ActionContractStatus.OUTCOME_UNKNOWN,
                        detail="Policy denied verification extraction after submission; reconcile the result.",
                        actor="policy",
                        attempted=True,
                        completed=True,
                        record_id=result.record_id,
                        verified=[],
                        failed=["policy_authorized", "approved_payload_matches_record"],
                        error=exc.decision.reason,
                        verification_status=VerificationStatus.UNVERIFIED,
                    )
                    return deepcopy(receipt)

            matches, verified, failed = verify_demo_record(action, result.record_id, result.observed_record)
            status = ActionContractStatus.VERIFIED_SUCCESS if matches else ActionContractStatus.VERIFIED_FAILURE
            receipt = self._make_receipt(
                action,
                status,
                detail="Independent demo record readback completed.",
                attempted=True,
                completed=True,
                record_id=result.record_id,
                verified=verified,
                failed=failed,
                error=result.error if not matches else None,
                verification_status=VerificationStatus.SUPPORTED if matches else VerificationStatus.CONTRADICTED,
            )
            return deepcopy(receipt)

    async def reconcile(self, action_id: str) -> Optional[ExecutionReceipt]:
        action = await self.get_action(action_id)
        if action is None:
            return None
        lock = self._action_locks.setdefault(action_id, asyncio.Lock())
        async with lock:
            refreshed = await self.get_action(action_id)
            if refreshed is not None:
                action = refreshed
                self.actions[action_id] = action
            if action.status != ActionContractStatus.OUTCOME_UNKNOWN:
                raise ValueError("Only an uncertain action outcome can be reconciled.")
            receipt = await self.get_receipt(action_id)
            stored_record = (
                self.store.get_demo_submission_by_idempotency(action.idempotency_key)
                if self.store
                else None
            )
            record_id = (
                stored_record.get("submission_id") if stored_record
                else self.idempotency_index.get(action.idempotency_key)
            )
            record = stored_record or (self.demo_records.get(record_id) if record_id else None)
            if not receipt:
                raise ValueError("The execution receipt is missing; this action cannot be reconciled safely.")
            if record_id is None or record is None:
                receipt.execution_error = "No demo record is currently indexed for this idempotency key. The action was not retried."
                if self.store:
                    self.store.save_receipt(receipt)
                self.receipts[action_id] = receipt
                return deepcopy(receipt)

            matches, verified, failed = verify_demo_record(action, record_id, record)
            status = ActionContractStatus.VERIFIED_SUCCESS if matches else ActionContractStatus.VERIFIED_FAILURE
            updated = self._make_receipt(
                action,
                status,
                detail="Idempotency record was read and reconciled without resubmission.",
                attempted=receipt.action_attempted,
                completed=True,
                record_id=record_id,
                verified=verified,
                failed=failed,
                error=None if matches else "The existing record did not match the approved payload.",
                verification_status=VerificationStatus.SUPPORTED if matches else VerificationStatus.CONTRADICTED,
            )
            return deepcopy(updated)

    async def record_demo_submission(
        self,
        idempotency_key: str | None,
        payload: dict,
    ) -> dict:
        if not idempotency_key:
            raise PermissionError("Demo submissions require a backend-approved ActionContract.")
        self.authorize_demo_submission(idempotency_key, payload)
        if self.store:
            record = self.store.create_demo_submission(idempotency_key, payload)
            submission_id = record["submission_id"]
            self.demo_records[submission_id] = deepcopy(record)
            self.idempotency_index[idempotency_key] = submission_id
            return deepcopy(record)

        existing_id = self.idempotency_index.get(idempotency_key)
        if existing_id:
            existing = self.demo_records[existing_id]
            if any(str(existing.get(key, "")) != str(value) for key, value in payload.items()):
                raise ValueError("This idempotency key was already used with a different payload.")
            return deepcopy(existing)

        submission_id = f"demo_{uuid4().hex[:12]}"
        record = dict(payload)
        record["submission_id"] = submission_id
        self.demo_records[submission_id] = record
        self.idempotency_index[idempotency_key] = submission_id
        return deepcopy(record)

    def authorize_demo_submission(self, idempotency_key: str, payload: dict) -> None:
        if self.store:
            action = next(
                (item for item in self.store.list_actions() if item.idempotency_key == idempotency_key),
                None,
            )
            if action is not None:
                self.actions[action.action_id] = action
        else:
            action = next(
                (item for item in self.actions.values() if item.idempotency_key == idempotency_key),
                None,
            )
        if action is None or action.status != ActionContractStatus.EXECUTING:
            raise PermissionError("No executing, backend-approved ActionContract authorizes this demo submission.")
        if approval_digest(action) != action.approval_digest or action.approved_digest != action.approval_digest:
            self._invalidate(action, "The demo endpoint rejected a payload after digest mismatch.")
            raise PermissionError("The approved action digest does not match the current action data.")
        approved_payload = action.payload.model_dump(mode="json")
        if approved_payload != payload:
            raise PermissionError("The submitted form data differs from the exact approved payload.")
