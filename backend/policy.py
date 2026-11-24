"""Deterministic policy gate for the controlled, signed local browser plan."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Literal, Mapping
from urllib.parse import urlsplit
from uuid import uuid4

from pydantic import BaseModel, ConfigDict

from action_digest import approval_digest
from models import ActionContract, ActionType, ProofContract, ResearchReportStatus, TaskResponse, TaskStatus
from warrant import WarrantError, WarrantSigner
from warrant_models import (
    DEMO_RECORD_ID_PATTERN,
    SignedWarrant,
    ValidatedPlan,
)


Decision = Literal["allow", "deny", "escalate"]
PolicyPhase = Literal["preflight", "claim", "execution"]
_READBACK_PATH = re.compile(r"^/demo/selections/" + DEMO_RECORD_ID_PATTERN + r"$")


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    decision_id: str
    task_id: str
    action_id: str
    warrant_id: str | None
    contract_hash: str | None
    action_type: str
    step_id: str | None
    target: str
    phase: PolicyPhase
    rule_id: str
    decision: Decision
    reason: str
    timestamp: datetime
    source: Literal["approved_plan", "sandbox_page_injection", "network_guard"] = "approved_plan"
    source_excerpt: str | None = None


@dataclass(frozen=True)
class PolicyState:
    task: TaskResponse | None
    proof_contract: ProofContract | None
    next_step_index: int
    phase: PolicyPhase


class PolicyDenied(PermissionError):
    def __init__(self, decision: PolicyDecision) -> None:
        super().__init__(decision.reason)
        self.decision = decision


def normalize_domain(host: str | None) -> str | None:
    if not host:
        return None
    value = host.rstrip(".").lower()
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _safe_target(target: str | None) -> str:
    if not isinstance(target, str):
        return "unavailable"
    try:
        parts = urlsplit(target)
        host = normalize_domain(parts.hostname)
        if not parts.scheme or not host:
            return "unparseable target"
        try:
            port = parts.port
        except ValueError:
            return f"{parts.scheme}://{host}/invalid-port"
        netloc = host + (f":{port}" if port is not None else "")
        path = parts.path[:300] or "/"
        return f"{parts.scheme}://{netloc}{path}"
    except (TypeError, ValueError):
        return "unparseable target"


class PolicyEngine:
    """Checks the signed plan, approved ActionContract, step order and parameters."""

    def __init__(self, signer: WarrantSigner) -> None:
        self.signer = signer

    def _decision(
        self,
        action: ActionContract,
        warrant: SignedWarrant | None,
        *,
        decision: Decision,
        rule_id: str,
        reason: str,
        action_type: str,
        step_id: str | None,
        target: str | None,
        phase: PolicyPhase,
    ) -> PolicyDecision:
        return PolicyDecision(
            decision_id=f"policy_{uuid4().hex}",
            task_id=action.task_id,
            action_id=action.action_id,
            warrant_id=warrant.warrant_id if warrant else None,
            contract_hash=warrant.contract_hash if warrant else None,
            action_type=action_type,
            step_id=step_id,
            target=_safe_target(target),
            phase=phase,
            rule_id=rule_id,
            decision=decision,
            reason=reason,
            timestamp=datetime.now(timezone.utc),
        )

    def denial(
        self,
        action: ActionContract,
        warrant: SignedWarrant | None,
        *,
        rule_id: str,
        reason: str,
        phase: PolicyPhase = "preflight",
        action_type: str | None = None,
        step_id: str | None = None,
        target: str | None = None,
    ) -> PolicyDecision:
        return self._decision(
            action,
            warrant,
            decision="deny",
            rule_id=rule_id,
            reason=reason,
            action_type=action_type or action.action_type.value,
            step_id=step_id,
            target=target or str(action.target_url),
            phase=phase,
        )

    @staticmethod
    def _target_matches(plan: ValidatedPlan, step, target: str) -> bool:
        try:
            actual = urlsplit(target)
            if actual.scheme != "http" or actual.username or actual.password or actual.query or actual.fragment:
                return False
            host = normalize_domain(actual.hostname)
            if host not in {"127.0.0.1", "localhost"}:
                return False
            actual_port = actual.port or 80

            params = step.parameters
            if hasattr(params, "url"):
                approved_url = params.url
                approved = urlsplit(approved_url)
                return (
                    target == approved_url
                    and normalize_domain(actual.hostname) == normalize_domain(approved.hostname)
                    and actual_port == (approved.port or 80)
                )

            if hasattr(params, "url_template"):
                template = params.url_template
            elif hasattr(params, "source_step_id"):
                source = next(item for item in plan.steps if item.id == params.source_step_id)
                template = source.parameters.url_template
            else:
                return False
            approved = urlsplit(template.replace("{record_id}", "record-id"))
            if host != normalize_domain(approved.hostname) or actual_port != (approved.port or 80):
                return False
            if "{record_id}" in template:
                if target == template:
                    return True
                return bool(_READBACK_PATH.fullmatch(actual.path))
            return target == template
        except (TypeError, ValueError):
            return False

    def check(
        self,
        action: ActionContract,
        warrant: SignedWarrant,
        state: PolicyState,
        *,
        step_id: str,
        action_type: str,
        target: str,
        parameters: Mapping,
    ) -> PolicyDecision:
        """Return a recorded allow/deny decision for one exact plan step."""
        phase = state.phase
        try:
            if state.task is None or state.proof_contract is None:
                return self.denial(action, warrant, rule_id="CURRENT_CONTRACT", reason="Task or ProofContract is unavailable.", phase=phase, action_type=action_type, step_id=step_id, target=target)
            if action.status.value not in {"APPROVED", "EXECUTING"}:
                return self.denial(action, warrant, rule_id="LIFECYCLE_STATE", reason=f"Action lifecycle state {action.status.value} is not authorized for execution.", phase=phase, action_type=action_type, step_id=step_id, target=target)
            if state.task.id != action.task_id or state.proof_contract.task_id != action.task_id or state.proof_contract.version != action.contract_version:
                return self.denial(action, warrant, rule_id="CURRENT_CONTRACT", reason="Task and ProofContract do not match the prepared action.", phase=phase, action_type=action_type, step_id=step_id, target=target)
            if (
                state.task.status != TaskStatus.COMPLETED
                or state.task.research_report is None
                or state.task.research_report.status != ResearchReportStatus.COMPLETED
                or ActionType.SUBMIT_FORM in state.proof_contract.prohibited_actions
                or ActionType.SUBMIT_FORM not in state.proof_contract.allowed_actions
                or ActionType.SUBMIT_FORM not in state.proof_contract.requires_approval_for
                or state.proof_contract.clarification_required_before_execution
                or any(item.blocking_stage == "execution" for item in state.proof_contract.ambiguities)
            ):
                return self.denial(action, warrant, rule_id="CURRENT_CONTRACT", reason="Task research or the current ProofContract no longer authorizes this action.", phase=phase, action_type=action_type, step_id=step_id, target=target)
            if approval_digest(action) != action.approval_digest or action.approved_digest != action.approval_digest:
                return self.denial(action, warrant, rule_id="ACTION_DIGEST", reason="The current ActionContract does not match its approved digest.", phase=phase, action_type=action_type, step_id=step_id, target=target)
            try:
                self.signer.validate(warrant, action, state.proof_contract)
            except WarrantError as exc:
                rule = "WARRANT_EXPIRY" if exc.code == "warrant_expired" else "WARRANT_INTEGRITY"
                return self.denial(action, warrant, rule_id=rule, reason=exc.message, phase=phase, action_type=action_type, step_id=step_id, target=target)
            if action.approved_warrant_hash != warrant.contract_hash:
                return self.denial(action, warrant, rule_id="APPROVAL_BINDING", reason="Approval is missing or bound to a different Warrant hash.", phase=phase, action_type=action_type, step_id=step_id, target=target)

            # Reject an external origin before evaluating plan order so that an
            # injected off-domain attempt is recorded as a domain boundary denial.
            authorized_domains = {normalize_domain(item) for item in warrant.allowed_domains}
            try:
                target_host = normalize_domain(urlsplit(target).hostname)
            except (TypeError, ValueError):
                target_host = None
            if target_host not in {"127.0.0.1", "localhost"} or target_host not in authorized_domains:
                return self.denial(action, warrant, rule_id="DOMAIN_BOUNDARY", reason="Target is outside the exact authorized loopback step.", phase=phase, action_type=action_type, step_id=step_id, target=target)

            plan: ValidatedPlan = warrant.plan
            if not 0 <= state.next_step_index < len(plan.steps):
                return self.denial(action, warrant, rule_id="PLAN_ORDER", reason="No further action is authorized by this plan.", phase=phase, action_type=action_type, step_id=step_id, target=target)
            expected = plan.steps[state.next_step_index]
            if expected.id != step_id or step_id not in warrant.authorized_steps:
                return self.denial(action, warrant, rule_id="PLAN_ORDER", reason="Action identifier or ordering differs from the approved plan.", phase=phase, action_type=action_type, step_id=step_id, target=target)
            if action_type != expected.action_type or action_type not in warrant.allowed_action_types:
                return self.denial(action, warrant, rule_id="ACTION_TYPE", reason="Action type is not authorized for this approved step.", phase=phase, action_type=action_type, step_id=step_id, target=target)

            expected_domain = normalize_domain(expected.target_domain)
            authorized_domains = {normalize_domain(item) for item in warrant.allowed_domains}
            try:
                target_host = normalize_domain(urlsplit(target).hostname)
            except ValueError:
                target_host = None
            if (
                expected_domain not in {"127.0.0.1", "localhost"}
                or expected_domain not in authorized_domains
                or expected_domain != normalize_domain(action.target_domain)
                or target_host != expected_domain
                or not self._target_matches(plan, expected, target)
            ):
                return self.denial(action, warrant, rule_id="DOMAIN_BOUNDARY", reason="Target is outside the exact authorized loopback step.", phase=phase, action_type=action_type, step_id=step_id, target=target)

            expected_parameters = expected.parameters.model_dump(mode="json")
            constraints = warrant.step_parameter_constraints.get(step_id)
            constraint_parameters = constraints.model_dump(mode="json") if hasattr(constraints, "model_dump") else None
            if (
                not isinstance(parameters, Mapping)
                or dict(parameters) != expected_parameters
                or constraint_parameters != expected_parameters
            ):
                return self.denial(action, warrant, rule_id="PARAMETER_BOUNDARY", reason="Action parameters differ from the exact approved step constraints.", phase=phase, action_type=action_type, step_id=step_id, target=target)

            return self._decision(
                action, warrant, decision="allow", rule_id="APPROVED_PLAN_STEP",
                reason="Action matches the current approved Warrant step.",
                action_type=action_type, step_id=step_id, target=target, phase=phase,
            )
        except Exception:
            return self.denial(
                action, warrant, rule_id="POLICY_INTERNAL_ERROR",
                reason="Policy evaluation failed; execution was denied.", phase=phase,
                action_type=action_type, step_id=step_id, target=target,
            )


class PolicyExecution:
    """Maintains ordered per-step checks during the fixed browser workflow."""

    def __init__(
        self,
        engine: PolicyEngine,
        action: ActionContract,
        task: TaskResponse,
        proof_contract: ProofContract,
        record: Callable[[PolicyDecision], None],
        *,
        phase: PolicyPhase = "execution",
    ) -> None:
        self.engine = engine
        self.action = action
        self.warrant = action.warrant
        self.task = task
        self.proof_contract = proof_contract
        self.record = record
        self.phase = phase
        self.next_step_index = 0
        self.action_attempted = False
        self.submission_request_seen = False
        self.blocked_decision: PolicyDecision | None = None
        if self.warrant is None:
            decision = engine.denial(action, None, rule_id="WARRANT_MISSING", reason="A signed Warrant is required before browser execution.", phase=phase)
            self._record_or_fail(decision)
            raise PolicyDenied(decision)

    def _record_or_fail(self, decision: PolicyDecision) -> None:
        try:
            self.record(decision)
        except Exception as exc:
            raise PolicyDenied(self.engine.denial(
                self.action, self.warrant, rule_id="POLICY_AUDIT_UNAVAILABLE",
                reason="Policy audit could not be persisted; execution was denied.",
                phase=self.phase, action_type=decision.action_type,
                step_id=decision.step_id, target=decision.target,
            )) from exc

    def authorize_step(
        self, step_id: str, action_type: str, target: str, parameters: Mapping,
    ) -> PolicyDecision:
        assert self.warrant is not None
        state = PolicyState(self.task, self.proof_contract, self.next_step_index, self.phase)
        try:
            decision = self.engine.check(
                self.action, self.warrant, state,
                step_id=step_id, action_type=action_type, target=target, parameters=parameters,
            )
        except Exception:
            decision = self.engine.denial(
                self.action, self.warrant, rule_id="POLICY_INTERNAL_ERROR",
                reason="Policy evaluation failed; execution was denied.",
                phase=self.phase, action_type=action_type, step_id=step_id, target=target,
            )
        self._record_or_fail(decision)
        if decision.decision != "allow":
            raise PolicyDenied(decision)
        self.next_step_index += 1
        return decision

    def attempt_untrusted_step(
        self,
        *,
        step_id: str,
        action_type: str,
        target: str,
        parameters: Mapping,
        instruction: str,
    ) -> PolicyDecision:
        """Evaluate and persist a page-originated attempt without dispatching it."""
        assert self.warrant is not None
        state = PolicyState(self.task, self.proof_contract, self.next_step_index, self.phase)
        try:
            decision = self.engine.check(
                self.action,
                self.warrant,
                state,
                step_id=step_id,
                action_type=action_type,
                target=target,
                parameters=parameters,
            ).model_copy(update={
                "source": "sandbox_page_injection",
                "source_excerpt": instruction[:600],
            })
        except Exception:
            decision = self.engine.denial(
                self.action,
                self.warrant,
                rule_id="POLICY_INTERNAL_ERROR",
                reason="Policy evaluation failed; the sandbox attempt was denied.",
                phase=self.phase,
                action_type=action_type,
                step_id=step_id,
                target=target,
            ).model_copy(update={
                "source": "sandbox_page_injection",
                "source_excerpt": instruction[:600],
            })
        if decision.decision == "allow":
            decision = self.engine.denial(
                self.action,
                self.warrant,
                rule_id="DEMO_ATTACK_FAIL_CLOSED",
                reason="The sandbox attempt was denied by the fail-closed demo boundary.",
                phase=self.phase,
                action_type=action_type,
                step_id=step_id,
                target=target,
            ).model_copy(update={
                "source": "sandbox_page_injection",
                "source_excerpt": instruction[:600],
            })
        self._record_or_fail(decision)
        return decision

    def mark_action_attempted(self) -> None:
        self.action_attempted = True

    def authorize_submission_request(self, target: str) -> bool:
        """Allow only the single POST bound to the already checked click step."""
        if self.warrant is None or not self.action_attempted or self.submission_request_seen:
            self.block_network_request(target, "No unused approved submit request is active.")
            return False
        click = next((step for step in self.warrant.plan.steps if step.id == "submit_form"), None)
        if click is None or target != click.parameters.request_url:
            self.block_network_request(target, "Submission target differs from the exact approved request URL.")
            return False
        self.submission_request_seen = True
        return True

    def block_network_request(self, target: str, reason: str) -> None:
        if self.blocked_decision is not None:
            return
        self.blocked_decision = self.engine.denial(
            self.action,
            self.warrant,
            rule_id="NETWORK_BOUNDARY",
            reason=reason,
            phase=self.phase,
            action_type="click" if self.action_attempted else "navigate",
            step_id="submit_form" if self.action_attempted else "open_form",
            target=target,
        ).model_copy(update={"source": "network_guard"})
        self._record_or_fail(self.blocked_decision)


def authorize_plan(
    engine: PolicyEngine,
    action: ActionContract,
    task: TaskResponse,
    proof_contract: ProofContract,
    record: Callable[[PolicyDecision], None],
    *,
    phase: PolicyPhase,
) -> list[PolicyDecision]:
    """Preflight every approved plan step in sequence before execution can be claimed."""
    run = PolicyExecution(engine, action, task, proof_contract, record, phase=phase)
    warrant = run.warrant
    assert warrant is not None
    decisions: list[PolicyDecision] = []
    for step in warrant.plan.steps:
        params = step.parameters
        if hasattr(params, "url"):
            target = params.url
        elif hasattr(params, "url_template"):
            target = params.url_template
        else:
            source = next(item for item in warrant.plan.steps if item.id == params.source_step_id)
            target = source.parameters.url_template
        decision = run.authorize_step(
            step.id,
            step.action_type,
            target,
            params.model_dump(mode="json"),
        )
        decisions.append(decision)
    return decisions
