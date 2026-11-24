"""Compile and sign an intent contract for the existing local sandbox adapter."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlsplit
from uuid import uuid4

from pydantic import BaseModel, ValidationError

from warrant_models import (
    DEMO_FILL_FIELDS,
    DEMO_FORM_PATH,
    DEMO_READBACK_FIELDS,
    DEMO_RECORD_TEMPLATE,
    DEMO_SUBMISSION_PATH,
    DEMO_SUBMIT_SELECTOR,
    SignedWarrant,
    ValidatedPlan,
    WarrantBody,
    sandbox_origin,
)

if TYPE_CHECKING:
    from models import ActionContract, ProofContract


SigningMode = Literal["configured", "local_demo", "disabled"]
_SIGNATURE_CONTEXT = b"ProofPilot/Warrant/HMAC-SHA256/v1\x00"
_LOCAL_DEMO_KEY = secrets.token_bytes(32)


class WarrantError(RuntimeError):
    def __init__(self, code: str, message: str, status_code: int = 409) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def canonical_json(value: BaseModel | Mapping) -> bytes:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_hash(value: BaseModel | Mapping) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def build_sandbox_plan(action: ActionContract, version: int = 1) -> ValidatedPlan:
    """Compile the exact supported form interaction, with no model-controlled parameters."""
    if action.action_type != "submit_demo_request" or not action.requires_approval:
        raise WarrantError("unsupported_action", "Only the approval-bound sandbox submission is supported.", 422)

    target = str(action.target_url)
    try:
        origin = sandbox_origin(target, DEMO_FORM_PATH)
        domain = urlsplit(origin).hostname
        if domain != action.target_domain:
            raise ValueError("Action domain does not match the sandbox origin.")
    except ValueError as exc:
        raise WarrantError("invalid_sandbox_target", "The action target is not the controlled sandbox form.", 422) from exc

    def step(step_id: str, action_type: str, parameters: dict, description: str) -> dict:
        return {
            "id": step_id,
            "action_type": action_type,
            "target_domain": domain,
            "parameters": parameters,
            "risk_level": "sandbox_write" if action_type in {"fill", "click"} else "read_only",
            "description": description,
        }

    steps = [
        step("open_form", "navigate", {"url": target, "method": "GET"}, "Open the local sandbox form."),
    ]
    for field, selector in DEMO_FILL_FIELDS:
        steps.append(step(
            f"fill_{field}", "fill",
            {"url": target, "field": field, "selector": selector, "value": getattr(action.payload, field)},
            f"Fill the approved {field} value.",
        ))
    steps.extend((
        step(
            "submit_form", "click",
            {
                "url": target, "selector": DEMO_SUBMIT_SELECTOR, "method": "POST",
                "request_url": origin + DEMO_SUBMISSION_PATH,
            },
            "Submit the approved payload to the local sandbox once.",
        ),
        step(
            "read_record", "read",
            {"url_template": origin + DEMO_RECORD_TEMPLATE, "method": "GET", "record_id_source": "submit_response"},
            "Read the persisted sandbox record by the returned identifier.",
        ),
        step(
            "extract_record", "extract",
            {"source_step_id": "read_record", "fields": DEMO_READBACK_FIELDS},
            "Extract the persisted record fields for comparison against the approved payload.",
        ),
    ))
    try:
        return ValidatedPlan(
            task_id=action.task_id,
            action_id=action.action_id,
            contract_version=action.contract_version,
            version=version,
            source="DETERMINISTIC_SANDBOX",
            steps=tuple(steps),
        )
    except ValidationError as exc:
        raise WarrantError("invalid_plan", "The action does not produce a valid sandbox plan.", 422) from exc


class WarrantSigner:
    def __init__(
        self,
        secret: bytes | None = None,
        *,
        mode: SigningMode = "configured",
    ) -> None:
        self.mode: SigningMode = "disabled"
        self._secret: bytes | None = None
        if mode == "disabled":
            return
        if secret is None and mode == "local_demo":
            secret = _LOCAL_DEMO_KEY
        if secret is not None and len(secret) >= 32:
            self.mode = mode
            self._secret = secret

    @classmethod
    def from_environment(cls, env: Mapping[str, str] | None = None) -> WarrantSigner:
        values = os.environ if env is None else env
        configured_mode = values.get("PROOFPILOT_WARRANT_MODE", "").strip().lower()
        secret = values.get("PROOFPILOT_WARRANT_SIGNING_SECRET", "").strip()
        if configured_mode not in {"", "configured", "required", "local_demo"}:
            return cls(mode="disabled")
        if secret:
            # Any explicitly supplied secret takes precedence. A short secret
            # disables signing instead of silently downgrading to demo mode.
            return cls(secret.encode("utf-8"))
        return cls(mode="local_demo" if configured_mode == "local_demo" else "disabled")

    def _sign(self, material: Mapping) -> str:
        if self._secret is None:
            raise WarrantError("warrant_signing_unavailable", "Warrant signing is not configured.", 503)
        return hmac.new(self._secret, _SIGNATURE_CONTEXT + canonical_json(material), "sha256").hexdigest()

    def issue(
        self,
        action: ActionContract,
        proof_contract: ProofContract,
        version: int = 1,
    ) -> SignedWarrant:
        if self.mode == "disabled":
            raise WarrantError("warrant_signing_unavailable", "Warrant signing is not configured.", 503)
        if proof_contract.task_id != action.task_id or proof_contract.version != action.contract_version:
            raise WarrantError("proof_contract_mismatch", "The action and ProofContract no longer match.")
        now = datetime.now(timezone.utc)
        if action.expires_at <= now:
            raise WarrantError("warrant_expired", "The action has expired. Prepare a new action before approval.")

        plan = build_sandbox_plan(action, version)
        body = WarrantBody(
            warrant_id=f"warrant_{uuid4().hex}",
            task_id=action.task_id,
            action_id=action.action_id,
            proof_contract_version=proof_contract.version,
            proof_contract_hash=canonical_hash(proof_contract),
            action_digest=action.approval_digest,
            plan_version=plan.version,
            plan_hash=canonical_hash(plan),
            plan=plan,
            authorized_steps=tuple(step.id for step in plan.steps),
            allowed_domains=tuple(dict.fromkeys(step.target_domain for step in plan.steps)),
            allowed_action_types=tuple(dict.fromkeys(step.action_type for step in plan.steps)),
            step_parameter_constraints={step.id: step.parameters for step in plan.steps},
            created_at=now,
            expires_at=action.expires_at,
            approval_budget=1,
            status="ISSUED",
            signing_mode=self.mode,
        )
        contract_hash = canonical_hash(body)
        signature = self._sign({**body.model_dump(mode="json"), "contract_hash": contract_hash})
        return SignedWarrant(
            **body.model_dump(mode="python"),
            contract_hash=contract_hash,
            signature=signature,
        )

    def validate(
        self,
        warrant: SignedWarrant,
        action: ActionContract,
        proof_contract: ProofContract | None = None,
        *,
        now: datetime | None = None,
    ) -> None:
        if self.mode == "disabled":
            raise WarrantError("warrant_signing_unavailable", "Warrant signing is not configured.", 503)
        try:
            warrant = SignedWarrant.model_validate(warrant)
        except ValidationError as exc:
            raise WarrantError("invalid_warrant", "The Warrant contract is malformed.") from exc

        material = warrant.model_dump(mode="json", exclude={"signature", "contract_hash"})
        computed_hash = canonical_hash(material)
        computed_signature = self._sign({**material, "contract_hash": warrant.contract_hash})
        if (
            not hmac.compare_digest(warrant.contract_hash, computed_hash)
            or not hmac.compare_digest(warrant.signature, computed_signature)
            or warrant.signing_mode != self.mode
        ):
            raise WarrantError("invalid_warrant_signature", "The Warrant contract signature is invalid.")

        now = now if now is not None else datetime.now(timezone.utc)
        if warrant.expires_at <= now or action.expires_at <= now:
            raise WarrantError("warrant_expired", "The Warrant contract has expired.")
        if warrant.created_at > now:
            raise WarrantError("invalid_warrant", "The Warrant contract is not active yet.")
        if (
            warrant.task_id != action.task_id
            or warrant.action_id != action.action_id
            or warrant.proof_contract_version != action.contract_version
            or warrant.expires_at != action.expires_at
            or not hmac.compare_digest(warrant.action_digest, action.approval_digest)
        ):
            raise WarrantError("warrant_action_mismatch", "The Warrant no longer matches the prepared action.")
        if proof_contract is not None and (
            proof_contract.task_id != warrant.task_id
            or proof_contract.version != warrant.proof_contract_version
            or not hmac.compare_digest(warrant.proof_contract_hash, canonical_hash(proof_contract))
        ):
            raise WarrantError("proof_contract_mismatch", "The ProofContract changed after the Warrant was issued.")
        expected_plan = build_sandbox_plan(action, warrant.plan_version)
        if (
            warrant.plan != expected_plan
            or not hmac.compare_digest(warrant.plan_hash, canonical_hash(expected_plan))
        ):
            raise WarrantError("warrant_plan_mismatch", "The validated plan changed after the Warrant was issued.")
