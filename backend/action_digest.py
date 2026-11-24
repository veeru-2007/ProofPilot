"""Canonical digest for the existing ActionContract approval boundary."""

from __future__ import annotations

import hashlib
import json

from models import ActionContract


def approval_digest(action: ActionContract) -> str:
    material = {
        "task_id": action.task_id,
        "action_id": action.action_id,
        "contract_version": action.contract_version,
        "action_type": action.action_type.value,
        "target_url": str(action.target_url),
        "target_domain": action.target_domain,
        "target_description": action.target_description,
        "payload": action.payload.model_dump(mode="json"),
        "preconditions": [item.model_dump(mode="json") for item in action.preconditions],
        "associated_requirement_ids": action.associated_requirement_ids,
        "associated_evidence_ids": action.associated_evidence_ids,
        "expected_postconditions": [item.model_dump(mode="json") for item in action.expected_postconditions],
        "prohibited_effects": action.prohibited_effects,
        "requires_approval": action.requires_approval,
        "permission_context": action.permission_context.model_dump(mode="json"),
        "created_at": action.created_at.isoformat(),
        "expires_at": action.expires_at.isoformat(),
        "idempotency_key": action.idempotency_key,
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
