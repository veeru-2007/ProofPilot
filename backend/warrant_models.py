"""Strict plan and Warrant schemas for the controlled local sandbox."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import AwareDatetime, BaseModel, BeforeValidator, ConfigDict, Field, field_validator, model_validator


DEMO_FORM_PATH = "/demo/laptop-selection"
DEMO_SUBMISSION_PATH = "/demo/submissions"
DEMO_READBACK_PREFIX = "/demo/selections/"
DEMO_SUBMIT_SELECTOR = "#submit-selection"
DEMO_FILL_FIELDS = (
    ("laptop", "#laptop"),
    ("budget", "#budget"),
    ("ram", "#ram"),
    ("gpu", "#gpu"),
    ("reason", "#reason"),
)
DEMO_RECORD_ID_PATTERN = r"[A-Za-z0-9_-]{1,80}"
DEMO_READBACK_FIELDS = ("submission_id", *(field for field, _ in DEMO_FILL_FIELDS))
DEMO_RECORD_TEMPLATE = DEMO_READBACK_PREFIX + "{record_id}"
MAX_PLAN_STEPS = 9

TaskId = Annotated[str, Field(min_length=1, max_length=128)]
ActionId = Annotated[str, Field(pattern=r"^action_[a-f0-9]{12}$")]
StepId = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
Version = Annotated[int, Field(ge=1, le=100)]
HexDigest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
DemoDomain = Literal["127.0.0.1", "localhost"]
ActionType = Literal["navigate", "read", "extract", "fill", "click"]
FormField = Literal["laptop", "budget", "ram", "gpu", "reason"]
ReadbackField = Literal["submission_id", "laptop", "budget", "ram", "gpu", "reason"]
LocalUrl = Annotated[str, Field(min_length=1, max_length=150)]


def _as_tuple(value):
    """Accept JSON arrays while preserving strict scalar and item validation."""
    return tuple(value) if isinstance(value, list) else value


def _parse_aware_datetime(value):
    """Allow ISO-8601 timestamps from JSON while keeping timezone checks strict."""
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    return value


def sandbox_origin(url: str, path: str) -> str:
    """Return an exact loopback origin and reject URL aliases or extra components."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise ValueError("The sandbox URL contains an invalid origin.") from exc
    host = parts.hostname
    if parts.scheme != "http" or host not in {"127.0.0.1", "localhost"} or port == 0:
        raise ValueError("Only the HTTP loopback sandbox is allowed.")
    origin = f"http://{host}" + (f":{port}" if port is not None else "")
    if url != origin + path:
        raise ValueError("The sandbox URL must match its exact supported path and origin.")
    return origin


def build_readback_url(target: str, record_id: str) -> str:
    if not isinstance(record_id, str) or re.fullmatch(DEMO_RECORD_ID_PATTERN, record_id) is None:
        raise ValueError("The sandbox returned an invalid record identifier.")
    return sandbox_origin(target, DEMO_FORM_PATH) + DEMO_READBACK_PREFIX + record_id


class StrictModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, revalidate_instances="always")


class NavigateParameters(StrictModel):
    url: LocalUrl
    method: Literal["GET"]

    @field_validator("url")
    @classmethod
    def validate_form_url(cls, value: str) -> str:
        sandbox_origin(value, DEMO_FORM_PATH)
        return value


class FillParameters(StrictModel):
    url: LocalUrl
    field: FormField
    selector: Annotated[str, Field(min_length=2, max_length=12)]
    value: Annotated[str, Field(min_length=1, max_length=1000)]

    @model_validator(mode="after")
    def validate_field(self) -> FillParameters:
        sandbox_origin(self.url, DEMO_FORM_PATH)
        if self.selector != dict(DEMO_FILL_FIELDS)[self.field]:
            raise ValueError("The selector must match its allowed sandbox form field.")
        limit = {"laptop": 300, "reason": 1000}.get(self.field, 100)
        if not self.value.strip() or len(self.value) > limit:
            raise ValueError("The sandbox field value is blank or exceeds its length limit.")
        return self


class ClickParameters(StrictModel):
    url: LocalUrl
    selector: Literal["#submit-selection"]
    method: Literal["POST"]
    request_url: LocalUrl

    @model_validator(mode="after")
    def validate_click(self) -> ClickParameters:
        origin = sandbox_origin(self.url, DEMO_FORM_PATH)
        if sandbox_origin(self.request_url, DEMO_SUBMISSION_PATH) != origin:
            raise ValueError("The submit request must remain on the sandbox form origin.")
        return self


class ReadParameters(StrictModel):
    url_template: LocalUrl
    method: Literal["GET"]
    record_id_source: Literal["submit_response"]

    @field_validator("url_template")
    @classmethod
    def validate_readback_template(cls, value: str) -> str:
        sandbox_origin(value, DEMO_RECORD_TEMPLATE)
        return value


class ExtractParameters(StrictModel):
    source_step_id: StepId
    fields: Annotated[tuple[ReadbackField, ...], BeforeValidator(_as_tuple), Field(min_length=1, max_length=6)]

    @field_validator("fields")
    @classmethod
    def reject_duplicate_fields(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("Extracted fields cannot be repeated.")
        return value


class StepBase(StrictModel):
    id: StepId
    target_domain: DemoDomain
    description: Annotated[str, Field(min_length=1, max_length=160)]


class NavigateStep(StepBase):
    action_type: Literal["navigate"]
    risk_level: Literal["read_only"]
    parameters: NavigateParameters


class FillStep(StepBase):
    action_type: Literal["fill"]
    risk_level: Literal["sandbox_write"]
    parameters: FillParameters


class ClickStep(StepBase):
    action_type: Literal["click"]
    risk_level: Literal["sandbox_write"]
    parameters: ClickParameters


class ReadStep(StepBase):
    action_type: Literal["read"]
    risk_level: Literal["read_only"]
    parameters: ReadParameters


class ExtractStep(StepBase):
    action_type: Literal["extract"]
    risk_level: Literal["read_only"]
    parameters: ExtractParameters


PlanStep = Annotated[
    NavigateStep | FillStep | ClickStep | ReadStep | ExtractStep,
    Field(discriminator="action_type"),
]


class ValidatedPlan(StrictModel):
    task_id: TaskId
    action_id: ActionId
    contract_version: Version
    version: Version
    source: Literal["DETERMINISTIC_SANDBOX"]
    steps: Annotated[tuple[PlanStep, ...], BeforeValidator(_as_tuple), Field(min_length=1, max_length=MAX_PLAN_STEPS)]

    @model_validator(mode="after")
    def validate_step_relationships(self) -> ValidatedPlan:
        prior_steps: dict[str, PlanStep] = {}
        origins: set[str] = set()
        for step in self.steps:
            if step.id in prior_steps:
                raise ValueError("Each step must have a unique ID.")
            if isinstance(step, ExtractStep):
                source_step = prior_steps.get(step.parameters.source_step_id)
                if not isinstance(source_step, ReadStep) or source_step.target_domain != step.target_domain:
                    raise ValueError("An extraction must reference a preceding read step on its declared domain.")
            else:
                origin = (
                    sandbox_origin(step.parameters.url_template, DEMO_RECORD_TEMPLATE)
                    if isinstance(step, ReadStep)
                    else sandbox_origin(step.parameters.url, DEMO_FORM_PATH)
                )
                if urlsplit(origin).hostname != step.target_domain:
                    raise ValueError("A step's target domain must match its sandbox URL.")
                origins.add(origin)
            prior_steps[step.id] = step
        if len(origins) != 1:
            raise ValueError("All executable plan steps must use one exact sandbox origin.")
        return self


StepParameters = NavigateParameters | FillParameters | ClickParameters | ReadParameters | ExtractParameters


class WarrantBody(StrictModel):
    warrant_id: Annotated[str, Field(pattern=r"^warrant_[a-f0-9]{32}$")]
    task_id: TaskId
    action_id: ActionId
    proof_contract_version: Version
    proof_contract_hash: HexDigest
    action_digest: HexDigest
    plan_version: Version
    plan_hash: HexDigest
    plan: ValidatedPlan
    authorized_steps: Annotated[tuple[StepId, ...], BeforeValidator(_as_tuple), Field(min_length=1, max_length=MAX_PLAN_STEPS)]
    allowed_domains: Annotated[tuple[DemoDomain, ...], BeforeValidator(_as_tuple), Field(min_length=1, max_length=1)]
    allowed_action_types: Annotated[tuple[ActionType, ...], BeforeValidator(_as_tuple), Field(min_length=1, max_length=5)]
    step_parameter_constraints: Annotated[dict[StepId, StepParameters], Field(min_length=1, max_length=MAX_PLAN_STEPS)]
    created_at: Annotated[AwareDatetime, BeforeValidator(_parse_aware_datetime)]
    expires_at: Annotated[AwareDatetime, BeforeValidator(_parse_aware_datetime)]
    approval_budget: Annotated[int, Field(ge=1, le=1)]
    status: Literal["ISSUED"]
    signing_mode: Literal["configured", "local_demo"]

    @model_validator(mode="after")
    def verify_body_consistency(self) -> WarrantBody:
        plan = self.plan
        if (
            self.task_id != plan.task_id or self.action_id != plan.action_id
            or self.proof_contract_version != plan.contract_version or self.plan_version != plan.version
        ):
            raise ValueError("The Warrant and plan must refer to the same task, action, and versions.")
        if self.expires_at <= self.created_at:
            raise ValueError("The Warrant must expire after it is created.")
        if (
            self.authorized_steps != tuple(step.id for step in plan.steps)
            or self.allowed_domains != tuple(dict.fromkeys(step.target_domain for step in plan.steps))
            or self.allowed_action_types != tuple(dict.fromkeys(step.action_type for step in plan.steps))
            or self.step_parameter_constraints != {step.id: step.parameters for step in plan.steps}
        ):
            raise ValueError("The Warrant permissions must match the exact validated plan.")
        return self


class SignedWarrant(WarrantBody):
    contract_hash: HexDigest
    signature: HexDigest
