from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional
from urllib.parse import urlparse
from uuid import uuid4

from warrant_models import SignedWarrant

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


class TaskStatus(str, Enum):
    CREATED = "created"
    QUEUED = "queued"
    PLANNED = "planned"
    SEARCH_PENDING = "search_pending"
    SEARCHING = "searching"
    BROWSING = "browsing"
    VERIFYING = "verifying"
    ANALYZING = "analyzing"
    AWAITING_APPROVAL = "awaiting_approval"
    EXECUTING = "executing"
    BLOCKED = "blocked"
    PARTIAL = "partial"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"


class VerificationStatus(str, Enum):
    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    UNVERIFIED = "unverified"


class RequirementEvaluationStatus(str, Enum):
    SATISFIED = "SATISFIED"
    NOT_SATISFIED = "NOT_SATISFIED"
    UNVERIFIED = "UNVERIFIED"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    INVALID_EVIDENCE = "INVALID_EVIDENCE"


class EvidenceExtractionStatus(str, Enum):
    EXTRACTED = "EXTRACTED"
    SUPPORTED = "SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    UNVERIFIED = "UNVERIFIED"


class ResearchReportStatus(str, Enum):
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class ResearchExecutionStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_WARNINGS = "COMPLETED_WITH_WARNINGS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    BLOCKED = "BLOCKED"


class SourceFailureCategory(str, Enum):
    ACCESS_DENIED = "ACCESS_DENIED"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    NETWORK_ERROR = "NETWORK_ERROR"
    CONTENT_UNAVAILABLE = "CONTENT_UNAVAILABLE"
    EXTRACTION_FAILED = "EXTRACTION_FAILED"
    INVALID_CONTENT = "INVALID_CONTENT"
    ROBOTS_OR_RESTRICTION = "ROBOTS_OR_RESTRICTION"
    UNKNOWN_FAILURE = "UNKNOWN_FAILURE"
    SUCCESS = "SUCCESS"


class CompletionCriterionStatus(str, Enum):
    SATISFIED = "SATISFIED"
    NOT_SATISFIED = "NOT_SATISFIED"
    UNVERIFIED = "UNVERIFIED"


class RequirementOperator(str, Enum):
    EQ = "eq"
    LTE = "lte"
    GTE = "gte"
    CONTAINS = "contains"
    ONE_OF = "one_of"
    EXISTS = "exists"


class ActionType(str, Enum):
    SEARCH_PUBLIC_WEB = "search_public_web"
    BROWSE_PUBLIC_PAGE = "browse_public_page"
    EXTRACT_EVIDENCE = "extract_evidence"
    SUBMIT_FORM = "submit_form"
    PURCHASE = "purchase"
    BOOK = "book"
    APPLY = "apply"
    SEND_MESSAGE = "send_message"
    MODIFY_ACCOUNT = "modify_account"
    DELETE_DATA = "delete_data"
    DOWNLOAD_FILE = "download_file"
    BYPASS_AUTHENTICATION = "bypass_authentication"
    BYPASS_CAPTCHA = "bypass_captcha"
    BYPASS_ANTI_BOT = "bypass_anti_bot"


class Requirement(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)

    id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    label: str = Field(min_length=1, max_length=300)
    subject: Optional[str] = Field(default=None, min_length=1, max_length=200)
    field: str = Field(min_length=1, max_length=100)
    operator: RequirementOperator
    expected: StrictStr | StrictInt | StrictFloat | list[StrictStr | StrictInt | StrictFloat] | None
    unit: Optional[str] = Field(default=None, min_length=1, max_length=40)
    hard_constraint: bool = True

    @field_validator("operator", mode="before")
    @classmethod
    def parse_operator(cls, value):
        if isinstance(value, str):
            try:
                return RequirementOperator(value)
            except ValueError:
                return value
        return value

    @model_validator(mode="after")
    def validate_expected_value(self):
        if self.operator == RequirementOperator.EXISTS:
            if self.expected is not None:
                raise ValueError("The exists operator requires expected=null.")
        elif self.expected is None:
            raise ValueError("This operator requires an expected value.")

        if self.operator == RequirementOperator.ONE_OF:
            if not isinstance(self.expected, list) or not self.expected:
                raise ValueError("The one_of operator requires a non-empty list of values.")
        elif isinstance(self.expected, list):
            raise ValueError("Only the one_of operator accepts a list of expected values.")

        if self.operator == RequirementOperator.CONTAINS and not isinstance(self.expected, str):
            raise ValueError("The contains operator requires a string expected value.")
        return self


class ContractAmbiguity(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)

    id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    description: str = Field(min_length=1, max_length=500)
    clarification_question: str = Field(min_length=1, max_length=500)
    related_requirement_ids: list[str] = Field(default_factory=list, max_length=50)
    blocking_stage: Literal["research", "execution", "none"] = "none"


class ProofContract(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)

    task_id: str = Field(min_length=1, max_length=128)
    goal: str = Field(min_length=3, max_length=3000)
    requirements: list[Requirement] = Field(min_length=1, max_length=50)
    allowed_domains: list[str] = Field(default_factory=list, max_length=30)
    allowed_actions: list[ActionType] = Field(min_length=1, max_length=20)
    prohibited_actions: list[ActionType] = Field(default_factory=list, max_length=20)
    requires_approval_for: list[ActionType] = Field(default_factory=list, max_length=20)
    completion_criteria: list[str] = Field(min_length=1, max_length=20)
    ambiguities: list[ContractAmbiguity] = Field(default_factory=list, max_length=30)
    clarification_required_before_research: bool = False
    clarification_required_before_execution: bool = False
    created_at: datetime = Field(default_factory=utc_now)
    version: int = Field(default=1, ge=1, le=100)

    @field_validator(
        "allowed_actions",
        "prohibited_actions",
        "requires_approval_for",
        mode="before",
    )
    @classmethod
    def parse_action_types(cls, values):
        if not isinstance(values, list):
            return values
        parsed = []
        for value in values:
            if isinstance(value, str):
                try:
                    value = ActionType(value)
                except ValueError:
                    pass
            parsed.append(value)
        return parsed

    @field_validator("allowed_domains")
    @classmethod
    def validate_domains(cls, domains: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for raw_domain in domains:
            domain = raw_domain.strip().rstrip(".").lower()
            try:
                domain = domain.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise ValueError("Domain entries must be valid hostnames.") from exc

            labels = domain.split(".")
            if (
                len(domain) > 253
                or len(labels) < 2
                or any(
                    not label
                    or len(label) > 63
                    or label.startswith("-")
                    or label.endswith("-")
                    or not all(char.isalnum() or char == "-" for char in label)
                    for label in labels
                )
                or labels[-1].isdigit()
            ):
                raise ValueError("Domain entries must be bare public-style hostnames without a scheme or path.")
            if domain in seen:
                raise ValueError("Allowed domains must not contain duplicates.")
            seen.add(domain)
            normalized.append(domain)
        return normalized

    @model_validator(mode="after")
    def validate_contract_consistency(self):
        requirement_ids = [item.id for item in self.requirements]
        if len(requirement_ids) != len(set(requirement_ids)):
            raise ValueError("Requirement IDs must be unique within a contract.")

        ambiguity_ids = [item.id for item in self.ambiguities]
        if len(ambiguity_ids) != len(set(ambiguity_ids)):
            raise ValueError("Ambiguity IDs must be unique within a contract.")

        known_requirement_ids = set(requirement_ids)
        for ambiguity in self.ambiguities:
            if not set(ambiguity.related_requirement_ids).issubset(known_requirement_ids):
                raise ValueError("Ambiguities may only refer to requirements in this contract.")

        for values, label in (
            (self.allowed_actions, "allowed_actions"),
            (self.prohibited_actions, "prohibited_actions"),
            (self.requires_approval_for, "requires_approval_for"),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{label} must not contain duplicates.")

        allowed = set(self.allowed_actions)
        prohibited = set(self.prohibited_actions)
        approval_required = set(self.requires_approval_for)
        if allowed.intersection(prohibited):
            raise ValueError("An action cannot be both allowed and prohibited.")
        if not approval_required.issubset(allowed):
            raise ValueError("Actions requiring approval must also appear in allowed_actions.")

        never_allowed = {
            ActionType.BYPASS_AUTHENTICATION,
            ActionType.BYPASS_CAPTCHA,
            ActionType.BYPASS_ANTI_BOT,
        }
        if not never_allowed.issubset(prohibited):
            raise ValueError("Authentication, CAPTCHA, and anti-bot bypasses must always be prohibited.")
        read_only = {
            ActionType.SEARCH_PUBLIC_WEB,
            ActionType.BROWSE_PUBLIC_PAGE,
            ActionType.EXTRACT_EVIDENCE,
        }
        if not read_only.issubset(allowed):
            raise ValueError("A ProofPilot contract must allow its core read-only research actions.")
        if not (allowed - read_only).issubset(approval_required):
            raise ValueError("Every non-read-only allowed action must require human approval.")

        never_allowed = {
            ActionType.BYPASS_AUTHENTICATION,
            ActionType.BYPASS_CAPTCHA,
            ActionType.BYPASS_ANTI_BOT,
        }
        if not never_allowed.issubset(prohibited):
            raise ValueError("Authentication, CAPTCHA, and anti-bot bypasses must always be prohibited.")
        read_only = {
            ActionType.SEARCH_PUBLIC_WEB,
            ActionType.BROWSE_PUBLIC_PAGE,
            ActionType.EXTRACT_EVIDENCE,
        }
        if not (allowed - read_only).issubset(approval_required):
            raise ValueError("Every non-read-only allowed action must require human approval.")

        expected_research_clarification = any(
            ambiguity.blocking_stage == "research" for ambiguity in self.ambiguities
        )
        expected_execution_clarification = any(
            ambiguity.blocking_stage == "execution" for ambiguity in self.ambiguities
        )
        if self.clarification_required_before_research != expected_research_clarification:
            raise ValueError("Research clarification flag must match the blocking ambiguities.")
        if self.clarification_required_before_execution != expected_execution_clarification:
            raise ValueError("Execution clarification flag must match the blocking ambiguities.")

        if not self.completion_criteria or any(not criterion.strip() for criterion in self.completion_criteria):
            raise ValueError("Completion criteria must contain non-empty text.")
        return self


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    quote: str = Field(min_length=1, max_length=2000)
    source_url: HttpUrl
    source_title: str = Field(min_length=1, max_length=300)
    excerpt_locator: Optional[str] = Field(default=None, max_length=500)
    timestamp: datetime = Field(default_factory=utc_now)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)


class Claim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    subject: str = Field(min_length=1, max_length=300)
    field: str = Field(min_length=1, max_length=100)
    value: str = Field(min_length=1, max_length=500)
    numeric_value: StrictInt | StrictFloat | None = None
    unit: Optional[str] = Field(default=None, max_length=40)
    currency: Optional[str] = Field(default=None, max_length=12)
    currency_symbol: Optional[str] = Field(default=None, max_length=12)
    source_domain: Optional[str] = Field(default=None, max_length=253)
    context: list[str] = Field(default_factory=list, max_length=12)
    evidence: Evidence
    verification_status: VerificationStatus
    verification_reason: str = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def populate_source_domain(self):
        if not self.source_domain:
            self.source_domain = urlparse(str(self.evidence.source_url)).hostname
        return self


class VerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim: Claim
    extracted_text: str = Field(max_length=250000)


class VerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim_id: str
    status: VerificationStatus
    reason: str = Field(min_length=1, max_length=1000)
    evidence_quote: str
    evidence_source_url: HttpUrl
    evidence_timestamp: datetime
    checked_at: datetime


class PlannedAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=3, max_length=500)
    target: Optional[str] = Field(default=None, max_length=500)
    approval_required: bool = False
    reason: str = Field(min_length=1, max_length=500)


class PlannerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task: str = Field(min_length=3, max_length=3000)
    budget: Optional[str] = Field(default=None, max_length=100)
    context: dict[str, Any] = Field(default_factory=dict)


class PlannerOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    objective: str = Field(min_length=3, max_length=500)
    steps: list[str] = Field(min_length=3, max_length=5)
    search_queries: list[str] = Field(min_length=3, max_length=5)
    extract_fields: list[str] = Field(min_length=1, max_length=30)
    comparison_criteria: list[str] = Field(min_length=1, max_length=30)
    approval_action: Optional[PlannedAction] = None


class AnalyzerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task: str = Field(min_length=3, max_length=3000)
    claims: list[Claim] = Field(default_factory=list)
    verifications: list[VerificationResult] = Field(default_factory=list)


class EvidenceSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim_id: str
    claim: str
    source_url: HttpUrl
    evidence_quote: str
    status: VerificationStatus


class AnalyzerOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recommendation: str = Field(min_length=1, max_length=3000)
    verified_information: list[EvidenceSummary] = Field(default_factory=list)
    inferences: list[str] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    source_links: list[HttpUrl] = Field(default_factory=list)
class TaskCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task: str = Field(min_length=3, max_length=3000)
    budget: Optional[str] = Field(default=None, max_length=100)
    context: dict[str, Any] = Field(default_factory=dict)
    client_request_id: Optional[str] = Field(default=None, min_length=8, max_length=128)


class RefineTaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instruction: str = Field(min_length=3, max_length=3000)


class SearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=2, max_length=1000)
    max_results: int = Field(default=5, ge=1, le=10)
    include_domains: list[str] = Field(default_factory=list, max_length=30)
    exclude_domains: list[str] = Field(default_factory=list, max_length=30)


class SearchSourceMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score: Optional[float] = None
    published_date: Optional[str] = None
    position: Optional[int] = None


class SearchResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str
    url: HttpUrl
    snippet: str
    metadata: SearchSourceMetadata = Field(default_factory=SearchSourceMetadata)


class SearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    query: str
    result_count: int
    answer: Optional[str] = None
    results: list[SearchResult]


class BrowserVisitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: HttpUrl
    query: Optional[str] = Field(default=None, max_length=500)
    allowed_domains: list[str] = Field(default_factory=list, max_length=30)
    timeout_seconds: int = Field(default=20, ge=5, le=60)
    max_text_chars: int = Field(default=50000, ge=1000, le=200000)

    @field_validator("allowed_domains")
    @classmethod
    def validate_allowed_domains(cls, domains: list[str]) -> list[str]:
        return ProofContract.validate_domains(domains)


class BrowserPageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str
    url: HttpUrl
    status_code: Optional[int] = None
    headings: list[str] = Field(default_factory=list)
    visible_text: str = ""
    relevant_content: list[str] = Field(default_factory=list)
    blocked_reason: Optional[str] = None
    rejected_domains: list[str] = Field(default_factory=list)


class ExecutionStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    status: TaskStatus
    detail: str
    started_at: datetime
    completed_at: Optional[datetime] = None


class AuditRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    action: str
    detail: str
    actor: str
    timestamp: datetime


class SourceRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: HttpUrl
    title: str
    source_domain: Optional[str] = Field(default=None, max_length=253)
    status_code: Optional[int] = None
    blocked_reason: Optional[str] = None
    headings_count: int = 0
    observed_at: datetime = Field(default_factory=utc_now)
    failure_type: Literal["blocked", "timeout", "malformed_source", "unavailable", "extraction_error"] | None = None
    failure_reason: Optional[str] = Field(default=None, max_length=1000)
    failed_at: Optional[datetime] = None
    coverage_impact: Literal["unassessed", "unaffected", "unresolved"] = "unassessed"
    affected_requirement_ids: list[str] = Field(default_factory=list, max_length=50)

    @model_validator(mode="after")
    def populate_source_domain(self):
        if not self.source_domain:
            self.source_domain = urlparse(str(self.url)).hostname
        return self


class SourceAttemptRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attempt_id: str = Field(default_factory=lambda: new_id("srcatt"))
    source_identifier: str = Field(min_length=1, max_length=128)
    source_url: Optional[HttpUrl] = None
    domain: Optional[str] = Field(default=None, max_length=253)
    source_type: Literal["page", "search"] = "page"
    attempt_number: int = Field(default=1, ge=1, le=20)
    timestamp: datetime = Field(default_factory=utc_now)
    failure_category: SourceFailureCategory
    http_status: Optional[int] = Field(default=None, ge=100, le=599)
    error_description: Optional[str] = Field(default=None, max_length=500)
    recovery_attempt_status: Literal[
        "NOT_NEEDED",
        "RETRY_SCHEDULED",
        "ALTERNATIVES_SEARCHED",
        "ALTERNATIVES_FOUND",
        "ALTERNATIVES_NOT_FOUND",
        "RECOVERED",
        "LIMIT_REACHED",
    ] = "NOT_NEEDED"
    recovery_operation_id: Optional[str] = Field(default=None, max_length=128)
    alternative_sources_found: bool = False
    retrieval_succeeded: bool = False
    evidence_extracted: bool = False
    affects_requirement: bool = False
    affected_requirement_ids: list[str] = Field(default_factory=list, max_length=50)
    retry_eligible: bool = False

    @model_validator(mode="after")
    def populate_domain(self):
        if not self.domain and self.source_url:
            self.domain = urlparse(str(self.source_url)).hostname
        return self


class ResearchSourceSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sources_discovered: int = Field(default=0, ge=0)
    source_attempts: int = Field(default=0, ge=0)
    sources_attempted: int = Field(default=0, ge=0)
    sources_accessed: int = Field(default=0, ge=0)
    sources_with_usable_evidence: int = Field(default=0, ge=0)
    sources_failed: int = Field(default=0, ge=0)
    sources_rejected: int = Field(default=0, ge=0)
    search_requests: int = Field(default=0, ge=0)
    search_failures: int = Field(default=0, ge=0)
    recovery_attempts: int = Field(default=0, ge=0)
    domains_represented: list[str] = Field(default_factory=list)
    requirements_supported: int = Field(default=0, ge=0)
    requirements_contradicted: int = Field(default=0, ge=0)
    requirements_unresolved: int = Field(default=0, ge=0)


class CurrencyConversionDetails(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    from_currency: str = Field(min_length=3, max_length=3)
    to_currency: str = Field(min_length=3, max_length=3)
    rate: StrictFloat = Field(gt=0)
    source: str = Field(min_length=1, max_length=300)
    timestamp: datetime
    original_value: StrictFloat | StrictInt
    converted_value: StrictFloat | StrictInt


class RequirementEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requirement_id: str
    requirement_description: str
    subject: Optional[str] = None
    status: RequirementEvaluationStatus
    expected: StrictStr | StrictInt | StrictFloat | list[StrictStr | StrictInt | StrictFloat] | None
    required_unit: Optional[str] = None
    required_currency: Optional[str] = None
    observed_value: Optional[str] = None
    observed_numeric_value: StrictInt | StrictFloat | None = None
    observed_unit: Optional[str] = None
    observed_currency: Optional[str] = None
    observed_currency_symbol: Optional[str] = None
    conversion_details: Optional[CurrencyConversionDetails] = None
    evidence_ids: list[str] = Field(default_factory=list)
    reason: str = Field(min_length=1, max_length=1000)


class EvidenceRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    subject: str
    field: str
    value: str
    source_url: HttpUrl
    source_domain: Optional[str] = Field(default=None, max_length=253)
    source_title: str
    supporting_text: str
    observed_at: datetime
    numeric_value: StrictInt | StrictFloat | None = None
    unit: Optional[str] = None
    currency: Optional[str] = None
    currency_symbol: Optional[str] = None
    context: list[str] = Field(default_factory=list, max_length=12)
    associated_requirement_ids: list[str] = Field(default_factory=list)
    extraction_status: EvidenceExtractionStatus

    @model_validator(mode="after")
    def populate_source_domain(self):
        if not self.source_domain:
            self.source_domain = urlparse(str(self.source_url)).hostname
        return self


class CompletionCriterionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    criterion: str
    status: CompletionCriterionStatus
    reason: str = Field(min_length=1, max_length=1000)


class ResearchReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str
    contract_version: int = Field(ge=1)
    status: ResearchReportStatus
    execution_status: ResearchExecutionStatus = ResearchExecutionStatus.COMPLETED
    requirements: list[Requirement]
    evaluations: list[RequirementEvaluation]
    evidence: list[EvidenceRecord]
    contradictions: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    sources_visited: list[SourceRecord] = Field(default_factory=list)
    domains_rejected: list[str] = Field(default_factory=list)
    completion_criteria: list[CompletionCriterionResult]
    unresolved_ambiguities: list[ContractAmbiguity] = Field(default_factory=list)
    research_failures: list[str] = Field(default_factory=list)
    source_attempts: list[SourceAttemptRecord] = Field(default_factory=list)
    source_summary: ResearchSourceSummary = Field(default_factory=ResearchSourceSummary)

    @model_validator(mode="before")
    @classmethod
    def infer_legacy_execution_status(cls, value):
        if not isinstance(value, dict):
            return value
        if value.get("source_attempts") is None:
            value["source_attempts"] = []
        if value.get("source_summary") is None:
            value.pop("source_summary", None)
        if "execution_status" not in value:
            raw_status = value.get("status", "")
            status = str(getattr(raw_status, "value", raw_status)).upper()
            if status == ResearchReportStatus.BLOCKED.value:
                value["execution_status"] = ResearchExecutionStatus.BLOCKED.value
            elif status == ResearchReportStatus.FAILED.value:
                value["execution_status"] = ResearchExecutionStatus.FAILED.value
            elif value.get("research_failures"):
                value["execution_status"] = ResearchExecutionStatus.COMPLETED_WITH_WARNINGS.value
            else:
                value["execution_status"] = ResearchExecutionStatus.COMPLETED.value
        if "source_summary" not in value:
            evaluations = value.get("evaluations") or []
            sources = value.get("sources_visited") or []
            evidence = value.get("evidence") or []
            statuses = []
            for item in evaluations:
                raw_status = getattr(item, "status", item.get("status", "") if isinstance(item, dict) else "")
                statuses.append(str(getattr(raw_status, "value", raw_status)))
            domains = {
                str(getattr(item, "source_domain", item.get("source_domain", "") if isinstance(item, dict) else "")).lower()
                for item in evidence
                if getattr(item, "source_domain", item.get("source_domain") if isinstance(item, dict) else None)
            }
            value["source_summary"] = {
                "sources_discovered": len(sources),
                "sources_attempted": len(sources),
                "sources_accessed": sum(
                    1 for item in sources
                    if not getattr(item, "failure_type", item.get("failure_type") if isinstance(item, dict) else None)
                ),
                "sources_failed": sum(
                    1 for item in sources
                    if getattr(item, "failure_type", item.get("failure_type") if isinstance(item, dict) else None)
                ),
                "domains_represented": sorted(domains),
                "requirements_supported": statuses.count(RequirementEvaluationStatus.SATISFIED.value),
                "requirements_contradicted": sum(
                    statuses.count(item)
                    for item in (RequirementEvaluationStatus.NOT_SATISFIED.value, RequirementEvaluationStatus.CONFLICTING_EVIDENCE.value)
                ),
                "requirements_unresolved": sum(
                    statuses.count(item)
                    for item in (RequirementEvaluationStatus.UNVERIFIED.value, RequirementEvaluationStatus.INVALID_EVIDENCE.value)
                ),
            }
        return value

    @model_validator(mode="after")
    def reconcile_source_summary(self):
        """Repair summaries from persisted source records when older reports contain zeros."""
        page_attempts = [item for item in self.source_attempts if item.source_type == "page"]
        search_attempts = [item for item in self.source_attempts if item.source_type == "search"]
        source_records = self.sources_visited
        if not page_attempts and not search_attempts and not source_records:
            return self

        def source_key(value: object | None, fallback: str) -> str:
            if value is None:
                return fallback
            parsed = urlparse(str(value).strip())
            if parsed.scheme and parsed.netloc:
                return (
                    f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
                    f"{parsed.path.rstrip('/')}{'?' + parsed.query if parsed.query else ''}"
                )
            return str(value).strip()

        attempted_keys: set[str] = set()
        accessed_keys: set[str] = set()
        failed_keys: set[str] = set()
        latest_by_source: dict[str, SourceAttemptRecord] = {}
        for attempt in page_attempts:
            key = attempt.source_identifier
            previous = latest_by_source.get(key)
            if previous is None or attempt.attempt_number >= previous.attempt_number:
                latest_by_source[key] = attempt

        if source_records:
            for source in source_records:
                key = source_key(source.url, str(source.url))
                attempted_keys.add(key)
                source_failed = bool(
                    source.failure_type
                    or source.blocked_reason
                    or (source.status_code is not None and source.status_code >= 400)
                )
                if source_failed:
                    failed_keys.add(key)
                else:
                    accessed_keys.add(key)
        else:
            attempted_keys = set(latest_by_source)
            accessed_keys = {
                key for key, attempt in latest_by_source.items()
                if attempt.retrieval_succeeded
            }
            failed_keys = {
                key for key, attempt in latest_by_source.items()
                if attempt.failure_category != SourceFailureCategory.SUCCESS
            }
        evidence_keys = {
            source_key(item.source_url, str(item.source_url))
            for item in self.evidence
            if item.associated_requirement_ids
        }
        recovery_ids = {
            item.recovery_operation_id
            for item in self.source_attempts
            if item.recovery_operation_id
        }
        statuses = [item.status for item in self.evaluations]
        summary_updates = {
            "sources_discovered": max(self.source_summary.sources_discovered, len(attempted_keys)),
            "sources_attempted": len(attempted_keys),
            "sources_accessed": len(accessed_keys),
            "sources_failed": len(failed_keys),
            "sources_with_usable_evidence": (
                len(evidence_keys)
                if self.evidence
                else len({
                    source_key(item.source_url, item.source_identifier)
                    for item in page_attempts
                    if item.evidence_extracted and item.affected_requirement_ids
                })
            ),
            "requirements_supported": sum(
                item == RequirementEvaluationStatus.SATISFIED for item in statuses
            ),
            "requirements_contradicted": sum(
                item in {
                    RequirementEvaluationStatus.NOT_SATISFIED,
                    RequirementEvaluationStatus.CONFLICTING_EVIDENCE,
                }
                for item in statuses
            ),
            "requirements_unresolved": sum(
                item in {
                    RequirementEvaluationStatus.UNVERIFIED,
                    RequirementEvaluationStatus.INVALID_EVIDENCE,
                }
                for item in statuses
            ),
        }
        if page_attempts:
            summary_updates["source_attempts"] = len(page_attempts)
        if search_attempts:
            summary_updates["search_requests"] = len(search_attempts)
            summary_updates["search_failures"] = sum(
                item.failure_category != SourceFailureCategory.SUCCESS
                for item in search_attempts
            )
        if recovery_ids:
            summary_updates["recovery_attempts"] = len(recovery_ids)
        if self.evidence:
            summary_updates["domains_represented"] = sorted({
                item.source_domain.lower()
                for item in self.evidence
                if item.source_domain
            })
        self.source_summary = self.source_summary.model_copy(update=summary_updates)
        return self


class ExecutionEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    task_id: str
    event_type: str
    timestamp: datetime
    message: str = Field(min_length=1, max_length=2000)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExecutionSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attempt: int = Field(ge=1)
    state: str
    worker_id: Optional[str] = None
    started_at: Optional[datetime] = None
    heartbeat_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = None
    retry_count: int = Field(default=0, ge=0)


class TaskResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    task: str
    status: TaskStatus
    progress: str
    plan: list[str]
    claims: list[Claim] = Field(default_factory=list)
    verifications: list[VerificationResult] = Field(default_factory=list)
    sources: list[SourceRecord] = Field(default_factory=list)
    analysis: Optional[AnalyzerOutput] = None
    progress_percent: int = Field(default=0, ge=0, le=100)
    current_stage: str = "created"
    partial_failures: list[str] = Field(default_factory=list)
    action_approval_id: Optional[str] = None
    action_outcome: Optional[dict[str, Any]] = None
    action_contract_id: Optional[str] = None
    execution_receipt_id: Optional[str] = None
    contract_version: Optional[int] = None
    research_report: Optional[ResearchReport] = None
    research_execution_status: Optional[ResearchExecutionStatus] = None
    execution: Optional[ExecutionSummary] = None
    audit: list[AuditRecord] = Field(default_factory=list)
    error: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="before")
    @classmethod
    def discard_legacy_findings_field(cls, value):
        if isinstance(value, dict):
            value = dict(value)
            value.pop("findings", None)
            # Older reports used this label for the current `unverified` state.
            for claim in value.get("claims") or []:
                if isinstance(claim, dict) and claim.get("verification_status") == "insufficient evidence":
                    claim["verification_status"] = VerificationStatus.UNVERIFIED.value
            for result in value.get("verifications") or []:
                if isinstance(result, dict) and result.get("status") == "insufficient evidence":
                    result["status"] = VerificationStatus.UNVERIFIED.value
        return value

    @model_validator(mode="after")
    def infer_research_execution_status(self):
        if self.research_execution_status is not None:
            return self
        if self.research_report is not None:
            self.research_execution_status = self.research_report.execution_status
        elif self.status in {TaskStatus.CREATED, TaskStatus.QUEUED, TaskStatus.PLANNED, TaskStatus.SEARCH_PENDING}:
            self.research_execution_status = ResearchExecutionStatus.PENDING
        elif self.status in {
            TaskStatus.SEARCHING,
            TaskStatus.BROWSING,
            TaskStatus.VERIFYING,
            TaskStatus.ANALYZING,
            TaskStatus.PAUSED,
            TaskStatus.AWAITING_APPROVAL,
            TaskStatus.EXECUTING,
        }:
            self.research_execution_status = ResearchExecutionStatus.RUNNING
        elif self.status == TaskStatus.CANCELLED:
            self.research_execution_status = ResearchExecutionStatus.CANCELLED
        elif self.status == TaskStatus.BLOCKED:
            self.research_execution_status = ResearchExecutionStatus.BLOCKED
        elif self.status == TaskStatus.FAILED:
            self.research_execution_status = ResearchExecutionStatus.FAILED
        elif self.status == TaskStatus.PARTIAL:
            self.research_execution_status = ResearchExecutionStatus.PARTIAL
        else:
            self.research_execution_status = ResearchExecutionStatus.COMPLETED
        return self


class DemoSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)

    laptop: str = Field(min_length=1, max_length=300)
    budget: str = Field(min_length=1, max_length=100)
    ram: str = Field(min_length=1, max_length=100)
    gpu: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=1000)


class DemoActionType(str, Enum):
    PREPARE_DEMO_REQUEST = "prepare_demo_request"
    SUBMIT_DEMO_REQUEST = "submit_demo_request"


class ActionContractStatus(str, Enum):
    PREPARED = "PREPARED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTING = "EXECUTING"
    VERIFIED_SUCCESS = "VERIFIED_SUCCESS"
    VERIFIED_FAILURE = "VERIFIED_FAILURE"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
    EXPIRED = "EXPIRED"
    INVALIDATED = "INVALIDATED"


class ActionCondition(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    condition_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9_]+$")
    description: str = Field(min_length=1, max_length=300)
    satisfied: Optional[bool] = None
    evidence_ids: list[str] = Field(default_factory=list, max_length=50)


class ActionPermissionContext(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    task_id: str
    contract_version: int = Field(ge=1)
    proof_action: ActionType
    requires_approval: bool
    target_policy: str = Field(min_length=1, max_length=100)
    target_domain: str = Field(min_length=1, max_length=253)


class ActionAuditEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event: str = Field(min_length=1, max_length=80)
    detail: str = Field(min_length=1, max_length=1000)
    actor: str = Field(min_length=1, max_length=80)
    timestamp: datetime


class ActionContractCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    action_type: DemoActionType
    target_url: HttpUrl
    payload: DemoSubmission
    associated_requirement_ids: list[str] = Field(default_factory=list, max_length=50)
    associated_evidence_ids: list[str] = Field(min_length=1, max_length=50)

    @field_validator("action_type", mode="before")
    @classmethod
    def parse_action_type(cls, value):
        if isinstance(value, str):
            try:
                return DemoActionType(value)
            except ValueError:
                return value
        return value


class ActionContract(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    action_id: str = Field(min_length=1, max_length=80, pattern=r"^action_[a-f0-9]{12}$")
    task_id: str = Field(min_length=1, max_length=128)
    contract_version: int = Field(ge=1)
    action_type: DemoActionType
    target_url: HttpUrl
    target_domain: str = Field(min_length=1, max_length=253)
    target_description: str = Field(min_length=1, max_length=300)
    payload: DemoSubmission
    preconditions: list[ActionCondition] = Field(min_length=1, max_length=20)
    associated_requirement_ids: list[str] = Field(default_factory=list, max_length=50)
    associated_evidence_ids: list[str] = Field(min_length=1, max_length=50)
    expected_postconditions: list[ActionCondition] = Field(min_length=1, max_length=20)
    prohibited_effects: list[str] = Field(min_length=1, max_length=20)
    permission_context: ActionPermissionContext
    requires_approval: bool = True
    status: ActionContractStatus = ActionContractStatus.PREPARED
    created_at: datetime
    updated_at: Optional[datetime] = None
    expires_at: datetime
    idempotency_key: str = Field(pattern=r"^idem_[a-f0-9]{32}$")
    approval_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    approved_digest: Optional[str] = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    warrant: SignedWarrant | None = None
    approved_warrant_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    approved_at: Optional[datetime] = None
    execution_receipt_id: Optional[str] = None
    audit: list[ActionAuditEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_action_binding(self):
        if self.permission_context.task_id != self.task_id:
            raise ValueError("Action permission context must belong to the action task.")
        if self.permission_context.contract_version != self.contract_version:
            raise ValueError("Action permission context must match the ProofContract version.")
        if not self.requires_approval or not self.permission_context.requires_approval:
            raise ValueError("Demo submissions always require explicit approval.")
        if self.expires_at <= self.created_at:
            raise ValueError("Action approval expiry must be after preparation.")
        if any(not condition.satisfied for condition in self.preconditions):
            raise ValueError("Action contracts may only be prepared when all preconditions are satisfied.")
        if any(condition.satisfied is not None for condition in self.expected_postconditions):
            raise ValueError("Expected postconditions cannot be marked satisfied before execution.")
        return self


class DemoExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_attempted: bool
    action_completed: bool
    record_id: Optional[str] = None
    observed_record: Optional[dict[str, Any]] = None
    error: Optional[str] = Field(default=None, max_length=2000)


class ExecutionReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    receipt_id: str = Field(min_length=1, max_length=80)
    task_id: str
    action_id: str
    action_type: DemoActionType
    approved_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    approved_warrant_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    execution_status: ActionContractStatus
    approval_timestamp: datetime
    execution_timestamp: Optional[datetime] = None
    verification_timestamp: Optional[datetime] = None
    target_url: HttpUrl
    payload: DemoSubmission
    resulting_record_id: Optional[str] = None
    action_attempted: bool
    action_completed: bool
    outcome_verified: bool
    verified_postconditions: list[str] = Field(default_factory=list)
    failed_postconditions: list[str] = Field(default_factory=list)
    evidence_used: list[str] = Field(default_factory=list)
    execution_error: Optional[str] = Field(default=None, max_length=2000)
    verification_status: VerificationStatus


