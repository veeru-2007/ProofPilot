import asyncio
import hashlib
import logging
import re
from copy import deepcopy
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse
from uuid import uuid4

from pydantic import ValidationError

from analyzer import analyze_findings
from browser import (
    BrowserVisitError,
    UnsafeUrlError,
    is_domain_allowed_url,
    visit_public_page,
)
from contracts import ContractConflictError, generate_proof_contract
from evidence import extract_structured_claims
from models import (
    ActionType,
    AnalyzerRequest,
    AuditRecord,
    BrowserVisitRequest,
    RefineTaskRequest,
    SourceRecord,
    SearchRequest,
    TaskCreateRequest,
    TaskResponse,
    TaskStatus,
    VerificationRequest,
    VerificationResult,
    VerificationStatus,
    PlannerRequest,
    ProofContract,
    ResearchExecutionStatus,
    ResearchReportStatus,
    ExecutionSummary,
    SourceAttemptRecord,
    SourceFailureCategory,
    BrowserPageResponse,
    new_id,
    utc_now,
)
from planner import create_plan
from search import (
    SearchConfigurationError,
    SearchProviderError,
    search_public_web,
)
from verifier import verify_claim
from requirement_engine import (
    build_research_report,
    enforce_research_permission,
    map_evidence_to_requirements,
)
from research_orchestrator import (
    ResearchOrchestrator,
    ResearchResiliencePolicy,
    canonical_source_url,
    classify_source_failure,
    coarse_failure_type,
    safe_failure_description,
)
from task_store import TaskStore


logger = logging.getLogger(__name__)
_ERROR_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?(?:token|key)|refresh[_-]?token|secret(?:[_-]?key)?|password|authorization|cookie)\b\s*[:=]\s*[^\s,;&]+"
)
_BEARER_SECRET = re.compile(r"(?i)\bBearer\s+[^\s,;&]+")
_AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_ERROR_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def _safe_exception_detail(exc: BaseException, fallback: str) -> str:
    detail = str(exc).strip()
    if not detail:
        return fallback
    detail = _ERROR_SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[redacted]", detail)
    detail = _BEARER_SECRET.sub("Bearer [redacted]", detail)
    detail = _AWS_ACCESS_KEY.sub("[redacted AWS access key]", detail)
    detail = _ERROR_URL.sub(lambda match: canonical_source_url(match.group(0).rstrip(".,)")), detail)
    return detail[:500] or fallback


def _page_failure(page: BrowserPageResponse) -> tuple[str, str] | None:
    if page.status_code in {401, 403, 429}:
        reason = page.blocked_reason or {
            401: "The source requires authentication (HTTP 401).",
            403: "The source denied access (HTTP 403).",
            429: "The source rate-limited access (HTTP 429).",
        }[page.status_code]
        return "blocked", reason
    if page.blocked_reason:
        reason = page.blocked_reason
        lowered = reason.casefold()
        if any(
            marker in lowered for marker in ("authentication", "access restriction", "captcha", "protected-page")
        ):
            return "blocked", reason
        return "unavailable", reason
    if page.status_code is None or not 200 <= page.status_code < 300:
        return "unavailable", f"The source returned HTTP {page.status_code or 'no status code'}."
    if not page.title.strip() or (not page.visible_text.strip() and not page.headings):
        return "malformed_source", "The source returned no usable title, headings, or visible text."
    return None


def _failed_source(
    url: str,
    title: str,
    failure_type: str,
    reason: str,
    *,
    status_code: int | None = None,
) -> SourceRecord:
    return SourceRecord(
        url=url,
        title=title or "Source unavailable",
        source_domain=urlparse(url).hostname,
        status_code=status_code,
        blocked_reason=reason if failure_type == "blocked" else None,
        failure_type=failure_type,
        failure_reason=reason[:1000],
        failed_at=utc_now(),
    )


def _stable_source_identifier(url: str) -> str:
    safe_url = canonical_source_url(url)
    return f"source_{hashlib.sha256(safe_url.encode('utf-8')).hexdigest()[:20]}"


ACTIVE_RESEARCH_STATUSES = {
    TaskStatus.QUEUED,
    TaskStatus.PLANNED,
    TaskStatus.SEARCH_PENDING,
    TaskStatus.SEARCHING,
    TaskStatus.BROWSING,
    TaskStatus.VERIFYING,
    TaskStatus.ANALYZING,
}


class TaskConflictError(ValueError):
    """The requested task change conflicts with an active workflow."""


def _clear_research_results(task: TaskResponse) -> None:
    task.error = None
    task.plan = []
    task.partial_failures = []
    task.claims = []
    task.verifications = []
    task.sources = []
    task.analysis = None
    task.research_report = None


def _contract_search_targets(
    contract: ProofContract, planner_queries: list[str]
) -> list[tuple[str, list[str]]]:
    targets: list[tuple[str, list[str]]] = []
    positions: dict[str, int] = {}

    def add(query: str, requirement_ids: list[str] | None = None) -> None:
        normalized = " ".join(query.split())[:1000].strip()
        if not normalized:
            return
        key = normalized.casefold()
        if key in positions:
            existing = targets[positions[key]][1]
            existing.extend(item for item in requirement_ids or [] if item not in existing)
            return
        positions[key] = len(targets)
        targets.append((normalized, list(requirement_ids or [])))

    requirements = sorted(contract.requirements, key=lambda item: item.hard_constraint, reverse=True)
    for requirement in requirements:
        expected = requirement.expected
        if isinstance(expected, list):
            expected_text = " or ".join(str(value) for value in expected)
        elif expected is None:
            expected_text = ""
        else:
            expected_text = str(expected)
        unit = f" {requirement.unit}" if requirement.unit else ""
        add(f"{contract.goal} {requirement.field} {expected_text}{unit}", [requirement.id])
        if len(targets) >= 4:
            break

    for query in planner_queries:
        if len(targets) >= 4:
            break
        add(query)

    if contract.completion_criteria:
        add(f"{contract.goal} {' '.join(contract.completion_criteria)}")
    return targets[:5]


def _contract_search_queries(contract: ProofContract, planner_queries: list[str]) -> list[str]:
    return [query for query, _ in _contract_search_targets(contract, planner_queries)]


class TaskAgent:
    def __init__(
        self,
        approval_service=None,
        task_store: TaskStore | None = None,
        browser_provider=None,
    ) -> None:
        self.tasks: dict[str, TaskResponse] = {}
        self.drafts: dict[str, TaskCreateRequest] = {}
        self.contracts: dict[str, ProofContract] = {}
        self._contract_locks: dict[str, asyncio.Lock] = {}
        self.approval_service = approval_service
        self.browser_provider = browser_provider
        self.task_store = task_store or TaskStore()
        self.cancelled_task_ids: set[str] = set()
        self.paused_task_events: dict[str, asyncio.Event] = {}
        self._worker_tasks: dict[str, asyncio.Task] = {}
        self._worker_ids: dict[str, str] = {}
        self._retiring_workers: set[asyncio.Task] = set()
        self._retry_excluded_domains: dict[str, set[str]] = {}
        for stored_task in self.task_store.list():
            self.tasks[stored_task.id] = stored_task
            try:
                stored_draft = self.task_store.get_draft(stored_task.id)
            except ValidationError:
                # Older versions could persist invalid refinements. One bad
                # draft must not prevent other tasks and the API from loading.
                logger.warning("Skipping invalid saved draft for task %s.", stored_task.id)
                stored_draft = None
            if stored_draft is not None:
                self.drafts[stored_task.id] = stored_draft
            stored_contract = self.task_store.get_contract(stored_task.id)
            if stored_contract is not None:
                self.contracts[stored_task.id] = stored_contract

    def _with_execution(self, task: TaskResponse) -> TaskResponse:
        copy = deepcopy(task)
        execution = self.task_store.get_execution(task.id)
        if execution is None:
            copy.execution = None
            return copy

        def parse_timestamp(value: str | None):
            if not value:
                return None
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                return None

        copy.execution = ExecutionSummary(
            attempt=int(execution["attempt"]),
            state=str(execution["state"]),
            worker_id=execution.get("worker_id"),
            started_at=parse_timestamp(execution.get("started_at")),
            heartbeat_at=parse_timestamp(execution.get("heartbeat_at")),
            finished_at=parse_timestamp(execution.get("finished_at")),
            error=execution.get("error"),
            retry_count=int(execution["retry_count"]),
        )
        return copy

    async def create(self, payload: TaskCreateRequest) -> TaskResponse:
        if payload.client_request_id:
            existing = self.task_store.get_by_request_id(payload.client_request_id)
            if existing is not None:
                return deepcopy(existing)
        task_id = new_id("task")
        now = utc_now()
        task = TaskResponse(
            id=task_id,
            task=payload.task,
            status=TaskStatus.QUEUED,
            progress="Creating the proof contract",
            progress_percent=5,
            current_stage="contract",
            plan=[],
            claims=[],
            verifications=[],
            sources=[],
            audit=[
                AuditRecord(
                    id=new_id("audit"),
                    action="TASK_CREATED",
                    detail="Natural-language task received",
                    actor="user",
                    timestamp=now,
                )
            ],
            created_at=now,
            updated_at=now,
        )
        self.tasks[task_id] = task
        self.drafts[task_id] = payload
        self.task_store.save(task, payload.client_request_id)
        self.task_store.save_draft(task_id, payload)
        self.task_store.append_event(task_id, "task_created", "Task created.", {"query": payload.task})
        self.task_store.append_event(task_id, "task_queued", "Task queued for research execution.")
        self._start_worker(task_id, payload)
        return self._with_execution(task)

    def _start_worker(self, task_id: str, payload: TaskCreateRequest) -> None:
        if task_id in self._worker_tasks:
            existing = self._worker_tasks[task_id]
            if not existing.done():
                return
        worker_id = f"worker_{uuid4().hex[:12]}"
        claim = self.task_store.claim_execution(task_id, worker_id)
        if claim is None:
            return
        if claim.get("worker_id") != worker_id:
            return
        self._worker_ids[task_id] = worker_id
        worker = asyncio.create_task(self.run_pipeline(task_id, payload))
        self._worker_tasks[task_id] = worker
        worker.add_done_callback(lambda completed: self._worker_finished(task_id, completed))

    def _worker_finished(self, task_id: str, worker: asyncio.Task) -> None:
        self._retiring_workers.discard(worker)
        if self._worker_tasks.get(task_id) is worker:
            self._worker_tasks.pop(task_id, None)
            self._worker_ids.pop(task_id, None)
        if not worker.cancelled() and worker.exception() is not None:
            logger.error("Research worker for %s stopped unexpectedly.", task_id, exc_info=worker.exception())

    def _has_active_worker(self, task_id: str) -> bool:
        worker = self._worker_tasks.get(task_id)
        return worker is not None and not worker.done()

    def _cancel_worker(self, task_id: str) -> None:
        worker = self._worker_tasks.pop(task_id, None)
        self._worker_ids.pop(task_id, None)
        if worker is not None and not worker.done():
            self._retiring_workers.add(worker)
            worker.cancel()

    async def shutdown(self) -> None:
        workers = set(self._worker_tasks.values()) | self._retiring_workers
        for task_id in list(self._worker_tasks):
            self._cancel_worker(task_id)
        await asyncio.gather(*workers, return_exceptions=True)

    async def get(self, task_id: str) -> Optional[TaskResponse]:
        task = self.tasks.get(task_id)
        if task is not None and self._has_active_worker(task_id):
            return self._with_execution(task)
        stored = self.task_store.get(task_id)
        if stored is not None:
            if task is not None:
                # Preserve direct in-memory mutations made by tests and active
                # pipeline code until they are persisted by the agent.
                if task.updated_at >= stored.updated_at:
                    return self._with_execution(task)
            task = stored
            self.tasks[task_id] = stored
        return self._with_execution(task) if task else None

    async def list(self) -> list[TaskResponse]:
        results = []
        for stored in self.task_store.list():
            task = self.tasks.get(stored.id)
            if task is None or (not self._has_active_worker(stored.id) and task.updated_at < stored.updated_at):
                self.tasks[stored.id] = stored
                task = stored
            results.append(self._with_execution(task))
        return results

    async def delete(self, task_id: str) -> bool:
        task = self.tasks.get(task_id)
        if task is not None and task.status not in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED, TaskStatus.PARTIAL}:
            return False
        self._require_no_executing_action(task_id)
        deleted = self.task_store.delete(task_id)
        if deleted:
            self.tasks.pop(task_id, None)
            self.drafts.pop(task_id, None)
            self.contracts.pop(task_id, None)
            self.cancelled_task_ids.discard(task_id)
        return deleted

    async def cancel(self, task_id: str) -> Optional[TaskResponse]:
        task = self.tasks.get(task_id)
        if not task:
            stored = self.task_store.get(task_id)
            if stored is None:
                return None
            task = stored
            self.tasks[task_id] = task
        if task.status in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED}:
            return self._with_execution(task)
        if self.approval_service is not None:
            self.approval_service.invalidate_task_actions(
                task_id,
                "The task was cancelled; this action approval no longer applies.",
            )
        task.status = TaskStatus.CANCELLED
        task.research_execution_status = ResearchExecutionStatus.CANCELLED
        task.progress = "Cancelled by the user"
        task.current_stage = "cancelled"
        task.updated_at = utc_now()
        self._audit(task, "TASK_CANCELLED", "The task was cancelled by the user.", "user")
        self.cancelled_task_ids.add(task_id)
        self.task_store.save(task)
        self.task_store.append_event(task_id, "task_cancelled", "Task cancelled by the user.")
        self.task_store.cancel_execution(task_id, "Cancelled by the user")
        self._cancel_worker(task_id)
        if gate := self.paused_task_events.pop(task_id, None):
            gate.set()
        return self._with_execution(task)

    async def get_contract(self, task_id: str) -> Optional[ProofContract]:
        contract = self.contracts.get(task_id)
        if contract is None:
            contract = self.task_store.get_contract(task_id)
            if contract is not None:
                self.contracts[task_id] = contract
        return deepcopy(contract) if contract else None

    async def generate_contract(self, task_id: str) -> Optional[ProofContract]:
        lock = self._contract_locks.setdefault(task_id, asyncio.Lock())
        async with lock:
            task = self.tasks.get(task_id)
            if task is None:
                return None

            existing = self.contracts.get(task_id)
            if existing is not None:
                return deepcopy(existing)

            task_text = task.task
            target_version = task.contract_version
            worker_id = self._worker_ids.get(task_id)
            draft = self.drafts.get(task_id)
            budget = draft.budget if draft is not None else None
            contract = await generate_proof_contract(task_id, task_text, budget)

            # Contract generation may await a remote model. Do not attach a result
            # generated for an old task version if the task was refined meanwhile.
            current = self.tasks.get(task_id)
            if (
                current is not task
                or current.task != task_text
                or current.contract_version != target_version
                or current.status == TaskStatus.CANCELLED
                or self._worker_ids.get(task_id) != worker_id
            ):
                raise ContractConflictError(
                    "The task changed while its proof contract was being generated. Retry the request."
                )

            if target_version is not None:
                contract.version = target_version

            self.contracts[task_id] = contract
            self.task_store.save_contract(contract)
            current.contract_version = contract.version
            self._audit(
                current,
                "PROOF_CONTRACT_READY",
                f"Proof Contract version {contract.version} is associated with this task.",
                "agent",
            )
            return deepcopy(contract)

    def _require_no_executing_action(self, task_id: str) -> None:
        if self.approval_service is not None and self.approval_service.has_executing_action(task_id):
            raise TaskConflictError("Wait for the approved action to finish before changing this task.")

    async def retry(self, task_id: str) -> Optional[TaskResponse]:
        task = self.tasks.get(task_id)
        payload = self.drafts.get(task_id)
        if not task or not payload:
            return None
        if self._has_active_worker(task_id) or task.status in ACTIVE_RESEARCH_STATUSES | {TaskStatus.PAUSED, TaskStatus.EXECUTING}:
            raise TaskConflictError("Cancel the active task before retrying it.")
        self._require_no_executing_action(task_id)
        previous_attempts = task.research_report.source_attempts if task.research_report else []
        failed_domains = {
            attempt.domain.lower().rstrip(".")
            for attempt in previous_attempts
            if attempt.source_type == "page"
            and attempt.domain
            and attempt.failure_category != SourceFailureCategory.SUCCESS
        }
        successful_domains = {
            attempt.domain.lower().rstrip(".")
            for attempt in previous_attempts
            if attempt.source_type == "page"
            and attempt.domain
            and attempt.failure_category == SourceFailureCategory.SUCCESS
        }
        if not failed_domains:
            for source in task.sources:
                domain = (source.source_domain or "").lower().rstrip(".")
                if not domain:
                    continue
                source_failed = bool(
                    source.failure_type
                    or source.blocked_reason
                    or (source.status_code is not None and source.status_code >= 400)
                )
                if source_failed:
                    failed_domains.add(domain)
                else:
                    successful_domains.add(domain)
        retry_exclusions = failed_domains - successful_domains
        if retry_exclusions:
            self._retry_excluded_domains[task_id] = retry_exclusions
        if self.approval_service is not None:
            self.approval_service.invalidate_task_actions(
                task_id,
                "Research was retried; prior action approval no longer applies.",
            )
        task.status = TaskStatus.QUEUED
        task.research_execution_status = ResearchExecutionStatus.PENDING
        task.progress = "Creating the proof contract"
        task.progress_percent = 5
        task.current_stage = "contract"
        _clear_research_results(task)
        task.action_approval_id = None
        task.action_outcome = None
        task.action_contract_id = None
        task.execution_receipt_id = None
        task.updated_at = utc_now()
        self._audit(task, "TASK_RETRIED", "The task was retried by the user.", "user")
        self.task_store.save(task)
        self.task_store.increment_retry(task_id)
        self.cancelled_task_ids.discard(task_id)
        self._start_worker(task_id, payload)
        return self._with_execution(task)

    async def refine(self, task_id: str, payload: RefineTaskRequest) -> Optional[TaskResponse]:
        task = self.tasks.get(task_id)
        draft = self.drafts.get(task_id)
        if not task or not draft:
            return None
        if self._has_active_worker(task_id) or task.status in ACTIVE_RESEARCH_STATUSES | {TaskStatus.PAUSED, TaskStatus.EXECUTING}:
            raise TaskConflictError("Cancel the active task before refining it.")
        self._require_no_executing_action(task_id)
        next_contract_version = (task.contract_version or 0) + 1
        if next_contract_version > 100:
            raise ValueError("The task has reached the contract version limit.")
        refined_text = f"{draft.task}\nRefinement: {payload.instruction}".strip()
        if len(refined_text) > 3000:
            raise ValueError("The refined task must contain at most 3000 characters.")
        refined = TaskCreateRequest.model_validate({**draft.model_dump(), "task": refined_text})
        if self.approval_service is not None:
            self.approval_service.invalidate_task_actions(
                task_id,
                "The task was refined; prior action approval no longer applies.",
            )
        self.drafts[task_id] = refined
        self.task_store.save_draft(task_id, refined)
        self.contracts.pop(task_id, None)
        self.task_store.delete_contract(task_id)
        task.status = TaskStatus.PLANNED
        task.research_execution_status = ResearchExecutionStatus.PENDING
        task.task = refined.task
        task.progress = "Creating a contract for the refined task"
        task.progress_percent = 5
        task.current_stage = "contract"
        task.contract_version = next_contract_version
        _clear_research_results(task)
        task.action_approval_id = None
        task.action_outcome = None
        task.action_contract_id = None
        task.execution_receipt_id = None
        task.updated_at = utc_now()
        self._audit(task, "TASK_REFINED", payload.instruction, "user")
        self.task_store.save(task)
        self.task_store.increment_retry(task_id)
        self.cancelled_task_ids.discard(task_id)
        self._start_worker(task_id, refined)
        return self._with_execution(task)

    def set_approval_service(self, approval_service) -> None:
        self.approval_service = approval_service

    def _audit(self, task: TaskResponse, action: str, detail: str, actor: str) -> None:
        task.audit.append(
            AuditRecord(
                id=new_id("audit"),
                action=action,
                detail=detail,
                actor=actor,
                timestamp=utc_now(),
            )
        )
        task.updated_at = utc_now()
        self.task_store.save(task)

    def _update(
        self,
        task: TaskResponse,
        status: TaskStatus,
        progress: str,
        percent: int,
        stage: str,
        action: str,
        detail: str,
        actor: str = "agent",
    ) -> None:
        task.status = status
        if status in {TaskStatus.CREATED, TaskStatus.QUEUED, TaskStatus.PLANNED, TaskStatus.SEARCH_PENDING}:
            task.research_execution_status = ResearchExecutionStatus.PENDING
        elif status == TaskStatus.BLOCKED:
            task.research_execution_status = ResearchExecutionStatus.BLOCKED
        elif status == TaskStatus.PARTIAL:
            task.research_execution_status = ResearchExecutionStatus.PARTIAL
        elif status == TaskStatus.FAILED:
            task.research_execution_status = ResearchExecutionStatus.FAILED
        elif status == TaskStatus.CANCELLED:
            task.research_execution_status = ResearchExecutionStatus.CANCELLED
        elif status in {TaskStatus.COMPLETED}:
            task.research_execution_status = ResearchExecutionStatus.COMPLETED
        elif status == TaskStatus.PAUSED:
            task.research_execution_status = ResearchExecutionStatus.RUNNING
        else:
            task.research_execution_status = ResearchExecutionStatus.RUNNING
        task.progress = progress
        task.progress_percent = percent
        task.current_stage = stage
        self._audit(task, action, detail, actor)

    async def pause(self, task_id: str) -> Optional[TaskResponse]:
        task = self.tasks.get(task_id)
        if not task:
            task = self.task_store.get(task_id)
        if not task:
            return None
        if task.status not in ACTIVE_RESEARCH_STATUSES:
            return self._with_execution(task)
        event = self.paused_task_events.setdefault(task_id, asyncio.Event())
        event.clear()
        task.status = TaskStatus.PAUSED
        task.research_execution_status = ResearchExecutionStatus.RUNNING
        task.progress = "Paused by the user"
        task.current_stage = "paused"
        task.updated_at = utc_now()
        self._audit(task, "TASK_PAUSED", "The task was paused by the user.", "user")
        self.task_store.save(task)
        self.task_store.append_event(task_id, "task_paused", "Task paused by the user.")
        self.task_store.pause_execution(task_id)
        return self._with_execution(task)

    async def resume(self, task_id: str) -> Optional[TaskResponse]:
        task = self.tasks.get(task_id)
        if not task:
            task = self.task_store.get(task_id)
        if not task:
            return None
        if task.status != TaskStatus.PAUSED:
            return self._with_execution(task)
        draft = self.drafts.get(task_id)
        if not self._has_active_worker(task_id) and draft is None:
            raise TaskConflictError("This task has no valid saved draft to resume.")
        event = self.paused_task_events.setdefault(task_id, asyncio.Event())
        event.set()
        task.status = TaskStatus.QUEUED
        task.research_execution_status = ResearchExecutionStatus.PENDING
        task.progress = "Resumed; waiting to continue"
        task.current_stage = "queued"
        task.updated_at = utc_now()
        self._audit(task, "TASK_RESUMED", "The task was resumed by the user.", "user")
        self.task_store.save(task)
        self.task_store.append_event(task_id, "task_resumed", "Task resumed by the user.")
        if self._has_active_worker(task_id):
            self.task_store.resume_execution(task_id)
        else:
            self.task_store.interrupt_execution(task_id)
            _clear_research_results(task)
            self.task_store.save(task)
            self._start_worker(task_id, draft)
        return self._with_execution(task)

    async def resume_pending_pipelines(self) -> None:
        for task_id, task in list(self.tasks.items()):
            if task.status not in ACTIVE_RESEARCH_STATUSES or self._has_active_worker(task_id):
                continue
            self.task_store.interrupt_execution(task_id)
            draft = self.drafts.get(task_id)
            if draft is None:
                task.error = "Research could not resume because its saved draft is missing or invalid."
                self._update(
                    task, TaskStatus.FAILED, "Research could not resume", task.progress_percent,
                    "failed", "TASK_FAILED", task.error,
                )
                continue
            _clear_research_results(task)
            task.status = TaskStatus.QUEUED
            task.research_execution_status = ResearchExecutionStatus.PENDING
            task.progress = "Queued after backend restart"
            task.progress_percent = 5
            task.current_stage = "contract"
            task.updated_at = utc_now()
            self.task_store.save(task)
            self._start_worker(task_id, draft)

    def _worker_is_current(self, task_id: str, worker_id: str | None) -> bool:
        return task_id not in self.cancelled_task_ids and (
            worker_id is None or self._worker_ids.get(task_id) == worker_id
        )

    async def _wait_while_paused(self, task_id: str, worker_id: str | None = None) -> bool:
        if not self._worker_is_current(task_id, worker_id):
            return False
        event = self.paused_task_events.get(task_id)
        if event is not None:
            await event.wait()
        return self._worker_is_current(task_id, worker_id)

    async def run_pipeline(self, task_id: str, payload: TaskCreateRequest) -> None:
        task = self.tasks.get(task_id)
        if task is None:
            return
        worker_id = self._worker_ids.get(task_id)
        contract: ProofContract | None = None
        domains_rejected: set[str] = set()
        page_text_by_url: dict[str, str] = {}
        verified_claim_ids: set[str] = set()
        source_attempts: list[SourceAttemptRecord] = []
        source_requirement_ids: dict[str, set[str]] = {}
        discovered_source_urls: set[str] = set()
        rejected_source_urls: set[str] = set()
        attempted_source_urls: set[str] = set()
        retry_excluded_domains = self._retry_excluded_domains.pop(task_id, set())
        attempted_domains: set[str] = set(retry_excluded_domains)
        resilience = ResearchResiliencePolicy.from_environment()
        orchestrator = ResearchOrchestrator(resilience)
        source_fetch_attempt_count = 0
        recovery_operation_count = 0
        search_request_count = 0

        def persist_source_attempt(attempt: SourceAttemptRecord) -> None:
            source_attempts.append(attempt)
            event_type = "source_attempt_recorded" if attempt.source_type == "page" else "search_attempt_recorded"
            self.task_store.append_event(
                task_id,
                event_type,
                (
                    f"Source attempt {attempt.failure_category.value.lower()}: {attempt.domain or 'search provider'}"
                    if attempt.failure_category != SourceFailureCategory.SUCCESS
                    else f"Source attempt succeeded: {attempt.domain or 'search provider'}"
                ),
                attempt.model_dump(mode="json"),
            )

        async def verify_pending_claims() -> None:
            for claim in task.claims:
                if claim.id in verified_claim_ids:
                    continue
                if not await self._wait_while_paused(task_id, worker_id):
                    return
                collected_text = page_text_by_url.get(str(claim.evidence.source_url), "")
                try:
                    result = verify_claim(
                        VerificationRequest(claim=claim, extracted_text=collected_text)
                    )
                except Exception as exc:
                    logger.exception("Claim verification failed for task %s.", task_id)
                    detail = _safe_exception_detail(exc, "verification service unavailable")
                    reason = f"Claim verification failed: {detail}"
                    task.partial_failures.append(f"{claim.evidence.source_title}: {reason}")
                    result = VerificationResult(
                        claim_id=claim.id,
                        status=VerificationStatus.UNVERIFIED,
                        reason=reason,
                        evidence_quote=claim.evidence.quote,
                        evidence_source_url=claim.evidence.source_url,
                        evidence_timestamp=claim.evidence.timestamp,
                        checked_at=utc_now(),
                    )
                task.verifications.append(result)
                claim.verification_status = result.status
                claim.verification_reason = result.reason
                verified_claim_ids.add(claim.id)
                if result.status == VerificationStatus.CONTRADICTED:
                    self.task_store.append_event(
                        task_id,
                        "contradiction_detected",
                        f"Contradictory evidence found for {claim.field}.",
                        {"claim_id": claim.id, "field": claim.field, "reason": result.reason},
                    )

        async def process_source(
            result,
            required_for: set[str] | None = None,
            recovery_operation_id: str | None = None,
        ) -> bool:
            nonlocal source_fetch_attempt_count
            raw_url = str(result.url)
            safe_url = canonical_source_url(raw_url)
            if safe_url in attempted_source_urls:
                return False
            attempted_source_urls.add(safe_url)
            discovered_source_urls.add(safe_url)
            parsed = urlparse(safe_url)
            domain = (parsed.hostname or "").lower().rstrip(".") or None
            if domain:
                attempted_domains.add(domain)
            source_identifier = _stable_source_identifier(safe_url)
            requirement_ids = set(source_requirement_ids.get(safe_url, set()))
            requirement_ids.update(required_for or set())
            source_requirement_ids.setdefault(safe_url, set()).update(requirement_ids)

            for attempt_number in range(1, resilience.max_attempts_per_source + 1):
                if source_fetch_attempt_count >= resilience.max_source_attempts:
                    if requirement_ids:
                        self.task_store.append_event(
                            task_id,
                            "source_attempt_limit_reached",
                            "The configured source-attempt limit was reached.",
                            {"source_identifier": source_identifier, "requirement_ids": sorted(requirement_ids)},
                        )
                    return False
                if not await self._wait_while_paused(task_id, worker_id):
                    return False
                enforce_research_permission(contract, ActionType.BROWSE_PUBLIC_PAGE)
                source_fetch_attempt_count += 1
                page = None
                category = None
                status_code = None
                safe_reason = None
                try:
                    browser_request = BrowserVisitRequest(
                        url=raw_url,
                        query=contract.goal[:500],
                        allowed_domains=contract.allowed_domains,
                        timeout_seconds=20,
                        max_text_chars=50000,
                    )
                    if self.browser_provider is None:
                        page = await visit_public_page(browser_request)
                    else:
                        page = await visit_public_page(browser_request, self.browser_provider)
                    status_code = page.status_code
                    domains_rejected.update(page.rejected_domains)
                    page_failure = _page_failure(page)
                    if page_failure:
                        category = classify_source_failure(
                            status_code=page.status_code,
                            error=page_failure[1],
                            invalid_content=page_failure[0] == "malformed_source",
                        )
                        safe_reason = safe_failure_description(category, status_code)
                except UnsafeUrlError as exc:
                    if exc.rejected_domain:
                        domains_rejected.add(exc.rejected_domain.lower().rstrip("."))
                    category = SourceFailureCategory.ROBOTS_OR_RESTRICTION
                    safe_reason = "The URL was rejected by ProofPilot's public URL safety checks."
                except BrowserVisitError as exc:
                    category = classify_source_failure(error=exc, exception=exc)
                    safe_reason = safe_failure_description(category)
                except (ValidationError, TypeError, ValueError) as exc:
                    category = classify_source_failure(error=exc, invalid_content=True)
                    safe_reason = safe_failure_description(category)
                except Exception:
                    logger.exception("Source visit failed for task %s.", task_id)
                    category = SourceFailureCategory.UNKNOWN_FAILURE
                    safe_reason = safe_failure_description(category)

                if category is not None:
                    retry_eligible = resilience.retry_eligible(category, attempt_number)
                    attempt = SourceAttemptRecord(
                        source_identifier=source_identifier,
                        source_url=safe_url,
                        domain=domain,
                        attempt_number=attempt_number,
                        failure_category=category,
                        http_status=status_code,
                        error_description=safe_reason,
                        recovery_attempt_status=(
                            "RETRY_SCHEDULED" if retry_eligible
                            else "ALTERNATIVES_SEARCHED" if recovery_operation_id
                            else "NOT_NEEDED"
                        ),
                        recovery_operation_id=recovery_operation_id,
                        alternative_sources_found=bool(recovery_operation_id),
                        affected_requirement_ids=sorted(requirement_ids),
                        affects_requirement=bool(requirement_ids),
                        retry_eligible=retry_eligible,
                    )
                    persist_source_attempt(attempt)
                    if retry_eligible:
                        await resilience.wait_before_retry(attempt_number)
                        continue
                    source_url = canonical_source_url(str(page.url)) if page is not None else safe_url
                    source_title = page.title if page is not None and page.title else result.title
                    source = _failed_source(
                        source_url,
                        source_title,
                        coarse_failure_type(category),
                        safe_reason or safe_failure_description(category),
                        status_code=status_code,
                    )
                    source.affected_requirement_ids = sorted(requirement_ids)
                    task.sources.append(source)
                    task.partial_failures.append(f"{domain or source_title}: {source.failure_reason}")
                    self.task_store.append_event(
                        task_id,
                        "source_failed",
                        f"Source {category.value.lower()}: {domain or source_title}",
                        {
                            "url": source_url,
                            "domain": domain,
                            "failure_category": category.value,
                            "reason": source.failure_reason,
                            "attempt_number": attempt_number,
                            "requirement_ids": sorted(requirement_ids),
                        },
                    )
                    return False

                safe_page_url = canonical_source_url(str(page.url))
                page = page.model_copy(update={"url": safe_page_url})
                page_text_by_url[str(page.url)] = "\n".join([*page.headings, page.visible_text])
                source = SourceRecord(
                    url=safe_page_url,
                    title=page.title,
                    source_domain=urlparse(safe_page_url).hostname,
                    status_code=page.status_code,
                    headings_count=len(page.headings),
                )
                task.sources.append(source)
                self.task_store.append_event(
                    task_id,
                    "source_opened",
                    f"Source opened: {page.title}",
                    {"url": safe_page_url, "domain": source.source_domain, "status_code": page.status_code},
                )
                enforce_research_permission(contract, ActionType.EXTRACT_EVIDENCE)
                try:
                    claims = extract_structured_claims(page)
                except Exception as exc:
                    logger.exception("Evidence extraction failed for task %s.", task_id)
                    category = SourceFailureCategory.EXTRACTION_FAILED
                    safe_reason = _safe_exception_detail(exc, safe_failure_description(category))
                    source.failure_type = coarse_failure_type(category)
                    source.failure_reason = safe_reason
                    source.failed_at = utc_now()
                    task.partial_failures.append(f"{page.title}: {safe_reason}")
                    attempt = SourceAttemptRecord(
                        source_identifier=source_identifier,
                        source_url=safe_page_url,
                        domain=source.source_domain,
                        attempt_number=attempt_number,
                        failure_category=category,
                        http_status=page.status_code,
                        error_description=safe_reason,
                        recovery_attempt_status="NOT_NEEDED",
                        recovery_operation_id=recovery_operation_id,
                        alternative_sources_found=bool(recovery_operation_id),
                        retrieval_succeeded=True,
                        affected_requirement_ids=sorted(requirement_ids),
                        affects_requirement=bool(requirement_ids),
                    )
                    persist_source_attempt(attempt)
                    self.task_store.append_event(
                        task_id,
                        "source_failed",
                        f"Evidence extraction failed: {source.source_domain or page.title}",
                        {"url": safe_page_url, "failure_category": category.value, "reason": safe_reason},
                    )
                    return False

                mapped = map_evidence_to_requirements(contract, claims)
                evidence_requirement_ids = {
                    requirement_id
                    for record in mapped
                    for requirement_id in record.associated_requirement_ids
                }
                attempt = SourceAttemptRecord(
                    source_identifier=source_identifier,
                    source_url=safe_page_url,
                    domain=source.source_domain,
                    attempt_number=attempt_number,
                    failure_category=SourceFailureCategory.SUCCESS,
                    http_status=page.status_code,
                    recovery_attempt_status=("ALTERNATIVES_SEARCHED" if recovery_operation_id else "NOT_NEEDED"),
                    recovery_operation_id=recovery_operation_id,
                    alternative_sources_found=bool(recovery_operation_id),
                    retrieval_succeeded=True,
                    evidence_extracted=bool(claims),
                    affected_requirement_ids=sorted(evidence_requirement_ids),
                    affects_requirement=bool(evidence_requirement_ids),
                )
                persist_source_attempt(attempt)
                for claim in claims:
                    if len(task.claims) >= 20:
                        break
                    claim.id = new_id("claim")
                    self.task_store.append_event(
                        task_id,
                        "claim_extracted",
                        f"Claim extracted: {claim.field}",
                        {"claim_id": claim.id, "subject": claim.subject, "field": claim.field, "value": claim.value},
                    )
                    self.task_store.append_event(
                        task_id,
                        "evidence_attached",
                        "Evidence attached to extracted claim.",
                        {"claim_id": claim.id, "source_url": str(claim.evidence.source_url), "quote": claim.evidence.quote},
                    )
                    task.claims.append(claim)
                return bool(evidence_requirement_ids)

        try:
            if task_id in self.cancelled_task_ids:
                return
            self.task_store.append_event(task_id, "task_started", "Research execution started.")
            if worker_id:
                self.task_store.heartbeat_execution(task_id, worker_id)
            if not await self._wait_while_paused(task_id, worker_id):
                return
            contract = await self.generate_contract(task_id)
            if not await self._wait_while_paused(task_id, worker_id):
                return
            if contract is None:
                raise RuntimeError("The task no longer exists, so research cannot start.")
            contract = ProofContract.model_validate(contract.model_dump(mode="python"))
            task.contract_version = contract.version

            for action in (
                ActionType.SEARCH_PUBLIC_WEB,
                ActionType.BROWSE_PUBLIC_PAGE,
                ActionType.EXTRACT_EVIDENCE,
            ):
                enforce_research_permission(contract, action)

            blocking_ambiguities = [
                ambiguity
                for ambiguity in contract.ambiguities
                if ambiguity.blocking_stage == "research"
            ]
            if contract.clarification_required_before_research or blocking_ambiguities:
                clarification_text = "\n".join(
                    f"{item.clarification_question}" for item in blocking_ambiguities
                ) or "Clarification is required before research can begin."
                task.status = TaskStatus.BLOCKED
                task.research_execution_status = ResearchExecutionStatus.BLOCKED
                task.progress = "Research is blocked until the task is clarified"
                task.progress_percent = 5
                task.current_stage = "contract_blocked"
                task.error = clarification_text
                task.research_report = build_research_report(
                    task_id=task_id,
                    contract=contract,
                    claims=[],
                    sources=[],
                    domains_rejected=[],
                    research_failures=[],
                    status_override=ResearchReportStatus.BLOCKED,
                )
                self._audit(
                    task,
                    "RESEARCH_BLOCKED_BY_CONTRACT",
                    clarification_text,
                    "agent",
                )
                self.task_store.save(task)
                if worker_id:
                    self.task_store.finish_execution(task_id, worker_id, "completed")
                return

            planner_context = dict(payload.context)
            planner_context["proof_contract"] = contract.model_dump(mode="json")
            planned = await create_plan(
                PlannerRequest(
                    task=contract.goal,
                    budget=payload.budget,
                    context=planner_context,
                )
            )
            if not await self._wait_while_paused(task_id, worker_id):
                return
            task.plan = planned.steps
            search_targets = _contract_search_targets(contract, planned.search_queries)
            search_queries = [query for query, _ in search_targets]
            self.task_store.append_event(
                task_id,
                "search_started",
                f"Starting {len(search_queries)} contract-aware searches.",
                {"query_count": len(search_queries)},
            )
            self._update(
                task,
                TaskStatus.SEARCHING,
                "Focused search queries prepared",
                20,
                "search",
                "PLAN_READY",
                f"{len(planned.steps)}-step plan with {len(search_queries)} contract-aware search queries",
            )

            unique_results = {}
            seen_source_hosts: dict[str, str] = {}
            search_provider_unavailable = False
            for index, (query, target_requirement_ids) in enumerate(search_targets, start=1):
                if search_provider_unavailable:
                    break
                if not await self._wait_while_paused(task_id, worker_id):
                    return
                enforce_research_permission(contract, ActionType.SEARCH_PUBLIC_WEB)
                response = None
                search_identifier = f"search_{hashlib.sha256(query.encode('utf-8')).hexdigest()[:20]}"
                for search_attempt_number in range(1, resilience.max_attempts_per_source + 1):
                    try:
                        search_request_count += 1
                        response = await search_public_web(
                            SearchRequest(
                                query=query,
                                max_results=2,
                                include_domains=contract.allowed_domains,
                                exclude_domains=sorted(retry_excluded_domains),
                            )
                        )
                        persist_source_attempt(SourceAttemptRecord(
                            source_identifier=search_identifier,
                            source_type="search",
                            attempt_number=search_attempt_number,
                            failure_category=SourceFailureCategory.SUCCESS,
                            affected_requirement_ids=target_requirement_ids,
                            affects_requirement=bool(target_requirement_ids),
                        ))
                        break
                    except Exception as exc:
                        if not await self._wait_while_paused(task_id, worker_id):
                            return
                        category = classify_source_failure(
                            status_code=getattr(exc, "status_code", None),
                            error=exc,
                            exception=exc,
                        )
                        if isinstance(exc, SearchConfigurationError) or getattr(exc, "status_code", None) == 401:
                            search_provider_unavailable = True
                        eligible = resilience.retry_eligible(category, search_attempt_number)
                        safe_reason = (
                            "The configured search provider is not available."
                            if isinstance(exc, SearchConfigurationError) or getattr(exc, "status_code", None) == 401
                            else safe_failure_description(category, getattr(exc, "status_code", None))
                            if getattr(exc, "status_code", None) is not None
                            else _safe_exception_detail(exc, safe_failure_description(category))
                        )
                        persist_source_attempt(SourceAttemptRecord(
                            source_identifier=search_identifier,
                            source_type="search",
                            attempt_number=search_attempt_number,
                            failure_category=category,
                            http_status=getattr(exc, "status_code", None),
                            error_description=safe_reason,
                            retry_eligible=eligible,
                            recovery_attempt_status="RETRY_SCHEDULED" if eligible else "NOT_NEEDED",
                            affected_requirement_ids=target_requirement_ids,
                            affects_requirement=bool(target_requirement_ids),
                        ))
                        if eligible:
                            await resilience.wait_before_retry(search_attempt_number)
                            continue
                        task.partial_failures.append(safe_reason)
                        self.task_store.append_event(
                            task_id,
                            "search_completed",
                            f"Search request failed: {safe_reason}",
                            {"search_id": search_identifier, "failure_category": category.value},
                        )
                        break

                if response is not None:
                    if not await self._wait_while_paused(task_id, worker_id):
                        return
                    for result in response.results:
                        safe_url = canonical_source_url(str(result.url))
                        discovered_source_urls.add(safe_url)
                        hostname = (urlparse(safe_url).hostname or "").lower().rstrip(".")
                        if hostname in retry_excluded_domains:
                            self.task_store.append_event(
                                task_id,
                                "source_skipped_after_retry",
                                "A previously failed source was excluded from the retry.",
                                {"url": safe_url, "domain": hostname},
                            )
                            continue
                        if not is_domain_allowed_url(str(result.url), contract.allowed_domains):
                            hostname = urlparse(str(result.url)).hostname
                            if hostname:
                                domains_rejected.add(hostname.lower().rstrip("."))
                            rejected_source_urls.add(safe_url)
                            self.task_store.append_event(
                                task_id,
                                "source_rejected_by_contract",
                                "A discovered source was outside the ProofContract's allowed domains.",
                                {"url": safe_url, "domain": hostname, "reason": "domain_not_allowed"},
                            )
                            continue
                        parsed = urlparse(safe_url)
                        host = (parsed.hostname or "").lower().rstrip(".")
                        canonical_url = safe_url
                        if canonical_url in unique_results:
                            source_requirement_ids.setdefault(canonical_url, set()).update(target_requirement_ids)
                            continue
                        previous_host_count = sum(1 for value in seen_source_hosts.values() if value == host)
                        if previous_host_count >= 2:
                            continue
                        seen_source_hosts[canonical_url] = host
                        unique_results[canonical_url] = result
                        source_requirement_ids.setdefault(canonical_url, set()).update(target_requirement_ids)
                        discovered_source_urls.add(canonical_url)
                        self.task_store.append_event(
                            task_id,
                            "source_discovered",
                            f"Source discovered: {host}",
                            {"url": canonical_url, "title": result.title, "requirement_ids": target_requirement_ids},
                        )

                if search_provider_unavailable:
                    break

                task.progress = f"Searching contract-permitted sources ({index}/{len(search_queries)})"
                task.progress_percent = 20 + int(15 * index / max(1, len(search_queries)))
                task.updated_at = utc_now()

            self.task_store.append_event(
                task_id,
                "search_completed",
                f"Search completed with {len(unique_results)} unique source candidates.",
                {"source_count": len(unique_results)},
            )

            if not unique_results:
                if contract.allowed_domains:
                    task.partial_failures.append(
                        "No search results matched the contract's allowed domains."
                    )
                else:
                    task.partial_failures.append("No search results were available.")

            result_list = list(unique_results.values())[:5]
            task.sources = []
            if not result_list:
                self._update(
                    task,
                    TaskStatus.VERIFYING,
                    "No sources were available. Compiling a partial report.",
                    55,
                    "browser",
                    "SEARCH_PARTIAL",
                    "; ".join(task.partial_failures),
                )
            else:
                self._update(
                    task,
                    TaskStatus.BROWSING,
                    f"Visiting {len(result_list)} permitted public sources",
                    45,
                    "browser",
                    "SEARCH_READY",
                    f"Selected {len(result_list)} unique source URLs",
                )

                for index, result in enumerate(result_list, start=1):
                    await process_source(result)
                    task.progress = f"Extracting evidence ({index}/{len(result_list)} pages)"
                    task.progress_percent = 45 + int(25 * index / len(result_list))
                    task.updated_at = utc_now()

            task.claims = task.claims[:20]
            if not await self._wait_while_paused(task_id, worker_id):
                return
            await verify_pending_claims()

            requirements_needing_recovery = orchestrator.requirements_needing_recovery(contract, task.claims)
            for requirement in requirements_needing_recovery:
                requirement_id = requirement.id
                if recovery_operation_count >= resilience.max_recovery_operations:
                    for attempt in source_attempts:
                        if attempt.source_type == "page" and requirement_id in attempt.affected_requirement_ids:
                            attempt.recovery_attempt_status = "LIMIT_REACHED"
                    self.task_store.append_event(
                        task_id,
                        "requirement_recovery_limited",
                        "The configured recovery-operation limit was reached.",
                        {"requirement_id": requirement_id, "limit": resilience.max_recovery_operations},
                    )
                    break
                if source_fetch_attempt_count >= resilience.max_source_attempts:
                    for attempt in source_attempts:
                        if attempt.source_type == "page" and requirement_id in attempt.affected_requirement_ids:
                            attempt.recovery_attempt_status = "LIMIT_REACHED"
                    self.task_store.append_event(
                        task_id,
                        "requirement_recovery_limited",
                        "The configured source-attempt limit was reached before recovery.",
                        {"requirement_id": requirement_id, "limit": resilience.max_source_attempts},
                    )
                    break
                if not await self._wait_while_paused(task_id, worker_id):
                    return

                recovery_operation_count += 1
                recovery_operation_id = new_id("recovery")
                query = orchestrator.query_for_requirement(contract, requirement)
                search_identifier = f"search_{hashlib.sha256(query.encode('utf-8')).hexdigest()[:20]}"
                excluded_domains = sorted(attempted_domains)
                self.task_store.append_event(
                    task_id,
                    "requirement_recovery_started",
                    f"Searching for an alternative source for requirement {requirement_id}.",
                    {
                        "recovery_operation_id": recovery_operation_id,
                        "requirement_id": requirement_id,
                        "excluded_domains": excluded_domains,
                    },
                )
                recovery_response = None
                for search_attempt_number in range(1, resilience.max_attempts_per_source + 1):
                    try:
                        search_request_count += 1
                        recovery_response = await search_public_web(
                            SearchRequest(
                                query=query,
                                max_results=4,
                                include_domains=contract.allowed_domains,
                                exclude_domains=excluded_domains,
                            )
                        )
                        persist_source_attempt(SourceAttemptRecord(
                            source_identifier=search_identifier,
                            source_type="search",
                            attempt_number=search_attempt_number,
                            failure_category=SourceFailureCategory.SUCCESS,
                            recovery_operation_id=recovery_operation_id,
                            affected_requirement_ids=[requirement_id],
                            affects_requirement=True,
                        ))
                        break
                    except Exception as exc:
                        category = classify_source_failure(
                            status_code=getattr(exc, "status_code", None),
                            error=exc,
                            exception=exc,
                        )
                        eligible = resilience.retry_eligible(category, search_attempt_number)
                        safe_reason = (
                            "The configured search provider is not available."
                            if isinstance(exc, SearchConfigurationError) or getattr(exc, "status_code", None) == 401
                            else safe_failure_description(category, getattr(exc, "status_code", None))
                            if getattr(exc, "status_code", None) is not None
                            else _safe_exception_detail(exc, safe_failure_description(category))
                        )
                        persist_source_attempt(SourceAttemptRecord(
                            source_identifier=search_identifier,
                            source_type="search",
                            attempt_number=search_attempt_number,
                            failure_category=category,
                            http_status=getattr(exc, "status_code", None),
                            error_description=safe_reason,
                            retry_eligible=eligible,
                            recovery_attempt_status="RETRY_SCHEDULED" if eligible else "ALTERNATIVES_NOT_FOUND",
                            recovery_operation_id=recovery_operation_id,
                            affected_requirement_ids=[requirement_id],
                            affects_requirement=True,
                        ))
                        if eligible:
                            await resilience.wait_before_retry(search_attempt_number)
                            continue
                        task.partial_failures.append(safe_reason)
                        break

                recovery_candidates = []
                if recovery_response is not None:
                    seen_recovery_domains: set[str] = set()
                    for result in recovery_response.results:
                        if not is_domain_allowed_url(str(result.url), contract.allowed_domains):
                            rejected_host = urlparse(str(result.url)).hostname
                            if rejected_host:
                                domains_rejected.add(rejected_host.lower().rstrip("."))
                            rejected_url = canonical_source_url(str(result.url))
                            discovered_source_urls.add(rejected_url)
                            rejected_source_urls.add(rejected_url)
                            self.task_store.append_event(
                                task_id,
                                "source_rejected_by_contract",
                                "An alternative source was outside the ProofContract's allowed domains.",
                                {"url": rejected_url, "domain": rejected_host, "reason": "domain_not_allowed"},
                            )
                            continue
                        safe_url = canonical_source_url(str(result.url))
                        host = (urlparse(safe_url).hostname or "").lower().rstrip(".")
                        same_attempted_domain = any(
                            host == previous or host.endswith(f".{previous}") or previous.endswith(f".{host}")
                            for previous in attempted_domains
                        )
                        if not host or same_attempted_domain or safe_url in discovered_source_urls:
                            continue
                        if host in seen_recovery_domains:
                            continue
                        seen_recovery_domains.add(host)
                        source_requirement_ids.setdefault(safe_url, set()).add(requirement_id)
                        discovered_source_urls.add(safe_url)
                        recovery_candidates.append(result)
                        self.task_store.append_event(
                            task_id,
                            "source_discovered",
                            f"Alternative source discovered: {host}",
                            {"url": safe_url, "title": result.title, "requirement_ids": [requirement_id]},
                        )
                        if len(recovery_candidates) >= 2:
                            break

                related_failures = [
                    attempt for attempt in source_attempts
                    if attempt.source_type == "page"
                    and attempt.failure_category != SourceFailureCategory.SUCCESS
                    and requirement_id in attempt.affected_requirement_ids
                ]
                for failed_attempt in related_failures:
                    failed_attempt.recovery_operation_id = recovery_operation_id
                    failed_attempt.alternative_sources_found = bool(recovery_candidates)
                    failed_attempt.recovery_attempt_status = (
                        "ALTERNATIVES_FOUND" if recovery_candidates else "ALTERNATIVES_NOT_FOUND"
                    )

                recovered = False
                for result in recovery_candidates:
                    if source_fetch_attempt_count >= resilience.max_source_attempts:
                        break
                    await process_source(result, {requirement_id}, recovery_operation_id)
                    await verify_pending_claims()
                    if orchestrator.has_resolved_requirement(contract, task.claims, requirement_id):
                        recovered = True
                        break

                if recovered:
                    for attempt in source_attempts:
                        if attempt.recovery_operation_id == recovery_operation_id:
                            attempt.recovery_attempt_status = "RECOVERED"
                    for failed_attempt in related_failures:
                        failed_attempt.recovery_attempt_status = "RECOVERED"
                elif recovery_candidates and source_fetch_attempt_count >= resilience.max_source_attempts:
                    for failed_attempt in related_failures:
                        failed_attempt.recovery_attempt_status = "LIMIT_REACHED"
                self.task_store.append_event(
                    task_id,
                    "requirement_recovery_completed",
                    f"Alternative-source recovery {'recovered evidence' if recovered else 'did not resolve the requirement'}.",
                    {
                        "recovery_operation_id": recovery_operation_id,
                        "requirement_id": requirement_id,
                        "alternative_sources_found": bool(recovery_candidates),
                        "recovered": recovered,
                    },
                )

            self._update(
                task,
                TaskStatus.VERIFYING,
                f"Verifying {len(task.claims)} extracted claims",
                75,
                "verification",
                "CLAIMS_EXTRACTED",
                f"Extracted {len(task.claims)} claims from collected page text",
            )

            await verify_pending_claims()
            verifications = task.verifications
            task.progress_percent = 85
            task.progress = "Comparing findings and separating verified facts from inference"
            task.current_stage = "analysis"
            task.updated_at = utc_now()
            self.task_store.append_event(
                task_id,
                "analysis_started",
                f"Analyzing {len(task.claims)} extracted claims.",
                {"claim_count": len(task.claims)},
            )
            self._audit(
                task,
                "CLAIMS_VERIFIED",
                f"Claim-level source verification: {len([v for v in verifications if v.status.value == 'supported'])} supported, "
                f"{len([v for v in verifications if v.status.value == 'contradicted'])} contradicted, "
                f"{len([v for v in verifications if v.status.value == 'unverified'])} unverified. "
                "ProofContract requirement evaluation is a separate layer.",
                "verifier",
            )
            verification_counts = {
                status.value: sum(1 for result in verifications if result.status == status)
                for status in VerificationStatus
            }
            self.task_store.append_event(
                task_id,
                "claim_verification_summary",
                "Claim-level source verification completed; requirement evaluation remains separate.",
                verification_counts,
            )

            analysis = await analyze_findings(
                AnalyzerRequest(
                    task=payload.task,
                    claims=task.claims,
                    verifications=task.verifications,
                )
            )
            if not await self._wait_while_paused(task_id, worker_id):
                return
            task.analysis = analysis

            task.research_report = build_research_report(
                task_id=task_id,
                contract=contract,
                claims=task.claims,
                sources=task.sources,
                domains_rejected=list(domains_rejected),
                research_failures=task.partial_failures,
                execution_status=(
                    ResearchExecutionStatus.COMPLETED_WITH_WARNINGS
                    if any(item.failure_category != SourceFailureCategory.SUCCESS for item in source_attempts)
                    else ResearchExecutionStatus.COMPLETED
                ),
                source_attempts=source_attempts,
                sources_discovered=len(discovered_source_urls),
                sources_rejected=len(rejected_source_urls),
            )
            for source in task.sources:
                if source.failure_type is not None:
                    self.task_store.append_event(
                        task_id,
                        "source_coverage_assessed",
                        f"Source failure impact on ProofContract coverage: {source.coverage_impact}.",
                        {
                            "url": str(source.url),
                            "domain": source.source_domain,
                            "failure_type": source.failure_type,
                            "failure_reason": source.failure_reason,
                            "failed_at": source.failed_at.isoformat() if source.failed_at else None,
                            "coverage_impact": source.coverage_impact,
                            "affected_requirement_ids": source.affected_requirement_ids,
                        },
                    )
            self.task_store.append_event(
                task_id,
                "report_generated",
                "Structured research report generated.",
                {
                    "claim_count": len(task.claims),
                    "source_count": len(task.sources),
                    "failure_count": len(task.partial_failures),
                },
            )
            task.status = (
                TaskStatus.PARTIAL
                if task.research_report.status == ResearchReportStatus.PARTIAL
                else TaskStatus.COMPLETED
            )
            task.research_execution_status = task.research_report.execution_status
            summary = task.research_report.source_summary
            unresolved_count = summary.requirements_unresolved
            task.progress = (
                f"Research process completed; {unresolved_count} requirement(s) remain unresolved after "
                f"{summary.sources_attempted} source(s) and {summary.recovery_attempts} recovery operation(s)."
                if task.status == TaskStatus.PARTIAL
                else (
                    "Research completed with source warnings; all current ProofContract requirements were evaluated."
                    if task.research_report.execution_status == ResearchExecutionStatus.COMPLETED_WITH_WARNINGS
                    else "Contract-enforced research and evaluation completed"
                )
            )
            task.progress_percent = 100
            task.current_stage = "complete"
            self._audit(
                task,
                "TASK_PARTIAL" if task.status == TaskStatus.PARTIAL else "TASK_COMPLETED",
                task.progress,
                "agent",
            )
            self.task_store.append_event(
                task_id,
                "task_completed" if task.status == TaskStatus.COMPLETED else "task_partial",
                task.progress,
                {"status": task.status.value},
            )
            self.task_store.save(task)
            if worker_id:
                self.task_store.finish_execution(
                    task_id,
                    worker_id,
                    "completed" if task.status == TaskStatus.COMPLETED else "partial",
                )
        except Exception as exc:
            if not await self._wait_while_paused(task_id, worker_id):
                return
            logger.exception("Research workflow failed for task %s.", task_id)
            task.status = TaskStatus.FAILED
            task.research_execution_status = ResearchExecutionStatus.FAILED
            safe_error = f"The research workflow failed during {task.current_stage or 'processing'}."
            task.progress = safe_error
            task.progress_percent = max(task.progress_percent, 1)
            task.current_stage = "failed"
            task.error = safe_error
            task.partial_failures.append(safe_error)
            for claim in task.claims:
                if claim.id not in verified_claim_ids:
                    claim.verification_status = VerificationStatus.UNVERIFIED
                    claim.verification_reason = (
                        "The research pipeline failed before this claim could be verified."
                    )
            if contract is not None:
                task.research_report = build_research_report(
                    task_id=task_id,
                    contract=contract,
                    claims=task.claims,
                    sources=task.sources,
                    domains_rejected=list(domains_rejected),
                    research_failures=task.partial_failures,
                    status_override=ResearchReportStatus.FAILED,
                    execution_status=ResearchExecutionStatus.FAILED,
                    source_attempts=source_attempts,
                    sources_discovered=len(discovered_source_urls),
                    sources_rejected=len(rejected_source_urls),
                )
            self._audit(task, "TASK_FAILED", safe_error, "agent")
            self.task_store.append_event(
                task_id,
                "task_failed",
                safe_error,
                {"error_type": type(exc).__name__, "stage": task.current_stage},
            )
            self.task_store.save(task)
            if worker_id:
                self.task_store.finish_execution(task_id, worker_id, "failed", safe_error)
