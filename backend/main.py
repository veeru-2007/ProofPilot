import asyncio
from html import escape
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from uuid import uuid4
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field

from agent import TaskAgent, TaskConflictError
from approval import ApprovalService
from adversarial_demo import DEMO_ATTACK_INSTRUCTION
from contracts import ContractConflictError, ContractGenerationError, ContractInputError
from demo_scenario import create_simulated_demo
from evidence import extract_structured_claims
from planner import create_plan
from analyzer import analyze_findings
from models import (
    ActionContract,
    ActionContractCreateRequest,
    ActionContractStatus,
    BrowserPageResponse,
    BrowserVisitRequest,
    Claim,
    DemoSubmission,
    ExecutionReceipt,
    AnalyzerRequest,
    AnalyzerOutput,
    PlannerRequest,
    PlannerOutput,
    ProofContract,
    VerificationRequest,
    VerificationResult,
    RefineTaskRequest,
    SearchRequest,
    SearchResponse,
    TaskCreateRequest,
    TaskResponse,
)
from search import (
    SearchConfigurationError,
    SearchProviderError,
    search_public_web,
)
from verifier import verify_claim
from browser import (
    BrowserVisitError,
    UnsafeUrlError,
    visit_public_page,
)
from task_store import TaskStore
from browser_providers import (
    browser_provider_status,
    create_browser_provider_from_env,
)
from warrant import WarrantError
from warrant_models import SignedWarrant, ValidatedPlan
from policy import PolicyDecision

load_dotenv(Path(__file__).with_name(".env"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.browser_provider = create_browser_provider_from_env()
    database_path = os.getenv("PROOFPILOT_DB_PATH", "").strip() or None
    app.state.task_store = TaskStore(database_path) if database_path else TaskStore()
    app.state.demo_submissions = {
        item["submission_id"]: item
        for item in app.state.task_store.list_demo_submissions()
    }
    app.state.demo_idempotency = app.state.task_store.list_demo_submission_index()
    app.state.approval_service = ApprovalService(
        demo_records=app.state.demo_submissions,
        idempotency_index=app.state.demo_idempotency,
        store=app.state.task_store,
        browser_provider=app.state.browser_provider,
    )
    app.state.task_agent = TaskAgent(
        app.state.approval_service,
        task_store=app.state.task_store,
        browser_provider=app.state.browser_provider,
    )
    try:
        await app.state.task_agent.resume_pending_pipelines()
        yield
    finally:
        await app.state.task_agent.shutdown()


app = FastAPI(
    title="ProofPilot API",
    description="Evidence-backed, human-controlled browser research API.",
    version="0.1.0",
    lifespan=lifespan,
)

allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173",
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(TaskConflictError)
async def task_conflict_handler(request: Request, exc: TaskConflictError):
    return JSONResponse(status_code=409, content={"detail": str(exc)})


@app.exception_handler(WarrantError)
async def warrant_error_handler(request: Request, exc: WarrantError):
    return JSONResponse(status_code=exc.status_code, content={"detail": {"code": exc.code, "message": exc.message}})


@app.get("/api/health", tags=["System"])
async def health(request: Request):
    search_configured = bool(os.getenv("TAVILY_API_KEY", "").strip())
    provider_status = browser_provider_status(request.app.state.browser_provider)
    approval_service = getattr(request.app.state, "approval_service", None)
    return {
        "status": "ok",
        "service": "ProofPilot API",
        "api_version": 1,
        "search": "configured" if search_configured else "not_configured",
        "browser": (
            "playwright_ready"
            if provider_status["provider"] == "local"
            else provider_status["status"]
        ),
        "browser_provider": provider_status,
        "warrant_signing_mode": approval_service.warrant_signer.mode if approval_service else "disabled",
    }


@app.get("/api/browser/status", tags=["System"])
async def browser_status(request: Request):
    """Return sanitized provider diagnostics without opening an AWS session."""
    return browser_provider_status(request.app.state.browser_provider)


@app.get("/demo/laptop-selection", response_class=HTMLResponse, include_in_schema=False)
async def laptop_selection_demo():
    instruction_attribute = escape(DEMO_ATTACK_INSTRUCTION, quote=True)
    return HTMLResponse("""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ProofPilot Demo Submission</title>
  <style>
    body{font-family:system-ui,sans-serif;background:#101218;color:#edf0f7;margin:0;padding:32px}
    main{max-width:620px;margin:auto;border:1px solid #30343f;border-radius:12px;background:#151820;padding:24px}
    h1{font-size:22px;margin-top:0} label{display:block;font-size:12px;color:#aab0bd;margin-top:14px}
    input,textarea{width:100%;box-sizing:border-box;margin-top:6px;border:1px solid #353946;border-radius:7px;background:#0f1116;color:#fff;padding:10px}
    button{margin-top:18px;border:1px solid #7599dc;border-radius:7px;background:#7197d8;color:#09101e;padding:10px 14px;font-weight:800}
    #result{margin-top:16px;color:#57d89b}
  </style>
</head>
<body>
  <main>
    <h1>ProofPilot laptop selection demo</h1>
    <p>Team-controlled local form. This page does not submit to a third-party service.</p>
    <aside hidden data-testid="proofpilot-injection" data-instruction="__PROOFPILOT_ATTACK_INSTRUCTION__"></aside>
    <label>Laptop<input id="laptop" name="laptop"></label>
    <label>Budget<input id="budget" name="budget"></label>
    <label>RAM<input id="ram" name="ram"></label>
    <label>GPU<input id="gpu" name="gpu"></label>
    <label>Reason<textarea id="reason" name="reason"></textarea></label>
    <button id="submit-selection" type="button">Submit approved selection</button>
    <div id="result" role="status"></div>
  </main>
  <script>
    document.querySelector('#submit-selection').addEventListener('click', async () => {
      const data = Object.fromEntries(['laptop','budget','ram','gpu','reason'].map(id => [id, document.querySelector('#'+id).value]));
      const status = document.querySelector('#result');
      status.textContent = 'Checking the approved request...';
      const response = await fetch('/demo/submissions', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)});
      const result = await response.json();
      status.textContent = response.ok
        ? 'Submission received: ' + result.submission_id
        : (result.detail || 'The request was not authorized. Prepare and approve it in ProofPilot first.');
    });
  </script>
</body>
</html>
""".replace("__PROOFPILOT_ATTACK_INSTRUCTION__", instruction_attribute))


@app.post("/demo/submissions", tags=["Demo"])
async def create_demo_submission(
    payload: DemoSubmission,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    try:
        return await request.app.state.approval_service.record_demo_submission(
            idempotency_key,
            payload.model_dump(mode="json"),
        )
    except WarrantError:
        raise
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/demo/selections/{submission_id}", tags=["Demo"])
async def get_demo_submission(submission_id: str, request: Request):
    record = request.app.state.demo_submissions.get(submission_id)
    if record is None:
        record = request.app.state.task_store.get_demo_submission(submission_id)
        if record is not None:
            request.app.state.demo_submissions[submission_id] = record
    if record is None:
        raise HTTPException(status_code=404, detail="Demo submission not found")
    return record


@app.post("/api/planner/plan", response_model=PlannerOutput, tags=["AI"])
async def plan_task(payload: PlannerRequest):
    return await create_plan(payload)


@app.post("/api/analyzer/analyze", response_model=AnalyzerOutput, tags=["AI"])
async def analyze(payload: AnalyzerRequest):
    return await analyze_findings(payload)


@app.post("/api/search", response_model=SearchResponse, tags=["Search"])
async def search(payload: SearchRequest):
    try:
        return await search_public_web(payload)
    except SearchConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except SearchProviderError as exc:
        status_code = exc.status_code if exc.status_code in {401, 429} else 502
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc


@app.post("/api/browser/visit", response_model=BrowserPageResponse, tags=["Browser"])
async def visit_page(payload: BrowserVisitRequest, request: Request):
    try:
        return await visit_public_page(payload, request.app.state.browser_provider)
    except UnsafeUrlError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except BrowserVisitError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/api/evidence/extract", response_model=list[Claim], tags=["Evidence"])
async def extract_evidence(payload: BrowserPageResponse, max_claims: int = 12):
    if not 1 <= max_claims <= 50:
        raise HTTPException(status_code=422, detail="max_claims must be between 1 and 50")
    return extract_structured_claims(payload, max_claims=max_claims)


@app.post("/api/verification/check", response_model=VerificationResult, tags=["Verification"])
async def check_verification(payload: VerificationRequest):
    return verify_claim(payload)


@app.get("/api/search/test", response_model=SearchResponse, tags=["Search"])
async def test_search(query: str = "ProofPilot public web search test", max_results: int = 3):
    try:
        payload = SearchRequest(query=query, max_results=max_results)
        return await search_public_web(payload)
    except SearchConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except SearchProviderError as exc:
        status_code = exc.status_code if exc.status_code in {401, 429} else 502
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc


@app.post("/api/tasks", response_model=TaskResponse, status_code=201, tags=["Tasks"])
async def create_task(payload: TaskCreateRequest, request: Request):
    try:
        return await request.app.state.task_agent.create(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/demo/scenario", response_model=TaskResponse, status_code=201, tags=["Demo"])
async def create_simulated_demo_scenario(request: Request):
    task_id = f"demo_{uuid4().hex[:12]}"
    task, contract = create_simulated_demo(task_id)
    draft = TaskCreateRequest(task=task.task)
    agent = request.app.state.task_agent
    store = request.app.state.task_store
    agent.tasks[task_id] = task
    agent.drafts[task_id] = draft
    agent.contracts[task_id] = contract
    store.save(task)
    store.save_draft(task_id, draft)
    store.save_contract(contract)
    store.append_event(task_id, "task_created", "A deterministic simulated demo was loaded.", {"simulated": True})
    store.append_event(
        task_id,
        "search_completed",
        "Loaded three fixed simulated product pages; no public search was performed.",
        {"simulated": True, "source_count": len(task.sources)},
    )
    for source in task.sources:
        store.append_event(
            task_id,
            "source_opened",
            f"Loaded simulated source: {source.title}",
            {"simulated": True, "url": str(source.url)},
        )
    store.append_event(
        task_id,
        "claim_extracted",
        f"Verified {len(task.claims)} claims from simulated sources.",
        {"simulated": True, "claim_count": len(task.claims)},
    )
    store.append_event(task_id, "report_generated", "Completed the simulated candidate evaluation.", {"simulated": True})
    store.append_event(task_id, "task_completed", "The simulated research scenario is complete.", {"simulated": True})
    return task


@app.get("/api/tasks/{task_id}", response_model=TaskResponse, tags=["Tasks"])
async def get_task(task_id: str, request: Request):
    task = await request.app.state.task_agent.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@app.get("/api/tasks", response_model=list[TaskResponse], tags=["Tasks"])
async def list_tasks(request: Request):
    return await request.app.state.task_agent.list()


@app.get("/api/events", tags=["Events"])
async def list_events(
    request: Request,
    task_id: str | None = None,
    limit: int = 500,
    after_event_id: str | None = None,
):
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
    if task_id is not None:
        task = await request.app.state.task_agent.get(task_id)
        if task is None:
            raise HTTPException(status_code=404, detail="Task not found")
    store = request.app.state.task_agent.task_store
    try:
        events = store.list_events(task_id, limit, after_event_id=after_event_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="Unknown event cursor.") from exc
    return [event.model_dump(mode="json") for event in events]


@app.get("/api/tasks/{task_id}/events/stream", tags=["Events"])
async def stream_task_events(task_id: str, request: Request, after_event_id: str | None = None):
    task = await request.app.state.task_agent.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")

    store = request.app.state.task_agent.task_store
    page_size = 500

    async def event_stream():
        cursor = request.headers.get("last-event-id") or after_event_id
        while not await request.is_disconnected():
            try:
                events = store.list_events(task_id, page_size, after_event_id=cursor)
            except ValueError:
                if cursor is None:
                    raise
                # A reconnect may refer to a cursor from a different API instance.
                # Replay from the start so the client can merge by event ID.
                cursor = None
                continue
            for event in events:
                cursor = event.event_id
                yield (
                    f"id: {event.event_id}\n"
                    f"event: {event.event_type}\n"
                    f"data: {event.model_dump_json()}\n\n"
                )
            if len(events) < page_size:
                yield ": keepalive\n\n"
                await asyncio.sleep(1)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/tasks/{task_id}/cancel", response_model=TaskResponse, tags=["Tasks"])
async def cancel_task(task_id: str, request: Request):
    task = await request.app.state.task_agent.cancel(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@app.post("/api/tasks/{task_id}/pause", response_model=TaskResponse, tags=["Tasks"])
async def pause_task(task_id: str, request: Request):
    task = await request.app.state.task_agent.pause(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@app.post("/api/tasks/{task_id}/resume", response_model=TaskResponse, tags=["Tasks"])
async def resume_task(task_id: str, request: Request):
    task = await request.app.state.task_agent.resume(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@app.delete("/api/tasks/{task_id}", tags=["Tasks"])
async def delete_task(task_id: str, request: Request):
    deleted = await request.app.state.task_agent.delete(task_id)
    if not deleted:
        task = await request.app.state.task_agent.get(task_id)
        if task is None:
            raise HTTPException(status_code=404, detail="Task not found")
        raise HTTPException(status_code=409, detail="Only completed, failed, partial, or cancelled tasks can be deleted")
    return {"deleted": True, "id": task_id}


@app.post(
    "/api/tasks/{task_id}/contract",
    response_model=ProofContract,
    status_code=201,
    tags=["Tasks"],
)
async def generate_task_contract(task_id: str, request: Request):
    try:
        contract = await request.app.state.task_agent.generate_contract(task_id)
    except ContractInputError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ContractConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ContractGenerationError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    if contract is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return contract


@app.get(
    "/api/tasks/{task_id}/contract",
    response_model=ProofContract,
    tags=["Tasks"],
)
async def get_task_contract(task_id: str, request: Request):
    task = await request.app.state.task_agent.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    contract = await request.app.state.task_agent.get_contract(task_id)
    if contract is None:
        raise HTTPException(status_code=404, detail="Proof contract not found")
    return contract


@app.post("/api/tasks/{task_id}/retry", response_model=TaskResponse, tags=["Tasks"])
async def retry_task(task_id: str, request: Request):
    task = await request.app.state.task_agent.retry(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@app.post("/api/tasks/{task_id}/refine", response_model=TaskResponse, tags=["Tasks"])
async def refine_task(task_id: str, payload: RefineTaskRequest, request: Request):
    task = await request.app.state.task_agent.refine(task_id, payload)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@app.post(
    "/api/tasks/{task_id}/actions",
    response_model=ActionContract,
    status_code=201,
    tags=["Action Contracts"],
)
async def prepare_action_contract(
    task_id: str,
    payload: ActionContractCreateRequest,
    request: Request,
):
    task = await request.app.state.task_agent.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    contract = await request.app.state.task_agent.get_contract(task_id)
    if contract is None:
        raise HTTPException(status_code=409, detail="A ProofContract must exist before action preparation.")
    try:
        action = await request.app.state.approval_service.prepare_action(task, contract, payload)
    except WarrantError:
        raise
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    stored_task = request.app.state.task_agent.tasks[task_id]
    stored_task.action_contract_id = action.action_id
    stored_task.execution_receipt_id = None
    stored_task.action_outcome = None
    request.app.state.task_agent._audit(
        stored_task,
        "ACTION_CONTRACT_PREPARED",
        f"ActionContract {action.action_id} is pending Warrant approval.",
        "agent",
    )
    return action


@app.get(
    "/api/tasks/{task_id}/actions",
    response_model=list[ActionContract],
    tags=["Action Contracts"],
)
async def list_task_actions(task_id: str, request: Request):
    task = await request.app.state.task_agent.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return await request.app.state.approval_service.list_for_task(task_id)


async def _load_action_context(action_id: str, request: Request):
    service = request.app.state.approval_service
    action = await service.get_action(action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="ActionContract not found")
    task = await request.app.state.task_agent.get(action.task_id)
    contract = await request.app.state.task_agent.get_contract(action.task_id)
    if task is None or contract is None:
        raise HTTPException(status_code=409, detail="The action task or ProofContract is unavailable.")
    return action, task, contract


@app.get("/api/actions/{action_id}", response_model=ActionContract, tags=["Action Contracts"])
async def get_action_contract(action_id: str, request: Request):
    action = await request.app.state.approval_service.get_action(action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="ActionContract not found")
    return action


class WarrantApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    warrant_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class WarrantValidationError(BaseModel):
    code: str
    message: str


class WarrantReviewResponse(BaseModel):
    warrant: SignedWarrant
    signature_valid: bool
    validation_error: WarrantValidationError | None
    approval_status: ActionContractStatus
    approved_warrant_hash: str | None
    signing_mode: Literal["configured", "local_demo", "disabled"]


async def _load_warrant_action(action_id: str, request: Request) -> ActionContract:
    action = await request.app.state.approval_service.get_action(action_id)
    if action is None:
        raise WarrantError("ACTION_NOT_FOUND", "ActionContract not found.", status_code=404)
    if action.warrant is None:
        raise WarrantError(
            "WARRANT_NOT_FOUND",
            "This action has no signed Warrant. Prepare a new action to request approval.",
            status_code=404,
        )
    return action


async def _validate_warrant_for_review(request: Request, action: ActionContract, warrant: SignedWarrant) -> None:
    proof = await request.app.state.task_agent.get_contract(action.task_id)
    if proof is None:
        raise WarrantError("WARRANT_PROOF_MISSING", "The ProofContract for this Warrant is unavailable.", status_code=409)
    request.app.state.approval_service.warrant_signer.validate(warrant, action, proof)
    if warrant != action.warrant:
        raise WarrantError("WARRANT_NOT_CURRENT", "The supplied Warrant is not current for this action.", status_code=409)


def _warrant_review_response(request: Request, action: ActionContract, error: WarrantError | None = None):
    return WarrantReviewResponse(
        warrant=action.warrant,
        signature_valid=error is None,
        validation_error=WarrantValidationError(code=error.code, message=error.message) if error else None,
        approval_status=action.status,
        approved_warrant_hash=action.approved_warrant_hash,
        signing_mode=request.app.state.approval_service.warrant_signer.mode,
    )


@app.get("/api/actions/{action_id}/plan", response_model=ValidatedPlan, tags=["Warrant"])
async def get_action_plan(action_id: str, request: Request):
    action = await _load_warrant_action(action_id, request)
    await _validate_warrant_for_review(request, action, action.warrant)
    return action.warrant.plan


@app.post("/api/actions/{action_id}/plan/validate", tags=["Warrant"])
async def validate_action_plan(action_id: str, payload: ValidatedPlan, request: Request):
    action = await _load_warrant_action(action_id, request)
    await _validate_warrant_for_review(request, action, action.warrant)
    if payload != action.warrant.plan:
        raise WarrantError("WARRANT_PLAN_MISMATCH", "The plan does not match the authorized action plan.", status_code=409)
    return {"valid": True, "plan_hash": action.warrant.plan_hash}


@app.get("/api/actions/{action_id}/warrant", response_model=WarrantReviewResponse, tags=["Warrant"])
async def get_action_warrant(action_id: str, request: Request):
    action = await _load_warrant_action(action_id, request)
    try:
        await _validate_warrant_for_review(request, action, action.warrant)
    except WarrantError as exc:
        return _warrant_review_response(request, action, exc)
    return _warrant_review_response(request, action)


@app.post("/api/actions/{action_id}/warrant/validate", response_model=WarrantReviewResponse, tags=["Warrant"])
async def validate_action_warrant(action_id: str, request: Request, payload: SignedWarrant | None = None):
    action = await _load_warrant_action(action_id, request)
    await _validate_warrant_for_review(request, action, payload or action.warrant)
    return _warrant_review_response(request, action)


@app.get("/api/actions/{action_id}/policy-decisions", response_model=list[PolicyDecision], tags=["Warrant Policy"])
async def get_action_policy_decisions(action_id: str, request: Request):
    action = await request.app.state.approval_service.get_action(action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="ActionContract not found")
    return request.app.state.approval_service.list_policy_decisions(action_id)


@app.post("/api/actions/{action_id}/approve", response_model=ActionContract, tags=["Action Contracts"])
async def approve_action_contract(action_id: str, request: Request, payload: WarrantApprovalRequest | None = None):
    _, task, contract = await _load_action_context(action_id, request)
    try:
        action = await request.app.state.approval_service.decide(
            action_id, True, task, contract, warrant_hash=payload.warrant_hash if payload else None,
        )
    except WarrantError:
        raise
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if action is None:
        raise HTTPException(status_code=404, detail="ActionContract not found")
    request.app.state.task_agent._audit(
        request.app.state.task_agent.tasks[action.task_id],
        "ACTION_APPROVED",
        f"ActionContract {action_id} approved with digest {action.approved_digest} and Warrant {action.approved_warrant_hash}.",
        "user",
    )
    return action


@app.post("/api/actions/{action_id}/reject", response_model=ActionContract, tags=["Action Contracts"])
async def reject_action_contract(action_id: str, request: Request):
    _, task, contract = await _load_action_context(action_id, request)
    try:
        action = await request.app.state.approval_service.decide(action_id, False, task, contract)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if action is None:
        raise HTTPException(status_code=404, detail="ActionContract not found")
    request.app.state.task_agent._audit(
        request.app.state.task_agent.tasks[action.task_id],
        "ACTION_REJECTED",
        f"ActionContract {action_id} rejected by the user.",
        "user",
    )
    return action


@app.post("/api/actions/{action_id}/execute", response_model=ExecutionReceipt, tags=["Action Contracts"])
async def execute_action_contract(action_id: str, request: Request):
    _, task, contract = await _load_action_context(action_id, request)
    try:
        receipt = await request.app.state.approval_service.execute(action_id, task, contract)
    except WarrantError:
        raise
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if receipt is None:
        raise HTTPException(status_code=404, detail="ActionContract not found")
    stored_task = request.app.state.task_agent.tasks.get(task.id)
    if stored_task is not None:
        stored_task.execution_receipt_id = receipt.receipt_id
        stored_task.action_outcome = receipt.model_dump(mode="json")
        request.app.state.task_agent._audit(
            stored_task,
            "ACTION_EXECUTION_RECORDED",
            f"ActionContract {action_id} reached {receipt.execution_status.value}.",
            "verifier",
        )
    return receipt


@app.get("/api/actions/{action_id}/receipt", response_model=ExecutionReceipt, tags=["Action Contracts"])
async def get_execution_receipt(action_id: str, request: Request):
    receipt = await request.app.state.approval_service.get_receipt(action_id)
    if receipt is None:
        raise HTTPException(status_code=404, detail="Execution receipt not found")
    return receipt


@app.post("/api/actions/{action_id}/reconcile", response_model=ExecutionReceipt, tags=["Action Contracts"])
async def reconcile_action_contract(action_id: str, request: Request):
    try:
        receipt = await request.app.state.approval_service.reconcile(action_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if receipt is None:
        raise HTTPException(status_code=404, detail="ActionContract not found")
    action = await request.app.state.approval_service.get_action(action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="ActionContract not found")
    stored_task = request.app.state.task_agent.tasks.get(action.task_id)
    if stored_task:
        stored_task.execution_receipt_id = receipt.receipt_id
        stored_task.action_outcome = receipt.model_dump(mode="json")
        request.app.state.task_agent._audit(
            stored_task,
            "ACTION_OUTCOME_RECONCILED",
            f"ActionContract {action_id} reconciled as {receipt.execution_status.value}.",
            "verifier",
        )
    return receipt
