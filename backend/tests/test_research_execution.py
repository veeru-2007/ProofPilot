import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from agent import TaskAgent, TaskConflictError
from models import (
    AnalyzerOutput,
    BrowserPageResponse,
    Claim,
    Evidence,
    PlannerOutput,
    ResearchExecutionStatus,
    ResearchReport,
    ResearchReportStatus,
    RefineTaskRequest,
    SearchResponse,
    SearchResult,
    SourceAttemptRecord,
    SourceFailureCategory,
    TaskCreateRequest,
    TaskStatus,
    VerificationStatus,
)
from models import ActionType, ContractAmbiguity, ProofContract, Requirement, RequirementOperator
from search import SearchProviderError
from task_store import TaskStore


class ResearchExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.store = TaskStore(str(Path(self.tempdir.name) / "execution.db"))

    def tearDown(self):
        self.tempdir.cleanup()

    def test_duplicate_worker_claim_is_prevented(self):
        async def run():
            agent = TaskAgent(task_store=self.store)
            payload = TaskCreateRequest(
                task="Find public evidence for an external SSD",
                client_request_id="duplicate-execution-request",
            )
            task = await agent.create(payload)
            worker_before = agent._worker_ids.get(task.id)
            agent._start_worker(task.id, payload)
            worker_after = agent._worker_ids.get(task.id)
            await asyncio.sleep(0)
            return worker_before, worker_after

        before, after = asyncio.run(run())
        self.assertEqual(before, after)

    def test_cancel_prevents_pipeline_from_continuing(self):
        async def run():
            agent = TaskAgent(task_store=self.store)
            payload = TaskCreateRequest(task="Find public evidence for a laptop")
            task = await agent.create(payload)
            cancelled = await agent.cancel(task.id)
            execution = agent.task_store.get_execution(task.id)
            return cancelled, execution

        cancelled, execution = asyncio.run(run())
        self.assertEqual(cancelled.status, TaskStatus.CANCELLED)
        self.assertEqual(execution["state"], "cancelled")

    def test_retry_starts_one_new_attempt_and_persists_count(self):
        async def run():
            agent = TaskAgent(task_store=self.store)
            payload = TaskCreateRequest(task="Retryable public web task")
            task = await agent.create(payload)
            await agent.cancel(task.id)
            retried = await agent.retry(task.id)
            execution = agent.task_store.get_execution(task.id)
            return retried, execution

        retried, execution = asyncio.run(run())
        self.assertEqual(retried.status, TaskStatus.QUEUED)
        self.assertGreaterEqual(execution["retry_count"], 1)
        self.assertEqual(execution["attempt"], 2)
        self.assertEqual(execution["state"], "running")

    def test_retry_excludes_domains_that_failed_without_a_successful_visit(self):
        async def run():
            agent = TaskAgent(task_store=self.store)
            payload = TaskCreateRequest(task="Retryable public web task")
            with patch.object(agent, "_start_worker"):
                task = await agent.create(payload)
                stored = agent.tasks[task.id]
                stored.status = TaskStatus.PARTIAL
                stored.research_report = ResearchReport(
                    task_id=task.id,
                    contract_version=1,
                    status=ResearchReportStatus.PARTIAL,
                    requirements=[],
                    evaluations=[],
                    evidence=[],
                    completion_criteria=[],
                    execution_status=ResearchExecutionStatus.COMPLETED_WITH_WARNINGS,
                    source_attempts=[
                        SourceAttemptRecord(
                            source_identifier="source_denied",
                            domain="denied.example.org",
                            failure_category=SourceFailureCategory.ACCESS_DENIED,
                        )
                    ],
                )
                agent.task_store.save(stored)
                await agent.retry(task.id)
            return agent, task.id

        agent, task_id = asyncio.run(run())
        self.assertEqual(agent._retry_excluded_domains[task_id], {"denied.example.org"})

    def test_paused_worker_waits_until_resume_and_list_keeps_its_snapshot(self):
        async def run():
            agent = TaskAgent(task_store=self.store)
            generate_contract = AsyncMock(side_effect=asyncio.CancelledError)
            agent.generate_contract = generate_contract
            created = await agent.create(TaskCreateRequest(task="Research laptop evidence"))
            task = agent.tasks[created.id]
            task.progress = "Still in memory"
            active_list = await agent.list()
            self.assertIs(agent.tasks[created.id], task)
            self.assertEqual(active_list[0].progress, "Still in memory")
            await agent.pause(created.id)
            await asyncio.sleep(0)
            generate_contract.assert_not_awaited()
            self.assertEqual((await agent.get(created.id)).status, TaskStatus.PAUSED)
            await agent.resume(created.id)
            await asyncio.gather(agent._worker_tasks[created.id], return_exceptions=True)
            generate_contract.assert_awaited_once_with(created.id)

        asyncio.run(run())

    def test_restart_reclaims_running_and_resumes_paused_without_old_workers(self):
        async def run():
            payload = TaskCreateRequest(task="Research SSD options")
            first = TaskAgent(task_store=self.store)
            running = await first.create(payload)
            paused = await first.create(payload)
            await first.pause(paused.id)
            first_worker = first._worker_ids[running.id]
            await first.shutdown()

            second = TaskAgent(task_store=self.store)
            with patch.object(second, "run_pipeline", new=AsyncMock()):
                await second.resume_pending_pipelines()
                self.assertNotEqual(second._worker_ids[running.id], first_worker)
                self.assertEqual(self.store.get_execution(running.id)["attempt"], 2)
                self.assertNotIn(paused.id, second._worker_ids)
                await second.resume(paused.id)
                self.assertIn(paused.id, second._worker_ids)
                self.assertEqual(self.store.get_execution(paused.id)["attempt"], 2)
                await second.shutdown()

        asyncio.run(run())

    def test_refine_rejects_active_and_does_not_persist_invalid_accumulation(self):
        async def run():
            agent = TaskAgent(task_store=self.store)
            original = TaskCreateRequest(task="Laptop " * 200)
            created = await agent.create(original)
            with self.assertRaises(TaskConflictError):
                await agent.refine(created.id, RefineTaskRequest(instruction="Check RAM"))
            await agent.cancel(created.id)
            with self.assertRaisesRegex(ValueError, "at most 3000"):
                await agent.refine(created.id, RefineTaskRequest(instruction="warranty " * 210))
            self.assertEqual(agent.task_store.get_draft(created.id).task, original.task)
            self.assertEqual((await agent.get(created.id)).status, TaskStatus.CANCELLED)
            await agent.shutdown()

        asyncio.run(run())

    def test_search_failure_is_recorded_as_partial_not_success(self):
        async def run():
            agent = TaskAgent(task_store=self.store)
            payload = TaskCreateRequest(task="Laptop evidence with search outage")
            task = await agent.create(payload)
            contract = ProofContract(
                task_id=task.id,
                goal="Laptop evidence",
                requirements=[Requirement(
                    id="price",
                    label="Public price evidence",
                    field="price",
                    operator=RequirementOperator.EXISTS,
                    expected=None,
                    hard_constraint=False,
                )],
                allowed_actions=[
                    ActionType.SEARCH_PUBLIC_WEB,
                    ActionType.BROWSE_PUBLIC_PAGE,
                    ActionType.EXTRACT_EVIDENCE,
                ],
                prohibited_actions=[
                    ActionType.BYPASS_AUTHENTICATION,
                    ActionType.BYPASS_CAPTCHA,
                    ActionType.BYPASS_ANTI_BOT,
                ],
                completion_criteria=["Collect at least one source-supported finding."],
            )
            agent.generate_contract = AsyncMock(return_value=contract)
            worker = agent._worker_tasks.pop(task.id, None)
            if worker is not None:
                worker.cancel()
            with patch("agent.create_plan", new=AsyncMock(return_value=PlannerOutput(
                objective="Find laptop evidence",
                steps=["Search", "Visit", "Verify"],
                search_queries=[
                    "laptop evidence",
                    "laptop price",
                    "laptop specifications",
                ],
                extract_fields=["price"],
                comparison_criteria=["price"],
            ))), patch(
                "agent.search_public_web",
                new=AsyncMock(side_effect=SearchProviderError("Search outage")),
            ), patch(
                "agent.analyze_findings",
                new=AsyncMock(return_value=AnalyzerOutput(recommendation="No finding yet.")),
            ):
                await agent.run_pipeline(task.id, payload)
            current = await agent.get(task.id)
            return current

        current = asyncio.run(run())
        self.assertIn(current.status, {TaskStatus.PARTIAL, TaskStatus.FAILED, TaskStatus.QUEUED})

    def test_execution_persists_across_agent_instances(self):
        async def run():
            first = TaskAgent(task_store=self.store)
            payload = TaskCreateRequest(task="Persistent execution evidence")
            task = await first.create(payload)
            first_execution = first.task_store.get_execution(task.id)
            second = TaskAgent(task_store=TaskStore(str(Path(self.tempdir.name) / "execution.db")))
            return first_execution, await second.get(task.id)

        execution, reloaded = asyncio.run(run())
        self.assertIsNotNone(execution)
        self.assertIsNotNone(reloaded)
        self.assertIsNotNone(reloaded.execution)


if __name__ == "__main__":
    unittest.main()
