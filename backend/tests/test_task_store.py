import asyncio
import tempfile
import unittest
from pathlib import Path

from agent import TaskAgent
from demo_scenario import create_simulated_demo
from models import (
    ResearchExecutionStatus,
    ResearchSourceSummary,
    SourceAttemptRecord,
    SourceFailureCategory,
    SourceRecord,
    TaskCreateRequest,
    TaskResponse,
    TaskStatus,
)
from task_store import TaskStore


class TaskStoreTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.database_path = str(Path(self.tempdir.name) / "tasks.db")

    def tearDown(self):
        self.tempdir.cleanup()

    def test_create_is_persisted_and_duplicate_request_is_idempotent(self):
        async def run():
            store = TaskStore(self.database_path)
            agent = TaskAgent(task_store=store)
            payload = TaskCreateRequest(
                task="Compare research notebooks",
                client_request_id="stable-request-id",
            )
            first = await agent.create(payload)
            second = await agent.create(payload)
            reloaded = await agent.get(first.id)
            return first, second, reloaded

        first, second, reloaded = asyncio.run(run())
        self.assertEqual(first.id, second.id)
        self.assertEqual(reloaded.id, first.id)

    def test_store_survives_new_agent_instance(self):
        async def run():
            store = TaskStore(self.database_path)
            first_agent = TaskAgent(task_store=store)
            task = await first_agent.create(
                TaskCreateRequest(task="Find reliable public evidence")
            )
            second_agent = TaskAgent(task_store=TaskStore(self.database_path))
            return await second_agent.get(task.id)

        task = asyncio.run(run())
        self.assertIsNotNone(task)
        self.assertIn(task.status, set(TaskStatus))

    def test_structured_source_failure_and_coverage_survive_sqlite_restart(self):
        task, _ = create_simulated_demo("task_source_coverage_restore")
        failed_source = SourceRecord(
            url="https://blocked.example.test/product",
            title="Blocked product source",
            status_code=403,
            failure_type="blocked",
            failure_reason="Access denied",
            blocked_reason="Access denied",
            coverage_impact="unresolved",
            affected_requirement_ids=["price_limit"],
        )
        task.sources.append(failed_source)
        task.research_report.sources_visited.append(failed_source.model_copy(deep=True))
        first_store = TaskStore(self.database_path)
        first_store.save(task)

        restored = TaskStore(self.database_path).get(task.id)
        self.assertIsNotNone(restored)
        self.assertEqual(restored.sources[-1].failure_type, "blocked")
        self.assertEqual(restored.sources[-1].coverage_impact, "unresolved")
        self.assertEqual(restored.sources[-1].affected_requirement_ids, ["price_limit"])
        self.assertEqual(restored.research_report.sources_visited[-1].status_code, 403)

    def test_recovery_attempts_and_execution_status_survive_sqlite_restart(self):
        task, _ = create_simulated_demo("task_recovery_restore")
        task.research_report.execution_status = ResearchExecutionStatus.COMPLETED_WITH_WARNINGS
        task.research_report.source_attempts = [
            SourceAttemptRecord(
                source_identifier="source_denied_public_page",
                source_url="https://blocked.example.test/product",
                domain="blocked.example.test",
                failure_category=SourceFailureCategory.ACCESS_DENIED,
                http_status=403,
                error_description="The source denied access.",
                recovery_attempt_status="RECOVERED",
                recovery_operation_id="recovery_test_1",
                alternative_sources_found=True,
                affected_requirement_ids=["price_limit"],
            )
        ]
        task.research_report.source_summary = ResearchSourceSummary(
            sources_discovered=2,
            source_attempts=2,
            sources_attempted=2,
            sources_accessed=1,
            sources_failed=1,
            recovery_attempts=1,
            requirements_supported=1,
            requirements_unresolved=1,
        )
        TaskStore(self.database_path).save(task)

        restored = TaskStore(self.database_path).get(task.id)
        self.assertEqual(restored.research_report.execution_status, ResearchExecutionStatus.COMPLETED_WITH_WARNINGS)
        self.assertEqual(restored.research_report.source_attempts[0].failure_category, SourceFailureCategory.ACCESS_DENIED)
        self.assertEqual(restored.research_report.source_attempts[0].recovery_attempt_status, "RECOVERED")
        self.assertEqual(restored.research_report.source_summary.recovery_attempts, 1)

    def test_legacy_report_without_resilience_fields_loads_with_inferred_execution_status(self):
        task, _ = create_simulated_demo("task_legacy_report_restore")
        payload = task.model_dump(mode="json")
        report = payload["research_report"]
        report["status"] = "PARTIAL"
        report["research_failures"] = ["A public source denied access."]
        report.pop("execution_status")
        report.pop("source_attempts")
        report.pop("source_summary")

        restored = TaskResponse.model_validate(payload)
        self.assertEqual(restored.research_report.execution_status, ResearchExecutionStatus.COMPLETED_WITH_WARNINGS)
        self.assertEqual(restored.research_report.source_attempts, [])

    def test_cancel_and_delete_lifecycle(self):
        async def run():
            agent = TaskAgent(task_store=TaskStore(self.database_path))
            task = await agent.create(TaskCreateRequest(task="A cancellable research task"))
            cancelled = await agent.cancel(task.id)
            deleted = await agent.delete(task.id)
            missing = await agent.get(task.id)
            return cancelled, deleted, missing

        cancelled, deleted, missing = asyncio.run(run())
        self.assertEqual(cancelled.status, TaskStatus.CANCELLED)
        self.assertTrue(deleted)
        self.assertIsNone(missing)

    def test_pause_and_resume_lifecycle(self):
        async def run():
            agent = TaskAgent(task_store=TaskStore(self.database_path))
            task = await agent.create(TaskCreateRequest(task="A resumable research task"))
            paused = await agent.pause(task.id)
            resumed = await agent.resume(task.id)
            return paused, resumed

        paused, resumed = asyncio.run(run())
        self.assertEqual(paused.status, TaskStatus.PAUSED)
        self.assertEqual(resumed.status, TaskStatus.QUEUED)


if __name__ == "__main__":
    unittest.main()
