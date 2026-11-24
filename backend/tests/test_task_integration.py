import asyncio
import os
import unittest

from agent import TaskAgent
from models import TaskCreateRequest


class TaskIntegrationTests(unittest.TestCase):
    def test_task_pipeline_handles_missing_search_credentials_partially(self):
        old_tavily = os.environ.pop("TAVILY_API_KEY", None)
        old_llm = os.environ.pop("LLM_API_KEY", None)
        old_openai = os.environ.pop("OPENAI_API_KEY", None)
        try:
            async def run():
                agent = TaskAgent()
                task = await agent.create(
                    TaskCreateRequest(
                        task="Research machine learning laptops under £1500",
                        budget="£1500",
                    )
                )
                for _ in range(30):
                    current = await agent.get(task.id)
                    if current.status.value in {"completed", "partial", "failed", "blocked"}:
                        return current
                    await asyncio.sleep(0.02)
                return await agent.get(task.id)

            task = asyncio.run(run())
        finally:
            if old_tavily is not None:
                os.environ["TAVILY_API_KEY"] = old_tavily
            if old_llm is not None:
                os.environ["LLM_API_KEY"] = old_llm
            if old_openai is not None:
                os.environ["OPENAI_API_KEY"] = old_openai

        self.assertIn(task.status.value, {"partial", "failed"})
        self.assertEqual(task.claims, [])
        self.assertGreater(len(task.plan), 0)
        self.assertGreater(len(task.partial_failures), 0)
        self.assertGreater(task.progress_percent, 0)
        self.assertEqual(task.contract_version, 1)
        self.assertIsNotNone(task.research_report)
        self.assertEqual(task.research_report.task_id, task.id)
        self.assertEqual(task.research_report.status.value, "PARTIAL")


if __name__ == "__main__":
    unittest.main()
