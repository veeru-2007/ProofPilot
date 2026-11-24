import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from fastapi.testclient import TestClient

from main import app, stream_task_events
from models import TaskResponse, TaskStatus, utc_now
from task_store import TaskStore


class ExecutionEventTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.store = TaskStore(str(Path(self.tempdir.name) / "events.db"))

    def tearDown(self):
        self.tempdir.cleanup()

    def test_event_persists_and_filters_by_task(self):
        first = self.store.append_event(
            "task_one",
            "task_created",
            "Task created.",
            {"query": "Laptop research"},
        )
        self.store.append_event(
            "task_two",
            "task_started",
            "Task started.",
        )
        first_task_events = self.store.list_events("task_one")
        all_events = self.store.list_events()

        self.assertEqual([event.event_id for event in first_task_events], [first.event_id])
        self.assertEqual(len(all_events), 2)
        self.assertEqual(first_task_events[0].task_id, "task_one")

    def test_event_api_replays_persisted_history(self):
        task_id = f"task_refresh_{uuid4().hex[:12]}"
        now = utc_now()
        self.store.save(TaskResponse(
            id=task_id,
            task="Refresh test",
            status=TaskStatus.COMPLETED,
            progress="Completed",
            plan=[],
            created_at=now,
            updated_at=now,
        ))
        first = self.store.append_event(task_id, "task_created", "Persisted event.")
        second = self.store.append_event(task_id, "task_started", "Next event.")
        other = self.store.append_event("other_task", "task_created", "Other event.")

        with patch.dict(os.environ, {"PROOFPILOT_DB_PATH": str(self.store.database_path)}), TestClient(app) as client:
            response = client.get(f"/api/events?task_id={task_id}")
            next_page = client.get(
                "/api/events",
                params={"task_id": task_id, "after_event_id": first.event_id, "limit": 1},
            )
            invalid_cursor = client.get(
                "/api/events",
                params={"task_id": task_id, "after_event_id": other.event_id},
            )

        self.assertEqual(response.status_code, 200)
        event_ids = [event["event_id"] for event in response.json()]
        self.assertEqual(event_ids, [first.event_id, second.event_id])
        self.assertTrue(all(event["task_id"] == task_id for event in response.json()))
        self.assertEqual(next_page.status_code, 200)
        self.assertEqual([event["event_id"] for event in next_page.json()], [second.event_id])
        self.assertEqual(invalid_cursor.status_code, 409)

    def test_event_stream_drains_a_full_page_and_resumes_at_header_cursor(self):
        async def run():
            task_id = "task_stream"
            events = [
                self.store.append_event(task_id, "task_started", f"Event {index}")
                for index in range(503)
            ]
            agent = SimpleNamespace(task_store=self.store, get=AsyncMock(return_value=object()))
            app_ = SimpleNamespace(state=SimpleNamespace(task_agent=agent))

            async def collect(count, headers, query=None):
                request = SimpleNamespace(
                    app=app_,
                    headers=headers,
                    is_disconnected=AsyncMock(return_value=False),
                )
                response = await stream_task_events(task_id, request, after_event_id=query)
                stream = response.body_iterator
                try:
                    return [await anext(stream) for _ in range(count)]
                finally:
                    await stream.aclose()

            replay = await collect(len(events), {})
            self.assertEqual(
                [line.splitlines()[0] for line in replay],
                [f"id: {event.event_id}" for event in events],
            )
            resumed = await collect(2, {"last-event-id": events[-3].event_id}, events[0].event_id)
            self.assertEqual(resumed, replay[-2:])
            reset = await collect(1, {"last-event-id": "obsolete-cursor"})
            self.assertEqual(reset, replay[:1])

        asyncio.run(run())

    def test_event_ids_are_unique(self):
        first = self.store.append_event("task_one", "search_started", "Search started.")
        second = self.store.append_event("task_one", "search_started", "Search started.")
        self.assertNotEqual(first.event_id, second.event_id)


if __name__ == "__main__":
    unittest.main()
