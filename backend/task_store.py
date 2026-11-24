import json
import sqlite3
from collections.abc import Callable
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from typing import Optional
from uuid import uuid4

from models import (
    ActionAuditEntry,
    ActionContract,
    ActionContractStatus,
    ExecutionReceipt,
    ProofContract,
    TaskCreateRequest,
    TaskResponse,
    ExecutionEvent,
    utc_now,
)
from policy import PolicyDecision


class TaskStore:
    def __init__(self, database_path: Optional[str] = None) -> None:
        if database_path:
            self.database_path = Path(database_path)
        else:
            self.database_path = Path(__file__).with_name("proofpilot.db")
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.database_path, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    client_request_id TEXT,
                    data TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_events (
                    event_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    message TEXT NOT NULL,
                    metadata TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_execution_events_task_time "
                "ON execution_events(task_id, timestamp)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS policy_decisions (
                    decision_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    data TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_policy_decisions_action_time "
                "ON policy_decisions(action_id, timestamp)"
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_tasks_client_request "
                "ON tasks(client_request_id) WHERE client_request_id IS NOT NULL"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS task_drafts (
                    task_id TEXT PRIMARY KEY,
                    data TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS proof_contracts (
                    task_id TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS action_contracts (
                    action_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    data TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_receipts (
                    action_id TEXT PRIMARY KEY,
                    receipt_id TEXT NOT NULL UNIQUE,
                    data TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS demo_submissions (
                    submission_id TEXT PRIMARY KEY,
                    idempotency_key TEXT UNIQUE,
                    data TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS task_executions (
                    task_id TEXT PRIMARY KEY,
                    attempt INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    worker_id TEXT,
                    started_at TEXT,
                    heartbeat_at TEXT,
                    finished_at TEXT,
                    error TEXT,
                    retry_count INTEGER NOT NULL DEFAULT 0
                )
                """
            )

    def save(self, task: TaskResponse, client_request_id: Optional[str] = None) -> None:
        payload = task.model_dump_json()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO tasks (id, client_request_id, data, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    data = excluded.data,
                    updated_at = excluded.updated_at
                """,
                (
                    task.id,
                    client_request_id,
                    payload,
                    task.created_at.isoformat(),
                    task.updated_at.isoformat(),
                ),
            )

    def save_draft(self, task_id: str, draft: TaskCreateRequest) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO task_drafts (task_id, data)
                VALUES (?, ?)
                ON CONFLICT(task_id) DO UPDATE SET data = excluded.data
                """,
                (task_id, draft.model_dump_json()),
            )

    def get_draft(self, task_id: str) -> Optional[TaskCreateRequest]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT data FROM task_drafts WHERE task_id = ?", (task_id,)
            ).fetchone()
        return TaskCreateRequest.model_validate_json(row["data"]) if row else None

    def get(self, task_id: str) -> Optional[TaskResponse]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT data FROM tasks WHERE id = ?", (task_id,)
            ).fetchone()
        return TaskResponse.model_validate_json(row["data"]) if row else None

    def get_by_request_id(self, client_request_id: str) -> Optional[TaskResponse]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT data FROM tasks WHERE client_request_id = ?",
                (client_request_id,),
            ).fetchone()
        return TaskResponse.model_validate_json(row["data"]) if row else None

    def list(self) -> list[TaskResponse]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT data FROM tasks ORDER BY updated_at DESC"
            ).fetchall()
        return [TaskResponse.model_validate_json(row["data"]) for row in rows]

    def delete(self, task_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
            connection.execute("DELETE FROM task_drafts WHERE task_id = ?", (task_id,))
            connection.execute("DELETE FROM task_executions WHERE task_id = ?", (task_id,))
        return cursor.rowcount > 0

    def save_contract(self, contract: ProofContract) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO proof_contracts (task_id, data, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    data = excluded.data,
                    updated_at = excluded.updated_at
                """,
                (contract.task_id, contract.model_dump_json(), contract.created_at.isoformat()),
            )

    def get_contract(self, task_id: str) -> Optional[ProofContract]:
        with self._connect() as connection:
            return self._read_contract(connection, task_id)

    @staticmethod
    def _read_contract(connection: sqlite3.Connection, task_id: str) -> ProofContract | None:
        row = connection.execute(
            "SELECT data FROM proof_contracts WHERE task_id = ?", (task_id,)
        ).fetchone()
        return ProofContract.model_validate_json(row["data"]) if row else None

    def delete_contract(self, task_id: str) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM proof_contracts WHERE task_id = ?", (task_id,))

    def claim_execution(self, task_id: str, worker_id: str) -> dict | None:
        now = utc_now().isoformat()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT attempt, state, worker_id, retry_count FROM task_executions WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            if row is not None and row["state"] in {"running", "paused"}:
                return dict(row)
            attempt = 1 if row is None else int(row["attempt"]) + 1
            retry_count = 0 if row is None else int(row["retry_count"])
            connection.execute(
                """
                INSERT INTO task_executions
                    (task_id, attempt, state, worker_id, started_at, heartbeat_at, retry_count)
                VALUES (?, ?, 'running', ?, ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    attempt = excluded.attempt,
                    state = 'running',
                    worker_id = excluded.worker_id,
                    started_at = excluded.started_at,
                    heartbeat_at = excluded.heartbeat_at,
                    finished_at = NULL,
                    error = NULL,
                    retry_count = excluded.retry_count
                """,
                (task_id, attempt, worker_id, now, now, retry_count),
            )
            return {
                "attempt": attempt,
                "state": "running",
                "worker_id": worker_id,
                "retry_count": retry_count,
            }

    def interrupt_execution(self, task_id: str) -> None:
        """Release the durable ownership left behind by a prior local server."""
        now = utc_now().isoformat()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE task_executions
                SET state = 'interrupted', finished_at = ?, error = ?
                WHERE task_id = ? AND state IN ('running', 'paused')
                """,
                (now, "Research worker stopped before completion.", task_id),
            )

    def heartbeat_execution(self, task_id: str, worker_id: str) -> bool:
        now = utc_now().isoformat()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE task_executions
                SET heartbeat_at = ?
                WHERE task_id = ? AND worker_id = ? AND state = 'running'
                """,
                (now, task_id, worker_id),
            )
        return cursor.rowcount > 0

    def pause_execution(self, task_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE task_executions SET state = 'paused' WHERE task_id = ?",
                (task_id,),
            )

    def resume_execution(self, task_id: str) -> None:
        now = utc_now().isoformat()
        with self._connect() as connection:
            connection.execute(
                "UPDATE task_executions SET state = 'running', heartbeat_at = ? WHERE task_id = ?",
                (now, task_id),
            )

    def increment_retry(self, task_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE task_executions
                SET retry_count = retry_count + 1
                WHERE task_id = ?
                """,
                (task_id,),
            )

    def cancel_execution(self, task_id: str, error: str | None = None) -> None:
        now = utc_now().isoformat()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE task_executions
                SET state = 'cancelled', finished_at = ?, error = ?
                WHERE task_id = ?
                """,
                (now, error, task_id),
            )

    def finish_execution(self, task_id: str, worker_id: str, state: str, error: str | None = None) -> None:
        now = utc_now().isoformat()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE task_executions
                SET state = ?, finished_at = ?, heartbeat_at = ?, error = ?
                WHERE task_id = ? AND worker_id = ? AND state = 'running'
                """,
                (state, now, now, error, task_id, worker_id),
            )

    def get_execution(self, task_id: str) -> dict | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM task_executions WHERE task_id = ?", (task_id,)
            ).fetchone()
        return dict(row) if row else None

    def append_event(
        self,
        task_id: str,
        event_type: str,
        message: str,
        metadata: dict | None = None,
    ) -> ExecutionEvent:
        event = ExecutionEvent(
            event_id=f"evt_{uuid4().hex}",
            task_id=task_id,
            event_type=event_type,
            timestamp=utc_now(),
            message=message,
            metadata=metadata or {},
        )
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO execution_events
                    (event_id, task_id, event_type, timestamp, message, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.task_id,
                    event.event_type,
                    event.timestamp.isoformat(),
                    event.message,
                    json.dumps(event.metadata, ensure_ascii=True),
                ),
            )
        return event

    def list_events(
        self,
        task_id: str | None = None,
        limit: int = 500,
        *,
        after_event_id: str | None = None,
    ) -> list[ExecutionEvent]:
        limit = max(1, min(limit, 500))
        with self._connect() as connection:
            after_rowid = 0
            if after_event_id is not None:
                cursor = connection.execute(
                    "SELECT rowid, task_id FROM execution_events WHERE event_id = ?",
                    (after_event_id,),
                ).fetchone()
                if cursor is None or (task_id is not None and cursor["task_id"] != task_id):
                    raise ValueError("The event cursor was not found in this stream.")
                after_rowid = cursor["rowid"]
            if task_id:
                rows = connection.execute(
                    """
                    SELECT event_id, task_id, event_type, timestamp, message, metadata
                    FROM execution_events
                    WHERE task_id = ? AND rowid > ?
                    ORDER BY rowid ASC
                    LIMIT ?
                    """,
                    (task_id, after_rowid, limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT event_id, task_id, event_type, timestamp, message, metadata
                    FROM execution_events
                    WHERE rowid > ?
                    ORDER BY rowid ASC
                    LIMIT ?
                    """,
                    (after_rowid, limit),
                ).fetchall()
        return [
            ExecutionEvent(
                event_id=row["event_id"],
                task_id=row["task_id"],
                event_type=row["event_type"],
                timestamp=row["timestamp"],
                message=row["message"],
                metadata=json.loads(row["metadata"]),
            )
            for row in rows
        ]

    def save_action(self, action: ActionContract, *, receipt: ExecutionReceipt | None = None) -> None:
        if receipt is not None and (
            receipt.action_id != action.action_id or receipt.receipt_id != action.execution_receipt_id
        ):
            raise ValueError("The receipt must match the persisted action.")
        with self._connect() as connection:
            self._write_action(connection, action)
            if receipt is not None:
                self._write_receipt(connection, receipt)

    @staticmethod
    def _write_action(connection: sqlite3.Connection, action: ActionContract) -> None:
        connection.execute(
            """
            INSERT INTO action_contracts (action_id, task_id, status, data, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(action_id) DO UPDATE SET
                task_id = excluded.task_id,
                status = excluded.status,
                data = excluded.data,
                updated_at = excluded.updated_at
            """,
            (
                action.action_id,
                action.task_id,
                action.status.value,
                action.model_dump_json(),
                action.updated_at.isoformat() if action.updated_at else action.created_at.isoformat(),
            ),
        )

    def create_prepared_action(
        self, action: ActionContract, issue_warrant: Callable[[list[ActionContract]], None]
    ) -> None:
        """Assign the next Warrant plan version and persist preparation in one transaction."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT data FROM action_contracts WHERE task_id = ?", (action.task_id,)
            ).fetchall()
            issue_warrant([ActionContract.model_validate_json(row["data"]) for row in rows])
            self._write_action(connection, action)

    def get_action(self, action_id: str) -> Optional[ActionContract]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT data FROM action_contracts WHERE action_id = ?", (action_id,)
            ).fetchone()
        return ActionContract.model_validate_json(row["data"]) if row else None

    def claim_action_execution(
        self,
        action_id: str,
        expected_digest: str,
        *,
        expected_warrant_hash: str,
        validate: Callable[[ActionContract, TaskResponse | None, ProofContract | None], list[PolicyDecision] | None],
    ) -> Optional[ActionContract]:
        """Atomically claim an approved action so only one worker can execute it."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT data FROM action_contracts WHERE action_id = ?",
                (action_id,),
            ).fetchone()
            if row is None:
                return None

            action = ActionContract.model_validate_json(row["data"])
            if (
                action.status != ActionContractStatus.APPROVED
                or action.approval_digest != expected_digest
                or action.approved_digest != expected_digest
                or action.warrant is None
                or action.warrant.contract_hash != expected_warrant_hash
                or action.approved_warrant_hash != expected_warrant_hash
            ):
                return None

            now = utc_now()
            expired = now >= action.expires_at
            if not expired:
                task_row = connection.execute(
                    "SELECT data FROM tasks WHERE id = ?", (action.task_id,)
                ).fetchone()
                task = TaskResponse.model_validate_json(task_row["data"]) if task_row else None
                decisions = validate(action, task, self._read_contract(connection, action.task_id))
                for decision in decisions or []:
                    self._write_policy_decision(connection, decision)
            claimed_status = (
                ActionContractStatus.EXPIRED
                if expired
                else ActionContractStatus.EXECUTING
            )
            action.status = claimed_status
            action.updated_at = now
            action.audit.append(
                ActionAuditEntry(
                    event=claimed_status.value,
                    detail=(
                        "The approval expired before its atomic execution claim."
                        if expired
                        else "Execution was atomically claimed by one backend worker."
                    ),
                    actor="system" if expired else "agent",
                    timestamp=now,
                )
            )
            cursor = connection.execute(
                """
                UPDATE action_contracts
                SET status = ?, data = ?, updated_at = ?
                WHERE action_id = ? AND status = ?
                """,
                (
                    claimed_status.value,
                    action.model_dump_json(),
                    now.isoformat(),
                    action_id,
                    ActionContractStatus.APPROVED.value,
                ),
            )
            if cursor.rowcount != 1:
                return None
            return None if expired else action

    @staticmethod
    def _write_policy_decision(connection: sqlite3.Connection, decision: PolicyDecision) -> None:
        connection.execute(
            """
            INSERT INTO policy_decisions (decision_id, task_id, action_id, timestamp, decision, data)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                decision.decision_id,
                decision.task_id,
                decision.action_id,
                decision.timestamp.isoformat(),
                decision.decision,
                decision.model_dump_json(),
            ),
        )

    def save_policy_decision(self, decision: PolicyDecision) -> None:
        with self._connect() as connection:
            self._write_policy_decision(connection, decision)

    def list_policy_decisions(self, action_id: str) -> list[PolicyDecision]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT data FROM policy_decisions WHERE action_id = ? ORDER BY timestamp, rowid",
                (action_id,),
            ).fetchall()
        return [PolicyDecision.model_validate_json(row["data"]) for row in rows]

    def list_actions(self, task_id: Optional[str] = None) -> list[ActionContract]:
        with self._connect() as connection:
            if task_id is None:
                rows = connection.execute(
                    "SELECT data FROM action_contracts ORDER BY updated_at DESC"
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT data FROM action_contracts WHERE task_id = ? ORDER BY updated_at DESC",
                    (task_id,),
                ).fetchall()
        return [ActionContract.model_validate_json(row["data"]) for row in rows]

    def save_receipt(self, receipt: ExecutionReceipt) -> None:
        with self._connect() as connection:
            self._write_receipt(connection, receipt)

    @staticmethod
    def _write_receipt(connection: sqlite3.Connection, receipt: ExecutionReceipt) -> None:
        connection.execute(
            """
            INSERT INTO execution_receipts (action_id, receipt_id, data, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(action_id) DO UPDATE SET
                receipt_id = excluded.receipt_id,
                data = excluded.data,
                updated_at = excluded.updated_at
            """,
            (
                receipt.action_id,
                receipt.receipt_id,
                receipt.model_dump_json(),
                (receipt.verification_timestamp or receipt.execution_timestamp or receipt.approval_timestamp).isoformat(),
            ),
        )

    def get_receipt(self, action_id: str) -> Optional[ExecutionReceipt]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT data FROM execution_receipts WHERE action_id = ?", (action_id,)
            ).fetchone()
        return ExecutionReceipt.model_validate_json(row["data"]) if row else None

    def create_demo_submission(
        self,
        idempotency_key: str,
        payload: dict,
        *,
        authorize: Callable[[ActionContract | None, ProofContract | None], None] | None = None,
    ) -> dict:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if authorize is not None:
                action_row = connection.execute(
                    "SELECT data FROM action_contracts WHERE json_extract(data, '$.idempotency_key') = ?",
                    (idempotency_key,),
                ).fetchone()
                action = ActionContract.model_validate_json(action_row["data"]) if action_row else None
                contract = self._read_contract(connection, action.task_id) if action else None
                authorize(action, contract)
            row = connection.execute(
                "SELECT data FROM demo_submissions WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if row:
                record = json.loads(row["data"])
                if any(str(record.get(key, "")) != str(value) for key, value in payload.items()):
                    raise ValueError("This idempotency key was already used with a different payload.")
                return record

            record = dict(payload)
            record["submission_id"] = f"demo_{uuid4().hex[:12]}"
            connection.execute(
                "INSERT INTO demo_submissions (submission_id, idempotency_key, data, created_at) VALUES (?, ?, ?, datetime('now'))",
                (record["submission_id"], idempotency_key, json.dumps(record, sort_keys=True)),
            )
            return record

    def get_demo_submission(self, submission_id: str) -> Optional[dict]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT data FROM demo_submissions WHERE submission_id = ?", (submission_id,)
            ).fetchone()
        return json.loads(row["data"]) if row else None

    def get_demo_submission_by_idempotency(self, idempotency_key: str) -> Optional[dict]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT data FROM demo_submissions WHERE idempotency_key = ?", (idempotency_key,)
            ).fetchone()
        return json.loads(row["data"]) if row else None

    def list_demo_submissions(self) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT data FROM demo_submissions ORDER BY created_at"
            ).fetchall()
        return [json.loads(row["data"]) for row in rows]

    def list_demo_submission_index(self) -> dict[str, str]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT idempotency_key, submission_id FROM demo_submissions WHERE idempotency_key IS NOT NULL"
            ).fetchall()
        return {row["idempotency_key"]: row["submission_id"] for row in rows}

