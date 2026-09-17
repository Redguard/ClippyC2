import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone


class AmbiguousCommandId(Exception):
    def __init__(self, command_id: str, matches: list[str]) -> None:
        self.command_id = command_id
        self.matches = matches
        super().__init__(f"ambiguous command id prefix: {command_id}")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


class CommandStore:
    def __init__(self, path: str) -> None:
        self.path = path
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS commands (
                    id TEXT PRIMARY KEY,
                    command TEXT NOT NULL,
                    type TEXT NOT NULL DEFAULT 'shell',
                    queued_at TEXT NOT NULL,
                    result TEXT,
                    completed_at TEXT,
                    bof_blob BLOB,
                    bof_args BLOB
                )
                """
            )
            self._migrate(conn)
            conn.commit()

    def _migrate(self, conn: sqlite3.Connection) -> None:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(commands)").fetchall()}
        if "type" not in columns:
            conn.execute("ALTER TABLE commands ADD COLUMN type TEXT NOT NULL DEFAULT 'shell'")
        if "bof_blob" not in columns:
            conn.execute("ALTER TABLE commands ADD COLUMN bof_blob BLOB")
        if "bof_args" not in columns:
            conn.execute("ALTER TABLE commands ADD COLUMN bof_args BLOB")

    def record_command(
        self,
        command_id: str,
        command: str,
        command_type: str = "shell",
        bof_blob: bytes | None = None,
        bof_args: bytes | None = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO commands (id, command, type, queued_at, bof_blob, bof_args)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (command_id, command, command_type, utc_now(), bof_blob, bof_args),
            )
            conn.commit()

    def has_result(self, command_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT result FROM commands WHERE id = ?",
                (command_id,),
            ).fetchone()
            return bool(row and row["result"] is not None)

    def record_result(self, command_id: str, command: str, result: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT command, result FROM commands WHERE id = ?",
                (command_id,),
            ).fetchone()
            if row and row["result"] is not None:
                return False
            completed_at = utc_now()
            if row:
                conn.execute(
                    """
                    UPDATE commands
                    SET result = ?, completed_at = ?
                    WHERE id = ?
                    """,
                    (result, completed_at, command_id),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO commands (id, command, type, queued_at, result, completed_at)
                    VALUES (?, ?, 'shell', ?, ?, ?)
                    """,
                    (command_id, command, utc_now(), result, completed_at),
                )
            conn.commit()
            return True

    def get_command_text(self, command_id: str) -> str:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT command FROM commands WHERE id = ?",
                (command_id,),
            ).fetchone()
            return row["command"] if row else ""

    def list_commands(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, command, type, queued_at, completed_at, result
                FROM commands
                ORDER BY queued_at DESC
                """
            ).fetchall()
        return [self._row_summary(row) for row in rows]

    def get_command(self, command_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM commands WHERE id = ?",
                (command_id,),
            ).fetchone()
            if row:
                return self._row_detail(row)

            rows = conn.execute(
                """
                SELECT * FROM commands
                WHERE id LIKE ?
                ORDER BY queued_at DESC
                """,
                (f"{command_id}%",),
            ).fetchall()
            if not rows:
                return None
            if len(rows) > 1:
                raise AmbiguousCommandId(command_id, [row["id"] for row in rows])
            return self._row_detail(rows[0])

    @staticmethod
    def _row_summary(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "command": row["command"],
            "type": row["type"] if "type" in row.keys() else "shell",
            "queued_at": row["queued_at"],
            "completed_at": row["completed_at"],
            "has_result": row["result"] is not None,
        }

    @staticmethod
    def _row_detail(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "command": row["command"],
            "type": row["type"] if "type" in row.keys() else "shell",
            "queued_at": row["queued_at"],
            "completed_at": row["completed_at"],
            "result": row["result"] or "",
            "has_result": row["result"] is not None,
        }
