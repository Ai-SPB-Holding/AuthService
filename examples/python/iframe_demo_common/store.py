from __future__ import annotations

import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class TokenRecord:
    session_id: str
    email: str | None
    sub: str | None
    access_token: str
    refresh_token: str
    updated_at: float


class SqliteTokenStore:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path)
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init(self) -> None:
        with self._connect() as c:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS demo_sessions (
                    client_label TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (client_label, session_id)
                )
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS demo_tokens (
                    client_label TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    email TEXT,
                    sub TEXT,
                    access_token TEXT NOT NULL,
                    refresh_token TEXT NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (client_label, session_id),
                    FOREIGN KEY(client_label, session_id) REFERENCES demo_sessions(client_label, session_id)
                )
                """
            )

    def ensure_session(self, session_id: str | None, client_label: str) -> str:
        sid = session_id or uuid.uuid4().hex
        now = time.time()
        with self._connect() as c:
            row = c.execute(
                "SELECT session_id FROM demo_sessions WHERE client_label = ? AND session_id = ?",
                (client_label, sid),
            ).fetchone()
            if row is None:
                c.execute(
                    "INSERT INTO demo_sessions (client_label, session_id, created_at) VALUES (?,?,?)",
                    (client_label, sid, now),
                )
        return sid

    def save_tokens(
        self,
        session_id: str,
        client_label: str,
        email: str | None,
        sub: str | None,
        access_token: str,
        refresh_token: str,
    ) -> None:
        now = time.time()
        with self._connect() as c:
            c.execute(
                """
                INSERT INTO demo_tokens (client_label, session_id, email, sub, access_token, refresh_token, updated_at)
                VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(client_label, session_id) DO UPDATE SET
                    email = excluded.email,
                    sub = excluded.sub,
                    access_token = excluded.access_token,
                    refresh_token = excluded.refresh_token,
                    updated_at = excluded.updated_at
                """,
                (client_label, session_id, email, sub, access_token, refresh_token, now),
            )

    def get_tokens(self, session_id: str, client_label: str) -> TokenRecord | None:
        with self._connect() as c:
            row = c.execute(
                """
                SELECT session_id, email, sub, access_token, refresh_token, updated_at
                FROM demo_tokens
                WHERE client_label = ? AND session_id = ?
                """,
                (client_label, session_id),
            ).fetchone()
        if row is None:
            return None
        return TokenRecord(
            session_id=row[0],
            email=row[1],
            sub=row[2],
            access_token=row[3],
            refresh_token=row[4],
            updated_at=row[5],
        )

    def clear_tokens(self, session_id: str, client_label: str) -> None:
        with self._connect() as c:
            c.execute(
                "DELETE FROM demo_tokens WHERE client_label = ? AND session_id = ?",
                (client_label, session_id),
            )

    def list_for_client(self, client_label: str, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as c:
            rows = c.execute(
                """
                SELECT t.session_id, t.email, t.sub, t.updated_at
                FROM demo_tokens t
                WHERE t.client_label = ?
                ORDER BY t.updated_at DESC
                LIMIT ?
                """,
                (client_label, limit),
            ).fetchall()
        return [
            {"session_id": r[0], "email": r[1], "sub": r[2], "updated_at": r[3]} for r in rows
        ]
