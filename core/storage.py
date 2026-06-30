from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path

from core.models import AnalysisResult
from core.utils import json_dumps


class SQLiteStorage:
    def __init__(self, path: str | Path = "hostloginsight.db") -> None:
        self.path = Path(path)
        self._init()

    def _connect(self):
        return sqlite3.connect(self.path)

    def _init(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    sources TEXT NOT NULL,
                    events TEXT NOT NULL,
                    findings TEXT NOT NULL,
                    timeline TEXT NOT NULL
                )
                """
            )

    def save_session(self, result: AnalysisResult) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO sessions(created_at, risk_score, sources, events, findings, timeline) VALUES(?,?,?,?,?,?)",
                (
                    datetime.now().isoformat(),
                    result.risk_score,
                    json_dumps([s.to_dict() for s in result.sources]),
                    json_dumps([e.to_dict() for e in result.events]),
                    json_dumps([f.to_dict() for f in result.findings]),
                    json_dumps(result.timeline),
                ),
            )
            return int(cur.lastrowid)

    def list_sessions(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute("SELECT id, created_at, risk_score FROM sessions ORDER BY id DESC LIMIT 50").fetchall()
        return [{"id": row[0], "created_at": row[1], "risk_score": row[2]} for row in rows]
