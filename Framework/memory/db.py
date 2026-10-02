"""SQLite 连接与建表。

数据库默认文件为 ``memory.db``（路径来自配置）。
注意：SQLite 中 ``VIEW`` 是关键字，因此表名使用带引号的 ``"view"``。
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Union

SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    agent       TEXT NOT NULL,
    report_json TEXT NOT NULL,
    code_hash   TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS "view" (
    id                TEXT PRIMARY KEY,
    session_id        TEXT NOT NULL,
    hypothesis_json   TEXT,
    tool_call_json    TEXT,
    tool_result_json  TEXT,
    inference_json    TEXT,
    status            TEXT,
    confidence        REAL,
    reason            TEXT,
    created_at        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ledger_session ON ledger(session_id);
CREATE INDEX IF NOT EXISTS idx_view_session   ON "view"(session_id);
"""


def get_connection(db_path: Union[str, Path]) -> sqlite3.Connection:
    """打开（必要时创建）SQLite 连接并确保表结构存在。"""
    path = Path(db_path)
    parent = path.parent
    if str(parent) not in ("", "."):
        parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()
