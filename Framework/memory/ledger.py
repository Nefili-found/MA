"""ledger 表读写：记录原始报告与对应生成 Agent。"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_code(code: str) -> str:
    """计算源码哈希，便于标识同一份输入。"""
    return hashlib.sha256((code or "").encode("utf-8")).hexdigest()


def write_report(
    conn: sqlite3.Connection,
    session_id: str,
    agent: str,
    report: Dict[str, Any],
    code: str,
) -> str:
    """写入一条原始报告，返回记录 id。"""
    row_id = uuid.uuid4().hex
    conn.execute(
        "INSERT INTO ledger (id, session_id, agent, report_json, code_hash, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (
            row_id,
            session_id,
            agent,
            json.dumps(report or {}, ensure_ascii=False),
            hash_code(code),
            _now(),
        ),
    )
    conn.commit()
    return row_id


def read_reports(conn: sqlite3.Connection, session_id: str) -> List[Dict[str, Any]]:
    """读取指定会话内的所有原始报告。"""
    rows = conn.execute(
        "SELECT id, agent, report_json, code_hash, created_at"
        " FROM ledger WHERE session_id = ? ORDER BY created_at ASC",
        (session_id,),
    ).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        try:
            report = json.loads(r["report_json"] or "{}")
        except json.JSONDecodeError:
            report = {}
        out.append(
            {
                "id": r["id"],
                "agent": r["agent"],
                "report": report,
                "code_hash": r["code_hash"],
                "created_at": r["created_at"],
            }
        )
    return out
