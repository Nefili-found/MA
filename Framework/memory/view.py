"""view 表读写：记录工具调用与 D 的假设验证推断。"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dumps(obj: Any) -> str:
    try:
        return json.dumps(obj if obj is not None else {}, ensure_ascii=False)
    except (TypeError, ValueError):
        # 非可序列化 / 循环引用时兜底，避免拖垮主流程
        try:
            return json.dumps({"error": "unserializable", "repr": repr(obj)[:2000]}, ensure_ascii=False)
        except Exception:
            return "{}"


def write_verification(
    conn: sqlite3.Connection,
    session_id: str,
    hypothesis: Dict[str, Any],
    tool_call: Dict[str, Any],
    tool_result: Dict[str, Any],
    inference: Dict[str, Any],
    status: str,
    confidence: float,
    reason: str,
) -> str:
    """写入一条验证记录（工具调用 + D 的推断），返回记录 id。"""
    row_id = uuid.uuid4().hex
    conn.execute(
        'INSERT INTO "view"'
        " (id, session_id, hypothesis_json, tool_call_json, tool_result_json,"
        "  inference_json, status, confidence, reason, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            row_id,
            session_id,
            _dumps(hypothesis),
            _dumps(tool_call),
            _dumps(tool_result),
            _dumps(inference),
            status,
            float(confidence or 0.0),
            reason or "",
            _now(),
        ),
    )
    conn.commit()
    return row_id


def read_views(conn: sqlite3.Connection, session_id: str) -> List[Dict[str, Any]]:
    """读取指定会话内的所有验证记录。"""
    rows = conn.execute(
        'SELECT * FROM "view" WHERE session_id = ? ORDER BY created_at ASC',
        (session_id,),
    ).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "id": r["id"],
                "session_id": r["session_id"],
                "hypothesis": _loads(r["hypothesis_json"]),
                "tool_call": _loads(r["tool_call_json"]),
                "tool_result": _loads(r["tool_result_json"]),
                "inference": _loads(r["inference_json"]),
                "status": r["status"],
                "confidence": r["confidence"],
                "reason": r["reason"],
                "created_at": r["created_at"],
            }
        )
    return out


def _loads(text: Optional[str]) -> Dict[str, Any]:
    try:
        data = json.loads(text or "{}")
        return data if isinstance(data, dict) else {"value": data}
    except json.JSONDecodeError:
        return {}
