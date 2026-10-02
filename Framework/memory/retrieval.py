"""会话内历史相似漏洞检索。

约束：
* 仅在同一会话内检索；
* 使用 LLM 语义相似度（无向量数据库）；
* 不保留跨会话长期记忆。

未配置 LLM 时退化为基于文本相似度（difflib）的近似匹配。
"""
from __future__ import annotations

import difflib
import json
import sqlite3
from typing import Any, Dict, List, Optional

from memory.ledger import read_reports

_KEYS = ("title", "cwe", "taint_source", "taint_sink", "evidence")


def _finding_text(finding: Dict[str, Any]) -> str:
    loc = finding.get("location") or {}
    parts = [str(finding.get(k, "")) for k in _KEYS]
    parts.append(str(loc.get("function", "")))
    return " | ".join(p for p in parts if p)


def find_similar_findings(
    conn: sqlite3.Connection,
    session_id: str,
    finding: Dict[str, Any],
    llm: Optional[Any] = None,
    top_k: int = 3,
) -> List[Dict[str, Any]]:
    """在当前会话的历史报告中，查找与 ``finding`` 语义相似的漏洞。"""
    candidates: List[Dict[str, Any]] = []
    for row in read_reports(conn, session_id):
        for f in (row.get("report") or {}).get("findings", []) or []:
            candidates.append(
                {"agent": row.get("agent"), "finding": f, "text": _finding_text(f)}
            )
    if not candidates:
        return []

    if llm is not None:
        try:
            return _llm_similar(llm, finding, candidates, top_k)
        except Exception:
            # 静默降级到启发式方法
            pass
    return _heuristic_similar(finding, candidates, top_k)


def _heuristic_similar(
    finding: Dict[str, Any], candidates: List[Dict[str, Any]], top_k: int
) -> List[Dict[str, Any]]:
    base = _finding_text(finding)
    scored = []
    for c in candidates:
        ratio = difflib.SequenceMatcher(None, base, c["text"]).ratio()
        scored.append((ratio, c))
    scored.sort(key=lambda x: x[0], reverse=True)
    out = []
    for score, c in scored[:top_k]:
        if score <= 0.0:
            continue
        out.append({"score": round(score, 4), "agent": c["agent"], "finding": c["finding"]})
    return out


def _llm_similar(
    llm: Any,
    finding: Dict[str, Any],
    candidates: List[Dict[str, Any]],
    top_k: int,
) -> List[Dict[str, Any]]:
    from langchain_core.messages import HumanMessage, SystemMessage

    compact = [
        {"index": i, "text": c["text"]} for i, c in enumerate(candidates)
    ]
    system = (
        "你是漏洞检索助手。给定一个查询漏洞和一组候选漏洞的精简文本，"
        "请按语义相似度排序，输出最相似的前若干个。"
        '只输出 JSON：{"matches": [{"index": 0, "score": 0.0}, ...]}，不要输出其他内容。'
    )
    human = json.dumps(
        {"query": _finding_text(finding), "candidates": compact, "top_k": top_k},
        ensure_ascii=False,
    )
    resp = llm.invoke([SystemMessage(content=system), HumanMessage(content=human)])
    text = getattr(resp, "content", str(resp))

    from agents import parse_json_object  # 延迟导入，避免循环

    data = parse_json_object(text)
    matches = data.get("matches")
    if not isinstance(matches, list):
        raise ValueError("LLM 检索返回结构非法")
    out = []
    for m in matches:
        if not isinstance(m, dict):
            continue
        idx = m.get("index")
        if isinstance(idx, int) and 0 <= idx < len(candidates):
            out.append(
                {
                    "score": float(m.get("score", 0.0) or 0.0),
                    "agent": candidates[idx]["agent"],
                    "finding": candidates[idx]["finding"],
                }
            )
    out.sort(key=lambda x: x["score"], reverse=True)
    return out[:top_k]
