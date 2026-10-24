"""D 的去重：把 A/B/C 的 findings 按语义合并成同一漏洞的多条贡献。

从 ``verify_agent/d.py`` 拆出（20 文档 §5.1-2）：原 d.py 一个文件同时承载
校验 / 落库 / 去重 / 裁决 / 工具循环 / 报告组装，可读性与可测性都受影响。

策略保持原样，两级：
1. 有 LLM → 让模型分组（失败则回落启发式，不中断）；
2. 无 LLM → 启发式分组：CWE + 函数名 + 行号块（//5）+ 归一标题。

合并时把 ``assumptions`` 按视角**并集**并重新编号——同一漏洞可能被 A/C 从
不同角度提出不同前置条件，只取 group[0] 会丢掉其余视角的 conditions，
核验覆盖率直接受损。
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from agents import parse_json_object, response_text
from memory.retrieval import find_similar_findings
from observability import log_event
from verify_agent.prompts import load_verify_prompts
from verify_agent.schema import REQUIRED_AGENTS


def collect_findings(reports: Dict[str, Any]) -> List[Dict[str, Any]]:
    """把三份报告摊平成 findings 列表，并带上 ``_agent`` / ``_contributions``。"""
    out: List[Dict[str, Any]] = []
    for agent in REQUIRED_AGENTS:
        report = reports.get(agent) or {}
        for f in report.get("findings", []) or []:
            item = dict(f)
            item["_agent"] = agent
            item["_contributions"] = [
                {
                    "agent": agent,
                    "confidence": float(f.get("confidence", 0.0) or 0.0),
                    "severity": f.get("severity", ""),
                    "evidence": f.get("evidence", ""),
                    "suggestion": f.get("suggestion", ""),
                }
            ]
            out.append(item)
    return out


def deduplicate(
    findings: List[Dict[str, Any]],
    session_id: str,
    conn: Any,
    llm: Optional[Any],
) -> List[Dict[str, Any]]:
    """语义去重 + 合并贡献 + 会话内相似历史检索。"""
    if not findings:
        return []

    groups = group_indices(findings, llm)
    merged: List[Dict[str, Any]] = []
    for group in groups:
        base = dict(findings[group[0]])
        contributions: List[Dict[str, Any]] = []
        chain: Optional[List[Any]] = None
        # 触发前提按视角并集：同一漏洞可能被 A/C 从不同角度提出不同前置条件，
        # 只取 group[0] 会丢掉其余视角的 conditions（核验覆盖率直接受损）。
        assumptions: List[Any] = []
        seen_cond: set = set()
        for idx in group:
            contributions.extend(findings[idx].get("_contributions", []))
            if chain is None and findings[idx].get("propagation_path"):
                chain = findings[idx]["propagation_path"]
            for cond in findings[idx].get("assumptions") or []:
                if isinstance(cond, dict):
                    key = (
                        str(cond.get("kind", "")).strip().lower(),
                        str(cond.get("text", "")).strip(),
                    )
                else:
                    key = ("", str(cond).strip())
                if not key[1] or key in seen_cond:
                    continue
                seen_cond.add(key)
                assumptions.append(cond)
        base["_contributions"] = contributions
        base["_agents"] = sorted({c["agent"] for c in contributions})
        if chain is not None:
            base["propagation_path"] = chain
        # 各视角给的 cond-1/cond-2 编号会重名，合并后重新编号（D 侧统一口径）
        for i, cond in enumerate(assumptions):
            if isinstance(cond, dict):
                cond = dict(cond)
                cond["id"] = f"cond-{i + 1}"
                assumptions[i] = cond
        base["assumptions"] = assumptions

        # 会话内历史相似漏洞检索（仅用于说明，不参与输出结构）
        try:
            base["_similar_history"] = find_similar_findings(conn, session_id, base, llm=llm)
        except Exception as exc:  # 检索失败不影响主流程
            log_event("retrieval.failed", level="warn", error=str(exc))
            base["_similar_history"] = []

        merged.append(base)
    return merged


def group_indices(findings: List[Dict[str, Any]], llm: Optional[Any]) -> List[List[int]]:
    """分组入口：LLM 优先，异常回落启发式。"""
    if llm is not None:
        try:
            return llm_group(findings, llm)
        except Exception as exc:
            log_event("dedupe.llm_failed", level="warn", error=str(exc))
    return heuristic_group(findings)


def heuristic_group(findings: List[Dict[str, Any]]) -> List[List[int]]:
    """启发式分组：CWE + 函数名 + 行号块（//5）+ 归一标题。"""
    buckets: Dict[tuple, List[int]] = {}
    for i, f in enumerate(findings):
        loc = f.get("location") or {}
        key = (
            str(f.get("cwe", "")).lower(),
            str(loc.get("function", "")).lower(),
            int(loc.get("line_start", 0) or 0) // 5,
            norm_title(f.get("title", "")),
        )
        buckets.setdefault(key, []).append(i)
    return list(buckets.values())


def norm_title(title: Any) -> str:
    return "".join(ch for ch in str(title).lower() if ch.isalnum())[:32]


def llm_group(findings: List[Dict[str, Any]], llm: Any) -> List[List[int]]:
    """让模型按语义分组；返回的分组保证覆盖所有下标（防止模型遗漏）。"""
    from langchain_core.messages import HumanMessage, SystemMessage

    compact = [
        {
            "index": i,
            "title": f.get("title", ""),
            "cwe": f.get("cwe", ""),
            "function": (f.get("location") or {}).get("function", ""),
            "taint_source": f.get("taint_source", ""),
            "taint_sink": f.get("taint_sink", ""),
        }
        for i, f in enumerate(findings)
    ]
    human = json.dumps(compact, ensure_ascii=False)
    prompt = load_verify_prompts().dedupe
    resp = llm.invoke([SystemMessage(content=prompt), HumanMessage(content=human)])
    data = parse_json_object(response_text(resp))
    groups = data.get("groups")
    if not isinstance(groups, list):
        raise ValueError("LLM 去重返回结构非法")

    result: List[List[int]] = []
    seen: set = set()
    n = len(findings)
    for g in groups:
        if not isinstance(g, list):
            continue
        g2 = [int(i) for i in g if isinstance(i, int) and 0 <= i < n and i not in seen]
        if g2:
            result.append(g2)
            seen.update(g2)
    for i in range(n):  # 防止模型遗漏
        if i not in seen:
            result.append([i])
            seen.add(i)
    return result
