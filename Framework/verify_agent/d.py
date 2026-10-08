"""汇总 / 验证 Agent D（独立为 verify_agent）。

职责：
1. 等待并校验 A/B/C 三份报告齐全（缺一即停止报错）；
2. 使用 LLM 语义相似度对 findings 去重；
3. 调取对应原始报告中的判断内容与 confidence，裁决冲突并给出最终置信度与理由；
4. 将原始报告 + 生成 Agent 写入 ledger；将工具调用与假设验证推断写入 view；
5. 调用工具验证污点假设（通过 llm.bind_tools([verify_taint]) 或直接调用）；
6. 生成精简的最终 JSON 报告并落盘 output/final_report.json。

若无法验证（工具返回 uncertain），标记为 uncertain 并说明原因。
工具调用失败 / 超时 / 无结果时，停止并报错。

本文件内联了 D 的提示词（去重 / 裁决 / 工具验证）。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from agents import get_llm, load_settings, parse_json_object
from config import resolve
from memory import db as mem_db
from memory.ledger import write_report
from memory.retrieval import find_similar_findings
from memory.view import write_verification
from observability import log_event, track_time
from tools.call_context import (
    CONTEXT_TOOLS,
    get_callees,
    get_callers,
    get_function_body,
    set_active_context,
)
from tools.verify_taint import verify_taint, verify_taint_tool

REQUIRED_AGENTS = ("A", "B", "C")


# ---------------------------------------------------------------------------
# 输出报告结构（本 agent 的报告结构）
# ---------------------------------------------------------------------------
# TODO: 输出报告结构待修改（将来自行调整字段）。
FINAL_REPORT_TEMPLATE: Dict[str, Any] = {
    "file": "",
    "findings": [
        {
            "location": {"file": "", "line_start": 0, "line_end": 0, "function": ""},
            "taint_chain": [],
            "verification_status": "uncertain",
            "confidence": 0.0,
            "fix_suggestion": "",
        }
    ],
}


# ---------------------------------------------------------------------------
# D 的提示词（内联）
# ---------------------------------------------------------------------------
PROMPT_DEDUPE = (
    "你是漏洞报告去重助手。给定若干漏洞条目的精简信息，"
    "请把语义上属于同一漏洞的条目分到同一组。"
    '只输出 JSON：{"groups": [[索引, ...], ...]}，不要输出其他内容。'
)

PROMPT_ADJUDICATE = (
    "你是漏洞裁决助手。给定同一漏洞的多个视角判断（含 confidence），"
    "请裁决冲突并给出最终置信度与理由。"
    '只输出 JSON：{"final_confidence": 0.0, "reason": ""}，不要输出其他内容。'
)

PROMPT_TOOL = (
    "你有以下工具可用：\n"
    "* get_callers(function_name)：返回该函数在文件内的调用者（追踪污点参数来源）；\n"
    "* get_callees(function_name)：返回该函数调用的其他函数（追踪 sink / 指针使用 / 资源释放）；\n"
    "* get_function_body(function_name)：返回该函数的签名与实现（确认跨过程依赖）；\n"
    "* verify_taint(hypothesis, context)：对污点假设给出 verified/rejected/uncertain 结论。\n"
    "请先按需调用上下文工具（get_callers/get_callees/get_function_body）补充跨过程证据，"
    "再调用 verify_taint 给出最终结论。"
)


# ---------------------------------------------------------------------------
# 节点入口
# ---------------------------------------------------------------------------
def run(state: Dict[str, Any]) -> Dict[str, Any]:
    settings = load_settings()
    reports: Dict[str, Any] = state.get("reports", {}) or {}

    # 1) 校验三份报告齐全
    missing = [a for a in REQUIRED_AGENTS if a not in reports]
    if missing:
        raise RuntimeError(f"D 未接收到全部报告，缺失: {missing}。已停止。")

    session_id = state.get("session_id", "")
    code = state.get("code", "")
    file_path = state.get("file_path", "")

    conn = mem_db.get_connection(resolve(settings.db_path))
    llm = get_llm(settings)

    try:
        # 2) 原始报告写入 ledger
        for agent in REQUIRED_AGENTS:
            write_report(conn, session_id, agent, reports[agent], code)

        # 3) 语义去重
        findings = _collect_findings(reports)
        with track_time("dedupe"):
            merged = _deduplicate(findings, session_id, conn, llm)

        # 4) 冲突裁决 + 置信度
        with track_time("adjudicate"):
            merged = _adjudicate(merged, llm)

        # 5) 工具验证
        with track_time("verify"):
            verified = _verify_findings(merged, state, session_id, conn, llm, settings)

        # 6) 精简最终报告并落盘
        final = _build_final_report(file_path, verified)
        _write_output(final, resolve(settings.output_path))
    finally:
        conn.close()

    log_event("d.done", merged=len(merged), verified=len(verified), findings=len(final["findings"]))
    return {
        "merged_findings": merged,
        "verified_findings": verified,
        "final_report": final,
    }


# ---------------------------------------------------------------------------
# 收集 / 去重
# ---------------------------------------------------------------------------
def _collect_findings(reports: Dict[str, Any]) -> List[Dict[str, Any]]:
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


def _deduplicate(
    findings: List[Dict[str, Any]],
    session_id: str,
    conn: Any,
    llm: Optional[Any],
) -> List[Dict[str, Any]]:
    if not findings:
        return []

    groups = _group_indices(findings, llm)
    merged: List[Dict[str, Any]] = []
    for group in groups:
        base = dict(findings[group[0]])
        contributions: List[Dict[str, Any]] = []
        chain: Optional[List[Any]] = None
        for idx in group:
            contributions.extend(findings[idx].get("_contributions", []))
            if chain is None and findings[idx].get("propagation_path"):
                chain = findings[idx]["propagation_path"]
        base["_contributions"] = contributions
        base["_agents"] = sorted({c["agent"] for c in contributions})
        if chain is not None:
            base["propagation_path"] = chain

        # 会话内历史相似漏洞检索（仅用于说明，不参与输出结构）
        try:
            base["_similar_history"] = find_similar_findings(conn, session_id, base, llm=llm)
        except Exception as exc:  # 检索失败不影响主流程
            log_event("retrieval.failed", error=str(exc))
            base["_similar_history"] = []

        merged.append(base)
    return merged


def _group_indices(findings: List[Dict[str, Any]], llm: Optional[Any]) -> List[List[int]]:
    if llm is not None:
        try:
            return _llm_group(findings, llm)
        except Exception as exc:
            log_event("dedupe.llm_failed", error=str(exc))
    return _heuristic_group(findings)


def _heuristic_group(findings: List[Dict[str, Any]]) -> List[List[int]]:
    buckets: Dict[tuple, List[int]] = {}
    for i, f in enumerate(findings):
        loc = f.get("location") or {}
        key = (
            str(f.get("cwe", "")).lower(),
            str(loc.get("function", "")).lower(),
            int(loc.get("line_start", 0) or 0) // 5,
            _norm_title(f.get("title", "")),
        )
        buckets.setdefault(key, []).append(i)
    return list(buckets.values())


def _norm_title(title: Any) -> str:
    return "".join(ch for ch in str(title).lower() if ch.isalnum())[:32]


def _llm_group(findings: List[Dict[str, Any]], llm: Any) -> List[List[int]]:
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
    resp = llm.invoke([SystemMessage(content=PROMPT_DEDUPE), HumanMessage(content=human)])
    data = parse_json_object(getattr(resp, "content", str(resp)))
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


# ---------------------------------------------------------------------------
# 冲突裁决
# ---------------------------------------------------------------------------
def _adjudicate(merged: List[Dict[str, Any]], llm: Optional[Any]) -> List[Dict[str, Any]]:
    for f in merged:
        contributions = f.get("_contributions", [])
        if llm is not None:
            try:
                f.update(_llm_adjudicate(f, contributions, llm))
                continue
            except Exception as exc:
                log_event("adjudicate.llm_failed", error=str(exc))
        f.update(_heuristic_adjudicate(contributions))
    return merged


def _heuristic_adjudicate(contributions: List[Dict[str, Any]]) -> Dict[str, Any]:
    confs = [c.get("confidence", 0.0) for c in contributions] or [0.0]
    severities = {str(c.get("severity", "")).lower() for c in contributions if c.get("severity")}
    agents = [c.get("agent") for c in contributions]
    conflict = len(severities) > 1
    reason = (
        f"由 {agents} 的判断汇总；各视角置信度={confs}；"
        + ("检测到严重级别冲突，取最高置信度并保守处理。" if conflict else "各视角结论基本一致。")
    )
    return {
        "final_confidence": round(max(confs), 4),
        "adjudication_reason": reason,
        "has_conflict": conflict,
    }


def _llm_adjudicate(
    finding: Dict[str, Any], contributions: List[Dict[str, Any]], llm: Any
) -> Dict[str, Any]:
    from langchain_core.messages import HumanMessage, SystemMessage

    payload = {
        "title": finding.get("title", ""),
        "cwe": finding.get("cwe", ""),
        "judgements": contributions,
    }
    resp = llm.invoke(
        [SystemMessage(content=PROMPT_ADJUDICATE), HumanMessage(content=json.dumps(payload, ensure_ascii=False))]
    )
    data = parse_json_object(getattr(resp, "content", str(resp)))
    fallback_conf = max([c.get("confidence", 0.0) for c in contributions] or [0.0])
    conf = float(data.get("final_confidence", fallback_conf) or fallback_conf)
    return {
        "final_confidence": round(conf, 4),
        "adjudication_reason": data.get("reason", ""),
        "has_conflict": None,
    }


# ---------------------------------------------------------------------------
# 工具验证
# ---------------------------------------------------------------------------
def _verify_findings(
    merged: List[Dict[str, Any]],
    state: Dict[str, Any],
    session_id: str,
    conn: Any,
    llm: Optional[Any],
    settings: Any,
) -> List[Dict[str, Any]]:
    file_path = state.get("file_path", "")
    code = state.get("code", "")
    verified: List[Dict[str, Any]] = []

    # 预提取当前文件的调用图上下文，供本轮的上下文工具按需查询
    set_active_context(code)

    for f in merged:
        hypothesis = _build_hypothesis(f, code)
        loc = f.get("location") or {}
        context = {
            "file": file_path,
            "line_range": [loc.get("line_start", 0), loc.get("line_end", 0)],
            "code": code,
        }

        tool_call, tool_result = _invoke_verify(hypothesis, context, llm, settings)

        if tool_result is None:
            raise RuntimeError("工具调用无结果，停止。")
        status = tool_result.get("status", "uncertain")
        if status not in ("verified", "rejected", "uncertain"):
            raise RuntimeError(f"工具返回非法状态: {status!r}，停止。")

        confidence = tool_result.get("confidence", 0.0) or 0.0
        if not confidence:
            # 工具未给出置信度时，回退到 D 的裁决置信度
            confidence = f.get("final_confidence", 0.0) or 0.0

        inference = {
            "finding_id": f.get("id", ""),
            "based_on_agents": f.get("_agents", []),
            "adjudication_reason": f.get("adjudication_reason", ""),
            "note": (
                "工具未给出结论，标记为 uncertain 并说明原因"
                if status == "uncertain"
                else "工具已给出结论"
            ),
        }

        write_verification(
            conn,
            session_id,
            hypothesis,
            tool_call,
            tool_result,
            inference,
            status,
            float(confidence),
            tool_result.get("reason", ""),
        )

        item = dict(f)
        item["verification_status"] = status
        item["confidence"] = round(float(confidence), 4)
        verified.append(item)

    return verified


def _build_hypothesis(finding: Dict[str, Any], code: str) -> Dict[str, Any]:
    loc = finding.get("location") or {}
    return {
        "finding_id": finding.get("id", ""),
        "title": finding.get("title", ""),
        "cwe": finding.get("cwe", ""),
        "taint_source": finding.get("taint_source", ""),
        "taint_sink": finding.get("taint_sink", ""),
        "propagation_path": finding.get("propagation_path", []),
        "location": loc,
        "code": code,
    }


def _invoke_verify(
    hypothesis: Dict[str, Any], context: Dict[str, Any], llm: Optional[Any], settings: Any
):
    """调用验证工具。

    * 有 LLM 且存在可绑定工具时：走 llm.bind_tools([verify_taint, ...上下文工具]) + 多轮工具循环；
    * 否则：直接调用 verify_taint。

    工具异常一律转换为 RuntimeError（停止并报错）。
    """
    if llm is not None and _available_tools():
        try:
            return _tool_loop(llm, hypothesis, context, settings)
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(f"工具调用失败: {exc}") from exc

    try:
        result = verify_taint(hypothesis, context)
    except Exception as exc:
        raise RuntimeError(f"工具调用失败: {exc}") from exc
    tool_call = {"tool": "verify_taint", "args": {"hypothesis": hypothesis, "context": context}}
    return tool_call, result


def _available_tools() -> List[Any]:
    """可绑定的工具集合：verify_taint + 上下文工具（缺失的自动跳过）。"""
    tools: List[Any] = []
    if verify_taint_tool is not None:
        tools.append(verify_taint_tool)
    tools.extend(t for t in CONTEXT_TOOLS if t is not None)
    return tools


def _dispatch_tool(
    name: Optional[str],
    args: Dict[str, Any],
    hypothesis: Dict[str, Any],
    context: Dict[str, Any],
) -> Any:
    """按工具名分发，返回 ``(result, call_record)``。

    * verify_taint：失败按原策略抛出（由上层转 RuntimeError 停止并报错）；
    * 上下文工具：内部已降级，额外再兜一层 try/except，绝不中断主流程。
    """
    args = args or {}
    # 兼容 LangChain 暴露的 *_tool 命名（verify_taint_tool / get_callers_tool 等）
    if name and name.endswith("_tool"):
        name = name[: -len("_tool")]
    if name == "verify_taint":
        h = args.get("hypothesis", hypothesis)
        c = args.get("context", context)
        result = verify_taint(h, c)
        # 只记紧凑标识：完整 hypothesis/context 已分别落 hypothesis_json，避免冗余与循环引用
        finding_id = h.get("finding_id", "") if isinstance(h, dict) else ""
        return result, {"tool": "verify_taint", "args": {"finding_id": finding_id}}

    if name in ("get_callers", "get_callees", "get_function_body"):
        impl = {
            "get_callers": get_callers,
            "get_callees": get_callees,
            "get_function_body": get_function_body,
        }[name]
        try:
            result = impl(args.get("function_name", ""))
        except Exception as exc:  # 上下文工具绝不中断主流程
            result = {"error": f"{type(exc).__name__}: {exc}"}
        return result, {"tool": name, "args": {"function_name": args.get("function_name", "")}}

    return {"error": f"unknown tool: {name}"}, {"tool": name, "error": "unknown tool"}


def _tool_loop(
    llm: Any, hypothesis: Dict[str, Any], context: Dict[str, Any], settings: Any
):
    """模型自主多轮工具循环（MAVUL 式）。

    契约：**每个 tool_call 都必须追加一条匹配 tool_call_id 的 ToolMessage**，
    否则下一次 invoke 会因缺少匹配输出而报 400（见 record_to_finish 2026-10-03_04）。
    """
    from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

    bound = llm.bind_tools(_available_tools())
    messages = [
        SystemMessage(content=PROMPT_TOOL),
        HumanMessage(
            content=json.dumps({"hypothesis": hypothesis, "context": context}, ensure_ascii=False)
        ),
    ]

    trace: List[Dict[str, Any]] = []
    last_call: Optional[Dict[str, Any]] = None
    last_result: Optional[Dict[str, Any]] = None
    for _ in range(max(1, settings.max_retries) + 2):
        resp = bound.invoke(messages)
        tool_calls = getattr(resp, "tool_calls", None) or []
        if not tool_calls:
            break
        messages.append(resp)
        for tc in tool_calls:
            name = tc.get("name")
            args = tc.get("args", {}) or {}
            result, call_record = _dispatch_tool(name, args, hypothesis, context)
            trace.append(call_record)
            if name == "verify_taint":
                last_result = result
                last_call = call_record
            messages.append(
                ToolMessage(
                    content=json.dumps(result, ensure_ascii=False),
                    tool_call_id=tc.get("id", ""),
                )
            )

    if last_result is None:
        # 模型没有给出 verify_taint 结论 -> 直接兜底调用
        last_result, last_call = _dispatch_tool(
            "verify_taint",
            {"hypothesis": hypothesis, "context": context},
            hypothesis,
            context,
        )
    if last_call is None:  # pragma: no cover - 防御
        last_call = {"tool": "verify_taint", "args": {}}
    # 用副本承载 trace：last_call 与 trace 中的同一条记录是同一个对象，
    # 直接 setdefault 会互指形成循环引用（json 落库时报 Circular reference）。
    summary = dict(last_call)
    summary["trace"] = trace
    return summary, last_result


# ---------------------------------------------------------------------------
# 最终报告
# ---------------------------------------------------------------------------
def _build_final_report(file_path: str, verified: List[Dict[str, Any]]) -> Dict[str, Any]:
    # TODO: 输出报告结构待修改。
    report: Dict[str, Any] = json.loads(json.dumps(FINAL_REPORT_TEMPLATE))
    report["file"] = file_path
    report["findings"] = []
    for f in verified:
        loc = f.get("location") or {}
        item: Dict[str, Any] = json.loads(json.dumps(FINAL_REPORT_TEMPLATE["findings"][0]))
        item["location"] = {
            "file": loc.get("file", file_path) or file_path,
            "line_start": loc.get("line_start", 0),
            "line_end": loc.get("line_end", 0),
            "function": loc.get("function", ""),
        }
        item["taint_chain"] = f.get("taint_chain") or f.get("propagation_path") or []
        item["verification_status"] = f.get("verification_status", "uncertain")
        item["confidence"] = round(float(f.get("confidence", 0.0) or 0.0), 4)
        item["fix_suggestion"] = f.get("fix_suggestion") or f.get("suggestion", "")
        report["findings"].append(item)
    return report


def _write_output(final: Dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        # 纯 JSON，不输出 markdown / SARIF / 可读摘要
        json.dump(final, fh, ensure_ascii=False, indent=2)
    log_event("output.written", path=str(path))
