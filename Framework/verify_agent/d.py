"""汇总 / 验证 Agent D（独立为 verify_agent）。

职责：
1. 等待并校验 A/B/C 三份报告齐全（缺一即停止报错）；
2. 使用 LLM 语义相似度对 findings 去重；
3. 调取对应原始报告中的判断内容与 confidence，裁决冲突并给出最终置信度与理由；
4. 将原始报告 + 生成 Agent 写入 ledger；将工具调用与假设验证推断写入 view；
5. 调用工具验证污点假设（通过 llm.bind_tools([verify_taint]) 或直接调用）；
6. 生成精简的最终 JSON 报告并落盘 output/final_report.json；
7. 生成面向修复端的输入投影并落盘 output/repair_input.json（repair-input/1，
   见 change_process/summery/修复端_输入需求与用途_2026-10-23_现状.md §4）。

【修复端输入 P0】location 在构造假设之前会被语法树校正：按行号反查所属函数、
把漏洞行吸附到最内层语句。A/B/C 给的函数名可能是占位文本，而行号是模型必须给的
主键；不校正的话 conditions[].holds 会全部退化为 null。

若无法验证（工具返回 uncertain），标记为 uncertain 并说明原因。
工具调用失败 / 超时 / 无结果时，停止并报错。

本文件内联了 D 的提示词（去重 / 裁决 / 工具验证）。

================================================================================
【优化点 O-7】D 工具循环接入 A 篇上下文治理（本次优化的核心落点）。
--------------------------------------------------------------------------------
对应 B 篇原文件：verify_agent/d.py（本文件优化前的版本）
原问题（对照 A 篇）：
    1. 首轮 HumanMessage 把完整源码放了【两遍】：``hypothesis.code`` 和
       ``context.code`` 都是同一份 code，纯重复占窗口。
    2. 工具结果（get_function_body 等）``json.dumps`` 后直接 append 为
       ToolMessage，多轮循环里反复累积，无任何计量 / 外存 / 裁剪 / 压缩。
    3. 没有“请求前压力检查”，只能等模型服务报 context overflow / 400。
本文件的优化（全部复用新增的 context 包，见各标注）：
    * 去重：hypothesis 不再内联完整 code，code 只在 context 中出现一次；
    * 外存（A 篇 spill）：首轮大源码、每条工具结果在写入消息前过
      ``ContextManager.spill_text``，完整内容落盘，模型只见首尾 + 读取提示；
    * 每轮 invoke 前 ``enforce_budget``：计量 → 裁剪历史大工具结果 → 仍超
      阈值再做摘要压缩（压缩边界已保证不切断 tool_call 配对）；
    * 治理动作（裁剪条数 / 落盘位置 / 压缩前后 token）写入 view 表 inference，
      可审计、可回放。
    * 降级模式（无 LLM）下，计量 / 外存 / 裁剪仍工作，压缩自动跳过。
================================================================================
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from agents import get_llm, load_settings, parse_json_object, response_text
from config import resolve
from context import ContextManager
from memory import db as mem_db
from memory.ledger import write_report
from memory.retrieval import find_similar_findings
from memory.view import write_verification
from observability import log_event, track_time
from tools.call_context import (
    CONTEXT_TOOLS,
    function_body_source,
    get_callees,
    get_callers,
    get_function_body,
    set_active_context,
    statement_at_line,
)
from tools.verify_taint import VERDICT_TO_STATUS, verify_taint, verify_taint_tool

REQUIRED_AGENTS = ("A", "B", "C")


# ---------------------------------------------------------------------------
# 输出报告结构（本 agent 的报告结构）
# ---------------------------------------------------------------------------
# 核验证据已进最终报告（原先只进 view 表）：修复 Agent 需要知道“为什么判它成立/被推翻”，
# 而不只是一个 verification_status。逐跳可达性、假设条件与阻塞守卫都在 evidence 里。
FINAL_REPORT_TEMPLATE: Dict[str, Any] = {
    "file": "",
    "findings": [
        {
            "location": {"file": "", "line_start": 0, "line_end": 0, "function": ""},
            "taint_chain": [],
            "verification_status": "uncertain",
            # 对抗式判定：accept / reject / challenge / uncertain
            "verdict": "uncertain",
            "confidence": 0.0,
            "fix_suggestion": "",
            # 工具信号证据（父设计 §3.1）：path=逐跳可达性，conditions=假设条件核验，
            # blockers=使条件不成立的守卫/校验，used_tools=本次用到的上下文工具。
            "evidence": {
                "path_status": "",
                "path": [],
                "conditions": [],
                "blockers": [],
                "used_tools": [],
            },
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
    "你是对抗式漏洞验证者。你的任务是**尝试推翻**给定的污点假设，而不是附和它。\n"
    "你有以下工具可用：\n"
    "* get_callers(function_name)：返回该函数在文件内的调用者（追踪污点参数来源）；\n"
    "* get_callees(function_name)：返回该函数调用的其他函数（追踪 sink / 指针使用 / 资源释放）；\n"
    "* get_function_body(function_name)：返回该函数的签名与实现（确认跨过程依赖）；\n"
    "* verify_taint(hypothesis, context)：工具侧的确定性核验（触发路径可达性 + 守卫/校验），\n"
    "  返回 verdict/evidence，可作为你的证据之一，但不要照抄它的结论。\n"
    "请先按需调用上下文工具（get_callers/get_callees/get_function_body）补充跨过程证据，"
    "再调用 verify_taint 取工具侧证据，最后给出你自己的裁决。\n"
    "注意：过大的源码或工具结果会以首尾预览 + 文件位置（stored at）给出，"
    "如需完整内容，请按需调用 get_function_body，或用 read 工具按 offset/limit 读取该文件。\n\n"
    "【最终输出】当证据足够时，停止调用工具，只输出一个 JSON 对象，不要任何解释或代码块：\n"
    '{"verdict": "accept|reject|challenge", "confidence": 0.0, "reason": ""}\n'
    "verdict 含义：accept=漏洞成立；reject=误报（触发路径不可达、或声称缺失的校验其实已存在）；"
    "challenge=证据不足以下结论。confidence 为 0~1。"
)


# ---------------------------------------------------------------------------
# 【优化 O-7】构造上下文治理器（读取 config 中的 context_* 配置）
# ---------------------------------------------------------------------------
def build_context_manager(settings: Any) -> ContextManager:
    """从配置构造 ContextManager，spill 目录解析为项目根下的绝对路径。"""
    return ContextManager(
        context_window=int(getattr(settings, "context_window", 128_000)),
        threshold_ratio=float(getattr(settings, "context_threshold_ratio", 0.8)),
        retain_ratio=float(getattr(settings, "context_retain_ratio", 0.16)),
        spill_root=str(resolve(getattr(settings, "spill_root", "output/spill"))),
        max_inline_bytes=int(getattr(settings, "spill_max_inline_bytes", 4096)),
        prune_threshold_chars=int(getattr(settings, "prune_threshold_chars", 8192)),
        prune_head_chars=int(getattr(settings, "prune_head_chars", 4096)),
        prune_tail_chars=int(getattr(settings, "prune_tail_chars", 1024)),
        enable_spill=bool(getattr(settings, "context_enable_spill", True)),
        enable_compaction=bool(getattr(settings, "context_enable_compaction", True)),
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
    # 【优化 O-7】本轮验证共享一个上下文治理器
    ctx = build_context_manager(settings)

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

        # 5) 工具验证（内部接入上下文治理）
        with track_time("verify"):
            verified = _verify_findings(merged, state, session_id, conn, llm, settings, ctx)

        # 6) 精简最终报告并落盘
        final = _build_final_report(file_path, verified)
        _write_output(final, resolve(settings.output_path))

        # 7) 【修复端输入 P0】面向修复端的投影，独立落盘
        #    （不动 final_report.json：那份是检测结论的稳定产物）
        repair_input = _build_repair_input(
            verified,
            file_path,
            state,
            report_file=str(getattr(settings, "output_path", "output/final_report.json")),
        )
        _write_repair_input(
            repair_input,
            resolve(getattr(settings, "repair_input_path", "output/repair_input.json")),
        )
    finally:
        conn.close()

    cases = repair_input.get("cases") or []
    log_event(
        "d.done",
        merged=len(merged),
        verified=len(verified),
        findings=len(final["findings"]),
        repair_cases=len(cases),
        repair_invalid=sum(1 for c in cases if not (c.get("validation") or {}).get("ok")),
    )
    return {
        "merged_findings": merged,
        "verified_findings": verified,
        "final_report": final,
        "repair_input": repair_input,
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
    data = parse_json_object(response_text(resp))
    fallback_conf = max([c.get("confidence", 0.0) for c in contributions] or [0.0])
    conf = float(data.get("final_confidence", fallback_conf) or fallback_conf)
    return {
        "final_confidence": round(conf, 4),
        "adjudication_reason": data.get("reason", ""),
        "has_conflict": None,
    }


# ---------------------------------------------------------------------------
# 定位校正（修复端输入 P0）：LLM 报的行号 → 语法树事实
# ---------------------------------------------------------------------------
def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _resolve_location(
    finding: Dict[str, Any],
    ctx: Any,
    code: str,
) -> Dict[str, Any]:
    """用语法树校正 ``location``：按行号反查所属函数 + 把漏洞行吸附到语句级。

    三件事都只能在检测端做（修复端没有文件系统）：

    1. ``function`` 改为**按行号反查**得到的函数名，覆盖 A/B/C 的文本判断 ——
       实测出现过占位文本 ``"containing function unavailable in supplied excerpt"``，
       而 ``verify_taint.check_assumptions`` 是拿这个名字去取函数体的；
    2. 记下函数的真实行范围（``function_line_start/end``），修复端要求的
       ``func_src`` / ``body_line_start`` 就是从这里切的；
    3. ``line_start/line_end`` 吸附到包含该行的***最内层语句***（修复端
       §2.2：要真正出问题的那条语句，不是签名行、也不是整个 if 块首行）。

    校正失败时保留原始行号并把来源标成 ``llm``，让下游看得出这条没核过。
    """
    out = dict(finding)
    loc = dict(finding.get("location") or {})
    line = _as_int(loc.get("line_start"))
    if line <= 0:
        out["location"] = loc
        return out

    info = None
    if ctx is not None:
        try:
            info = ctx.function_at(line)
        except Exception:  # pragma: no cover - 防御：降级为不校正
            info = None
    if info is not None:
        loc["function"] = info.get("function", "")
        loc["function_line_start"] = _as_int(info.get("line_start"))
        loc["function_line_end"] = _as_int(info.get("line_end"))
        loc["function_resolved_by"] = "ast"
    else:
        loc["function_resolved_by"] = "llm"

    stmt = statement_at_line(code, line, fallback_to_next=True)
    if stmt is not None:
        loc["line_start"] = _as_int(stmt.get("line_start"))
        loc["line_end"] = _as_int(stmt.get("line_end")) or loc["line_start"]
        loc["line_source"] = "ast" if stmt.get("matched") == "contains" else "ast-next"
    else:
        loc["line_source"] = "llm"

    out["location"] = loc
    return out


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
    ctx: ContextManager,  # 【优化 O-7】注入上下文治理器
) -> List[Dict[str, Any]]:
    file_path = state.get("file_path", "")
    code = state.get("code", "")
    verified: List[Dict[str, Any]] = []
    tau = float(getattr(settings, "verify_tau", 0.8) or 0.8)
    drop_rejected = bool(getattr(settings, "verify_drop_rejected", True))

    # 预提取当前文件的调用图上下文，供本轮的上下文工具与工具信号按需查询
    call_ctx = set_active_context(code)

    for finding_idx, f in enumerate(merged):
        # 【修复端输入 P0】先用语法树校正 location，再构造假设。
        # 顺序不能反：verify_taint.check_assumptions 依赖 location.function 取函数体，
        # 占位文本 / 空串会让 conditions[].holds 全部退化为 null。
        f = _resolve_location(f, call_ctx, code)
        hypothesis = _build_hypothesis(f, code)
        loc = f.get("location") or {}
        # 内部完整 context（含完整 code），仅供直接调用 verify_taint 兜底使用
        context = {
            "file": file_path,
            "line_range": [loc.get("line_start", 0), loc.get("line_end", 0)],
            "code": code,
        }

        # 信号 1：工具（代码事实，独立于 LLM）
        tool_sig = _signal_tool(hypothesis, context)
        # 信号 2：LLM（语义，复用 bind_tools 多轮；无 LLM 时为 None）
        tool_call, tool_result, context_reports, llm_sig = _invoke_verify(
            hypothesis, context, llm, settings, ctx, session_id, finding_idx
        )

        if tool_result is None:
            raise RuntimeError("工具调用无结果，停止。")
        tool_status = tool_result.get("status", "uncertain")
        if tool_status not in ("verified", "rejected", "uncertain"):
            raise RuntimeError(f"工具返回非法状态: {tool_status!r}，停止。")

        verdict = _combine(tool_sig, llm_sig, tau)
        confidence = verdict["confidence"]
        if not confidence:
            # 双方都未给出置信度时，回退到 D 的裁决置信度
            confidence = float(f.get("final_confidence", 0.0) or 0.0)
        status = verdict["status"]

        inference = {
            "finding_id": f.get("id", ""),
            "based_on_agents": f.get("_agents", []),
            "adjudication_reason": f.get("adjudication_reason", ""),
            "note": (
                "工具未给出结论，标记为 uncertain 并说明原因"
                if status == "uncertain"
                else "已给出结论"
            ),
            "verdict": verdict["verdict"],
            "tool_verdict": tool_sig.get("verdict", ""),
            "llm_verdict": "" if llm_sig is None else llm_sig.get("verdict", ""),
            "overturn": verdict["overturn"],
            "conflict": verdict["conflict"],
            "blockers": (tool_sig.get("evidence") or {}).get("blockers", []),
            "path_status": (tool_sig.get("evidence") or {}).get("path_status", ""),
            # 【优化 O-7】记录本 finding 的上下文治理动作，便于审计 / 回放
            "context_management": context_reports,
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
            verdict["reason"] or tool_result.get("reason", ""),
            verdict=verdict["verdict"],
            evidence=tool_sig.get("evidence") or {},
            conflict=verdict["conflict"],
        )

        if verdict["overturn"] and drop_rejected:
            # 可推翻：真正丢弃（G1）。留痕以便与「降级空报告」区分。
            log_event(
                "verify.overturn",
                finding_id=f.get("id", ""),
                verdict=verdict["verdict"],
                confidence=verdict["confidence"],
                tool_verdict=tool_sig.get("verdict", ""),
                llm_verdict="" if llm_sig is None else llm_sig.get("verdict", ""),
            )
            continue

        item = dict(f)
        item["verification_status"] = status
        item["confidence"] = round(float(confidence), 4)
        item["verdict"] = verdict["verdict"]
        item["evidence"] = tool_sig.get("evidence") or {}
        verified.append(item)

    return verified


def _norm_path(raw: Any) -> List[str]:
    """把报告里的传播路径归一为有序节点名列表（丢弃空元素与相邻重复）。"""
    seq: List[str] = []
    for item in raw or []:
        if isinstance(item, dict):
            text = str(item.get("function") or item.get("name") or item.get("node") or "")
        else:
            text = str(item or "")
        text = text.strip()
        if not text:
            continue
        if not seq or seq[-1] != text:
            seq.append(text)
    return seq


def _norm_assumptions(finding: Dict[str, Any]) -> List[Dict[str, str]]:
    """读取 finding 里的假设条件（触发前提），归一为 ``[{id, kind, text}]``。

    §7① 方案 ①：**不改 A/B/C**。若 A/B/C 将来提供 ``assume`` / ``conditions``
    字段就直接读；当前报告 schema 里没有，于是返回空列表，条件核验退化为
    「仅核路径」（子设计 §4.3 第 3 条）。
    """
    raw: Any = finding.get("assumptions")
    if not raw:
        raw = finding.get("assume")
    if not raw:
        raw = finding.get("conditions")

    out: List[Dict[str, str]] = []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return out
    for i, item in enumerate(raw):
        if isinstance(item, dict):
            text = str(item.get("text") or item.get("condition") or item.get("assume") or "").strip()
            kind = str(item.get("kind") or "other").strip()
            ident = str(item.get("id") or f"cond-{i + 1}").strip()
        elif isinstance(item, str):
            text, kind, ident = item.strip(), "other", f"cond-{i + 1}"
        else:
            continue
        if not text:
            continue
        out.append({"id": ident, "kind": kind, "text": text})
    return out


def _build_hypothesis(finding: Dict[str, Any], code: str) -> Dict[str, Any]:
    """构造待验证假设。

    【优化 O-7】不再把完整 ``code`` 内联进 hypothesis：完整源码只在 context 中
    出现一次，消除原来 hypothesis.code 与 context.code 的重复传输。

    【假设条件 + 触发路径核验】新增两键（旧键语义不变）：
      * ``trigger_path``：归一后的 source→sink 节点序列，默认取
        ``propagation_path``，供 verify_taint 逐跳核验可达性；
      * ``assumptions``：假设条件（触发前提），来源优先级见 _norm_assumptions。
    """
    loc = finding.get("location") or {}
    propagation = finding.get("propagation_path", [])
    return {
        "finding_id": finding.get("id", ""),
        "title": finding.get("title", ""),
        "cwe": finding.get("cwe", ""),
        "taint_source": finding.get("taint_source", ""),
        "taint_sink": finding.get("taint_sink", ""),
        "propagation_path": propagation,
        "trigger_path": _norm_path(propagation),
        "assumptions": _norm_assumptions(finding),
        "location": loc,
    }


def _build_model_payload(
    hypothesis: Dict[str, Any],
    context: Dict[str, Any],
    ctx: ContextManager,
    session_id: str,
    finding_idx: int,
) -> Tuple[str, List[dict]]:
    """构造模型可见的首轮 payload。

    【优化 O-7】大源码经 spill（A 篇外存）：完整源码落盘，模型只见首尾预览 +
    文件位置；code 只出现一次。返回 (payload 文本, 治理动作列表)。
    """
    code = context.get("code", "") or ""
    code_view, code_locator = ctx.prepare_large_input(
        code,
        session_id=session_id,
        tool_name="input-source",
        call_id=f"finding-{finding_idx}-source",
    )
    context_view = {
        "file": context.get("file", ""),
        "line_range": context.get("line_range", []),
        "code": code_view,
    }
    actions: List[dict] = []
    if code_locator:
        context_view["code_spill_locator"] = code_locator
        context_view["code_note"] = (
            "完整源码已外存：可用 read 工具按 offset/limit 读取，"
            "或调用 get_function_body 按需取相关函数。"
        )
        actions.append(
            {
                "stage": "spill.input_source",
                "locator": code_locator,
                "original_bytes": len(code.encode("utf-8")),
            }
        )
    payload = json.dumps(
        {"hypothesis": hypothesis, "context": context_view}, ensure_ascii=False
    )
    return payload, actions


def _invoke_verify(
    hypothesis: Dict[str, Any],
    context: Dict[str, Any],
    llm: Optional[Any],
    settings: Any,
    ctx: ContextManager,
    session_id: str,
    finding_idx: int,
):
    """调用验证工具。

    * 有 LLM 且存在可绑定工具时：走 llm.bind_tools([verify_taint, ...上下文工具]) + 多轮工具循环
      （循环内接入上下文治理）；
    * 否则：直接调用 verify_taint（使用含完整 code 的内部 context）。

    工具异常一律转换为 RuntimeError（停止并报错）。
    返回 (tool_call, tool_result, context_reports, llm_sig)：

    * ``llm_sig`` 为 LLM 侧裁决 ``{verdict, confidence, reason}``（父设计 §3.2 的
      ``_signal_llm``）；走纯工具兜底路径时为 ``None``，表示「无 LLM 信号」——
      与「LLM 表态 uncertain」严格区分。
    """
    if llm is not None and _available_tools():
        try:
            call, result, reports, llm_sig = _tool_loop(
                llm, hypothesis, context, settings, ctx, session_id, finding_idx
            )
            return call, result, reports, llm_sig
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(f"工具调用失败: {exc}") from exc

    # 兜底：直接调用（无 LLM / 无工具）。这里使用完整 context，不受外存影响。
    try:
        result = verify_taint(hypothesis, context)
    except Exception as exc:
        raise RuntimeError(f"工具调用失败: {exc}") from exc
    tool_call = {"tool": "verify_taint", "args": {"hypothesis": hypothesis, "context": context}}
    return tool_call, result, [], None


def _available_tools() -> List[Any]:
    """可绑定的工具集合：verify_taint + 上下文工具（缺失的自动跳过）。"""
    tools: List[Any] = []
    if verify_taint_tool is not None:
        tools.append(verify_taint_tool)
    tools.extend(t for t in CONTEXT_TOOLS if t is not None)
    return tools


# ---------------------------------------------------------------------------
# 双信号：工具信号（代码事实） + LLM 信号（语义） → _combine（父设计 §3.2/§3.3）
# ---------------------------------------------------------------------------
def _signal_tool(hypothesis: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """工具信号：直接调用 verify_taint，不调 LLM。

    刻意与「LLM 工具调用失败必须抛错」区分：工具信号是纯本地逻辑，
    异常时降级为 ``uncertain``（只影响合并，不影响主流程）。
    """
    try:
        result = verify_taint(hypothesis, context)
    except Exception as exc:  # 纯工具信号不拖垮整图
        log_event("verify.tool_signal_failed", error=f"{type(exc).__name__}: {exc}")
        return {
            "verdict": "uncertain",
            "confidence": 0.0,
            "reason": f"工具信号异常: {exc}",
            "evidence": {},
        }
    if not isinstance(result, dict):
        return {
            "verdict": "uncertain",
            "confidence": 0.0,
            "reason": "工具信号返回结构非法",
            "evidence": {},
        }
    try:
        confidence = float(result.get("confidence") or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    return {
        "verdict": str(result.get("verdict") or "uncertain").strip().lower(),
        "confidence": confidence,
        "reason": str(result.get("reason") or ""),
        "evidence": result.get("evidence") or {},
    }


def _combine(
    tool_sig: Dict[str, Any],
    llm_sig: Optional[Dict[str, Any]],
    tau: float,
) -> Dict[str, Any]:
    """双信号合并（定稿判定表）。

    * 2c：LLM 单方 reject 且另一方不表态（uncertain / 无信号）→ 丢弃；
    * 1c：工具 reject 且 ``confidence >= tau`` → 丢弃（实际只有「路径确定断链」
      能过 τ，因为 blocker 命中封顶 0.55）；
    * 正面冲突（一方 accept、另一方 reject）一律保留并标记 ``conflict``——
      代码事实说可达、LLM 说误报，属于真对抗，不能静默丢。
    """
    tool_v = str(tool_sig.get("verdict") or "uncertain").strip().lower()
    tool_c = float(tool_sig.get("confidence") or 0.0)
    llm_v = None if llm_sig is None else str(llm_sig.get("verdict") or "").strip().lower()
    llm_c = 0.0 if llm_sig is None else float(llm_sig.get("confidence") or 0.0)
    llm_reason = "" if llm_sig is None else str(llm_sig.get("reason") or "")

    verdict = "uncertain"
    confidence = 0.0
    overturn = False
    conflict = False

    if tool_v == "accept":
        if llm_v in (None, "accept", "uncertain"):
            verdict, confidence = "accept", max(tool_c, llm_c)
        else:  # LLM 认为误报 / 证据不足 → 真冲突，保留
            verdict, confidence, conflict = "uncertain", min(tool_c, llm_c), True
    elif tool_v == "reject":
        if llm_v == "reject":
            verdict, confidence, overturn = "reject", max(tool_c, llm_c), True
        elif llm_v == "accept":
            verdict, confidence, conflict = "uncertain", min(tool_c, llm_c), True
        elif tool_c >= tau:  # LLM challenge / uncertain / 无信号，工具证据够硬
            verdict, confidence, overturn = "reject", tool_c, True
        else:
            verdict, confidence, conflict = "uncertain", tool_c, True
    else:  # 工具 uncertain → 采用 LLM
        if llm_v == "accept":
            verdict, confidence = "accept", llm_c
        elif llm_v == "reject":
            verdict, confidence, overturn = "reject", llm_c, True
        elif llm_v == "challenge":
            verdict, confidence = "uncertain", llm_c
        else:
            verdict, confidence = "uncertain", tool_c

    reason = "工具信号：" + (tool_sig.get("reason") or "无")
    if llm_sig is not None:
        reason += "；LLM 信号：" + (llm_reason or "无")
    if conflict:
        reason += "；两信号冲突，保留并标记 conflict"
    if overturn:
        reason += "；判定可推翻（丢弃该 finding）"

    return {
        "verdict": verdict,
        "status": VERDICT_TO_STATUS.get(verdict, "uncertain"),
        "confidence": round(max(0.0, min(1.0, confidence)), 4),
        "overturn": overturn,
        "conflict": conflict,
        "reason": reason,
    }


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


_LLM_VERDICTS = ("accept", "reject", "challenge", "uncertain")


def _parse_llm_verdict(text: str) -> Dict[str, Any]:
    """解析 LLM 最终文本里的对抗裁决 → ``{verdict, confidence, reason}``。

    解析失败一律降级为 ``uncertain``（不抛错、不拖垮主流程）：LLM 信号缺失
    只会让 ``_combine`` 退回「采用工具证据」，不会造成误丢。
    """
    fallback: Dict[str, Any] = {
        "verdict": "uncertain",
        "confidence": 0.0,
        "reason": "LLM 未给出合法裁决，按 uncertain 处理",
    }
    raw = str(text or "").strip()
    if not raw:
        return fallback
    try:
        data = parse_json_object(raw)
    except Exception as exc:
        log_event("verify.llm_signal_parse_failed", error=str(exc))
        return fallback

    verdict = str(data.get("verdict") or "").strip().lower()
    if verdict not in _LLM_VERDICTS:
        log_event("verify.llm_signal_bad_verdict", verdict=verdict)
        return fallback
    try:
        confidence = float(data.get("confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    return {
        "verdict": verdict,
        "confidence": max(0.0, min(1.0, confidence)),
        "reason": str(data.get("reason") or "").strip(),
    }


def _tool_loop(
    llm: Any,
    hypothesis: Dict[str, Any],
    context: Dict[str, Any],
    settings: Any,
    ctx: ContextManager,
    session_id: str,
    finding_idx: int,
):
    """模型自主多轮工具循环（MAVUL 式），接入 A 篇上下文治理。

    契约（B 篇历史教训）：**每个 tool_call 都必须追加一条匹配 tool_call_id 的
    ToolMessage**，否则下一次 invoke 会因缺少匹配输出而报 400
    （见 record_to_finish 2026-10-03_04）。压缩逻辑也已保证不切断该配对。

    治理顺序（A 篇）：
      1. 首轮大源码 spill，只发一次；
      2. 每条工具结果在写入 ToolMessage 前 spill（大函数体落盘）；
      3. 每轮 invoke 前 enforce_budget（计量 → 裁剪历史 → 压缩）。
    """
    from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

    available = _available_tools()
    bound = llm.bind_tools(available)

    # 【优化 O-7】首轮 payload：大源码外存 + code 去重
    payload_text, input_actions = _build_model_payload(
        hypothesis, context, ctx, session_id, finding_idx
    )
    messages = [
        SystemMessage(content=PROMPT_TOOL),
        HumanMessage(content=payload_text),
    ]
    context_reports: List[dict] = list(input_actions)

    trace: List[Dict[str, Any]] = []
    last_call: Optional[Dict[str, Any]] = None
    last_result: Optional[Dict[str, Any]] = None
    llm_final_text: str = ""
    for _ in range(max(1, settings.max_retries) + 2):
        # 【优化 O-7】请求前预算治理：计量 → 裁剪 → 压缩
        messages, report = ctx.enforce_budget(
            messages,
            llm=llm,
            tools=available,
            session_id=session_id,
            phase=f"d.verify.finding-{finding_idx}",
        )
        if report.acted:
            log_event(
                "context.enforce",
                phase=report.phase,
                before=report.before_tokens,
                after=report.after_tokens,
                pruned=report.pruned_replacements,
                compact=report.compact_ok,
            )
            context_reports.append(report.to_dict())

        resp = bound.invoke(messages)
        tool_calls = getattr(resp, "tool_calls", None) or []
        if not tool_calls:
            # 不再调工具的一轮 = LLM 的最终裁决输出（父设计 §3.2 的 llm_sig）
            llm_final_text = (
                response_text(resp) if getattr(resp, "content", None) is not None else ""
            )
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

            # 【优化 O-7】工具结果写入前 spill：超大结果落盘，只留首尾 + 读取提示
            result_text = json.dumps(result, ensure_ascii=False, default=str)
            result_text = ctx.spill_text(
                result_text,
                session_id=session_id,
                tool_name=name or "tool",
                call_id=str(tc.get("id", "")),
            )
            # 无论工具是否可执行，都必须补齐匹配的 ToolMessage（B 篇 400 教训）
            messages.append(
                ToolMessage(
                    content=result_text,
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
    return summary, last_result, context_reports, _parse_llm_verdict(llm_final_text)


# ---------------------------------------------------------------------------
# 最终报告
# ---------------------------------------------------------------------------
def _build_final_report(file_path: str, verified: List[Dict[str, Any]]) -> Dict[str, Any]:
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
        item["verdict"] = f.get("verdict") or "uncertain"
        item["confidence"] = round(float(f.get("confidence", 0.0) or 0.0), 4)
        item["fix_suggestion"] = f.get("fix_suggestion") or f.get("suggestion", "")
        # 核验证据：缺失时（旧数据 / 未经核验）也保持结构完整，不输出 null
        ev = f.get("evidence") or {}
        item["evidence"] = {
            "path_status": ev.get("path_status", "") or "",
            "path": ev.get("path") or [],
            "conditions": ev.get("conditions") or [],
            "blockers": ev.get("blockers") or [],
            "used_tools": ev.get("used_tools") or [],
        }
        report["findings"].append(item)
    return report


def _write_output(final: Dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        # 纯 JSON，不输出 markdown / SARIF / 可读摘要
        json.dump(final, fh, ensure_ascii=False, indent=2)
    log_event("output.written", path=str(path))


# ---------------------------------------------------------------------------
# 修复端输入投影（repair-input/1）
#
# 依据 change_process/summery/修复端_输入需求与用途_2026-10-23_现状.md §4：
# 修复端 C1/C4 的唯一代码输入是「目标函数全文」，它没有文件系统访问权，
# 所以这一段必须在检测端切好、切准、切得和工程里那份文件一致。
# 为什么另写文件而不改 final_report.json：后者是「检测结论」的稳定产物，已有下游；
# 两边演进互不阻塞。
# ---------------------------------------------------------------------------
REPAIR_SCHEMA = "repair-input/1"
REPAIR_VERDICTS = ("accept", "uncertain", "challenge", "reject")
_CWE_PATTERN = re.compile(r"CWE[-_ ]?\s*(\d+)", re.IGNORECASE)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_cwe(raw: Any) -> str:
    """归一为 ``^CWE-\\d+$`` 规范串；抽不出来返回空串。

    修复端 C3 的第一道操作是 CWE 硬过滤（``cwe_key(d.cwe) == cwe_key(target)``），
    CWE 写歪 = 检索结果恒为空集。A/B/C 实测会给 ``"CWE-787 越界写"`` 这类变体，
    所以必须收窄到规范串；抽不出来就置空，让校验把该 case 挡在 accept 档外。
    """
    match = _CWE_PATTERN.search(str(raw or ""))
    return f"CWE-{int(match.group(1))}" if match else ""


def _is_absolute_path(value: str) -> bool:
    text = str(value or "")
    return bool(text) and (os.path.isabs(text) or re.match(r"^[A-Za-z]:[\\/]", text) is not None)


def _safe_id(text: str) -> str:
    """把任意文本压成可用作目录名的片段。"""
    cleaned = re.sub(r"[^0-9A-Za-z._-]+", "_", str(text or "")).strip("._-")
    return cleaned or "case"


def _source_meta(state: Dict[str, Any], file_path: str) -> Dict[str, Any]:
    """组装 ``source``：仓库相对路径优先（跨机器可复现），绝对路径降级但会被校验拦下。"""
    rel = str(state.get("rel_file") or "").strip().replace("\\", "/")
    scan = str(file_path or "")
    return {
        "repo": str(state.get("repo") or ""),
        "commit": str(state.get("commit") or ""),
        "file": rel or scan.replace("\\", "/"),
        "scan_file": scan,
    }


def _unique_case_id(
    case_id: str,
    finding: Dict[str, Any],
    source: Dict[str, Any],
    line: int,
    used: set,
) -> str:
    """确定 case 目录名：优先用调用方给的 ``case_id``，否则按「文件名__函数__行号」生成。"""
    base = _safe_id(case_id) if str(case_id or "").strip() else ""
    if not base:
        loc = finding.get("location") or {}
        func = str(loc.get("function") or "unknown")
        stem = os.path.splitext(os.path.basename(str(source.get("file") or "")))[0]
        base = "__".join([_safe_id(stem or "case"), _safe_id(func), f"L{line or 0}"])
    candidate = base
    seq = 2
    while candidate in used:
        candidate = f"{base}__{seq}"
        seq += 1
    used.add(candidate)
    return candidate


def _build_repair_input(
    verified: List[Dict[str, Any]],
    file_path: str,
    state: Dict[str, Any],
    report_file: str = "output/final_report.json",
) -> Dict[str, Any]:
    """构建面向修复端的输入投影（``repair-input/1``）。

    每个 case 按设计稿 §4 的形状给出 ``case_id / source / vuln / code / evidence``，
    并额外附两个**增量**字段（下游可忽略、检测端自检用）：

    * ``code.line_source`` / ``code.function_resolved_by``：这行 / 这个函数名是
      语法树给的（``ast``）还是照抄 LLM 的（``llm``）；
    * ``validation``：检测端先跑一遍 §4 的六条校验。``ok=False`` 的 case 修复端
      应记 ``invalid_baseline``、不进 Repair Rate 分母（不是"没修好"）。

    ``code.func_src`` 按原文件字节整段切出（含签名与花括号），因此
    ``body_line_start/end`` 与它的行数天然自洽；断不截，超长函数由修复端自己切窗口。
    """
    code = str(state.get("code") or "")
    source = _source_meta(state, file_path)
    default_case_id = str(state.get("case_id") or "")
    generated_at = _now_iso()
    used_ids: set = set()
    cases: List[Dict[str, Any]] = []

    for index, finding in enumerate(verified):
        loc = finding.get("location") or {}
        line = _as_int(loc.get("line_start"))
        line_end = _as_int(loc.get("line_end")) or line
        fn_start = _as_int(loc.get("function_line_start"))
        fn_end = _as_int(loc.get("function_line_end"))
        evidence = finding.get("evidence") or {}

        case_id = default_case_id
        if default_case_id and len(verified) > 1:
            case_id = f"{default_case_id}__f{index + 1}"

        cases.append(
            {
                "case_id": _unique_case_id(case_id, finding, source, line, used_ids),
                "source": dict(source),
                "vuln": {
                    "cwe": _normalize_cwe(finding.get("cwe")),
                    "line": line,
                    "line_end": line_end,
                    "func": str(loc.get("function") or ""),
                    "confidence": round(float(finding.get("confidence", 0.0) or 0.0), 4),
                    "verdict": str(finding.get("verdict") or "uncertain"),
                },
                "code": {
                    "func_src": function_body_source(code, fn_start, fn_end),
                    "body_line_start": fn_start,
                    "body_line_end": fn_end,
                    "truncated": False,
                    "line_source": str(loc.get("line_source") or "llm"),
                    "function_resolved_by": str(loc.get("function_resolved_by") or "llm"),
                },
                "evidence": {
                    "path_status": str(evidence.get("path_status") or ""),
                    "path": evidence.get("path") or [],
                    "conditions": evidence.get("conditions") or [],
                    "blockers": evidence.get("blockers") or [],
                },
                "provenance": {
                    "detector": "A/B/C+D",
                    "report_file": report_file,
                    "generated_at": generated_at,
                },
            }
        )

    for case in cases:
        errors = _validate_repair_case(case)
        case["validation"] = {"ok": not errors, "errors": errors}

    return {
        "schema": REPAIR_SCHEMA,
        "generated_at": generated_at,
        "provenance": {
            "detector": "A/B/C+D",
            "report_file": report_file,
            "case_count": len(cases),
            "invalid_count": sum(1 for c in cases if not c["validation"]["ok"]),
        },
        "cases": cases,
    }


def _validate_repair_case(case: Dict[str, Any]) -> List[str]:
    """设计稿 §4 的六条校验（第 5 条的「case_id 批次内唯一」在构建时已保证）。

    返回错误列表；空列表 = 这条可以直接交给修复端。
    """
    errors: List[str] = []
    vuln = case.get("vuln") or {}
    code = case.get("code") or {}
    source = case.get("source") or {}

    cwe = str(vuln.get("cwe") or "")
    if re.fullmatch(r"CWE-\d+", cwe) is None:
        errors.append(f"vuln.cwe 不是规范串: {cwe!r}")

    if str(vuln.get("verdict") or "") not in REPAIR_VERDICTS:
        errors.append(f"vuln.verdict 非法: {vuln.get('verdict')!r}")

    if not str(case.get("case_id") or ""):
        errors.append("case_id 为空")
    if _is_absolute_path(str(source.get("file") or "")):
        errors.append("source.file 是绝对路径（应为仓库相对路径，否则跨机器无法复现）")

    src = str(code.get("func_src") or "")
    start = _as_int(code.get("body_line_start"))
    end = _as_int(code.get("body_line_end"))
    if not src:
        # 后续四条都建立在 func_src 之上，缺了就没有继续核的必要
        errors.append("code.func_src 为空（未能按行号定位函数）")
        return errors

    lines = src.splitlines()
    if end < start or len(lines) != end - start + 1:
        errors.append(
            f"func_src 行数 {len(lines)} != body_line_end-body_line_start+1 ({end - start + 1})"
        )

    line = _as_int(vuln.get("line"))
    if not (start <= line <= end):
        errors.append(f"vuln.line {line} 落在函数范围 [{start}, {end}] 之外")
    elif not (0 <= line - start < len(lines)):
        # func_src 行数与行范围不一致时，偏移量可能越界（上面的行数检查已记过）
        errors.append("vuln.line 在 func_src 内取不到对应行")
    else:
        text = lines[line - start].strip()
        if not text:
            errors.append("vuln.line 指向空行")
        elif text in ("{", "}", "};"):
            errors.append("vuln.line 指向花括号行，不是语句")

    return errors


def _write_repair_input(payload: Dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    cases = payload.get("cases") or []
    log_event(
        "repair_input.written",
        path=str(path),
        cases=len(cases),
        invalid=sum(1 for c in cases if not (c.get("validation") or {}).get("ok")),
    )
