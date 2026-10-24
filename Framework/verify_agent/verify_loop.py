"""D 的验证编排：逐条 finding 走「工具信号 + LLM 信号 → 合并 → 落 view」。

从 ``verify_agent/d.py`` 拆出（20 文档 §5.1-2），把原先混在一个文件里的
「定位校正 / 双信号合并 / 工具循环 / 报告组装」拆到各自模块后，这里只做编排：

* 定位校正 → :mod:`verify_agent.location`
* 双信号与判定表 → :mod:`verify_agent.signals`
* LLM 工具循环与兜底调用 → :mod:`verify_agent.tool_loop`

【健壮性包 B-2】单条 finding 的工具失败（``VerifyError``）只隔离该条：标
``uncertain`` + 记 ``errors``，其余 finding 照常验证，不中断整轮。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from config import resolve
from context import ContextManager
from errors import VerifyError
from memory.view import write_verification
from observability import log_event
from tools.call_context import set_active_context  # noqa: F401  （兼容 d.set_active_context）
from verify_agent.location import build_hypothesis, resolve_location
from verify_agent.signals import combine, tool_signal
from verify_agent.tool_loop import invoke_verify


def build_context_manager(settings: Any) -> ContextManager:
    """【优化 O-7】从配置构造 ContextManager，spill 目录解析为项目根下的绝对路径。"""
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


def degraded_item(finding: Dict[str, Any], error: VerifyError) -> Dict[str, Any]:
    """【健壮性包 B-2】验证步骤失败时的降级产物。

    保留 finding 本体（宁可交一条 ``uncertain``，也不静默丢掉一条可能真存在的漏洞），
    只把验证结论退化为 uncertain，并在 ``verify_error`` 里留原因。
    """
    item = dict(finding)
    item["verification_status"] = "uncertain"
    item["verdict"] = "uncertain"
    item["confidence"] = round(float(finding.get("confidence", 0.0) or 0.0), 4)
    item["evidence"] = {
        "path_status": "unverified",
        "path": [],
        "conditions": [],
        "blockers": [],
        "used_tools": [],
    }
    item["verify_error"] = str(error)
    return item


def verify_findings(
    merged: List[Dict[str, Any]],
    state: Dict[str, Any],
    session_id: str,
    conn: Any,
    llm: Optional[Any],
    settings: Any,
    ctx: ContextManager,  # 【优化 O-7】注入上下文治理器
    errors: Optional[List[str]] = None,  # 【健壮性包 B-2】失败条目回流到 state["errors"]
) -> List[Dict[str, Any]]:
    """逐条验证并落 view；返回最终保留的 findings（含 verdict / evidence）。"""
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
        f = resolve_location(f, call_ctx, code)
        hypothesis = build_hypothesis(f, code)
        loc = f.get("location") or {}
        # 内部完整 context（含完整 code），仅供直接调用 verify_taint 兜底使用
        context = {
            "file": file_path,
            "line_range": [loc.get("line_start", 0), loc.get("line_end", 0)],
            "code": code,
        }

        # 信号 1：工具（代码事实，独立于 LLM）
        tool_sig = tool_signal(hypothesis, context)
        # 信号 2：LLM（语义，复用 bind_tools 多轮；无 LLM 时为 None）
        # 【健壮性包 B-2】VerifyError 只隔离当前 finding：标 uncertain + 记 errors，继续下一条
        try:
            tool_call, tool_result, context_reports, llm_sig = invoke_verify(
                hypothesis, context, llm, settings, ctx, session_id, finding_idx
            )
            if tool_result is None:
                raise VerifyError("工具调用无结果")
            tool_status = tool_result.get("status", "uncertain")
            if tool_status not in ("verified", "rejected", "uncertain"):
                raise VerifyError(f"工具返回非法状态: {tool_status!r}")
        except VerifyError as exc:
            log_event(
                "verify.degraded",
                level="warn",
                finding_id=f.get("id", ""),
                error=str(exc),
            )
            if errors is not None:
                errors.append(f"verify:{f.get('id', '')}: {exc}")
            verified.append(degraded_item(f, exc))
            continue

        verdict = combine(tool_sig, llm_sig, tau)
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
