"""D 的 LLM 工具循环：模型自主多轮调用上下文工具 + verify_taint。

从 ``verify_agent/d.py`` 拆出（20 文档 §5.1-2）；治理逻辑沿用优化点 O-7。

契约（B 篇历史教训）：**每个 tool_call 都必须追加一条匹配 tool_call_id 的
ToolMessage**，否则下一次 invoke 会因缺少匹配输出而报 400
（见 record_to_finish 2026-10-03_04）。压缩逻辑也已保证不切断该配对。

治理顺序（A 篇）：
  1. 首轮大源码 spill，只发一次；
  2. 每条工具结果在写入 ToolMessage 前 spill（大函数体落盘）；
  3. 每轮 invoke 前 enforce_budget（计量 → 裁剪历史 → 压缩）。
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from agents import response_text
from context import ContextManager
from errors import VerifyError
from observability import log_event
from tools.call_context import CONTEXT_TOOLS, get_callees, get_callers, get_function_body
from tools.verify_taint import verify_taint, verify_taint_tool
from verify_agent.prompts import load_verify_prompts
from verify_agent.signals import parse_llm_verdict


def build_model_payload(
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


def available_tools() -> List[Any]:
    """可绑定的工具集合：verify_taint + 上下文工具（缺失的自动跳过）。"""
    tools: List[Any] = []
    if verify_taint_tool is not None:
        tools.append(verify_taint_tool)
    tools.extend(t for t in CONTEXT_TOOLS if t is not None)
    return tools


def dispatch_tool(
    name: Optional[str],
    args: Dict[str, Any],
    hypothesis: Dict[str, Any],
    context: Dict[str, Any],
) -> Any:
    """按工具名分发，返回 ``(result, call_record)``。

    * verify_taint：失败直接抛出（由上层包成 ``VerifyError``，只隔离该 finding）；
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


def invoke_verify(
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

    工具异常一律转为 ``VerifyError``（只隔离当前 finding，不中断整轮）。
    返回 (tool_call, tool_result, context_reports, llm_sig)：

    * ``llm_sig`` 为 LLM 侧裁决 ``{verdict, confidence, reason}``（父设计 §3.2 的
      ``_signal_llm``）；走纯工具兜底路径时为 ``None``，表示「无 LLM 信号」——
      与「LLM 表态 uncertain」严格区分。
    """
    if llm is not None and available_tools():
        try:
            call, result, reports, llm_sig = tool_loop(
                llm, hypothesis, context, settings, ctx, session_id, finding_idx
            )
            return call, result, reports, llm_sig
        except VerifyError:
            raise
        except Exception as exc:
            raise VerifyError(f"工具调用失败: {exc}") from exc

    # 兜底：直接调用（无 LLM / 无工具）。这里使用完整 context，不受外存影响。
    try:
        result = verify_taint(hypothesis, context)
    except Exception as exc:
        raise VerifyError(f"工具调用失败: {exc}") from exc
    tool_call = {"tool": "verify_taint", "args": {"hypothesis": hypothesis, "context": context}}
    return tool_call, result, [], None


def tool_loop(
    llm: Any,
    hypothesis: Dict[str, Any],
    context: Dict[str, Any],
    settings: Any,
    ctx: ContextManager,
    session_id: str,
    finding_idx: int,
):
    """模型自主多轮工具循环（MAVUL 式），接入 A 篇上下文治理。

    每个 ``tool_call`` 都必须补齐匹配的 ``ToolMessage``（见模块 docstring 的 400 教训）。
    """
    from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

    tools = available_tools()
    bound = llm.bind_tools(tools)

    # 【优化 O-7】首轮 payload：大源码外存 + code 去重
    payload_text, input_actions = build_model_payload(
        hypothesis, context, ctx, session_id, finding_idx
    )
    messages = [
        SystemMessage(content=load_verify_prompts().tool),
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
            tools=tools,
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
            result, call_record = dispatch_tool(name, args, hypothesis, context)
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
        last_result, last_call = dispatch_tool(
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
    return summary, last_result, context_reports, parse_llm_verdict(llm_final_text)
