"""长会话上下文压缩（compaction）：模型生成摘要检查点替换旧历史。

================================================================================
【优化点 O-4】移植 A 篇“压缩”机制，并适配 LangChain 消息 + 工具循环。
--------------------------------------------------------------------------------
优化来源（A 篇）：chapters/09-context-engineering/src/compaction.py
    * 压力 >= 80% 触发；保留最近 16% 原文（进行中的工作细节）；
    * 压缩请求重放“system + 被压缩区原文 + 固定摘要指令”，保持前缀一致以便 KV cache；
    * 用 <compacted-summary> 检查点【替换】旧历史（而不是追加）；
    * 缩小校验：摘要没有真正变短就拒绝，重试，仍失败则保留原文，绝不破坏会话。
B 篇特有的关键安全增强（A 篇没有工具调用配对问题，B 篇有）：
    * B 篇记录 2026-10-03_04 表明：ToolMessage 缺少匹配的 AIMessage(tool_calls)
      时，API 报 400 ``tool call missing output``。
    * 因此压缩边界绝不能切断 tool_call / ToolMessage 配对：
      ``_safe_tail_start`` 保证“保留区不得以孤立 ToolMessage 开头”，
      会把其对应的 AIMessage(tool_calls) 一起纳入保留区。
    * 被压缩区也因此自闭合（区内每个 tool_call 都有对应 ToolMessage），
      把它重放给模型做摘要不会触发配对错误。
================================================================================
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Optional

from .meter import TokenMeter, content_to_text, estimate_message, _message_role

# ---------------------------------------------------------------------------
# 压缩指令（沿用 A 篇官方 8 段结构，并结合 B 篇漏洞检测语境补充证据 / 假设字段）
# ---------------------------------------------------------------------------
COMPACTION_INSTRUCTION = """You are now acting as a compaction engine for this multi-agent vulnerability-detection assistant. Condense the conversation ABOVE into a structured checkpoint that lets the verification agent resume the work with no loss of essential context.

Output EXACTLY the Markdown structure below: keep every section, in order. Use terse bullets, not prose paragraphs. Write "(none)" for an empty section — never drop a section.

## Primary Request and Intent
- [the original goal: which C file / function is being analyzed, and the verification workflow]

## Key Technical Concepts
- [CWE types, taint analysis, AST/CFG/DFA, call graph, memory layout, tools in play]

## Vulnerability Hypotheses
- [each candidate finding: title, CWE, taint source -> sink, propagation path, location, agents that reported it]

## Tool Calls and Evidence
- [get_callers / get_callees / get_function_body / verify_taint observations and concrete evidence already obtained]

## Adjudication and Verification
- [dedupe groups, confidence per finding, conflict adjudication, verified/rejected/uncertain status]

## Files and Code
- [exact path: why it matters, key code snippets; if a full body was stored to a file, keep its locator]

## Errors and Fixes
- [error: how it was resolved, plus any related user feedback]

## Pending Jobs and Next Step
- [findings still awaiting verification; the single next action, or "(none)"]

## Critical Context
- [decisions and rationale, constraints, open questions, stored-file locators, data needed to continue]

Rules:
- Write concise English engineering prose. Preserve exact file paths, function names, CWE ids, line numbers, tool names, identifiers, numeric values, and stored-file locators.
- Do NOT drop any unverified hypothesis or any tool-derived evidence; compress wording, not facts.
- Do NOT mention this summarization request or that the context was compacted.
- Output only the checkpoint text: do not call any tool or take any other action.
- If the conversation already contains a <compacted-summary> block, it is a PRIOR checkpoint: preserve still-true facts, drop stale ones, and merge newer information into a single consolidated summary."""

CHECKPOINT_PREAMBLE = (
    "This is an automatically generated checkpoint condensing an earlier span of "
    "the conversation to free up context. Treat the captured context as established "
    "background and build on it without restating it. Continue the task directly from "
    "the messages that follow, without acknowledging this checkpoint."
)

SUMMARY_OPEN_TAG = "<compacted-summary>"
SUMMARY_CLOSE_TAG = "</compacted-summary>"


@dataclass(frozen=True)
class CompactResult:
    messages: list[Any]
    ok: bool
    shadowed_count: int
    shadowed_tokens: int
    checkpoint_tokens: int
    attempts: int
    reason: str
    tail_start: int = -1


def should_compact(
    meter: TokenMeter,
    messages: list[Any],
    tools: Optional[list[Any]] = None,
) -> bool:
    """压力是否达到阈值（官方 thresholdRatio 默认 0.8）。"""
    return meter.pressure(meter.measure(messages, tools)).over_threshold


def _require_system_head(messages: list[Any]) -> None:
    if not messages or _message_role(messages[0]) != "system":
        raise ValueError("压缩输入必须以 system 消息开头")


def _require_ratio(name: str, value: float) -> None:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
        or not 0 < value <= 1
    ):
        raise ValueError(f"{name} 必须位于 (0, 1] 区间")


def _tool_call_ids(ai_message: Any) -> set[str]:
    ids: set[str] = set()
    for tc in getattr(ai_message, "tool_calls", None) or []:
        if isinstance(tc, dict) and tc.get("id") is not None:
            ids.add(str(tc.get("id")))
        else:
            tid = getattr(tc, "id", None)
            if tid is not None:
                ids.add(str(tid))
    return ids


def _safe_tail_start(messages: list[Any], tail_start: int) -> int:
    """把保留区起点回退到安全位置，绝不切断 tool_call / ToolMessage 配对。

    若保留区第一条是 ToolMessage，则它依赖的 AIMessage(tool_calls) 必须也在
    保留区——否则该 ToolMessage 会变成孤立结果，触发 400。重复检查直到保留区
    第一条不是孤立 ToolMessage。
    """
    n = len(messages)
    while 1 <= tail_start < n:
        msg = messages[tail_start]
        if _message_role(msg) != "tool":
            break
        tcid = getattr(msg, "tool_call_id", None)
        owner: Optional[int] = None
        for i in range(tail_start - 1, 0, -1):
            candidate = messages[i]
            if _message_role(candidate) == "ai" and tcid in _tool_call_ids(candidate):
                owner = i
                break
        if owner is not None:
            tail_start = owner
        else:
            # 找不到归属时保守前移，避免遗留孤立 ToolMessage
            tail_start -= 1
    return tail_start


def select_shadowed_start(
    meter: TokenMeter, messages: list[Any], retain_ratio: float = 0.16
) -> int:
    """从尾部向前累积 token 达到保留预算（默认 16% context_window），
    之前的消息是被压缩区。返回保留区起点；-1 表示无可压缩区。"""
    _require_system_head(messages)
    _require_ratio("retain_ratio", retain_ratio)
    retain_tokens = int(meter.context_window * retain_ratio)
    accumulated = 0
    tail_start = len(messages)
    # 下标 0 是 system，不参与压缩
    for index in range(len(messages) - 1, 0, -1):
        accumulated += estimate_message(messages[index])
        tail_start = index
        if accumulated >= retain_tokens:
            break

    # 关键：边界不能切断 tool_call 配对
    tail_start = _safe_tail_start(messages, tail_start)
    return tail_start if tail_start > 1 else -1


def build_summary_prompt(messages: list[Any], tail_start: int) -> list[Any]:
    """构造压缩请求：system 原文 + 被压缩区逐字重放 + 末尾摘要指令。

    重放内容与正常请求保持相同前缀，为模型服务复用 KV cache 提供条件。
    """
    _require_system_head(messages)
    if not isinstance(tail_start, int) or isinstance(tail_start, bool) or not 1 < tail_start <= len(messages):
        raise ValueError("tail_start 必须位于可压缩消息区间内")
    from langchain_core.messages import HumanMessage

    return [
        messages[0],  # system：原样重放
        *messages[1:tail_start],  # 被压缩区（自闭合）逐字重放
        HumanMessage(content=COMPACTION_INSTRUCTION),
    ]


def build_checkpoint_message(summary: str) -> Any:
    """把摘要包装成 checkpoint 消息（role=user/human）：preamble + 标签。"""
    from langchain_core.messages import HumanMessage

    return HumanMessage(
        content=(
            f"{CHECKPOINT_PREAMBLE}\n\n"
            f"{SUMMARY_OPEN_TAG}\n{summary}\n{SUMMARY_CLOSE_TAG}"
        )
    )


def replace(messages: list[Any], tail_start: int, checkpoint: Any) -> list[Any]:
    """用 checkpoint 替换被压缩区 [1..tail_start)，缩短后续模型输入。"""
    _require_system_head(messages)
    if not isinstance(tail_start, int) or isinstance(tail_start, bool) or not 1 < tail_start <= len(messages):
        raise ValueError("tail_start 必须位于可压缩消息区间内")
    return [messages[0], checkpoint, *messages[tail_start:]]


def _message_text(response: Any) -> str:
    """从 LLM 响应中取纯文本摘要。"""
    content = getattr(response, "content", response)
    return content_to_text(content)


def compact(
    llm: Any,
    meter: TokenMeter,
    messages: list[Any],
    tools: Optional[list[Any]] = None,
    threshold_ratio: float = 0.8,
    retain_ratio: float = 0.16,
    retries: int = 1,
) -> CompactResult:
    """超过阈值时选择旧历史、生成摘要、校验缩小幅度并替换。

    ``llm`` 为 None（B 篇未配置 API Key 的降级模式）时无法做模型摘要，
    直接返回 ok=False，由调用方保留原文。
    """
    _require_system_head(messages)
    _require_ratio("threshold_ratio", threshold_ratio)
    _require_ratio("retain_ratio", retain_ratio)
    if retain_ratio >= threshold_ratio:
        raise ValueError("retain_ratio 必须小于 threshold_ratio")
    if not isinstance(retries, int) or isinstance(retries, bool) or retries < 0:
        raise ValueError("retries 必须是非负整数")

    if llm is None:
        return CompactResult(
            messages=messages, ok=False, shadowed_count=0, shadowed_tokens=0,
            checkpoint_tokens=0, attempts=0,
            reason="未配置 LLM，无法生成摘要，保留原文（降级模式）",
        )

    threshold_tokens = int(meter.context_window * threshold_ratio)
    current = list(messages)
    last_good: Optional[CompactResult] = None
    attempts = 0

    for attempt in range(retries + 1):
        if meter.measure(current, tools).total_tokens < threshold_tokens:
            break  # 压力已回安全区（可能是上一轮替换的效果）

        tail_start = select_shadowed_start(meter, current, retain_ratio)
        if tail_start < 0:
            break  # 无可压缩区

        shadowed = current[1:tail_start]
        shadowed_tokens = sum(estimate_message(m) for m in shadowed)

        prompt = build_summary_prompt(current, tail_start)
        try:
            response = llm.invoke(prompt)
        except Exception as exc:
            return CompactResult(
                messages=current, ok=False, shadowed_count=0, shadowed_tokens=0,
                checkpoint_tokens=0, attempts=attempts,
                reason=f"压缩调用失败，保留原文继续：{type(exc).__name__}: {exc}",
            )
        attempts += 1
        summary_text = _message_text(response)

        checkpoint = build_checkpoint_message(summary_text)
        checkpoint_tokens = estimate_message(checkpoint)

        # 缩小校验：checkpoint 不小于被压缩区 -> 拒绝本次摘要并重试
        if checkpoint_tokens >= shadowed_tokens:
            print(
                f"    ↳ 第 {attempt + 1} 次摘要未缩小"
                f"（{checkpoint_tokens} >= {shadowed_tokens} token），拒绝"
            )
            continue

        current = replace(current, tail_start, checkpoint)
        last_good = CompactResult(
            messages=current, ok=True,
            shadowed_count=len(shadowed), shadowed_tokens=shadowed_tokens,
            checkpoint_tokens=checkpoint_tokens, attempts=attempts,
            reason="", tail_start=tail_start,
        )
        if meter.measure(current, tools).total_tokens < threshold_tokens:
            return CompactResult(
                messages=current, ok=True,
                shadowed_count=last_good.shadowed_count,
                shadowed_tokens=last_good.shadowed_tokens,
                checkpoint_tokens=last_good.checkpoint_tokens,
                attempts=attempts, reason="压力降到阈值以下，压缩收敛",
                tail_start=tail_start,
            )

    if last_good is not None:
        return CompactResult(
            messages=last_good.messages, ok=True,
            shadowed_count=last_good.shadowed_count,
            shadowed_tokens=last_good.shadowed_tokens,
            checkpoint_tokens=last_good.checkpoint_tokens,
            attempts=attempts, reason="替换后仍超阈值，保留已替换结果继续",
            tail_start=last_good.tail_start,
        )
    return CompactResult(
        messages=current, ok=False, shadowed_count=0, shadowed_tokens=0,
        checkpoint_tokens=0, attempts=attempts,
        reason="摘要未缩小或无可压缩区，保留原文继续",
    )
