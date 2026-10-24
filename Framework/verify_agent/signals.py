"""双信号：工具信号（代码事实） + LLM 信号（语义） → 合并裁决。

从 ``verify_agent/d.py`` 拆出（20 文档 §5.1-2）。设计依据：父设计 §3.2/§3.3。

两个信号的定位严格区分：

* ``tool_signal`` —— 纯本地逻辑（``verify_taint``），异常降级为 ``uncertain``，
  绝不影响主流程；单凭启发式 blocker（封顶 0.55）永远过不了默认 τ。
* ``llm_signal`` —— 语义判断，走工具循环；调用失败由上层转 ``VerifyError``。

``combine`` 是定稿判定表，正面对抗（一方 accept、另一方 reject）一律保留并
标记 ``conflict``，不静默丢。
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from agents import parse_json_object
from observability import log_event
from tools.verify_taint import VERDICT_TO_STATUS, verify_taint


def tool_signal(hypothesis: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """工具信号：直接调用 verify_taint，不调 LLM。

    刻意与「LLM 工具调用失败必须抛错」区分：工具信号是纯本地逻辑，
    异常时降级为 ``uncertain``（只影响合并，不影响主流程）。
    """
    try:
        result = verify_taint(hypothesis, context)
    except Exception as exc:  # 纯工具信号不拖垮整图
        log_event("verify.tool_signal_failed", level="warn", error=f"{type(exc).__name__}: {exc}")
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


def combine(
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


LLM_VERDICTS = ("accept", "reject", "challenge", "uncertain")


def parse_llm_verdict(text: str) -> Dict[str, Any]:
    """解析 LLM 最终文本里的对抗裁决 → ``{verdict, confidence, reason}``。

    解析失败一律降级为 ``uncertain``（不抛错、不拖垮主流程）：LLM 信号缺失
    只会让 ``combine`` 退回「采用工具证据」，不会造成误丢。
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
        log_event("verify.llm_signal_parse_failed", level="warn", error=str(exc))
        return fallback

    verdict = str(data.get("verdict") or "").strip().lower()
    if verdict not in LLM_VERDICTS:
        log_event("verify.llm_signal_bad_verdict", level="warn", verdict=verdict)
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
