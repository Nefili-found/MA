"""D 的冲突裁决：同一漏洞的多视角判断 → 最终置信度与理由。

从 ``verify_agent/d.py`` 拆出（20 文档 §5.1-2）。策略保持原样：
有 LLM 就走模型裁决（失败回落启发式），无 LLM 直接用启发式——
即“取最高置信度 + 冲突提示”，保守且可解释。
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from agents import parse_json_object, response_text
from observability import log_event
from verify_agent.prompts import load_verify_prompts


def adjudicate(merged: List[Dict[str, Any]], llm: Optional[Any]) -> List[Dict[str, Any]]:
    """对每条合并后的 finding 计算 ``final_confidence`` 与裁决理由（原地更新）。"""
    for f in merged:
        contributions = f.get("_contributions", [])
        if llm is not None:
            try:
                f.update(llm_adjudicate(f, contributions, llm))
                continue
            except Exception as exc:
                log_event("adjudicate.llm_failed", level="warn", error=str(exc))
        f.update(heuristic_adjudicate(contributions))
    return merged


def heuristic_adjudicate(contributions: List[Dict[str, Any]]) -> Dict[str, Any]:
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


def llm_adjudicate(
    finding: Dict[str, Any], contributions: List[Dict[str, Any]], llm: Any
) -> Dict[str, Any]:
    from langchain_core.messages import HumanMessage, SystemMessage

    payload = {
        "title": finding.get("title", ""),
        "cwe": finding.get("cwe", ""),
        "judgements": contributions,
    }
    prompt = load_verify_prompts().adjudicate
    resp = llm.invoke(
        [SystemMessage(content=prompt), HumanMessage(content=json.dumps(payload, ensure_ascii=False))]
    )
    data = parse_json_object(response_text(resp))
    fallback_conf = max([c.get("confidence", 0.0) for c in contributions] or [0.0])
    conf = float(data.get("final_confidence", fallback_conf) or fallback_conf)
    return {
        "final_confidence": round(conf, 4),
        "adjudication_reason": data.get("reason", ""),
        "has_conflict": None,
    }
