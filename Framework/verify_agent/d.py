"""汇总 / 验证 Agent D —— 编排入口。

职责（严格按顺序，每步一个模块）：

| 步骤 | 做什么 | 实现 |
| --- | --- | --- |
| 1 | 校验 A/B/C 三份报告齐全（缺一 = 编排缺陷 → ``FatalError``） | 本文件 |
| 2 | 原始报告写 ledger（审计用，不做处理） | ``memory.ledger`` |
| 3 | 语义去重 + 贡献合并 + 会话内相似历史 | :mod:`verify_agent.dedupe` |
| 4 | 冲突裁决 → ``final_confidence`` 与理由 | :mod:`verify_agent.adjudicate` |
| 5 | 逐条验证：定位校正 → 双信号 → 判定表 → 落 view | :mod:`verify_agent.verify_loop` |
| 6 | 精简最终报告并落盘 ``output/final_report.json`` | :mod:`verify_agent.report_builder` |
| 7 | 面向修复端的投影 ``output/repair_input.json``（``repair-input/1``） | :mod:`verify_agent.repair_projection` |

【20 文档 §5.1-2】改造前这一个文件 1300+ 行，同时承载报告校验、ledger 写入、
去重、仲裁、工具循环、view 写入、报告组装、修复端投影、六条校验。现在按职责
拆到下面的模块，本文件只保留编排；各模块的提示词在 :mod:`verify_agent.prompts`
（外置到 ``prompts/verify.yaml``，见 20 文档 §5.2-8）。

关键不变量（拆分后仍然成立）：

* **先校正 location 再构造 hypothesis** —— ``verify_taint.check_assumptions`` 是拿
  ``location.function`` 取函数体的，占位文本会让 ``conditions[].holds`` 全变 null；
* **单条验证失败只隔离该条**（``VerifyError``）—— 其余 finding 照常验证；
* **``errors`` 汇总回 ``state``** —— 静默降级不允许存在。
"""
from __future__ import annotations

from typing import Any, Dict, List

from agents import get_llm, load_settings
from config import resolve
from errors import FatalError
from memory import db as mem_db
from memory.ledger import write_report
from observability import log_event, track_time
from verify_agent.adjudicate import adjudicate as _adjudicate
from verify_agent.adjudicate import heuristic_adjudicate as _heuristic_adjudicate
from verify_agent.adjudicate import llm_adjudicate as _llm_adjudicate
from verify_agent.dedupe import collect_findings as _collect_findings
from verify_agent.dedupe import deduplicate as _deduplicate
from verify_agent.dedupe import group_indices as _group_indices
from verify_agent.dedupe import heuristic_group as _heuristic_group
from verify_agent.dedupe import llm_group as _llm_group
from verify_agent.dedupe import norm_title as _norm_title
from verify_agent.location import as_int as _as_int
from verify_agent.location import build_hypothesis as _build_hypothesis
from verify_agent.location import norm_assumptions as _norm_assumptions
from verify_agent.location import norm_path as _norm_path
from verify_agent.location import normalize_slice_location as _normalize_slice_location
from verify_agent.location import resolve_location as _resolve_location
from verify_agent.prompts import DEFAULTS as PROMPT_DEFAULTS
from verify_agent.prompts import load_verify_prompts
from verify_agent.repair_projection import REPAIR_SCHEMA, REPAIR_VERDICTS
from verify_agent.repair_projection import build_repair_input as _build_repair_input
from verify_agent.repair_projection import is_absolute_path as _is_absolute_path
from verify_agent.repair_projection import normalize_cwe as _normalize_cwe
from verify_agent.repair_projection import now_iso as _now_iso
from verify_agent.repair_projection import safe_id as _safe_id
from verify_agent.repair_projection import source_meta as _source_meta
from verify_agent.repair_projection import unique_case_id as _unique_case_id
from verify_agent.repair_projection import validate_repair_case as _validate_repair_case
from verify_agent.repair_projection import write_repair_input as _write_repair_input
from verify_agent.report_builder import build_final_report as _build_final_report
from verify_agent.report_builder import write_output as _write_output
from verify_agent.schema import FINAL_REPORT_TEMPLATE, REQUIRED_AGENTS
from verify_agent.signals import LLM_VERDICTS as _LLM_VERDICTS
from verify_agent.signals import combine as _combine
from verify_agent.signals import parse_llm_verdict as _parse_llm_verdict
from verify_agent.signals import tool_signal as _signal_tool
from verify_agent.tool_loop import available_tools as _available_tools
from verify_agent.tool_loop import build_model_payload as _build_model_payload
from verify_agent.tool_loop import dispatch_tool as _dispatch_tool
from verify_agent.tool_loop import invoke_verify as _invoke_verify
from verify_agent.tool_loop import tool_loop as _tool_loop
from verify_agent.verify_loop import build_context_manager  # noqa: F401
from verify_agent.verify_loop import degraded_item as _degraded_item
from verify_agent.verify_loop import set_active_context  # noqa: F401
from verify_agent.verify_loop import verify_findings as _verify_findings

__all__ = [
    "REQUIRED_AGENTS",
    "FINAL_REPORT_TEMPLATE",
    "REPAIR_SCHEMA",
    "REPAIR_VERDICTS",
    "PROMPT_DEFAULTS",
    "load_verify_prompts",
    "build_context_manager",
    "run",
]


# ---------------------------------------------------------------------------
# 节点入口
# ---------------------------------------------------------------------------
def run(state: Dict[str, Any]) -> Dict[str, Any]:
    settings = load_settings()
    reports: Dict[str, Any] = state.get("reports", {}) or {}

    # 1) 校验三份报告齐全
    missing = [a for a in REQUIRED_AGENTS if a not in reports]
    if missing:
        # 【健壮性包 B-2】A/B/C 均已降级，仍缺报告 = 编排缺陷，不可恢复
        raise FatalError(f"D 未接收到全部报告，缺失: {missing}。已停止。")

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

        # 3) 切片坐标归一：只有 --slice-start 给了才生效。
        #    必须在去重前做——去重/裁决/验证/投影每一步都要用同一套坐标。
        findings = _collect_findings(reports)
        slice_start = int(state.get("slice_start") or 0)
        if slice_start > 0:
            n_lines = len(str(code).splitlines())
            findings = [_normalize_slice_location(f, slice_start, n_lines) for f in findings]
        with track_time("dedupe"):
            merged = _deduplicate(findings, session_id, conn, llm)

        # 4) 冲突裁决 + 置信度
        with track_time("adjudicate"):
            merged = _adjudicate(merged, llm)

        # 5) 工具验证（内部接入上下文治理）
        #    【健壮性包 B-2】单条 finding 验证失败只隔离该条，不中断整轮
        verify_errors: List[str] = []
        with track_time("verify"):
            verified = _verify_findings(
                merged, state, session_id, conn, llm, settings, ctx, errors=verify_errors
            )

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
        verify_errors=len(verify_errors),
    )
    return {
        "merged_findings": merged,
        "verified_findings": verified,
        "final_report": final,
        "repair_input": repair_input,
        "errors": verify_errors,
    }
