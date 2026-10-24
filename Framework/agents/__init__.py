"""A/B/C 扫描节点（LangGraph 节点实现）—— 只做编排，实现按关切点拆分。

【20 文档 §5.1-3】改造前本文件 370+ 行，把 LLM 构建、提示词加载、JSON 解析、
报告规范化、降级逻辑、上下文治理（O-8）六件事混在一起，职责边界模糊。
现在按下表拆分，本文件只留「扫描节点」这一件事：

| 关切点 | 模块 |
| --- | --- |
| LLM 客户端构造（提供商适配点） | :mod:`agents.llm_client` |
| 角色 Prompt 加载 + schema 提示 | :mod:`agents.prompts` |
| JSON 提取 / 报告规范化 / 降级骨架 | :mod:`agents.json_utils` |
| 扫描侧上下文治理器构造（O-8 / O-10） | :mod:`agents.context_manager` |
| 扫描节点（本文件） | ``run_scan_agent`` / ``_scan_with_llm`` |

下面的再导出块是为了不改动既有调用方（``agents.a/b/c``、``verify_agent.*``、
``tests/``）——它们历史上写的是 ``from agents import get_llm, parse_json_object``。
新代码请直接从具体模块导入。

降级语义（健壮性包 B-2）：未配置可用 LLM 时返回空报告骨架；``ScanError``
（LLM 调用失败 / 格式修复超限）同样降级为空报告并记入 ``state["errors"]``，
整条流水线仍然能跑到 D。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from config import Settings, load_settings, resolve  # noqa: F401  （resolve 供外部沿用）
from context import ContextManager, content_to_text  # noqa: F401  （content_to_text 历史导出）
from errors import ScanError
from observability import log_event, track_time

# --- 拆分后的实现模块 ---
from agents.context_manager import build_context_manager
from agents.json_utils import empty_report, normalize_report, parse_json_object, response_text
from agents.json_utils import iter_json_objects as _iter_json_objects
from agents.llm_client import get_llm
from agents.prompts import build_schema_hint, load_roles, role_prompt_for
from agents.prompts import report_array_key as _report_array_key

#: 历史名（拆分前是模块内的私有构造函数），保留供 tests / 旧调用方使用
_build_context_manager = build_context_manager

__all__ = [
    "get_llm",
    "load_roles",
    "role_prompt_for",
    "build_schema_hint",
    "parse_json_object",
    "normalize_report",
    "empty_report",
    "response_text",
    "build_context_manager",
    "run_scan_agent",
]


def run_scan_agent(
    agent: str,
    report_template: Dict[str, Any],
    finding_template: Dict[str, Any],
    state: Dict[str, Any],
) -> Dict[str, Any]:
    """A/B/C 共用的扫描节点：返回 ``{"reports": {agent: report}, "errors": [...]}``。

    报告结构由调用方（各 agent 文件）通过 report_template / finding_template 传入。

    【健壮性包 B-2】扫描失败不再崩图：``ScanError``（LLM 不可用 / 格式修复超限 /
    调用抛错）在此被捕获 → 降级为空报告骨架 + 记入 ``state["errors"]``，
    流水线照常进到 D。非 ``ScanError`` 的异常（编程缺陷）照旧冒泡。
    """
    settings = load_settings()
    file_path = state.get("file_path", "")
    code = state.get("code", "")
    session_id = state.get("session_id", "scan")
    array_key = _report_array_key(report_template)

    errors: List[str] = []
    with track_time(f"scan.{agent}"):
        llm = get_llm(settings)
        if llm is None:
            log_event(
                "scan.fallback",
                level="warn",
                agent=agent,
                note="LLM 未配置，返回空报告骨架",
            )
            report = empty_report(report_template, agent, file_path)
            errors.append(f"scan.{agent}: LLM 未配置，已降级为空报告")
        else:
            ctx = build_context_manager(settings)  # 【优化 O-8】
            try:
                report = _scan_with_llm(
                    agent, code, file_path, settings, llm, report_template,
                    finding_template, ctx, session_id,
                )
            except ScanError as exc:
                # 【健壮性包 B-2】可降级失败：空报告 + errors，图继续跑到 D
                log_event("scan.degraded", level="warn", agent=agent, error=str(exc))
                report = empty_report(report_template, agent, file_path)
                errors.append(f"scan.{agent}: {exc}")

    log_event("scan.done", agent=agent, findings=len(report.get(array_key, [])))
    return {"reports": {agent: report}, "errors": errors}


def _scan_with_llm(
    agent, code, file_path, settings, llm, report_template, finding_template,
    ctx: "ContextManager", session_id: str,
) -> Dict[str, Any]:
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

    system = role_prompt_for(agent, settings) + "\n\n" + build_schema_hint(
        report_template, finding_template
    )

    # 【优化 O-8】大源码外存（A 篇 spill）：完整源码落盘，模型只见首尾 + 位置。
    # 小文件（小于内联字节预算）原样返回，行为与优化前完全一致。
    code_view, code_locator = ctx.prepare_large_input(
        code or "",
        session_id=session_id,
        tool_name=f"scan-{agent}-source",
        call_id=f"{agent}-source",
    )
    code_block = f"待扫描文件: {file_path}\n\n```c\n{code_view}\n```"
    if code_locator:
        code_block += (
            "\n\n[注意] 该文件较大，完整源码已外存到："
            f"{code_locator}（可用 read 工具按 offset/limit 读取）。"
            "本次仅提供首尾片段，请据此识别风险，并在证据中注明未能覆盖的中段。"
        )
        log_event("scan.source_spilled", agent=agent, locator=code_locator)

    messages = [
        SystemMessage(content=system),
        HumanMessage(content=code_block),
    ]

    # 【优化 O-8】调用前计量与压力记录（首轮单请求，主要做可观测的预算检查）
    pressure = ctx.pressure(messages)
    log_event(
        "scan.pressure",
        agent=agent,
        tokens=pressure.total_tokens,
        ratio=f"{pressure.ratio:.3f}",
        over_threshold=pressure.over_threshold,
    )

    last_error: Optional[Exception] = None
    for attempt in range(1, settings.max_retries + 1):
        # 【优化 O-8】每次 invoke（含格式修复重试）前统一做预算治理
        messages, report = ctx.enforce_budget(
            messages, llm=llm, session_id=session_id, phase=f"scan.{agent}.attempt-{attempt}"
        )
        if report.acted:
            log_event(
                "scan.context_enforce",
                agent=agent,
                before=report.before_tokens,
                after=report.after_tokens,
                pruned=report.pruned_replacements,
                compact=report.compact_ok,
            )

        # 【健壮性包 B-2】LLM 调用失败（网络 / 鉴权 / 限流）也是可降级失败
        try:
            response = llm.invoke(messages)
        except Exception as exc:
            raise ScanError(f"LLM 调用失败: {type(exc).__name__}: {exc}") from exc
        text = response_text(response)
        try:
            raw = parse_json_object(text)
            return normalize_report(raw, agent, file_path, report_template, finding_template)
        except Exception as exc:  # 自动修复/重试
            last_error = exc
            log_event("scan.repair", level="warn", agent=agent, attempt=attempt, error=str(exc))
            messages.append(AIMessage(content=text))
            messages.append(
                HumanMessage(
                    content="上面的输出不是合法 JSON。请只输出符合 schema 的合法 JSON，不要任何多余内容。"
                )
            )
    raise ScanError(
        f"报告格式修复失败（已重试 {settings.max_retries} 次）: {last_error}"
    )
