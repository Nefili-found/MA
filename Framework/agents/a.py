"""扫描 Agent A（视角：Static Analyze）。

报告结构见 REPORT_TEMPLATE / FINDING_TEMPLATE；角色 Prompt 见 prompts/roles.yaml 的
``A.role_prompt``。

assumptions（触发前提）是本视角的重点：A 偏「外部输入未经校验 / 净化」，
因此 kind 优先 sanitizer；无前置条件时保持空数组，不要编造。
"""
from __future__ import annotations

from typing import Any, Dict

from agents import run_scan_agent

AGENT_NAME = "A"

# ---- 本视角的报告结构 ----
REPORT_TEMPLATE: Dict[str, Any] = {
    "agent": "",
    "file": "",
    "findings": [],
}

FINDING_TEMPLATE: Dict[str, Any] = {
    "id": "",
    "title": "",
    "location": {"file": "", "line_start": 0, "line_end": 0, "function": ""},
    "cwe": "",
    "severity": "",
    "confidence": 0.0,
    "taint_source": "",
    "taint_sink": "",
    # 触发路径：按 source→sink 顺序写**本文件内的函数名**（如 ["main","handle","strcpy"]）。
    # 写成表达式/变量时下游只会判为“无法核”，不会误判为断链。
    "propagation_path": [],
    # 触发前提（假设条件）：使该漏洞成立所必需的前置条件，逐条可核验。
    # A 视角偏“外部输入未经校验/净化” → kind 优先 sanitizer。
    # kind 只能取 null_check / bounds_check / sanitizer / other（verify_taint 按 kind 选匹配规则）。
    # 无前置条件时保持空数组，不要编造。
    "assumptions": [
        {"id": "cond-1", "kind": "sanitizer", "text": ""},
    ],
    "evidence": "",
    "suggestion": "",
}


def run(state: Dict[str, Any]) -> Dict[str, Any]:
    return run_scan_agent(AGENT_NAME, REPORT_TEMPLATE, FINDING_TEMPLATE, state)
