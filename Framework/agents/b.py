"""扫描 Agent B（视角：Behavior Analyze）。

报告结构见 REPORT_TEMPLATE / FINDING_TEMPLATE；角色 Prompt 见 prompts/roles.yaml 的
``B.role_prompt``。

assumptions（触发前提）是本视角的重点：B 描述「什么样的输入会进入异常分支」，
因此 kind 优先 null_check 或 other（分支可达性条件）。
"""
from __future__ import annotations

from typing import Any, Dict

from agents import run_scan_agent

AGENT_NAME = "B"

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
    # B 视角强调 path reachability：这里的每一跳都应当真的可达。
    "propagation_path": [],
    # 触发前提（假设条件）：使该漏洞成立所必需的前置条件，逐条可核验。
    # B 视角偏“进入异常分支所需的条件” → kind 优先 null_check 或 other。
    # kind 只能取 null_check / bounds_check / sanitizer / other。
    "assumptions": [
        {"id": "cond-1", "kind": "null_check", "text": ""},
    ],
    "evidence": "",
    "suggestion": "",
}


def run(state: Dict[str, Any]) -> Dict[str, Any]:
    return run_scan_agent(AGENT_NAME, REPORT_TEMPLATE, FINDING_TEMPLATE, state)
