"""扫描 Agent A（视角：Static Analyze）。

报告结构（REPORT_TEMPLATE / FINDING_TEMPLATE）直接复制自框架原有结构，字段保持不变。
角色 Prompt 见 prompts/roles.yaml 的 ``A.role_prompt``。
TODO: 报告字段待自改。
"""
from __future__ import annotations

from typing import Any, Dict

from agents import run_scan_agent

AGENT_NAME = "A"

# ---- 本视角的报告结构（照搬代码原有字段，勿在此处改内容）----
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
    "propagation_path": [],
    "evidence": "",
    "suggestion": "",
}


def run(state: Dict[str, Any]) -> Dict[str, Any]:
    return run_scan_agent(AGENT_NAME, REPORT_TEMPLATE, FINDING_TEMPLATE, state)
