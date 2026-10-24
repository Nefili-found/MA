"""扫描 Agent C（视角：Memory Layout）。

报告结构见 REPORT_TEMPLATE / FINDING_TEMPLATE；角色 Prompt 见 prompts/roles.yaml 的
``C.role_prompt``。

assumptions（触发前提）是本视角的重点：C 描述「以什么长度/索引写入哪个对象」，
因此 kind 优先 bounds_check。
"""
from __future__ import annotations

from typing import Any, Dict

from agents import run_scan_agent

AGENT_NAME = "C"

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
    # 触发路径：按 source→sink 顺序写**本文件内的函数名**（如 ["main","handle","memcpy"]）。
    "propagation_path": [],
    # 触发前提（假设条件）：使该漏洞成立所必需的前置条件，逐条可核验。
    # C 视角偏“长度/容量/索引校验缺失” → kind 优先 bounds_check；
    # text 要写明「哪个缓冲区、以什么长度写入」。
    "assumptions": [
        {"id": "cond-1", "kind": "bounds_check", "text": ""},
    ],
    "evidence": "",
    "suggestion": "",
}


def run(state: Dict[str, Any]) -> Dict[str, Any]:
    return run_scan_agent(AGENT_NAME, REPORT_TEMPLATE, FINDING_TEMPLATE, state)
