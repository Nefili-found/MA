"""D 节点的共享常量：必需视角与最终报告模板。

拆出来的独立模块（dedupe / adjudicate / report_builder / d）都从这里取，
避免为了一个常量互相 import 形成环。
"""
from __future__ import annotations

from typing import Any, Dict

#: D 需要的上游视角；缺一即视为编排缺陷（FatalError）
REQUIRED_AGENTS = ("A", "B", "C")

#: 最终报告结构（output/final_report.json）。
# 核验证据已进最终报告（原先只进 view 表）：修复 Agent 需要知道“为什么判它成立/被推翻”，
# 而不只是一个 verification_status。逐跳可达性、假设条件与阻塞守卫都在 evidence 里。
FINAL_REPORT_TEMPLATE: Dict[str, Any] = {
    "file": "",
    "findings": [
        {
            "location": {"file": "", "line_start": 0, "line_end": 0, "function": ""},
            "taint_chain": [],
            "verification_status": "uncertain",
            # 对抗式判定：accept / reject / challenge / uncertain
            "verdict": "uncertain",
            "confidence": 0.0,
            "fix_suggestion": "",
            # 工具信号证据（父设计 §3.1）：path=逐跳可达性，conditions=假设条件核验，
            # blockers=使条件不成立的守卫/校验，used_tools=本次用到的上下文工具。
            "evidence": {
                "path_status": "",
                "path": [],
                "conditions": [],
                "blockers": [],
                "used_tools": [],
            },
        }
    ],
}
