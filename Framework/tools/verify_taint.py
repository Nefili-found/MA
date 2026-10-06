"""污点假设验证工具接口。

默认实现返回 ``uncertain``（原因："具体验证工具未配置"）。
TODO: 请在此处接入你真实的污点验证工具
      （静态分析器 / 符号执行 / 数据流引擎 / 自定义规则等）。
      保持 ``verify_taint`` 的入参和返回结构不变，便于被 D 直接调用。
"""
from __future__ import annotations

from typing import Any, Dict

TOOL_NAME = "verify_taint"


def verify_taint(hypothesis: dict, context: dict) -> dict:
    """验证一个污点假设。

    :param hypothesis: 来自 D 的待验证污点假设，例如::

        {
          "finding_id": "A-1",
          "cwe": "CWE-120",
          "taint_source": "argv[1]",
          "taint_sink": "strncpy",
          "propagation_path": ["argv[1]", "src", "dst"],
          "location": {...},
          "code": "..."          # 可选：相关代码片段
        }

    :param context: 验证所需的上下文，例如::

        {"file": "examples/input/sample.c", "line_range": [10, 14], "code": "..."}

    :return: 统一结构::

        {
          "status": "verified|rejected|uncertain",
          "confidence": 0.0,
          "reason": "",
          "tool_name": "",
          "raw_output": {}
        }
    """
    # -------- 默认占位实现：交由后续补充真实工具 --------
    # TODO: 在这里调用真实的污点验证工具，并根据其结果填充 status / confidence / reason。
    return {
        "status": "uncertain",
        "confidence": 0.0,
        "reason": "具体验证工具未配置",
        "tool_name": TOOL_NAME,
        "raw_output": {},
    }


# ---------------------------------------------------------------------------
# LangChain 工具包装（供 D 使用 llm.bind_tools([...]) 绑定）。
# 若未安装 langchain-core，则降级为 None，D 会退化为直接调用 verify_taint。
# ---------------------------------------------------------------------------
try:  # pragma: no cover - 依赖存在时才会执行
    from langchain_core.tools import tool as _lc_tool  # type: ignore

    @_lc_tool("verify_taint")
    def verify_taint_tool(hypothesis: dict, context: dict) -> dict:
        """验证污点假设，返回 verify_taint 的字典结果。"""
        return verify_taint(hypothesis, context)

except Exception:  # pragma: no cover
    verify_taint_tool = None  # type: ignore
