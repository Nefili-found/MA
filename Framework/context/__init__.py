"""上下文治理包（基于 A 篇第 09 章上下文工程，移植到 B 篇 LangChain 技术栈）。

四件套 + 门面：
    * :class:`TokenMeter`          —— 计量（meter.py）
    * :class:`ToolResultPruner`    —— 工具结果裁剪（pruner.py）
    * :class:`SpillPolicy` / :class:`LocalSpillStore` —— 大结果外存（spill.py）
    * :func:`compact`              —— 摘要压缩（compaction.py）
    * :class:`ContextManager`      —— 统一治理门面（manager.py）

典型用法（见 verify_agent/d.py、agents/__init__.py）::

    from context import ContextManager
    ctx = ContextManager.from_settings(settings)

    # 每次请求前
    messages, report = ctx.enforce_budget(
        messages, llm=llm, tools=bound_tools, session_id=session_id, phase="d.verify"
    )
    resp = llm.invoke(messages)
"""

from __future__ import annotations

from .meter import (
    CHARS_PER_TOKEN,
    DEFAULT_CONTEXT_WINDOW,
    PRESSURE_THRESHOLD,
    Measurement,
    Pressure,
    TokenMeter,
    content_to_text,
    estimate_message,
    estimate_tokens,
    estimate_tools,
)
from .pruner import PruneRecord, PruneResult, ToolResultPruner
from .spill import LocalSpillStore, SaveTextSpill, SpillPolicy, SpillRef, SpillStore
from .compaction import (
    CHECKPOINT_PREAMBLE,
    COMPACTION_INSTRUCTION,
    CompactResult,
    build_checkpoint_message,
    build_summary_prompt,
    compact,
    replace,
    select_shadowed_start,
    should_compact,
)
from .manager import ContextManager, ContextReport

__all__ = [
    # meter
    "CHARS_PER_TOKEN",
    "DEFAULT_CONTEXT_WINDOW",
    "PRESSURE_THRESHOLD",
    "Measurement",
    "Pressure",
    "TokenMeter",
    "content_to_text",
    "estimate_message",
    "estimate_tokens",
    "estimate_tools",
    # pruner
    "PruneRecord",
    "PruneResult",
    "ToolResultPruner",
    # spill
    "LocalSpillStore",
    "SaveTextSpill",
    "SpillPolicy",
    "SpillRef",
    "SpillStore",
    # compaction
    "CHECKPOINT_PREAMBLE",
    "COMPACTION_INSTRUCTION",
    "CompactResult",
    "build_checkpoint_message",
    "build_summary_prompt",
    "compact",
    "replace",
    "select_shadowed_start",
    "should_compact",
    # manager
    "ContextManager",
    "ContextReport",
]
