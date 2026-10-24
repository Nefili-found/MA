"""工具结果裁剪（prune）：缩短模型看到的大 ToolMessage，完整原文落盘可恢复。

================================================================================
【优化点 O-3】移植 A 篇“工具结果裁剪”机制，并适配 LangChain 消息列表。
--------------------------------------------------------------------------------
优化来源（A 篇）：chapters/09-context-engineering/src/pruner.py
B 篇原来的问题：
    * D 的多轮工具循环（``verify_agent/d.py::_tool_loop``）每轮都把
      ``get_function_body`` / ``get_callers`` / ``get_callees`` 的结果
      ``json.dumps`` 后作为 ToolMessage 追加进 messages；同一份大结果随后进入
      每一次 ``bound.invoke``，历史越长越接近窗口上限，且没有任何裁剪。
与 A 篇的差异 / 适配（重要）：
    * A 篇有事件溯源日志（Session），裁剪只改“模型可见表层”，完整原文天然留在
      append-only 日志里；B 篇直接持有 LangChain 消息列表，没有那层日志。
    * 因此本模块在裁掉一条大 ToolMessage 前，**先把完整原文通过 SpillStore
      落盘**，并在裁剪标记里写明文件位置（locator），保证“模型看到短版本、
      完整内容仍可按需读取”。
    * 裁剪后的 ToolMessage 用 ``model_copy`` 重建，**完整保留
      ``tool_call_id`` / ``name``**，绝不破坏 B 篇踩过坑的 tool_call 配对
      （缺配对会报 400，见 record_to_finish/2026-10-03_04.md）。
    * 默认只裁剪 role=tool 的工具结果（与 A 篇 ToolResultPruner 一致）；
      首轮的大输入（源码 / hypothesis）由 manager 的 spill 在写入前处理。
================================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

PRUNE_MARKER = "\n\n[... 上下文裁剪：中间 {omitted} 个字符已省略；{where} ...]\n\n"


@dataclass(frozen=True)
class PruneRecord:
    """一条裁剪记录（用于写日志 / 记忆库 view 表，便于审计与回放）。"""

    index: int
    role: str
    tool_call_id: Optional[str]
    original_chars: int
    pruned_chars: int
    locator: Optional[str]


@dataclass(frozen=True)
class PruneResult:
    messages: list[Any]
    replacements: int
    chars_removed: int
    records: tuple[PruneRecord, ...] = field(default_factory=tuple)


class ToolResultPruner:
    """对消息列表里的大工具结果做 head/middle/tail 裁剪。"""

    def __init__(
        self,
        threshold_chars: int = 8192,
        head_chars: int = 4096,
        tail_chars: int = 1024,
        prunable_roles: tuple[str, ...] = ("tool",),
    ) -> None:
        if (
            not isinstance(threshold_chars, int)
            or isinstance(threshold_chars, bool)
            or threshold_chars <= 0
        ):
            raise ValueError("threshold_chars 必须是正整数")
        if not isinstance(head_chars, int) or isinstance(head_chars, bool) or head_chars < 0:
            raise ValueError("head_chars 必须是非负整数")
        if not isinstance(tail_chars, int) or isinstance(tail_chars, bool) or tail_chars < 0:
            raise ValueError("tail_chars 必须是非负整数")
        if head_chars + len(PRUNE_MARKER) + tail_chars > threshold_chars:
            raise ValueError("head + marker + tail 不能超过 threshold")
        self.threshold_chars = threshold_chars
        self.head_chars = head_chars
        self.tail_chars = tail_chars
        self.prunable_roles = prunable_roles

    def prune_content(self, text: str, where: str = "完整内容见外存") -> Optional[str]:
        """按字符裁剪：head + 标记 + tail。Python str 按 Unicode code point 切片，
        不切坏中文，也不拆代理项对。

        接受条件只要求“确实缩短”：阈值用于决定是否触发裁剪，而不是强制裁剪后
        必须短于阈值（标记里若带较长文案，略超阈值也应接受，核心是大幅变短）。
        """
        if text is None or len(text) <= self.threshold_chars:
            return None
        tail = text[-self.tail_chars:] if self.tail_chars else ""
        omitted = len(text) - self.head_chars - self.tail_chars
        marker = PRUNE_MARKER.format(omitted=max(0, omitted), where=where)
        replacement = text[: self.head_chars] + marker + tail
        if len(replacement) >= len(text):
            # 没有真正变短则拒绝产出“更差”的替换
            return None
        return replacement

    def prune_messages(
        self,
        messages: list[Any],
        *,
        session_id: str = "session",
        spill_store: Any = None,
    ) -> PruneResult:
        """扫描消息列表，裁剪超长工具结果；完整原文落盘后重建短消息。"""
        new_messages: list[Any] = list(messages)
        records: list[PruneRecord] = []
        replacements = 0
        removed = 0

        for index, message in enumerate(new_messages):
            role = str(getattr(message, "type", "") or getattr(message, "role", ""))
            if role not in self.prunable_roles:
                continue
            content = getattr(message, "content", None)
            if not isinstance(content, str) or len(content) <= self.threshold_chars:
                continue

            # 1) 先把完整原文落盘，绝不在模型可见侧丢失
            locator: Optional[str] = None
            tool_name = str(getattr(message, "name", "") or f"{role}-result")
            call_id = str(getattr(message, "tool_call_id", "") or f"msg-{index}")
            if spill_store is not None:
                locator = self._spill_safely(
                    spill_store, session_id, tool_name, call_id, content
                )

            # 标记文案保持简短（不把长路径塞进 head/tail 之间，避免把替换文本撑大）
            where = "完整原文已保存到外存" if locator else "完整原文已从模型输入裁剪（未配置外存）"
            pruned = self.prune_content(content, where=where)
            if pruned is None:
                continue

            # 完整原文位置作为独立一行追加在末尾（不占 head/tail 预算）
            if locator:
                locator_line = (
                    f"\n[完整原文已保存：{locator}（可用 read 工具按 offset/limit 读取）]\n"
                )
                # 极端情况下 locator 过长导致追加后反而更长，则不追加（仍可从日志/审计找回）
                if len(pruned) + len(locator_line) < len(content):
                    pruned = pruned + locator_line

            # 2) 用短内容重建消息，保留 tool_call_id / name 等配对元数据
            new_messages[index] = _with_content(message, pruned)

            records.append(
                PruneRecord(
                    index=index,
                    role=role,
                    tool_call_id=getattr(message, "tool_call_id", None),
                    original_chars=len(content),
                    pruned_chars=len(pruned),
                    locator=locator,
                )
            )
            replacements += 1
            removed += len(content) - len(pruned)

        return PruneResult(
            messages=new_messages,
            replacements=replacements,
            chars_removed=removed,
            records=tuple(records),
        )

    @staticmethod
    def _spill_safely(store: Any, session_id: str, tool_name: str, call_id: str, content: str) -> Optional[str]:
        """调用 SpillStore.save_text 落盘，返回 locator；任何失败都返回 None。"""
        try:
            from .spill import SaveTextSpill

            ref = store.save_text(
                SaveTextSpill(
                    session_id=session_id,
                    tool_name=tool_name,
                    call_id=call_id,
                    label="pruned-tool-result",
                    suggested_name=f"{tool_name}.txt",
                    content=content,
                )
            )
            return getattr(ref, "locator", None)
        except Exception:
            return None


def _with_content(message: Any, new_content: str) -> Any:
    """更新消息 content，同时保留其余字段（pydantic v2 / v1 兼容）。"""
    if hasattr(message, "model_copy"):
        return message.model_copy(update={"content": new_content})
    if hasattr(message, "copy"):
        try:
            return message.copy(update={"content": new_content})
        except TypeError:
            pass
    # 最后兜底：直接构造（ToolMessage 等若缺必填字段会抛错，故前面优先 model_copy）
    return message.__class__(content=new_content)
