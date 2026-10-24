"""过大结果的外存（spill）：完整正文落盘，模型只接收首尾预览 + 读取位置。

================================================================================
【优化点 O-2】移植 A 篇“外存（spill）”机制。
--------------------------------------------------------------------------------
优化来源（A 篇）：chapters/09-context-engineering/src/spill.py
B 篇原来的问题：
    * A/B/C 扫描把整份 C 源码、D 工具验证把 ``context``（含完整 code）原样塞进
      每一次请求；``get_function_body`` 返回的整个函数体也会被 json 化后作为
      ToolMessage 累积。大结果既没有落盘，也没有读取提示，一旦超限只能被模型
      服务拒绝。
本模块做什么：
    * 结果超过 ``max_inline_bytes`` 后，先把完整正文写入会话私有目录（
      ``LocalSpillStore``），再返回“首尾预览 + 省略字节数 + 文件位置 + 读取提示”。
    * 按 UTF-8 **字节**而非字符判断（文件存储 / 网络传输按字节限制），
      首尾预览按字符边界切分，绝不切坏中文等多字节字符。
    * 无存储后端 / 保存失败 / 工具本身就是 read / 嵌套调用时，一律保留原文，
      绝不把一次成功调用改成失败（与 A 篇一致）。
================================================================================
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import uuid4


@dataclass(frozen=True)
class SaveTextSpill:
    session_id: str
    tool_name: str
    call_id: str
    label: str
    suggested_name: str
    content: str


@dataclass(frozen=True)
class SpillRef:
    """外存引用：文件位置、字节数、读取提示。"""

    locator: str
    bytes: int
    retrieval_hint: str


class SpillStore(Protocol):
    def save_text(self, request: SaveTextSpill) -> SpillRef: ...


class LocalSpillStore:
    """把内容放到 session 私有目录；``suggested_name`` 只作为文件名提示。"""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()

    def save_text(self, request: SaveTextSpill) -> SpillRef:
        owner = _safe_segment(request.session_id, "session")
        stem = _safe_segment(Path(request.suggested_name).stem, "spill")
        suffix = Path(request.suggested_name).suffix
        if not re.fullmatch(r"\.[a-zA-Z0-9]{1,10}", suffix):
            suffix = ".txt"
        directory = self.root / owner
        directory.mkdir(parents=True, exist_ok=True)
        try:
            directory.chmod(0o700)
        except OSError:
            pass
        # uuid 避免同名覆盖（多次工具调用可能都叫 get_function_body.txt）
        target = directory / f"{stem}-{uuid4().hex}{suffix}"
        target.write_text(request.content, encoding="utf-8")
        try:
            target.chmod(0o600)
        except OSError:
            pass
        return SpillRef(
            locator=str(target),
            bytes=len(request.content.encode("utf-8")),
            retrieval_hint="Use the read tool with offset and limit to inspect this file.",
        )


class SpillPolicy:
    """判断一个文本结果是否需要外存，并生成预算内的替换文本。"""

    def __init__(
        self,
        max_inline_bytes: int | None,
        store: SpillStore | None,
    ) -> None:
        if max_inline_bytes is not None and (
            not isinstance(max_inline_bytes, int)
            or isinstance(max_inline_bytes, bool)
            or max_inline_bytes < 0
        ):
            raise ValueError("max_inline_bytes 必须是非负整数或 None")
        self.max_inline_bytes = max_inline_bytes
        self.store = store

    def transform(
        self,
        text: str,
        *,
        session_id: str,
        tool_name: str,
        call_id: str,
        nested: bool = False,
    ) -> str:
        """尝试外存；保存失败 / read 工具 / 嵌套调用 / 无后端时保留原文。"""
        replacement, _ref = self.transform_with_ref(
            text,
            session_id=session_id,
            tool_name=tool_name,
            call_id=call_id,
            nested=nested,
        )
        return replacement

    def transform_with_ref(
        self,
        text: str,
        *,
        session_id: str,
        tool_name: str,
        call_id: str,
        nested: bool = False,
    ) -> tuple[str, "SpillRef | None"]:
        """与 :meth:`transform` 相同，额外返回外存引用（未外存时为 None）。

        直接返回结构化 SpillRef，避免调用方靠字符串解析文件路径
        （路径里可能含 '.'，如 .txt，字符串切割会截断）。
        """
        cap = self.max_inline_bytes
        total = len(text.encode("utf-8"))
        if (
            cap is None
            or total <= cap
            or nested
            or tool_name == "read"
            or self.store is None
        ):
            return text, None
        try:
            ref = self.store.save_text(
                SaveTextSpill(
                    session_id=session_id,
                    tool_name=tool_name,
                    call_id=call_id,
                    label="result",
                    suggested_name=f"{tool_name}.txt",
                    content=text,
                )
            )
        except Exception:
            # 外存失败绝不能把成功调用变成失败
            return text, None

        # 先按“最坏情况下提示文本最长”预留预算，再生成首尾预览
        worst_notice = _notice(total, ref)
        preview_budget = max(0, cap - len(("\n\n" + worst_notice).encode("utf-8")))
        preview = _head_tail_utf8(text, preview_budget)
        omitted = total - len(preview.encode("utf-8"))
        notice = _notice(omitted, ref)
        replacement = f"{preview}\n\n{notice}" if preview else notice
        # 预览 + 提示仍超预算 -> 返回原文，不能给出残缺且无法恢复的结果
        if len(replacement.encode("utf-8")) > cap:
            return text, None
        return replacement, ref


def _notice(omitted: int, ref: SpillRef) -> str:
    return (
        f"(Omitted {omitted} bytes. Full formatted result stored at: "
        f"{ref.locator}. {ref.retrieval_hint})"
    )


def _head_tail_utf8(text: str, budget: int) -> str:
    """在 UTF-8 字节预算内取首尾两段（各占约一半预算）。"""
    head_budget = (budget + 1) // 2
    tail_budget = budget // 2
    head = _take_utf8_prefix(text, head_budget)
    remaining = text[len(head):]
    tail = _take_utf8_suffix(remaining, tail_budget)
    return head + tail


def _take_utf8_prefix(text: str, budget: int) -> str:
    used = 0
    kept: list[str] = []
    for character in text:
        size = len(character.encode("utf-8"))
        if used + size > budget:
            break
        kept.append(character)
        used += size
    return "".join(kept)


def _take_utf8_suffix(text: str, budget: int) -> str:
    used = 0
    kept: list[str] = []
    for character in reversed(text):
        size = len(character.encode("utf-8"))
        if used + size > budget:
            break
        kept.append(character)
        used += size
    return "".join(reversed(kept))


def _safe_segment(value: str, fallback: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip(".-")
    return safe[:80] or fallback
