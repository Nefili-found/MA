"""上下文治理门面（ContextManager）：把 A 篇四件套串成一条统一调用链。

================================================================================
【优化点 O-5】新增统一入口，让 B 篇各 Agent / D 工具循环用一行代码完成
“计量 → 裁剪（含外存）→ 压缩”的上下文预算治理。
--------------------------------------------------------------------------------
调用时机（对应 A 篇“每次请求前先估算”）：
    * 新产生的大结果（源码 / 函数体 / 假设）在【写入消息前】调用
      ``spill_text`` / ``prepare_large_input``（A 篇的 spill 时机）；
    * 每次 ``llm.invoke`` / ``bound.invoke`` 前调用 ``enforce_budget``，
      内部依次：计量 → 裁剪历史大工具结果（完整原文落盘）→ 仍超阈值再压缩。

设计要点：
    * 组件本身无请求级可变状态（spill 落盘用 uuid 命名），A/B/C 并行节点
      可安全共享同一个 ContextManager。
    * 不依赖 config 包（避免循环导入）：由调用方显式传入窗口 / 阈值 / 目录，
      或用 ``from_settings`` 从一个简单配置对象读取。
    * 治理动作全部记录到 ``ContextReport``，可写入日志 / 记忆库 view 表审计。
================================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .meter import TokenMeter, PRESSURE_THRESHOLD
from .pruner import ToolResultPruner
from .spill import LocalSpillStore, SpillPolicy
from .compaction import compact


@dataclass
class ContextReport:
    """一次上下文治理的动作报告（可 json 化，便于落 view 表 / 日志）。"""

    phase: str = ""
    context_window: int = 0
    threshold_tokens: int = 0
    tools_tokens: int = 0
    before_tokens: int = 0
    after_tokens: int = 0
    before_ratio: float = 0.0
    after_ratio: float = 0.0
    pruned_replacements: int = 0
    pruned_chars_removed: int = 0
    spill_locators: list[str] = field(default_factory=list)
    compact_ok: bool = False
    compact_attempts: int = 0
    compact_reason: str = ""
    shadowed_count: int = 0
    shadowed_tokens: int = 0
    checkpoint_tokens: int = 0
    actions: list[str] = field(default_factory=list)

    @property
    def acted(self) -> bool:
        return bool(self.pruned_replacements or self.compact_ok or self.spill_locators)

    def to_dict(self) -> dict:
        return {
            "phase": self.phase,
            "context_window": self.context_window,
            "threshold_tokens": self.threshold_tokens,
            "tools_tokens": self.tools_tokens,
            "before_tokens": self.before_tokens,
            "after_tokens": self.after_tokens,
            "before_ratio": round(self.before_ratio, 4),
            "after_ratio": round(self.after_ratio, 4),
            "pruned_replacements": self.pruned_replacements,
            "pruned_chars_removed": self.pruned_chars_removed,
            "spill_locators": list(self.spill_locators),
            "compact_ok": self.compact_ok,
            "compact_attempts": self.compact_attempts,
            "compact_reason": self.compact_reason,
            "shadowed_count": self.shadowed_count,
            "shadowed_tokens": self.shadowed_tokens,
            "checkpoint_tokens": self.checkpoint_tokens,
            "actions": list(self.actions),
        }


class ContextManager:
    """统一的上下文治理门面。"""

    def __init__(
        self,
        context_window: int = 128_000,
        threshold_ratio: float = PRESSURE_THRESHOLD,
        retain_ratio: float = 0.16,
        *,
        spill_root: str = "output/spill",
        max_inline_bytes: Optional[int] = 4096,
        prune_threshold_chars: int = 8192,
        prune_head_chars: int = 4096,
        prune_tail_chars: int = 1024,
        enable_spill: bool = True,
        enable_compaction: bool = True,
    ) -> None:
        self.context_window = context_window
        self.threshold_ratio = threshold_ratio
        self.retain_ratio = retain_ratio
        self.enable_compaction = enable_compaction

        self.meter = TokenMeter(context_window, threshold_ratio)
        self.store = LocalSpillStore(spill_root) if enable_spill else None
        self.spill_policy = SpillPolicy(
            max_inline_bytes if enable_spill else None,
            self.store,
        )
        self.pruner = ToolResultPruner(
            threshold_chars=prune_threshold_chars,
            head_chars=prune_head_chars,
            tail_chars=prune_tail_chars,
        )

    # ------------------------------------------------------------------
    # 构造助手
    # ------------------------------------------------------------------
    @classmethod
    def from_settings(cls, settings: Any) -> "ContextManager":
        """从 B 篇 config.Settings（仅需读取若干 context_* 属性）构造。

        缺省属性时使用内置默认值，保证旧配置文件也能运行。
        """
        def g(name: str, default: Any) -> Any:
            return getattr(settings, name, default)

        root = g("spill_root", "output/spill")
        return cls(
            context_window=int(g("context_window", 128_000)),
            threshold_ratio=float(g("context_threshold_ratio", 0.8)),
            retain_ratio=float(g("context_retain_ratio", 0.16)),
            spill_root=str(root),
            max_inline_bytes=int(g("spill_max_inline_bytes", 4096)),
            prune_threshold_chars=int(g("prune_threshold_chars", 8192)),
            prune_head_chars=int(g("prune_head_chars", 4096)),
            prune_tail_chars=int(g("prune_tail_chars", 1024)),
            enable_spill=bool(g("context_enable_spill", True)),
            enable_compaction=bool(g("context_enable_compaction", True)),
        )

    # ------------------------------------------------------------------
    # 计量（只读，供调用方在任何时候查看压力）
    # ------------------------------------------------------------------
    def measure(self, messages: list[Any], tools: Optional[list[Any]] = None):
        return self.meter.measure(messages, tools)

    def pressure(self, messages: list[Any], tools: Optional[list[Any]] = None):
        return self.meter.pressure(self.meter.measure(messages, tools))

    # ------------------------------------------------------------------
    # 外存（spill）：新产生的大结果 / 大输入在写入消息前调用
    # ------------------------------------------------------------------
    def spill_text(
        self,
        text: str,
        *,
        session_id: str,
        tool_name: str,
        call_id: str,
    ) -> str:
        """超过内联预算的完整文本落盘，返回首尾预览 + 读取提示；否则原样返回。"""
        if not isinstance(text, str):
            return text
        return self.spill_policy.transform(
            text,
            session_id=session_id,
            tool_name=tool_name,
            call_id=call_id,
        )

    def prepare_large_input(
        self,
        text: str,
        *,
        session_id: str,
        tool_name: str,
        call_id: str,
    ) -> tuple[str, Optional[str]]:
        """与 spill_text 相同，额外返回外存文件 locator（未外存时为 None）。"""
        if not isinstance(text, str) or not text:
            return text, None
        replaced, ref = self.spill_policy.transform_with_ref(
            text, session_id=session_id, tool_name=tool_name, call_id=call_id
        )
        if ref is None:
            return text, None
        return replaced, ref.locator

    # ------------------------------------------------------------------
    # 统一预算治理：每次模型请求前调用
    # ------------------------------------------------------------------
    def enforce_budget(
        self,
        messages: list[Any],
        *,
        llm: Any = None,
        tools: Optional[list[Any]] = None,
        session_id: str = "session",
        phase: str = "invoke",
        allow_compaction: Optional[bool] = None,
    ) -> tuple[list[Any], ContextReport]:
        """计量 → 裁剪（含外存）→ 压缩，返回处理后的消息与动作报告。

        不满足阈值时原样返回（report.actions 为空），零副作用。
        """
        allow_compaction = self.enable_compaction if allow_compaction is None else allow_compaction

        before = self.meter.measure(messages, tools)
        before_pressure = self.meter.pressure(before)
        report = ContextReport(
            phase=phase,
            context_window=self.meter.context_window,
            threshold_tokens=before_pressure.threshold_tokens,
            tools_tokens=before.tools_tokens,
            before_tokens=before.total_tokens,
            before_ratio=before_pressure.ratio,
        )

        current = list(messages)

        if not before_pressure.over_threshold:
            # 未达阈值：不裁剪、不压缩，只回填 after
            report.after_tokens = before.total_tokens
            report.after_ratio = before_pressure.ratio
            return current, report

        report.actions.append(
            f"压力 {before_pressure.ratio:.1%} >= 阈值，开始上下文治理（{phase}）"
        )

        # 1) 裁剪历史中的大工具结果（完整原文落盘，不调用模型）
        if self.pruner is not None and self.store is not None:
            pr = self.pruner.prune_messages(
                current, session_id=session_id, spill_store=self.store
            )
            if pr.replacements:
                current = pr.messages
                report.pruned_replacements += pr.replacements
                report.pruned_chars_removed += pr.chars_removed
                locs = [r.locator for r in pr.records if r.locator]
                report.spill_locators.extend(locs)
                report.actions.append(
                    f"裁剪 {pr.replacements} 条大工具结果，"
                    f"移除约 {pr.chars_removed} 字符，完整原文落盘 {len(locs)} 份"
                )

        mid = self.meter.measure(current, tools)
        mid_pressure = self.meter.pressure(mid)

        # 2) 裁剪后仍超阈值 -> 压缩（需要 LLM；降级模式无 LLM 则跳过）
        if allow_compaction and mid_pressure.over_threshold:
            if llm is None:
                report.actions.append(
                    "裁剪后仍超阈值，但未配置 LLM，无法压缩（降级模式），保留现状"
                )
            else:
                result = compact(
                    llm,
                    self.meter,
                    current,
                    tools=None,  # 压缩只压缩消息；tools schema 固定，不随压缩变化
                    threshold_ratio=self.threshold_ratio,
                    retain_ratio=self.retain_ratio,
                )
                report.compact_ok = result.ok
                report.compact_attempts = result.attempts
                report.compact_reason = result.reason
                report.shadowed_count = result.shadowed_count
                report.shadowed_tokens = result.shadowed_tokens
                report.checkpoint_tokens = result.checkpoint_tokens
                if result.ok:
                    current = result.messages
                    report.actions.append(
                        f"压缩 {result.shadowed_count} 条旧消息"
                        f"（{result.shadowed_tokens}→{result.checkpoint_tokens} token）：{result.reason or '完成'}"
                    )
                else:
                    report.actions.append(f"压缩未生效，保留原文：{result.reason}")

        after = self.meter.measure(current, tools)
        report.after_tokens = after.total_tokens
        report.after_ratio = after.total_tokens / self.meter.context_window
        return current, report
