"""扫描侧的上下文治理器构造（优化点 O-8 / O-10 的接线点）。

从 ``agents/__init__.py`` 拆出（20 文档 §5.1-3）。参数全部来自 config 的
``context.*`` 段，这里只负责把 Settings 翻译成 ``ContextManager``，不掺业务逻辑。
"""
from __future__ import annotations

from config import Settings, resolve
from context import ContextManager


def build_context_manager(settings: Settings) -> ContextManager:
    """【优化 O-8】从配置构造扫描用的上下文治理器（spill 目录解析为绝对路径）。"""
    return ContextManager(
        context_window=int(getattr(settings, "context_window", 128_000)),
        threshold_ratio=float(getattr(settings, "context_threshold_ratio", 0.8)),
        retain_ratio=float(getattr(settings, "context_retain_ratio", 0.16)),
        spill_root=str(resolve(getattr(settings, "spill_root", "output/spill"))),
        max_inline_bytes=int(getattr(settings, "spill_max_inline_bytes", 4096)),
        prune_threshold_chars=int(getattr(settings, "prune_threshold_chars", 8192)),
        prune_head_chars=int(getattr(settings, "prune_head_chars", 4096)),
        prune_tail_chars=int(getattr(settings, "prune_tail_chars", 1024)),
        enable_spill=bool(getattr(settings, "context_enable_spill", True)),
        enable_compaction=bool(getattr(settings, "context_enable_compaction", True)),
    )
