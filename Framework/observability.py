"""可观测性辅助：日志、耗时统计、token 估算。

均为轻量实现，按需调用，不强制全局启用。
TODO: 如需接入 OpenTelemetry / LangSmith / 结构化日志，请在此扩展。
"""
from __future__ import annotations

import contextlib
import sys
import time
from typing import Any, Iterator, Optional

_LOG_ENABLED = True


def set_log_enabled(enabled: bool) -> None:
    """全局开关（通常由配置中的 logging.enabled 控制）。"""
    global _LOG_ENABLED
    _LOG_ENABLED = bool(enabled)


def log_event(event: str, **fields: Any) -> None:
    """打印一条事件日志（默认写到 stderr，避免污染最终 JSON 输出）。"""
    if not _LOG_ENABLED:
        return
    payload = " ".join(f"{k}={v}" for k, v in fields.items())
    print(f"[event] {event} {payload}".rstrip(), file=sys.stderr)


@contextlib.contextmanager
def track_time(label: str) -> Iterator[Dict[str, Any]]:
    """计时上下文管理器::

        with track_time("scan.A") as rec:
            ...
        print(rec["elapsed_ms"])
    """
    start = time.perf_counter()
    record: Dict[str, Any] = {"label": label}
    try:
        yield record
    finally:
        record["elapsed_ms"] = round((time.perf_counter() - start) * 1000, 2)
        log_event("timing", **record)


def count_tokens(text: str, model: Optional[str] = None) -> int:
    """粗略 token 估算（约 4 字符/token）。

    【优化 O-9】统一计量口径：复用 context.meter 的 ``estimate_tokens``
    （ceil 向上取整，与 TokenMeter / 压力计算完全一致），避免出现两处
    估算结果不一致；惰性导入，不引入循环依赖。无法导入时回退旧实现。

    TODO: 如需精确统计，接入 tiktoken（langchain-openai 已依赖 tiktoken）。
    """
    if not text:
        return 0
    try:
        from context.meter import estimate_tokens

        return estimate_tokens(text)
    except Exception:
        return max(1, len(text) // 4)
