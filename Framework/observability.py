"""可观测性辅助：结构化日志、耗时统计、token 估算。

【健壮性包 B-1】日志结构化（对应 20 文档 §5.3-14）。
改造前：``log_event`` 只打 ``[event] name k=v``，字段不固定、无 severity，
日志聚合系统无法解析，也没法按级别过滤。
改造后：
* 每条事件带 ``ts`` / ``level`` / ``event`` + 业务字段；
* 默认输出 **JSON 行**（一行一个对象，可直接被 jq / 聚合系统消费）；
* ``level`` 取 debug / info / warn / error，低于配置级别的直接丢弃；
* 保留 ``text`` 格式（仍是 ``[event] name k=v``），``logging.format: text`` 一键退回。

TODO: 如需接入 OpenTelemetry / LangSmith，在此扩展 exporter 即可。
"""
from __future__ import annotations

import contextlib
import json
import sys
import time
from typing import Any, Dict, Iterator, Optional

# ---------------------------------------------------------------------------
# 日志开关 / 格式 / 级别（由 config 的 logging 段控制）
# ---------------------------------------------------------------------------
_LOG_ENABLED = True
_LOG_FORMAT = "json"  # json = 一行一个 JSON 对象（可聚合）；text = 人读
_LOG_LEVEL = "info"

_LEVEL_ORDER = {"debug": 10, "info": 20, "warn": 30, "error": 40}
_RESERVED_KEYS = ("ts", "level", "event")


def set_log_enabled(enabled: bool) -> None:
    """全局开关（通常由配置中的 logging.enabled 控制）。"""
    global _LOG_ENABLED
    _LOG_ENABLED = bool(enabled)


def set_log_format(log_format: Optional[str]) -> None:
    """日志格式：``json``（默认）或 ``text``；非法值回落到 json。"""
    global _LOG_FORMAT
    fmt = str(log_format or "").strip().lower()
    _LOG_FORMAT = fmt if fmt in ("json", "text") else "json"


def set_log_level(level: Optional[str]) -> None:
    """最低输出级别：debug / info / warn / error；非法值回落到 info。"""
    global _LOG_LEVEL
    lvl = str(level or "").strip().lower()
    if lvl == "warning":
        lvl = "warn"
    _LOG_LEVEL = lvl if lvl in _LEVEL_ORDER else "info"


def configure_logging(
    enabled: Optional[bool] = None,
    log_format: Optional[str] = None,
    log_level: Optional[str] = None,
) -> None:
    """一次性应用配置（main.py 加载 Settings 后调用）；None 表示保持现值。"""
    if enabled is not None:
        set_log_enabled(bool(enabled))
    if log_format is not None:
        set_log_format(log_format)
    if log_level is not None:
        set_log_level(log_level)


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def log_event(event: str, level: str = "info", **fields: Any) -> None:
    """输出一条事件日志到 stderr（stdout 留给最终 JSON，不被污染）。

    * ``json``（默认）：``{"ts": ..., "level": ..., "event": ..., ...fields}``，
      一行一条，字段平铺，可直接 grep / jq / 送入聚合系统；
    * ``text``：``[event] name k=v``，与改造前完全一致，便于人工扫读。

    ``level`` 进 debug / info / warn / error；低于当前 ``log_level`` 的事件被丢弃。
    """
    if not _LOG_ENABLED:
        return
    lvl = str(level or "info").strip().lower()
    if lvl == "warning":
        lvl = "warn"
    if _LEVEL_ORDER.get(lvl, 20) < _LEVEL_ORDER.get(_LOG_LEVEL, 20):
        return

    if _LOG_FORMAT == "text":
        payload = " ".join(f"{k}={v}" for k, v in fields.items())
        print(f"[event] {event} {payload}".rstrip(), file=sys.stderr)
        return

    record: Dict[str, Any] = {"ts": _now_iso(), "level": lvl, "event": event}
    for key, value in fields.items():
        # 保留字段不被业务字段覆盖；同名业务字段加前缀以保留信息
        out_key = f"field_{key}" if key in _RESERVED_KEYS else key
        record[out_key] = value if isinstance(
            value, (str, int, float, bool, type(None))
        ) else str(value)
    print(json.dumps(record, ensure_ascii=False), file=sys.stderr)


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
