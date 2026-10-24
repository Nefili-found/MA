"""入库门禁：纯确定性检查（无 LLM）。

对应设计文档 §5.6。任何一条不过，该**对**不入库（成对判定，§7.3），
理由与原始输出写进 ``rejects.jsonl`` —— 否则事后无法判断是模型的问题
还是门禁过严。
"""

from __future__ import annotations

from typing import Iterable

from .config import KBConfig
from .extract import BEHAVIOR_FIELD, VIEWS
from .pairs import PairRecord

REQUIRED_FIELDS: tuple[str, ...] = ("root_cause", "risky_calls", "fixing_strategy")


def check(cfg: KBConfig, pair: PairRecord, record: dict, view: str) -> list[str]:
    """返回违规列表（空 = 通过）。"""
    problems: list[str] = []

    if view not in VIEWS:
        return [f"未知视图 {view}"]

    for key in REQUIRED_FIELDS:
        if key not in record:
            problems.append(f"缺字段 {key}")

    root = str(record.get("root_cause", "") or "").strip()
    if not root:
        problems.append("root_cause 为空")
    elif len(root) > cfg.max_root_cause_chars:
        problems.append(f"root_cause 超长（{len(root)} > {cfg.max_root_cause_chars}）")

    strategy = str(record.get("fixing_strategy", "") or "").strip()
    if not strategy:
        problems.append("fixing_strategy 为空")
    elif len(strategy) > cfg.max_strategy_chars:
        problems.append(f"fixing_strategy 超长（{len(strategy)} > {cfg.max_strategy_chars}）")

    behavior_key = BEHAVIOR_FIELD[view]
    behavior = str(record.get(behavior_key, "") or "").strip()
    if not behavior:
        problems.append(f"{behavior_key} 为空")
    elif len(behavior) > cfg.max_behavior_chars:
        problems.append(f"{behavior_key} 超长（{len(behavior)} > {cfg.max_behavior_chars}）")

    other_key = BEHAVIOR_FIELD["control_flow" if view == "data_flow" else "data_flow"]
    if record.get(other_key):
        problems.append(f"视图互斥被破坏：{view} 记录里出现 {other_key}")

    calls = record.get("risky_calls")
    if not isinstance(calls, list):
        problems.append("risky_calls 不是数组")
    elif len(calls) > cfg.max_calls:
        problems.append(f"risky_calls 过多（{len(calls)} > {cfg.max_calls}）")

    return problems


def prunable_calls(pair: PairRecord, record: dict) -> list[str]:
    """``risky_calls`` 里在源码中找不到的名字（模型编的 API）。"""
    calls = record.get("risky_calls") or []
    haystack = pair.vul_src + "\n" + pair.non_src
    return [str(name) for name in calls if str(name) and str(name) not in haystack]


def normalize(cfg: KBConfig, pair: PairRecord, record: dict, view: str) -> tuple[dict, list[str]]:
    """可修复的问题就地修（截断 / 删掉编造的 API 名），不可修的留给 :func:`check`。

    :return: ``(清洗后的记录, 被丢弃的调用名列表)``
    """
    out = dict(record)
    out["root_cause"] = str(out.get("root_cause", "")).strip()[: cfg.max_root_cause_chars]
    out["fixing_strategy"] = str(out.get("fixing_strategy", "")).strip()[: cfg.max_strategy_chars]
    key = BEHAVIOR_FIELD[view]
    out[key] = str(out.get(key, "")).strip()[: cfg.max_behavior_chars]
    # 另一视图的行为字段必须显式为 None（meta 契约要求两键都存在）
    out[BEHAVIOR_FIELD["control_flow" if view == "data_flow" else "data_flow"]] = None

    dropped = prunable_calls(pair, out)
    kept = [c for c in (out.get("risky_calls") or []) if str(c) not in dropped]
    out["risky_calls"] = [str(c) for c in kept][: cfg.max_calls]
    return out, dropped


def gate_pair(
    cfg: KBConfig, pair: PairRecord, records: dict[str, dict]
) -> tuple[bool, dict[str, dict], dict[str, list[str]], dict[str, list[str]]]:
    """对一个 pair 的两个视图做门禁。

    :return: ``(是否整对通过, 清洗后的记录, 违规说明, 被丢弃的调用名)``
    """
    cleaned: dict[str, dict] = {}
    problems: dict[str, list[str]] = {}
    dropped: dict[str, list[str]] = {}
    for view in VIEWS:
        record, dropped_calls = normalize(cfg, pair, records.get(view) or {}, view)
        cleaned[view] = record
        dropped[view] = dropped_calls
        problems[view] = check(cfg, pair, record, view)
    ok = all(not v for v in problems.values())
    return ok, cleaned, problems, dropped


__all__ = ["REQUIRED_FIELDS", "check", "prunable_calls", "normalize", "gate_pair"]
