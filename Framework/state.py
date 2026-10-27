"""LangGraph 图状态定义。

该状态在各节点之间流转。A/B/C 三个扫描 Agent 会并行执行，
因此对会被并行写入的字段（``reports`` / ``errors``）使用 reducer 做安全合并，
避免 LangGraph 因并发写同一 channel 而报错。
"""
from __future__ import annotations

import operator
from typing import Annotated, Any, Dict, List, TypedDict


def merge_reports(left: Dict[str, Any] | None, right: Dict[str, Any] | None) -> Dict[str, Any]:
    """合并 A/B/C 各自写入的 report。

    每个扫描 Agent 只写自己那一份（例如 ``{"A": {...}}``），
    通过该 reducer 汇集为 ``{"A": ..., "B": ..., "C": ...}``。
    """
    return {**(left or {}), **(right or {})}


class ScanState(TypedDict, total=False):
    # ---- 输入 ----
    file_path: str
    code: str

    # ---- 修复端输入元数据（由 main.py 的 CLI 参数注入）----
    # 只影响 output/repair_input.json；final_report.json 不依赖这些
    case_id: str      # 用例目录名（批次内唯一）
    repo: str         # 上游仓库名
    commit: str       # 被扫描文件对应的上游 commit
    rel_file: str     # 仓库相对路径（用于跨机器复现）

    # ---- 行号基准（D5）：切片扫描时行号从切片起算 ----
    # 注意：这两个键必须在这里声明。LangGraph 按 TypedDict 的 channel 传状态，
    # 没声明的键在 START → D 之间会被静默丢弃（实测：加进 main.py 的 state 却在
    # D 里取不到，投影 line_base 一直回落成 file，case 全被判 invalid_baseline）。
    slice_start: int  # 切片在原文件里的起始行号（1-based）；0 = 完整文件
    line_base: str    # file | function（function = 行号相对切片起点）

    # ---- A/B/C 原始报告：{"A": {...}, "B": {...}, "C": {...}} ----
    reports: Annotated[Dict[str, Any], merge_reports]

    # ---- D 去重整合后的中间结果 ----
    merged_findings: List[Dict[str, Any]]

    # ---- 工具验证后的结果 ----
    verified_findings: List[Dict[str, Any]]

    # ---- 最终输出 JSON ----
    final_report: Dict[str, Any]

    # ---- 面向修复端的输入投影（repair-input/1）----
    repair_input: Dict[str, Any]

    # ---- 会话 id（记忆库隔离用）----
    session_id: str

    # ---- 错误收集（reducer 追加）----
    errors: Annotated[List[str], operator.add]
