"""LangGraph 图编排。

结构（A/B/C 并行 fan-out，D 作为 join 节点）：::

            ┌─> A ─┐
    START ──┼─> B ─┼─> D ─> END
            └─> C ─┘

LangGraph 会在 A/B/C 三个节点全部完成后才执行 D（join 语义）。
若需要“顺序调度”，可自行把 A/B/C 改成链式边（A->B->C），
但本骨架默认保留并行 fan-out。
"""
from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from agents import a, b, c
from verify_agent import d
from state import ScanState


def build_graph() -> Any:
    """构建并编译图。"""
    graph = StateGraph(ScanState)

    graph.add_node("A", a.run)
    graph.add_node("B", b.run)
    graph.add_node("C", c.run)
    graph.add_node("D", d.run)

    # A/B/C 并行 fan-out
    graph.add_edge(START, "A")
    graph.add_edge(START, "B")
    graph.add_edge(START, "C")

    # A/B/C -> D（join）：三者都完成后 D 才会执行
    graph.add_edge("A", "D")
    graph.add_edge("B", "D")
    graph.add_edge("C", "D")

    graph.add_edge("D", END)

    return graph.compile()
