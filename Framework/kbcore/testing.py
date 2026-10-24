"""测试用假实现（零网络 / 零 GPU / 零 faiss）。

设计文档 §3-D5：每个模块的顶层函数都要能在没有外部依赖的环境里跑通。
本模块提供的假实现同时也是"契约的可执行说明"——
真实实现必须满足同样的签名与返回形状。
"""

from __future__ import annotations

import hashlib
import math
import random
from typing import Iterable, Optional, Sequence

from .interfaces import LLMError, TokenUsage


class FakeLLM:
    """按 ``tag`` 顺序返回预置文本；无脚本时按 tag 生成合法 JSON。"""

    def __init__(
        self,
        script: Optional[dict[str, list[str]]] = None,
        *,
        default: Optional[str] = None,
        raise_on: Optional[set[str]] = None,
    ):
        self.script = {k: list(v) for k, v in (script or {}).items()}
        self.default = default
        self.raise_on = raise_on or set()
        self.calls: list[dict] = []
        self.usage = TokenUsage()

    def complete(
        self,
        system: str,
        user: str,
        *,
        tag: str = "",
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> tuple[str, TokenUsage]:
        self.calls.append({"tag": tag, "system": system, "user": user})
        if tag in self.raise_on:
            raise LLMError(f"fake failure on tag={tag}")

        if self.script.get(tag):
            text = self.script[tag].pop(0)
        elif self.default is not None:
            text = self.default
        else:
            text = _auto_payload(tag)

        usage = TokenUsage(in_tokens=len(user) // 4, out_tokens=len(text) // 4, calls=1)
        self.usage = self.usage + usage
        return text, usage


def _auto_payload(tag: str) -> str:
    if tag == "abstract":
        return '{"root_cause": "an externally supplied length is used before being compared with the destination capacity"}'
    if tag.endswith("data_flow"):
        return (
            '{"root_cause": "external length reaches a copy without a capacity comparison", '
            '"risky_calls": ["memcpy"], '
            '"taint_flow": "the input length flows into the copy size", '
            '"fixing_strategy": "compare the length with the destination capacity before copying"}'
        )
    return (
        '{"root_cause": "the bounds check is evaluated after the index is already used", '
        '"risky_calls": ["memcpy"], '
        '"control_branch": "the loop guard is checked after the redundant index access", '
        '"fixing_strategy": "move the bounds check ahead of the index access"}'
    )


class HashingEmbedder:
    """确定性 384 维嵌入（字符 3-gram 哈希 + L2 归一）。

    **不是生产用嵌入**：只用来在没有 ``sentence-transformers`` 的环境里跑通
    存储与检索链路（例如本仓库的 CI / 单测）。
    """

    dim = 384

    def __init__(self, dim: int = 384, seed: int = 7):
        self.dim = dim
        self.seed = seed

    def _vec(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        body = " ".join((text or "").lower().split())
        for i in range(max(1, len(body) - 2)):
            gram = body[i : i + 3]
            h = int(hashlib.md5(f"{self.seed}:{gram}".encode()).hexdigest()[:8], 16)
            vec[h % self.dim] += 1.0
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]

    def encode(self, texts: Sequence[str]) -> list[list[float]]:
        return [self._vec(t) for t in texts]


class FlatL2Index:
    """极简 L2 索引（纯 Python）。faiss 不可用时的兜底，行为与 IndexFlatL2 一致。"""

    backend = "flat-python"

    def __init__(self, dim: int = 384):
        self.dim = dim
        self.rows: list[tuple[int, list[float]]] = []

    def add(self, rows: Iterable[tuple[int, Sequence[float]]]) -> None:
        for row_id, vec in rows:
            self.rows.append((int(row_id), [float(x) for x in vec]))

    def search(self, vec: Sequence[float], k: int) -> list[tuple[int, float]]:
        q = [float(x) for x in vec]
        scored = [
            (row_id, sum((a - b) ** 2 for a, b in zip(q, row)))
            for row_id, row in self.rows
        ]
        scored.sort(key=lambda pair: pair[1])
        return scored[:k]

    def save(self, path) -> None:
        import json
        from pathlib import Path

        Path(path).write_text(
            json.dumps([{"row": r, "vec": v} for r, v in self.rows]), encoding="utf-8"
        )


class ScriptedEmbedder:
    """完全可控的嵌入：按文本查表，未命中给确定性随机向量。"""

    dim = 4

    def __init__(self, table: dict[str, list[float]], dim: int = 4):
        self.table = dict(table)
        self.dim = dim

    def encode(self, texts: Sequence[str]) -> list[list[float]]:
        out = []
        for text in texts:
            if text in self.table:
                out.append(list(self.table[text]))
            else:
                rng = random.Random(text)
                out.append([rng.random() for _ in range(self.dim)])
        return out


__all__ = ["FakeLLM", "HashingEmbedder", "FlatL2Index", "ScriptedEmbedder"]
