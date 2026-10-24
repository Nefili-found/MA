"""外部依赖的协议层（LLM / 嵌入 / 向量索引）。

设计文档 §3/§5 的纪律：模块只通过协议触达外部世界，真实实现集中在
``kbcore.llm`` / ``kbcore.embed`` / ``kbcore.store``，单测一律注入假实现，
从而做到**零网络、零 GPU、零 faiss** 也能跑通整条流水线。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Protocol, Sequence, runtime_checkable


@dataclass
class TokenUsage:
    """单次调用的计量。``usd`` 由调用方按自己的价目表填，缺省 0。"""

    in_tokens: int = 0
    out_tokens: int = 0
    usd: float = 0.0
    calls: int = 0

    def __add__(self, other: "TokenUsage") -> "TokenUsage":
        return TokenUsage(
            in_tokens=self.in_tokens + other.in_tokens,
            out_tokens=self.out_tokens + other.out_tokens,
            usd=self.usd + other.usd,
            calls=self.calls + other.calls,
        )

    def as_dict(self) -> dict:
        return {
            "in": self.in_tokens,
            "out": self.out_tokens,
            "usd": round(self.usd, 6),
            "calls": self.calls,
        }


class LLMError(RuntimeError):
    """LLM 调用失败（网络 / 鉴权 / 服务端）。由 ``loop``/``cli`` 决定如何记账。"""


@runtime_checkable
class LLMClient(Protocol):
    def complete(
        self,
        system: str,
        user: str,
        *,
        tag: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> tuple[str, TokenUsage]:
        """返回 ``(文本, 计量)``。失败抛 :class:`LLMError`。"""


@runtime_checkable
class Embedder(Protocol):
    dim: int

    def encode(self, texts: Sequence[str]) -> list[list[float]]:
        """返回 L2 归一化的向量列表（与 ``texts`` 等长）。"""


@runtime_checkable
class VectorIndex(Protocol):
    backend: str

    def add(self, rows: Iterable[tuple[int, Sequence[float]]]) -> None: ...

    def search(self, vec: Sequence[float], k: int) -> list[tuple[int, float]]:
        """返回 ``(row_id, squared_l2)``，按距离升序。"""

    def save(self, path) -> None: ...


@dataclass
class RunStats:
    """一次建库的总开销（写进 manifest，§8-G6）。"""

    llm: TokenUsage = field(default_factory=TokenUsage)
    pairs_total: int = 0
    pairs_ok: int = 0
    pairs_rejected: int = 0
    cache_hits: int = 0
    evidence_func: int = 0
    evidence_file: int = 0
    evidence_none: int = 0

    def as_dict(self) -> dict:
        return {
            "llm": self.llm.as_dict(),
            "pairs_total": self.pairs_total,
            "pairs_ok": self.pairs_ok,
            "pairs_rejected": self.pairs_rejected,
            "cache_hits": self.cache_hits,
            "evidence": {
                "function": self.evidence_func,
                "file": self.evidence_file,
                "none": self.evidence_none,
            },
        }


__all__ = [
    "TokenUsage",
    "LLMError",
    "LLMClient",
    "Embedder",
    "VectorIndex",
    "RunStats",
]
