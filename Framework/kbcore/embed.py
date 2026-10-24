"""384 维嵌入（``all-MiniLM-L6-v2``）。

设计文档 §5.7：只编码 ``root_cause``（修复端 §5.2 就是拿它建索引）。
量纲错了整库报废，所以 :func:`check_vectors` 会硬断言维度与归一化。
"""

from __future__ import annotations

from typing import Sequence

from .config import KBConfig
from .interfaces import Embedder


class SentenceTransformerEmbedder:
    """生产用嵌入。构造时才 import ``sentence-transformers``（缺依赖时由工厂降级）。"""

    def __init__(self, model_name: str, dim: int = 384, batch: int = 64):
        from sentence_transformers import SentenceTransformer  # type: ignore

        self.model_name = model_name
        self.dim = int(dim)
        self.batch = int(batch)
        self.production = True
        self._model = SentenceTransformer(model_name)

    def encode(self, texts: Sequence[str]) -> list[list[float]]:
        vectors = self._model.encode(
            list(texts),
            batch_size=self.batch,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        return [list(map(float, vec)) for vec in vectors]


def get_embedder(cfg: KBConfig, *, allow_fallback: bool = True) -> Embedder:
    """取嵌入器：优先真实模型，缺依赖时退到确定性哈希嵌入（**非生产**）。"""
    try:
        return SentenceTransformerEmbedder(cfg.embed_model, cfg.embed_dim, cfg.embed_batch)
    except Exception as exc:  # pragma: no cover - 取决于环境
        if not allow_fallback:
            raise RuntimeError(
                f"无法加载嵌入模型 {cfg.embed_model}：{exc}。"
                "请安装 sentence-transformers，或显式允许降级（embeddings 会标记为非生产）"
            ) from exc
        from .testing import HashingEmbedder

        embedder = HashingEmbedder(dim=cfg.embed_dim)
        setattr(embedder, "production", False)
        setattr(embedder, "fallback_reason", str(exc))
        return embedder


def check_vectors(vectors: Sequence[Sequence[float]], dim: int) -> None:
    """维度与归一化断言。任一不满足直接抛错（silent 会让整库检索失效）。"""
    if len(vectors) == 0:
        return
    got = len(vectors[0])
    if got != dim:
        raise ValueError(f"向量维度 {got} != 配置的 {dim}（模型与配置不一致，整库不可用）")
    for i, vec in enumerate(vectors):
        norm = sum(float(x) * float(x) for x in vec) ** 0.5
        if abs(norm - 1.0) > 1e-3:
            raise ValueError(f"第 {i} 条向量未归一化（norm={norm:.4f}）")


__all__ = ["SentenceTransformerEmbedder", "get_embedder", "check_vectors"]
