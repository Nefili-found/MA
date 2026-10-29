"""落盘：两个向量库 + ``meta.jsonl`` + ``manifest.json``。

对应设计文档 §5.8，三个不可省的约定：

* **两库同序**：行号 = ``index_row`` = 该记录在 ``meta.jsonl`` 中的位置，
  修复端命中后只需读一次 meta；
* **先 meta 后索引、最后 manifest**：manifest 存在才算构建成功，
  中途崩溃不会留下"有索引没 meta"的半成品；
* **``corpus_sha256``**：数据/顺序一变哈希就变，结果表可追溯到具体库版本。
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .config import KBConfig
from .embed import check_vectors
from .interfaces import Embedder, RunStats
from .pipeline import VIEWS, assign_index_rows

logger = logging.getLogger(__name__)

try:  # 可选依赖
    import faiss  # type: ignore

    FAISS_AVAILABLE = True
except Exception:  # pragma: no cover - 取决于环境
    FAISS_AVAILABLE = False


@dataclass
class BuildResult:
    out_dir: Path
    meta_path: Path
    index_paths: dict[str, Path] = field(default_factory=dict)
    manifest_path: Optional[Path] = None
    backend: str = ""
    n_df: int = 0
    n_cf: int = 0


def corpus_sha256(records: list[dict]) -> str:
    """语料指纹：pair_id + 视图 + root_cause，顺序敏感。"""
    h = hashlib.sha256()
    for record in records:
        h.update(f"{record['pair_id']}|{record['view_type']}|{record['root_cause']}\n".encode("utf-8"))
    return h.hexdigest()


def _make_index(dim: int):
    if FAISS_AVAILABLE:
        return faiss.IndexFlatL2(dim), "faiss"
    from .testing import FlatL2Index

    return FlatL2Index(dim), "flat-python"


def write_meta(records: list[dict], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in records) + ("\n" if records else ""),
        encoding="utf-8",
    )
    return path


def build(
    cfg: KBConfig,
    records: list[dict],
    embedder: Embedder,
    *,
    out_dir: Optional[Path] = None,
    stats: Optional[RunStats] = None,
) -> BuildResult:
    """建两个库并落盘。``records`` 必须已过门禁（gate）。"""
    out_dir = Path(out_dir or cfg.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 【可观测性】静默降级是最危险的：当前 KB 是 hashing-ngram + flat-python，
    # 检索结果**没有语义**，但用户从产物上看不出来。启动时明确 warn 一次。
    if not FAISS_AVAILABLE:
        logger.warning(
            "[kbcore] faiss-cpu 未安装 → 索引退化为 flat-python（578 条可用，10w 条会慢）；"
            "pip install faiss-cpu 以启用真向量 ANN。"
        )
    if not bool(getattr(embedder, "production", False)):
        reason = getattr(embedder, "fallback_reason", None) or "未知"
        logger.warning(
            "[kbcore] embedding 未走生产模型 → 向量是 hashing-ngram，**检索结果无语义，勿用于评测**。"
            "fallback_reason=%s", reason,
        )

    records = sorted(records, key=lambda r: (r["pair_id"], r["view_type"]))
    assign_index_rows(records)

    meta_path = write_meta(records, out_dir / "meta.jsonl")

    indexes = {}
    index_paths: dict[str, Path] = {}
    counts: dict[str, int] = {}
    for view in VIEWS:
        rows = [r for r in records if r["view_type"] == view]
        index, backend = _make_index(cfg.embed_dim)
        vectors = embedder.encode([r["root_cause"] for r in rows]) if rows else []
        check_vectors(vectors, cfg.embed_dim)
        # faiss 的 IndexFlatL2.add() 只吃 ndarray（内部读 x.shape）；元组列表 (序号, 向量)
        # 是纯 Python 兜底 FlatL2Index 的入参形状。两条分支必须分开，
        # 否则装了 faiss 反而崩在 'list' object has no attribute 'shape'。
        if FAISS_AVAILABLE:  # pragma: no cover - 取决于环境（由 tests/test_kb_store_faiss.py 覆盖）
            import numpy as np  # 惰性导入：无 faiss 时不引入 numpy 硬依赖

            arr = np.asarray(vectors, dtype="float32")
            if arr.size == 0:  # 空视图也要给出 (0, dim) 的形状，faiss 不接受一维空数组
                arr = arr.reshape(0, cfg.embed_dim)
            index.add(arr)
        else:
            index.add([(i, vec) for i, vec in enumerate(vectors)])
        path = out_dir / ("kb_df.faiss" if view == "data_flow" else "kb_cf.faiss")
        if not FAISS_AVAILABLE:
            path = path.with_suffix(".json")
        index.save(str(path)) if hasattr(index, "save") else None
        if FAISS_AVAILABLE:  # pragma: no cover - 取决于环境
            faiss.write_index(index, str(path))
        indexes[view] = index
        index_paths[view] = path
        counts[view] = len(rows)

    manifest = {
        "kb_ver": cfg.kb_ver,
        "embed_model": getattr(embedder, "model_name", None) or "hashing-ngram",
        "embed_production": bool(getattr(embedder, "production", False)),
        "embed_fallback_reason": getattr(embedder, "fallback_reason", None),
        "dim": cfg.embed_dim,
        "metric": "l2",
        "backend": "faiss" if FAISS_AVAILABLE else "flat-python",
        "n_df": counts.get("data_flow", 0),
        "n_cf": counts.get("control_flow", 0),
        "corpus_sha256": corpus_sha256(records),
        "prompt_ver": cfg.prompt_ver,
        "abstract_prompt_ver": cfg.abstract_prompt_ver,
        "llm_model": cfg.model,
        "evidence_mode": cfg.evidence_mode,
        "cwe_counts": _cwe_counts(records),
        "stats": (stats or RunStats()).as_dict(),
        "index_files": {k: str(v.name) for k, v in index_paths.items()},
    }
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    return BuildResult(
        out_dir=out_dir,
        meta_path=meta_path,
        index_paths=index_paths,
        manifest_path=manifest_path,
        backend=manifest["backend"],
        n_df=counts.get("data_flow", 0),
        n_cf=counts.get("control_flow", 0),
    )


def _cwe_counts(records: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for record in records:
        out[record["cwe"]] = out.get(record["cwe"], 0) + 1
    return dict(sorted(out.items()))


def load_meta(out_dir: Path) -> list[dict]:
    """读回 ``meta.jsonl``（修复端 ``kb.py`` 的等价实现，供审计/自检）。"""
    path = Path(out_dir) / "meta.jsonl"
    if not path.exists():
        raise FileNotFoundError(f"缺 meta.jsonl：{path}")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


__all__ = [
    "FAISS_AVAILABLE",
    "BuildResult",
    "build",
    "write_meta",
    "corpus_sha256",
    "load_meta",
]
