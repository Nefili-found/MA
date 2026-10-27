"""检索层：C2 级联 + C3 混合重排，并修掉旧实现的三处硬伤。

设计依据：``change_process/summery/修复端_结构重构_2026-10-24_设计.md`` §7 / §8。

三处硬伤与对应修法
------------------
======================  ==============================  ====================================
硬伤                    旧实现                           本实现
======================  ==============================  ====================================
无 CWE 硬过滤            完全没有                        ``cwe_key(doc) == cwe_key(target)``
BM25 未池内归一           ``min(1, max(0, s))`` 的 clip    **池内 min-max**，与 cos 同量纲
去重 key 用 ``id(meta)``  ``id()`` 在同一批对象间会变     按 ``(pair_id, view_type)`` 去重
======================  ==============================  ====================================

三种相似度各自的口径（写清是因为它们必须能放在一起加）：

* ``cos``：索引是 ``IndexFlatL2``，元素已 L2 归一，所以 ``d² = 2 - 2·cos`` ⇒
  ``cos = 1 - d²/2``。**不用再除任何东西**，这是归一化带来的等价性。
* ``bm25``：标准 Okapi BM25（``k1=1.5``、``b=0.75``），IDF 只在**该 CWE 池内**统计——
  池外文档不参与 IDF，否则"这个 CWE 只有 21 对"会让 IDF 失真。
* 融合：``score = cos_weight·cos + (1 - cos_weight)·bm25_norm``，默认 ``cos_weight=0.3``。

``cos_weight`` 的来历：0.3 是从旧实现继承的，且只在"CodeLlama 真加载"的前提下标定过。
**换了嵌入模型必须重扫**（设计稿 §5.2 决策 4），所以本模块把它随结果一起带出去，写进
``CaseOutcome``，而不是埋在代码里当常量。
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from kbcore.store import load_meta

from .schema import QueryView, RetrievalHit, cwe_key

VIEWS: tuple = ("data_flow", "control_flow")

#: 索引文件名（视图 → 基名）。``.faiss`` 不存在时退到 ``.json``（纯 Python 兜底）
INDEX_BASENAME = {"data_flow": "kb_df", "control_flow": "kb_cf"}

#: 默认融合权重（cos 占比）。换嵌入模型必须重扫，见模块 docstring。
DEFAULT_COS_WEIGHT = 0.3

#: BM25 参数（Okapi 默认值）
BM25_K1 = 1.5
BM25_B = 0.75

#: CWE 归并表：``CWE-401（内存泄漏）`` 取 exemplar 时并入 ``CWE-416（UAF）`` 的候选池。
#:
#: 出处（**唯一**依据）：APPATCH 官方实现 ``other fix framework/code/appatch_ablated/
#: patching_appatch.py`` 里的 ``if train_cwe == 'CWE-401': train_cwe = 'CWE-416'``。
#: 它的用途只是"取 exemplar 时归入同一候选池"，**不是说两种缺陷同类**，所以：
#:
#: * 默认**关闭**（``cwe_merge=False``），与设计稿 §7 的字面要求有一处偏差，已记录在案；
#: * 打开时按对称归并处理（查询侧与库侧走同一函数），避免只在一侧生效造成漏召。
CWE_MERGE_TABLE: Dict[str, str] = {"CWE-401": "CWE-416"}

_TOKEN_RE = re.compile(r"[a-z0-9_]+")


# ---------------------------------------------------------------- 知识库句柄


@dataclass
class KnowledgeBase:
    """已加载的知识库：meta + 每个视图的索引。构造后只读。"""

    out_dir: Path
    meta: List[Dict[str, Any]] = field(default_factory=list)
    manifest: Dict[str, Any] = field(default_factory=dict)
    #: 视图 → meta 下标列表（按 meta 顺序）；索引里的 id 就是这里的下标
    view_rows: Dict[str, List[int]] = field(default_factory=dict, repr=False)
    indexes: Dict[str, Any] = field(default_factory=dict, repr=False)
    notes: List[str] = field(default_factory=list)

    @property
    def kb_ver(self) -> str:
        return str(self.manifest.get("kb_ver") or "")

    @property
    def corpus_sha256(self) -> str:
        return str(self.manifest.get("corpus_sha256") or "")

    @property
    def backend(self) -> str:
        return str(self.manifest.get("backend") or "")

    @property
    def embed_model(self) -> str:
        return str(self.manifest.get("embed_model") or "")

    def records_for(self, view: str) -> List[Dict[str, Any]]:
        return [self.meta[i] for i in self.view_rows.get(view, [])]


def load_kb(out_dir: str | Path) -> KnowledgeBase:
    """读 ``artifacts/<kb_ver>/``：``meta.jsonl`` + 两个视图索引 + ``manifest.json``。"""
    out_dir = Path(out_dir)
    if not out_dir.is_dir():
        raise NotADirectoryError(f"知识库目录不存在：{out_dir}")
    meta = load_meta(out_dir)
    manifest_path = out_dir / "manifest.json"
    manifest = (
        json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    )

    view_rows: Dict[str, List[int]] = {view: [] for view in VIEWS}
    for index, record in enumerate(meta):
        view = str(record.get("view_type") or "")
        view_rows.setdefault(view, []).append(index)

    kb = KnowledgeBase(out_dir=out_dir, meta=meta, manifest=manifest, view_rows=view_rows)
    declared = (manifest.get("index_files") or {}) if isinstance(manifest.get("index_files"), dict) else {}

    for view in VIEWS:
        names = []
        if isinstance(declared.get(view), str):
            names.append(str(declared[view]))
        names.extend([f"{INDEX_BASENAME[view]}.faiss", f"{INDEX_BASENAME[view]}.json"])
        for name in names:
            path = out_dir / name
            if not path.exists():
                continue
            kb.indexes[view] = _load_index(path)
            break
        else:
            kb.notes.append(f"{view}: 索引文件缺失（已尝试 {names}），该视图检索为空")
    return kb


def _load_index(path: Path) -> Any:
    if path.suffix == ".faiss":
        import faiss  # type: ignore

        return faiss.read_index(str(path))
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {"rows": [{"row": int(r["row"]), "vec": [float(x) for x in r["vec"]]} for r in raw]}


def _search(index: Any, vector: Sequence[float], k: int) -> List[Tuple[int, float]]:
    """统一检索接口，返回 ``[(id, 平方 L2 距离), …]``，按距离升序。"""
    if isinstance(index, dict):  # .json 兜底：纯 Python 平方 L2
        scored = [
            (row["row"], sum((a - b) ** 2 for a, b in zip(vector, row["vec"])))
            for row in index["rows"]
        ]
        scored.sort(key=lambda pair: pair[1])
        return scored[:k]

    import numpy as np  # type: ignore

    query = np.asarray([list(vector)], dtype="float32")
    dists, ids = index.search(query, min(k, index.ntotal))
    return [(int(i), float(d)) for i, d in zip(ids[0], dists[0]) if int(i) >= 0]


# ---------------------------------------------------------------- 检索结果


@dataclass
class RetrievalResult:
    """一次检索的全部可审计信息（``CaseOutcome`` 里只留摘要）。"""

    view_type: str = ""
    hits: List[RetrievalHit] = field(default_factory=list)
    pool_size: int = 0
    cos_weight: float = DEFAULT_COS_WEIGHT
    cwe_merge: bool = False
    kb_ver: str = ""
    corpus_sha256: str = ""
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "view_type": self.view_type,
            "hits": [h.to_dict() for h in self.hits],
            "pool_size": self.pool_size,
            "cos_weight": self.cos_weight,
            "cwe_merge": self.cwe_merge,
            "kb_ver": self.kb_ver,
            "corpus_sha256": self.corpus_sha256,
            "notes": list(self.notes),
        }

    @property
    def pair_ids(self) -> List[str]:
        return [h.pair_id for h in self.hits]


# ---------------------------------------------------------------- 主入口


def retrieve_for_case(
    kb: KnowledgeBase,
    query: QueryView,
    target_cwe: str,
    *,
    top_k: int = 4,
    cos_weight: float = DEFAULT_COS_WEIGHT,
    cwe_merge: bool = False,
    k1: float = BM25_K1,
    b: float = BM25_B,
    query_vector: Optional[Sequence[float]] = None,
) -> RetrievalResult:
    """单视图检索（**唯一入口**）：CWE 硬过滤 → 向量召回 + BM25 → 池内归一 → 融合 → 去重 → Top-K。

    ``QueryView`` 是有意**不带** CWE 的：它是"检索键"，CWE 是"身份"。混在一起会让
    "``Query`` 契约与知识库记录同构"这件事失效（两臂共用同一份下游的前提）。目标 CWE
    必须由调用方从 ``RepairCase.vuln.cwe`` 传进来。

    ``query_vector`` 给定时跳过自编码：测试可以完全控制 cos，生产侧也能复用已算好的向量。
    """
    result = RetrievalResult(
        view_type=query.view_type,
        cos_weight=float(cos_weight),
        cwe_merge=bool(cwe_merge),
        kb_ver=kb.kb_ver,
        corpus_sha256=kb.corpus_sha256,
    )
    return _retrieve_with_target(
        kb, query, cwe_key(target_cwe), result, top_k, cos_weight, cwe_merge, k1, b, query_vector
    )


def _retrieve_with_target(
    kb: KnowledgeBase,
    query: QueryView,
    target_cwe: str,
    result: RetrievalResult,
    top_k: int,
    cos_weight: float,
    cwe_merge: bool,
    k1: float,
    b: float,
    query_vector: Optional[Sequence[float]] = None,
) -> RetrievalResult:
    view = query.view_type
    index = kb.indexes.get(view)
    if index is None:
        result.notes.append(f"{view}: 没有可用的索引，返回空结果")
        return result

    rows = kb.view_rows.get(view, [])
    if not rows:
        result.notes.append(f"{view}: 知识库里没有该视图的记录")
        return result

    if not target_cwe:
        result.notes.append("target_cwe 为空 ⇒ 不做 CWE 过滤（结果不可用于正式评测）")

    # ---- 1) 向量召回：整池搜索，不截断（BM25 的 IDF 需要全池）
    vector = list(query_vector) if query_vector is not None else _encode_query(kb, query)
    if vector is None:
        result.notes.append("查询向量不可用（缺嵌入模型或导入失败）⇒ 只按 BM25 排序")
        candidates = [(i, None) for i in range(len(rows))]
    else:
        raw = _search(index, vector, k=len(rows))
        candidates = [(row_id, dist) for row_id, dist in raw if 0 <= row_id < len(rows)]

    # ---- 2) CWE 硬过滤（在池上做，池 = 过滤后的候选）
    pool: List[Tuple[int, Dict[str, Any], Optional[float]]] = []
    for row_id, dist in candidates:
        record = kb.meta[rows[row_id]]
        if target_cwe and _bucket(record.get("cwe"), cwe_merge) != _bucket(target_cwe, cwe_merge):
            continue
        cos = None if dist is None else max(-1.0, min(1.0, 1.0 - float(dist) / 2.0))
        pool.append((row_id, record, cos))
    result.pool_size = len(pool)
    if not pool:
        result.notes.append(f"池为空：CWE={target_cwe} 在 {view} 视图下没有候选")
        return result

    # ---- 3) BM25（只在池内统计 IDF）
    docs = [_doc_text(record) for _rid, record, _cos in pool]
    q_tokens = _tokens(_query_text(query))
    raw_scores = _bm25_scores(q_tokens, docs, k1=k1, b=b)
    norm_scores = _minmax(raw_scores)
    if norm_scores is None:
        norm_scores = [0.0] * len(raw_scores)
        result.notes.append("池内 BM25 全部相等 ⇒ 归一后统一为 0，排序由 cos 决定")

    # ---- 4) 融合 + 5) 按 (pair_id, view_type) 去重
    scored: List[Tuple[float, int, Dict[str, Any], Optional[float], float, float]] = []
    for (row_id, record, cos), bm25_raw, bm25 in zip(pool, raw_scores, norm_scores):
        cos_value = 0.0 if cos is None else cos
        score = cos_weight * cos_value + (1.0 - cos_weight) * bm25
        scored.append((score, row_id, record, cos, bm25, bm25_raw))

    scored.sort(key=lambda item: (-item[0], item[1]))
    seen: Dict[Tuple[str, str], int] = {}
    hits: List[RetrievalHit] = []
    dropped_duplicates = 0
    for score, row_id, record, cos, bm25, bm25_raw in scored:
        key = (str(record.get("pair_id") or ""), str(record.get("view_type") or ""))
        if key in seen:
            dropped_duplicates += 1
            continue
        seen[key] = row_id
        hits.append(
            RetrievalHit(
                pair_id=key[0],
                view_type=key[1],
                cwe=str(record.get("cwe") or ""),
                rank=len(hits) + 1,
                cos=0.0 if cos is None else cos,
                bm25=bm25,
                bm25_raw=bm25_raw,
                score=score,
                index_row=_as_int(record.get("index_row"), -1),
            )
        )
        if len(hits) >= top_k:
            break

    if dropped_duplicates:
        result.notes.append(f"按 (pair_id, view_type) 去重，丢弃 {dropped_duplicates} 条重复")
    result.hits = hits
    return result


# ---------------------------------------------------------------- 文本与打分


def _bucket(cwe: Any, merge: bool) -> str:
    key = cwe_key(cwe)
    return CWE_MERGE_TABLE.get(key, key) if merge else key


def _doc_text(record: Dict[str, Any]) -> str:
    parts = [
        str(record.get("root_cause") or ""),
        str(record.get("taint_flow") or ""),
        str(record.get("control_branch") or ""),
        str(record.get("fixing_strategy") or ""),
        " ".join(str(x) for x in (record.get("risky_calls") or [])),
    ]
    return " ".join(p for p in parts if p)


def _query_text(query: QueryView) -> str:
    parts = [
        query.root_cause,
        query.taint_flow or "",
        query.control_branch or "",
        " ".join(query.risky_calls),
    ]
    return " ".join(p for p in parts if p)


def _tokens(text: str) -> List[str]:
    return _TOKEN_RE.findall((text or "").lower())


def _bm25_scores(
    query_tokens: Iterable[str],
    docs: Sequence[str],
    *,
    k1: float = BM25_K1,
    b: float = BM25_B,
) -> List[float]:
    """池内 Okapi BM25。``docs`` 就是池，IDF 只按池内文档统计。"""
    tokenized = [_tokens(doc) for doc in docs]
    n = len(tokenized)
    if n == 0:
        return []
    lengths = [len(t) for t in tokenized]
    avgdl = (sum(lengths) / n) or 1.0

    df: Dict[str, int] = {}
    for tokens in tokenized:
        for term in set(tokens):
            df[term] = df.get(term, 0) + 1

    terms = list(dict.fromkeys(query_tokens))
    # 查询词可能在整个池里都不出现（df=0）：这不是异常，标准 BM25 里该词的 idf 取
    # 最大值、但因 tf=0 而贡献 0 分。用 ``df.get(term, 0)``，别直接下标。
    idf = {
        term: math.log(1 + (n - df.get(term, 0) + 0.5) / (df.get(term, 0) + 0.5))
        for term in terms
    }

    scores: List[float] = []
    for tokens, length in zip(tokenized, lengths):
        tf: Dict[str, int] = {}
        for term in tokens:
            tf[term] = tf.get(term, 0) + 1
        total = 0.0
        for term in terms:
            freq = tf.get(term, 0)
            if not freq:
                continue
            denom = freq + k1 * (1 - b + b * length / avgdl)
            total += idf[term] * freq * (k1 + 1) / denom
        scores.append(total)
    return scores


def _minmax(values: Sequence[float]) -> Optional[List[float]]:
    """池内 min-max 归一。全相等时返回 ``None``（表示"这一段没有区分度"），不返回全 1。

    旧实现是 ``min(1, max(0, s))`` 的 clip，几乎所有 BM25 分都 > 1，于是**大量并列 1.0**，
    融合时 BM25 这 70% 的权重等于白给。返回 ``None`` 而不是全 0，是为了让调用方
    **显式**决定并列时怎么办（这里选"退化为 0，交给 cos 排序"）。
    """
    if not values:
        return None
    lo, hi = min(values), max(values)
    if hi - lo <= 1e-12:
        return None
    return [(v - lo) / (hi - lo) for v in values]


def _encode_query(kb: KnowledgeBase, query: QueryView) -> Optional[List[float]]:
    """用**建库时同一份权重**编码查询。

    模型身份从 ``manifest.embed_model`` 读，可能是 HF 名也可能是仓库内目录（我们用的是后者）。
    任何一步失败都返回 ``None``：宁可退化成"只按 BM25 排序"，也不要拿错模型的向量去比。
    """
    model = kb.embed_model
    if not model:
        return None
    text = _query_text(query)
    if not text.strip():
        return None
    try:
        from sentence_transformers import SentenceTransformer  # type: ignore

        encoder = _ENCODER_CACHE.get(model)
        if encoder is None:
            path = Path(model)
            if not path.is_absolute():
                path = Path(__file__).resolve().parent.parent / path
            encoder = SentenceTransformer(str(path))
            _ENCODER_CACHE[model] = encoder
        vector = encoder.encode([text], normalize_embeddings=True, show_progress_bar=False)[0]
        return [float(x) for x in vector]
    except Exception:  # noqa: BLE001 - 缺依赖/换机器都当作"没有向量"
        return None


_ENCODER_CACHE: Dict[str, Any] = {}


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


__all__ = [
    "VIEWS",
    "INDEX_BASENAME",
    "DEFAULT_COS_WEIGHT",
    "BM25_K1",
    "BM25_B",
    "CWE_MERGE_TABLE",
    "KnowledgeBase",
    "RetrievalResult",
    "load_kb",
    "retrieve_for_case",
]
