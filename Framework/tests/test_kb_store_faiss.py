#!/usr/bin/env python3
"""store.build() 的索引分支回归。

为什么单独成文件
----------------
``kbcore/store.py`` 的 faiss 分支长期标着 ``# pragma: no cover``，**从没被任何测试执行过**
（仓库里只有 ``test_kb_llm_path.py`` 直接构造 ``FlatL2Index``，没有一处让 ``build()`` 在
faiss 在位时跑）。后果是装上 faiss 当天就炸：

    index.add([(i, vec) for i, vec in enumerate(vectors)])
    AttributeError: 'list' object has no attribute 'shape'

本测试锁死三件事：

1. ``backend`` / 落盘后缀与 faiss 可用性一致（``.faiss`` 或 ``.json``）；
2. 建库后能真读回来、真检索，最近邻命中自己；
3. **索引 id 是「每个视图内的序号」，不是 meta 里的全局 ``index_row``** —— 这是
   ``repair/retrieve.py`` 取记录时最容易踩的坑，用断言钉住。

没有 faiss 的环境跳过检索部分（但仍验证 ``flat-python`` 分支与落盘）。
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kbcore.config import KBConfig
from kbcore.store import FAISS_AVAILABLE, build, load_meta
from kbcore.testing import HashingEmbedder

DIM = 384

# 两条 pair × 两个视图 = 4 条记录；root_cause 刻意写得语义不同，便于断言最近邻是自己。
RECORDS = [
    {
        "pair_id": "P1",
        "view_type": "data_flow",
        "cwe": "CWE-125",
        "root_cause": "an external length reaches a copy without a capacity comparison",
    },
    {
        "pair_id": "P1",
        "view_type": "control_flow",
        "cwe": "CWE-125",
        "root_cause": "the loop guard is checked after the redundant index access",
    },
    {
        "pair_id": "P2",
        "view_type": "data_flow",
        "cwe": "CWE-190",
        "root_cause": "an integer multiplication overflows before the allocation size is used",
    },
    {
        "pair_id": "P2",
        "view_type": "control_flow",
        "cwe": "CWE-190",
        "root_cause": "the bounds check compares against a truncated length",
    },
]


def load_index(path: Path):
    """读回索引：faiss 用 read_index，兜底读 FlatL2Index 的 json。"""
    if FAISS_AVAILABLE:
        import faiss  # type: ignore

        return faiss.read_index(str(path))
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return {"rows": raw}


def search(index, vector, k: int):
    """统一的 search 接口，返回 ``[(id, distance), …]``。"""
    if FAISS_AVAILABLE:
        import numpy as np  # type: ignore

        query = np.asarray([vector], dtype="float32")
        dists, ids = index.search(query, k)
        return [(int(i), float(d)) for i, d in zip(ids[0], dists[0])]
    scored = [
        (row["row"], sum((a - b) ** 2 for a, b in zip(vector, row["vec"])))
        for row in index["rows"]
    ]
    return sorted(scored, key=lambda pair: pair[1])[:k]


class BuildIndexTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.out = Path(self._tmp.name) / "kb"
        self.cfg = KBConfig(out_dir=self.out, embed_dim=DIM, kb_ver="kb-test")
        self.records = [dict(r) for r in RECORDS]
        self.embedder = HashingEmbedder(dim=DIM)
        self.result = build(self.cfg, self.records, self.embedder)
        self.manifest = json.loads((self.out / "manifest.json").read_text(encoding="utf-8"))
        self.meta = load_meta(self.out)

    def test_backend_matches_environment(self):
        expected = "faiss" if FAISS_AVAILABLE else "flat-python"
        self.assertEqual(self.result.backend, expected)
        self.assertEqual(self.manifest["backend"], expected)
        self.assertEqual(self.manifest["dim"], DIM)
        self.assertEqual(self.manifest["n_df"], 2)
        self.assertEqual(self.manifest["n_cf"], 2)

    def test_low_quality_embedder_is_recorded(self):
        # HashingEmbedder 不是生产嵌入，manifest 必须如实记账，别让降级库冒充真库
        self.assertEqual(self.manifest["embed_model"], "hashing-ngram")
        self.assertFalse(self.manifest["embed_production"])

    def test_index_files_written(self):
        suffix = ".faiss" if FAISS_AVAILABLE else ".json"
        for view in ("df", "cf"):
            path = self.out / f"kb_{view}{suffix}"
            self.assertTrue(path.exists(), f"缺索引文件 {path.name}")
            self.assertGreater(path.stat().st_size, 0, f"{path.name} 是空文件")
        self.assertEqual(
            self.manifest["index_files"],
            {"data_flow": f"kb_df{suffix}", "control_flow": f"kb_cf{suffix}"},
        )

    def test_meta_rows_are_global_and_sorted(self):
        self.assertEqual(len(self.meta), len(RECORDS))
        # index_row 是排序后的全局序号，从 0 连续
        self.assertEqual([r["index_row"] for r in self.meta], [0, 1, 2, 3])
        # 排序键是 (pair_id, view_type)，而 "control_flow" < "data_flow"（字典序），
        # 所以同一 pair 里 control_flow 排在 data_flow 前面——这个顺序很容易被误记。
        keys = [(r["pair_id"], r["view_type"]) for r in self.meta]
        self.assertEqual(
            keys,
            [
                ("P1", "control_flow"),
                ("P1", "data_flow"),
                ("P2", "control_flow"),
                ("P2", "data_flow"),
            ],
        )

    def test_search_hits_itself_with_per_view_id(self):
        """最近邻命中自己；且返回的 id 是视图内序号，不是全局 index_row。"""
        df_meta = [r for r in self.meta if r["view_type"] == "data_flow"]
        self.assertEqual([r["pair_id"] for r in df_meta], ["P1", "P2"])
        # df 的第一条在视图内是 id 0，全局 index_row 却是 1（因为 P1/control_flow 占了 0）
        self.assertEqual(df_meta[0]["index_row"], 1)

        suffix = ".faiss" if FAISS_AVAILABLE else ".json"
        df_index = load_index(self.out / f"kb_df{suffix}")
        query = self.embedder.encode([df_meta[0]["root_cause"]])[0]
        hits = search(df_index, query, k=2)
        self.assertEqual(hits[0][0], 0, "最近邻不是记录自身（应为视图内序号 0，而非全局 1）")
        self.assertAlmostEqual(hits[0][1], 0.0, places=4)

        # 反向验证：取 P2/data_flow（视图内 id 1、全局 3）也能命中自己
        self.assertEqual(df_meta[1]["index_row"], 3)
        hits2 = search(df_index, self.embedder.encode([df_meta[1]["root_cause"]])[0], k=1)
        self.assertEqual(hits2[0][0], 1)

    def test_vectors_are_normalized_and_reloadable(self):
        """读回的向量与重新编码的向量一致——证明索引里存的确实是 encode 的产物。"""
        suffix = ".faiss" if FAISS_AVAILABLE else ".json"
        index = load_index(self.out / f"kb_df{suffix}")
        df_first = next(r for r in self.meta if r["view_type"] == "data_flow")
        expected = self.embedder.encode([df_first["root_cause"]])[0]
        hits = search(index, expected, k=1)
        self.assertEqual(hits[0][0], 0)
        self.assertAlmostEqual(hits[0][1], 0.0, places=4)


class ResolvedPathsTest(unittest.TestCase):
    def test_relative_out_dir_resolves_against_repo_root(self):
        cfg = KBConfig(out_dir=Path("artifacts/_unused"), kb_ver="x").resolve_paths()
        self.assertTrue(cfg.out_dir.is_absolute())
        self.assertEqual(cfg.out_dir.name, "_unused")


if __name__ == "__main__":
    unittest.main(verbosity=2)
