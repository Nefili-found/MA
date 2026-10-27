#!/usr/bin/env python3
"""``repair.retrieve`` 检索层回归 —— 重点是旧实现的三处硬伤各自一个反例。

三处硬伤（设计稿 §7）与本文对应的反例：

============================  ==========================================
硬伤                          反例
============================  ==========================================
无 CWE 硬过滤                  池里混两个 CWE，断言命中全是目标 CWE
BM25 clip 到 [0,1] 导致并列    构造"两条 raw 都 > 1 但值不同"的池，断言归一后不并列
去重 key 用 ``id(meta)``       池里放两份同 ``(pair_id, view_type)`` 的记录，断言只留一条
============================  ==========================================

知识库用 ``kbcore.store.build`` 真实建（``ScriptedEmbedder`` 控制向量），所以
``meta.jsonl`` / 索引文件 / ``manifest.json`` 都是真产物，不是打桩。
"""

import math
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kbcore.config import KBConfig
from kbcore.store import build
from kbcore.testing import ScriptedEmbedder
from repair.retrieve import (
    CWE_MERGE_TABLE,
    DEFAULT_COS_WEIGHT,
    KnowledgeBase,
    load_kb,
    retrieve_for_case,
)
from repair.schema import QueryView

DIM = 4


def unit(*comps):
    norm = math.sqrt(sum(c * c for c in comps)) or 1.0
    return [c / norm for c in comps]


E0, E1, E2, E3 = unit(1, 0, 0, 0), unit(0, 1, 0, 0), unit(0, 0, 1, 0), unit(0, 0, 0, 1)


def record(pair_id, cwe, root_cause, *, view="data_flow", **extra):
    base = {"pair_id": pair_id, "view_type": view, "cwe": cwe, "root_cause": root_cause}
    base.update(extra)
    return base


def build_kb(tmp: Path, records, *, vectors) -> KnowledgeBase:
    cfg = KBConfig(out_dir=tmp / "kb", embed_dim=DIM, kb_ver="test")
    embedder = ScriptedEmbedder(vectors, dim=DIM)
    build(cfg, [dict(r) for r in records], embedder)
    return load_kb(tmp / "kb")


def query_for(text: str, *, view="data_flow", risky=()) -> QueryView:
    return QueryView(view_type=view, root_cause=text, risky_calls=list(risky))


class BaseCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)


class CweHardFilterTest(BaseCase):
    def test_pool_is_restricted_to_target_cwe(self):
        records = [
            record("P1", "CWE-125", "bounds check off by one"),
            record("P2", "CWE-190", "integer overflow before allocation"),
            record("P3", "CWE-125", "index used before bounds comparison"),
            record("P4", "CWE-476", "null dereference without a check"),
        ]
        vectors = {r["root_cause"]: v for r, v in zip(records, (E0, E1, E2, E3))}
        kb = build_kb(self.tmp, records, vectors=vectors)

        result = retrieve_for_case(kb, query_for("bounds check off by one"),
                                   "CWE-125", top_k=4, query_vector=E0)
        self.assertEqual(result.pool_size, 2, "池里应只剩两条 CWE-125")
        self.assertTrue(result.hits)
        self.assertEqual({h.cwe for h in result.hits}, {"CWE-125"})

    def test_empty_pool_when_cwe_absent(self):
        records = [record("P1", "CWE-125", "bounds check off by one")]
        kb = build_kb(self.tmp, records, vectors={"bounds check off by one": E0})
        result = retrieve_for_case(kb, query_for("anything"), "CWE-787", query_vector=E0)
        self.assertEqual(result.pool_size, 0)
        self.assertEqual(result.hits, [])
        self.assertTrue(any("池为空" in n for n in result.notes))

    def test_missing_target_cwe_is_flagged(self):
        records = [record("P1", "CWE-125", "bounds check off by one")]
        kb = build_kb(self.tmp, records, vectors={"bounds check off by one": E0})
        result = retrieve_for_case(kb, query_for("x"), "", query_vector=E0)
        self.assertTrue(any("target_cwe 为空" in n for n in result.notes))

    def test_merge_table_is_off_by_default(self):
        records = [
            record("P1", "CWE-416", "pointer used after free"),
            record("P2", "CWE-401", "allocation result never released"),
        ]
        vectors = {r["root_cause"]: v for r, v in zip(records, (E0, E1))}
        kb = build_kb(self.tmp, records, vectors=vectors)

        strict = retrieve_for_case(kb, query_for("x"), "CWE-401", query_vector=E0)
        self.assertEqual([h.pair_id for h in strict.hits], ["P2"], "严格相等：只应命中 CWE-401")

        merged = retrieve_for_case(kb, query_for("x"), "CWE-401", cwe_merge=True, query_vector=E0)
        self.assertEqual({h.pair_id for h in merged.hits}, {"P1", "P2"},
                         "开归并后 CWE-401 与 CWE-416 同池")
        self.assertEqual(CWE_MERGE_TABLE["CWE-401"], "CWE-416")


class Bm25PoolNormalisationTest(BaseCase):
    """反例：旧实现的 clip 会把两条 raw>1 的分数压成并列 1.0。"""

    def _kb(self):
        records = [
            record("P1", "CWE-1", "alpha bounds alpha check missing here"),
            record("P2", "CWE-1", "alpha guard present"),
            record("P3", "CWE-1", "beta gamma delta"),
            record("P4", "CWE-1", "beta gamma epsilon"),
            record("P5", "CWE-1", "zeta eta theta"),
            record("P6", "CWE-1", "iota kappa lambda"),
        ]
        vectors = {r["root_cause"]: v for r, v in zip(records, (E0, E1, E2, E3, E0, E1))}
        return build_kb(self.tmp, records, vectors=vectors)

    def test_no_tie_after_minmax(self):
        kb = self._kb()
        query = query_for("alpha")
        # query_vector=None + manifest.embed_model="hashing-ngram" ⇒ 编码失败，退化成纯 BM25 排序
        result = retrieve_for_case(kb, query, "CWE-1", top_k=6, cos_weight=0.0)

        above_one = [h for h in result.hits if h.bm25_raw > 1.0]
        self.assertGreaterEqual(len(above_one), 2,
                                "反例前提：至少两条 raw BM25 > 1（clip 会把它们压成并列 1.0）")
        values = {round(h.bm25, 6) for h in above_one}
        self.assertGreater(len(values), 1, "池内 min-max 后这两条不该并列")

    def test_higher_raw_means_higher_normalised(self):
        kb = self._kb()
        result = retrieve_for_case(kb, query_for("alpha"), "CWE-1", top_k=6, cos_weight=0.0)
        ordered = sorted(result.hits, key=lambda h: -h.bm25_raw)
        self.assertEqual([h.pair_id for h in ordered], [h.pair_id for h in result.hits],
                         "cos_weight=0 时排序应与 raw BM25 单调一致")
        self.assertAlmostEqual(max(h.bm25 for h in result.hits), 1.0, places=6)
        self.assertAlmostEqual(min(h.bm25 for h in result.hits), 0.0, places=6)

    def test_all_equal_bm25_degrades_to_zero_with_note(self):
        records = [record(f"P{i}", "CWE-1", "identical text") for i in range(3)]
        vectors = {"identical text": E0}
        kb = build_kb(self.tmp, records, vectors=vectors)
        result = retrieve_for_case(kb, query_for("nothing matches"), "CWE-1", query_vector=E1)
        self.assertTrue(any("池内 BM25 全部相等" in n for n in result.notes))
        self.assertTrue(all(h.bm25 == 0.0 for h in result.hits))


class DedupeTest(BaseCase):
    def test_same_pair_and_view_kept_once(self):
        # 库里同一 (pair_id, view_type) 出现两次——旧实现用 id(meta) 去重会漏掉
        records = [
            record("P1", "CWE-1", "alpha bounds check missing", index_row=0),
            record("P1", "CWE-1", "alpha alpha bounds check completely missing", index_row=1),
            record("P2", "CWE-1", "beta gamma", index_row=2),
        ]
        vectors = {r["root_cause"]: v for r, v in zip(records, (E0, E1, E2))}
        kb = build_kb(self.tmp, records, vectors=vectors)
        result = retrieve_for_case(kb, query_for("alpha bounds"), "CWE-1",
                                   top_k=5, query_vector=E0)
        pair_ids = [h.pair_id for h in result.hits]
        self.assertEqual(pair_ids.count("P1"), 1, "同 (pair_id, view_type) 只能留一条")
        self.assertEqual(len(pair_ids), len(set(pair_ids)))
        self.assertTrue(any("去重" in n for n in result.notes))

    def test_dedup_keeps_the_better_ranked_copy(self):
        records = [
            record("P1", "CWE-1", "weak match", index_row=0),
            record("P1", "CWE-1", "alpha alpha alpha", index_row=1),
        ]
        vectors = {r["root_cause"]: v for r, v in zip(records, (E3, E0))}
        kb = build_kb(self.tmp, records, vectors=vectors)
        result = retrieve_for_case(kb, query_for("alpha"), "CWE-1",
                                   top_k=2, cos_weight=0.0, query_vector=E0)
        self.assertEqual(result.hits[0].index_row, 1, "应保留打分更高的那一份")


class FusionAndCosTest(BaseCase):
    def test_cos_conversion_from_squared_l2(self):
        records = [
            record("P1", "CWE-1", "identical to query"),
            record("P2", "CWE-1", "opposite to query"),
        ]
        vectors = {"identical to query": E0, "opposite to query": unit(-1, 0, 0, 0)}
        kb = build_kb(self.tmp, records, vectors=vectors)
        result = retrieve_for_case(kb, query_for("identical to query"), "CWE-1",
                                   top_k=2, query_vector=E0)
        by_id = {h.pair_id: h for h in result.hits}
        self.assertAlmostEqual(by_id["P1"].cos, 1.0, places=5)
        self.assertAlmostEqual(by_id["P2"].cos, -1.0, places=5)

    def test_score_is_the_documented_blend(self):
        records = [
            record("P1", "CWE-1", "alpha bounds check missing"),
            record("P2", "CWE-1", "beta gamma delta"),
        ]
        vectors = {r["root_cause"]: v for r, v in zip(records, (E0, E1))}
        kb = build_kb(self.tmp, records, vectors=vectors)
        result = retrieve_for_case(kb, query_for("alpha"), "CWE-1", top_k=2, query_vector=E0)
        for hit in result.hits:
            expected = DEFAULT_COS_WEIGHT * hit.cos + (1 - DEFAULT_COS_WEIGHT) * hit.bm25
            self.assertAlmostEqual(hit.score, expected, places=6)

    def test_cos_weight_is_recorded(self):
        records = [record("P1", "CWE-1", "alpha")]
        kb = build_kb(self.tmp, records, vectors={"alpha": E0})
        result = retrieve_for_case(kb, query_for("alpha"), "CWE-1",
                                   cos_weight=0.55, query_vector=E0)
        self.assertAlmostEqual(result.cos_weight, 0.55)
        payload = result.to_dict()
        self.assertAlmostEqual(payload["cos_weight"], 0.55)
        self.assertEqual(payload["kb_ver"], "test")
        self.assertTrue(payload["corpus_sha256"])


class RankingTest(BaseCase):
    def test_top_k_and_descending_order(self):
        records = [record(f"P{i}", "CWE-1", "alpha " * (i + 1)) for i in range(5)]
        vectors = {r["root_cause"]: unit(1, i * 0.1, 0, 0) for i, r in enumerate(records)}
        kb = build_kb(self.tmp, records, vectors=vectors)
        result = retrieve_for_case(kb, query_for("alpha"), "CWE-1", top_k=3, query_vector=E0)
        self.assertEqual(len(result.hits), 3)
        self.assertEqual([h.rank for h in result.hits], [1, 2, 3])
        scores = [h.score for h in result.hits]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_view_isolation(self):
        records = [
            record("P1", "CWE-1", "data flow cause", view="data_flow"),
            record("P1", "CWE-1", "control flow cause", view="control_flow"),
        ]
        vectors = {"data flow cause": E0, "control flow cause": E1}
        kb = build_kb(self.tmp, records, vectors=vectors)
        result = retrieve_for_case(kb, query_for("control flow cause", view="control_flow"),
                                   "CWE-1", query_vector=E1)
        self.assertEqual(result.view_type, "control_flow")
        self.assertEqual(len(result.hits), 1)


class RealKbSmokeTest(unittest.TestCase):
    """对着真实的标定库跑一次（``.cache/`` 被 gitignore，缺了自动跳过）。"""

    CALIB = ROOT / ".cache" / "calib_kb"

    def setUp(self):
        if not (self.CALIB / "meta.jsonl").exists():
            self.skipTest(f"缺标定库 {self.CALIB}（先跑 kbcore.cli build --per-cwe 3）")

    def test_real_calib_kb(self):
        kb = load_kb(self.CALIB)
        self.assertIn(kb.backend, ("faiss", "flat-python"))
        self.assertEqual(len(kb.meta), 36)
        manifest_cwe = (kb.manifest.get("cwe_counts") or {})
        self.assertEqual(sum(manifest_cwe.values()), 36)

        target = sorted(manifest_cwe)[0]
        query = query_for("an externally supplied length reaches a copy without comparison")
        result = retrieve_for_case(kb, query, target, top_k=4)
        self.assertEqual(result.kb_ver, "calib")
        self.assertTrue(result.corpus_sha256)
        self.assertGreater(result.pool_size, 0, f"{target} 在标定库里应有候选")
        self.assertEqual({h.cwe for h in result.hits}, {target})
        self.assertLessEqual(len(result.hits), 4)
        for hit in result.hits:
            self.assertGreaterEqual(hit.cos, -1.0)
            self.assertLessEqual(hit.cos, 1.0)
            self.assertGreaterEqual(hit.bm25, 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
