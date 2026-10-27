#!/usr/bin/env python3
"""``repair.report`` 报告层回归。

报告层的唯一职责是**如实渲染**已有记录，不重算任何指标。所以测试只关心：
计数对不对、空集合会不会崩、被挡下的 case 会不会混进判分表。
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from repair.report import (
    compare_arms,
    render_control_comparison,
    render_judging_table,
    summarize,
    write_all,
)


def record(case_id="C1", *, final="retrieved", hits=2, sufficient=True, kind="accepted",
           degraded=False, reverified=False, improved=False, pool=5, cwe="CWE-125"):
    view_hits = [
        {
            "pair_id": f"{cwe}_P{i}",
            "view_type": "data_flow",
            "cwe": cwe,
            "rank": i + 1,
            "cos": 0.9 - i * 0.1,
            "bm25": 1.0 - i * 0.2,
            "bm25_raw": 12.5 - i,
            "score": 0.8 - i * 0.1,
            "index_row": i,
        }
        for i in range(hits)
    ]
    retrieval = {
        "data_flow": {"view_type": "data_flow", "hits": view_hits, "pool_size": pool},
    }
    return {
        "case": {
            "case_id": case_id,
            "vuln": {"cwe": cwe, "verdict": "uncertain"},
            "code": {"line_base": "function"},
            "anchor_text": "memcpy (dst, src, len);",
        },
        "outcome": {
            "case_id": case_id,
            "entry_kind": kind,
            "entry_reason": "" if sufficient else "verdict='uncertain'",
            "final": final,
            "facts_sufficiency": "ok" if sufficient else "insufficient",
            "facts_sufficiency_why": "protected=1（已有针对同符号的守卫）",
            "query_degraded": degraded,
            "reverify": {"requested": reverified, "rounds": 1 if reverified else 0,
                         "improved": improved},
        },
        "query": {
            "views": {
                "data_flow": {
                    "root_cause": "an externally supplied length reaches a copy",
                    "evidence_refs": ["cond-1"],
                    "degraded_reason": "no_llm" if degraded else "",
                }
            }
        },
        "retrieval": retrieval,
        "facts": {},
    }


class SummarizeTest(unittest.TestCase):
    def test_empty_is_safe(self):
        summary = summarize([])
        self.assertEqual(summary["cases"], 0)
        self.assertEqual(summary["by_final"], {})
        self.assertEqual(summary["pool_size_avg"], 0.0)
        self.assertEqual(summary["hits_total"], 0)

    def test_counts_are_grouped(self):
        records = [
            record("C1", final="retrieved", hits=2),
            record("C2", final="no_match", hits=0),
            record("C3", final="insufficient_facts", hits=0, sufficient=False),
            record("C4", final="invalid_baseline", hits=0, kind="invalid_baseline"),
        ]
        summary = summarize(records)
        self.assertEqual(summary["cases"], 4)
        self.assertEqual(summary["by_final"]["retrieved"], 1)
        self.assertEqual(summary["by_final"]["no_match"], 1)
        self.assertEqual(summary["by_final"]["insufficient_facts"], 1)
        self.assertEqual(summary["by_final"]["invalid_baseline"], 1)
        self.assertEqual(summary["hits_total"], 2)
        self.assertEqual(summary["cases_with_hits"], 1)

    def test_reverify_and_degrade_are_counted(self):
        summary = summarize([
            record("C1", reverified=True, improved=True, degraded=True),
            record("C2"),
        ])
        self.assertEqual(summary["reverify_requested"], 1)
        self.assertEqual(summary["reverify_improved"], 1)
        self.assertEqual(summary["query_degraded"], 1)

    def test_pool_size_stats(self):
        summary = summarize([record("C1", pool=3), record("C2", pool=7)])
        self.assertEqual(summary["pool_size_min"], 3)
        self.assertEqual(summary["pool_size_max"], 7)
        self.assertAlmostEqual(summary["pool_size_avg"], 5.0)


class JudgingTableTest(unittest.TestCase):
    def test_hits_become_rows_with_empty_judge_column(self):
        text = render_judging_table([record("C1", hits=2)])
        self.assertIn("## C1", text)
        self.assertIn("| rank | pair_id | CWE | cos | bm25 | bm25_raw | score | 判为同类? |", text)
        self.assertIn("CWE-125_P0", text)
        self.assertIn("_no_match_" if False else "CWE-125_P1", text)
        # 判分列必须留空（人填），不能预先写成 Y
        row = [line for line in text.splitlines() if "CWE-125_P0" in line][0]
        self.assertTrue(row.rstrip().endswith("|"))
        self.assertNotIn("| Y |", row)

    def test_rejected_case_shows_reason_and_no_hit_table(self):
        text = render_judging_table([
            record("C9", final="invalid_baseline", hits=0, kind="invalid_baseline", sufficient=False)
        ])
        self.assertIn("未进入检索", text)
        self.assertNotIn("| rank |", text)

    def test_no_hits_shows_placeholder(self):
        text = render_judging_table([record("C2", final="no_match", hits=0)])
        self.assertIn("_无命中_", text)

    def test_degraded_query_is_flagged(self):
        text = render_judging_table([record("C1", degraded=True)])
        self.assertIn("降级", text)
        self.assertIn("no_llm", text)


class ControlComparisonTest(unittest.TestCase):
    """对照臂对比：只度量"变了多少"，不度量"变准多少"。"""

    def _pair(self, case_id, main_ids, control_ids):
        def build(ids):
            return {
                "case": {"case_id": case_id},
                "retrieval": {
                    "data_flow": {
                        "pool_size": 10,
                        "hits": [
                            {"pair_id": pid, "rank": i + 1, "cwe": "CWE-1", "cos": 0.5,
                             "bm25": 0.5, "bm25_raw": 3.0, "score": 0.5, "index_row": i}
                            for i, pid in enumerate(ids)
                        ],
                    }
                },
            }

        return build(main_ids), build(control_ids)

    def test_same_top1_is_counted(self):
        main, control = self._pair("C1", ["A", "B"], ["A", "C"])
        comparison = compare_arms([main], [control])
        self.assertEqual(comparison["views_compared"], 2, "两个视图都会算（缺的那个当空）")
        self.assertEqual(comparison["same_top1"], 1)
        self.assertEqual(comparison["overlap_total"], 1)

    def test_different_top1_is_counted(self):
        main, control = self._pair("C1", ["A", "B"], ["B", "A"])
        comparison = compare_arms([main], [control])
        self.assertEqual(comparison["same_top1"], 0)
        self.assertEqual(comparison["overlap_total"], 2, "交集按集合算，与顺序无关")
        self.assertEqual(comparison["changed_top1"], 2)

    def test_one_arm_only_having_hits(self):
        main, control = self._pair("C1", ["A"], [])
        comparison = compare_arms([main], [control])
        self.assertGreaterEqual(comparison["main_only_views"], 1)
        self.assertEqual(comparison["control_only_views"], 0)

    def test_pool_identical_flag(self):
        main, control = self._pair("C1", ["A"], ["A"])
        self.assertTrue(compare_arms([main], [control])["pool_identical"])

    def test_render_states_control_data_is_discarded(self):
        main, control = self._pair("C1", ["A"], ["B"])
        text = render_control_comparison(compare_arms([main], [control]))
        self.assertIn("用完即弃", text)
        self.assertIn("不能", text)
        self.assertIn("| 对比视图数 |", text)


class WriteAllTest(unittest.TestCase):
    def test_three_products_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = [record("C1", hits=1)]
            paths = write_all(tmp, records, top_k=4)
            for key in ("cases", "judging", "summary"):
                self.assertTrue(paths[key].exists(), f"缺 {key}")
            lines = paths["cases"].read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["case"]["case_id"], "C1")
            summary = json.loads(paths["summary"].read_text(encoding="utf-8"))
            self.assertEqual(summary["cases"], 1)

    def test_empty_batch_still_writes_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_all(tmp, [], top_k=4)
            self.assertEqual(paths["cases"].read_text(encoding="utf-8"), "")
            self.assertIn("# R1 检索判分表", paths["judging"].read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
