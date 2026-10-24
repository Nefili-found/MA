"""K2/K4 单测：extract / abstract / gate / pipeline / store（全部用假实现，不联网）。

覆盖的失败模式都是真跑时最容易咬人的那一类：
prompt 里证据段的有无、缓存键漏字段、模型输出带围栏、编造的 API 名、
视图互斥被破坏、成对剔除、索引行号与 meta 对齐。
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kbcore.anchor import locate
from kbcore.cache import Cache, cache_key
from kbcore.config import KBConfig, load_config
from kbcore.extract import BEHAVIOR_FIELD, build_prompt, extract_pair, number_lines, render
from kbcore.gate import check, gate_pair, normalize, prunable_calls
from kbcore.pairs import load_pairs
from kbcore.pipeline import build_records, process_pair
from kbcore.store import build, corpus_sha256, load_meta
from kbcore.testing import FakeLLM, FlatL2Index, HashingEmbedder
from kbcore.views import extract_evidence

DATASET = ROOT / "other fix framework" / "datasets" / "patchdb_cvefixes_for_appatch_train"


def _cfg(tmp: Path, **over) -> KBConfig:
    cfg = load_config()
    cfg.model = "fake-model"
    cfg.pairs_root = DATASET
    cfg.runs_dir = tmp / "runs"
    cfg.cache_dir = tmp / "cache"
    cfg.out_dir = tmp / "out"
    cfg.concurrency = 2
    for key, value in over.items():
        setattr(cfg, key, value)
    return cfg


class PromptRenderTest(unittest.TestCase):
    def setUp(self):
        self.pairs = load_pairs(DATASET, limit=2)
        self.cfg = _cfg(Path(tempfile.mkdtemp()))

    def test_number_lines_uses_real_line_numbers(self):
        text = number_lines("a\nb", start_line=10)
        self.assertIn("10 | a", text)
        self.assertIn("11 | b", text)

    def test_template_uses_dollar_placeholders(self):
        self.assertEqual(render("x=$a y=$b", {"a": 1, "b": 2}), "x=1 y=2")
        # 未提供的占位符保持原样，不抛异常（模板可增量演进）
        self.assertEqual(render("x=$missing", {}), "x=$missing")

    def test_evidence_block_appears_only_when_available(self):
        pair = self.pairs[0]
        anchor = locate(pair)
        ev = extract_evidence(pair, anchor)
        with_ev = build_prompt(self.cfg, pair, anchor, ev, "data_flow")
        self.assertIn("Structural evidence", with_ev)
        without_ev = build_prompt(self.cfg, pair, anchor, None, "data_flow")
        self.assertNotIn("Structural evidence", without_ev)

    def test_view_prompts_differ(self):
        pair = self.pairs[0]
        anchor = locate(pair)
        df = build_prompt(self.cfg, pair, anchor, None, "data_flow")
        cf = build_prompt(self.cfg, pair, anchor, None, "control_flow")
        self.assertNotEqual(df, cf)
        self.assertIn("data-flow", df)
        self.assertIn("control-flow", cf)


class CacheKeyTest(unittest.TestCase):
    def test_key_changes_with_every_input(self):
        base = cache_key("extract", "p", "data_flow", "pv1", "m", 0.0, 1024, "tree_sitter", "ev")
        variants = [
            cache_key("extract", "p2", "data_flow", "pv1", "m", 0.0, 1024, "tree_sitter", "ev"),
            cache_key("extract", "p", "control_flow", "pv1", "m", 0.0, 1024, "tree_sitter", "ev"),
            cache_key("extract", "p", "data_flow", "pv2", "m", 0.0, 1024, "tree_sitter", "ev"),
            cache_key("extract", "p", "data_flow", "pv1", "m2", 0.0, 1024, "tree_sitter", "ev"),
            cache_key("extract", "p", "data_flow", "pv1", "m", 0.7, 1024, "tree_sitter", "ev"),
            cache_key("extract", "p", "data_flow", "pv1", "m", 0.0, 1024, "none", "ev"),
            cache_key("extract", "p", "data_flow", "pv1", "m", 0.0, 1024, "tree_sitter", "ev2"),
        ]
        self.assertEqual(len({base, *variants}), 8)

    def test_cache_roundtrip_and_disable(self):
        tmp = Path(tempfile.mkdtemp())
        cache = Cache(tmp, enabled=True)
        self.assertIsNone(cache.get("k"))
        cache.put("k", {"v": 1})
        self.assertEqual(cache.get("k"), {"v": 1})
        off = Cache(tmp, enabled=False)
        off.put("k2", {"v": 2})
        self.assertIsNone(off.get("k2"))


class ExtractTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cfg = _cfg(self.tmp)
        self.pairs = load_pairs(DATASET, limit=2)
        self.cache = Cache(self.cfg.cache_dir, enabled=True)

    def test_fenced_json_is_parsed(self):
        pair = self.pairs[0]
        anchor = locate(pair)
        ev = extract_evidence(pair, anchor)
        payload = (
            "```json\n"
            '{"root_cause": "a length reaches a copy unchecked", "risky_calls": ["memcpy"],'
            ' "taint_flow": "input length to copy size", "fixing_strategy": "compare before copy"}\n'
            "```"
        )
        llm = FakeLLM({"extract:data_flow": [payload], "extract:control_flow": []})
        raw = extract_pair(self.cfg, pair, anchor, ev, llm, self.cache)
        self.assertEqual(raw.df["root_cause"], "a length reaches a copy unchecked")
        self.assertIsNotNone(raw.cf.get("control_branch"))

    def test_retry_on_missing_key(self):
        pair = self.pairs[0]
        anchor = locate(pair)
        bad = '{"root_cause": "", "risky_calls": []}'
        good = (
            '{"root_cause": "an unchecked length reaches a copy", "risky_calls": [],'
            ' "taint_flow": "length to copy", "fixing_strategy": "validate first"}'
        )
        llm = FakeLLM({"extract:data_flow": [bad, good]})
        raw = extract_pair(self.cfg, pair, anchor, None, llm, self.cache)
        self.assertEqual(raw.df["root_cause"], "an unchecked length reaches a copy")
        # 第二次调用必须带纠正提示
        self.assertIn("rejected", llm.calls[1]["user"])

    def test_cache_prevents_second_call(self):
        pair = self.pairs[1]
        anchor = locate(pair)
        ev = extract_evidence(pair, anchor)
        llm = FakeLLM()
        extract_pair(self.cfg, pair, anchor, ev, llm, self.cache)
        calls_first = len(llm.calls)
        raw2 = extract_pair(self.cfg, pair, anchor, ev, FakeLLM(), self.cache)
        self.assertTrue(raw2.cache_hit)
        self.assertEqual(calls_first, 2)  # 两个视图各一次调用

    def test_failure_raises_after_retries(self):
        pair = self.pairs[0]
        anchor = locate(pair)
        llm = FakeLLM({"extract:data_flow": ["not json", "still not json"]})
        with self.assertRaises(ValueError):
            extract_pair(self.cfg, pair, anchor, None, llm, self.cache)


class GateTest(unittest.TestCase):
    def setUp(self):
        self.cfg = _cfg(Path(tempfile.mkdtemp()))
        self.pair = load_pairs(DATASET, limit=1)[0]

    def _record(self, **over):
        base = {
            "root_cause": "an unchecked length reaches a copy",
            "risky_calls": ["memcpy"],
            "taint_flow": "length to copy size",
            "fixing_strategy": "validate the length first",
        }
        base.update(over)
        return base

    def test_clean_record_passes(self):
        self.assertEqual(check(self.cfg, self.pair, self._record(), "data_flow"), [])

    def test_view_exclusivity_enforced(self):
        problems = check(self.cfg, self.pair, self._record(control_branch="x"), "data_flow")
        self.assertTrue(any("视图互斥" in p for p in problems))

    def test_missing_behavior_field(self):
        record = self._record()
        record.pop("taint_flow")
        self.assertTrue(any("taint_flow" in p for p in check(self.cfg, self.pair, record, "data_flow")))

    def test_invented_calls_are_dropped(self):
        present = self.pair.func  # 函数名必然出现在源码里
        record = self._record(risky_calls=[present, "totally_made_up_api"])
        dropped = prunable_calls(self.pair, record)
        self.assertEqual(dropped, ["totally_made_up_api"])
        cleaned, dropped2 = normalize(self.cfg, self.pair, record, "data_flow")
        self.assertEqual(cleaned["risky_calls"], [present])
        self.assertEqual(dropped2, ["totally_made_up_api"])

    def test_pair_gate_is_all_or_nothing(self):
        df = self._record()
        cf = self._record(taint_flow=None, control_branch="guard ordering")
        cf.pop("taint_flow")
        ok, cleaned, problems, dropped = gate_pair(
            self.cfg, self.pair, {"data_flow": df, "control_flow": cf}
        )
        self.assertTrue(ok)
        self.assertIsNone(cleaned["control_flow"]["taint_flow"])

        bad_cf = dict(cf)
        bad_cf["root_cause"] = ""
        ok2, _, problems2, _ = gate_pair(
            self.cfg, self.pair, {"data_flow": df, "control_flow": bad_cf}
        )
        self.assertFalse(ok2)
        self.assertTrue(problems2["control_flow"])


class PipelineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cfg = _cfg(self.tmp)

    def test_process_pair_produces_two_records(self):
        pair = load_pairs(DATASET, limit=1)[0]
        outcome = process_pair(self.cfg, pair, FakeLLM(), Cache(self.cfg.cache_dir, enabled=False))
        self.assertTrue(outcome.ok)
        self.assertEqual(len(outcome.records), 2)
        views = {r["view_type"] for r in outcome.records}
        self.assertEqual(views, {"data_flow", "control_flow"})
        for record in outcome.records:
            behavior = BEHAVIOR_FIELD[record["view_type"]]
            other = BEHAVIOR_FIELD["control_flow" if record["view_type"] == "data_flow" else "data_flow"]
            self.assertTrue(record[behavior])
            self.assertIsNone(record[other])
            self.assertEqual(record["cwe"], pair.cwe)
            self.assertTrue(record["vuln_code"])
            self.assertEqual(record["index_row"], -1)

    def test_build_records_stats(self):
        pairs = load_pairs(DATASET, limit=3)
        records, rejects, stats = build_records(
            self.cfg, pairs, FakeLLM(), cache=Cache(self.cfg.cache_dir, enabled=False)
        )
        self.assertEqual(len(records), 6)
        self.assertEqual(rejects, [])
        self.assertEqual(stats.pairs_ok, 3)
        self.assertEqual(stats.evidence_func + stats.evidence_file + stats.evidence_none, 3)

    def test_evidence_mode_none_still_works(self):
        cfg = _cfg(self.tmp, evidence_mode="none")
        pair = load_pairs(DATASET, limit=1)[0]
        outcome = process_pair(cfg, pair, FakeLLM(), Cache(cfg.cache_dir, enabled=False))
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.evidence_scope, "none")
        self.assertEqual({r["evidence"] for r in outcome.records}, {"none"})


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cfg = _cfg(self.tmp)

    def test_build_writes_meta_manifest_and_index_alignment(self):
        pairs = load_pairs(DATASET, limit=4)
        records, _, stats = build_records(
            self.cfg, pairs, FakeLLM(), cache=Cache(self.cfg.cache_dir, enabled=False)
        )
        embedder = HashingEmbedder(dim=self.cfg.embed_dim)
        result = build(self.cfg, records, embedder, stats=stats)

        meta = load_meta(result.out_dir)
        self.assertEqual(len(meta), 8)
        self.assertEqual([r["index_row"] for r in meta], list(range(8)))
        # 两库同序：DF 记录与 CF 记录各占一半，且 row 与 meta 位置一致
        for row, record in enumerate(meta):
            self.assertEqual(record["pair_id"], meta[row]["pair_id"])
        self.assertTrue(result.manifest_path.exists())
        manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["dim"], self.cfg.embed_dim)
        self.assertEqual(manifest["metric"], "l2")
        self.assertEqual(manifest["n_df"] + manifest["n_cf"], 8)
        self.assertEqual(manifest["corpus_sha256"], corpus_sha256(meta))
        self.assertIn("cwe_counts", manifest)

    def test_manifest_is_written_last(self):
        """manifest 存在 = 构建成功：中途失败不应留下它。"""
        records = []
        embedder = HashingEmbedder(dim=self.cfg.embed_dim)
        result = build(self.cfg, records, embedder)
        self.assertTrue(result.manifest_path.exists())
        self.assertEqual(load_meta(result.out_dir), [])

    def test_flat_index_orders_by_distance(self):
        index = FlatL2Index(dim=3)
        index.add([(0, [1.0, 0.0, 0.0]), (1, [0.0, 1.0, 0.0]), (2, [0.9, 0.1, 0.0])])
        hits = index.search([1.0, 0.0, 0.0], k=2)
        self.assertEqual([row for row, _ in hits], [0, 2])
        self.assertLessEqual(hits[0][1], hits[1][1])


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
