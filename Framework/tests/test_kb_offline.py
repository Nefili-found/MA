"""K0/K1 单测：pairs / anchor / views / abstraction（全部无网络、无 LLM）。

跑法（本仓库的 .venv 没有 pytest，所以用标准库 unittest）：
    .venv/Scripts/python.exe -m pytest tests/test_kb_offline.py -q      # 有 pytest 时
    .venv/Scripts/python.exe -m unittest tests.test_kb_offline -v       # 无 pytest 时
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common.abstraction import abstraction_violations, free_identifiers, strip_non_code
from kbcore.anchor import CROSSCHECK_TOLERANCE, crosscheck_with_ast, locate
from kbcore.pairs import KNOWN_CWES, cwe_histogram, load_pairs, parse_pair_id
from kbcore.views import extract_evidence, find_function

DATASET = ROOT / "other fix framework" / "datasets" / "patchdb_cvefixes_for_appatch_train"

# 实测基线（设计文档 §1.1 / §1.3；数字变了说明数据集被换过）
EXPECTED_PAIRS = 306
EXPECTED_CWE = {"CWE-125": 45, "CWE-190": 58, "CWE-401": 21, "CWE-457": 19, "CWE-476": 70, "CWE-787": 93}
EXPECTED_REPLACE = 183
EXPECTED_INSERT_ONLY = 123


class ParsePairIdTest(unittest.TestCase):
    def test_with_cve_and_commit(self):
        meta = parse_pair_id(
            "CWE-125_CVE-2018-16392_OpenSC_360e95d45ac4123255a4c796db96337f332160ad_decrypt_response"
        )
        self.assertEqual(meta["cwe"], "CWE-125")
        self.assertEqual(meta["cve"], "CVE-2018-16392")
        self.assertEqual(meta["repo"], "OpenSC")
        self.assertEqual(meta["func"], "decrypt_response")
        self.assertTrue(meta["commit"].startswith("360e95d4"))

    def test_patchdb_without_cve(self):
        meta = parse_pair_id(
            "CWE-125_PatchDB_31d4f3a2f3c73f279ff96a7135d7202ef6833f12_ext4_valid_extent"
        )
        self.assertEqual(meta["cve"], "")
        self.assertEqual(meta["commit"], "31d4f3a2f3c73f279ff96a7135d7202ef6833f12")
        self.assertEqual(meta["repo"], "PatchDB")
        self.assertEqual(meta["func"], "ext4_valid_extent")

    def test_func_keeps_underscores(self):
        meta = parse_pair_id(
            "CWE-125_CVE-2014-3184_linux_4ab25786c87eb20857bbb715c3ae34ec8fd6a214_kye_report_fixup"
        )
        self.assertEqual(meta["func"], "kye_report_fixup")

    def test_missing_cwe_raises(self):
        with self.assertRaises(ValueError):
            parse_pair_id("CVE-2018-16392_OpenSC_deadbeef_foo")

    def test_missing_both_ids_raises(self):
        with self.assertRaises(ValueError):
            parse_pair_id("CWE-125_whatever")


class DatasetTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pairs = load_pairs(DATASET)
        cls.by_id = {p.pair_id: p for p in cls.pairs}

    def test_pair_count_and_cwe_histogram(self):
        self.assertEqual(len(self.pairs), EXPECTED_PAIRS)
        self.assertEqual(cwe_histogram(self.pairs), EXPECTED_CWE)
        self.assertEqual(set(EXPECTED_CWE), set(KNOWN_CWES))

    def test_every_pair_has_both_files(self):
        for pair in self.pairs:
            self.assertTrue(pair.vul_src.strip(), pair.pair_id)
            self.assertTrue(pair.non_src.strip(), pair.pair_id)
            self.assertNotEqual(pair.vul_src, pair.non_src, pair.pair_id)

    def test_ast_artifacts_only_on_subset(self):
        with_ast = sum(1 for p in self.pairs if p.has_ast_artifacts)
        self.assertEqual(with_ast, 103)

    def test_limit_and_ordering(self):
        first = load_pairs(DATASET, limit=3)
        self.assertEqual([p.pair_id for p in first], [p.pair_id for p in self.pairs[:3]])

    def test_unknown_cwe_guard(self):
        # 本数据集只有六个 CWE；allow_unknown_cwe=False 时不得静默放行
        self.assertTrue(all(p.cwe in KNOWN_CWES for p in self.pairs))


class AnchorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pairs = load_pairs(DATASET)

    def test_kind_distribution_matches_baseline(self):
        kinds = {"replace": 0, "insert_only": 0, "delete_only": 0}
        for pair in self.pairs:
            kinds[locate(pair).kind] += 1
        self.assertEqual(kinds["replace"], EXPECTED_REPLACE)
        self.assertEqual(kinds["insert_only"], EXPECTED_INSERT_ONLY)
        self.assertEqual(kinds["delete_only"], 0)

    def test_single_change_region(self):
        for pair in self.pairs[:60]:
            self.assertEqual(locate(pair).extra_ops, 0, pair.pair_id)

    def test_line_ranges_are_sane(self):
        for pair in self.pairs[:60]:
            anchor = locate(pair)
            self.assertGreaterEqual(anchor.vul_start, 1)
            self.assertLessEqual(anchor.vul_end, len(pair.vul_lines))
            self.assertGreaterEqual(anchor.new_start, 1)
            self.assertLessEqual(anchor.new_end, len(pair.non_lines))

    def test_crosscheck_hits_on_artifact_subset(self):
        hits = misses = 0
        for pair in self.pairs:
            anchor = locate(pair)
            result = crosscheck_with_ast(pair, anchor)
            if result is None:
                continue
            if result:
                hits += 1
            else:
                misses += 1
        self.assertEqual(hits, 103)
        self.assertEqual(misses, 0)

    def test_crosscheck_returns_none_without_artifact(self):
        pair = next(p for p in self.pairs if not p.has_ast_artifacts)
        self.assertIsNone(crosscheck_with_ast(pair, locate(pair)))


class ViewsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pairs = load_pairs(DATASET)
        cls.sample = cls.pairs[0]

    def test_evidence_available_for_all_pairs(self):
        missing = [p.pair_id for p in self.pairs if extract_evidence(p, locate(p)) is None]
        self.assertEqual(missing, [])

    def test_scope_is_function_or_file(self):
        scopes = {extract_evidence(p, locate(p)).scope for p in self.pairs[:40]}
        self.assertTrue(scopes <= {"function", "file"})
        self.assertIn("function", scopes)

    def test_literal_c_fragment(self):
        """手工构造的片段：验证 guards 顺序、defs 最近优先、calls 提取。"""

        class FakePair:
            pair_id = "synthetic"
            cwe = "CWE-787"
            cve = ""
            repo = ""
            func = "f"
            commit = ""
            vul_src = (
                "int copy(char *dst, const char *src, int n)\n"
                "{\n"
                "    int len = n;\n"
                "    if (len > 0) {\n"
                "        for (int i = 0; i < len; i++) {\n"
                "            if (src[i] == 0) { return -1; }\n"
                "            memcpy(dst + i, src + i, 1);\n"
                "        }\n"
                "    }\n"
                "    return len;\n"
                "}\n"
            )
            non_src = vul_src.replace("memcpy(dst + i", "if (i < 8) memcpy(dst + i")
            artifacts = {}

            @property
            def vul_lines(self):
                return self.vul_src.splitlines()

            @property
            def non_lines(self):
                return self.non_src.splitlines()

        pair = FakePair()
        anchor = locate(pair)
        ev = extract_evidence(pair, anchor)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.scope, "function")
        # 外层 if 在前、内层 for 在后
        guard_lines = [g.line for g in ev.cf.guards]
        self.assertEqual(guard_lines[:2], [4, 5])
        # defs：变更语句上的 i 取自 for 初始化声明（第 5 行，最近的前置定义）
        self.assertIn(5, [d.line for d in ev.df.defs])
        # 变更语句上的标识符集合应含 dst / src / i
        self.assertTrue({"dst", "src", "i"} <= set(ev.df.idents))
        # 参数与外部 API
        self.assertIn("dst", ev.df.params)
        self.assertIn("memcpy", [c.code for c in ev.df.calls])

    def test_parse_error_degrades_to_file_scope(self):
        class BrokenPair:
            pair_id = "broken"
            cwe = "CWE-190"
            cve = ""
            repo = ""
            func = "f"
            commit = ""
            vul_src = "state { A, B }\nint x = 1;\n"
            non_src = "state { A, B }\nint x = 2;\n"
            artifacts = {}

            @property
            def vul_lines(self):
                return self.vul_src.splitlines()

            @property
            def non_lines(self):
                return self.non_src.splitlines()

        ev = extract_evidence(BrokenPair(), locate(BrokenPair()))
        self.assertIsNotNone(ev)
        self.assertEqual(ev.scope, "file")


class AbstractionTest(unittest.TestCase):
    SRC = """
    int handle(char *dst, int count)
    {
        /* parse cipher length */
        int real_len = count;
        memcpy(dst, &real_len, 4);
        return real_len;
    }
    """

    def test_comment_words_are_not_identifiers(self):
        self.assertNotIn("length", free_identifiers(self.SRC))
        self.assertEqual(abstraction_violations("the parse cipher length is wrong", self.SRC), [])

    def test_concrete_identifier_is_flagged(self):
        hits = abstraction_violations("real_len is used without a bounds check", self.SRC)
        self.assertEqual(hits, ["real_len"])

    def test_prose_allowed_words_pass(self):
        self.assertIn("count", free_identifiers(self.SRC, include_prose_words=False))
        self.assertEqual(abstraction_violations("the destination capacity is not compared", self.SRC), [])

    def test_stdlib_and_keywords_ignored(self):
        idents = free_identifiers("int x = strlen(s) + sizeof(int);")
        self.assertNotIn("strlen", idents)
        self.assertNotIn("sizeof", idents)

    def test_strip_non_code_keeps_code(self):
        stripped = strip_non_code(self.SRC)
        self.assertNotIn("cipher length", stripped)
        self.assertIn("real_len", stripped)


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
