#!/usr/bin/env python3
"""``repair.intake`` 入口层回归。

覆盖三件事：

1. **两类输入都归一得对**：``repair-input/1`` JSON 与评测集索引 JSONL；
2. **入口判定五档逐一走到**：检测端自检、``line_base``、CWE 规范串、verdict、放行；
3. **真实数据的分档结果**：121 条 held-out case 里 104 条可用、17 条被上游的坏锚点挡下。

第 3 条的期望值是**从数据实测得来的硬事实**，不是为了让测试变绿而挑的数：
``test_data/build_repair_eval_cases.py`` 统计出 ``anchor_ok: 104/121``，而坏锚点
（漏洞行指向空行/花括号/未记录）正好是 ``validate_repair_case`` 会拦的形态。
数据集一变这个断言就该红 —— 那是数据变了，不是测试写错。
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from repair.intake import (
    DEFAULT_LINE_BASE,
    accepted,
    evaluate_entry,
    gate,
    load_eval_cases,
    load_repair_input,
    resolve_line_base,
    summary,
)
from repair.schema import (
    ENTRY_ACCEPTED,
    ENTRY_INVALID,
    ENTRY_SKIPPED,
    CaseOutcome,
    RepairCase,
    cwe_key,
    is_canonical_cwe,
)

EVAL_CASES = ROOT / "test_data" / "repair_eval_cases.jsonl"


def make_raw(**over) -> dict:
    """构造一个**合法**的 ``repair-input/1`` case，便于逐项破坏。"""
    func = "\n".join(
        [
            "static int decrypt(struct s *s, unsigned char *out, unsigned int len)",
            "{",
            "    if (s == NULL)",
            "        return -1;",
            "    memcpy(out, s->buf, len);",
            "    return 0;",
            "}",
        ]
    )
    raw = {
        "case_id": "CVE-TEST__decrypt",
        "source": {"repo": "OpenSC", "commit": "abc123", "file": "src/card.c"},
        "vuln": {
            "cwe": "CWE-125",
            "line": 5,
            "line_end": 5,
            "func": "decrypt",
            "confidence": 0.86,
            "verdict": "accept",
        },
        "code": {
            "func_src": func,
            "body_line_start": 1,
            "body_line_end": 7,
            "line_base": "function",
            "line_source": "ast",
            "function_resolved_by": "ast",
        },
        "evidence": {"path_status": "", "path": [], "conditions": [], "blockers": []},
        "validation": {"ok": True, "errors": []},
    }
    for key, value in over.items():
        if isinstance(value, dict) and isinstance(raw.get(key), dict):
            raw[key] = {**raw[key], **value}
        else:
            raw[key] = value
    return raw


class RepairInputLoadingTest(unittest.TestCase):
    def _write(self, payload: dict) -> Path:
        tmp = tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        )
        json.dump(payload, tmp, ensure_ascii=False)
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        return Path(tmp.name)

    def test_loads_and_freezes_meta(self):
        path = self._write(
            {
                "schema": "repair-input/1",
                "generated_at": "2026-10-24T00:00:00Z",
                "provenance": {"case_count": 1},
                "cases": [make_raw()],
            }
        )
        meta, cases = load_repair_input(path)
        self.assertEqual(meta["schema"], "repair-input/1")
        self.assertEqual(meta["case_count"], 1)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].case_id, "CVE-TEST__decrypt")
        self.assertEqual(cases[0].origin, "repair-input/1")

    def test_rejects_wrong_schema(self):
        path = self._write({"schema": "repair-input/0", "cases": []})
        with self.assertRaises(ValueError):
            load_repair_input(path)

    def test_missing_line_base_is_inferred_not_guessed(self):
        raw = make_raw()
        del raw["code"]["line_base"]
        path = self._write({"schema": "repair-input/1", "cases": [raw]})
        _, cases = load_repair_input(path)
        case = cases[0]
        self.assertEqual(case.code.line_base, DEFAULT_LINE_BASE)
        self.assertEqual(case.code.line_base_source, "inferred")

    def test_explicit_line_base_is_kept(self):
        path = self._write({"schema": "repair-input/1", "cases": [make_raw()]})
        _, cases = load_repair_input(path)
        self.assertEqual(cases[0].code.line_base, "function")
        self.assertEqual(cases[0].code.line_base_source, "explicit")


class EntryGateTest(unittest.TestCase):
    def _gate(self, raw: dict):
        case = resolve_line_base(RepairCase.from_dict(raw))
        return case, evaluate_entry(case)

    def test_accepts_good_case(self):
        case, intake = self._gate(make_raw())
        self.assertTrue(intake.accepted)
        self.assertEqual(intake.kind, ENTRY_ACCEPTED)
        self.assertEqual(case.anchor_text, "memcpy(out, s->buf, len);")

    def test_detection_self_check_false_blocks(self):
        raw = make_raw(validation={"ok": False, "errors": ["vuln.line 指向空行"]})
        _, intake = self._gate(raw)
        self.assertFalse(intake.accepted)
        self.assertEqual(intake.kind, ENTRY_INVALID)
        self.assertIn("detection_validation", intake.reason)

    def test_detection_error_without_validation_block_also_blocks(self):
        # 没有透传 validation 时，入口自己跑检测端六条校验
        raw = make_raw()
        del raw["validation"]
        raw["code"]["body_line_end"] = 99  # 行数与 func_src 不符
        _, intake = self._gate(raw)
        self.assertEqual(intake.kind, ENTRY_INVALID)

    def test_line_base_function_requires_body_start_one(self):
        raw = make_raw(code={"body_line_start": 18, "body_line_end": 24, "line_base": "function"})
        raw["vuln"]["line"] = 22
        _, intake = self._gate(raw)
        self.assertEqual(intake.kind, ENTRY_INVALID)
        self.assertIn("line_base", intake.reason)

    def test_line_base_file_requires_source_file(self):
        raw = make_raw(code={"line_base": "file"}, source={"file": ""})
        _, intake = self._gate(raw)
        self.assertEqual(intake.kind, ENTRY_INVALID)
        self.assertIn("line_base", intake.reason)

    def test_non_canonical_cwe_blocks(self):
        # 设计稿 §4.1 的判定顺序里检测端自检在最前，所以这类输入拦在 detection_validation；
        # 入口自己的 cwe 检查是第二道保险（见 intake.py 的注释）。
        raw = make_raw(vuln={"cwe": "CWE 越界读"})
        _, intake = self._gate(raw)
        self.assertEqual(intake.kind, ENTRY_INVALID)
        self.assertIn("detection_validation", intake.reason)
        self.assertFalse(is_canonical_cwe(cwe_key("CWE 越界读")))

    def test_uncertain_verdict_is_skipped_not_invalid(self):
        raw = make_raw(vuln={"verdict": "uncertain"})
        _, intake = self._gate(raw)
        self.assertFalse(intake.accepted)
        self.assertEqual(intake.kind, ENTRY_SKIPPED)
        self.assertIn("verdict", intake.reason)

    def test_accept_verdicts_is_configurable(self):
        raw = make_raw(vuln={"verdict": "uncertain"})
        case = resolve_line_base(RepairCase.from_dict(raw))
        intake = evaluate_entry(case, accept_verdicts=("accept", "uncertain"))
        self.assertTrue(intake.accepted)

    def test_gate_keeps_rejected_cases_for_accounting(self):
        good = resolve_line_base(RepairCase.from_dict(make_raw()))
        bad = resolve_line_base(RepairCase.from_dict(make_raw(vuln={"verdict": "reject"})))
        cases = gate([good, bad])
        self.assertEqual(len(cases), 2, "未通过的 case 也要留下记账，不能静默丢弃")
        self.assertEqual(len(accepted(cases)), 1)


class CweKeyTest(unittest.TestCase):
    """``cwe_key`` 是 C3 硬过滤的键：写歪 = 检索恒空集，所以单独立测。"""

    def test_normalizes_real_world_variants(self):
        # 检测端实测会给 "CWE-787 越界写" 这类带中文后缀的变体
        self.assertEqual(cwe_key("CWE-787 越界写"), "CWE-787")
        self.assertEqual(cwe_key("cwe_401"), "CWE-401")
        self.assertEqual(cwe_key("CWE 457"), "CWE-457")
        self.assertEqual(cwe_key("cwe-125"), "CWE-125")

    def test_unparseable_becomes_empty(self):
        self.assertEqual(cwe_key("越界读"), "")
        self.assertEqual(cwe_key(None), "")
        self.assertEqual(cwe_key(""), "")

    def test_canonical_check(self):
        self.assertTrue(is_canonical_cwe("CWE-125"))
        self.assertFalse(is_canonical_cwe("CWE-125 "))  # 尾空格也算不规范，先经 cwe_key 归一
        self.assertFalse(is_canonical_cwe(""))


class EvalCaseLoadingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not EVAL_CASES.exists():
            raise unittest.SkipTest(f"缺 {EVAL_CASES}，先跑 test_data/build_repair_eval_cases.py")
        cls.cases = gate(load_eval_cases(EVAL_CASES))
        cls.summary = summary(cls.cases)

    def test_counts_by_origin(self):
        self.assertEqual(len(self.cases), 121)
        self.assertEqual(self.summary["by_origin"], {"extractfix": 24, "zeroday": 97})

    def test_all_are_function_line_base(self):
        self.assertEqual(self.summary["line_base"], {"function/explicit": 121})

    def test_gate_outcome_matches_upstream_anchor_quality(self):
        # 上游 17 条坏锚点（line=0 / 空行 / 花括号）被检测端六条校验挡下
        self.assertEqual(self.summary["by_kind"][ENTRY_ACCEPTED], 104)
        self.assertEqual(self.summary["by_kind"][ENTRY_INVALID], 17)
        self.assertNotIn(ENTRY_SKIPPED, self.summary["by_kind"])

    def test_accepted_cases_have_usable_anchor(self):
        for case in accepted(self.cases):
            self.assertTrue(case.anchor_text, f"{case.case_id} 锚点为空却通过了入口")
            self.assertNotIn(case.anchor_text, ("{", "}", "};"))
            self.assertEqual(case.code.body_line_start, 1)
            self.assertGreaterEqual(case.vuln_line_local, 1)
            self.assertLessEqual(case.vuln_line_local, case.code.line_count)

    def test_case_ids_unique(self):
        ids = [c.case_id for c in self.cases]
        self.assertEqual(len(ids), len(set(ids)))

    def test_rejected_reasons_are_all_detection_side(self):
        reasons = self.summary["by_reason"]
        self.assertEqual(set(reasons), {"detection_validation"})


class OutcomeContractTest(unittest.TestCase):
    def test_case_outcome_validates_final_and_rounds(self):
        ok = CaseOutcome(case_id="x", entry_kind=ENTRY_ACCEPTED, final="insufficient_facts")
        self.assertEqual(ok.validate(), [])

        bad_final = CaseOutcome(case_id="x", final="修好了")
        self.assertTrue(any("final 非法" in e for e in bad_final.validate()))

        bad_rounds = CaseOutcome(case_id="x", reverify_rounds=2)
        self.assertTrue(any("reverify_rounds" in e for e in bad_rounds.validate()))

    def test_case_outcome_roundtrips(self):
        outcome = CaseOutcome(
            case_id="x", origin="extractfix", entry_kind=ENTRY_ACCEPTED, final="success"
        )
        payload = json.loads(json.dumps(outcome.to_dict(), ensure_ascii=False))
        self.assertEqual(payload["reverify"], {"requested": False, "rounds": 0, "improved": False})


if __name__ == "__main__":
    unittest.main(verbosity=2)
