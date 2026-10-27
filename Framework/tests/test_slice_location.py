#!/usr/bin/env python3
"""切片扫描的行号归一（D5 前置）回归。

背景（真实事故）：拿 APPATCH 的评测切片跑检测端，文件名是
``CWE-125___binutils-gdb_EF12___binutils___dwarf.c___9090-9393___9290.c_vul.c``，
内容只有 304 行；A/B/C 把漏洞行写成原文件坐标 **9290**。于是
``ctx.function_at(9290)`` 返回 ``None`` → ``function_line_start/end`` 缺失 →
``func_src`` 切不出来 → 整个 case 被判 ``invalid_baseline``。

本文件的断言把这个行为钉死：**只在行号超出切片行数时才平移**。
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from verify_agent.location import as_int, normalize_slice_location
from verify_agent.repair_projection import build_repair_input, validate_repair_case

FUNC = "\n".join(
    [
        "static int process(char *buf, unsigned int n)",
        "{",
        "    if (n == 0)",
        "        return -1;",
        "    buf[n - 1] = 0;",
        "    return 0;",
        "}",
    ]
)


def finding(line, line_end=None, **over):
    item = {
        "id": "F-1",
        "cwe": "CWE-125",
        "confidence": 0.9,
        "verdict": "accept",
        "location": {
            "line_start": line,
            "line_end": line_end if line_end is not None else line,
            "function": "process",
            "function_line_start": 1,
            "function_line_end": len(FUNC.splitlines()),
            "line_source": "ast",
            "function_resolved_by": "ast",
        },
        "evidence": {"path_status": "unverifiable", "path": [], "conditions": [], "blockers": []},
    }
    item.update(over)
    return item


class NormalizeSliceLocationTest(unittest.TestCase):
    def test_absolute_line_is_shifted(self):
        # 9090 起、304 行的切片，报出 9290 → 切片内是 201
        out = normalize_slice_location(finding(9290), 9090, 304)
        self.assertEqual(out["location"]["line_start"], 201)
        self.assertEqual(out["location"]["line_end"], 201)
        self.assertEqual(out["location"]["slice_shifted_from"], 9290)

    def test_in_range_line_is_never_touched(self):
        # 模型本来报对了（201 在 304 行内），不能把对的改错
        out = normalize_slice_location(finding(201), 9090, 304)
        self.assertEqual(out["location"]["line_start"], 201)
        self.assertNotIn("slice_shifted_from", out["location"])

    def test_offset_zero_is_a_noop(self):
        out = normalize_slice_location(finding(9290), 0, 304)
        self.assertEqual(out["location"]["line_start"], 9290)

    def test_hopeless_line_is_left_alone(self):
        # 平移后依旧越界 → 不硬凑假行号，交给 resolve_location 标 llm
        out = normalize_slice_location(finding(99999), 9090, 304)
        self.assertEqual(out["location"]["line_start"], 99999)
        self.assertNotIn("slice_shifted_from", out["location"])

    def test_line_range_shifts_together(self):
        out = normalize_slice_location(finding(9290, 9295), 9090, 304)
        self.assertEqual(out["location"]["line_start"], 201)
        self.assertEqual(out["location"]["line_end"], 206)

    def test_end_clamped_to_start_when_end_exceeds_slice(self):
        out = normalize_slice_location(finding(9290, 12000), 9090, 304)
        self.assertEqual(out["location"]["line_start"], 201)
        self.assertEqual(out["location"]["line_end"], 201)

    def test_original_finding_is_not_mutated(self):
        src = finding(9290)
        normalize_slice_location(src, 9090, 304)
        self.assertEqual(src["location"]["line_start"], 9290)


class ProjectionLineBaseTest(unittest.TestCase):
    def test_slice_state_declares_function_line_base(self):
        state = {
            "code": FUNC,
            "rel_file": "other fix framework/datasets/x/vul.c",
            "repo": "demo",
            "commit": "",
            "case_id": "case-1",
            "slice_start": 9090,
            "line_base": "function",
        }
        payload = build_repair_input([finding(5)], "/tmp/vul.c", state)
        code = payload["cases"][0]["code"]
        self.assertEqual(code["line_base"], "function")
        self.assertEqual(code["body_line_start"], 1)
        self.assertEqual(code["body_line_end"], len(FUNC.splitlines()))
        self.assertTrue(code["func_src"], "func_src 不该为空")
        self.assertEqual(validate_repair_case(payload["cases"][0]), [])

    def test_file_state_defaults_to_file_line_base(self):
        state = {
            "code": FUNC,
            "rel_file": "src/demo.c",
            "repo": "demo",
            "commit": "",
            "case_id": "case-2",
            "line_base": "file",
        }
        payload = build_repair_input([finding(5)], "/tmp/demo.c", state)
        self.assertEqual(payload["cases"][0]["code"]["line_base"], "file")

    def test_missing_line_base_falls_back_to_file(self):
        # 老调用方（没传 line_base 的）行为不变：走 file
        state = {
            "code": FUNC,
            "rel_file": "src/demo.c",
            "repo": "demo",
            "commit": "",
            "case_id": "case-3",
        }
        payload = build_repair_input([finding(5)], "/tmp/demo.c", state)
        self.assertEqual(payload["cases"][0]["code"]["line_base"], "file")

    def test_shifted_finding_validates_after_normalisation(self):
        """演示完整链条：先用原文件坐标的 finding 平移，再投影 → 校验通过。"""
        state = {
            "code": FUNC,
            "rel_file": "other fix framework/datasets/x/vul.c",
            "repo": "demo",
            "commit": "",
            "case_id": "case-4",
            "slice_start": 9090,
            "line_base": "function",
        }
        shifted = normalize_slice_location(finding(9094), 9090, len(FUNC.splitlines()))
        self.assertEqual(shifted["location"]["line_start"], 5)
        payload = build_repair_input([shifted], "/tmp/vul.c", state)
        self.assertEqual(validate_repair_case(payload["cases"][0]), [])
        self.assertIn("buf[n - 1]", payload["cases"][0]["code"]["func_src"])

    def test_as_int_is_tolerant(self):
        self.assertEqual(as_int("12"), 12)
        self.assertEqual(as_int(None), 0)
        self.assertEqual(as_int("x"), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
