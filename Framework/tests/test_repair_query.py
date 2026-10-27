#!/usr/bin/env python3
"""``repair.query`` 检索键构建回归。

本文件的核心断言只有一条：**骨架字段来自事实与 AST，不来自 LLM**。
做法是让 FakeLLM 返回一句与骨架毫无关系的话（甚至一句"banana"），然后检查
``risky_calls`` / ``taint_flow`` / ``control_branch`` / ``evidence_refs`` 依旧正确。
只要哪天有人把某一步挪回 LLM，这些断言会立刻红。
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kbcore.testing import FakeLLM
from repair.query import (
    DEGRADED_SOURCE_LINES,
    MAX_BEHAVIOR_CHARS,
    build_query,
    collect_risky_calls,
)
from repair.schema import (
    Dropped,
    FactSet,
    Protected,
    Reach,
    RepairCase,
    RequiredGap,
    Sufficiency,
)

# 变量名刻意选 ``secret_len`` / ``dstbuf``：它们不在 ``common.abstraction`` 的
# PROSE_ALLOWED 白名单里，所以拿它们写 root_cause 一定会被判抽象度违例。
FUNC = "\n".join(
    [
        "static int copy_into(char *dstbuf, const char *src, unsigned int secret_len)",
        "{",
        "    if (dstbuf == NULL)",
        "        return -1;",
        "    unsigned int n = strlen(src);",
        "    memcpy(dstbuf, src, secret_len);",
        "    return 0;",
        "}",
    ]
)

CLEAN_CAUSE = (
    "an externally supplied length is used to copy into the destination buffer "
    "without comparing it with the destination capacity"
)
DIRTY_CAUSE = "the secret_len is used to copy into dstbuf without a capacity comparison"


def make_case() -> RepairCase:
    return RepairCase.from_dict(
        {
            "case_id": "CVE-TEST__copy_into",
            "source": {"repo": "demo", "commit": "abc", "file": "src/demo.c"},
            "vuln": {
                "cwe": "CWE-787",
                "line": 6,
                "line_end": 6,
                "func": "copy_into",
                "confidence": 0.9,
                "verdict": "accept",
            },
            "code": {
                "func_src": FUNC,
                "body_line_start": 1,
                "body_line_end": len(FUNC.splitlines()),
                "line_base": "function",
            },
            "evidence": {"path_status": "reachable", "conditions": [], "blockers": []},
            "validation": {"ok": True, "errors": []},
        }
    )


def make_facts(**over) -> FactSet:
    facts = FactSet(
        required_gaps=[
            RequiredGap(id="cond-1", kind="bounds_check", text="外部长度未与目标容量比较", anchor_line=6)
        ],
        protected=[Protected(id="cond-2", kind="null_check", line=3, code="if (dstbuf == NULL)", symbol="dstbuf")],
        reach=Reach(status="reachable", chain=["main", "copy_into"]),
        dropped=[Dropped(id="cond-3", reason="holds=null（无法核）")],
        sufficiency=Sufficiency(ok=True, why="required_gaps=1"),
    )
    for key, value in over.items():
        setattr(facts, key, value)
    return facts


def llm_script(**per_view) -> FakeLLM:
    """按 ``data_flow`` / ``control_flow`` 给每次调用排队脚本。"""
    return FakeLLM(script={f"repair_query:{view}": list(texts) for view, texts in per_view.items()})


def json_cause(text: str) -> str:
    return json.dumps({"root_cause": text})


class SkeletonFromFactsTest(unittest.TestCase):
    def setUp(self):
        self.case = make_case()
        self.facts = make_facts()
        self.llm = llm_script(
            data_flow=[json_cause(CLEAN_CAUSE)], control_flow=[json_cause(CLEAN_CAUSE)]
        )
        self.pair = build_query(self.case, self.facts, self.llm)

    def test_two_views_are_produced(self):
        self.assertEqual(set(self.pair.views), {"data_flow", "control_flow"})
        self.assertFalse(self.pair.degraded)
        self.assertEqual(self.pair.degraded_reason, "")

    def test_risky_calls_come_from_ast(self):
        calls = self.pair.views["data_flow"].risky_calls
        self.assertIn("memcpy", calls)
        self.assertIn("strlen", calls)
        self.assertNotIn("copy_into", calls, "不该把自己算成 sibling call")
        # 两个视图共享同一份 AST 结果
        self.assertEqual(calls, self.pair.views["control_flow"].risky_calls)

    def test_taint_flow_is_templated_from_reach_and_gaps(self):
        taint = self.pair.views["data_flow"].taint_flow
        self.assertIn("reach: main -> copy_into", taint)
        self.assertIn("外部长度未与目标容量比较", taint)
        self.assertIsNone(self.pair.views["control_flow"].taint_flow, "CF 视图不该带 taint_flow")

    def test_control_branch_is_templated_from_kinds_and_protected(self):
        branch = self.pair.views["control_flow"].control_branch
        self.assertIn("missing bounds_check", branch)
        # 措辞是"强化这个守卫"而非"别动它"：检测端证明不了守卫够不够严
        self.assertIn("existing null_check on dstbuf at line 3", branch)
        self.assertIn("do not bypass it", branch)
        self.assertIn("strengthen it if too weak", branch)
        self.assertIn("if (dstbuf == NULL)", branch)
        self.assertIsNone(self.pair.views["data_flow"].control_branch, "DF 视图不该带 control_branch")

    def test_evidence_refs_point_at_real_facts(self):
        for view in self.pair.views.values():
            self.assertEqual(view.evidence_refs, ["cond-1", "cond-2"])
            for ref in view.evidence_refs:
                self.assertIn(ref, {"cond-1", "cond-2"})

    def test_root_cause_is_the_only_llm_output(self):
        for view in self.pair.views.values():
            self.assertEqual(view.root_cause, CLEAN_CAUSE)


class SkeletonIsNotFromLlmTest(unittest.TestCase):
    """LLM 返回一句毫不相关的话，骨架字段也必须一字不变。"""

    def test_irrelevant_reply_does_not_change_skeleton(self):
        case, facts = make_case(), make_facts()
        self.llm = FakeLLM(
            script={
                "repair_query:data_flow": [json_cause("banana")],
                "repair_query:control_flow": [json_cause("banana")],
            }
        )
        pair = build_query(case, facts, self.llm)
        self.assertEqual(pair.views["data_flow"].root_cause, "banana")
        self.assertIn("reach: main -> copy_into", pair.views["data_flow"].taint_flow)
        self.assertIn("missing bounds_check", pair.views["control_flow"].control_branch)
        self.assertEqual(pair.views["data_flow"].risky_calls, ["strlen", "memcpy"])

    def test_prompt_carries_the_facts(self):
        # 事实必须真的进了 prompt，否则模型无从遵守 1–3 步的骨架
        case, facts = make_case(), make_facts()
        llm = llm_script(data_flow=[json_cause(CLEAN_CAUSE)], control_flow=[json_cause(CLEAN_CAUSE)])
        build_query(case, facts, llm)
        users = [c["user"] for c in llm.calls]
        self.assertEqual(len(users), 2)
        for user in users:
            self.assertIn("MISSING (verified absent)", user)
            self.assertIn("EXISTING GUARD on `dstbuf` at line 3", user)
            self.assertIn("REACH: main -> copy_into", user)
            self.assertIn("CWE-787", user)
            self.assertIn("copy_into", user)


class AbstractionGateTest(unittest.TestCase):
    def test_violation_is_retried_once_then_accepted(self):
        case, facts = make_case(), make_facts()
        llm = llm_script(
            data_flow=[json_cause(DIRTY_CAUSE), json_cause(CLEAN_CAUSE)],
            control_flow=[json_cause(CLEAN_CAUSE)],
        )
        pair = build_query(case, facts, llm)
        self.assertEqual(pair.views["data_flow"].root_cause, CLEAN_CAUSE)
        self.assertEqual(pair.views["data_flow"].degraded_reason, "")
        self.assertFalse(pair.degraded)
        # 第二次调用的 prompt 里应带违例反馈
        retry_prompt = [c for c in llm.calls if c["tag"] == "repair_query:data_flow"][1]["user"]
        self.assertIn("leaked implementation identifiers", retry_prompt)
        self.assertIn("secret_len", retry_prompt)

    def test_persistent_violation_degrades(self):
        case, facts = make_case(), make_facts()
        llm = llm_script(
            data_flow=[json_cause(DIRTY_CAUSE), json_cause(DIRTY_CAUSE)],
            control_flow=[json_cause(CLEAN_CAUSE)],
        )
        pair = build_query(case, facts, llm)
        view = pair.views["data_flow"]
        self.assertTrue(pair.degraded)
        self.assertIn("abstraction_violation", view.degraded_reason)
        self.assertIn("secret_len", view.degraded_reason)
        # 降级值 = func_src 前 200 行原文
        self.assertEqual(view.root_cause, "\n".join(FUNC.splitlines()[:DEGRADED_SOURCE_LINES]))
        # 另一个视图不受牵连
        self.assertEqual(pair.views["control_flow"].root_cause, CLEAN_CAUSE)
        self.assertEqual(pair.views["control_flow"].degraded_reason, "")

    def test_unparseable_output_twice_degrades_with_its_own_reason(self):
        case, facts = make_case(), make_facts()
        llm = llm_script(
            data_flow=["not json at all", "still not json"],
            control_flow=[json_cause(CLEAN_CAUSE)],
        )
        pair = build_query(case, facts, llm)
        self.assertIn("llm_output_unusable", pair.views["data_flow"].degraded_reason)
        self.assertTrue(pair.degraded)


class NoLlmTest(unittest.TestCase):
    def test_without_llm_everything_degrades_but_skeleton_survives(self):
        pair = build_query(make_case(), make_facts(), None)
        self.assertTrue(pair.degraded)
        for view in pair.views.values():
            self.assertIn("no_llm", view.degraded_reason)
            self.assertEqual(view.root_cause, "\n".join(FUNC.splitlines()[:DEGRADED_SOURCE_LINES]))
        self.assertIn("reach: main -> copy_into", pair.views["data_flow"].taint_flow)
        self.assertEqual(pair.views["data_flow"].risky_calls, ["strlen", "memcpy"])


class SkeletonEdgeCaseTest(unittest.TestCase):
    def test_empty_facts_yield_no_behavior_text(self):
        pair = build_query(make_case(), FactSet(), None)
        self.assertIsNone(pair.views["data_flow"].taint_flow)
        self.assertIsNone(pair.views["control_flow"].control_branch)

    def test_behavior_text_is_clipped(self):
        long_gap = RequiredGap(id="cond-1", kind="bounds_check", text="x" * 600, anchor_line=6)
        facts = FactSet(required_gaps=[long_gap], sufficiency=Sufficiency(ok=True, why="x"))
        pair = build_query(make_case(), facts, None)
        self.assertLessEqual(len(pair.views["data_flow"].taint_flow), MAX_BEHAVIOR_CHARS)

    def test_unreachable_does_not_claim_reachability(self):
        facts = make_facts(reach=Reach(status="unreachable", chain=[]))
        pair = build_query(make_case(), facts, None)
        self.assertNotIn("reach:", (pair.views["data_flow"].taint_flow or "").lower())


class ControlArmTest(unittest.TestCase):
    """对照臂（``source="none"``）：同一套下游，只把"检测端事实"这一个变量拿掉。"""

    def test_no_facts_reach_the_prompt_or_the_skeletons(self):
        case, facts = make_case(), make_facts()
        llm = llm_script(
            data_flow=[json_cause(CLEAN_CAUSE)], control_flow=[json_cause(CLEAN_CAUSE)]
        )
        pair = build_query(case, facts, llm, source="none")

        self.assertEqual(pair.source, "none")
        self.assertIsNone(pair.views["data_flow"].taint_flow)
        self.assertIsNone(pair.views["control_flow"].control_branch)
        self.assertEqual(pair.views["data_flow"].evidence_refs, [])
        self.assertEqual(pair.views["control_flow"].evidence_refs, [])

        for call in llm.calls:
            self.assertNotIn("Verified facts", call["user"])
            self.assertNotIn("MISSING (verified absent)", call["user"])
            self.assertNotIn("EXISTING GUARD", call["user"])
            # 事实里的原句都不该漏进去
            self.assertNotIn("外部长度未与目标容量比较", call["user"])

    def test_ast_risky_calls_are_kept_in_the_control_arm(self):
        # 刻意的单变量消融：AST 来自代码本身，不属于"检测端事实"
        case, facts = make_case(), make_facts()
        llm = llm_script(
            data_flow=[json_cause(CLEAN_CAUSE)], control_flow=[json_cause(CLEAN_CAUSE)]
        )
        pair = build_query(case, facts, llm, source="none")
        self.assertEqual(pair.views["data_flow"].risky_calls, ["strlen", "memcpy"])

    def test_code_block_is_present_in_both_arms(self):
        case, facts = make_case(), make_facts()
        llm = llm_script(
            data_flow=[json_cause(CLEAN_CAUSE)], control_flow=[json_cause(CLEAN_CAUSE)]
        )
        build_query(case, facts, llm, source="none")
        build_query(case, facts, llm_script(
            data_flow=[json_cause(CLEAN_CAUSE)], control_flow=[json_cause(CLEAN_CAUSE)]
        ), source="evidence")
        for call in llm.calls:
            self.assertIn("secret_len", call["user"], "两臂都该看到代码本体")

    def test_evidence_arm_still_carries_facts(self):
        case, facts = make_case(), make_facts()
        llm = llm_script(
            data_flow=[json_cause(CLEAN_CAUSE)], control_flow=[json_cause(CLEAN_CAUSE)]
        )
        pair = build_query(case, facts, llm)
        self.assertEqual(pair.source, "evidence")
        self.assertIn("Verified facts", llm.calls[0]["user"])
        self.assertEqual(pair.views["data_flow"].evidence_refs, ["cond-1", "cond-2"])

    def test_unknown_source_raises(self):
        with self.assertRaises(ValueError):
            build_query(make_case(), make_facts(), None, source="llm")


class RiskyCallsTest(unittest.TestCase):
    def test_respects_limit_and_dedupes(self):
        many = "\n".join(
            [
                "static int fan(char *dst, const char *src)",
                "{",
                "    a1(); a2(); a1();",
                "    b1(); b2(); b3(); b4(); b5(); b6();",
                "    return 0;",
                "}",
            ]
        )
        case = RepairCase.from_dict(
            {
                "case_id": "x",
                "source": {"file": "x.c"},
                "vuln": {"cwe": "CWE-787", "line": 3, "line_end": 3, "func": "fan", "verdict": "accept"},
                "code": {"func_src": many, "body_line_start": 1, "body_line_end": 6,
                         "line_base": "function"},
                "evidence": {"path_status": ""},
            }
        )
        calls = collect_risky_calls(case, limit=8)
        self.assertEqual(len(calls), 8, "上限 8 与知识库 gate.max_calls 对齐")
        self.assertEqual(len(set(calls)), len(calls), "不应有重复")
        self.assertEqual(calls[0], "a1", "应按首次调用行排序")

    def test_empty_code_is_safe(self):
        case = RepairCase.from_dict(
            {
                "case_id": "x",
                "source": {"file": "x.c"},
                "vuln": {"cwe": "CWE-787", "line": 1, "verdict": "accept"},
                "code": {"func_src": "", "body_line_start": 1, "body_line_end": 1},
                "evidence": {},
            }
        )
        self.assertEqual(collect_risky_calls(case), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
