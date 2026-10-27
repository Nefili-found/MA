#!/usr/bin/env python3
"""``verify_agent.reverify`` 复核执行侧回归。

这里跑的是**真**的 ``check_assumptions`` / ``check_trigger_path``（tree-sitter 解析
真 C 片段），不是打桩——因为复核最容易错的地方就是窗口与行号口径，只有真跑才暴露。

覆盖：
* ``recheck_condition``：``holds=null`` 经复核变成 ``holds=false`` + blocker（真守卫被找到）；
* ``widen_window``：一条假设都没有时窗口不是瓶颈，只记账、不硬造条件；
* ``resolve_reachability``：``unreachable`` 经复核变成 ``reachable``；
* 铁律：**verdict 不动**、**原 case 不被改**、单条 ask 失败不拖垮整轮。

已知边界（写在夹具旁边，因为它决定了夹具怎么起名）
--------------------------------------------------
``verify_taint._KEYWORDS`` 里含英文停用词（``in`` / ``is`` / ``the`` / ``when`` …），
所以变量名恰好叫 ``in`` 时，从假设文本里**永远抽不出这个符号**。夹具因此用 ``src``。
这是检测端的符号抽取边界，reverify 只能在 ``taint_sink`` 里补一行代码来缓解，绕不过去。
"""

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools.call_context import build_context
from verify_agent.reverify import (
    SUPPORTED_KINDS,
    VERIFY_REQUEST_SCHEMA,
    reverify_case,
)

# 守卫在 sink 之前：null 检查覆盖 memcpy
GUARDED = "\n".join(
    [
        "static int decrypt(char *out, const char *src, unsigned int len)",
        "{",
        "    if (src == NULL)",
        "        return -1;",
        "    memcpy(out, src, len);",
        "    return 0;",
        "}",
    ]
)

# 两个函数，outer 调用 inner —— 用来验证触发链复核
TWO_FUNCS = "\n".join(
    [
        "static int inner(char *dst, const char *src, int n)",
        "{",
        "    memcpy(dst, src, n);",
        "    return 0;",
        "}",
        "",
        "static int outer(char *dst, const char *src, int n)",
        "{",
        "    return inner(dst, src, n);",
        "}",
    ]
)


def make_case(func_src: str, *, line: int, func: str, evidence=None) -> dict:
    return {
        "case_id": "CVE-TEST__decrypt",
        "source": {"repo": "OpenSC", "commit": "abc", "file": "src/card.c"},
        "vuln": {
            "cwe": "CWE-125",
            "line": line,
            "line_end": line,
            "func": func,
            "confidence": 0.9,
            "verdict": "accept",
        },
        "code": {
            "func_src": func_src,
            "body_line_start": 1,
            "body_line_end": len(func_src.splitlines()),
            "line_base": "function",
            "line_source": "ast",
            "function_resolved_by": "ast",
        },
        "evidence": {
            "path_status": "",
            "path": [],
            "conditions": [],
            "blockers": [],
            **(evidence or {}),
        },
        "validation": {"ok": True, "errors": []},
    }


def request(*asks, round_no=1) -> dict:
    return {
        "schema": VERIFY_REQUEST_SCHEMA,
        "case_id": "CVE-TEST__decrypt",
        "reason": "insufficient_facts",
        "round": round_no,
        "asks": list(asks),
        "context": {"file": "src/card.c", "line": 5, "func": "decrypt"},
    }


NULL_CONDITION = {
    "id": "cond-1",
    "kind": "null_check",
    "text": "src is null when the sink reads it",
    "holds": None,
    "blocker": None,
    "note": "",
}


class RecheckConditionTest(unittest.TestCase):
    def setUp(self):
        self.case = make_case(
            GUARDED, line=5, func="decrypt", evidence={"conditions": [NULL_CONDITION]}
        )
        self.original = copy.deepcopy(self.case)

    def _ask(self):
        return {
            "kind": "recheck_condition",
            "condition_id": "cond-1",
            "text": "src is null when the sink reads it",
            "hint_line": 5,
        }

    def test_null_condition_becomes_blocked(self):
        out = reverify_case(self.case, request(self._ask()))
        conditions = out["evidence"]["conditions"]
        self.assertEqual(len(conditions), 1)
        self.assertIs(conditions[0]["holds"], False, "真守卫应把 holds 从 null 变成 false")
        self.assertIsNotNone(conditions[0]["blocker"])
        self.assertIn("NULL", conditions[0]["blocker"]["code"])
        self.assertEqual(len(out["evidence"]["blockers"]), 1)
        self.assertTrue(out["reverify"]["improved"])

    def test_verdict_is_never_touched(self):
        out = reverify_case(self.case, request(self._ask()))
        # 铁律 1：只补事实，不改判定
        self.assertEqual(out["vuln"]["verdict"], self.original["vuln"]["verdict"])

    def test_original_case_is_not_mutated(self):
        reverify_case(self.case, request(self._ask()))
        self.assertEqual(self.case, self.original, "复核必须返回新对象，不能就地改传入的 case")

    def test_round_and_reason_are_recorded(self):
        out = reverify_case(self.case, request(self._ask(), round_no=1))
        block = out["reverify"]
        self.assertEqual(block["schema"], VERIFY_REQUEST_SCHEMA)
        self.assertEqual(block["round"], 1)
        self.assertEqual(block["asked"], 1)
        self.assertEqual([d["kind"] for d in block["done"]], ["recheck_condition"])
        self.assertEqual(block["before"]["holds"]["null"], 1)
        self.assertEqual(block["after"]["holds"]["false"], 1)

    def test_validation_is_recomputed(self):
        out = reverify_case(self.case, request(self._ask()))
        self.assertTrue(out["validation"]["ok"])
        self.assertEqual(out["validation"]["errors"], [])


class WidenWindowTest(unittest.TestCase):
    def test_no_assumptions_only_records_a_note(self):
        # 一条假设都没有时 check_assumptions 直接返回"无假设条件"——窗口不是瓶颈
        case = make_case(GUARDED, line=5, func="decrypt")
        ask = {"kind": "widen_window", "function": "decrypt", "detail": "无假设条件"}
        out = reverify_case(case, request(ask))
        self.assertEqual(out["evidence"]["conditions"], [], "不该凭空造出条件")
        self.assertFalse(out["reverify"]["improved"])
        self.assertTrue(any("无假设条件" in n for n in out["reverify"]["notes"]))

    def test_existing_conditions_are_rechecked_over_full_window(self):
        case = make_case(
            GUARDED, line=5, func="decrypt", evidence={"conditions": [NULL_CONDITION]}
        )
        ask = {"kind": "widen_window", "function": "decrypt"}
        out = reverify_case(case, request(ask))
        self.assertIs(out["evidence"]["conditions"][0]["holds"], False)


class ResolveReachabilityTest(unittest.TestCase):
    def test_unreachable_becomes_reachable(self):
        case = make_case(
            TWO_FUNCS, line=9, func="outer", evidence={"path_status": "unreachable"}
        )
        ask = {"kind": "resolve_reachability", "function": "outer", "path": ["outer", "inner"]}
        out = reverify_case(case, request(ask))
        self.assertEqual(out["evidence"]["path_status"], "reachable")
        self.assertGreaterEqual(len(out["evidence"]["path"]), 1)
        self.assertTrue(out["reverify"]["improved"], "unreachable → reachable 应记 improved")

    def test_no_chain_available_means_no_change(self):
        case = make_case(
            GUARDED, line=5, func="decrypt", evidence={"path_status": "unreachable"}
        )
        ask = {"kind": "resolve_reachability", "function": "decrypt"}
        out = reverify_case(case, request(ask))
        self.assertEqual(out["evidence"]["path_status"], "unreachable", "拿不到链就不该改状态")
        self.assertFalse(out["reverify"]["improved"])
        self.assertTrue(any("没有可用的触发链" in n for n in out["reverify"]["notes"]))

    def test_sequence_can_come_from_existing_evidence_path(self):
        path = [{"hop": 0, "from": "outer", "to": "inner", "reachable": None}]
        case = make_case(
            TWO_FUNCS,
            line=9,
            func="outer",
            evidence={"path_status": "unverifiable", "path": path},
        )
        ask = {"kind": "resolve_reachability", "function": "outer"}
        out = reverify_case(case, request(ask))
        self.assertEqual(out["evidence"]["path_status"], "reachable")


class RobustnessTest(unittest.TestCase):
    def test_unsupported_kind_is_skipped_not_fatal(self):
        case = make_case(GUARDED, line=5, func="decrypt")
        out = reverify_case(case, request({"kind": "re_triage_everything"}))
        self.assertEqual(out["reverify"]["done"], [])
        self.assertEqual(len(out["reverify"]["skipped"]), 1)
        self.assertIn("不支持的动作", out["reverify"]["skipped"][0]["why"])
        self.assertEqual(out["reverify"]["skipped"][0]["kind"], "re_triage_everything")
        self.assertEqual(
            set(SUPPORTED_KINDS),
            {"recheck_condition", "resolve_reachability", "widen_window"},
        )

    def test_wrong_schema_raises(self):
        case = make_case(GUARDED, line=5, func="decrypt")
        bad = request({"kind": "widen_window"})
        bad["schema"] = "verify-request/2"
        with self.assertRaises(ValueError):
            reverify_case(case, bad)

    def test_missing_code_window_raises(self):
        case = make_case("", line=1, func="decrypt")
        with self.assertRaises(ValueError):
            reverify_case(case, request({"kind": "widen_window"}))

    def test_explicit_code_and_ctx_override_are_honoured(self):
        case = make_case("/* stale window */", line=5, func="decrypt")
        ctx = build_context(GUARDED)
        ask = {
            "kind": "recheck_condition",
            "condition_id": "cond-1",
            "text": "src is null",
            "hint_line": 5,
        }
        out = reverify_case(case, request(ask), code=GUARDED, ctx=ctx)
        self.assertEqual(len(out["evidence"]["conditions"]), 1)
        self.assertIs(out["evidence"]["conditions"][0]["holds"], False)

    def test_empty_request_is_a_noop(self):
        case = make_case(GUARDED, line=5, func="decrypt")
        out = reverify_case(case, request())
        self.assertEqual(out["reverify"]["done"], [])
        self.assertFalse(out["reverify"]["improved"])
        self.assertEqual(out["evidence"], case["evidence"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
