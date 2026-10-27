#!/usr/bin/env python3
"""``repair.facts`` 事实层回归。

``evidence`` 的字段形状不是猜的：``conditions[i]`` 的 ``{id, kind, text, holds, blocker, note}``
与 ``blockers[i]`` 的 ``{line, kind, pattern, symbol, code}`` 取自
``tools/verify_taint.py::check_assumptions`` 的返回值，并用 ``output/final_report.json``
里一条真实 finding 校对过；``path[i]`` 的 ``{hop, from, to, reachable, ...}`` 取自
``check_trigger_path``。
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from repair.facts import (
    VERIFY_REQUEST_SCHEMA,
    build_facts,
    build_reverify_request,
    reverify_needed,
)
from repair.schema import RepairCase

FUNC = "\n".join(
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


def make_case(evidence=None, *, verdict="accept", cwe="CWE-125") -> RepairCase:
    raw = {
        "case_id": "CVE-TEST__decrypt",
        "source": {"repo": "OpenSC", "commit": "abc", "file": "src/card.c"},
        "vuln": {
            "cwe": cwe,
            "line": 5,
            "line_end": 5,
            "func": "decrypt",
            "confidence": 0.9,
            "verdict": verdict,
        },
        "code": {
            "func_src": FUNC,
            "body_line_start": 1,
            "body_line_end": 7,
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
    return RepairCase.from_dict(raw)


def cond(cid, holds, *, kind="bounds_check", text="外部长度未与目标容量比较", blocker=None) -> dict:
    return {"id": cid, "kind": kind, "text": text, "holds": holds, "blocker": blocker, "note": ""}


BLOCKER = {
    "file": "src/card.c",
    "line": 3,
    "kind": "null_check",
    "pattern": "equal_null",
    "symbol": "s",
    "code": "if (s == NULL)",
}


def cond_drops(facts):
    """只看条件级的丢弃。``path_status`` 为空串时一定会多出一条 ``id="path"`` 的丢弃记录
    （空白状态 = 无法核 ⇒ 不提可达性），那是正确行为，与条件级断言无关。"""
    return [d for d in facts.dropped if d.id != "path"]


class FactsMappingTest(unittest.TestCase):
    """D2 三分类：true→gaps / false+blocker→protected / null→dropped。"""

    def test_holds_true_becomes_required_gap(self):
        facts = build_facts(make_case({"conditions": [cond("cond-1", True)]}))
        self.assertEqual([g.id for g in facts.required_gaps], ["cond-1"])
        self.assertEqual(facts.required_gaps[0].anchor_line, 5, "锚点应落在 vuln.line")
        self.assertEqual(facts.protected, [])
        self.assertEqual(cond_drops(facts), [])

    def test_holds_false_with_blocker_becomes_protected(self):
        facts = build_facts(
            make_case({"conditions": [cond("cond-2", False, kind="null_check", blocker=BLOCKER)]})
        )
        self.assertEqual(facts.required_gaps, [])
        self.assertEqual(len(facts.protected), 1)
        protected = facts.protected[0]
        self.assertEqual(protected.id, "cond-2")
        self.assertEqual(protected.line, 3)
        self.assertEqual(protected.symbol, "s")
        self.assertEqual(protected.code, "if (s == NULL)")

    def test_holds_false_without_blocker_is_dropped_not_protected(self):
        # 没有 blocker 就"不能说这里已有守卫"，只能丢弃并记账
        facts = build_facts(make_case({"conditions": [cond("cond-3", False)]}))
        self.assertEqual(facts.protected, [])
        self.assertEqual([d.id for d in cond_drops(facts)], ["cond-3"])
        self.assertIn("未给 blocker", facts.dropped[0].reason)

    def test_holds_null_is_dropped(self):
        facts = build_facts(make_case({"conditions": [cond("cond-4", None)]}))
        self.assertEqual(facts.required_gaps, [])
        self.assertEqual(facts.protected, [])
        self.assertEqual([d.id for d in cond_drops(facts)], ["cond-4"])
        self.assertIn("holds=null", facts.dropped[0].reason)

    def test_orphan_blockers_are_merged_into_protected(self):
        # blockers[] 里没被任何 condition 引用的，也要进 protected（§5「与 false 合并」）
        facts = build_facts(
            make_case(
                {
                    "conditions": [cond("cond-1", True)],
                    "blockers": [BLOCKER],
                }
            )
        )
        self.assertEqual([g.id for g in facts.required_gaps], ["cond-1"])
        self.assertEqual([p.id for p in facts.protected], ["blocker-1"])

    def test_duplicate_blocker_is_not_double_counted(self):
        facts = build_facts(
            make_case(
                {
                    "conditions": [cond("cond-2", False, kind="null_check", blocker=BLOCKER)],
                    "blockers": [BLOCKER, BLOCKER],
                }
            )
        )
        self.assertEqual(len(facts.protected), 1, "同一 (line, code) 的 blocker 只能算一条")

    def test_many_conditions_on_one_guard_merge_into_one_protected(self):
        """实测场景：5 条假设条件命中同一个 ``if (row > nused)``。"""
        conds = [
            cond(f"cond-{i}", False, kind="bounds_check", blocker=BLOCKER) for i in range(1, 6)
        ]
        facts = build_facts(make_case({"conditions": conds}))
        self.assertEqual(len(facts.protected), 1, "同一个守卫只能占一条 protected")
        entry = facts.protected[0]
        self.assertEqual(
            entry.condition_ids,
            ["cond-1", "cond-2", "cond-3", "cond-4", "cond-5"],
            "来源条件 id 要全部留住，供 evidence_refs 审计",
        )
        self.assertEqual(len(facts.evidence_refs), 5)

    def test_non_dict_condition_is_dropped_with_reason(self):
        facts = build_facts(make_case({"conditions": ["holds=true"]}))
        self.assertEqual(facts.dropped[0].id, "cond-1")
        self.assertIn("不是对象", facts.dropped[0].reason)

    def test_evidence_refs_cover_gaps_and_protected(self):
        facts = build_facts(
            make_case(
                {
                    "conditions": [
                        cond("cond-1", True),
                        cond("cond-2", False, kind="null_check", blocker=BLOCKER),
                        cond("cond-3", None),
                    ]
                }
            )
        )
        self.assertEqual(facts.evidence_refs, ["cond-1", "cond-2"])


class ReachTest(unittest.TestCase):
    def _path(self, seq, reachable=True):
        return [
            {"hop": i, "from": a, "to": b, "file": "src/card.c", "line": 10 + i,
             "code": "", "reachable": reachable, "note": ""}
            for i, (a, b) in enumerate(zip(seq, seq[1:]))
        ]

    def test_reachable_builds_chain(self):
        facts = build_facts(
            make_case(
                {
                    "path_status": "reachable",
                    "path": self._path(["main", "dispatch", "decrypt"]),
                }
            )
        )
        self.assertEqual(facts.reach.status, "reachable")
        self.assertEqual(facts.reach.chain, ["main", "dispatch", "decrypt"])

    def test_reachable_but_single_node_drops_chain(self):
        facts = build_facts(
            make_case({"path_status": "reachable", "path": [{"hop": 0, "from": "x", "to": ""}]})
        )
        self.assertEqual(facts.reach.chain, [], "链少于 2 个节点就不能算合法链")

    def test_unreachable_is_strong_signal_and_reaches_protected_by_nothing(self):
        facts = build_facts(make_case({"path_status": "unreachable"}))
        self.assertEqual(facts.reach.status, "unreachable")
        self.assertEqual(facts.reach.chain, [])
        self.assertEqual([d.id for d in facts.dropped], ["path"])
        self.assertIn("强误报信号", facts.dropped[0].reason)

    def test_unverifiable_never_claims_reachability(self):
        facts = build_facts(make_case({"path_status": "unverifiable"}))
        self.assertEqual(facts.reach.status, "unverifiable")
        self.assertEqual(facts.reach.chain, [])
        self.assertIn("不提可达性", facts.dropped[0].reason)

    def test_blank_status_is_treated_as_unverifiable(self):
        facts = build_facts(make_case({"path_status": ""}))
        self.assertEqual(facts.reach.status, "unverifiable")
        self.assertEqual(facts.reach.chain, [])


class SufficiencyTest(unittest.TestCase):
    """§5 的充足性三选一。"""

    def test_rule1_required_gaps(self):
        facts = build_facts(make_case({"conditions": [cond("cond-1", True)]}, verdict="uncertain"))
        self.assertTrue(facts.sufficiency.ok)
        self.assertIn("required_gaps=1", facts.sufficiency.why)

    def test_rule2_reachable_chain(self):
        path = [{"hop": 0, "from": "main", "to": "decrypt", "reachable": True}]
        facts = build_facts(make_case({"path_status": "reachable", "path": path}, verdict="uncertain"))
        self.assertTrue(facts.sufficiency.ok)
        self.assertIn("触发链可用", facts.sufficiency.why)

    def test_rule3_accept_verdict_alone_is_enough(self):
        facts = build_facts(make_case(verdict="accept"))
        self.assertTrue(facts.sufficiency.ok)
        self.assertIn("verdict=accept", facts.sufficiency.why)

    def test_insufficient_when_no_rule_applies(self):
        facts = build_facts(make_case({"path_status": "unverifiable"}, verdict="uncertain"))
        self.assertFalse(facts.sufficiency.ok)
        self.assertIn("事实不足", facts.sufficiency.why)

    def test_rule4_existing_guard_alone_is_enough(self):
        """实测补充规则：缺陷在守卫本身时，保护项就是唯一可用事实。

        APPATCH extractfix 的 binutils 用例：``if (row > nused)`` 不够严，
        被 `check_assumptions` 判成 blocker，于是 gaps 永远为空。
        """
        facts = build_facts(
            make_case(
                {"path_status": "unverifiable",
                 "conditions": [cond("cond-1", False, kind="bounds_check", blocker=BLOCKER)]},
                verdict="uncertain",
            )
        )
        self.assertTrue(facts.sufficiency.ok)
        self.assertIn("protected=1", facts.sufficiency.why)
        self.assertIn("缺陷在守卫处", facts.sufficiency.why)


class ReverifyRequestTest(unittest.TestCase):
    def test_no_request_when_facts_are_enough_and_reachable(self):
        path = [{"hop": 0, "from": "main", "to": "decrypt", "reachable": True}]
        case = make_case({"path_status": "reachable", "path": path,
                          "conditions": [cond("cond-1", True)]})
        self.assertIsNone(build_reverify_request(case))
        need, _, asks = reverify_needed(case)
        self.assertFalse(need)
        self.assertEqual(asks, [])

    def test_unreachable_requests_reachability_even_when_sufficient(self):
        # verdict=accept 让 sufficiency 为真，但 unreachable 仍必须复核（§5 映射表）
        case = make_case({"path_status": "unreachable"}, verdict="accept")
        facts = build_facts(case)
        self.assertTrue(facts.sufficiency.ok)
        request = build_reverify_request(case, facts)
        self.assertIsNotNone(request)
        self.assertEqual(request["reason"], "unreachable_path")
        self.assertEqual([a["kind"] for a in request["asks"]], ["resolve_reachability"])

    def test_insufficient_with_null_conditions_asks_recheck(self):
        case = make_case({"conditions": [cond("cond-7", None)]}, verdict="uncertain")
        request = build_reverify_request(case)
        self.assertEqual(request["reason"], "insufficient_facts")
        ask = request["asks"][0]
        self.assertEqual(ask["kind"], "recheck_condition")
        self.assertEqual(ask["condition_id"], "cond-7")
        self.assertEqual(ask["hint_line"], 5, "hint 用切片内行号")
        self.assertIn("外部长度", ask["text"])

    def test_insufficient_without_any_condition_asks_widen_window(self):
        case = make_case(verdict="uncertain")
        request = build_reverify_request(case)
        self.assertEqual([a["kind"] for a in request["asks"]], ["widen_window"])

    def test_request_shape_matches_contract(self):
        case = make_case({"path_status": "unreachable", "conditions": [cond("c1", None)]},
                         verdict="uncertain")
        request = build_reverify_request(case)
        self.assertEqual(request["schema"], VERIFY_REQUEST_SCHEMA)
        self.assertEqual(request["case_id"], "CVE-TEST__decrypt")
        self.assertEqual(request["round"], 1)
        self.assertIn("unreachable_path", request["reason"])
        self.assertIn("insufficient_facts", request["reason"])
        self.assertEqual(request["context"]["line"], 5)
        for ask in request["asks"]:
            self.assertIn(ask["kind"], ("recheck_condition", "resolve_reachability", "widen_window"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
