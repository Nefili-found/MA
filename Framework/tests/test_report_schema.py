# -*- coding: utf-8 -*-
"""A/B/C 报告结构（assumptions 字段）与 Prompt 约定的离线自测。

运行（在 Framework 根目录）：
    .venv/Scripts/python.exe tests/test_report_schema.py

覆盖：
    1. normalize_report 保留 assumptions，并仍按模板补齐缺省 / 丢弃未知字段；
    2. 模型没给 assumptions 时回填模板占位，经 _norm_assumptions 归一后为空列表；
    3. _collect_findings → _deduplicate 跨视角合并 assumptions（去重 + 重新编号）；
    4. 端到端：三份报告 → 合并 → _build_hypothesis → verify_taint 命中 blocker；
    5. 后向兼容：不带 assumptions 的旧格式报告仍能跑通全链路；
    6. schema 提示包含字段约定（kind 枚举 / 路径写法）。

全部通过会打印 ALL_TESTS_PASS 并以退出码 0 结束。
"""
from __future__ import annotations

import pathlib
import sqlite3
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agents import a as agent_a  # noqa: E402
from agents import b as agent_b  # noqa: E402
from agents import c as agent_c  # noqa: E402
from agents import build_schema_hint, normalize_report  # noqa: E402
from memory import db as mem_db  # noqa: E402
from tools.verify_taint import verify_taint  # noqa: E402
import verify_agent.d as d  # noqa: E402

# 行号：3=gate 起始, 4=判空守卫, 5=sink 调用
CODE = """int sink(char *p) { return p ? *p : 0; }

int gate(char *raw) {
  if (raw == NULL) return -1;
  return sink(raw);
}
"""


def check(name: str, fn) -> None:
    fn()
    print(f"  ok  {name}")


def _raw_finding(**over) -> dict:
    finding = {
        "id": "A-1",
        "title": "null pointer dereference",
        "location": {"file": "t.c", "line_start": 5, "line_end": 5, "function": "gate"},
        "cwe": "CWE-476",
        "severity": "high",
        "confidence": 0.7,
        "taint_source": "raw",
        "taint_sink": "sink",
        "propagation_path": ["gate", "sink"],
        "assumptions": [
            {"id": "cond-1", "kind": "null_check", "text": "raw 未判空"}
        ],
        "evidence": "",
        "suggestion": "",
        "some_unknown_field": "should be dropped",
    }
    finding.update(over)
    return finding


# ---------------------------------------------------------------------------
# 1. normalize_report 行为
# ---------------------------------------------------------------------------
def t_normalize_keeps_assumptions() -> None:
    for name, module, prefix in (("A", agent_a, "A"), ("B", agent_b, "B"), ("C", agent_c, "C")):
        raw = {"agent": name, "file": "t.c", "findings": [_raw_finding(id=f"{prefix}-1")]}
        out = normalize_report(raw, name, "t.c", module.REPORT_TEMPLATE, module.FINDING_TEMPLATE)
        finding = out["findings"][0]
        assert "some_unknown_field" not in finding, (name, finding)
        assert finding["assumptions"] == [
            {"id": "cond-1", "kind": "null_check", "text": "raw 未判空"}
        ], (name, finding["assumptions"])
        # 模板里缺的字段仍按默认值补齐
        assert finding["severity"] == "high" and finding["cwe"] == "CWE-476", finding


def t_normalize_defaults_when_missing() -> None:
    """模型没给 assumptions → 保持模板占位；归一后应被视为「无条件」。"""
    raw = {"agent": "A", "file": "t.c", "findings": [{"id": "A-1", "title": "x"}]}
    out = normalize_report(
        raw, "A", "t.c", agent_a.REPORT_TEMPLATE, agent_a.FINDING_TEMPLATE
    )
    placeholder = out["findings"][0]["assumptions"]
    assert isinstance(placeholder, list) and placeholder, placeholder
    assert placeholder[0]["text"] == "", placeholder
    # 占位（text 为空）不得变成一条“真的假设条件”
    assert d._norm_assumptions(out["findings"][0]) == [], d._norm_assumptions(out["findings"][0])


# ---------------------------------------------------------------------------
# 2. 跨视角合并
# ---------------------------------------------------------------------------
def _reports(third_agent: str = "C") -> dict:
    base = dict(
        title="null pointer dereference",
        cwe="CWE-476",
        location={"file": "t.c", "line_start": 5, "line_end": 5, "function": "gate"},
    )
    return {
        "A": {
            "agent": "A",
            "file": "t.c",
            "findings": [
                {**_raw_finding(**base), "id": "A-1",
                 "assumptions": [{"id": "cond-1", "kind": "sanitizer",
                                  "text": "raw 未经校验即传入 sink"}]}
            ],
        },
        "B": {
            "agent": "B",
            "file": "t.c",
            "findings": [
                {**_raw_finding(**base), "id": "B-1",
                 "assumptions": [{"id": "cond-1", "kind": "null_check",
                                  "text": "raw 未判空"}]}
            ],
        },
        third_agent: {
            "agent": third_agent,
            "file": "t.c",
            "findings": [
                {**_raw_finding(**base), "id": f"{third_agent}-1",
                 # 与 B 完全重复 → 应被去重
                 "assumptions": [
                     {"id": "cond-1", "kind": "null_check", "text": "raw 未判空"},
                     {"id": "cond-2", "kind": "bounds_check",
                      "text": "raw 指向的缓冲区长度未校验"},
                 ]}
            ],
        },
    }


def _merged(reports: dict) -> list:
    path = pathlib.Path(tempfile.mkdtemp()) / "merge.db"
    conn = mem_db.get_connection(path)
    try:
        findings = d._collect_findings(reports)
        return d._deduplicate(findings, "s", conn, None)
    finally:
        conn.close()


def t_dedupe_merges_assumptions() -> None:
    merged = _merged(_reports())
    assert len(merged) == 1, merged
    conds = merged[0]["assumptions"]
    assert len(conds) == 3, conds                      # 3 个不同条件，重复的 1 条已去重
    assert [c["id"] for c in conds] == ["cond-1", "cond-2", "cond-3"], conds
    texts = {c["text"] for c in conds}
    assert texts == {"raw 未经校验即传入 sink", "raw 未判空", "raw 指向的缓冲区长度未校验"}, texts
    assert merged[0]["_agents"] == ["A", "B", "C"], merged[0]["_agents"]


def t_dedupe_keeps_propagation_path() -> None:
    merged = _merged(_reports())
    assert merged[0]["propagation_path"] == ["gate", "sink"], merged[0]["propagation_path"]


# ---------------------------------------------------------------------------
# 3. 端到端：报告 → 假设 → 核验
# ---------------------------------------------------------------------------
def t_end_to_end_blocker() -> None:
    merged = _merged(_reports())
    hypothesis = d._build_hypothesis(merged[0], CODE)
    assert hypothesis["assumptions"], hypothesis
    assert hypothesis["trigger_path"] == ["gate", "sink"], hypothesis

    out = verify_taint(hypothesis, {"file": "t.c", "code": CODE})
    null_cond = [c for c in out["evidence"]["conditions"] if c.get("kind") == "null_check"]
    assert null_cond and null_cond[0]["holds"] is False, out["evidence"]
    assert out["evidence"]["blockers"][0]["line"] == 4, out["evidence"]
    assert out["verdict"] == "reject", out
    assert out["confidence"] == 0.55, out       # blocker 封顶，单方不可 overturn
    # 另两条条件在 gate 里没有对应守卫 → 视为成立
    others = [c for c in out["evidence"]["conditions"] if c.get("kind") != "null_check"]
    assert all(c["holds"] is True for c in others), others


def t_end_to_end_legacy_report() -> None:
    """旧格式（无 assumptions 字段）仍能跑通，且退化为「仅核路径」。"""
    reports = _reports()
    for agent in ("A", "B", "C"):
        for finding in reports[agent]["findings"]:
            finding.pop("assumptions", None)
    merged = _merged(reports)
    assert merged[0]["assumptions"] == [], merged[0]["assumptions"]

    hypothesis = d._build_hypothesis(merged[0], CODE)
    assert hypothesis["assumptions"] == [], hypothesis
    out = verify_taint(hypothesis, {"file": "t.c", "code": CODE})
    assert out["evidence"]["conditions"] == [], out["evidence"]
    assert out["verdict"] == "accept", out       # 路径全可达且无条件 → accept


# ---------------------------------------------------------------------------
# 4. schema 提示
# ---------------------------------------------------------------------------
def t_schema_hint_rules() -> None:
    hint = build_schema_hint(agent_a.REPORT_TEMPLATE, agent_a.FINDING_TEMPLATE)
    assert "assumptions" in hint, hint[-400:]
    assert "null_check / bounds_check / sanitizer / other" in hint, hint[-400:]
    assert "本文件内的函数名" in hint, hint[-400:]
    assert '"findings"' in hint or "findings" in hint, hint[:400]


def main() -> int:
    print("=== A/B/C 报告结构（assumptions）自测 ===")
    check("结构：三视角模板均保留 assumptions 且丢弃未知字段", t_normalize_keeps_assumptions)
    check("结构：缺省 assumptions 不变成真的条件", t_normalize_defaults_when_missing)
    check("去重：跨视角合并 + 重新编号", t_dedupe_merges_assumptions)
    check("去重：propagation_path 仍取首个非空", t_dedupe_keeps_propagation_path)
    check("端到端：合并后的假设命中 blocker", t_end_to_end_blocker)
    check("兼容：旧格式报告退化为仅核路径", t_end_to_end_legacy_report)
    check("提示：schema 含字段约定", t_schema_hint_rules)
    print("ALL_TESTS_PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
