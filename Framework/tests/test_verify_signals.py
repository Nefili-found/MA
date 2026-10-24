# -*- coding: utf-8 -*-
"""「假设条件 + 触发路径」核验的离线自测：不依赖真实 API。

运行（在 Framework 根目录）：
    .venv/Scripts/python.exe tests/test_verify_signals.py

覆盖：
    1. 触发路径可达性：全可达 / 确定断链 / 非函数名跳；
    2. 假设条件 blocker：同符号判空命中、无关符号判空**不得**命中（语料实测结论的回归点）；
    3. verify_taint 的 verdict/status/confidence 映射与旧键兼容；
    4. _combine 双信号全表（status / overturn / conflict）；
    5. _build_hypothesis 的 trigger_path / assumptions 归一；
    6. view 表新增列的幂等迁移与读写；
    7. _verify_findings 的 filter + 打标（含 drop_rejected 开关）。

全部通过会打印 ALL_TESTS_PASS 并以退出码 0 结束。
"""
from __future__ import annotations

import pathlib
import sqlite3
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from config import load_settings  # noqa: E402
from memory import db as mem_db  # noqa: E402
from memory.view import read_views, write_verification  # noqa: E402
from tools.call_context import set_active_context  # noqa: E402
from tools.verify_taint import (  # noqa: E402
    CONF_ACCEPT,
    CONF_BLOCKER_ONLY,
    CONF_CHALLENGE,
    CONF_PATH_BROKEN,
    verify_taint,
)
import verify_agent.d as d  # noqa: E402

# 行号必须与下面 CODE 严格对齐（1-based）
CODE = """int sink(char *p) { return p ? *p : 0; }

int gate(char *raw) {
  if (raw == NULL) return -1;
  return sink(raw);
}

int other(const char *name) {
  if (name == NULL) return 0;
  return sink((char *)name);
}

int direct(char *raw) {
  return sink(raw);
}

int relay(char *raw) { return direct(raw); }
"""

CTX = {"file": "t.c", "code": CODE, "line_range": [1, 17]}


def check(name: str, fn) -> None:
    fn()
    print(f"  ok  {name}")


# ---------------------------------------------------------------------------
# 1. 触发路径可达性
# ---------------------------------------------------------------------------
def t_path_reachable() -> None:
    out = verify_taint(
        {"propagation_path": ["gate", "sink"], "location": {"file": "t.c"}}, CTX
    )
    assert out["verdict"] == "accept", out
    assert out["status"] == "verified", out
    assert out["confidence"] == CONF_ACCEPT, out
    assert out["evidence"]["path_status"] == "reachable", out["evidence"]
    hop = out["evidence"]["path"][0]
    assert hop["reachable"] is True and hop["line"] == 5, hop


def t_path_broken() -> None:
    out = verify_taint(
        {"propagation_path": ["gate", "relay"], "location": {"file": "t.c"}}, CTX
    )
    assert out["verdict"] == "reject", out
    assert out["status"] == "rejected", out
    assert out["confidence"] == CONF_PATH_BROKEN, out
    assert out["evidence"]["path_status"] == "unreachable", out["evidence"]


def t_path_expression_nodes() -> None:
    out = verify_taint(
        {"propagation_path": ["argv[1]", "dst"], "location": {"file": "t.c"}}, CTX
    )
    assert out["verdict"] == "challenge", out
    assert out["status"] == "uncertain", out
    assert out["confidence"] == CONF_CHALLENGE, out


def t_path_empty() -> None:
    out = verify_taint({"propagation_path": [], "location": {}}, {})
    assert out["verdict"] == "challenge", out
    assert out["evidence"]["path"] == [], out["evidence"]


# ---------------------------------------------------------------------------
# 2. 假设条件 blocker（作用域化）
# ---------------------------------------------------------------------------
def t_blocker_same_symbol() -> None:
    out = verify_taint(
        {
            "propagation_path": ["gate", "sink"],
            "taint_source": "raw",
            "assumptions": [{"id": "c1", "kind": "null_check", "text": "raw 未判空"}],
            "location": {"file": "t.c", "line_start": 5, "line_end": 5, "function": "gate"},
        },
        CTX,
    )
    cond = out["evidence"]["conditions"][0]
    assert cond["holds"] is False, cond
    blocker = out["evidence"]["blockers"][0]
    assert blocker["line"] == 4, blocker          # 守卫在 sink 之前
    assert blocker["symbol"] == "raw", blocker
    assert out["verdict"] == "reject", out
    assert out["confidence"] == CONF_BLOCKER_ONLY, out


def t_blocker_unrelated_symbol() -> None:
    """语料实测结论的回归点：别的符号被判空，不能拿来反驳本条假设。"""
    out = verify_taint(
        {
            "propagation_path": ["other", "sink"],
            "taint_source": "raw",
            "assumptions": [{"id": "c1", "kind": "null_check", "text": "raw 未判空"}],
            "location": {"file": "t.c", "line_start": 10, "line_end": 10, "function": "other"},
        },
        CTX,
    )
    assert out["evidence"]["blockers"] == [], out["evidence"]
    assert out["evidence"]["conditions"][0]["holds"] is True, out["evidence"]
    assert out["verdict"] == "accept", out


def t_blocker_after_sink_ignored() -> None:
    """守卫出现在 sink 之后不算阻塞（位置作用域）。"""
    code = """int sink(char *p);

int late(char *raw) {
  int r = sink(raw);
  if (raw == NULL) return -1;
  return r;
}
"""
    set_active_context(code)
    out = verify_taint(
        {
            "propagation_path": ["late"],
            "taint_source": "raw",
            "assumptions": [{"id": "c1", "kind": "null_check", "text": "raw 未判空"}],
            "location": {"file": "l.c", "line_start": 4, "line_end": 4, "function": "late"},
        },
        {"file": "l.c", "code": code},
    )
    assert out["evidence"]["blockers"] == [], out["evidence"]
    set_active_context(CODE)


def t_blocker_missing_function() -> None:
    out = verify_taint(
        {
            "propagation_path": ["main", "foo"],
            "taint_source": "raw",
            "assumptions": [{"id": "c1", "kind": "null_check", "text": "raw 未判空"}],
            "location": {"file": "t.c", "line_start": 3, "line_end": 3, "function": "not_here"},
        },
        CTX,
    )
    assert out["evidence"]["conditions"][0]["holds"] is None, out["evidence"]
    assert out["verdict"] != "accept", out


# ---------------------------------------------------------------------------
# 3. 旧结构兼容
# ---------------------------------------------------------------------------
def t_legacy_keys() -> None:
    out = verify_taint({"propagation_path": ["gate", "sink"], "location": {}}, CTX)
    for key in ("status", "confidence", "reason", "tool_name", "raw_output"):
        assert key in out, (key, out)
    assert out["status"] in ("verified", "rejected", "uncertain"), out
    assert 0.0 <= float(out["confidence"]) <= 1.0, out


# ---------------------------------------------------------------------------
# 4. _combine 双信号全表
# ---------------------------------------------------------------------------
def _sig(verdict: str, confidence: float) -> dict:
    return {"verdict": verdict, "confidence": confidence, "reason": "", "evidence": {}}


def t_combine_matrix() -> None:
    tau = 0.8
    tool = {
        "accept": _sig("accept", 0.9),
        "reject_hard": _sig("reject", 0.9),
        "reject_soft": _sig("reject", 0.55),
        "uncertain": _sig("uncertain", 0.3),
    }
    llm = {
        "accept": _sig("accept", 0.8),
        "reject": _sig("reject", 0.7),
        "challenge": _sig("challenge", 0.4),
        "uncertain": _sig("uncertain", 0.2),
        "none": None,
    }
    # (status, overturn, conflict)
    expected = {
        ("accept", "accept"): ("verified", False, False),
        ("accept", "reject"): ("uncertain", False, True),
        ("accept", "challenge"): ("uncertain", False, True),
        ("accept", "uncertain"): ("verified", False, False),
        ("accept", "none"): ("verified", False, False),
        ("reject_hard", "accept"): ("uncertain", False, True),
        ("reject_hard", "reject"): ("rejected", True, False),
        ("reject_hard", "challenge"): ("rejected", True, False),
        ("reject_hard", "uncertain"): ("rejected", True, False),
        ("reject_hard", "none"): ("rejected", True, False),
        ("reject_soft", "accept"): ("uncertain", False, True),
        ("reject_soft", "reject"): ("rejected", True, False),
        ("reject_soft", "challenge"): ("uncertain", False, True),
        ("reject_soft", "uncertain"): ("uncertain", False, True),
        ("reject_soft", "none"): ("uncertain", False, True),
        ("uncertain", "accept"): ("verified", False, False),
        ("uncertain", "reject"): ("rejected", True, False),
        ("uncertain", "challenge"): ("uncertain", False, False),
        ("uncertain", "uncertain"): ("uncertain", False, False),
        ("uncertain", "none"): ("uncertain", False, False),
    }
    for (tk, tv), (lk, lv) in ((t, l) for t in tool.items() for l in llm.items()):
        got = d._combine(tv, lv, tau)
        want = expected[(tk, lk)]
        trio = (got["status"], got["overturn"], got["conflict"])
        assert trio == want, (tk, lk, trio, want, got)


def t_combine_tau_raises_overturn() -> None:
    """τ 调低到 0.5 时，blocker-only 的工具信号可单方推翻（配置可调）。"""
    got = d._combine(_sig("reject", 0.55), None, 0.5)
    assert got["overturn"] is True and got["status"] == "rejected", got


# ---------------------------------------------------------------------------
# 5. _build_hypothesis 归一
# ---------------------------------------------------------------------------
def t_build_hypothesis() -> None:
    hyp = d._build_hypothesis(
        {
            "id": "A-1",
            "propagation_path": ["main", "foo", "foo", "bar"],
            "assume": ["service 未判空", {"id": "c9", "kind": "null_check", "text": "x"}],
        },
        "",
    )
    assert hyp["trigger_path"] == ["main", "foo", "bar"], hyp
    assert hyp["propagation_path"] == ["main", "foo", "foo", "bar"], hyp
    assert hyp["assumptions"][0] == {"id": "cond-1", "kind": "other", "text": "service 未判空"}, hyp
    assert hyp["assumptions"][1]["id"] == "c9", hyp
    assert hyp["assumptions"][1]["kind"] == "null_check", hyp

    empty = d._build_hypothesis({"id": "B-1"}, "")
    assert empty["trigger_path"] == [] and empty["assumptions"] == [], empty


# ---------------------------------------------------------------------------
# 6. view 表迁移
# ---------------------------------------------------------------------------
def t_view_migration() -> None:
    path = pathlib.Path(tempfile.mkdtemp()) / "mig.db"
    raw = sqlite3.connect(str(path))
    raw.executescript(
        """
        CREATE TABLE "view" (
            id TEXT PRIMARY KEY, session_id TEXT NOT NULL, hypothesis_json TEXT,
            tool_call_json TEXT, tool_result_json TEXT, inference_json TEXT,
            status TEXT, confidence REAL, reason TEXT, created_at TEXT NOT NULL
        );
        """
    )
    raw.execute(
        'INSERT INTO "view" (id, session_id, status, confidence, reason, created_at)'
        " VALUES ('old1', 's0', 'uncertain', 0.0, '历史行', '2026-01-01T00:00:00')"
    )
    raw.commit()
    raw.close()

    conn = mem_db.get_connection(path)
    cols = [r["name"] for r in conn.execute('PRAGMA table_info("view")').fetchall()]
    assert {"verdict", "evidence_json", "conflict"} <= set(cols), cols

    history = read_views(conn, "s0")
    assert history[0]["verdict"] is None and history[0]["conflict"] is False, history

    write_verification(
        conn, "s1", {"finding_id": "A-1"}, {"tool": "verify_taint"},
        {"status": "rejected"}, {"verdict": "reject"},
        "rejected", 0.9, "断链",
        verdict="reject", evidence={"path_status": "unreachable"}, conflict=True,
    )
    row = read_views(conn, "s1")[0]
    assert row["verdict"] == "reject", row
    assert row["evidence"]["path_status"] == "unreachable", row
    assert row["conflict"] is True, row
    conn.close()

    conn2 = mem_db.get_connection(path)  # 幂等：再开一次不应报错、列不变
    cols2 = [r["name"] for r in conn2.execute('PRAGMA table_info("view")').fetchall()]
    assert cols2 == cols, (cols, cols2)
    conn2.close()


# ---------------------------------------------------------------------------
# 7. _verify_findings：filter + 打标
# ---------------------------------------------------------------------------
def _verify_findings_harness(drop: bool):
    settings = load_settings()
    settings.verify_drop_rejected = drop
    path = pathlib.Path(tempfile.mkdtemp()) / "vf.db"
    conn = mem_db.get_connection(path)
    ctx = d.build_context_manager(settings)
    findings = [
        {
            "id": "A-1",
            "propagation_path": ["gate", "sink"],
            "taint_source": "raw",
            "assumptions": [{"id": "c1", "kind": "null_check", "text": "raw 未判空"}],
            "location": {"file": "t.c", "line_start": 5, "line_end": 5, "function": "gate"},
        },
        {
            "id": "B-1",
            "propagation_path": ["gate", "relay"],
            "location": {"file": "t.c", "line_start": 5, "line_end": 5, "function": "gate"},
        },
        {
            "id": "C-1",
            "propagation_path": ["argv[1]", "dst"],
            "location": {"file": "t.c", "line_start": 14, "line_end": 14, "function": "direct"},
        },
    ]
    state = {"file_path": "t.c", "code": CODE, "session_id": "sess"}
    out = d._verify_findings(findings, state, "sess", conn, None, settings, ctx)
    views = read_views(conn, "sess")
    conn.close()
    return out, views


def t_verify_findings_drop() -> None:
    out, views = _verify_findings_harness(drop=True)
    ids = [f["id"] for f in out]
    assert ids == ["A-1", "C-1"], (ids, out)
    # blocker-only（0.55）+ 无 LLM 信号 → 冲突保留，但打 uncertain
    assert out[0]["verification_status"] == "uncertain", out[0]
    assert out[0]["evidence"]["blockers"][0]["line"] == 4, out[0]["evidence"]
    # 断链被丢弃，但 view 里必须留痕
    assert [v["status"] for v in views] == ["uncertain", "rejected", "uncertain"], views
    assert views[1]["verdict"] == "reject", views[1]


def t_verify_findings_keep() -> None:
    out, _ = _verify_findings_harness(drop=False)
    ids = [f["id"] for f in out]
    assert ids == ["A-1", "B-1", "C-1"], (ids, out)
    assert out[1]["verification_status"] == "rejected", out[1]


# ---------------------------------------------------------------------------
# 8. 最终报告结构（含 verdict / evidence）
# ---------------------------------------------------------------------------
def t_final_report_shape() -> None:
    out, _ = _verify_findings_harness(drop=False)
    final = d._build_final_report("t.c", out)
    assert set(final) == {"file", "findings"}, final
    for item in final["findings"]:
        assert set(item) == {
            "location", "taint_chain", "verification_status", "verdict",
            "confidence", "fix_suggestion", "evidence",
        }, item
        assert set(item["evidence"]) == {
            "path_status", "path", "conditions", "blockers", "used_tools"
        }, item["evidence"]
    assert "rejected" in {i["verification_status"] for i in final["findings"]}, final


def t_final_report_carries_evidence() -> None:
    """证据必须真的带进最终报告：path 逐跳、conditions、blockers 都要能对上。"""
    out, _ = _verify_findings_harness(drop=False)
    final = d._build_final_report("t.c", out)
    by_id = dict(zip([f["id"] for f in out], final["findings"]))

    # A-1：路径可达 + 命中 null_check blocker
    a1 = by_id["A-1"]
    assert a1["verdict"] == "uncertain", a1
    assert a1["evidence"]["path_status"] == "reachable", a1["evidence"]
    assert a1["evidence"]["path"][0]["reachable"] is True, a1["evidence"]
    assert a1["evidence"]["blockers"][0]["line"] == 4, a1["evidence"]
    assert a1["evidence"]["used_tools"], a1["evidence"]

    # C-1：非函数名跳 → unverifiable，无 blocker
    c1 = by_id["C-1"]
    assert c1["evidence"]["path_status"] == "unverifiable", c1["evidence"]
    assert c1["evidence"]["blockers"] == [], c1["evidence"]

    # 空证据也能落成完整结构（旧数据 / 未核验）
    legacy = d._build_final_report("t.c", [{"id": "X", "location": {}, "suggestion": "s"}])
    item = legacy["findings"][0]
    assert item["verdict"] == "uncertain", item
    assert item["evidence"] == {
        "path_status": "", "path": [], "conditions": [], "blockers": [], "used_tools": []
    }, item["evidence"]


def main() -> int:
    print("=== 假设条件 + 触发路径核验自测 ===")
    check("路径：全可达 → accept/0.90", t_path_reachable)
    check("路径：同文件断链 → reject/0.90", t_path_broken)
    check("路径：表达式节点 → challenge/0.30", t_path_expression_nodes)
    check("路径：空路径 → challenge", t_path_empty)
    check("条件：同符号判空命中 blocker", t_blocker_same_symbol)
    check("条件：无关符号判空不得命中", t_blocker_unrelated_symbol)
    check("条件：sink 之后的守卫不算 blocker", t_blocker_after_sink_ignored)
    check("条件：目标函数缺失 → holds=None", t_blocker_missing_function)
    check("兼容：verify_taint 旧键齐全", t_legacy_keys)
    check("合并：20 格全表", t_combine_matrix)
    check("合并：τ 可调（0.55 在 τ=0.5 下可推翻）", t_combine_tau_raises_overturn)
    check("假设：trigger_path / assumptions 归一", t_build_hypothesis)
    check("落库：view 表幂等迁移 + 读写", t_view_migration)
    check("过滤：drop_rejected=true 时剔除并留痕", t_verify_findings_drop)
    check("过滤：drop_rejected=false 时只打标", t_verify_findings_keep)
    check("输出：最终报告结构（含 verdict/evidence）", t_final_report_shape)
    check("输出：证据真的带进最终报告", t_final_report_carries_evidence)
    print("ALL_TESTS_PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
