# -*- coding: utf-8 -*-
"""管线级离线 e2e：假 LLM 跑真实 LangGraph，验证 assumptions 能穿透整条链路。

运行（在 Framework 根目录）：
    .venv/Scripts/python.exe tests/test_pipeline_assumptions.py

为什么需要它：真实端到端要调模型，Key 失效时无法验证「模型被要求输出 assumptions」
这件事是否真的贯穿到核验环节。这里用按 System Prompt 分发的 FakeLLM 代替模型，
其余全是生产代码（graph / A/B/C / D / ledger / view / verify_taint）。

覆盖：
    1. A/B/C 的 system prompt 确实包含 assumptions 字段与字段约定；
    2. 三份报告经 normalize_report 后 assumptions 非空，并写入 ledger；
    3. D 去重后合并三视角条件，进入 verify_taint（conditions 非空）；
    4. 命中 blocker 的条件落进 view 的 evidence_json；
    5. 最终报告与 view 行都能正常落盘（使用临时库/临时输出，不碰真实文件）。

全部通过会打印 ALL_TESTS_PASS 并以退出码 0 结束。
"""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from langchain_core.messages import AIMessage  # noqa: E402

import agents  # noqa: E402
import verify_agent.d as d  # noqa: E402
from config import Settings  # noqa: E402
from memory import db as mem_db  # noqa: E402
from memory.ledger import read_reports  # noqa: E402
from memory.view import read_views  # noqa: E402

CODE = """int sink(char *p);

int gate(char *raw) {
  if (raw == NULL) return -1;
  return sink(raw);
}

int main(int argc, char **argv) {
  return gate(argv[1]);
}
"""

REPORTS = {
    "A": {
        "agent": "A",
        "file": "t.c",
        "findings": [
            {
                "id": "A-1",
                "title": "null pointer dereference",
                "location": {"file": "t.c", "line_start": 5, "line_end": 5, "function": "gate"},
                "cwe": "CWE-476",
                "severity": "high",
                "confidence": 0.72,
                "taint_source": "raw",
                "taint_sink": "sink",
                "propagation_path": ["main", "gate"],
                "assumptions": [
                    {"id": "cond-1", "kind": "sanitizer", "text": "raw 未经校验即传入 sink"}
                ],
                "evidence": "gate 直接把 raw 传给 sink",
                "suggestion": "调用前校验 raw",
            }
        ],
    },
    "B": {
        "agent": "B",
        "file": "t.c",
        "findings": [
            {
                "id": "B-1",
                "title": "null pointer dereference",
                "location": {"file": "t.c", "line_start": 5, "line_end": 5, "function": "gate"},
                "cwe": "CWE-476",
                "severity": "high",
                "confidence": 0.65,
                "taint_source": "raw",
                "taint_sink": "sink",
                "propagation_path": ["main", "gate"],
                "assumptions": [
                    {"id": "cond-1", "kind": "null_check", "text": "raw 未判空"},
                    {"id": "cond-2", "kind": "other", "text": "argv[1] 可为 NULL 且一路透传到 sink"},
                ],
                "evidence": "main 未校验 argv[1]",
                "suggestion": "在 main 入口判空",
            }
        ],
    },
    "C": {
        "agent": "C",
        "file": "t.c",
        "findings": [
            {
                "id": "C-1",
                "title": "null pointer dereference",
                "location": {"file": "t.c", "line_start": 5, "line_end": 5, "function": "gate"},
                "cwe": "CWE-476",
                "severity": "medium",
                "confidence": 0.6,
                "taint_source": "raw",
                "taint_sink": "sink",
                "propagation_path": ["main", "gate"],
                "assumptions": [
                    # 与 B 的 cond-1 完全重复 → 合并后应去重
                    {"id": "cond-1", "kind": "null_check", "text": "raw 未判空"},
                    {"id": "cond-2", "kind": "bounds_check", "text": "raw 指向的缓冲区长度未校验"},
                ],
                "evidence": "无长度语义",
                "suggestion": "加长度参数",
            }
        ],
    },
}


class FakeLLM:
    """按 System Prompt 分发的假模型；同时记录每个 Agent 收到的 system prompt。"""

    def __init__(self) -> None:
        self.seen_system: list = []

    def bind_tools(self, tools):
        self.tools = tools
        return self

    # -- 分发 -----------------------------------------------------------
    def invoke(self, messages):
        system = str(getattr(messages[0], "content", "") or "")
        self.seen_system.append(system)

        if "static source code program analysis" in system:
            return AIMessage(content=json.dumps(REPORTS["A"], ensure_ascii=False))
        if "program behavior and control flow deduction" in system:
            return AIMessage(content=json.dumps(REPORTS["B"], ensure_ascii=False))
        if "memory security vulnerability analysis" in system:
            return AIMessage(content=json.dumps(REPORTS["C"], ensure_ascii=False))
        if "漏洞报告去重助手" in system:
            human = str(getattr(messages[-1], "content", "") or "")
            try:
                n = len(json.loads(human))
            except Exception:
                n = 1
            return AIMessage(content=json.dumps({"groups": [list(range(n))]}))
        if "漏洞裁决助手" in system:
            return AIMessage(
                content=json.dumps({"final_confidence": 0.7, "reason": "三视角基本一致"})
            )
        if "漏洞检索助手" in system:
            return AIMessage(content=json.dumps({"matches": []}))
        if "对抗式漏洞验证者" in system:
            # 不调工具，直接给裁决：证据不足 → challenge（不会单独推翻 finding）
            return AIMessage(
                content=json.dumps(
                    {"verdict": "challenge", "confidence": 0.4, "reason": "单文件证据有限"}
                )
            )
        # 摘要压缩请求等
        return AIMessage(content="## Primary Request\n- checkpoint")


def main() -> int:
    print("=== 管线级 e2e（假 LLM，真实 graph） ===")
    fake = FakeLLM()
    tmp = pathlib.Path(tempfile.mkdtemp())
    settings = Settings(
        api_key="fake",
        db_path=str(tmp / "pipe.db"),
        output_path=str(tmp / "final_report.json"),
        repair_input_path=str(tmp / "repair_input.json"),
        max_retries=2,
    )

    # 只替换 LLM 与配置，其余走生产代码
    agents.get_llm = lambda *a, **k: fake
    d.get_llm = lambda *a, **k: fake
    agents.load_settings = lambda *a, **k: settings
    d.load_settings = lambda *a, **k: settings

    from graph import build_graph

    state = {
        "file_path": "t.c",
        "code": CODE,
        "reports": {},
        "merged_findings": [],
        "verified_findings": [],
        "final_report": {},
        "session_id": "pipe-sess",
        "errors": [],
    }
    result = build_graph().invoke(state, config={"recursion_limit": 50})

    # 1) A/B/C 拿到的提示确实要求 assumptions
    scan_prompts = [s for s in fake.seen_system if "【Report fields】" in s]
    assert len(scan_prompts) == 3, len(scan_prompts)
    for s in scan_prompts:
        assert '"assumptions"' in s, s[-500:]
        assert "null_check / bounds_check / sanitizer / other" in s, s[-500:]
    print("  ok  A/B/C 提示包含 assumptions 字段与 kind 枚举")

    # 2) ledger：三份报告都保住了 assumptions
    conn = mem_db.get_connection(settings.db_path)
    reports = read_reports(conn, "pipe-sess")
    assert sorted(r["agent"] for r in reports) == ["A", "B", "C"], reports
    counts = {
        r["agent"]: len((r["report"]["findings"][0] or {}).get("assumptions") or [])
        for r in reports
    }
    assert counts == {"A": 1, "B": 2, "C": 2}, counts
    print(f"  ok  ledger 三份报告的 assumptions 数量 {counts}")

    # 3) 去重合并 → 三视角条件并集（4 条不同条件，重名已重编）
    merged = result["merged_findings"]
    assert len(merged) == 1, merged
    conds = merged[0]["assumptions"]
    assert len(conds) == 4, conds
    assert [c["id"] for c in conds] == ["cond-1", "cond-2", "cond-3", "cond-4"], conds
    assert merged[0]["_agents"] == ["A", "B", "C"], merged[0]["_agents"]
    print(f"  ok  合并后条件 {[c['kind'] for c in conds]}")

    # 4) view：conditions 与 blocker 落库
    views = read_views(conn, "pipe-sess")
    assert len(views) == 1, views
    ev = views[0]["evidence"]
    assert len(ev.get("conditions", [])) == 4, ev
    blockers = ev.get("blockers") or []
    assert blockers and blockers[0]["line"] == 4, ev
    assert views[0]["verdict"] == "uncertain", views[0]["verdict"]
    print(f"  ok  view 落库 conditions={len(ev['conditions'])} blocker@line={blockers[0]['line']}")

    # 5) 最终报告落盘（含核验证据）
    final = result["final_report"]
    assert pathlib.Path(settings.output_path).exists(), settings.output_path
    assert len(final["findings"]) == 1, final
    finding = final["findings"][0]
    assert finding["verification_status"] == "uncertain", final
    assert finding["verdict"] == "uncertain", finding
    ev = finding["evidence"]
    assert len(ev["conditions"]) == 4, ev
    assert ev["blockers"][0]["line"] == 4, ev
    assert ev["path_status"] == "reachable", ev
    assert ev["path"][0]["from"] == "main" and ev["path"][0]["to"] == "gate", ev["path"]
    # 落盘 JSON 也必须带上（不是只在内存里）
    on_disk = json.loads(pathlib.Path(settings.output_path).read_text(encoding="utf-8"))
    assert on_disk["findings"][0]["evidence"]["blockers"][0]["line"] == 4, on_disk

    # 6) 修复端输入投影：func_src / 语句级行号 / 规范化 CWE 都在
    repair_doc = json.loads(pathlib.Path(settings.repair_input_path).read_text(encoding="utf-8"))
    assert repair_doc["schema"] == "repair-input/1", repair_doc
    case = repair_doc["cases"][0]
    assert case["vuln"]["func"] == "gate", case["vuln"]
    assert case["code"]["func_src"].startswith("int gate("), case["code"]
    assert case["code"]["line_source"] == "ast", case["code"]
    assert case["vuln"]["cwe"].startswith("CWE-"), case["vuln"]
    assert case["validation"]["ok"] is True, case["validation"]
    print(f"  ok  repair_input 落盘 cases={len(repair_doc['cases'])} func={case['vuln']['func']}")
    conn.close()

    # 收尾：恢复被替换的函数，避免影响同进程内的其它测试
    import importlib

    importlib.reload(agents)
    importlib.reload(d)
    print("  ok  最终报告落盘且含 path/conditions/blockers")
    print("ALL_TESTS_PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
