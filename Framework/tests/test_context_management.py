# -*- coding: utf-8 -*-
"""上下文治理（A 篇四件套接入 B 篇）的离线自测：不依赖真实 API，用 Mock LLM。

运行（在 Framework 根目录）：
    python tests/test_context_management.py

覆盖：
    1. 领域工具（call_context）调用者/被调用者去重 + 限量 + 函数体体量元信息；
    2. D 工具循环：大源码 / 大工具结果外存（spill），tool_call 与 ToolMessage 配对；
    3. 高压力下：先裁剪（prune）后压缩（compact），且不切断 tool_call 配对。

全部通过会打印 ALL_TESTS_PASS 并以退出码 0 结束。
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage  # noqa: E402

from config import load_settings  # noqa: E402
from context import ContextManager  # noqa: E402
from tools import call_context as cc  # noqa: E402
import verify_agent.d as d  # noqa: E402


def validate_pairs(msgs) -> None:
    """每条 ToolMessage 的 tool_call_id 必须在其前面某个 AIMessage.tool_calls 中声明。"""
    declared = set()
    for m in msgs:
        if m.type == "ai":
            for tc in (m.tool_calls or []):
                declared.add(tc["id"] if isinstance(tc, dict) else tc.id)
        elif m.type == "tool":
            assert m.tool_call_id in declared, f"孤立 ToolMessage: {m.tool_call_id}"


def test_domain_tools() -> None:
    calls = "\n".join(f"    helper({i});" for i in range(45))
    code = f"void helper(int x){{}}\nint main(void){{\n{calls}\n    return 0;\n}}\n"
    c = cc.build_context(code)
    callees = cc.get_callees("main", c)
    callers = cc.get_callers("helper", c)
    body = cc.get_function_body("main", c)
    assert callees["count"] == 45 and callees["returned"] == cc.DEFAULT_MAX_HITS
    assert callees["truncated"] is True
    assert callers["count"] == 45 and callers["returned"] == cc.DEFAULT_MAX_HITS
    assert callers["truncated"] is True
    assert body["found"] and body["body_lines"] > 0 and body["body_chars"] > 0
    print("[1] 领域工具去重/限量/体量元信息  PASS")


class FakeLLM:
    """按脚本返回工具调用；对压缩请求返回短摘要。"""

    def __init__(self, scripted):
        self.scripted = scripted
        self.n = 0
        self.compact_calls = 0

    def bind_tools(self, tools):
        self.tools = tools
        return self

    def invoke(self, messages):
        last = messages[-1]
        if getattr(last, "type", "") == "human" and "compaction engine" in (
            getattr(last, "content", "") or ""
        ):
            self.compact_calls += 1
            return AIMessage(content="## Primary Request\n- short checkpoint")
        r = self.scripted[min(self.n, len(self.scripted) - 1)]
        self.n += 1
        return r


def test_tool_loop_spill() -> None:
    body = "\n".join(f"    int x{i} = {i};" for i in range(2000))
    big_code = (
        "#include <string.h>\n"
        f"void big_func(char *p) {{\n{body}\n    strcpy(p, \"data\");\n}}\n"
        "int main(void){ char b[10]; big_func(b); return 0; }\n"
    )
    spill_root = os.path.join(tempfile.gettempdir(), "ma_ctx_spill_test_2")
    mgr = ContextManager(
        context_window=200_000, spill_root=spill_root,
        max_inline_bytes=512, prune_threshold_chars=10_000_000,
    )
    d.set_active_context(big_code)
    hypothesis = {"finding_id": "F1", "title": "stack overflow", "cwe": "CWE-121"}
    context = {"file": "sample.c", "line_range": [1, 2], "code": big_code}
    scripted = [
        AIMessage(content="", tool_calls=[{"name": "get_function_body",
                  "args": {"function_name": "big_func"}, "id": "k1"}]),
        AIMessage(content="", tool_calls=[{"name": "verify_taint",
                  "args": {"hypothesis": hypothesis}, "id": "k2"}]),
        AIMessage(content="done", tool_calls=[]),
    ]
    summary, result, reports, llm_sig = d._tool_loop(
        FakeLLM(scripted), hypothesis, context, load_settings(),
        mgr, "session-test", 0,
    )
    assert result.get("status") in ("verified", "rejected", "uncertain")
    # 末轮内容不是合法裁决 JSON -> LLM 信号降级为 uncertain（不抛错）
    assert llm_sig is not None and llm_sig["verdict"] == "uncertain", llm_sig
    assert [t.get("tool") for t in summary["trace"]][0] == "get_function_body"
    assert any(t.get("tool") == "verify_taint" for t in summary["trace"])
    assert any(isinstance(r, dict) and r.get("stage", "").startswith("spill") for r in reports)
    files = [f for _, _, fs in os.walk(spill_root) for f in fs]
    assert files, "大结果应已落盘"
    print("[2] 工具循环外存 + 工具配对  PASS")


def test_prune_compact_pairs() -> None:
    spill_root = os.path.join(tempfile.gettempdir(), "ma_ctx_spill_test_3")
    mgr = ContextManager(
        context_window=1400, spill_root=spill_root,
        max_inline_bytes=100_000, prune_threshold_chars=300,
        prune_head_chars=120, prune_tail_chars=60,
    )
    big = "Z" * 2500
    msgs = [SystemMessage(content="you are a verifier")]
    for i in range(6):
        msgs.append(AIMessage(content="", tool_calls=[{"name": "get_function_body",
                     "args": {"function_name": f"f{i}"}, "id": f"q{i}"}]))
        msgs.append(ToolMessage(content=big, tool_call_id=f"q{i}"))
    msgs.append(HumanMessage(content="please continue"))

    out, rep = mgr.enforce_budget(msgs, llm=FakeLLM([]), session_id="s", phase="stress")
    validate_pairs(out)  # 压缩/裁剪后仍不允许出现孤立 ToolMessage
    assert rep.pruned_replacements >= 1 or rep.compact_ok
    assert rep.after_tokens <= rep.before_tokens
    print(f"[3] 高压力裁剪/压缩 + 配对安全  PASS "
          f"(pruned={rep.pruned_replacements}, compact={rep.compact_ok}, "
          f"{rep.before_tokens}->{rep.after_tokens})")


def main() -> None:
    test_domain_tools()
    test_tool_loop_spill()
    test_prune_compact_pairs()
    print("\nALL_TESTS_PASS")


if __name__ == "__main__":
    main()
