# -*- coding: utf-8 -*-
"""工具循环（tool_loop）接入注入探针的离线自测：开关过滤 + dispatch 分发。

覆盖：
    1. ``injection_enabled=True`` → ``available_tools`` 绑定注入核验与注入探针工具；
    2. ``injection_enabled=False`` → 两者都不绑定；``dynamic_enabled=False`` 不绑动态工具；
    3. ``dispatch_tool("injection_runtime", ...)`` 透传 hypothesis/context，
       返回探针结果与 ``tool=injection_runtime`` 的调用记录；
    4. 带 ``_tool`` 后缀的工具名经归一后仍能分发到探针。

依赖 tree-sitter / langchain 的 import 在缺依赖环境会跳过（打印 SKIP，退出码 0），
与仓库其他离线测试一致。

运行（Framework 根目录）：
    python tests/test_tool_loop_runtime.py
"""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    import verify_agent.tool_loop as tl  # noqa: E402
except Exception as exc:  # 缺 tree-sitter / langchain 等原生依赖时跳过
    print(f"SKIP: 工具循环模块依赖未安装（{type(exc).__name__}: {exc}），本用例不在本机执行")
    raise SystemExit(0)


def _base_uncertain() -> dict:
    return {
        "status": "uncertain",
        "verdict": "uncertain",
        "confidence": 0.0,
        "reason": "",
        "evidence": {},
    }


def check(name: str, fn) -> None:
    fn()
    print(f"  ok  {name}")


# 1) 注入开关开启：核验与探针工具都绑定（工具对象存在时才校验身份）
def t_bind_when_injection_on() -> None:
    tools = tl.available_tools(dynamic_enabled=True, injection_enabled=True)
    if tl.injection_check_tool is not None:
        assert tl.injection_check_tool in tools, "注入核验工具应被绑定"
    if tl.injection_runtime_tool is not None:
        assert tl.injection_runtime_tool in tools, "注入探针工具应被绑定"


# 2) 开关关闭：对应工具一律不绑定
def t_filter_by_switch() -> None:
    inj_off = tl.available_tools(dynamic_enabled=True, injection_enabled=False)
    if tl.injection_check_tool is not None:
        assert tl.injection_check_tool not in inj_off, "注入开关关闭时不应绑核验工具"
    if tl.injection_runtime_tool is not None:
        assert tl.injection_runtime_tool not in inj_off, "注入开关关闭时不应绑探针工具"

    dyn_off = tl.available_tools(dynamic_enabled=False, injection_enabled=True)
    if tl.dynamic_check_tool is not None:
        assert tl.dynamic_check_tool not in dyn_off, "动态开关关闭时不应绑动态工具"


# 3) dispatch 分发到探针：参数透传，结果原样返回，记录 tool 名
def t_dispatch_runtime() -> None:
    calls = {"n": 0}

    def _fake_runtime(hypothesis: dict, context: dict) -> dict:
        calls["n"] += 1
        return {**_base_uncertain(), "evidence": {"probe_type": "command_canary"}}

    orig = tl.injection_runtime
    tl.injection_runtime = _fake_runtime
    try:
        hyp = {"finding_id": "rt-1", "cwe": "78"}
        ctx = {"file": "x.c", "code": "system(cmd);"}
        result, record = tl.dispatch_tool("injection_runtime", {}, hyp, ctx)
        assert calls["n"] == 1, "应恰好调用一次探针"
        assert record["tool"] == "injection_runtime", record
        assert record["args"]["finding_id"] == "rt-1"
        assert result["evidence"]["probe_type"] == "command_canary"
    finally:
        tl.injection_runtime = orig


# 4) 带 _tool 后缀的工具名归一后仍分发到探针
def t_dispatch_runtime_suffixed() -> None:
    calls = {"n": 0}

    def _fake_runtime(hypothesis: dict, context: dict) -> dict:
        calls["n"] += 1
        return _base_uncertain()

    orig = tl.injection_runtime
    tl.injection_runtime = _fake_runtime
    try:
        result, record = tl.dispatch_tool(
            "injection_runtime_tool", {}, {"finding_id": "rt-2"}, {"code": ""}
        )
        assert calls["n"] == 1, "后缀归一后应分发到探针"
        assert record["tool"] == "injection_runtime", record
    finally:
        tl.injection_runtime = orig


def main() -> int:
    check("注入开关开启时绑定核验/探针工具", t_bind_when_injection_on)
    check("开关关闭时按规则过滤工具", t_filter_by_switch)
    check("dispatch 分发到注入探针并透传参数", t_dispatch_runtime)
    check("带 _tool 后缀的工具名归一后可分发", t_dispatch_runtime_suffixed)
    print("TOOL_LOOP_RUNTIME OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
