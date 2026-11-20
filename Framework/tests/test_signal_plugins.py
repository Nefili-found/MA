# -*- coding: utf-8 -*-
"""工具信号提权分支的离线自测：mock 核验工具与注入探针，不依赖真实 LLM / 编译环境。

覆盖：
    1. 动态工具返回 accept → 工具信号提权为 accept，置信度取 0.92，证据挂 evidence.dynamic；
    2. 注入静态核验返回 accept → 提权 0.88，证据挂 evidence.injection；
    3. 注入探针返回 accept → 提权 0.90，证据挂 evidence.injection_runtime；
    4. ``dynamic_enabled=False`` → 不调用动态工具，evidence 不挂 dynamic 段；
    5. ``injection_enabled=False`` → 不调用注入核验/探针，evidence 不挂注入段。

依赖 tree-sitter / langchain 的 import 在缺依赖环境会跳过（打印 SKIP，退出码 0），
与仓库其他离线测试一致。

运行（在 Framework 根目录）：
    python tests/test_signal_plugins.py
"""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    import verify_agent.signals as sig  # noqa: E402
except Exception as exc:  # 缺 tree-sitter / langchain 等原生依赖时跳过
    print(f"SKIP: 信号模块依赖未安装（{type(exc).__name__}: {exc}），本用例不在本机执行")
    raise SystemExit(0)


def _base_uncertain() -> dict:
    return {
        "status": "uncertain",
        "verdict": "uncertain",
        "confidence": 0.0,
        "reason": "",
        "evidence": {},
    }


def _fake_verify_taint(hypothesis: dict, context: dict) -> dict:
    return _base_uncertain()


def _fake_dyn_accept(hypothesis: dict, context: dict, enabled: bool = True) -> dict:
    return {
        "status": "verified",
        "verdict": "accept",
        "confidence": sig.CONF_DYNAMIC_CRASH,
        "reason": "动态执行复现运行时错误",
        "evidence": {"crash": True, "crash_type": "heap-buffer-overflow"},
    }


def _fake_inj_accept(hypothesis: dict, context: dict, enabled: bool = True) -> dict:
    return {
        "status": "verified",
        "verdict": "accept",
        "confidence": sig.CONF_INJECTION_EVIDENCE,
        "reason": "源码命中注入 sink 且直达",
        "evidence": {"cwe": "78", "direct_input": True},
    }


def _fake_rt_accept(hypothesis: dict, context: dict, enabled: bool = True) -> dict:
    return {
        "status": "verified",
        "verdict": "accept",
        "confidence": sig.CONF_INJECTION_RUNTIME,
        "reason": "命令注入探针复现：canary 回显",
        "evidence": {"reproduced": True, "probe_type": "command_canary"},
    }


def main() -> int:
    # 保存原引用，便于用例间隔离
    orig = {
        "verify_taint": sig.verify_taint,
        "dynamic_check": sig.dynamic_check,
        "injection_check": sig.injection_check,
        "injection_runtime": sig.injection_runtime,
    }
    dyn_calls = {"n": 0}
    rt_calls = {"n": 0}

    def _fake_dyn_count(hypothesis: dict, context: dict, enabled: bool = True) -> dict:
        dyn_calls["n"] += 1
        return _fake_dyn_accept(hypothesis, context, enabled=enabled)

    def _fake_rt_count(hypothesis: dict, context: dict, enabled: bool = True) -> dict:
        rt_calls["n"] += 1
        return _base_uncertain()

    try:
        # 1) 动态 accept 提权：静态 uncertain + 动态崩溃 → 工具信号 accept / 0.92
        sig.verify_taint = _fake_verify_taint
        sig.dynamic_check = _fake_dyn_accept
        sig.injection_check = lambda h, c, enabled=True: _base_uncertain()
        sig.injection_runtime = lambda h, c, enabled=True: _base_uncertain()
        out = sig.tool_signal({"finding_id": "x-1", "cwe": "120"}, {"code": ""})
        assert out["verdict"] == "accept", out
        assert out["confidence"] == sig.CONF_DYNAMIC_CRASH, out
        assert out["evidence"].get("dynamic", {}).get("crash") is True, out
        print("  ok  动态 accept 提权到工具信号（0.92，evidence.dynamic 落挂）")

        # 2) 注入静态核验 accept 提权：静态 uncertain + 注入源码证据 → accept / 0.88
        sig.dynamic_check = lambda h, c, enabled=True: _base_uncertain()
        sig.injection_check = _fake_inj_accept
        out2 = sig.tool_signal({"finding_id": "x-2", "cwe": "78"}, {"code": ""})
        assert out2["verdict"] == "accept", out2
        assert out2["confidence"] == sig.CONF_INJECTION_EVIDENCE, out2
        assert out2["evidence"].get("injection", {}).get("direct_input") is True, out2
        print("  ok  注入静态 accept 提权到工具信号（0.88，evidence.injection 落挂）")

        # 3) 注入探针 accept 提权：静态 uncertain + 探针复现 → accept / 0.90
        sig.injection_check = lambda h, c, enabled=True: _base_uncertain()
        sig.injection_runtime = _fake_rt_accept
        out3 = sig.tool_signal({"finding_id": "x-3", "cwe": "78"}, {"code": ""})
        assert out3["verdict"] == "accept", out3
        assert out3["confidence"] == sig.CONF_INJECTION_RUNTIME, out3
        assert out3["evidence"].get("injection_runtime", {}).get("reproduced") is True, out3
        print("  ok  注入探针 accept 提权到工具信号（0.90，evidence.injection_runtime 落挂）")

        # 4) 动态开关关闭：不调用动态工具，evidence 不挂 dynamic 段
        sig.dynamic_check = _fake_dyn_count
        sig.injection_runtime = _fake_rt_count
        out4 = sig.tool_signal(
            {"finding_id": "x-4", "cwe": "120"},
            {"code": ""},
            dynamic_enabled=False,
        )
        assert dyn_calls["n"] == 0, "开关关闭时不应调用 dynamic_check"
        assert "dynamic" not in out4["evidence"], out4["evidence"]
        print("  ok  dynamic_enabled=False 时跳过动态工具且不挂动态证据")

        # 5) 注入开关关闭：不调用注入核验/探针，evidence 不挂注入段
        rt_calls["n"] = 0
        out5 = sig.tool_signal(
            {"finding_id": "x-5", "cwe": "78"},
            {"code": ""},
            injection_enabled=False,
        )
        assert rt_calls["n"] == 0, "开关关闭时不应调用 injection_runtime"
        assert "injection" not in out5["evidence"], out5["evidence"]
        assert "injection_runtime" not in out5["evidence"], out5["evidence"]
        print("  ok  injection_enabled=False 时跳过注入核验/探针且不挂注入证据")
    finally:
        sig.verify_taint = orig["verify_taint"]
        sig.dynamic_check = orig["dynamic_check"]
        sig.injection_check = orig["injection_check"]
        sig.injection_runtime = orig["injection_runtime"]

    print("ALL_TESTS_PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
