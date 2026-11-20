# -*- coding: utf-8 -*-
"""P2 框架纯逻辑自测：覆盖率排序 / 邻域变异 / 崩溃最小化 / 注入探针文本 / 抽象后端。

编译执行、探针复现、引擎分析等路径依赖 gcc/clang/docker 或真实引擎，本机不跑；
这里只验证不依赖工具链的生成、排序、缩减与降级逻辑。

运行（Framework 根目录）：
    python tests/test_p2_framework.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tools.dynamic_check as dc  # noqa: E402
from tools.injection_runtime import (  # noqa: E402
    CANARY,
    injection_runtime,
    _cmd_probe_call,
    _cmd_probe_harness,
)
import tools.injection_runtime as ir  # noqa: E402
from tools.analysis_backends import (  # noqa: E402
    get_symbolic_backend,
    get_taint_backend,
)


def check(name: str, fn) -> None:
    fn()
    print(f"  ok  {name}")


# 1) 覆盖率排序：有覆盖数据时按新增覆盖量降序；无数据退回原序
def t_rank_by_coverage() -> None:
    dc.COVERAGE_ENABLED = True
    calls = ["seed-a", "seed-b", "seed-c"]
    signatures = {
        0: frozenset({"x"}),
        1: frozenset({"x", "y", "z"}),
        2: frozenset(),
    }
    ordered, gains = dc._rank_by_coverage(calls, signatures)
    # seed-b 新增 y,z 增益最高排首；seed-c 无覆盖排末
    assert ordered[0] == "seed-b"
    assert ordered[-1] == "seed-c"
    assert gains[1][0] >= gains[0][0]

    # 无覆盖数据 → 原序退回
    ordered2, _ = dc._rank_by_coverage(calls, {})
    assert ordered2 == calls
    dc.COVERAGE_ENABLED = False


# 2) 邻域变异：生成与原调用不同的候选
def t_neighbor_mutate() -> None:
    call = 'copy_name((char*)malloc(4), (char*)malloc(4), 4096);'
    variants = dc._neighbor_mutate(call)
    assert variants, "应至少产生一个邻域变体"
    assert all(v != call for v in variants)


# 3) 崩溃最小化：无 replay 原样返回；replay 恒真则缩减；恒假则保留
def t_minimize_none_replay() -> None:
    call = 'copy_name((char*)malloc(256), (char*)malloc(256), 4096);'
    min_call, rec = dc._minimize_call(call, replay=None)
    assert min_call == call
    assert rec["minimized"] is False


def t_minimize_replay_true() -> None:
    call = 'copy_name((char*)malloc(256), (char*)malloc(256), 4096);'
    min_call, rec = dc._minimize_call(call, replay=lambda _c: True)
    assert "4096" not in min_call, "大长度值应被缩减"
    assert rec["minimized"] is True


def t_minimize_replay_false() -> None:
    call = 'copy_name((char*)malloc(256), (char*)malloc(256), 4096);'
    min_call, rec = dc._minimize_call(call, replay=lambda _c: False)
    assert min_call == call, "replay 不确认仍崩时不得缩减"


# 4) 注入探针：harness 文本含 canary / 被测函数 / main
def t_cmd_probe_harness_text() -> None:
    probe = _cmd_probe_call("run_cmd")
    harness = _cmd_probe_harness("void run_cmd(char *c) { system(c); }", probe)
    assert CANARY in harness
    assert "run_cmd(" in harness
    assert "int main(void)" in harness


# 5) 注入探针降级：开关关闭 / 非 78,89 / SQL 骨架（不依赖工具链）
def t_probe_skip_paths() -> None:
    code = "void run_cmd(char *c) { system(c); }"
    h = {"finding_id": "x", "cwe": "78", "location": {"function": "run_cmd"}}

    off = injection_runtime(h, {"code": code}, enabled=False)
    assert off["verdict"] == "uncertain" and "已关闭" in off["reason"]

    # 临时打开模块开关，覆盖 CWE 分流与 SQL 骨架分支；测完恢复默认关闭
    ir.ENABLED = True
    try:
        xss = injection_runtime(
            {"finding_id": "x", "cwe": "79", "location": {"function": "run_cmd"}},
            {"code": code},
        )
        assert "不在动态复现范围" in xss["reason"]

        sql = injection_runtime(
            {"finding_id": "x", "cwe": "89", "location": {"function": "query"}},
            {"code": "void query(sqlite3 *db, char *s) { sqlite3_exec(db, s, 0, 0); }"},
        )
        assert "骨架" in sql["reason"] and sql["verdict"] == "uncertain"
    finally:
        ir.ENABLED = False


# 6) 抽象后端：未接入时返回 unavailable，不产出 findings
def t_unavailable_backends() -> None:
    sb = get_symbolic_backend()
    res = sb.analyze("void f() { }", [], ["system"], {})
    assert res["status"] == "unavailable"
    assert res["findings"] == []

    tb = get_taint_backend()
    res2 = tb.track("void f() { }", ["input"], ["system"], {})
    assert res2["status"] == "unavailable"
    assert res2["findings"] == []


def main() -> int:
    check("覆盖率排序（增益降序 / 无数据原序）", t_rank_by_coverage)
    check("邻域变异生成候选", t_neighbor_mutate)
    check("最小化：无 replay 原样返回", t_minimize_none_replay)
    check("最小化：replay 恒真则缩减", t_minimize_replay_true)
    check("最小化：replay 恒假则保留", t_minimize_replay_false)
    check("命令注入探针 harness 文本", t_cmd_probe_harness_text)
    check("注入探针降级路径", t_probe_skip_paths)
    check("符号/污点抽象后端 unavailable", t_unavailable_backends)
    print("P2_FRAMEWORK OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
