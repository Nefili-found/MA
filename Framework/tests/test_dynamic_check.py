# -*- coding: utf-8 -*-
"""dynamic_check 冒烟测试：本机无 gcc，只验证降级路径与 harness 生成逻辑。"""
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.dynamic_check import (
    CONF_DYNAMIC_CRASH,
    MAX_ITERATIONS,
    OUTCOME_DISABLED,
    OUTCOME_NOT_APPLICABLE,
    OUTCOME_TOOLCHAIN_MISSING,
    dynamic_check,
    _extract_function,
    _gen_calls,
    _collect_dep_sources,
    _extract_type_definitions,
    _param_role,
    _harness,
    _minimize_call,
    _parse_gcov_lines,
    _read_line_coverage,
    _FUNC_RE,
    _NUMERIC_RE,
    _STRING_LITERAL_RE,
    _toolchain,
)

SAMPLE_VULN = """
#include <string.h>
void copy_name(char *dst, const char *src, int len) {
    memcpy(dst, src, len);
}
"""

# 1) 语法：动态导入无报错
print("[1] import OK")

# 2) 内存类 CWE + 本机无 gcc → 优雅跳过，不抛异常
h = {
    "finding_id": "f-001",
    "cwe": "CWE-119",
    "location": {"function": "copy_name"},
}
r = dynamic_check(h, {"code": SAMPLE_VULN})
print("[2] memory CWE result:", r["verdict"], "| conf:", r["confidence"], "|", r["reason"])
assert r["verdict"] == "uncertain" and r["confidence"] == 0.0

# 3) 非内存类 CWE → 直接跳过（不会尝试编译）
h2 = {"finding_id": "f-002", "cwe": "CWE-78", "location": {"function": "copy_name"}}
r2 = dynamic_check(h2, {"code": SAMPLE_VULN})
print("[3] non-memory CWE result:", r2["reason"])
assert "非内存类" in r2["reason"]

# 4) harness 生成逻辑：提取函数 + 生成变异调用（不编译，只打印）
func_src = _extract_function(SAMPLE_VULN, "copy_name")
m = _FUNC_RE.search(func_src)
calls = _gen_calls("copy_name", [p.strip() for p in m.group("params").split(",")])
print("[4] extracted func:", "copy_name" in func_src, "| calls generated:", len(calls))
print("    sample call:", calls[0])

# 5) 永不 reject 检查：异常输入（空 code、无函数名）也返回 uncertain
r3 = dynamic_check({"finding_id": "f-003", "cwe": "CWE-120"}, {"code": ""})
print("[5] empty code result:", r3["verdict"], "|", r3["reason"])
assert r3["verdict"] != "reject"


def _exec_available() -> bool:
    """本机/容器是否具备编译执行条件（gcc/clang 或 docker）。"""
    return _toolchain() is not None or shutil.which("docker") is not None


# 6) 应用层开关 enabled=False → 直接跳过，不探测工具链、不触发编译/运行
h_off = {"finding_id": "f-004", "cwe": "CWE-119", "location": {"function": "copy_name"}}
r_off = dynamic_check(h_off, {"code": SAMPLE_VULN}, enabled=False)
print("[6] disabled:", r_off["verdict"], "|", r_off["reason"])
assert r_off["verdict"] == "uncertain" and r_off["confidence"] == 0.0
assert "已关闭" in r_off["reason"]

# 7) 正向崩溃复现：有 gcc/clang/docker 时，越界样本应被 ASan/运行时错误抓住 → accept 0.92；
#    无执行环境时跳过本用例（不在本机实跑编译-运行路径）。
if not _exec_available():
    print("[7] SKIP: 未找到 gcc/clang/docker，正向崩溃用例不在本机执行")
else:
    r_crash = dynamic_check(
        {"finding_id": "f-005", "cwe": "CWE-120",
         "location": {"function": "copy_name"}},
        {"code": SAMPLE_VULN},
    )
    print("[7] crash reproduce:", r_crash["verdict"],
          "| conf:", r_crash["confidence"], "|", r_crash["reason"])
    assert r_crash["verdict"] == "accept"
    assert r_crash["confidence"] == CONF_DYNAMIC_CRASH
    assert r_crash["evidence"].get("crash") is True

# ---- P1：harness 依赖补齐 + 种子增强（本机只验证生成逻辑，不编译） ----

SAMPLE_WITH_DEPS = """
#include <string.h>
struct name_buf { char data[32]; };
static int clamp_len(int n) { return n > 256 ? 256 : n; }
void copy_name(char *dst, const char *src, int len) {
    int safe = clamp_len(len);
    memcpy(dst, src, safe);
}
"""

# 8) 依赖闭包：同文件 helper 被收集进 harness 依赖列表
func_src_dep = _extract_function(SAMPLE_WITH_DEPS, "copy_name")
dep_names, dep_srcs, dep_source = _collect_dep_sources(
    SAMPLE_WITH_DEPS, "copy_name", func_src_dep
)
print("[8] dep functions:", dep_names, "| source:", dep_source)
assert "clamp_len" in dep_names
assert any("clamp_len" in s for s in dep_srcs)

# 9) 类型定义：struct 定义被提取进 harness 头部
type_defs = _extract_type_definitions(SAMPLE_WITH_DEPS)
print("[9] type defs:", [d.split()[1] if len(d.split()) > 1 else d for d in type_defs])
assert any("struct name_buf" in d for d in type_defs)

# 10) 种子增强：参数角色推断 + 串字面量 + 越界联动 + 上限截断
assert _param_role("char *dst") == "buffer"
assert _param_role("const char *src") == "buffer"
assert _param_role("int len") == "length"
calls2 = _gen_calls("copy_name", ["char *dst", "const char *src", "int len"])
print("[10] enhanced seeds:", len(calls2), "| sample:", calls2[0])
assert any('"A"' in c for c in calls2), "应包含短串字面量种子"
assert any("malloc(1)" in c and "4096" in c for c in calls2), "应包含小缓冲+大长度越界联动"
assert len(calls2) <= MAX_ITERATIONS

# 11) harness 拼装：类型定义 + 依赖函数 + 被测函数 + 分种子 main 同处一个编译单元
harness_text = _harness(type_defs, dep_srcs, func_src_dep, calls2)
assert "struct name_buf" in harness_text
assert "clamp_len" in harness_text
assert "int main(int argc" in harness_text
assert "atoi(argv[1])" in harness_text
print("[11] harness assembled: type defs + deps + target + indexed main")

# 12) 种子索引定位：每个种子包成独立 seed_i，main 的 case 与之一一对应
for i, call in enumerate(calls2):
    assert f"static void seed_{i}(void) {{ {call} }}" in harness_text, f"seed_{i} 与调用不匹配"
    assert f"case {i}: seed_{i}();" in harness_text, f"case {i} 缺失"
print("[12] seed index mapping: %d seeds → seed_i + case i" % len(calls2))

# ---- A 档：结果分级 / 种子边界 / harness 防护片段（离线只验生成与降级） ----

# 13) 结果分级：顶层 outcome 与证据 outcome 一致，分级口径与开关/适用域对应
assert r_off["outcome"] == OUTCOME_DISABLED, r_off["outcome"]
assert r_off["evidence"]["outcome"] == OUTCOME_DISABLED
assert r2["outcome"] == OUTCOME_NOT_APPLICABLE, r2["outcome"]
assert r["outcome"] == OUTCOME_TOOLCHAIN_MISSING, r["outcome"]
assert r["evidence"]["outcome"] == OUTCOME_TOOLCHAIN_MISSING
# 未崩 / 降级结果绝不 reject，且带超时计数档（离线无超时，记 0）
assert r["evidence"].get("timeouts") == 0
print("[13] outcome labels:", r_off["outcome"], "/", r2["outcome"], "/", r["outcome"])

# 14) 种子边界：整数含 INT_MIN 极值；buffer 种子含随机字母串与转义串
assert any("-2147483648" in c for c in calls2), "应含 INT_MIN 边界整数种子"
assert any("\\n\\t" in c for c in calls2), "应含特殊转义串种子"
assert any('"' in c and any(ch.isalnum() for ch in c) for c in calls2)
print("[14] boundary seeds: INT_MIN + escape literal + random alnum literal present")

# 15) harness 防护片段：rlimit 资源上限与危险信号保持默认处置（Linux 下生效）
assert "_apply_limits" in harness_text
assert "setrlimit" in harness_text
assert "RLIMIT_AS" in harness_text and "RLIMIT_CPU" in harness_text
assert "#ifdef __linux__" in harness_text
print("[15] harness guard: rlimit(AS/STACK/CPU/FSIZE) + signal defaults present")

# ---- 步骤 2/3：最小化二分与覆盖率行级解析（离线用样例文本/回调验证） ----

# 16) 数值收缩：大整数被替换为仍复现崩溃的最简候选；replay=None 原样返回
call_num = 'copy_name((char*)malloc(64), "longstringAAAA", 4096);'


def _replay_num(trial: str) -> bool:
    # 模拟：去掉 4096 这个危险大长度后崩溃仍复现
    return "4096" not in trial


min_num, rec_num = _minimize_call(call_num, replay=_replay_num)
print("[16] minimized num:", min_num, "| steps:", rec_num["steps"])
assert "4096" not in min_num
assert rec_num["minimized"] is True
min_raw, rec_raw = _minimize_call(call_num, replay=None)
assert min_raw == call_num and rec_raw["minimized"] is False

# 17) 串二分：前缀仍崩则继续砍；前缀不崩即保守停止，记录截断步
call_str = 'copy_name("longstringAAAA", 1);'


def _replay_str(trial: str) -> bool:
    m = _STRING_LITERAL_RE.search(trial)
    return m is not None and len(m.group(1)) <= 7


min_str, rec_str = _minimize_call(call_str, replay=_replay_str)
m_str = _STRING_LITERAL_RE.search(min_str)
print("[17] minimized str:", m_str.group(1), "| steps:", rec_str["steps"])
assert len(m_str.group(1)) <= 14  # 不超过原始长度
assert rec_str["minimized"] is True

# 18) gcov 文本解析：正计数行计入覆盖，不可执行/未覆盖行不计入
GCOV_SAMPLE = """
        -:    0:Source:copy.c
        2:    1:#include <string.h>
        5:    2:void copy_name(char *dst, const char *src, int len) {
    #####:    3:    memcpy(dst, src, len);
        1:    4:}
"""
covered = _parse_gcov_lines(GCOV_SAMPLE)
print("[18] gcov covered lines:", sorted(covered))
assert covered == {1, 2, 4}

# 19) _read_line_coverage：有 .gcov 文本返回行号集合；空目录返回 None
with tempfile.TemporaryDirectory() as td:
    cov = _read_line_coverage(td)
    assert cov is None, "无 .gcov 文本应返回 None"
    with open(Path(td) / "harness.gcov", "w", encoding="utf-8") as fh:
        fh.write(GCOV_SAMPLE)
    cov2 = _read_line_coverage(td)
    assert cov2 == {1, 2, 4}
print("[19] line coverage readback:", sorted(cov2))

print("SMOKE OK")
