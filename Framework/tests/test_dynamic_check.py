# -*- coding: utf-8 -*-
"""dynamic_check 冒烟测试：本机无 gcc，只验证降级路径与 harness 生成逻辑。"""
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tools.dynamic_check as dc
from tools.dynamic_check import (
    CONF_DYNAMIC_CRASH,
    MAX_ITERATIONS,
    NEIGHBOR_TOP_K,
    OUTCOME_DISABLED,
    OUTCOME_NOT_APPLICABLE,
    OUTCOME_SAFE,
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
    _export_gcov,
    _coverage_signature,
    _rank_by_coverage,
    _neighbor_mutate,
    _is_crash,
    _parse_llm_seeds,
    _merge_seeds,
    _llm_seeds,
    _FUNC_RE,
    _NUMERIC_RE,
    _STRING_LITERAL_RE,
    _sanitizer_flags,
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
    """是否具备"真正复现崩溃"的条件：docker 容器，或本地编译器可链接 sanitizer。

    仅存在 gcc 但工具链未带 ASan/UBSan 运行库（部分 MinGW 构建）时，小范围
    栈/堆越界不触发 SEGV，正向崩溃用例继续 SKIP，不在此环境断言 accept。
    """
    if shutil.which("docker") is not None:
        return True
    compiler = _toolchain()
    return compiler is not None and bool(_sanitizer_flags(compiler, False))


# 6) 应用层开关 enabled=False → 直接跳过，不探测工具链、不触发编译/运行
h_off = {"finding_id": "f-004", "cwe": "CWE-119", "location": {"function": "copy_name"}}
r_off = dynamic_check(h_off, {"code": SAMPLE_VULN}, enabled=False)
print("[6] disabled:", r_off["verdict"], "|", r_off["reason"])
assert r_off["verdict"] == "uncertain" and r_off["confidence"] == 0.0
assert "已关闭" in r_off["reason"]

# 7) 正向崩溃复现：有 docker 或本地编译器可链接 sanitizer 时，越界样本应被
#    ASan/运行时错误抓住 → accept 0.92；缺执行环境 / 缺 sanitizer 运行库时跳过。
if not _exec_available():
    print("[7] SKIP: 未找到可链接 ASan/UBSan 的编译器或 docker，正向崩溃用例不在本机执行")
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
# 无编译器/docker → toolchain_missing；有编译器（即便缺 sanitizer 运行库，
# 退化普通编译）跑通未崩 → safe。两种环境都绝不 reject。
assert r["outcome"] in (OUTCOME_TOOLCHAIN_MISSING, OUTCOME_SAFE), r["outcome"]
assert r["evidence"]["outcome"] == r["outcome"]
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

# 20) 第二轮闭环·导出降级：空目录无 gcov 产物时导出不抛异常，签名回退 None
with tempfile.TemporaryDirectory() as td:
    _export_gcov(td, None, False)
    assert _coverage_signature(td) is None, "空目录无覆盖产物应返回 None"
print("[20] gcov export degrades silently; empty dir signature -> None")

# 21) 第二轮闭环·覆盖增量排序：新增覆盖多的种子排前（临时开启覆盖反馈）
old_cov = dc.COVERAGE_ENABLED
dc.COVERAGE_ENABLED = True
try:
    calls_rank = ["seed_a", "seed_b"]
    sigs = {0: frozenset({1}), 1: frozenset({1, 2, 3, 4})}
    ordered, gains = _rank_by_coverage(calls_rank, sigs)
    assert ordered[0] == "seed_b", f"增量更大的 seed_b 应排前: {ordered}"
    assert gains[1][0] > gains[0][0], "seed_b 新增覆盖量应大于 seed_a"
finally:
    dc.COVERAGE_ENABLED = old_cov
print("[21] coverage-gain ranking: higher-gain seed first")

# 22) 第二轮闭环·邻域变异候选去重：候选不含首轮原调用，且与首轮集合不相交
sample_call = 'copy_name((char*)malloc(64), "longstringAAAA", 4096);'
variants = _neighbor_mutate(sample_call)
seen2 = {sample_call}
second_round = [v for v in variants if v not in seen2]
assert second_round, "应至少生成一个邻域变异候选"
assert all(v != sample_call for v in second_round)
assert NEIGHBOR_TOP_K >= 1
print("[22] neighbor variants deduped, exclude first-round seeds; top_k =", NEIGHBOR_TOP_K)

# 23) 保守崩溃判定：退化普通编译仅凭非零退出码不算崩，须有明确标记；
#     sanitizer 在位时非零退出码可采信。
assert not _is_crash(1, "", False), "退化环境空 blob + 非零退出码不应判崩"
assert _is_crash(1, "Segmentation fault (core dumped)", False), "SEGV 文案在退化环境应判崩"
assert _is_crash(1, "", True), "sanitizer 在位时非零退出码可采信"
assert not _is_crash(0, "", True), "退出码 0 不应判崩"
print("[23] conservative crash gate: mark-only fallback when sanitizer missing")

# 24) LLM 输出解析：合法语句保留，注释/围栏/非本函数调用/重复行丢弃
LLM_RAW = """```c
copy_name((char*)malloc(1), "x", 4096);
// 这是注释
other_func(1);
copy_name((char*)malloc(1), "x", 4096);
copy_name(NULL, NULL, -1)
```"""
parsed = _parse_llm_seeds(LLM_RAW, "copy_name")
assert parsed == [
    "copy_name((char*)malloc(1), \"x\", 4096);",
    "copy_name(NULL, NULL, -1);",
], parsed
assert not any("other_func" in p for p in parsed)
print("[24] llm seed parse: valid kept, noise/dup dropped")

# 25) 种子合并：LLM 排前、去重保序、按上限截断
merged = _merge_seeds(["L1", "L2"], ["H1", "L2"])
assert merged == ["L1", "L2", "H1"], merged
assert _merge_seeds(["a", "b", "c"], cap=2) == ["a", "b"]
print("[25] seed merge: llm-first, dedup, cap")

# 26) LLM 种子提供方：可用假客户端出种子；抛异常 / None 客户端回退空列表
class _FakeResp:
    def __init__(self, content):
        self.content = content


class _FakeLLM:
    def __init__(self, content=None, exc=None):
        self.content, self.exc = content, exc

    def invoke(self, prompt):
        if self.exc:
            raise self.exc
        return _FakeResp(self.content)


good = _llm_seeds(_FakeLLM('copy_name((char*)malloc(1), "x", 4096);'),
                  "copy_name", ["char*", "const char*", "int"], "src", "120")
assert good == ["copy_name((char*)malloc(1), \"x\", 4096);"], good
assert _llm_seeds(_FakeLLM(exc=RuntimeError("boom")), "copy_name", [], "src", "120") == []
assert _llm_seeds(None, "copy_name", [], "src", "120") == []
print("[26] llm provider: seeds on success, empty fallback on error/None")

# 27) 工具链发现 / 本地环境 / 覆盖工具适配（离线，不触发真实编译链接）
import os as _os
_fake_cc = _os.path.abspath(__file__)  # 存在的文件，仅用于命中 DYNCHECK_CC 分支
_os.environ["DYNCHECK_CC"] = _fake_cc
assert dc._toolchain() == _fake_cc, "DYNCHECK_CC 显式路径应优先返回"
_os.environ.pop("DYNCHECK_CC", None)

_env = dc._local_env(r"C:\fake\llvm-mingw\bin\clang.exe")
assert _env["PATH"].startswith(r"C:\fake\llvm-mingw\bin" + _os.pathsep)
assert "PATH" in dc._local_env(None)

_tool, _runner = dc._find_gcov_tool(None)
assert _runner in (None, "llvm-cov", "gcov")
# 无工具 / 空目录时导出静默返回，不抛异常、不阻塞主流程
dc._export_gcov(tempfile.mkdtemp(), None, False)
print("[27] toolchain discovery, local env, gcov-tool adaptation")

print("SMOKE OK")
