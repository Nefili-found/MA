# -*- coding: utf-8 -*-
"""dynamic_check 冒烟测试：本机无 gcc，只验证降级路径与 harness 生成逻辑。"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.dynamic_check import (
    dynamic_check, _extract_function, _gen_calls, _FUNC_RE,
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

print("SMOKE OK")
