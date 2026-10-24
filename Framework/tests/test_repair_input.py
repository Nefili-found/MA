# -*- coding: utf-8 -*-
"""修复端输入投影（repair-input/1）的离线自测。

运行（在 Framework 根目录）：
    .venv/Scripts/python.exe tests/test_repair_input.py

覆盖（对应 change_process/summery/修复端_输入需求与用途_2026-10-23_现状.md）：
    1. 按行号反查函数（§2.1）—— 不依赖 LLM 报的函数名；
    2. 漏洞行吸附到最内层语句（§2.2）；
    3. 行号落在签名行 / 花括号行时退化为「下一条语句」；
    4. func_src 按原文件字节切出（§4 code 段）；
    5. CWE 归一为 ^CWE-\\d+$（§2.3）；
    6. _resolve_location 修好 location 之后，conditions[].holds 不再是 null（级联修复）；
    7. §4 六条校验能拦住坏 case（行号在函数外 / 绝对路径 / 空 CWE）；
    8. 一条 case 的完整投影形状 + case_id 唯一。

全部通过会打印 ALL_TESTS_PASS 并以退出码 0 结束。
"""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools.call_context import (  # noqa: E402
    build_context,
    function_body_source,
    set_active_context,
    statement_at_line,
)
from tools.verify_taint import verify_taint  # noqa: E402
import verify_agent.d as d  # noqa: E402

# 行号对照（1-based）：
#   3 = int decrypt(...)   4 = {          5 = int len = n;
#   6 = if (len > 16)      7 = memcpy(...)  8 = return len;   9 = }
CODE = """#include <string.h>

int decrypt(char *out, const char *in, int n)
{
  int len = n;
  if (len > 16)
    memcpy(out, in, len);
  return len;
}
"""

PLACEHOLDER = "containing function unavailable in supplied excerpt"


def check(name: str, fn) -> None:
    fn()
    print(f"  ok  {name}")


def _raw_finding(**over) -> dict:
    finding = {
        "id": "A-1",
        "title": "out-of-bounds write",
        "cwe": "CWE-787 越界写",
        "location": {
            "file": "src/decrypt.c",
            "line_start": 7,
            "line_end": 7,
            "function": PLACEHOLDER,
        },
        "confidence": 0.8,
        "verdict": "accept",
        "taint_source": "n",
        "taint_sink": "memcpy",
        "assumptions": [
            {"id": "cond-1", "kind": "bounds_check", "text": "len 未与 out 的容量比较"}
        ],
        "suggestion": "把 len 夹取到目标缓冲区容量",
    }
    finding.update(over)
    return finding


# ---------------------------------------------------------------------------
# 1. 按行号反查函数
# ---------------------------------------------------------------------------
def t_function_at_line() -> None:
    ctx = build_context(CODE)
    info = ctx.function_at(7)
    assert info is not None, "第 7 行应落在 decrypt 内"
    assert info["function"] == "decrypt", info
    assert (info["line_start"], info["line_end"]) == (3, 9), info
    assert ctx.function_at(1) is None, "第 1 行在所有函数之外"
    assert ctx.function_at(0) is None, "行号 0 = 未知，不应命中"


# ---------------------------------------------------------------------------
# 2 / 3. 语句级吸附
# ---------------------------------------------------------------------------
def t_statement_contains() -> None:
    hit = statement_at_line(CODE, 7)
    assert hit is not None and hit["matched"] == "contains", hit
    assert (hit["line_start"], hit["line_end"]) == (7, 7), hit
    assert hit["kind"] == "expression_statement", hit
    assert "memcpy" in hit["text"], hit

    # 落在 if 头行 → 命中 if_statement 本身（不是它的块首行）
    head = statement_at_line(CODE, 6)
    assert head is not None and head["kind"] == "if_statement", head
    assert (head["line_start"], head["line_end"]) == (6, 7), head


def t_statement_fallback_next() -> None:
    # 第 4 行是函数体的 '{'，不属于任何语句 → 退化到下一条语句（第 5 行）
    assert statement_at_line(CODE, 4) is None, "不带退化时应返回 None"
    hit = statement_at_line(CODE, 4, fallback_to_next=True)
    assert hit is not None and hit["matched"] == "next", hit
    assert hit["line_start"] == 5 and hit["kind"] == "declaration", hit
    # 函数末尾之后没有任何语句 → 退化也取不到
    assert statement_at_line(CODE, 99, fallback_to_next=True) is None


# ---------------------------------------------------------------------------
# 4. func_src 按原文件字节切出
# ---------------------------------------------------------------------------
def t_func_src_bytes() -> None:
    src = function_body_source(CODE, 3, 9)
    assert src.startswith("int decrypt(char *out"), src[:40]
    assert src.rstrip("\n").endswith("}"), src[-20:]
    assert len(src.splitlines()) == 9 - 3 + 1, len(src.splitlines())
    # 非法区间一律返回空串，绝不返回错位的半截代码
    assert function_body_source(CODE, 0, 9) == ""
    assert function_body_source(CODE, 9, 3) == ""
    assert function_body_source(CODE, 100, 120) == ""


# ---------------------------------------------------------------------------
# 5. CWE 归一
# ---------------------------------------------------------------------------
def t_cwe_normalize() -> None:
    assert d._normalize_cwe("CWE-787 越界写") == "CWE-787"
    assert d._normalize_cwe("cwe_125") == "CWE-125"
    assert d._normalize_cwe("CWE-476") == "CWE-476"
    assert d._normalize_cwe("buffer overflow") == ""
    assert d._normalize_cwe(None) == ""
    assert d._normalize_cwe("") == ""


# ---------------------------------------------------------------------------
# 6. _resolve_location：校正后才谈得上 conditions
# ---------------------------------------------------------------------------
def t_resolve_location() -> None:
    ctx = build_context(CODE)
    resolved = d._resolve_location(_raw_finding(), ctx, CODE)
    loc = resolved["location"]
    assert loc["function"] == "decrypt", loc          # 占位文本被语法树事实覆盖
    assert loc["function_resolved_by"] == "ast", loc
    assert (loc["function_line_start"], loc["function_line_end"]) == (3, 9), loc
    assert (loc["line_start"], loc["line_end"]) == (7, 7), loc
    assert loc["line_source"] == "ast", loc
    # 原始 finding 不被就地改写
    assert _raw_finding()["location"]["function"] == PLACEHOLDER


def t_resolve_enables_conditions() -> None:
    """级联修复：函数名校正后，check_assumptions 才取得到函数体。"""
    ctx = build_context(CODE)
    set_active_context(ctx)

    broken = d._build_hypothesis(_raw_finding(), CODE)
    broken_out = verify_taint(broken, {"file": "src/decrypt.c", "code": CODE})
    assert all(c["holds"] is None for c in broken_out["evidence"]["conditions"]), broken_out

    fixed = d._build_hypothesis(d._resolve_location(_raw_finding(), ctx, CODE), CODE)
    fixed_out = verify_taint(fixed, {"file": "src/decrypt.c", "code": CODE})
    conds = fixed_out["evidence"]["conditions"]
    assert conds, fixed_out
    assert all(c["holds"] is not None for c in conds), conds


# ---------------------------------------------------------------------------
# 7. §4 六条校验
# ---------------------------------------------------------------------------
def t_validate_catches_bad_cases() -> None:
    good = d._build_repair_input(
        [d._resolve_location(_raw_finding(), build_context(CODE), CODE)],
        "src/decrypt.c",
        {
            "code": CODE,
            "case_id": "CVE-2018-0001",
            "repo": "example",
            "commit": "deadbeef",
            "rel_file": "src/decrypt.c",
        },
    )
    assert good["cases"][0]["validation"]["ok"], good["cases"][0]["validation"]

    case = good["cases"][0]

    # 行号落在函数外
    bad = {**case, "vuln": {**case["vuln"], "line": 40}, "validation": {}}
    errors = d._validate_repair_case(bad)
    assert any("函数范围" in e for e in errors), errors

    # CWE 抽不出来 → 非规范串
    bad = {**case, "vuln": {**case["vuln"], "cwe": ""}, "validation": {}}
    assert any("cwe" in e for e in d._validate_repair_case(bad))

    # func_src 与行范围不自洽
    bad = {**case, "code": {**case["code"], "func_src": "int f();\n"}, "validation": {}}
    assert any("行数" in e for e in d._validate_repair_case(bad))

    # 绝对路径
    bad = {
        **case,
        "source": {**case["source"], "file": "C:/work/example/src/decrypt.c"},
        "validation": {},
    }
    assert any("绝对路径" in e for e in d._validate_repair_case(bad))

    # verdict 非法
    bad = {**case, "vuln": {**case["vuln"], "verdict": "yes"}, "validation": {}}
    assert any("verdict" in e for e in d._validate_repair_case(bad))


# ---------------------------------------------------------------------------
# 8. 投影形状 + case_id 唯一
# ---------------------------------------------------------------------------
def t_projection_shape() -> None:
    ctx = build_context(CODE)
    resolved = d._resolve_location(_raw_finding(), ctx, CODE)
    payload = d._build_repair_input(
        [resolved],
        "src/decrypt.c",
        {
            "code": CODE,
            "repo": "example",
            "commit": "deadbeef",
            "rel_file": "src/decrypt.c",
        },
    )
    assert payload["schema"] == "repair-input/1", payload["schema"]
    assert payload["provenance"]["case_count"] == 1, payload["provenance"]
    assert payload["provenance"]["invalid_count"] == 0, payload["provenance"]

    case = payload["cases"][0]
    assert case["source"] == {
        "repo": "example",
        "commit": "deadbeef",
        "file": "src/decrypt.c",
        "scan_file": "src/decrypt.c",
    }, case["source"]
    assert case["vuln"]["cwe"] == "CWE-787", case["vuln"]
    assert case["vuln"]["line"] == 7 and case["vuln"]["func"] == "decrypt", case["vuln"]
    assert case["vuln"]["confidence"] == 0.8 and case["vuln"]["verdict"] == "accept", case["vuln"]
    assert case["code"]["func_src"] == function_body_source(CODE, 3, 9), case["code"]
    assert (case["code"]["body_line_start"], case["code"]["body_line_end"]) == (3, 9), case["code"]
    assert case["code"]["truncated"] is False, case["code"]
    assert case["code"]["line_source"] == "ast", case["code"]
    # 函数没定位到时 func_src 为空，必须被校验判 invalid（不能悄悄交出去）
    assert case["case_id"], case


def t_case_id_unique() -> None:
    ctx = build_context(CODE)
    findings = [
        d._resolve_location(_raw_finding(id="A-1"), ctx, CODE),
        d._resolve_location(_raw_finding(id="B-1", location={
            "file": "src/decrypt.c", "line_start": 5, "line_end": 5, "function": PLACEHOLDER,
        }), ctx, CODE),
    ]
    payload = d._build_repair_input(findings, "src/decrypt.c", {"code": CODE, "rel_file": "src/decrypt.c"})
    ids = [c["case_id"] for c in payload["cases"]]
    assert len(ids) == len(set(ids)) == 2, ids
    assert all(c["validation"]["ok"] for c in payload["cases"]), [c["validation"] for c in payload["cases"]]


def t_missing_function_is_invalid() -> None:
    """函数定位不到 → func_src 为空 → 校验必须拦下（不是"修不好"）。"""
    finding = _raw_finding(location={
        "file": "src/decrypt.c", "line_start": 7, "line_end": 7, "function": "nope",
    })
    payload = d._build_repair_input([finding], "src/decrypt.c", {"code": CODE, "rel_file": "src/decrypt.c"})
    case = payload["cases"][0]
    assert case["code"]["func_src"] == "", case["code"]
    assert case["validation"]["ok"] is False, case["validation"]
    assert any("func_src 为空" in e for e in case["validation"]["errors"]), case["validation"]


def main() -> int:
    print("=== 修复端输入投影（repair-input/1）自测 ===")
    check("定位：按行号反查函数", t_function_at_line)
    check("语句：吸附到最内层语句", t_statement_contains)
    check("语句：签名/花括号行退化为下一条语句", t_statement_fallback_next)
    check("函数全文：按原文件字节切出", t_func_src_bytes)
    check("CWE：归一为规范串", t_cwe_normalize)
    check("定位：跳过 LLM 的占位函数名", t_resolve_location)
    check("级联：校正后 conditions.holds 不再是 null", t_resolve_enables_conditions)
    check("校验：六条能拦住坏 case", t_validate_catches_bad_cases)
    check("投影：字段形状符合 §4", t_projection_shape)
    check("投影：case_id 批次内唯一", t_case_id_unique)
    check("投影：函数定位不到时判 invalid_baseline", t_missing_function_is_invalid)
    print("ALL_TESTS_PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
