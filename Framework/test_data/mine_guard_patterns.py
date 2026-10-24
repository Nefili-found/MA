#!/usr/bin/env python3
"""mine_guard_patterns.py

从 PrimeVul 原始 split 中抽样，统计「守卫 / 边界检查 / 净化器」候选模式在
vulnerable（target=1）与 benign（target=0）函数里的出现率，用于给
``tools/verify_taint.py`` 的 blocker 词表提供**语料驱动**的种子（设计 §4.4-B）。

用法（在 Framework 根目录）：
    python test_data/mine_guard_patterns.py --split valid --limit 4000
    python test_data/mine_guard_patterns.py --split test  --limit 8000 --top 40

判读方式：
    * ``benign%`` 高、``vuln%`` 低 且 ``lift = benign% / vuln%`` 明显 > 1 的模式，
      才适合当 blocker（它更多出现在**没有**漏洞的代码里）；
    * ``lift`` ≈ 1 的模式没有区分力，只说明该写法普遍，不宜单独作为 reject 依据。

只做统计，不写任何文件；纯离线，不依赖第三方库。
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys

RAW_DIR = os.path.join(os.path.dirname(__file__), "primevul_raw")

# 候选 blocker 模式（结构化写法，尽量贴近真实 C/C++ 代码）
GUARD_PATTERNS = {
    # ---- null / 有效性检查 ----
    "null_eq": r"==\s*(?:NULL|nullptr|0)\b",
    "null_neq": r"!=\s*(?:NULL|nullptr|0)\b",
    "null_bang": r"if\s*\(\s*!\s*[A-Za-z_][\w\.\->\[\]]*\s*\)",
    "isnull_call": r"\b(?:IsNull\w*|isNull\w*|IsNullOrEmpty|IsEmpty|empty)\s*\(",
    "assert_family": r"\b(?:assert|ASSERT|DCHECK|DCHECK_EQ|DCHECK_NE|DCHECK_GE|DCHECK_LE|DCHECK_LT|CHECK|CHECK_EQ|CHECK_NE|CHECK_GE|CHECK_LE|CHECK_LT|CHECK_GT|NOTREACHED)\s*\(",
    # ---- 边界 / 长度检查 ----
    "bounds_sizeof": r"(?:<=|>=|<|>)\s*sizeof\s*\(",
    "bounds_len_cmp": r"\b(?:len|length|size|count|sz|n|idx|index|pos)\b\s*(?:<=|>=|<|>)\s*[A-Za-z0-9_]",
    "bounds_fits": r"\b(?:fits|Fits|CanFit|Bounds|bounds|Clamp|clamp|Limit|limit|Min|Max)\w*\s*\(",
    "bounds_required": r"\b(?:required|Required|required_size|needed)\b",
    # ---- 净化 / 校验 ----
    "validate_call": r"\b(?:Validat|validat|Verif|verif|Check|check|Ensure|ensure|Valid|valid|Allowed|allowed)\w*\s*\(",
    "sanitize_call": r"\b(?:Sanitiz|sanitiz|Escape|escape|Encode|encode|Normalize|normalize)\w*\s*\(",
    "whitelist": r"\b(?:whitelist|Whitelist|allowlist|Allowlist|is_allowed|allowed_values)\b",
    # ---- 安全拷贝 / 有界写入 ----
    "safe_copy": r"\b(?:strncpy_s|strcpy_s|strcat_s|snprintf|snprintf_s|vsnprintf|memcpy_s|memmove_s|strlcpy|SafeCopy)\w*\s*\(",
    "safe_string": r"\bSafeString\s*\(",
    # ---- 提前退出 / 错误处理 ----
    "early_return": r"if\s*\([^;\n]{0,160}\)\s*(?:\{\s*)?(?:return|continue|break)\b",
    "goto_cleanup": r"\bgoto\s+(?:fail|err|error|out|cleanup|done|end|exit)\b",
}

# 值得额外挖掘的「校验类函数名」前缀（用于发现语料里实际常用的净化器）
VALIDATOR_PREFIXES = (
    "Is", "Has", "Can", "Check", "Validate", "Valid", "Verify", "Ensure",
    "Sanitize", "Escape", "Normalize", "Safe", "Clamp", "Limit", "Bounds",
)
CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


def iter_funcs(split: str, limit: int):
    """流式读取指定 split，产出 (func 文本, label)。"""
    path = os.path.join(RAW_DIR, f"primevul_{split}.jsonl")
    if not os.path.exists(path):
        raise SystemExit(f"未找到 {path}")
    n = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            s = line.strip()
            if not s:
                continue
            try:
                d = json.loads(s)
            except Exception:
                continue
            func = d.get("func")
            if not isinstance(func, str) or not func.strip():
                continue
            label = d.get("target")
            if label not in (0, 1):
                continue
            yield func, int(label)
            n += 1
            if limit and n >= limit:
                return


# 「同一标识符在解引用前被判空」的守卫形态（贴近设计 §4.4-B 的真实规则）
DEREF_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?:->|\.)")


def _guard_before_deref_metrics(func: str):
    """统计：函数内被解引用的标识符里，有多少在**首次解引用之前**被判空。

    返回 (deref_ident_count, guarded_before_count)。
    判空形态：``X == NULL`` / ``X != NULL`` / ``!X`` / ``DCHECK(X)`` / ``CHECK(X)``。
    """
    derefs = {}
    for m in DEREF_RE.finditer(func):
        name = m.group(1)
        # 排除 this / nullptr 之类的关键字式写法
        if name in ("this", "nullptr", "NULL", "std", "return", "else", "if"):
            continue
        derefs.setdefault(name, m.start())

    guarded = 0
    for name, first_pos in derefs.items():
        n = re.escape(name)
        pats = (
            rf"\b{n}\s*==\s*(?:NULL|nullptr|0)\b",
            rf"\b{n}\s*!=\s*(?:NULL|nullptr|0)\b",
            rf"!\s*{n}\b\s*\)",
            rf"\b(?:DCHECK|CHECK|assert|ASSERT)\s*\(\s*{n}\s*\)",
        )
        prefix = func[:first_pos]
        if any(re.search(p, prefix) for p in pats):
            guarded += 1
    return len(derefs), guarded


def mine(split: str, limit: int, top: int) -> int:
    total = {0: 0, 1: 0}
    hits = {k: {0: 0, 1: 0} for k in GUARD_PATTERNS}
    validator_calls = {0: collections.Counter(), 1: collections.Counter()}
    # 「同一标识符解引用前判空」指标
    deref_func_hit = {0: 0, 1: 0}       # 至少有一个标识符被判空后才解引用的函数数
    deref_total = {0: 0, 1: 0}          # 被解引用标识符总数
    deref_guarded = {0: 0, 1: 0}        # 其中判空在前的个数

    lines = {0: 0, 1: 0}  # 用于检查「函数长度」这个混淆变量
    for func, label in iter_funcs(split, limit):
        total[label] += 1
        lines[label] += func.count("\n") + 1
        for key, pat in GUARD_PATTERNS.items():
            if re.search(pat, func):
                hits[key][label] += 1
        for name in set(CALL_RE.findall(func)):
            if any(name.startswith(p) for p in VALIDATOR_PREFIXES):
                validator_calls[label][name] += 1

        n_deref, n_guarded = _guard_before_deref_metrics(func)
        deref_total[label] += n_deref
        deref_guarded[label] += n_guarded
        if n_guarded:
            deref_func_hit[label] += 1

    if not total[0] and not total[1]:
        print("没有抽到任何样本", file=sys.stderr)
        return 1

    print("=== mine_guard_patterns.py ===")
    print(f"split={split}  kept={total[0] + total[1]}  benign={total[0]}  vulnerable={total[1]}")
    for label, name in ((0, "benign"), (1, "vulnerable")):
        if total[label]:
            print(f"  avg lines ({name}) = {lines[label] / total[label]:.1f}")
    print()
    print(f"{'pattern':<18}{'benign%':>9}{'vuln%':>9}{'lift':>8}  note")
    print("-" * 60)
    rows = []
    for key in GUARD_PATTERNS:
        b = 100.0 * hits[key][0] / total[0] if total[0] else 0.0
        v = 100.0 * hits[key][1] / total[1] if total[1] else 0.0
        lift = (b / v) if v > 0 else float("inf")
        rows.append((key, b, v, lift))
    rows.sort(key=lambda r: (-(r[3] if r[3] != float("inf") else 1e9), -r[1]))
    for key, b, v, lift in rows:
        lift_s = "inf" if lift == float("inf") else f"{lift:.2f}"
        note = "强区分" if lift >= 1.5 else ("弱/无区分" if lift < 1.2 else "中等")
        print(f"{key:<18}{b:>8.1f}%{v:>8.1f}%{lift_s:>8}  {note}")

    # ---- 「同一标识符解引用前判空」的区分力 ----
    print()
    print("--- 同一标识符在首次解引用前被判空（= 设计 §4.4-B 的真实规则）---")
    for label, name in ((0, "benign"), (1, "vulnerable")):
        if not total[label]:
            continue
        func_pct = 100.0 * deref_func_hit[label] / total[label]
        ident_pct = (
            100.0 * deref_guarded[label] / deref_total[label] if deref_total[label] else 0.0
        )
        print(
            f"  {name:<11} 命中函数占比={func_pct:5.1f}%   被守卫标识符占比={ident_pct:5.1f}%"
            f"   (deref 标识符数={deref_total[label]})"
        )
    if total[0] and total[1] and deref_func_hit[0] and deref_func_hit[1]:
        lift = (deref_func_hit[0] / total[0]) / (deref_func_hit[1] / total[1])
        print(f"  lift(函数级) = {lift:.2f}  " + ("→ 可用于 reject" if lift >= 1.2 else "→ 区分力不足，不能单独 reject"))

    print()
    print(f"--- 语料中最常见的校验类函数调用（benign 前 {top} 个）---")
    for name, c in validator_calls[0].most_common(top):
        v = validator_calls[1].get(name, 0)
        print(f"  {name:<32} benign={c:<6} vulnerable={v}")

    print()
    print(f"--- 语料中最常见的校验类函数调用（vulnerable 前 {top} 个）---")
    for name, c in validator_calls[1].most_common(top):
        b = validator_calls[0].get(name, 0)
        print(f"  {name:<32} vulnerable={c:<6} benign={b}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="统计 PrimeVul 中守卫/边界/净化模式的出现率。")
    ap.add_argument("--split", default="valid", choices=["train", "valid", "test"])
    ap.add_argument("--limit", type=int, default=4000, help="最多抽样多少条函数（0=全部，很慢）")
    ap.add_argument("--top", type=int, default=25, help="校验类函数名展示条数")
    args = ap.parse_args()
    return mine(args.split, args.limit, args.top)


if __name__ == "__main__":
    sys.exit(main())
