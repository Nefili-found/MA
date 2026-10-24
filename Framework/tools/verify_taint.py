"""污点假设验证工具（工具信号实现）。

设计依据：`change_process/design/汇总Agent_验证环节_假设条件与触发路径_设计.md`
（§4.1–§4.4）与父设计 `汇总Agent_验证环节_设计.md`（§3.1）。

本文件产出**独立于 LLM 的工具信号**：

* ``check_trigger_path``  —— 触发路径逐跳可达性（同文件调用图，确定性）
* ``check_assumptions``   —— 假设条件 blocker 核验（启发式，作用域化）
* ``verify_taint``        —— 两者汇总为父设计 §3.1 的返回结构

================================================================================
【重要：blocker 的语料口径】见 §4.4-B 实测注记与 test_data/mine_guard_patterns.py
--------------------------------------------------------------------------------
在 PrimeVul（valid / test 各抽 4000 条）上实测：**结构化守卫写法在 vulnerable 函数里
反而更常见**（函数平均长度 34.5 vs 175.3 行带来的混淆）：

    null_eq            benign 16.3%  vuln 43.4%  lift 0.38
    null_bang          benign 13.9%  vuln 40.3%  lift 0.34
    bounds_len_cmp     benign  4.3%  vuln 22.0%  lift 0.19
    goto_cleanup       benign  0.5%  vuln  9.7%  lift 0.05
    「同一标识符判空在解引用前」benign 10.5%  vuln 27.1%  lift 0.39

因此本实现**不采用**「函数里出现过守卫 → 条件不成立」的朴素规则，而是三重作用域化：

1. **符号作用域**：守卫判空的必须就是假设里点名的那个符号（来自 ``taint_source``
   或假设文本），而不是任意标识符；
2. **位置作用域**：守卫必须出现在 sink 行之前；
3. **块作用域**：守卫所在行的花括号深度必须 <= sink 所在行的深度
   （即守卫块支配 / 包住 sink，兄弟分支里的守卫不算）。

并且 blocker 命中的置信度封顶 ``CONF_BLOCKER_ONLY = 0.55``，低于默认 τ(=0.8)，
**单凭启发式永远不能单独推翻 finding**（详见 d.py::_combine）。这不是保守妥协，
而是上述实测结论的直接产物。

TODO: 后续接入真实静态分析 / 符号执行时，只需替换 check_assumptions 的实现，
      返回结构保持不变。
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from tools.call_context import (
    CallContext,
    active_context,
    get_callees,
    get_callers,
    get_function_body,
    set_active_context,
)

TOOL_NAME = "verify_taint"

# ---------------------------------------------------------------------------
# 置信度常量（与设计 §4.4-C 对齐；d.py::_combine 的 τ 阈值以此为输入）
# ---------------------------------------------------------------------------
CONF_PATH_BROKEN = 0.90   # 同文件调用图确定性断链
CONF_ACCEPT = 0.90        # 路径逐跳可达且条件均未被反驳
CONF_BLOCKER_ONLY = 0.55  # 仅命中启发式 blocker（故意低于默认 τ=0.8）
CONF_CHALLENGE = 0.30     # 存在无法核验的跳 / 条件

VERDICT_TO_STATUS = {
    "accept": "verified",
    "reject": "rejected",
    "challenge": "uncertain",
    "uncertain": "uncertain",
}

# 假设条件 kind 的别名归一
_KIND_ALIASES = {
    "null": "null_check",
    "null_check": "null_check",
    "nullptr": "null_check",
    "null_guard": "null_check",
    "bounds": "bounds_check",
    "bounds_check": "bounds_check",
    "length": "bounds_check",
    "size": "bounds_check",
    "oob": "bounds_check",
    "sanitizer": "sanitizer",
    "sanitize": "sanitizer",
    "validation": "sanitizer",
    "validate": "sanitizer",
}

_NULL_TOKENS = r"(?:NULL|nullptr|0)"
_ASSERT_FAMILY = r"(?:DCHECK|CHECK|CHECK_EQ|CHECK_NE|CHECK_GE|CHECK_LE|CHECK_LT|CHECK_GT|assert|ASSERT)"

# 常见 C/C++ 关键字与惯用词：从假设文本里抽符号时应排除
_KEYWORDS = frozenset(
    """
    if else for while do switch case default break continue return goto sizeof
    void int char short long float double signed unsigned const static extern
    struct union enum typedef class public private protected new delete this
    true false NULL nullptr auto inline virtual override template typename
    and or not NULL_ is are the of to in on when then must should may can
    check checked validation validated sanitizer guard null NULL_ptr
    """.split()
)

_IDENT_RE = re.compile(r"\b[A-Za-z_]\w*\b")
_MAX_SYMBOLS = 6


# ---------------------------------------------------------------------------
# 通用小工具
# ---------------------------------------------------------------------------
def _short(name: Any) -> str:
    """取函数短名（``A::B::f`` → ``f``），用于跨限定名比较。"""
    return str(name or "").split("::")[-1].strip()


def _resolve_function(name: Any, ctx: CallContext) -> Optional[str]:
    """把查询名归一为 ``ctx.functions`` 里的键；不在本文件内则返回 None。"""
    raw = str(name or "").strip()
    if not raw:
        return None
    cand = raw.split("(", 1)[0].strip()
    if cand in ctx.functions:
        return cand
    short = cand.split("::")[-1].strip()
    for key in ctx.functions:
        if key.split("::")[-1] == short:
            return key
    return None


def _norm_path(raw: Any) -> List[str]:
    """把路径字段归一为有序节点名列表（丢弃空元素与相邻重复）。"""
    seq: List[str] = []
    for item in raw or []:
        if isinstance(item, dict):
            text = str(
                item.get("function") or item.get("name") or item.get("node") or ""
            )
        else:
            text = str(item or "")
        text = text.strip()
        if not text:
            continue
        if not seq or seq[-1] != text:
            seq.append(text)
    return seq


def _normalize_assumptions(raw: Any) -> List[Dict[str, str]]:
    """归一假设条件为 ``[{id, kind, text}]``；结构异常时静默跳过。"""
    out: List[Dict[str, str]] = []
    if not isinstance(raw, list):
        return out
    for i, item in enumerate(raw):
        if isinstance(item, dict):
            text = str(item.get("text") or item.get("condition") or item.get("assume") or "").strip()
            kind = str(item.get("kind") or "other").strip()
            ident = str(item.get("id") or f"cond-{i + 1}").strip()
        elif isinstance(item, str):
            text, kind, ident = item.strip(), "other", f"cond-{i + 1}"
        else:
            continue
        if not text:
            continue
        out.append({"id": ident, "kind": kind, "text": text})
    return out


def _symbols_from(text: Any) -> List[str]:
    """从一段文本里抽取候选符号（标识符，排除关键字）。

    单字符标识符（``p`` / ``q`` / ``i``）在 C 代码里极常见，必须保留；
    关键字（``if`` / ``return`` 等）会被排除，正则匹配时用 ``\\b`` 定界。
    """
    out: List[str] = []
    for name in _IDENT_RE.findall(str(text or "")):
        if not name or name.lower() in _KEYWORDS:
            continue
        if name not in out:
            out.append(name)
    return out


def _target_symbols(hypothesis: Dict[str, Any], assumption: Dict[str, str]) -> List[str]:
    """假设条件要对哪个符号成立：优先 taint_source，其次假设文本。"""
    symbols: List[str] = []
    for text in (
        hypothesis.get("taint_source"),
        hypothesis.get("taint_sink"),
        assumption.get("text"),
    ):
        for name in _symbols_from(text):
            if name not in symbols:
                symbols.append(name)
    return symbols[:_MAX_SYMBOLS]


def _line_depths(lines: List[str]) -> List[int]:
    """每行行首的花括号深度（朴素计数，不处理字符串/注释内的花括号）。"""
    depths: List[int] = []
    depth = 0
    for line in lines:
        depths.append(depth)
        depth += line.count("{") - line.count("}")
        if depth < 0:
            depth = 0
    return depths


def _guard_patterns_for(symbol: str) -> Dict[str, List[Tuple[str, str]]]:
    """按 kind 分组、且**针对具体符号**的守卫正则。"""
    s = re.escape(symbol)
    return {
        "null_check": [
            ("null_cmp", rf"\b{s}\s*(?:==|!=)\s*{_NULL_TOKENS}\b"),
            ("null_bang", rf"!\s*{s}\b\s*\)"),
            ("assert", rf"{_ASSERT_FAMILY}\s*\(\s*{s}\s*\)"),
            ("isnull_call", rf"\b(?:IsNull\w*|isNull\w*|IsNullOrEmpty)\s*\(\s*{s}\s*\)"),
        ],
        "bounds_check": [
            ("len_cmp", rf"\b{s}\b\s*(?:<=|>=|<|>)\s*[A-Za-z0-9_]"),
            ("len_cmp_rev", rf"[A-Za-z0-9_]\s*(?:<=|>=|<|>)\s*\b{s}\b"),
            ("sizeof_cmp", rf"\b{s}\b\s*(?:<=|>=|<|>)\s*sizeof\s*\("),
            ("fits_call", rf"\b(?:fits|Fits|CanFit|Bounds|bounds|Clamp|clamp)\w*\s*\([^;{{}}]*\b{s}\b"),
        ],
        "sanitizer": [
            (
                "validate_call",
                rf"\b(?:Validat|validat|Verif|verif|Check|check|Ensure|ensure|Allowed|allowed)\w*\s*\([^;{{}}]*\b{s}\b",
            ),
            (
                "sanitize_call",
                rf"\b(?:Sanitiz|sanitiz|Escape|escape|Encode|encode|Normalize|normalize)\w*\s*\([^;{{}}]*\b{s}\b",
            ),
        ],
    }


# ---------------------------------------------------------------------------
# (A) 触发路径可达性（§4.4-A，纯工具 / 确定性）
# ---------------------------------------------------------------------------
def check_trigger_path(
    hypothesis: Dict[str, Any],
    ctx: Optional[CallContext] = None,
) -> Dict[str, Any]:
    """逐跳核验触发路径，返回 ``evidence.path`` 与整体可达性状态。

    返回::

        {
          "path": [{"hop": 0, "from": ..., "to": ..., "file": ..., "line": 0,
                    "code": "", "reachable": True|False|None, "note": ""}],
          "status": "reachable|unreachable|unverifiable",
          "used_tools": ["get_callees", "get_callers"],
          "note": "",
        }
    """
    cc = ctx if ctx is not None else active_context()
    file_path = str((hypothesis.get("location") or {}).get("file") or "")
    seq = _norm_path(hypothesis.get("trigger_path") or hypothesis.get("propagation_path"))

    if len(seq) < 2:
        return {
            "path": [],
            "status": "unverifiable",
            "used_tools": [],
            "note": "触发路径少于 2 个节点，无法逐跳核验",
        }

    hops: List[Dict[str, Any]] = []
    used: List[str] = []
    any_unreachable = False
    any_unverifiable = False

    for i, (src, dst) in enumerate(zip(seq, seq[1:])):
        f_src = _resolve_function(src, cc)
        f_dst = _resolve_function(dst, cc)
        hop: Dict[str, Any] = {
            "hop": i,
            "from": src,
            "to": dst,
            "file": file_path,
            "line": 0,
            "code": "",
            "reachable": None,
            "note": "",
        }

        if f_src is None or f_dst is None:
            hop["note"] = "端点不是本文件内的函数名（表达式/变量或外部函数），调用图无法核验"
            any_unverifiable = True
            hops.append(hop)
            continue

        # 先查 callee 方向（谁被谁调用），再查 caller 方向兜底
        if "get_callees" not in used:
            used.append("get_callees")
        callees = get_callees(f_src, cc)
        hit = next(
            (
                c
                for c in callees.get("callees", []) or []
                if _short(c.get("callee")) == _short(f_dst)
            ),
            None,
        )
        if hit is not None:
            hop["reachable"] = True
            hop["line"] = int(hit.get("call_line") or 0)
            hop["note"] = f"{f_src} 内调用 {f_dst}（第 {hop['line']} 行）"
            hops.append(hop)
            continue

        if "get_callers" not in used:
            used.append("get_callers")
        callers = get_callers(f_dst, cc)
        hit = next(
            (
                c
                for c in callers.get("callers", []) or []
                if _short(c.get("caller")) == _short(f_src)
            ),
            None,
        )
        if hit is not None:
            hop["reachable"] = True
            hop["line"] = int(hit.get("call_line") or 0)
            hop["note"] = f"{f_dst} 被 {f_src} 调用（第 {hop['line']} 行）"
            hops.append(hop)
            continue

        # 两端都在本文件内、却查不到边 → 同文件内确定性断链
        hop["reachable"] = False
        hop["note"] = f"{f_src} 与 {f_dst} 在本文件调用图中无边（断链）"
        any_unreachable = True
        hops.append(hop)

    if any_unreachable:
        status = "unreachable"
    elif any_unverifiable:
        status = "unverifiable"
    else:
        status = "reachable"
    return {"path": hops, "status": status, "used_tools": used, "note": ""}


# ---------------------------------------------------------------------------
# (B) 假设条件 blocker（§4.4-B，启发式 + 三重作用域化）
# ---------------------------------------------------------------------------
def _match_blocker(
    assumption: Dict[str, str],
    symbols: List[str],
    window: List[str],
    depths: List[int],
    sink_idx: int,
    base_line: int,
    file_path: str,
) -> Optional[Dict[str, Any]]:
    """在 sink 之前的窗口内寻找「反驳该假设」的守卫，命中返回 blocker。"""
    kind = _KIND_ALIASES.get(str(assumption.get("kind", "")).strip().lower())
    kinds = [kind] if kind else ["null_check", "bounds_check", "sanitizer"]

    for checked_kind in kinds:
        for symbol in symbols:
            for pat_kind, pattern in _guard_patterns_for(symbol).get(checked_kind, []):
                for idx in range(0, max(0, sink_idx)):
                    # 块作用域：守卫行必须不深于 sink 行（支配 / 包住 sink）
                    if depths[idx] > depths[sink_idx]:
                        continue
                    if not re.search(pattern, window[idx]):
                        continue
                    return {
                        "file": file_path,
                        "line": base_line + idx,
                        "kind": checked_kind,
                        "pattern": pat_kind,
                        "symbol": symbol,
                        "code": window[idx].strip(),
                    }
    return None


def check_assumptions(
    hypothesis: Dict[str, Any],
    ctx: Optional[CallContext] = None,
    code: str = "",
) -> Dict[str, Any]:
    """逐条核验假设条件，返回 ``evidence.conditions`` 与 ``evidence.blockers``。

    ``holds`` 语义：``True`` 成立 / ``False`` 被 blocker 反驳 / ``None`` 无法核。
    """
    cc = ctx if ctx is not None else active_context()
    assumptions = _normalize_assumptions(hypothesis.get("assumptions"))
    used: List[str] = []
    if not assumptions:
        # §4.3 第 3 条：无假设条件时条件核验退化为「仅核路径」
        return {"conditions": [], "blockers": [], "used_tools": used, "note": "无假设条件"}

    loc = hypothesis.get("location") or {}
    file_path = str(loc.get("file") or "")
    target = _resolve_function(loc.get("function") or "", cc) or _resolve_function(
        hypothesis.get("taint_sink") or "", cc
    )

    body = get_function_body(target, cc) if target else {"found": False}
    if target:
        used.append("get_function_body")

    if not target or not body.get("found"):
        conditions = [
            {**a, "holds": None, "blocker": None, "note": "目标函数不在本文件内，无法取实现体"}
            for a in assumptions
        ]
        return {
            "conditions": conditions,
            "blockers": [],
            "used_tools": used,
            "note": "无法定位 sink 所在函数",
        }

    fn_start = int(body.get("line_start") or 0)
    fn_end = int(body.get("line_end") or 0)
    sink_line = int(loc.get("line_start") or 0)
    if not (fn_start and fn_start <= sink_line <= fn_end):
        sink_line = fn_end

    source_lines = (code or "").splitlines()
    if source_lines and fn_start and fn_end:
        window = source_lines[fn_start - 1 : sink_line]
        base_line = fn_start
    else:
        # 没有源码文本时退化：用函数体文本，行号以函数起始行为基准
        window = (body.get("body") or "").splitlines()
        base_line = fn_start or 1

    if not window:
        conditions = [
            {**a, "holds": None, "blocker": None, "note": "无法取得 sink 之前的代码窗口"}
            for a in assumptions
        ]
        return {"conditions": conditions, "blockers": [], "used_tools": used, "note": ""}

    depths = _line_depths(window)
    sink_idx = len(window) - 1

    conditions: List[Dict[str, Any]] = []
    blockers: List[Dict[str, Any]] = []
    for assumption in assumptions:
        symbols = _target_symbols(hypothesis, assumption)
        if not symbols:
            conditions.append(
                {
                    **assumption,
                    "holds": None,
                    "blocker": None,
                    "note": "无法从假设/污点源中抽取出目标符号",
                }
            )
            continue
        blocker = _match_blocker(
            assumption, symbols, window, depths, sink_idx, base_line, file_path
        )
        if blocker is not None:
            conditions.append({**assumption, "holds": False, "blocker": blocker, "note": ""})
            blockers.append(blocker)
        else:
            conditions.append(
                {
                    **assumption,
                    "holds": True,
                    "blocker": None,
                    "note": "sink 之前未发现针对该符号的守卫/校验",
                }
            )

    return {"conditions": conditions, "blockers": blockers, "used_tools": used, "note": ""}


# ---------------------------------------------------------------------------
# (C) verdict 映射（§4.4-C）
# ---------------------------------------------------------------------------
def _map_verdict(
    path_result: Dict[str, Any], cond_result: Dict[str, Any]
) -> Tuple[str, float, str]:
    """把路径 / 条件核验结果映射为 (verdict, confidence, reason)。

    优先级：确定性断链 → blocker → 双正条件满足（accept）→ 其余 challenge。
    """
    if path_result.get("status") == "unreachable":
        broken = [
            h for h in path_result.get("path", []) if h.get("reachable") is False
        ]
        detail = "；".join(h.get("note", "") for h in broken[:2])
        return "reject", CONF_PATH_BROKEN, f"触发路径在同文件调用图中不可达：{detail}"

    blockers = cond_result.get("blockers") or []
    if blockers:
        b = blockers[0]
        return (
            "reject",
            CONF_BLOCKER_ONLY,
            f"假设条件被代码中的守卫反驳（{b.get('kind')}@{b.get('file')}:{b.get('line')}）",
        )

    conditions = cond_result.get("conditions") or []
    all_hold = all(c.get("holds") is True for c in conditions)

    if path_result.get("status") == "reachable" and all_hold:
        return "accept", CONF_ACCEPT, "触发路径逐跳可达，且假设条件均未被代码反驳"

    reasons: List[str] = []
    unverifiable = [
        h for h in path_result.get("path", []) if h.get("reachable") is None
    ]
    if unverifiable:
        reasons.append(f"存在 {len(unverifiable)} 跳无法在单文件调用图中核验")
    if path_result.get("status") == "unverifiable" and not path_result.get("path"):
        reasons.append(path_result.get("note") or "触发路径无法逐跳核验")
    unknown = [c for c in conditions if c.get("holds") is None]
    if unknown:
        reasons.append(f"存在 {len(unknown)} 条假设条件无法核验")
    if not reasons:
        reasons.append("证据不足以判定")
    return "challenge", CONF_CHALLENGE, "；".join(reasons)


# ---------------------------------------------------------------------------
# 对外入口
# ---------------------------------------------------------------------------
def verify_taint(hypothesis: dict, context: dict) -> dict:
    """验证一个污点假设（工具信号）。

    :param hypothesis: 来自 D 的待验证假设，含 ``finding_id / title / cwe /
        taint_source / taint_sink / trigger_path / propagation_path /
        assumptions / location``。
    :param context: ``{"file", "line_range", "code"}``；``code`` 用于行号对齐
        与括号深度计算（缺失时退化为函数体文本）。

    :return: 父设计 §3.1 结构（旧键语义不变，新增 ``verdict`` / ``evidence``）::

        {
          "status": "verified|rejected|uncertain",
          "verdict": "accept|reject|challenge|uncertain",
          "confidence": 0.0,
          "reason": "",
          "evidence": {"path": [...], "path_status": "", "conditions": [...],
                       "blockers": [...], "used_tools": [...]},
          "tool_name": "verify_taint",
          "raw_output": {...}
        }
    """
    context = context or {}
    code = str(context.get("code") or "")

    # D 在 _verify_findings 开头已 set_active_context；此处仅作兜底（例如单测直接调用）
    cc = active_context()
    if not cc.functions and code:
        cc = set_active_context(code)

    path_result = check_trigger_path(hypothesis or {}, cc)
    cond_result = check_assumptions(hypothesis or {}, cc, code=code)
    verdict, confidence, reason = _map_verdict(path_result, cond_result)

    used_tools: List[str] = []
    for name in path_result.get("used_tools", []) + cond_result.get("used_tools", []):
        if name not in used_tools:
            used_tools.append(name)

    return {
        "status": VERDICT_TO_STATUS.get(verdict, "uncertain"),
        "verdict": verdict,
        "confidence": confidence,
        "reason": reason,
        "evidence": {
            "path": path_result.get("path", []),
            "path_status": path_result.get("status", "unverifiable"),
            "conditions": cond_result.get("conditions", []),
            "blockers": cond_result.get("blockers", []),
            "used_tools": used_tools,
        },
        "tool_name": TOOL_NAME,
        "raw_output": {
            "path_status": path_result.get("status", "unverifiable"),
            "hop_count": len(path_result.get("path", [])),
            "condition_count": len(cond_result.get("conditions", [])),
            "blocker_count": len(cond_result.get("blockers", [])),
        },
    }


# ---------------------------------------------------------------------------
# LangChain 工具包装（供 D 使用 llm.bind_tools([...]) 绑定）。
# 若未安装 langchain-core，则降级为 None，D 会退化为直接调用 verify_taint。
# ---------------------------------------------------------------------------
try:  # pragma: no cover - 依赖存在时才会执行
    from langchain_core.tools import tool as _lc_tool  # type: ignore

    @_lc_tool("verify_taint")
    def verify_taint_tool(hypothesis: dict, context: dict) -> dict:
        """验证污点假设，返回 verify_taint 的字典结果。"""
        return verify_taint(hypothesis, context)

except Exception:  # pragma: no cover
    verify_taint_tool = None  # type: ignore
