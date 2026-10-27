"""检测端复核（``verify-request/1``）的执行侧。

设计依据：``change_process/summery/修复端_结构重构_2026-10-24_设计.md`` §5.1。

分工
----
* **修复端决定问什么**：``repair/facts.py::build_reverify_request`` 根据事实缺口组装请求；
* **检测端负责怎么答**：本模块收到请求后，把窗口收窄/放宽、把 sink 限制到目标函数，
  重跑现成的 :func:`tools.verify_taint.check_assumptions` /
  :func:`tools.verify_taint.check_trigger_path`，返回**补过事实的新 case**。

三条铁律（写在代码里也写在文档里）
----------------------------------
1. **只补事实，不放宽判定**：绝不改 ``vuln.verdict``，只动 ``evidence``。
   否则"事实注入"会退化成"把猜测包装成检测结论"。
2. **单 case 最多 1 轮**：编排方（``loop``）负责计数，本模块只执行一轮。
3. **行号口径**：``ctx`` 由 ``case.code.func_src`` 构建，其行号从 1 开始，因此传进
   ``check_assumptions`` 的 ``location.line_start`` 一律用**切片内行号**
   （``vuln.line - body_line_start + 1``），不能用真实文件行号。这是 ``line_base``
   带来的唯一硬约束，写错了窗口会整体错位。
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional

from tools.call_context import CallContext, build_context
from tools.verify_taint import check_assumptions, check_trigger_path

from .repair_projection import validate_repair_case

VERIFY_REQUEST_SCHEMA = "verify-request/1"

#: 本模块支持的动作（与设计稿 §5.1 的三种 ``kind`` 一一对应）
SUPPORTED_KINDS = ("recheck_condition", "resolve_reachability", "widen_window")


def reverify_case(
    case: Dict[str, Any],
    request: Dict[str, Any],
    *,
    code: Optional[str] = None,
    ctx: Optional[CallContext] = None,
) -> Dict[str, Any]:
    """执行一次复核，返回**新** case（不改传入对象）。

    :param case: ``repair-input/1`` 的单个 case（dict）
    :param request: ``verify-request/1``（``repair.facts.build_reverify_request`` 的产物）
    :param code: 覆盖用的源码窗口；缺省用 ``case.code.func_src``。
        ``ctx`` 必须与它同源。
    :param ctx: 复用的 :class:`CallContext`；缺省按 ``code`` 现建。

    返回的新 case 带有 ``reverify`` 记账块，说明这轮问了什么、事实变了多少。
    """
    schema = str(request.get("schema") or "")
    if schema != VERIFY_REQUEST_SCHEMA:
        raise ValueError(f"request.schema={schema!r}，期望 {VERIFY_REQUEST_SCHEMA!r}")

    func_src = code if code is not None else str((case.get("code") or {}).get("func_src") or "")
    if not func_src.strip():
        raise ValueError("没有可复核的源码窗口（code.func_src 为空且未传 code）")
    cc = ctx if ctx is not None else build_context(func_src)

    out = copy.deepcopy(case)
    evidence = dict(out.get("evidence") or {})
    evidence.setdefault("path", [])
    evidence.setdefault("conditions", [])
    evidence.setdefault("blockers", [])
    before = _snapshot(evidence)

    done: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    notes: List[str] = []

    for ask in request.get("asks") or []:
        kind = str((ask or {}).get("kind") or "")
        if kind not in SUPPORTED_KINDS:
            skipped.append({"kind": kind, "why": f"不支持的动作（支持：{SUPPORTED_KINDS}）"})
            continue
        try:
            if kind == "recheck_condition":
                _do_recheck_condition(out, evidence, ask, cc, func_src)
            elif kind == "widen_window":
                _do_widen_window(out, evidence, ask, cc, func_src, notes)
            else:
                _do_resolve_reachability(out, evidence, ask, cc, notes)
            done.append({"kind": kind})
        except Exception as exc:  # noqa: BLE001 - 单条 ask 失败不拖垮整轮
            skipped.append({"kind": kind, "why": f"{type(exc).__name__}: {exc}"})

    evidence["path_status"] = str(evidence.get("path_status") or "")
    out["evidence"] = evidence
    # 只补事实，不动判定（铁律 1）。verdict 保持原样，validation 重新算一遍。
    errors = validate_repair_case(out)
    out["validation"] = {"ok": not errors, "errors": errors}
    out["reverify"] = {
        "schema": VERIFY_REQUEST_SCHEMA,
        "round": int(request.get("round") or 1),
        "reason": str(request.get("reason") or ""),
        "asked": len(request.get("asks") or []),
        "done": done,
        "skipped": skipped,
        "notes": notes,
        "before": before,
        "after": _snapshot(evidence),
        "improved": _improved(before, _snapshot(evidence)),
    }
    return out


# ---------------------------------------------------------------- 三种动作


def _do_recheck_condition(
    case: Dict[str, Any],
    evidence: Dict[str, Any],
    ask: Dict[str, Any],
    ctx: CallContext,
    code: str,
) -> None:
    """以 ``hint_line`` 收窄窗口，重跑 ``check_assumptions``。"""
    target = _target_function(case, ask, ctx)
    hint = _as_int(ask.get("hint_line")) or _local_line(case)
    condition_id = str(ask.get("condition_id") or "cond-1")
    hypothesis = {
        "location": {
            "file": str((case.get("source") or {}).get("file") or ""),
            "function": target,
            "line_start": hint,  # 收窄窗口的唯一手段
        },
        # 把 sink 行的**代码**当 taint_sink：``check_assumptions`` 的符号是从
        # ``taint_source`` → ``taint_sink`` → 假设文本 依次抽取的，前两者优先。
        # 只靠假设文本抽符号不可靠——``_KEYWORDS`` 里含英文停用词（in / is / the / when），
        # 变量恰好叫 ``in`` 时永远抽不出来。代码行是更硬的事实来源。
        "taint_sink": _line_text(code, hint),
        "assumptions": [
            {
                "id": condition_id,
                "kind": _condition_kind(case, condition_id),
                "text": str(ask.get("text") or ""),
            }
        ],
    }
    result = check_assumptions(hypothesis, ctx, code)
    _merge_conditions(evidence, result.get("conditions") or [])
    _merge_blockers(evidence, result.get("blockers") or [])


def _do_widen_window(
    case: Dict[str, Any],
    evidence: Dict[str, Any],
    ask: Dict[str, Any],
    ctx: CallContext,
    code: str,
    notes: List[str],
) -> None:
    """把窗口放到整个函数（sink 取函数末行），重跑 ``check_assumptions``。

    适用场景：输入一条假设条件都没有，怀疑是窗口没盖住 sink 之前的守卫。
    没有假设条件时 ``check_assumptions`` 会直接返回"无假设条件"——那说明窗口不是瓶颈，
    记账即可，不硬造条件。
    """
    target = _target_function(case, ask, ctx)
    fn_end = _function_end(ctx, target) or len(code.splitlines())
    hypothesis = {
        "location": {
            "file": str((case.get("source") or {}).get("file") or ""),
            "function": target,
            "line_start": fn_end,  # 放到函数末尾 = 最宽窗口
        },
        "assumptions": _assumptions_from(case),
    }
    result = check_assumptions(hypothesis, ctx, code)
    _merge_conditions(evidence, result.get("conditions") or [])
    _merge_blockers(evidence, result.get("blockers") or [])
    note = str(result.get("note") or "")
    if note:
        notes.append(f"widen_window: {note}")


def _do_resolve_reachability(
    case: Dict[str, Any],
    evidence: Dict[str, Any],
    ask: Dict[str, Any],
    ctx: CallContext,
    notes: List[str],
) -> None:
    """把候选链限制在目标函数及其 callee，重跑 ``check_trigger_path``。

    序列来源优先级（都拿不到就**不动**，并记一条 note，不伪造链）：

    1. ``ask.path``（调用方显式给的链）
    2. 现有 ``evidence.path`` 的 ``from → to`` 串
    """
    target = _target_function(case, ask, ctx)
    seq = _norm_sequence(ask.get("path"))
    if not seq:
        seq = _sequence_from_evidence(evidence.get("path") or [])
    if len(seq) < 2:
        notes.append(
            "resolve_reachability: 没有可用的触发链（请求与证据里都缺 from→to），未改动"
        )
        return
    if target and seq[0] != target:
        seq = [target] + [x for x in seq if x != target]

    hypothesis = {
        "location": {"file": str((case.get("source") or {}).get("file") or ""), "function": target},
        "trigger_path": seq,
    }
    result = check_trigger_path(hypothesis, ctx)
    evidence["path"] = result.get("path") or []
    evidence["path_status"] = str(result.get("status") or "unverifiable")
    evidence["used_tools"] = result.get("used_tools") or []


# ---------------------------------------------------------------- 合并与记账


def _merge_conditions(evidence: Dict[str, Any], fresh: List[Dict[str, Any]]) -> None:
    """按 ``id`` 覆盖式合并：复核结果优先，未提到的旧条件保留。"""
    by_id: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for cond in evidence.get("conditions") or []:
        if not isinstance(cond, dict):
            continue
        key = str(cond.get("id") or "")
        by_id[key] = cond
        order.append(key)
    for cond in fresh:
        key = str(cond.get("id") or "")
        if key not in by_id:
            order.append(key)
        by_id[key] = cond
    evidence["conditions"] = [by_id[k] for k in order if k in by_id]


def _merge_blockers(evidence: Dict[str, Any], fresh: List[Dict[str, Any]]) -> None:
    """blocker 按 ``(line, code)`` 去重累加——它是 protected 的来源，重复会虚增统计。"""
    existing = {
        (_as_int(b.get("line")), str(b.get("code") or ""))
        for b in (evidence.get("blockers") or [])
        if isinstance(b, dict)
    }
    merged = list(evidence.get("blockers") or [])
    for blocker in fresh:
        if not isinstance(blocker, dict):
            continue
        key = (_as_int(blocker.get("line")), str(blocker.get("code") or ""))
        if key in existing:
            continue
        existing.add(key)
        merged.append(blocker)
    evidence["blockers"] = merged


def _snapshot(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """事实面的可比较快照（用于判断这轮复核有没有真的改善）。"""
    holds: Dict[str, int] = {"true": 0, "false": 0, "null": 0}
    for cond in evidence.get("conditions") or []:
        if not isinstance(cond, dict):
            continue
        value = cond.get("holds")
        holds["null" if value is None else ("true" if value else "false")] += 1
    return {
        "path_status": str(evidence.get("path_status") or ""),
        "path_hops": len(evidence.get("path") or []),
        "conditions": len(evidence.get("conditions") or []),
        "blockers": len(evidence.get("blockers") or []),
        "holds": holds,
    }


def _improved(before: Dict[str, Any], after: Dict[str, Any]) -> bool:
    """这轮复核是否补到了可用事实。

    判定：``holds=null`` 变少，或 ``path_status`` 从不可用变为 ``reachable``。
    """
    if after["holds"]["null"] < before["holds"]["null"]:
        return True
    if before["path_status"] != "reachable" and after["path_status"] == "reachable":
        return True
    return False


# ---------------------------------------------------------------- 小工具


def _target_function(case: Dict[str, Any], ask: Dict[str, Any], ctx: CallContext) -> str:
    explicit = str(ask.get("function") or (case.get("vuln") or {}).get("func") or "").strip()
    if explicit and explicit in ctx.functions:
        return explicit
    if explicit:
        canonical = ctx._canonical(explicit)  # noqa: SLF001 - 复用既有归一逻辑
        if canonical in ctx.functions:
            return canonical
    line = _local_line(case)
    for name, info in ctx.functions.items():
        start = _as_int((info or {}).get("line_start"))
        end = _as_int((info or {}).get("line_end"))
        if start <= line <= end:
            return name
    return explicit


def _function_end(ctx: CallContext, name: str) -> int:
    info = ctx.functions.get(name) or {}
    return _as_int(info.get("line_end"))


def _condition_kind(case: Dict[str, Any], condition_id: str) -> str:
    """从原 case 的 evidence 里取回该条件的 kind（请求里只带了 ask 的 kind）。"""
    for cond in (case.get("evidence") or {}).get("conditions") or []:
        if isinstance(cond, dict) and str(cond.get("id") or "") == condition_id:
            return str(cond.get("kind") or "other")
    return "other"


def _line_text(code: str, line_no: int) -> str:
    """取 ``code`` 里第 ``line_no`` 行（1-based）的文本；越界返回空串。"""
    lines = (code or "").splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].strip()
    return ""


def _local_line(case: Dict[str, Any]) -> int:
    """``vuln.line`` 换成**切片内行号**——ctx 是按 func_src 建的，从 1 开始编号。"""
    vuln = case.get("vuln") or {}
    code = case.get("code") or {}
    start = _as_int(code.get("body_line_start"), 1) or 1
    return _as_int(vuln.get("line")) - start + 1


def _assumptions_from(case: Dict[str, Any]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for cond in (case.get("evidence") or {}).get("conditions") or []:
        if not isinstance(cond, dict):
            continue
        text = str(cond.get("text") or "").strip()
        if not text:
            continue
        out.append(
            {
                "id": str(cond.get("id") or f"cond-{len(out) + 1}"),
                "kind": str(cond.get("kind") or "other"),
                "text": text,
            }
        )
    return out


def _norm_sequence(raw: Any) -> List[str]:
    if not isinstance(raw, list):
        return []
    return [str(x).strip() for x in raw if str(x).strip()]


def _sequence_from_evidence(path: List[Any]) -> List[str]:
    seq: List[str] = []
    for hop in path:
        if not isinstance(hop, dict):
            continue
        src = str(hop.get("from") or "").strip()
        dst = str(hop.get("to") or "").strip()
        if src and not seq:
            seq.append(src)
        if dst and (not seq or seq[-1] != dst):
            seq.append(dst)
    return seq


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


__all__ = ["VERIFY_REQUEST_SCHEMA", "SUPPORTED_KINDS", "reverify_case"]
