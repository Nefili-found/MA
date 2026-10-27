"""事实层：把检测端的 ``evidence`` 映射成"这轮修复必须遵守什么"。

设计依据：``change_process/summery/修复端_结构重构_2026-10-24_设计.md`` §5 / §5.1。

映射规则（D2，**固定语义，不许自行放宽**）
-------------------------------------------
| ``evidence.conditions[i]`` | 含义 | 去向 |
| --- | --- | --- |
| ``holds = true`` | 代码里确实缺这条前提 | ``required_gaps``（本轮必须处理） |
| ``holds = false`` 且带 blocker | 已经有人查过 | ``protected``（禁止改动） |
| ``holds = null`` | 无法核 | ``dropped``（不进 prompt、不进统计） |
| ``path_status = reachable`` 且链合法 | 触发链可用 | ``reach.chain`` |
| ``path_status = unreachable`` | 触发路径不成立 = 强误报信号 | ``dropped`` + 触发复核（见 §5 表格） |
| ``path_status = unverifiable`` | 不提可达性 | ``dropped``，prompt 里不出现"可达"字样 |

两个刻意分开的信号
------------------
设计稿里有**两条规则会打架**，这里不替它调和，而是分成两个独立信号：

* ``sufficiency``（§5 三选一）回答"能不能据此构造检索键"——注意其中第 3 条是
  ``verdict = accept``，而入口默认只放行 ``accept``，所以**正常路径上 sufficiency 恒为真**；
* ``reverify_needed``（§5 映射表）回答"要不要请检测端复核"——``unreachable`` 是强误报
  信号，无论 sufficiency 如何都该复核。

把两者混成一个布尔会让 ``unreachable`` 被 ``verdict=accept`` 掩盖掉，那等于白丢一条最
有价值的误报线索。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .schema import (
    Dropped,
    FactSet,
    Protected,
    Reach,
    RepairCase,
    RequiredGap,
    Sufficiency,
)

#: ``path_status`` 的已知取值（与 ``tools/verify_taint.py`` 的 ``check_trigger_path`` 同源）
PATH_STATUSES = ("reachable", "unreachable", "unverifiable")

#: 复核请求的 schema 名（§5.1）
VERIFY_REQUEST_SCHEMA = "verify-request/1"


# ---------------------------------------------------------------- 主入口


def build_facts(case: RepairCase) -> FactSet:
    """``evidence`` → :class:`FactSet`。纯函数，不读写、不联网。"""
    gaps: List[RequiredGap] = []
    protected: List[Protected] = []
    dropped: List[Dropped] = []
    #: (line, code) → Protected：同一个守卫只保留一条，来源 id 累加进去
    seen: Dict[Tuple[int, str], Protected] = {}

    for index, cond in enumerate(case.evidence.conditions or []):
        if not isinstance(cond, dict):
            dropped.append(Dropped(id=f"cond-{index + 1}", reason="条件不是对象，无法解析"))
            continue
        cond_id = str(cond.get("id") or f"cond-{index + 1}")
        kind = str(cond.get("kind") or "")
        text = str(cond.get("text") or "")
        holds = cond.get("holds")
        blocker = cond.get("blocker") if isinstance(cond.get("blocker"), dict) else None

        if holds is True:
            gaps.append(
                RequiredGap(id=cond_id, kind=kind, text=text, anchor_line=case.vuln.line)
            )
        elif holds is False and blocker is not None:
            # 多条假设条件经常命中**同一个**守卫（实测 5 条假设 → 同一个
            # ``if (row > nused)``）。按 (line, code) 合并，否则 protected 会被
            # 虚增成 5 条，下游 prompt 里也会重复 5 遍同一句"已有守卫"。
            key = (_as_int(blocker.get("line")), str(blocker.get("code") or ""))
            merged = seen.get(key)
            if merged is not None:
                merged.condition_ids.append(cond_id)
            else:
                entry = _protected_from(cond_id, kind, blocker)
                seen[key] = entry
                protected.append(entry)
        elif holds is False:
            # verify_taint 里 holds=false 必然带 blocker；走到这里说明输入被改过或来源不同
            dropped.append(Dropped(id=cond_id, reason="holds=false 但未给 blocker（无法据此判定）"))
        else:
            dropped.append(Dropped(id=cond_id, reason="holds=null（无法核）"))

    # blockers[] 里未被任何 condition 引用的，也要进 protected（§5：「与 false 合并」）
    for index, blocker in enumerate(case.evidence.blockers or []):
        if not isinstance(blocker, dict):
            continue
        key = (_as_int(blocker.get("line")), str(blocker.get("code") or ""))
        if key in seen:
            seen[key].condition_ids.append(f"blocker-{index + 1}")
            continue
        entry = _protected_from(f"blocker-{index + 1}", "", blocker)
        seen[key] = entry
        protected.append(entry)

    reach = _build_reach(case)
    if reach.status == "unverifiable":
        dropped.append(Dropped(id="path", reason="path_status=unverifiable（无法核 ⇒ 不提可达性）"))
    elif reach.status == "unreachable":
        dropped.append(Dropped(id="path", reason="path_status=unreachable（触发路径不成立 ⇒ 强误报信号）"))

    sufficiency = _judge_sufficiency(case, gaps, reach, protected)
    return FactSet(
        required_gaps=gaps,
        protected=protected,
        reach=reach,
        dropped=dropped,
        sufficiency=sufficiency,
    )


def _protected_from(cond_id: str, fallback_kind: str, blocker: Dict[str, Any]) -> Protected:
    return Protected(
        id=cond_id,
        kind=str(blocker.get("kind") or fallback_kind),
        line=_as_int(blocker.get("line")),
        code=str(blocker.get("code") or ""),
        symbol=str(blocker.get("symbol") or ""),
        condition_ids=[cond_id],
    )


def _build_reach(case: RepairCase) -> Reach:
    """``path_status`` + ``path[]`` → :class:`Reach`。

    ``reachable`` 时把逐跳的 ``from → to`` 串成 ``chain``。链不合法（少于 2 个节点）就
    只保留状态、不给链——让 sufficiency 的第 2 条自然不成立，而不是伪造一条链。
    """
    status = str(case.evidence.path_status or "").strip().lower()
    if status not in PATH_STATUSES:
        # 空/未知一律按"无法核"处理：宁可不说可达，也不要凭空宣称
        return Reach(status="unverifiable" if not status else status, chain=[])

    if status != "reachable":
        return Reach(status=status, chain=[])

    hops = [h for h in (case.evidence.path or []) if isinstance(h, dict)]
    if not hops:
        return Reach(status=status, chain=[])

    chain: List[str] = []
    first = str(hops[0].get("from") or "").strip()
    if first:
        chain.append(first)
    for hop in hops:
        node = str(hop.get("to") or "").strip()
        if node and (not chain or chain[-1] != node):
            chain.append(node)
    if len(chain) < 2:
        return Reach(status=status, chain=[])
    return Reach(status=status, chain=chain)


def _judge_sufficiency(
    case: RepairCase,
    gaps: List[RequiredGap],
    reach: Reach,
    protected: Optional[List[Protected]] = None,
) -> Sufficiency:
    """充足性判定。

    §5 原文只给了三条（gaps / 可达链 / verdict=accept）。这里**加了第 4 条**：
    ``protected`` 非空。理由是一处实测差异，不是随意放宽：

    检测端的 ``check_assumptions`` 只能判断"某符号在 sink 之前有没有检查"，判断不了
    "这个检查对不对"。APPATCH extractfix 里 ``binutils dwarf.c`` 那条 CWE-125 的真实缺陷
    就是 ``if (row > nused)`` 这个**不够严**的守卫本身——它会被判成 blocker，于是
    ``protected`` 非空而 ``required_gaps`` 永远为空。若照字面只认前三条，这类"缺陷在守卫处"
    的高质量 case 会全部落进 ``insufficient_facts`` 被排除，而它们恰恰是最该被检索到的一类。

    第 4 条的语义刻意写得窄：**"已有 N 处针对同符号的守卫"是可用线索**（缺陷在守卫处，
    或守卫与使用之间的不一致），而不是"这条 case 够格进 Repair Rate 分母"。后者仍只由
    ``final`` 决定。
    """
    if gaps:
        return Sufficiency(ok=True, why=f"required_gaps={len(gaps)}（有确实缺的前提）")
    if reach.status == "reachable" and len(reach.chain) >= 2:
        return Sufficiency(ok=True, why=f"触发链可用：{' → '.join(reach.chain)}")
    if case.vuln.verdict == "accept":
        return Sufficiency(
            ok=True,
            why="verdict=accept（检测端已判定为真，无事实也可尝试修复）",
        )
    protected = protected or []
    if protected:
        spots = ", ".join(f"{p.kind or 'guard'}@{p.line}" for p in protected[:3])
        return Sufficiency(
            ok=True,
            why=(
                f"protected={len(protected)}（已有针对同符号的守卫：{spots}）"
                " ⇒ 缺陷在守卫处或守卫与使用之间"
            ),
        )
    return Sufficiency(
        ok=False,
        why="无 required_gaps、无可达链、无已存守卫、verdict 非 accept ⇒ 事实不足",
    )


# ---------------------------------------------------------------- 复核请求


def reverify_needed(
    case: RepairCase, facts: Optional[FactSet] = None
) -> Tuple[bool, str, List[Dict[str, Any]]]:
    """要不要请检测端复核，以及问什么。

    返回 ``(need, reason, asks)``。``asks`` 的形状即 ``verify-request/1`` 的 ``asks``。

    触发条件（两类，互不覆盖）：

    1. ``path_status = unreachable`` → ``resolve_reachability``。这是**强误报信号**，
       按 §5 映射表必须复核，不受 sufficiency 影响；
    2. ``sufficiency.ok = False`` → 按缺口补问：
       * 有 ``holds=null`` 的条件 → ``recheck_condition``（收窄窗口重跑）
       * 一条条件都没有 → ``widen_window``（可能是窗口没盖住 sink 前的守卫）
    """
    facts = facts or build_facts(case)

    asks: List[Dict[str, Any]] = []
    reasons: List[str] = []

    if facts.reach.status == "unreachable":
        reasons.append("unreachable_path")
        asks.append(
            {
                "kind": "resolve_reachability",
                "function": case.vuln.func or _guess_function(case),
            }
        )

    if not facts.sufficiency.ok:
        reasons.append("insufficient_facts")
        unverifiable_conditions = [
            d for d in facts.dropped if d.id.startswith("cond-") and "holds=null" in d.reason
        ]
        for item in unverifiable_conditions:
            asks.append(
                {
                    "kind": "recheck_condition",
                    "condition_id": item.id,
                    "text": _condition_text(case, item.id),
                    "hint_line": case.vuln_line_local,
                }
            )
        if not case.evidence.conditions:
            asks.append(
                {
                    "kind": "widen_window",
                    "function": case.vuln.func or _guess_function(case),
                    "detail": "输入没有任何假设条件，sink 之前的窗口可能没盖住",
                }
            )

    return (bool(asks), "+".join(reasons), asks)


def build_reverify_request(
    case: RepairCase,
    facts: Optional[FactSet] = None,
    *,
    round_no: int = 1,
) -> Optional[Dict[str, Any]]:
    """组装 ``verify-request/1``；不需要复核时返回 ``None``。"""
    need, reason, asks = reverify_needed(case, facts)
    if not need:
        return None
    return {
        "schema": VERIFY_REQUEST_SCHEMA,
        "case_id": case.case_id,
        "reason": reason,
        "round": int(round_no),
        "asks": asks,
        "context": {
            "file": case.source.file,
            "line": case.vuln.line,
            "func": case.vuln.func,
        },
    }


def _condition_text(case: RepairCase, condition_id: str) -> str:
    for cond in case.evidence.conditions or []:
        if isinstance(cond, dict) and str(cond.get("id") or "") == condition_id:
            return str(cond.get("text") or "")
    return ""


def _guess_function(case: RepairCase) -> str:
    """``vuln.func`` 为空时（评测集路径）用切片里的首个函数名兜底。"""
    from tools.call_context import build_context

    try:
        ctx = build_context(case.code.func_src)
    except Exception:  # pragma: no cover - 解析失败就放弃兜底
        return ""
    for name, info in (getattr(ctx, "functions", {}) or {}).items():
        start = _as_int((info or {}).get("line_start"))
        end = _as_int((info or {}).get("line_end"))
        if start <= case.vuln_line_local <= end:
            return str(name)
    return ""


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


__all__ = [
    "PATH_STATUSES",
    "VERIFY_REQUEST_SCHEMA",
    "build_facts",
    "reverify_needed",
    "build_reverify_request",
]
