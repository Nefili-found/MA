"""检索键构建：``FactSet`` + AST → ``Query`` 四字段。

设计依据：``change_process/summery/修复端_结构重构_2026-10-24_设计.md`` §6。

**只有 Step 4 走 LLM**，其余全是确定性模板与 AST：

===========  ==================================================  ============
Step         做什么                                              依赖
===========  ==================================================  ============
1            ``risky_calls``：函数体内的调用名                     ``tools.call_context``
2            ``taint_flow``（DF）/ ``control_branch``（CF）        ``required_gaps`` + ``reach``
3            ``protected`` → CF 的负向条件（"已有守卫，不得删"）     ``protected``
4            ``root_cause``：一句话                               **LLM**
5            抽象度门禁，违例重试 1 次 → ``degraded``              ``common.abstraction``
===========  ==================================================  ============

这一分工是本次重构的核心：旧设计让 LLM 一次性推完四步（自由推理），现在三步由事实与 AST
钉死，LLM 只负责"把事实串成一句人话"。这样"检索打不中"才能被区分成 *事实错* 还是 *抽象错*，
而不是笼统地归咎于"模型没想对"。
"""

from __future__ import annotations

import string
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from common.abstraction import abstraction_violations
from kbcore.llm import parse_json_object
from tools.call_context import build_context, get_callees

from .schema import FactSet, QueryPair, QueryView, RepairCase

#: 视图 → 该视图独占的字段名（与知识库 ``BEHAVIOR_FIELD`` 保持一致）
BEHAVIOR_FIELD = {"data_flow": "taint_flow", "control_flow": "control_branch"}
VIEWS: tuple = ("data_flow", "control_flow")

#: 行为描述的长度上限。知识库侧由 ``gate.max_behavior_chars`` 截到 400，
#: 查询侧同样截到 400 才能让 BM25 的"词频口径"两侧可比。
MAX_BEHAVIOR_CHARS = 400

#: 降级时原样截取 ``func_src`` 的行数（§6：仍是"前 200 行原文当 root_cause"）
DEGRADED_SOURCE_LINES = 200

DEFAULT_PROMPT = "repair_query.md"

SYSTEM_PROMPT = (
    "You are a senior C/C++ security analyst. "
    "You output exactly one JSON object and nothing else — no markdown, no code fences, no commentary."
)


# ---------------------------------------------------------------- 主入口


def build_query(
    case: RepairCase,
    facts: FactSet,
    llm: Optional[Any] = None,
    *,
    prompts_dir: Optional[Path] = None,
    prompt_name: str = DEFAULT_PROMPT,
    source: str = "evidence",
) -> QueryPair:
    """构造 ``QueryPair``。``llm`` 为 ``None`` 时全部视图降级（离线可跑）。

    ``llm`` 只需满足 ``complete(system, user, tag=..., temperature=..., max_tokens=...)
    -> (text, usage)``；:class:`kbcore.testing.FakeLLM` 即满足。

    ``source`` 是两个实验臂的开关（设计稿 §12）：

    * ``evidence``（主臂，默认）：``required_gaps`` / ``protected`` / ``reach`` 进 prompt，
      并模板化成 ``taint_flow`` / ``control_branch``，``evidence_refs`` 指向具体事实；
    * ``none``（对照臂）：**丢掉检测端事实**——prompt 里没有 facts 段，两个行为字段为
      ``None``，``evidence_refs`` 为空，只留 CWE + 函数 + 漏洞行 + 代码 + AST 兄弟调用。

    ⚠ 一处刻意选择：对照臂**保留** ``risky_calls``（AST 从代码本身抽的，不属于"检测端事实"）。
    §12 字面写的是"只吃 func_src + cwe + vuln.line"，但那样就同时消融了 AST 与事实两个变量，
    比出来的差异说不清是谁贡献的。保留 AST 才能把差异归因到"事实注入"这一个变量上。
    """
    if source not in ("evidence", "none"):
        raise ValueError(f"source={source!r}，只支持 'evidence' | 'none'")

    risky_calls = collect_risky_calls(case)
    uses_facts = source == "evidence"
    refs = facts.evidence_refs if uses_facts else []
    skeletons = {
        "data_flow": _df_skeleton(facts) if uses_facts else None,
        "control_flow": _cf_skeleton(facts) if uses_facts else None,
    }

    pair = QueryPair(source=source)
    degraded_reasons: List[str] = []

    for view in VIEWS:
        view_obj = QueryView(
            view_type=view,
            risky_calls=list(risky_calls),
            taint_flow=skeletons["data_flow"] if view == "data_flow" else None,
            control_branch=skeletons["control_flow"] if view == "control_flow" else None,
            evidence_refs=list(refs),
        )

        if llm is None:
            _degrade(case, view_obj, "no_llm（未注入 LLM，无法生成 root_cause）")
            degraded_reasons.append(f"{view}: no_llm")
            pair.views[view] = view_obj
            continue

        root_cause, raw_text, why = _generate_root_cause(
            case, facts, view, risky_calls, prompts_dir, prompt_name, llm, use_facts=uses_facts
        )
        view_obj.root_cause = root_cause
        pair.raw[view] = raw_text
        if why:
            view_obj.degraded_reason = why
            degraded_reasons.append(f"{view}: {why}")
        pair.views[view] = view_obj

    pair.degraded = bool(degraded_reasons)
    pair.degraded_reason = "; ".join(degraded_reasons)
    return pair


# ---------------------------------------------------------------- Step 1：AST


def collect_risky_calls(case: RepairCase, *, limit: int = 8) -> List[str]:
    """函数体内的被调用名（AST，去重、按首次调用行排序）。

    ``limit=8`` 与知识库门禁 ``gate.max_calls: 8`` 对齐——库里的 ``risky_calls`` 是
    同一个上限截出来的，查询侧多给没有收益，反而让 BM25 里噪音词变多。
    """
    code = case.code.func_src
    if not code.strip():
        return []
    try:
        ctx = build_context(code)
    except Exception:  # noqa: BLE001 - 解析失败就当没有调用信息
        return []

    function = _resolve_function(case, ctx)
    if not function:
        return []
    result = get_callees(function, ctx)
    hits = result.get("callees") or []
    if not isinstance(hits, list):
        return []

    ordered: List[str] = []
    for hit in sorted(hits, key=lambda h: _as_int((h or {}).get("call_line"))):
        name = str((hit or {}).get("callee") or "").strip()
        if not name or name == function:
            continue
        if name not in ordered:
            ordered.append(name)
        if len(ordered) >= limit:
            break
    return ordered


def _resolve_function(case: RepairCase, ctx: Any) -> str:
    """定位 ``vuln.line`` 所在的函数；``vuln.func`` 优先但必须真在索引里。"""
    declared = (case.vuln.func or "").strip()
    if declared and declared in ctx.functions:
        return declared
    if declared:
        canonical = ctx._canonical(declared)  # noqa: SLF001 - 复用既有归一逻辑
        if canonical in ctx.functions:
            return canonical
    line = case.vuln_line_local
    for name, info in ctx.functions.items():
        if _as_int((info or {}).get("line_start")) <= line <= _as_int((info or {}).get("line_end")):
            return name
    return ""


# ---------------------------------------------------------------- Step 2/3：骨架


def _df_skeleton(facts: FactSet) -> Optional[str]:
    """DF 视图的行为骨架：可达链 + 确实缺的前提。"""
    parts: List[str] = []
    if facts.reach.chain:
        parts.append("reach: " + " -> ".join(facts.reach.chain))
    for gap in facts.required_gaps:
        parts.append(gap.text)
    return _clip(" ; ".join(p for p in parts if p))


def _cf_skeleton(facts: FactSet) -> Optional[str]:
    """CF 视图的行为骨架：缺哪些前提（带 kind）+ 哪些守卫已存在不得删。"""
    parts: List[str] = []
    for gap in facts.required_gaps:
        parts.append(f"missing {gap.kind}: {gap.text}" if gap.kind else gap.text)
    for item in facts.protected:
        # 措辞刻意是"强化这个守卫"而不是"别动它"：检测端只能证明"这里有一个检查"，
        # 证明不了"这个检查够严"。实测里 `if (row > nused)` 就是缺陷本体。
        target = f" on {item.symbol}" if item.symbol else ""
        kind = item.kind or "guard"
        parts.append(
            f"existing {kind}{target} at line {item.line} — do not bypass it, "
            f"strengthen it if too weak: {item.code}"
        )
    return _clip(" ; ".join(p for p in parts if p))


# ---------------------------------------------------------------- Step 4：LLM


def _generate_root_cause(
    case: RepairCase,
    facts: FactSet,
    view: str,
    risky_calls: Sequence[str],
    prompts_dir: Optional[Path],
    prompt_name: str,
    llm: Any,
    *,
    use_facts: bool = True,
) -> tuple:
    """一次生成 + 最多一次违例重试。返回 ``(root_cause, raw_text, degraded_reason)``。"""
    template = _load_prompt(prompts_dir, prompt_name)
    base = _render(
        template,
        {
            "cwe": case.vuln.cwe,
            "view": "data-flow" if view == "data_flow" else "control-flow",
            "function": case.vuln.func or _function_hint(case),
            "line": str(case.vuln_line_local),
            "anchor": case.anchor_text or "(unknown)",
            "facts_section": _facts_section(facts) if use_facts else "",
            "code_block": _number_lines(case.code.func_src),
            "sibling_calls": ", ".join(risky_calls) if risky_calls else "(none)",
        },
    )

    attempts = 0
    last_text = ""
    violations: List[str] = []
    while attempts <= 1:
        prompt = base
        if violations:
            prompt = base + (
                "\n\nYour previous answer leaked implementation identifiers: "
                + ", ".join(violations)
                + "\nRewrite it without ANY of those tokens, keeping the same meaning."
            )
        text, _usage = llm.complete(
            SYSTEM_PROMPT,
            prompt,
            tag=f"repair_query:{view}",
            temperature=0.0,
            max_tokens=512,
        )
        last_text = text
        try:
            data = parse_json_object(text)
        except ValueError:
            violations = []
            attempts += 1
            continue
        candidate = str(data.get("root_cause") or "").strip()
        if not candidate:
            violations = []
            attempts += 1
            continue
        violations = abstraction_violations(candidate, case.code.func_src)
        if not violations:
            return candidate, last_text, ""
        attempts += 1

    # 两次都违例（或两次都没给出可用 JSON/句子）→ 降级，并如实记账
    reason = (
        "abstraction_violation: " + ", ".join(violations)
        if violations
        else "llm_output_unusable（两次都没拿到可解析的 root_cause）"
    )
    return _degraded_root_cause(case), last_text, reason


def _degrade(case: RepairCase, view: QueryView, reason: str) -> None:
    view.root_cause = _degraded_root_cause(case)
    view.degraded_reason = reason


def _degraded_root_cause(case: RepairCase) -> str:
    """§6 的降级取值：``func_src`` 前 200 行原文。

    这条继承自旧设计。它不是好查询（把代码当根因描述），但比"没有查询"强，
    而且 ``degraded`` 标记会让它不进主结果表的头部分析。
    """
    return "\n".join(case.code.lines[:DEGRADED_SOURCE_LINES])


# ---------------------------------------------------------------- 辅助


def _facts_section(facts: FactSet) -> str:
    """完整的「事实」小节（含标题）。对照臂传空串即可**整段消失**。

    整段消失而不是留个空标题：空标题会被模型读成"有事实但没列出"，是反向提示。
    """
    body = _facts_block(facts)
    if not body.strip():
        return ""
    return "## Verified facts (authoritative)\n\n" + body + "\n\n"


def _facts_block(facts: FactSet) -> str:
    """把事实渲染成人可读、模型可依的几行。空事实要显式说"没有"，否则模型会自行脑补。"""
    lines: List[str] = []
    for gap in facts.required_gaps:
        prefix = f"[{gap.kind}] " if gap.kind else ""
        lines.append(f"- MISSING (verified absent): {prefix}{gap.text}")
    for item in facts.protected:
        target = f" on `{item.symbol}`" if item.symbol else ""
        lines.append(
            f"- EXISTING GUARD{target} at line {item.line}: `{item.code}` "
            f"({item.kind or 'guard'}) — do NOT claim it is missing and do NOT remove it; "
            "if it is too weak / off by one, the fix is to strengthen THIS guard "
            "rather than add a second check"
        )
    if facts.reach.chain:
        lines.append("- REACH: " + " -> ".join(facts.reach.chain))
    elif facts.reach.status == "unreachable":
        lines.append("- REACH: the trigger path is NOT reachable")
    else:
        lines.append("- REACH: unknown (do not claim reachability)")
    for item in facts.dropped:
        lines.append(f"- IGNORED: {item.id} — {item.reason}")
    return "\n".join(lines)


def _load_prompt(prompts_dir: Optional[Path], name: str) -> str:
    """读 prompt 模板。"""
    root = (
        Path(prompts_dir)
        if prompts_dir is not None
        else Path(__file__).resolve().parent.parent / "prompts"
    )
    path = root / name
    if not path.exists():
        raise FileNotFoundError(f"prompt 模板缺失：{path}")
    return path.read_text(encoding="utf-8")


def _number_lines(src: str, start_line: int = 1) -> str:
    """给每行加行号前缀（压低行号幻觉；与知识库侧 ``kbcore.extract.number_lines`` 同格式）。

    刻意不 import ``kbcore.extract``：那会把 ``.pairs`` / ``.anchor`` 一整串拖进来，
    而这里只需要 4 行字符串处理。
    """
    return "\n".join(
        f"{start_line + offset:4d} | {line}" for offset, line in enumerate(src.splitlines())
    )


def _render(template: str, mapping: Dict[str, str]) -> str:
    """``string.Template`` 填充：用 ``$var`` 而非 ``{}``，否则 JSON 花括号会被当占位符。"""
    return string.Template(template).safe_substitute(mapping)


def _function_hint(case: RepairCase) -> str:
    try:
        ctx = build_context(case.code.func_src)
    except Exception:  # noqa: BLE001
        return "(unknown)"
    return _resolve_function(case, ctx) or "(unknown)"


def _clip(text: str) -> Optional[str]:
    text = (text or "").strip()
    if not text:
        return None
    return text[:MAX_BEHAVIOR_CHARS]


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


__all__ = [
    "BEHAVIOR_FIELD",
    "VIEWS",
    "MAX_BEHAVIOR_CHARS",
    "DEGRADED_SOURCE_LINES",
    "SYSTEM_PROMPT",
    "build_query",
    "collect_risky_calls",
]
