"""location 校正与假设构造：把 LLM 报的行号变成语法树事实。

从 ``verify_agent/d.py`` 拆出（20 文档 §5.1-2）。这里是修复端输入的 P0 前置：
**先校正 location，再构造 hypothesis**，顺序不能反 —— ``verify_taint.check_assumptions``
是拿 ``location.function`` 去取函数体的，占位文本 / 空串会让 ``conditions[].holds``
全部退化为 null。

三件事都只能在检测端做（修复端没有文件系统）：

1. ``function`` 改为**按行号反查**得到的函数名，覆盖 A/B/C 的文本判断；
2. 记下函数的真实行范围（``function_line_start/end``），修复端要的 ``func_src``
   就是从这里切的；
3. ``line_start/line_end`` 吸附到包含该行的***最内层语句***。
"""
from __future__ import annotations

from typing import Any, Dict, List

from tools.call_context import statement_at_line


def as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def resolve_location(
    finding: Dict[str, Any],
    ctx: Any,
    code: str,
) -> Dict[str, Any]:
    """用语法树校正 ``location``：按行号反查所属函数 + 把漏洞行吸附到语句级。

    校正失败时保留原始行号并把来源标成 ``llm``，让下游看得出这条没核过。
    """
    out = dict(finding)
    loc = dict(finding.get("location") or {})
    line = as_int(loc.get("line_start"))
    if line <= 0:
        out["location"] = loc
        return out

    info = None
    if ctx is not None:
        try:
            info = ctx.function_at(line)
        except Exception:  # pragma: no cover - 防御：降级为不校正
            info = None
    if info is not None:
        loc["function"] = info.get("function", "")
        loc["function_line_start"] = as_int(info.get("line_start"))
        loc["function_line_end"] = as_int(info.get("line_end"))
        loc["function_resolved_by"] = "ast"
    else:
        loc["function_resolved_by"] = "llm"

    stmt = statement_at_line(code, line, fallback_to_next=True)
    if stmt is not None:
        loc["line_start"] = as_int(stmt.get("line_start"))
        loc["line_end"] = as_int(stmt.get("line_end")) or loc["line_start"]
        loc["line_source"] = "ast" if stmt.get("matched") == "contains" else "ast-next"
    else:
        loc["line_source"] = "llm"

    out["location"] = loc
    return out


def normalize_slice_location(
    finding: Dict[str, Any],
    offset: int,
    n_lines: int,
) -> Dict[str, Any]:
    """把「原文件绝对行号」归一为「切片内行号」。

    场景：``--file`` 给的是**切片**（例如数据集里 ``..._9090-9393___9290.c_vul.c``，
    内容只有 304 行），而 A/B/C 常把结论里的行号写成原文件坐标（9290）。
    9290 在 304 行的代码里取不到任何函数，下游 ``function_at`` 返回 ``None``，
    ``func_src`` 就切不出来，整个 case 被判 ``invalid_baseline``。

    判定规则刻意保守：**只有行号已经超出切片行数时**才平移——那说明它报的是原文件坐标。
    行号本来就在切片范围内时一律不动（模型也可能直接报对了，不能把对的改错）。

    平移后仍不合法（例如偏得离谱）则原样返回，交给 ``resolve_location`` 标成 ``llm``，
    不硬凑一个假行号。
    """
    if offset <= 0 or n_lines <= 0:
        return finding
    loc = dict(finding.get("location") or {})
    line = as_int(loc.get("line_start"))
    if line <= 0 or line <= n_lines:
        return finding

    shifted = line - offset + 1
    if not (1 <= shifted <= n_lines):
        return finding

    end = as_int(loc.get("line_end")) or line
    shifted_end = end - offset + 1
    loc["line_start"] = shifted
    loc["line_end"] = shifted_end if 1 <= shifted_end <= n_lines else shifted
    loc["slice_shifted_from"] = line
    out = dict(finding)
    out["location"] = loc
    return out


def norm_path(raw: Any) -> List[str]:
    """把报告里的传播路径归一为有序节点名列表（丢弃空元素与相邻重复）。"""
    seq: List[str] = []
    for item in raw or []:
        if isinstance(item, dict):
            text = str(item.get("function") or item.get("name") or item.get("node") or "")
        else:
            text = str(item or "")
        text = text.strip()
        if not text:
            continue
        if not seq or seq[-1] != text:
            seq.append(text)
    return seq


def norm_assumptions(finding: Dict[str, Any]) -> List[Dict[str, str]]:
    """读取 finding 里的假设条件（触发前提），归一为 ``[{id, kind, text}]``。

    §7① 方案 ①：**不改 A/B/C**。若 A/B/C 将来提供 ``assume`` / ``conditions``
    字段就直接读；当前报告 schema 里没有，于是返回空列表，条件核验退化为
    「仅核路径」（子设计 §4.3 第 3 条）。
    """
    raw: Any = finding.get("assumptions")
    if not raw:
        raw = finding.get("assume")
    if not raw:
        raw = finding.get("conditions")

    out: List[Dict[str, str]] = []
    if isinstance(raw, str):
        raw = [raw]
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


def build_hypothesis(finding: Dict[str, Any], code: str) -> Dict[str, Any]:
    """构造待验证假设。

    【优化 O-7】不再把完整 ``code`` 内联进 hypothesis：完整源码只在 context 中
    出现一次，消除原来 hypothesis.code 与 context.code 的重复传输。

    【假设条件 + 触发路径核验】新增两键（旧键语义不变）：
      * ``trigger_path``：归一后的 source→sink 节点序列，默认取
        ``propagation_path``，供 verify_taint 逐跳核验可达性；
      * ``assumptions``：假设条件（触发前提），来源优先级见 ``norm_assumptions``。
    """
    loc = finding.get("location") or {}
    propagation = finding.get("propagation_path", [])
    return {
        "finding_id": finding.get("id", ""),
        "title": finding.get("title", ""),
        "cwe": finding.get("cwe", ""),
        "taint_source": finding.get("taint_source", ""),
        "taint_sink": finding.get("taint_sink", ""),
        "propagation_path": propagation,
        "trigger_path": norm_path(propagation),
        "assumptions": norm_assumptions(finding),
        "location": loc,
    }
