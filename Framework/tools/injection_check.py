"""注入类 CWE 的源码事实核验工具（命令注入 78 / SQL 注入 89 / XSS 79）。

与 ``tools/dynamic_check.py`` 同构、同证据哲学，但不做编译/运行：
动态执行需要 shell / 数据库 / 浏览器等外部环境配合，本模块先在**源码层**核验
注入专属事实——危险 sink 是否命中、输入是否直达 sink、有无参数化/转义/白名单
等安全写法。

口径（与 verify_taint 的"只出有罪证据、启发式不推翻"对齐）：

* 只处理 78 / 89 / 79，其余 CWE 直接跳过（uncertain）；
* 命中 sink + 直达线索 + 无安全写法 → accept（源码启发式证据，0.88，≥ τ=0.8）；
* 命中疑似守卫 → 降级 uncertain（守卫是否真有效由路径核验 / LLM 复核，本工具不推翻）；
* 未命中 sink / 来源无法确认 / 源码缺失 → uncertain；
* **永不 reject**：源码静态看不到 ≠ 没有漏洞，也不据此判无罪。

字段沿用 D 假设结构：``finding_id / title / cwe / location.function /
function_name / taint_source / taint_sink``。
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

from observability import log_event

TOOL_NAME = "injection_check"

# ---------------------------------------------------------------------------
# 置信度常量
# ---------------------------------------------------------------------------
#: 源码启发式注入证据：高于默认 τ(0.8)，可定案；略低于动态崩溃 0.92，
#: 因为它是静态特征而非运行时复现。
CONF_INJECTION_EVIDENCE = 0.88

#: 开关：显式关闭时直接跳过（默认开启；与 DYNCHECK_ENABLED 同款环境变量风格）。
ENABLED = os.environ.get("INJCHECK_ENABLED", "1") not in ("0", "false", "False")

#: 本工具覆盖的注入类 CWE。
INJECTION_CWES = frozenset({"78", "89", "79"})

_CWE_RE = re.compile(r"(?:CWE[-_ ]?)?(\d{1,5})", re.IGNORECASE)

# ---------------------------------------------------------------------------
# sink / 守卫 / 拼接 特征表（按 CWE 分组）
# ---------------------------------------------------------------------------
#: 命令注入 sink：shell 执行 / 进程创建。
_CMD_SINKS = [
    "system", "popen", "execl", "execlp", "execv", "execvp", "execve",
    "posix_spawn",
]
#: SQL 注入 sink：查询 / 语句准备。
_SQL_SINKS = [
    "sqlite3_exec", "sqlite3_prepare", "sqlite3_prepare_v2",
    "mysql_query", "PQexec", "db_query",
]
#: XSS sink：输出到响应 / 页面的常见函数（粗口径，守卫优先抵消误报）。
_XSS_SINKS = [
    "printf", "fprintf", "sprintf", "snprintf", "fputs", "fwrite", "puts",
]

#: 命令注入守卫：参数数组执行（不经 shell）/ 输入引用转义 / 白名单校验。
_CMD_GUARDS = [
    r"\bexecve\s*\(",          # 参数数组 + 环境数组，不经 sh
    r"\bposix_spawn\s*\(",
    r"\b(?:shell_)?quote\w*\s*\(",
    r"\bescape\w*\s*\(",
    r"\b(?:whitelist|allowlist|valid_\w*|check_\w*)\b",
]
#: SQL 守卫：参数化绑定 / 转义。
_SQL_GUARDS = [
    r"\bsqlite3_bind\w*\s*\(",  # prepare + bind = 参数化查询
    r"\bmysql_real_escape_string\s*\(",
    r"\bescape\w*\s*\(",
]
#: XSS 守卫：HTML / 实体转义包裹。
_XSS_GUARDS = [
    r"\b(?:html_)?escape\w*\s*\(",
    r"\bhtmlentities\s*\(",
    r"\bxmlEscape\s*\(",
    r"\bencode\w*\s*\(",
    r"\bsanitize\w*\s*\(",
]

#: 把外部输入拼进命令 / SQL 串的常见构造函数。
_CONCAT_BUILDERS = re.compile(
    r"\b(?:sprintf|snprintf|asprintf|strcat|strcpy|strncat|strncpy)\b"
)
#: sink 调用里的字符串字面量（用于判断实参是否纯字面量）。
_STR_LITERAL = re.compile(r'"(?:\\.|[^"\\])*"')
_IDENT = re.compile(r"\b[A-Za-z_]\w*\b")


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------
def _norm_cwe(raw: Any) -> str:
    """从 hypothesis 的 cwe 字段抽出数字编号；抽不到返回 ''。"""
    m = _CWE_RE.search(str(raw or ""))
    return m.group(1) if m else ""


def _extract_function(code: str, func_name: str) -> Optional[str]:
    """粗提取被测函数文本（括号配平截取）；取不到返回 None。"""
    if not func_name:
        return None
    idx = code.find(func_name)
    if idx < 0:
        return None
    start = code.rfind("\n", 0, idx)
    brace_start = code.find("{", idx)
    if brace_start < 0:
        return None
    depth = 0
    for i in range(brace_start, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return code[start + 1: i + 1]
    return None


def _sink_regex(sinks: List[str]) -> re.Pattern:
    return re.compile(r"\b(?:" + "|".join(re.escape(s) for s in sinks) + r")\s*\(")


def _sink_hits(cwe: str, body: str) -> List[Dict[str, Any]]:
    """在函数体里找 sink 命中，返回 [{name, line, snippet}]。"""
    if cwe == "78":
        sinks = _CMD_SINKS
    elif cwe == "89":
        sinks = _SQL_SINKS
    else:
        sinks = _XSS_SINKS
    rx = _sink_regex(sinks)
    hits: List[Dict[str, Any]] = []
    for line_no, line in enumerate(body.splitlines(), start=1):
        m = rx.search(line)
        if not m:
            continue
        name = _IDENT.search(line[m.start():])
        hits.append({
            "name": name.group(0) if name else m.group(0),
            "line": line_no,
            "snippet": line.strip()[:160],
        })
    return hits


def _guard_hits(cwe: str, body: str, sink_line: int) -> List[Dict[str, Any]]:
    """找安全写法守卫（粗规则，不做三重作用域——那是 verify_taint 的职责）。

    * SQL 参数化 ``bind`` 与 prepare 是配套调用，允许出现在 sink 前后，不卡位置；
    * 其余守卫在 sink 前窗口 + sink 同行实参内检查（如 ``escape_html(x)`` 包裹）。
    """
    lines = body.splitlines()
    # SQL：prepare + bind 视为参数化查询，整个函数体找 bind，不卡位置。
    if cwe == "89":
        for line_no, line in enumerate(lines, start=1):
            if re.search(r"\bsqlite3_bind\w*\s*\(", line):
                return [{"pattern": "sqlite3_bind*", "line": line_no,
                         "snippet": line.strip()[:120]}]
    if cwe == "78":
        guards = _CMD_GUARDS
    elif cwe == "89":
        guards = _SQL_GUARDS
    else:
        guards = _XSS_GUARDS
    guard_rx = [re.compile(p) for p in guards]
    hits: List[Dict[str, Any]] = []
    for line_no, line in enumerate(lines, start=1):
        if line_no > sink_line:  # 同行实参里的包裹守卫也纳入
            break
        for rx in guard_rx:
            if rx.search(line):
                hits.append({"pattern": rx.pattern, "line": line_no,
                             "snippet": line.strip()[:120]})
                break
    return hits


def _direct_input(hypothesis: Dict[str, Any], body: str,
                  sink: Dict[str, Any]) -> bool:
    """判断外部输入是否直达 sink：实参含变量 / 存在拼接构造 / taint_source 出现。"""
    # 1) sink 实参不是纯字符串字面量（含标识符变量）
    snippet = sink.get("snippet", "")
    non_literal = _STR_LITERAL.sub("", snippet)
    if _IDENT.search(non_literal):
        return True
    # 2) 函数体内存在把输入拼进命令 / SQL 的构造
    if _CONCAT_BUILDERS.search(body):
        return True
    # 3) 假设点名的 taint_source 变量出现在 sink 行
    source = str(hypothesis.get("taint_source") or "")
    for tok in _IDENT.findall(source):
        if tok in snippet:
            return True
    return False


def _skip(reason: str, finding_id: str = "", **extra: Any) -> Dict[str, Any]:
    """统一降级返回：uncertain + 0.0 置信度（绝不 reject）。"""
    ev: Dict[str, Any] = {"skipped": True, "reason": reason}
    ev.update(extra)
    return {
        "status": "uncertain",
        "verdict": "uncertain",
        "confidence": 0.0,
        "reason": f"注入核验跳过：{reason}",
        "evidence": ev,
        "tool_name": TOOL_NAME,
        "raw_output": {"finding_id": finding_id},
    }


# ---------------------------------------------------------------------------
# 对外入口
# ---------------------------------------------------------------------------
def injection_check(hypothesis: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """对一条注入类 finding 做源码事实核验，返回与 verify_taint 同构的结果。

    :param hypothesis: ``{finding_id, title, cwe, location:{function},
        function_name, taint_source, taint_sink, ...}``
    :param context:    ``{file, line_range, code}``
    """
    hypothesis = hypothesis or {}
    context = context or {}
    finding_id = str(hypothesis.get("finding_id") or "")

    if not ENABLED:
        return _skip("INJCHECK_ENABLED=0", finding_id)

    cwe = _norm_cwe(hypothesis.get("cwe"))
    if cwe not in INJECTION_CWES:
        return _skip(
            f"CWE {cwe or '?'} 非注入类（78/89/79），本工具不适用",
            finding_id,
        )

    code = str(context.get("code") or "")
    if not code.strip():
        return _skip("context.code 为空", finding_id)

    func_name = str(
        (hypothesis.get("location") or {}).get("function")
        or hypothesis.get("function_name")
        or ""
    ).strip()
    body = _extract_function(code, func_name) if func_name else None
    # 取不到函数体时退回整段源码扫描（注入 sink 可能在顶层 / 其他函数）。
    scan_body = body or code

    sinks = _sink_hits(cwe, scan_body)
    if not sinks:
        return _skip("未在源码识别到对应注入 sink", finding_id, cwe=cwe)

    # 取首个 sink 行做守卫位置判断；守卫命中即降级 uncertain，不推翻 finding。
    first_sink = sinks[0]
    guards = _guard_hits(cwe, scan_body, first_sink["line"])
    if guards:
        return {
            "status": "uncertain",
            "verdict": "uncertain",
            "confidence": 0.0,
            "reason": (
                f"命中 {len(sinks)} 个 sink，但存在疑似安全写法"
                f"（参数化 / 转义 / 白名单），需路径与上下文复核"
            ),
            "evidence": {
                "cwe": cwe,
                "sink_hits": sinks,
                "guards": guards,
                "direct_input": False,
                "backend": "static-source",
            },
            "tool_name": TOOL_NAME,
            "raw_output": {"finding_id": finding_id, "sink_count": len(sinks)},
        }

    direct = _direct_input(hypothesis, scan_body, first_sink)
    if not direct:
        return _skip(
            "命中 sink，但输入来源无法从源码确认（存疑，不判无罪）",
            finding_id,
            cwe=cwe,
            sink_hits=sinks,
        )

    cwe_label = {"78": "命令注入", "89": "SQL 注入", "79": "XSS"}[cwe]
    return {
        "status": "verified",
        "verdict": "accept",
        "confidence": CONF_INJECTION_EVIDENCE,
        "reason": (
            f"源码命中{cwe_label} sink（{len(sinks)} 处），外部输入直达且未见"
            f"参数化 / 转义 / 白名单等安全写法"
        ),
        "evidence": {
            "cwe": cwe,
            "sink_hits": sinks,
            "guards": [],
            "direct_input": True,
            "backend": "static-source",
        },
        "tool_name": TOOL_NAME,
        "raw_output": {"finding_id": finding_id, "sink_count": len(sinks)},
    }


# ---------------------------------------------------------------------------
# LangChain 工具包装（与 verify_taint_tool / dynamic_check_tool 同款降级策略）
# ---------------------------------------------------------------------------
try:  # pragma: no cover
    from langchain_core.tools import tool as _lc_tool  # type: ignore

    @_lc_tool("injection_check")
    def injection_check_tool(hypothesis: dict, context: dict) -> dict:
        """对命令注入 / SQL 注入 / XSS finding 做源码事实核验（只输出有罪证据）。"""
        return injection_check(hypothesis, context)

except Exception:  # pragma: no cover
    injection_check_tool = None  # type: ignore
