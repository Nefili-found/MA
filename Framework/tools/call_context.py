"""单文件调用上下文工具（tree-sitter-cpp 实现，兼容 C 与 C++）。

为 D（verifier）提供跨过程证据：给定单份 C / C++ 源码，预提取「函数索引 + 调用点边」，
并导出 MAVUL 式三件套工具：

* ``get_callers``       —— 谁调用了该函数（追踪污点参数来源 / 入口校验）
* ``get_callees``       —— 该函数调用了谁（追踪 sink / 指针使用 / 资源释放）
* ``get_function_body`` —— 该函数的签名、行范围与实现（确认跨过程依赖）

约束（与项目一致）：
* 严格**单文件内**抽取，不跨文件 / 不跨仓；
* 解析失败一律降级为空结果，**不抛异常**（避免拖垮整图）。

导出范式参照 ``tools/verify_taint.py``：纯函数 + try/except 包裹的 LangChain 工具
（未安装 ``langchain-core`` 时工具为 ``None``）。

================================================================================
【优化点 O-6】领域层的“输出结构化限量”，从源头减少进入上下文的体量。
--------------------------------------------------------------------------------
对应 B 篇原文件：tools/call_context.py（本文件优化前的版本）
原问题：
    * ``get_callers`` / ``get_callees`` 把**全部**匹配边一次性返回（可能上百条，
      且同一调用点被重复计入），在 D 的多轮工具循环里这些大 JSON 会被反复累积。
    * ``get_function_body`` 返回完整函数体但不附带体量信息，D 无从判断是否超大。
本文件的优化（领域层，负责“按语义精炼”）：
    * caller/callee 列表【去重】+【限量】（默认最多 40 条），返回
      total / returned / truncated，模型需要更多时可再按函数名定点查询；
    * function_body 额外返回 body_lines / body_chars 体量信号（默认仍返回完整
      函数体，因为它是“按需获取完整实现”的工具）；
    * 超大函数体的真正落盘交给治理层：D 在把结果写入 ToolMessage 前调用
      ``ContextManager.spill_text``（A 篇 spill 时机），历史累积再由
      prune / compact 兜底。领域层不重复实现字节裁剪。
所有改动向后兼容：``count`` 字段保留（语义为去重后的真实总数），原三件套函数名、
参数与返回结构不变，仅新增字段与可选参数。
================================================================================
"""
from __future__ import annotations

from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

from tree_sitter import Language, Parser

import tree_sitter_cpp

TOOL_NAMES: Tuple[str, ...] = ("get_callers", "get_callees", "get_function_body")

# 【优化】列表类结果的默认上限：每个函数返回的调用者 / 被调用者条目上限。
# 超出部分只返回截断提示，模型可按需对具体函数定点查询。
DEFAULT_MAX_HITS = 40
# 【优化】函数体直接返回的最大行数 / 字符数（纯函数可选参数，默认不硬截断，
# 交给治理层 spill；这里仅作为需要时的手动上限）。
DEFAULT_MAX_BODY_LINES = 0  # 0 表示不限制
DEFAULT_MAX_BODY_CHARS = 0  # 0 表示不限制


# ---------------------------------------------------------------------------
# tree-sitter 语言加载（失败则整体降级为空上下文）
# ---------------------------------------------------------------------------
def _load_language() -> Optional["Language"]:
    try:
        return Language(tree_sitter_cpp.language())
    except Exception:  # pragma: no cover - 依赖/版本异常
        return None


_LANGUAGE = _load_language()


def _iter_descendants(node: Any) -> Iterator[Any]:
    """深度优先遍历某节点及其全部后代。"""
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        # reversed()：让“第一个子节点”最后入栈、最先弹出，得到自然前序遍历
        stack.extend(reversed(getattr(cur, "children", None) or []))


def _node_text(node: Any) -> str:
    try:
        raw = node.text
    except Exception:  # pragma: no cover
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return str(raw or "")


def _first_identifier(node: Any) -> Optional[str]:
    for n in _iter_descendants(node):
        if n.type == "identifier":
            return _node_text(n)
    return None


def _declarator_name(node: Any) -> Optional[str]:
    """解析声明符链，返回函数名（保留 C++ 的限定名，如 ``A::B::f``）。"""
    cur = node
    for _ in range(32):  # 防御性上限，避免异常 AST 死循环
        if cur is None:
            break
        if cur.type in (
            "identifier",
            "field_identifier",
            "qualified_identifier",
            "destructor_name",
            "operator_name",
        ):
            return _node_text(cur)
        nxt = cur.child_by_field_name("declarator")
        if nxt is None:
            break
        cur = nxt
    return _first_identifier(node)


def _func_name(func_node: Any) -> Optional[str]:
    """从 function_definition 取函数名。

    兼容 C 的 ``identifier`` 与 C++ 的 ``qualified_identifier``（如
    ``CellularNetwork::Clear``）及类内 ``field_identifier``。
    """
    decl = func_node.child_by_field_name("declarator")
    if decl is None:
        return None
    name_node = (
        decl.child_by_field_name("declarator")
        if decl.type == "function_declarator"
        else decl
    )
    if name_node is None:
        name_node = decl
    return _declarator_name(name_node)


def _callee_name(call_node: Any) -> Optional[str]:
    """从 call_expression 取被调函数名（C / C++ 的常见调用形式）。"""
    fn = call_node.child_by_field_name("function")
    if fn is None:
        return None
    if fn.type == "identifier":
        return _node_text(fn)
    if fn.type == "field_expression":  # obj.method / ptr->method
        field = fn.child_by_field_name("field")
        if field is not None:
            return _node_text(field)
    if fn.type == "qualified_identifier":  # Class::static_method
        return _node_text(fn)
    if fn.type == "template_function":  # foo<T>(...)
        name = fn.child_by_field_name("name")
        if name is not None:
            return _node_text(name)
    # 函数指针调用 / 复杂表达式 -> 未知
    return None


def _as_line(value: Any) -> int:
    """把行号字段安全归一为 int；非法 / 缺省一律当 0（= 未知）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# 上下文对象
# ---------------------------------------------------------------------------
class CallContext:
    """单文件的函数索引 + 调用点边。"""

    def __init__(
        self,
        functions: Dict[str, Dict[str, Any]],
        edges: List[Tuple[str, str, int, int]],
    ) -> None:
        # functions: name -> {"signature", "line_start", "line_end", "body"}
        self.functions = functions
        # edges: (caller, callee, call_line, call_column)  —— 列号用于同行多调用点去重
        self.edges = edges

    def _canonical(self, function_name: str) -> str:
        """把查询名归一为索引键：去参数列表 + 用简单名补全为限定名。

        模型常传完整签名（如 ``CellularNetwork::CellularNetwork(const ServiceInfo*)``），
        这里先截掉参数列表，再按简单名匹配限定名（``Clear`` → ``CellularNetwork::Clear``）。
        """
        name = (function_name or "").strip()
        if "(" in name:
            name = name.split("(", 1)[0].strip()
        if name in self.functions:
            return name
        short = name.split("::")[-1]
        for key in self.functions:
            if key.split("::")[-1] == short:
                return key
        return name

    def callers(self, function_name: str, max_hits: int = DEFAULT_MAX_HITS) -> Dict[str, Any]:
        raw = (function_name or "").strip()
        name = self._canonical(raw)
        short = name.split("::")[-1]
        # 【优化】按 (caller, 行, 列) 去重：同一行的多个调用点用列号区分，
        # 避免 `foo(); foo();` 这类同行调用被误并；仍能去掉完全相同的重复边。
        seen: set[Tuple[str, int, int]] = set()
        unique: List[Dict[str, Any]] = []
        for (caller, callee, line, col) in self.edges:
            if not (callee == name or callee.split("::")[-1] == short):
                continue
            key = (caller, line, col)
            if key in seen:
                continue
            seen.add(key)
            unique.append({"caller": caller, "call_line": line, "call_column": col})

        total = len(unique)
        limit = max_hits if isinstance(max_hits, int) and max_hits > 0 else total
        hits = unique[:limit]
        return {
            "function": raw,
            "resolved": name,
            "found": name in self.functions,
            "callers": hits,
            "count": total,        # 兼容旧字段：去重后的真实总数
            "returned": len(hits),
            "truncated": total > len(hits),
            "hint": (
                f"仅返回前 {len(hits)} 个调用点，共 {total} 个；"
                "如需定位具体来源，可用 get_function_body 查看对应调用者。"
                if total > len(hits) else ""
            ),
        }

    def callees(self, function_name: str, max_hits: int = DEFAULT_MAX_HITS) -> Dict[str, Any]:
        raw = (function_name or "").strip()
        name = self._canonical(raw)
        short = name.split("::")[-1]
        # 【优化】按 (callee, 行, 列) 去重
        seen: set[Tuple[str, int, int]] = set()
        unique: List[Dict[str, Any]] = []
        for (caller, callee, line, col) in self.edges:
            if not (caller == name or caller.split("::")[-1] == short):
                continue
            key = (callee, line, col)
            if key in seen:
                continue
            seen.add(key)
            unique.append(
                {
                    "callee": callee,
                    "call_line": line,
                    "call_column": col,
                    "defined_in_file": callee in self.functions,
                }
            )

        total = len(unique)
        limit = max_hits if isinstance(max_hits, int) and max_hits > 0 else total
        hits = unique[:limit]
        return {
            "function": raw,
            "resolved": name,
            "found": name in self.functions,
            "callees": hits,
            "count": total,
            "returned": len(hits),
            "truncated": total > len(hits),
            "hint": (
                f"仅返回前 {len(hits)} 个调用点，共 {total} 个；"
                "可用 get_function_body 查看具体被调函数实现。"
                if total > len(hits) else ""
            ),
        }

    def function_body(
        self,
        function_name: str,
        max_lines: int = DEFAULT_MAX_BODY_LINES,
        max_chars: int = DEFAULT_MAX_BODY_CHARS,
    ) -> Dict[str, Any]:
        raw = (function_name or "").strip()
        name = self._canonical(raw)
        info = self.functions.get(name)
        if info is None:
            return {"function": raw, "found": False}

        body = info.get("body", "") or ""
        body_lines = body.count("\n") + 1
        body_chars = len(body)

        # 【优化】仅在显式传入上限时做硬截断；默认不限制（完整 body 交给
        # 治理层 spill：D 写入 ToolMessage 前会落盘并返回首尾预览）。
        truncated = False
        omitted_lines = 0
        if (max_lines and body_lines > max_lines) or (max_chars and body_chars > max_chars):
            lines = body.splitlines()
            if max_lines and len(lines) > max_lines:
                head_n = max(1, max_lines - 8)
                head = "\n".join(lines[:head_n])
                tail = "\n".join(lines[-8:])
                body = f"{head}\n    /* ...[函数体过长，中间省略 {len(lines) - head_n - 8} 行]... */\n{tail}"
                omitted_lines = len(lines) - head_n - 8
            if max_chars and len(body) > max_chars:
                body = body[:max_chars] + "\n    /* ...[函数体过长，按字符截断]... */"
            truncated = True

        return {
            "function": raw,
            "resolved": name,
            "found": True,
            **info,
            "body": body,
            "body_lines": body_lines,
            "body_chars": body_chars,
            "body_truncated": truncated,
            "omitted_lines": omitted_lines,
        }

    def function_at(self, line: int) -> Optional[Dict[str, Any]]:
        """按行号反查所属函数；行号不在任何函数内时返回 ``None``。

        与 ``_canonical``（按名查）互补：A/B/C 报的 ``location.function`` 可能是
        占位文本（实测 ``"containing function unavailable in supplied excerpt"``）
        或空串，而**行号是模型必须给的主键**，所以按行反查比按名查可靠。

        区间重叠（嵌套 lambda / 类内定义）时取行跨度最小的那个。
        """
        target = _as_line(line)
        if target <= 0:
            return None
        best: Optional[Tuple[int, str, Dict[str, Any]]] = None
        for name, info in self.functions.items():
            start = _as_line(info.get("line_start"))
            end = _as_line(info.get("line_end"))
            if not (start and end and start <= target <= end):
                continue
            span = end - start
            if best is None or span < best[0]:
                best = (span, name, info)
        if best is None:
            return None
        _, name, info = best
        return {"function": name, **info}


def build_context(code: str) -> CallContext:
    """解析单份 C / C++ 源码，构建 ``CallContext``（失败降级为空上下文）。"""
    functions: Dict[str, Dict[str, Any]] = {}
    edges: List[Tuple[str, str, int, int]] = []

    if not code or _LANGUAGE is None:
        return CallContext(functions, edges)

    try:
        parser = Parser(_LANGUAGE)
        tree = parser.parse(code.encode("utf-8", "replace"))
        root = tree.root_node
    except Exception:  # pragma: no cover - 解析异常时降级
        return CallContext(functions, edges)

    for node in _iter_descendants(root):
        if node.type != "function_definition":
            continue
        name = _func_name(node)
        if not name:
            continue
        decl = node.child_by_field_name("declarator")
        body = node.child_by_field_name("body")
        functions[name] = {
            "signature": _node_text(decl) if decl is not None else name,
            "line_start": node.start_point.row + 1,
            "line_end": node.end_point.row + 1,
            "body": _node_text(body) if body is not None else "",
        }
        if body is not None:
            for call in _iter_descendants(body):
                if call.type != "call_expression":
                    continue
                callee = _callee_name(call)
                if callee:
                    # 【优化】记录 (caller, callee, 行, 列)，列号用于同行多调用点去重
                    edges.append((name, callee, call.start_point.row + 1, call.start_point.column))

    return CallContext(functions, edges)


# ---------------------------------------------------------------------------
# 语句级定位：把报告里的行号吸附到语法的「最内层语句」
# ---------------------------------------------------------------------------
# 只收**语句**，不收 ``compound_statement``（整块）—— 修复端明确不要「整个 if 块
# 的首行」，宁可返回 None 让调用方退化为「下一条语句」或保留原行号。
_STATEMENT_TYPES = frozenset(
    {
        "expression_statement",
        "declaration",
        "return_statement",
        "if_statement",
        "for_statement",
        "for_range_loop",
        "while_statement",
        "do_statement",
        "switch_statement",
        "case_statement",
        "break_statement",
        "continue_statement",
        "goto_statement",
        "labeled_statement",
        "throw_statement",
        "try_statement",
        "co_return_statement",
        "co_yield_statement",
    }
)


def statement_regions(code: str) -> List[Dict[str, Any]]:
    """解析一次，返回全文所有语句的 ``{line_start, line_end, kind, text}``。

    单独导出是为了让「一个文件多条 finding」只解析一次（``statement_at_line``
    内部按源码内容做单条缓存，避免每个 finding 重新解析同一份文件）。
    """
    if not code or _LANGUAGE is None:
        return []
    try:
        tree = Parser(_LANGUAGE).parse(code.encode("utf-8", "replace"))
    except Exception:  # pragma: no cover - 解析异常时降级
        return []
    regions: List[Dict[str, Any]] = []
    for node in _iter_descendants(tree.root_node):
        if node.type not in _STATEMENT_TYPES:
            continue
        start = node.start_point.row + 1
        end = node.end_point.row + 1
        if end < start:
            continue
        regions.append(
            {"line_start": start, "line_end": end, "kind": node.type, "text": _node_text(node)}
        )
    return regions


# 单条缓存：同一份源码（内容相同）只解析一次。键为源码文本，容量 1。
_REGION_CACHE: Dict[str, Any] = {"code": "", "regions": []}


def _regions_for(code: str) -> List[Dict[str, Any]]:
    if _REGION_CACHE["code"] == code and _REGION_CACHE["regions"]:
        return _REGION_CACHE["regions"]
    regions = statement_regions(code)
    _REGION_CACHE["code"] = code
    _REGION_CACHE["regions"] = regions
    return regions


def statement_at_line(
    code: str,
    line: int,
    fallback_to_next: bool = False,
) -> Optional[Dict[str, Any]]:
    """把行号吸附到包含它的**最内层语句**（1-based 起止行）。

    返回 ``{line_start, line_end, kind, text, matched}``，其中 ``matched`` 为
    ``"contains"``（该行落在语句内）或 ``"next"``（退化到下一条语句）。

    ``fallback_to_next=True`` 时，若该行不在任何语句内（典型：函数签名行、
    注释行、独占一行的 ``{`` / ``}``），取行号在其后最近的一条语句 —— 对应
    ``change_process/summery/修复端_输入需求与用途_2026-10-23_现状.md`` §2.2 的退化约定。

    解析失败或确实无语句可选时返回 ``None``，调用方应保留原始行号并标注来源。
    """
    target = _as_line(line)
    if target <= 0:
        return None
    regions = _regions_for(code)
    if not regions:
        return None

    best: Optional[Tuple[Tuple[int, int], Dict[str, Any]]] = None
    for region in regions:
        if not (region["line_start"] <= target <= region["line_end"]):
            continue
        span = region["line_end"] - region["line_start"]
        key = (span, -region["line_start"])  # 跨度最小 = 最内层
        if best is None or key < best[0]:
            best = (key, region)
    if best is not None:
        return {**best[1], "matched": "contains"}

    if not fallback_to_next:
        return None
    after: Optional[Tuple[int, Dict[str, Any]]] = None
    for region in regions:
        if region["line_start"] < target:
            continue
        if after is None or region["line_start"] < after[0]:
            after = (region["line_start"], region)
    if after is None:
        return None
    return {**after[1], "matched": "next"}


def function_body_source(code: str, line_start: int, line_end: int) -> str:
    """按**原文件字节**切出函数全文（含签名与花括号）。

    ``CallContext.functions[name]["body"]`` 只有花括号内的部分、且丢掉了
    signature 与 body 之间的空白，无法用于「按内容定位」的补丁回填；而修复端
    要求 ``func_src`` 与工程里那份文件一致（见
    ``change_process/summery/修复端_输入需求与用途_2026-10-23_现状.md`` §4），所以这里直接
    切源码行，保留每行原有行尾（CRLF / LF 不归一）。
    """
    start = _as_line(line_start)
    end = _as_line(line_end)
    if not code or start <= 0 or end < start:
        return ""
    lines = code.splitlines(keepends=True)
    if start - 1 >= len(lines):
        return ""
    return "".join(lines[start - 1 : end])


# ---------------------------------------------------------------------------
# 模块级「当前文件上下文」：每次运行由 D 通过 set_active_context() 设置
# ---------------------------------------------------------------------------
_ACTIVE_CONTEXT: Optional[CallContext] = None

ContextArg = Union[str, CallContext, None]


def set_active_context(code_or_ctx: ContextArg) -> CallContext:
    """设置当前文件上下文。接受源码字符串或已构建的 CallContext。"""
    global _ACTIVE_CONTEXT
    if isinstance(code_or_ctx, CallContext):
        _ACTIVE_CONTEXT = code_or_ctx
    else:
        _ACTIVE_CONTEXT = build_context(code_or_ctx or "")
    return _ACTIVE_CONTEXT


def _active() -> CallContext:
    return _ACTIVE_CONTEXT if _ACTIVE_CONTEXT is not None else CallContext({}, [])


def active_context() -> CallContext:
    """返回当前文件上下文（未设置时为空上下文）。

    公开的只读取用器：供 ``tools/verify_taint.py`` 复用 D 在
    ``_verify_findings`` 开头通过 ``set_active_context`` 建好的调用图，
    避免为同一次运行重复解析源码。
    """
    return _active()


# ---------------------------------------------------------------------------
# 纯函数（可显式传 context，便于测试 / 复用）
# ---------------------------------------------------------------------------
def get_callers(
    function_name: str,
    context: Optional[CallContext] = None,
    max_hits: int = DEFAULT_MAX_HITS,
) -> Dict[str, Any]:
    """返回目标函数在文件内的所有调用者（caller + 调用行号，去重并限量）。"""
    return (context or _active()).callers(function_name, max_hits=max_hits)


def get_callees(
    function_name: str,
    context: Optional[CallContext] = None,
    max_hits: int = DEFAULT_MAX_HITS,
) -> Dict[str, Any]:
    """返回目标函数调用的所有函数（callee + 调用行号，去重并限量）。"""
    return (context or _active()).callees(function_name, max_hits=max_hits)


def get_function_body(
    function_name: str,
    context: Optional[CallContext] = None,
    max_lines: int = DEFAULT_MAX_BODY_LINES,
    max_chars: int = DEFAULT_MAX_BODY_CHARS,
) -> Dict[str, Any]:
    """返回目标函数的签名、起止行号与实现（含体量元信息）。"""
    return (context or _active()).function_body(
        function_name, max_lines=max_lines, max_chars=max_chars
    )


# ---------------------------------------------------------------------------
# LangChain 工具包装（供 D 使用 llm.bind_tools([...]) 绑定）。
# 若未安装 langchain-core，则降级为 None，D 会退化为直接调用纯函数。
# ---------------------------------------------------------------------------
try:  # pragma: no cover - 依赖存在时才会执行
    from langchain_core.tools import tool as _lc_tool  # type: ignore

    @_lc_tool("get_callers")
    def get_callers_tool(function_name: str) -> dict:
        """返回目标函数在文件内的所有调用者（caller 函数名 + 调用行号），用于追踪污点参数来源。"""
        return get_callers(function_name)

    @_lc_tool("get_callees")
    def get_callees_tool(function_name: str) -> dict:
        """返回目标函数调用的所有函数（callee 名 + 调用行号），用于追踪 sink、指针使用与资源释放。"""
        return get_callees(function_name)

    @_lc_tool("get_function_body")
    def get_function_body_tool(function_name: str) -> dict:
        """返回目标函数的签名、起止行号与函数体实现，用于确认跨过程依赖。"""
        return get_function_body(function_name)

    CONTEXT_TOOLS = [get_callers_tool, get_callees_tool, get_function_body_tool]

except Exception:  # pragma: no cover
    get_callers_tool = None  # type: ignore
    get_callees_tool = None  # type: ignore
    get_function_body_tool = None  # type: ignore
    CONTEXT_TOOLS = []
