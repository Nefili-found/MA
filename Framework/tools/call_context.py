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
"""
from __future__ import annotations

from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

from tree_sitter import Language, Parser

import tree_sitter_cpp

TOOL_NAMES: Tuple[str, ...] = ("get_callers", "get_callees", "get_function_body")


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


# ---------------------------------------------------------------------------
# 上下文对象
# ---------------------------------------------------------------------------
class CallContext:
    """单文件的函数索引 + 调用点边。"""

    def __init__(
        self,
        functions: Dict[str, Dict[str, Any]],
        edges: List[Tuple[str, str, int]],
    ) -> None:
        # functions: name -> {"signature", "line_start", "line_end", "body"}
        self.functions = functions
        # edges: (caller, callee, call_line)
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

    def callers(self, function_name: str) -> Dict[str, Any]:
        raw = (function_name or "").strip()
        name = self._canonical(raw)
        short = name.split("::")[-1]
        hits = [
            {"caller": caller, "call_line": line}
            for (caller, callee, line) in self.edges
            if callee == name or callee.split("::")[-1] == short
        ]
        return {
            "function": raw,
            "resolved": name,
            "found": name in self.functions,
            "callers": hits,
            "count": len(hits),
        }

    def callees(self, function_name: str) -> Dict[str, Any]:
        raw = (function_name or "").strip()
        name = self._canonical(raw)
        short = name.split("::")[-1]
        hits = [
            {
                "callee": callee,
                "call_line": line,
                "defined_in_file": callee in self.functions,
            }
            for (caller, callee, line) in self.edges
            if caller == name or caller.split("::")[-1] == short
        ]
        return {
            "function": raw,
            "resolved": name,
            "found": name in self.functions,
            "callees": hits,
            "count": len(hits),
        }

    def function_body(self, function_name: str) -> Dict[str, Any]:
        raw = (function_name or "").strip()
        name = self._canonical(raw)
        info = self.functions.get(name)
        if info is None:
            return {"function": raw, "found": False}
        return {"function": raw, "resolved": name, "found": True, **info}


def build_context(code: str) -> CallContext:
    """解析单份 C / C++ 源码，构建 ``CallContext``（失败降级为空上下文）。"""
    functions: Dict[str, Dict[str, Any]] = {}
    edges: List[Tuple[str, str, int]] = []

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
                    edges.append((name, callee, call.start_point.row + 1))

    return CallContext(functions, edges)


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


# ---------------------------------------------------------------------------
# 纯函数（可显式传 context，便于测试 / 复用）
# ---------------------------------------------------------------------------
def get_callers(function_name: str, context: Optional[CallContext] = None) -> Dict[str, Any]:
    """返回目标函数在文件内的所有调用者（caller + 调用行号）。"""
    return (context or _active()).callers(function_name)


def get_callees(function_name: str, context: Optional[CallContext] = None) -> Dict[str, Any]:
    """返回目标函数调用的所有函数（callee + 调用行号）。"""
    return (context or _active()).callees(function_name)


def get_function_body(function_name: str, context: Optional[CallContext] = None) -> Dict[str, Any]:
    """返回目标函数的签名、起止行号与实现。"""
    return (context or _active()).function_body(function_name)


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
