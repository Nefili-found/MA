"""DF / CF 视图证据（tree-sitter，确定性，无 LLM）。

对应设计文档 §5.3：给 LLM 一份**结构化的取数事实**，让它不用在代码里瞎猜
"值从哪来、在什么条件下触发"。论文原样是让 LLM 从修复对自由抽取；本模块
把"自由读代码"升级成"读代码 + 读证据"，语义归纳仍交给 LLM。

两条纪律：

1. 证据里**只放行号 + 原文代码行**，不写任何自然语言解释——解释是 LLM 的活，
   混进来就变成提示泄漏（把答案喂回给模型）。
2. 解析失败一律返回 ``None``（触发 §5.4 的退化路径），**不抛异常**，
   沿用本仓库 `tools/call_context.py` 的降级风格。

依赖：``tree-sitter`` 0.25.x + ``tree-sitter-cpp``（ABI 14，勿升 0.26，
见 requirements.txt:11-16）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from .anchor import Anchor
from .pairs import PairRecord

# 语句级节点（用于把改动行收敛到"一条语句"）
_STATEMENT_TYPES = frozenset(
    {
        "expression_statement",
        "declaration",
        "return_statement",
        "if_statement",
        "switch_statement",
        "for_statement",
        "while_statement",
        "do_statement",
        "call_expression",  # 兜底：宏/单行调用
    }
)

# 控制流容器（CF 证据）
_GUARD_TYPES = frozenset(
    {"if_statement", "switch_statement", "for_statement", "while_statement", "do_statement"}
)

# 外部输入型 API（只影响打标，不影响证据内容）
EXTERNAL_APIS: frozenset[str] = frozenset(
    {
        "recv", "recvfrom", "recvmsg", "read", "readlink", "fread", "fgets", "gets", "getc",
        "getchar", "scanf", "fscanf", "sscanf", "strtoul", "strtol", "atoi", "atol", "getenv",
        "mmap", "ioctl", "fgetws", "fwscanf", "pread", "copy_from_user", "skb_copy_datagram",
    }
)

DEFAULT_MAX_DF_ITEMS = 40
DEFAULT_MAX_CF_ITEMS = 20


@dataclass(frozen=True)
class LineRef:
    """一条证据：行号 + 原文。"""

    line: int
    code: str

    def render(self) -> str:
        return f"L{self.line}: {self.code.strip()}"


@dataclass
class DFEvidence:
    """数据流证据：改动语句上的值从哪来、流到哪去。"""

    change_stmt: LineRef
    idents: list[str] = field(default_factory=list)
    defs: list[LineRef] = field(default_factory=list)
    calls: list[LineRef] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    externals: list[LineRef] = field(default_factory=list)
    truncated: bool = False

    def render(self) -> str:
        if not (self.idents or self.defs or self.calls):
            return ""
        out = [f"changed statement -> {self.change_stmt.render()}"]
        if self.idents:
            out.append("identifiers on that statement: " + ", ".join(self.idents))
        if self.params:
            out.append("function parameters: " + ", ".join(self.params))
        if self.defs:
            out.append("nearest definitions / assignments:")
            out.extend("  " + r.render() for r in self.defs)
        if self.calls:
            out.append("calls on that statement:")
            out.extend("  " + r.render() for r in self.calls)
        if self.externals:
            out.append("external-input APIs used in this function:")
            out.extend("  " + r.render() for r in self.externals)
        if self.truncated:
            out.append("(list truncated)")
        return "\n".join(out)


@dataclass
class CFEvidence:
    """控制流证据：在什么分支 / 循环 / 早退条件下被触发。"""

    guards: list[LineRef] = field(default_factory=list)
    early_returns: list[LineRef] = field(default_factory=list)
    loops: list[LineRef] = field(default_factory=list)
    depth: int = 0
    truncated: bool = False

    def render(self) -> str:
        if not (self.guards or self.early_returns or self.loops):
            return ""
        out: list[str] = []
        if self.guards:
            out.append(f"enclosing branches (outer -> inner, depth={self.depth}):")
            out.extend("  " + r.render() for r in self.guards)
        if self.loops:
            out.append("loops in this function:")
            out.extend("  " + r.render() for r in self.loops)
        if self.early_returns:
            out.append("earlier early returns:")
            out.extend("  " + r.render() for r in self.early_returns)
        if self.truncated:
            out.append("(list truncated)")
        return "\n".join(out)


@dataclass
class Evidence:
    """一个 pair 的视图证据集合。"""

    df: DFEvidence
    cf: CFEvidence
    scope: str = "function"  # "function" | "file"（片段不是合法 C 时退化为整片段）

    def render(self, view: str) -> str:
        body = self.df.render() if view == "data_flow" else self.cf.render()
        if self.scope == "file" and body:
            # 片段不是合法 C（宏 / 残缺签名）时无法确定函数边界，证据退化为整片段
            body = "scope: whole snippet (function boundary not recoverable)\n" + body
        return body

    def cache_key_part(self) -> str:
        """参与缓存键的稳定摘要（证据变则缓存失效）。"""
        df = "|".join(r.render() for r in [self.df.change_stmt, *self.df.defs, *self.df.calls])
        cf = "|".join(r.render() for r in [*self.cf.guards, *self.cf.early_returns])
        return f"{df}##{cf}"


# ---------------------------------------------------------------------------
# tree-sitter 装载与遍历
# ---------------------------------------------------------------------------
def _load_language() -> Optional[Any]:
    """加载 C/C++ grammar；失败返回 ``None``（整体降级为"无证据"）。"""
    try:
        from tree_sitter import Language  # type: ignore
        import tree_sitter_cpp  # type: ignore

        return Language(tree_sitter_cpp.language())
    except Exception:  # pragma: no cover - 依赖缺失/版本不匹配
        return None


_LANGUAGE = _load_language()


def _iter_nodes(node: Any) -> Iterable[Any]:
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        stack.extend(reversed(getattr(cur, "children", None) or []))


def _text(node: Any) -> str:
    raw = getattr(node, "text", b"") or b""
    return raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)


def _start_line(node: Any) -> int:
    return int(node.start_point[0]) + 1


def _end_line(node: Any) -> int:
    return int(node.end_point[0]) + 1


def _covers(node: Any, line: int) -> bool:
    return _start_line(node) <= line <= _end_line(node)


def _span(node: Any) -> int:
    return _end_line(node) - _start_line(node)


def _line_ref(src_lines: list[str], node: Any) -> LineRef:
    line = _start_line(node)
    code = src_lines[line - 1] if 0 <= line - 1 < len(src_lines) else _text(node)
    return LineRef(line=line, code=code)


def _declarator_name(node: Any) -> Optional[str]:
    """从 ``declaration`` / ``parameter_declaration`` 里取声明名。"""
    for field_name in ("declarator",):
        cur = node.child_by_field_name(field_name)
        for _ in range(16):
            if cur is None:
                break
            if cur.type in ("identifier", "field_identifier", "qualified_identifier"):
                return _text(cur)
            nxt = cur.child_by_field_name("declarator")
            if nxt is None:
                # 兜底：declarator 内部第一个 identifier（数组 / 指针 / 函数声明符）
                for sub in _iter_nodes(cur):
                    if sub.type in ("identifier", "field_identifier"):
                        return _text(sub)
                break
            cur = nxt
    return None


def _call_name(node: Any) -> str:
    fn = node.child_by_field_name("function")
    if fn is None:
        return ""
    return " ".join(_text(fn).split())


def find_function(root: Any, line: int) -> Optional[Any]:
    """取覆盖该行的**最内层**函数定义。"""
    best = None
    for node in _iter_nodes(root):
        if node.type != "function_definition":
            continue
        if _covers(node, line) and (best is None or _span(node) < _span(best)):
            best = node
    return best


def find_scope(root: Any, line: int) -> tuple[Optional[Any], str]:
    """搜索范围：优先宿主函数，退化为整片段。

    数据集中有少量片段不是合法 C（宏污染、签名被裁掉，实测 30/306 段无法定位
    函数边界），此时``function_definition`` 不存在；直接放弃会让这些样本失去证据，
    所以退化为 ``translation_unit``，并用 ``scope="file"`` 如实标注。
    """
    func = find_function(root, line)
    if func is not None:
        return func, "function"
    if _covers(root, line) or _span(root) >= 1:
        return root, "file"
    return None, "file"


def _statement_on_line(func: Any, line: int) -> Optional[Any]:
    """改动行所在的**最小**语句节点。"""
    best = None
    for node in _iter_nodes(func):
        if node.type not in _STATEMENT_TYPES:
            continue
        if not _covers(node, line):
            continue
        if best is None or _span(node) < _span(best):
            best = node
    return best


def _inside_parameter_list(node: Any) -> bool:
    """该节点是否落在函数形参表里（形参由 ``params`` 单独承载，不进 ``defs``）。"""
    cur = getattr(node, "parent", None)
    for _ in range(32):
        if cur is None:
            return False
        if cur.type in ("parameter_list", "function_declarator"):
            return True
        cur = getattr(cur, "parent", None)
    return False


def _collect_defs(func: Any, src_lines: list[str]) -> dict[str, list[LineRef]]:
    """函数体内 名字 → 定义/赋值行（形参表与本函数自身的声明符不计入）。"""
    table: dict[str, list[LineRef]] = {}
    for node in _iter_nodes(func):
        if node.type == "declaration":
            if _inside_parameter_list(node):
                continue
            name = _declarator_name(node)
            if name:
                table.setdefault(name, []).append(_line_ref(src_lines, node))
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            if left is None:
                continue
            for sub in _iter_nodes(left):
                if sub.type in ("identifier", "field_identifier"):
                    table.setdefault(_text(sub), []).append(_line_ref(src_lines, node))
                    break

    # 去重（同一行重复出现的声明/赋值只留一条）
    for name, refs in table.items():
        seen: set[tuple[int, str]] = set()
        unique: list[LineRef] = []
        for ref in refs:
            key = (ref.line, ref.code.strip())
            if key in seen:
                continue
            seen.add(key)
            unique.append(ref)
        table[name] = unique
    return table


def _params(func: Any) -> list[str]:
    names: list[str] = []
    for node in _iter_nodes(func):
        if node.type == "parameter_declaration":
            name = _declarator_name(node)
            if name:
                names.append(name)
    return names


def _identifiers(node: Any) -> list[str]:
    seen: list[str] = []
    for sub in _iter_nodes(node):
        if sub.type in ("identifier", "field_identifier"):
            tok = _text(sub)
            if tok and tok not in seen:
                seen.append(tok)
    return seen


# ---------------------------------------------------------------------------
# 对外入口
# ---------------------------------------------------------------------------
def extract_evidence(
    pair: PairRecord,
    anchor: Anchor,
    *,
    max_df_items: int = DEFAULT_MAX_DF_ITEMS,
    max_cf_items: int = DEFAULT_MAX_CF_ITEMS,
) -> Optional[Evidence]:
    """抽取 DF / CF 证据。解析失败或无宿主函数时返回 ``None``。"""
    if _LANGUAGE is None:  # pragma: no cover - 依赖缺失
        return None

    from tree_sitter import Parser  # type: ignore

    try:
        parser = Parser(_LANGUAGE)
        tree = parser.parse(pair.vul_src.encode("utf-8", "replace"))
    except Exception:  # pragma: no cover
        return None

    root = tree.root_node
    line = anchor.vul_start
    scope_node, scope = find_scope(root, line)
    if scope_node is None:
        return None

    src_lines = pair.vul_lines
    stmt = _statement_on_line(scope_node, line) or scope_node
    df = _build_df(scope_node, stmt, src_lines, max_df_items)
    cf = _build_cf(scope_node, line, src_lines, max_cf_items)
    return Evidence(df=df, cf=cf, scope=scope)


def _build_df(func: Any, stmt: Any, src_lines: list[str], limit: int) -> DFEvidence:
    defs_table = _collect_defs(func, src_lines)
    idents = _identifiers(stmt)
    change_line = _start_line(stmt)

    defs: list[LineRef] = []
    for name in idents:
        cands = defs_table.get(name) or []
        # 最近的定义优先；同距离取靠前的
        cands_sorted = sorted(
            (c for c in cands if c.line <= change_line),
            key=lambda r: (-r.line,),
        )
        if cands_sorted:
            defs.append(cands_sorted[0])
        elif cands:
            defs.append(sorted(cands, key=lambda r: r.line)[0])

    calls: list[LineRef] = []
    for node in _iter_nodes(stmt):
        if node.type == "call_expression":
            name = _call_name(node)
            if name:
                calls.append(LineRef(_start_line(node), name))

    externals: list[LineRef] = []
    for node in _iter_nodes(func):
        if node.type == "call_expression":
            name = _call_name(node).split("(")[0].strip()
            if name in EXTERNAL_APIS:
                externals.append(_line_ref(src_lines, node))

    truncated = False
    if len(defs) > limit:
        defs, truncated = defs[:limit], True

    return DFEvidence(
        change_stmt=_line_ref(src_lines, stmt),
        idents=idents,
        defs=defs,
        calls=calls,
        params=_params(func),
        externals=externals,
        truncated=truncated,
    )


def _build_cf(func: Any, line: int, src_lines: list[str], limit: int) -> CFEvidence:
    guards = [n for n in _iter_nodes(func) if n.type in _GUARD_TYPES and _covers(n, line)]
    # 外层在前：span 大的先出现
    guards.sort(key=lambda n: (-_span(n), _start_line(n)))

    loops = [
        n
        for n in _iter_nodes(func)
        if n.type in ("for_statement", "while_statement", "do_statement")
    ]
    loops.sort(key=_start_line)

    early = [n for n in _iter_nodes(func) if n.type == "return_statement" and _start_line(n) < line]
    early.sort(key=_start_line)

    truncated = False
    if len(guards) > limit:
        guards, truncated = guards[:limit], True
    if len(loops) > limit:
        loops, truncated = loops[:limit], True

    return CFEvidence(
        guards=[_line_ref(src_lines, n) for n in guards],
        early_returns=[_line_ref(src_lines, n) for n in early],
        loops=[_line_ref(src_lines, n) for n in loops],
        depth=len(guards),
        truncated=truncated,
    )


__all__ = [
    "EXTERNAL_APIS",
    "DEFAULT_MAX_DF_ITEMS",
    "DEFAULT_MAX_CF_ITEMS",
    "LineRef",
    "DFEvidence",
    "CFEvidence",
    "Evidence",
    "extract_evidence",
    "find_function",
]
