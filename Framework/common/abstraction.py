"""实现无关性检查（`root_cause` 不得泄漏具体标识符）。

设计稿 §5.1 的硬约束：知识项的根因描述必须是"实现无关"形式
（"外部长度未与目标缓冲区容量比较即用于拷贝"，而不是"`len` 没和 `buf_size` 比"）。
理由与知识抽象同源：**查询侧不抽象，就检索不到被抽象过的库内内容**。

本模块被两侧共用（见 `change_process/design/知识库_双视图抽取与存储_代码方案_设计.md` §7.2）：

* 知识库侧：`kbcore.abstract` 用它判定条目能否入库；
* 修复端：`patch_gen.query` 需要它判定查询是否要重试。

判定方式是纯词法（不依赖 LLM、可离线单测）：把源码里"长度 ≥ 4 的自由标识符"
抽出来，若出现在根因文本里即判违例。

只作用于 ``root_cause``：``risky_calls``（API 名天然通用）、
``taint_flow`` / ``control_branch``（行为描述，修复端 BM25 要拿它分词）
都**不**做这层检查，否则 IDF 归零、区分度消失。
"""

from __future__ import annotations

import re
from typing import Iterable, Set

# C 关键字（只影响"是不是自由标识符"，不追求完整 C23 词表）
C_KEYWORDS: frozenset[str] = frozenset(
    """
    auto break case char const continue default do double else enum extern float for goto if
    inline int long register restrict return short signed sizeof static struct switch typedef
    union unsigned void volatile while _Bool _Complex _Imaginary alignas alignof bool true false
    nullptr constexpr decltype thread_local
    """.split()
)

# 标准库 / 内置类型白名单：它们出现在根因里是正常的，不算"泄漏实现细节"
STD_WHITELIST: frozenset[str] = frozenset(
    """
    malloc calloc realloc free memcpy memmove memset memcmp strlen strcpy strncpy strcat strncat
    strcmp strncmp strchr strrchr strstr sprintf snprintf vsnprintf vsprintf printf fprintf vfprintf
    puts fputs fgets fputc fgetc getchar putchar scanf sscanf fscanf fopen fclose fread fwrite
    read write recv recvfrom send sendto socket accept bind listen open close lseek ioctl mmap
    atoi atol atoll strtol strtoul strtoll strtod size_t ssize_t ptrdiff_t intptr_t uintptr_t
    NULL EOF stdin stdout stderr offsetof assert abort exit qsort bsearch time rand srand
    """.split()
)

_IDENT_RE = re.compile(r"[A-Za-z_]\w*")

# 常用安全词汇：即便源码里恰好有同名标识符，出现在根因描述里也是正常的。
# 不做这层放行，任何用 size / count 之类词命名的变量都会把 root_cause 判成违例。
PROSE_ALLOWED: frozenset[str] = frozenset(
    """
    length size count index buffer data input output offset capacity pointer null value values
    string array loop bound bounds guard check checks range position element elements target
    source sink copy bytes memory allocate allocation validate validation compare comparison
    condition branch reachable reachability user external attacker controlled supplied resulting
    integer overflow underflow dereference ownership reference lifetime release
    error path name file line field record entry item node list object region stream message
    request response handle flag mode type state status level config option args argv argc env
    width height inner outer lower upper next prev head tail root child parent start end first
    last min max total sum temp block chunk page slot frame cycle bit bits
    read write open close send receive parse format encode decode
    errors names files lines records entries items nodes lists objects regions streams messages
    requests responses handles flags modes types states statuses levels options keys key masks mask
    sizes lengths counts indices values cards card words word todo endian size count bytes
    """.split()
)

# 注释与字符串字面量不是标识符：整段抹掉再抽取，否则注释里的英文词会被误判成违例。
# 例：`/* parse cipher length */` 会让 "length" 进违例集合，把正常表述判死。
_NON_CODE_RE = re.compile(
    r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'",
    re.S,
)

# 最短长度：太短的标识符（i / n / c）在自然语言里可能是普通英文词，误判率高
MIN_IDENT_LEN = 4


def strip_non_code(src: str) -> str:
    """去掉注释与字符串字面量（保留代码标识符与结构）。"""
    return _NON_CODE_RE.sub(" ", src or "")


def free_identifiers(src: str, *, include_prose_words: bool = True) -> Set[str]:
    """源码中自由标识符集合：长度 ≥ 4、非 C 关键字、非标准库白名单、非通用安全词。"""
    out: Set[str] = set()
    for m in _IDENT_RE.finditer(strip_non_code(src)):
        tok = m.group(0)
        if len(tok) < MIN_IDENT_LEN:
            continue
        if tok in C_KEYWORDS or tok in STD_WHITELIST:
            continue
        if include_prose_words and tok in PROSE_ALLOWED:
            continue
        out.add(tok)
    return out


def abstraction_violations(text: str, src: str, extra_allowed: Iterable[str] = ()) -> list[str]:
    """返回 ``text`` 里出现的源码标识符（违例列表，已排序、去重）。

    空列表 = 通过。``extra_allowed`` 供调用方临时放行（例如 CWE 名、语言扩展关键字）。
    """
    if not text:
        return []
    idents = free_identifiers(src)
    if extra_allowed:
        idents -= {str(x) for x in extra_allowed}
    hits = [tok for tok in idents if re.search(rf"(?<![A-Za-z0-9_]){re.escape(tok)}(?![A-Za-z0-9_])", text)]
    return sorted(hits)


__all__ = [
    "C_KEYWORDS",
    "STD_WHITELIST",
    "PROSE_ALLOWED",
    "MIN_IDENT_LEN",
    "strip_non_code",
    "free_identifiers",
    "abstraction_violations",
]
