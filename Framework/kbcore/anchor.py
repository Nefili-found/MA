"""漏洞行定位（确定性，无 LLM）。

对应设计文档 `知识库_双视图抽取与存储_代码方案_设计.md` §5.2。

**为什么不用数据集里现成的 ``.diff``**（§1.4 实测）：

* 它是**模式级对齐**（0 处 ``@@``），节点词表是 ``decl_stmt`` / ``block_content`` 这类
  Joern C 前端词表，不是文本 diff；
* 偏移量落在**修复后文件**的坐标上：103 对有 10 对的最大偏移超过 ``_vul.c``
  字节长度但落在 ``_nonvul.c`` 内（如 169 > 168 ≤ 171）。直接当 vul 行号用会错位；
* 只有 103/306 对带该工件，CWE-401 一对都没有。

所以主路径是 ``difflib``：实测 306 对**每对恰有一个非 equal opcode**，
漏洞行可以完全确定性推导；``.diff`` 只降级为旁证（:func:`crosscheck_with_ast`）。
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .pairs import PairRecord

Confidence = Literal["high", "low"]
Kind = Literal["replace", "insert_only", "delete_only"]

# ratio 低于该值说明两版差异过大，定位结果只作参考（§1.3 实测最小 0.667）
HIGH_CONFIDENCE_RATIO = 0.85

# 旁证比对允许的行偏移
CROSSCHECK_TOLERANCE = 3

# .diff 里的"改动"段类型（其余是 match）
_CHANGE_KINDS = frozenset(
    {"insert-node", "delete-node", "update-node", "insert-tree", "delete-tree", "move-tree"}
)

_RANGE_RE = re.compile(r"\[(\d+),(\d+)\]")


@dataclass(frozen=True)
class Anchor:
    """改动区域。行号 1-based、闭区间。"""

    vul_start: int
    vul_end: int
    new_start: int
    new_end: int
    kind: Kind
    ratio: float
    confidence: Confidence
    extra_ops: int = 0  # 除首个改动外的额外 opcode 数（实测恒为 0）

    @property
    def vul_lines(self) -> tuple[int, int]:
        return (self.vul_start, self.vul_end)

    @property
    def new_lines(self) -> tuple[int, int]:
        return (self.new_start, self.new_end)

    def as_dict(self) -> dict:
        return {
            "vul_lines": [self.vul_start, self.vul_end],
            "new_lines": [self.new_start, self.new_end],
            "kind": self.kind,
            "confidence": self.confidence,
            "ratio": round(self.ratio, 4),
            "extra_ops": self.extra_ops,
        }


def locate(pair: PairRecord) -> Anchor:
    """用 ``difflib`` 定位改动区域。

    边界处理：
    * ``insert_only``（vul 侧为空）：取插入点两侧相邻行，供 tree-sitter 找宿主语句；
    * ``delete_only``（修复侧为空）：vul 侧就是被删区间；
    * 多个改动段：取第一段，``extra_ops`` 记录多出来的段数（实测为 0，出现即为数据异常）。
    """
    a = pair.vul_lines
    b = pair.non_lines
    if not a or not b:
        raise ValueError(f"{pair.pair_id}: 空片段无法定位")

    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    ops = [op for op in sm.get_opcodes() if op[0] != "equal"]
    if not ops:
        raise ValueError(f"{pair.pair_id}: vul 与 nonvul 完全相同，无改动区域")

    tag, i1, i2, j1, j2 = ops[0]

    if tag == "replace":
        kind: Kind = "replace"
        vul_start, vul_end = i1 + 1, max(i2, i1 + 1)
        new_start, new_end = j1 + 1, max(j2, j1 + 1)
    elif tag == "insert":
        kind = "insert_only"
        # vul 侧没有对应行：取插入点两侧各一行（clamp 到 1..len(a)）
        vul_start = max(1, min(i1, len(a)))
        vul_end = max(vul_start, min(i1 + 1, len(a)))
        new_start, new_end = j1 + 1, max(j2, j1 + 1)
    else:  # delete
        kind = "delete_only"
        vul_start, vul_end = i1 + 1, max(i2, i1 + 1)
        new_start = max(1, min(j1, len(b)))
        new_end = max(new_start, min(j1 + 1, len(b)))

    ratio = sm.ratio()
    return Anchor(
        vul_start=vul_start,
        vul_end=vul_end,
        new_start=new_start,
        new_end=new_end,
        kind=kind,
        ratio=ratio,
        confidence="high" if ratio >= HIGH_CONFIDENCE_RATIO else "low",
        extra_ops=max(0, len(ops) - 1),
    )


# ---------------------------------------------------------------------------
# 旁证：用数据集里的模式级 .diff 交叉校验（仅 103 对可用）
# ---------------------------------------------------------------------------
def _line_at_offset(src: str, offset: int) -> int:
    """字节偏移 → 1-based 行号（``src`` 与数据一致按 utf-8 解码）。"""
    if offset <= 0:
        return 1
    return src.count("\n", 0, min(offset, len(src))) + 1


def _changed_offsets(diff_text: str) -> list[tuple[int, int]]:
    """从 .diff 抽出改动段的偏移区间（修复侧坐标，见模块 docstring）。"""
    out: list[tuple[int, int]] = []
    for seg in diff_text.split("==="):
        body = seg.strip()
        if not body:
            continue
        lines = [ln for ln in body.splitlines() if ln.strip()]
        if not lines or lines[0].strip() not in _CHANGE_KINDS:
            continue
        for ln in lines[1:]:
            for m in _RANGE_RE.finditer(ln):
                start, end = int(m.group(1)), int(m.group(2))
                if end > start:
                    out.append((start, end))
    return out


def crosscheck_with_ast(pair: PairRecord, anchor: Anchor) -> bool | None:
    """用 ``.diff`` 的改动节点校验 anchor。

    :return: ``True`` 命中（改动节点落在 anchor 的修复侧区间 ± ``CROSSCHECK_TOLERANCE`` 行内）；
             ``False`` 未命中；``None`` 该对无工件或工件无改动段。
    """
    diff_path: Path | None = pair.artifacts.get("diff")
    if diff_path is None or not diff_path.exists():
        return None

    offsets = _changed_offsets(diff_path.read_text(encoding="utf-8", errors="replace"))
    if not offsets:
        return None

    lo = max(1, anchor.new_start - CROSSCHECK_TOLERANCE)
    hi = anchor.new_end + CROSSCHECK_TOLERANCE
    for start, _end in offsets:
        line = _line_at_offset(pair.non_src, start)
        if lo <= line <= hi:
            return True
    return False


__all__ = ["Anchor", "HIGH_CONFIDENCE_RATIO", "CROSSCHECK_TOLERANCE", "locate", "crosscheck_with_ast"]
