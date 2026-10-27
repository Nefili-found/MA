#!/usr/bin/env python3
"""build_repair_eval_cases.py

把 APPATCH 包里的两个**评测集**（不参与建库）规范化成修复端可直接消费的 case 索引：

    other fix framework/datasets/extractfix_dataset/    24 对（平铺文件）
    other fix framework/datasets/zeroday_repair/        97 对（一目录一对）

产出 ``test_data/repair_eval_cases.jsonl``：一行一个 case，只存**指针与记账**，
不复制 C 源码（源码留在被 .gitignore 忽略的 ``other fix framework/`` 里）。

设计约束
--------
* **不复制数据**：两个评测集加起来只有 0.4 MB，但复制就会和原始包漂移；
  这里只产索引，消费方按 ``vul_file`` / ``fixed_file`` 读盘。
* **行号口径必须显式**：两个数据集的文件都是「切片重编号」（第 1 行 = 原文件
  ``slice_start`` 行），所以名字里的 ``vuln_line`` 是**原文件绝对行号**，
  切片内行号 = ``vuln_line - slice_start + 1``。索引同时存两者，消费方不用再猜。
  这与知识库产物 ``anchors`` 的 ``evidence_scope=function`` 同源，故
  ``line_base`` 一律记为 ``function``（``body_line_start`` 恒为 1，禁止用于 R3）。
* **自检不自欺**：只要有一条 ``切片行数 != slice_end - slice_start + 1``，
  就说明该数据集的切片口径变了，直接报错退出，不产出半真索引。
* 与建库语料（patchdb_cvefixes_for_appatch_train）**互斥**：这两个集是 APPATCH
  的评测集，正是用来做 held-out 评估的，绝不能混进 KB。

用法::

    .venv\\Scripts\\python.exe test_data/build_repair_eval_cases.py
    .venv\\Scripts\\python.exe test_data/build_repair_eval_cases.py --check   # 只核对，不写盘
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kbcore.pairs import KNOWN_CWES  # noqa: E402  （单一白名单来源，不另抄一份）

DEFAULT_ROOTS = {
    "extractfix": ROOT / "other fix framework" / "datasets" / "extractfix_dataset",
    "zeroday": ROOT / "other fix framework" / "datasets" / "zeroday_repair",
}
DEFAULT_OUT = Path(__file__).resolve().parent / "repair_eval_cases.jsonl"

CWE_RE = re.compile(r"^CWE-\d+$")
RANGE_RE = re.compile(r"^(\d+)-(\d+)$")


@dataclass
class EvalCase:
    case_id: str
    eval_set: str
    cwe: str
    target: str
    file: str
    slice_start: int
    slice_end: int
    vuln_line_abs: int
    vul_file: Path
    fixed_file: Path
    notes: list = field(default_factory=list)

    @property
    def vuln_line_local(self) -> int:
        """切片内行号（文件第 1 行 = 原文件第 ``slice_start`` 行）。"""
        return self.vuln_line_abs - self.slice_start + 1

    def as_dict(self) -> dict:
        vul_src = _read(self.vul_file)
        fixed_src = _read(self.fixed_file)
        lines = vul_src.splitlines()
        local = self.vuln_line_local
        anchor = lines[local - 1].strip() if 0 <= local - 1 < len(lines) else ""
        return {
            "case_id": self.case_id,
            "eval_set": self.eval_set,
            "cwe": self.cwe,
            "target": self.target,
            "file": self.file,
            "slice": [self.slice_start, self.slice_end],
            "vuln_line_abs": self.vuln_line_abs,
            "vuln_line_local": local,
            "line_base": "function",
            "body_line_start": 1,
            "body_line_end": len(lines),
            "anchor_text": anchor,
            "anchor_ok": not any(n.startswith("anchor_") for n in self.notes),
            "vul_file": _rel(self.vul_file),
            "fixed_file": _rel(self.fixed_file),
            "vul_sha256": _sha256(vul_src),
            "fixed_sha256": _sha256(fixed_src),
            "vul_lines": len(lines),
            "fixed_lines": len(fixed_src.splitlines()),
            "notes": self.notes,
        }


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8", "replace")


def _rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:  # pragma: no cover - 数据源被移到仓库外
        return str(path)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _safe(text: str) -> str:
    cleaned = re.sub(r"[^0-9A-Za-z._-]+", "_", text).strip("._-")
    return cleaned or "x"


def _parse_stem(stem: str) -> dict:
    """``CWE-125___target[___path…]___start-end___vulnline`` → 各字段。"""
    parts = [p for p in stem.split("___") if p]
    if len(parts) < 4:
        raise ValueError(f"文件名段数不足（需要 ≥4）：{stem!r}")
    cwe = parts[0].strip()
    if not CWE_RE.match(cwe):
        raise ValueError(f"首段不是 CWE 规范串：{parts[0]!r}（{stem!r}）")
    target = parts[1].strip()
    rng = parts[-2].strip()
    tail = parts[-1].strip()
    mid = parts[2:-2]

    m = RANGE_RE.match(rng)
    if not m:
        raise ValueError(f"倒数第二段不是 start-end：{rng!r}（{stem!r}）")
    start, end = int(m.group(1)), int(m.group(2))

    # 末段形如 ``1236.c``（可再带 ``_vul.c`` / ``_nonvul.c`` 后缀，已被调用方剥掉）
    line_txt = tail.rsplit(".", 1)[0] if "." in tail else tail
    if not line_txt.isdigit():
        raise ValueError(f"末段取不到 vuln 行号：{tail!r}（{stem!r}）")
    vuln_line = int(line_txt)

    return {
        "cwe": cwe,
        "target": target,
        "file": "/".join(mid) if mid else "",
        "slice_start": start,
        "slice_end": end,
        "vuln_line_abs": vuln_line,
    }


def iter_extractfix(root: Path) -> Iterable[EvalCase]:
    """平铺布局：``<stem>_vul.c`` 与 ``<stem>_nonvul.c`` 同目录。"""
    vul_files = {p.name[: -len("_vul.c")]: p for p in sorted(root.glob("*_vul.c"))}
    non_files = {p.name[: -len("_nonvul.c")]: p for p in sorted(root.glob("*_nonvul.c"))}
    only_vul = sorted(set(vul_files) - set(non_files))
    only_non = sorted(set(non_files) - set(vul_files))
    if only_vul or only_non:
        raise ValueError(
            f"extractfix 有成对缺失：只有 vul {only_vul[:3]}；只有 nonvul {only_non[:3]}"
        )

    for stem in sorted(vul_files):
        meta = _parse_stem(stem)
        yield EvalCase(
            case_id="__".join(
                [
                    "extractfix",
                    _safe(meta["cwe"]),
                    _safe(meta["target"]),
                    _safe(meta["file"] or "unknown"),
                    f"L{meta['vuln_line_abs']}",
                ]
            ),
            eval_set="extractfix",
            vul_file=vul_files[stem],
            fixed_file=non_files[stem],
            **meta,
        )


def iter_zeroday(root: Path) -> Iterable[EvalCase]:
    """目录布局：``<目录名>/vul.c`` 与 ``<目录名>/nonvul.c``。"""
    for entry in sorted(p for p in root.iterdir() if p.is_dir()):
        vul_file, fixed_file = entry / "vul.c", entry / "nonvul.c"
        if not vul_file.is_file() or not fixed_file.is_file():
            raise ValueError(f"zeroday 目录缺 vul.c / nonvul.c：{entry.name}")
        meta = _parse_stem(entry.name)
        yield EvalCase(
            case_id="__".join(
                [
                    "zeroday",
                    _safe(meta["cwe"]),
                    _safe(meta["target"]),
                    f"L{meta['vuln_line_abs']}",
                ]
            ),
            eval_set="zeroday",
            vul_file=vul_file,
            fixed_file=fixed_file,
            **meta,
        )


def inspect_case(case: EvalCase) -> tuple:
    """单 case 自检 → ``(errors, notes)``。

    **硬错误**（结构坏了，整批中止）只有四种：CWE 未登记、文件为空、
    vul 与 nonvul 完全相同（上游没给修复）、切片行数与 ``slice_end-slice_start+1`` 不符。

    **软记账**（``notes``）是上游数据本身的问题，不中止：APPATCH 的 zeroday 集里有
    2 条 ``vuln line = 0``（未记录）和 15 条把漏洞行标在函数体开括号或空行上。
    这些 case 保留，由消费方（``repair/intake.py``）按 ``anchor_ok=false`` 判
    ``invalid_baseline``——不在这里替它做决定，也不假装数据是干净的。
    """
    errors: list = []
    notes: list = []
    if case.cwe not in KNOWN_CWES:
        errors.append(f"{case.case_id}: 未登记的 CWE {case.cwe}")
    vul_src = _read(case.vul_file)
    fixed_src = _read(case.fixed_file)
    if not vul_src.strip():
        errors.append(f"{case.case_id}: vul 文件为空")
    if not fixed_src.strip():
        errors.append(f"{case.case_id}: nonvul 文件为空")
    if vul_src == fixed_src:
        errors.append(f"{case.case_id}: vul 与 nonvul 内容完全相同（无修复信息）")

    lines = vul_src.splitlines()
    expected = case.slice_end - case.slice_start + 1
    if len(lines) != expected:
        errors.append(
            f"{case.case_id}: 切片行数 {len(lines)} != slice_end-slice_start+1 ({expected})"
            " —— 切片口径可能变了"
        )

    local = case.vuln_line_local
    if case.vuln_line_abs <= 0:
        notes.append("anchor_missing: 上游未记录漏洞行号（vuln line = 0）")
    elif not (1 <= local <= len(lines)):
        notes.append(f"anchor_out_of_range: local={local}, lines={len(lines)}")
    else:
        text = lines[local - 1].strip()
        if not text:
            notes.append("anchor_blank: 漏洞行是空行")
        elif text in ("{", "}", "};"):
            notes.append("anchor_brace: 漏洞行是花括号，不是语句")
    return errors, notes


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--extractfix", default=str(DEFAULT_ROOTS["extractfix"]))
    parser.add_argument("--zeroday", default=str(DEFAULT_ROOTS["zeroday"]))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--check", action="store_true", help="只核对，不写盘")
    args = parser.parse_args(argv)

    cases: list = []
    for label, root in (("extractfix", Path(args.extractfix)), ("zeroday", Path(args.zeroday))):
        if not root.is_dir():
            print(f"!! 缺数据集目录：{root}", file=sys.stderr)
            return 2
        cases.extend(iter_extractfix(root) if label == "extractfix" else iter_zeroday(root))

    errors: list = []
    by_id: dict = {}
    for case in cases:
        dup = by_id.setdefault(case.case_id, case)
        if dup is not case:
            errors.append(f"case_id 重复：{case.case_id}（{dup.vul_file.name} / {case.vul_file.name}）")
        case_errors, case_notes = inspect_case(case)
        errors.extend(case_errors)
        case.notes.extend(case_notes)

    records = [case.as_dict() for case in cases]

    # ---- 汇总 ----
    print(f"cases        : {len(records)}")
    for label in ("extractfix", "zeroday"):
        subset = [r for r in records if r["eval_set"] == label]
        print(f"  {label:11}: {len(subset)}")
    hist: dict = {}
    for r in records:
        hist[r["cwe"]] = hist.get(r["cwe"], 0) + 1
    print(f"cwe          : {dict(sorted(hist.items()))}")
    print(f"lines(range) : {min(r['vul_lines'] for r in records)}-{max(r['vul_lines'] for r in records)}")
    flagged = [r for r in records if not r["anchor_ok"]]
    print(f"anchor_ok    : {len(records) - len(flagged)}/{len(records)}（{len(flagged)} 条上游未记录有效漏洞行）")

    if errors:
        print(f"\n!! {len(errors)} 条自检失败：", file=sys.stderr)
        for item in errors[:20]:
            print(f"   - {item}", file=sys.stderr)
        if len(errors) > 20:
            print(f"   … 另有 {len(errors) - 20} 条", file=sys.stderr)
        return 1

    if args.check:
        print("\n--check：自检通过，未写盘")
        return 0

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n", encoding="utf-8"
    )
    print(f"\nwrote        : {out} ({len(records)} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
