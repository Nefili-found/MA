"""入口层：把外部 case 读成 :class:`repair.schema.RepairCase` 并判定能否进入修复流程。

设计依据：``change_process/summery/修复端_结构重构_2026-10-24_设计.md`` §4.1 / §9。

两类输入
--------
1. ``repair-input/1``（生产路径，检测端 D 投影产出）：``{"schema": …, "cases": [...]}``；
2. 评测集索引（``test_data/repair_eval_cases.jsonl``，由
   ``test_data/build_repair_eval_cases.py`` 生成）：一行一个 held-out case。

两者最终都归一成同一个 ``RepairCase``，下游 ``facts`` / ``query`` / ``retrieve``
不需要知道输入来自哪里。

入口判定顺序（**顺序本身是契约**，不要重排）
-------------------------------------------
1. 检测端自检失败（``validation.ok == false`` 或六条校验不过）→ ``invalid_baseline``
2. ``line_base`` 不合法（D5 / §9）→ ``invalid_baseline``
3. ``cwe`` 抽不出规范串 → ``invalid_baseline``
4. ``verdict`` 不在放行集合里 → ``entry_skipped``
5. 其余 → ``accepted``

``invalid_baseline`` 与 ``entry_skipped`` 都**不进** Repair Rate 分母——它们的含义是
"这条输入就不该拿去修"，不是"没修好"。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .schema import (
    ENTRY_ACCEPTED,
    ENTRY_INVALID,
    ENTRY_SKIPPED,
    Intake,
    RepairCase,
    is_canonical_cwe,
)

ROOT = Path(__file__).resolve().parent.parent

REPAIR_SCHEMA = "repair-input/1"

#: 生产路径的默认放行档位。``uncertain`` 默认不放行（可配），因为 "不确定" 拿去修
#: 会把误报算成修复失败，污染 Repair Rate。
DEFAULT_ACCEPT_VERDICTS: tuple = ("accept",)

#: 缺 ``line_base`` 时的推断值。检测端 ``repair_projection`` 给的
#: ``body_line_start`` 本来就是**真实文件行号**（``function_body_source(code, fn_start, fn_end)``），
#: 所以缺省推断成 ``file`` 是对齐实现的事实判断，不是在猜。
DEFAULT_LINE_BASE = "file"


# ---------------------------------------------------------------- 构造函数


def _read_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_repair_input(
    path: str | Path,
    *,
    default_line_base: str = DEFAULT_LINE_BASE,
) -> Tuple[Dict[str, Any], List[RepairCase]]:
    """读 ``repair-input/1`` 文件 → ``(payload 元信息, cases)``。"""
    payload = _read_json(Path(path))
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: 顶层不是对象")
    schema = str(payload.get("schema") or "")
    if schema != REPAIR_SCHEMA:
        raise ValueError(f"{path}: schema={schema!r}，期望 {REPAIR_SCHEMA!r}")
    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, list):
        raise ValueError(f"{path}: cases 不是数组")

    cases = [
        resolve_line_base(
            RepairCase.from_dict(raw, origin="repair-input/1"), default=default_line_base
        )
        for raw in raw_cases
        if isinstance(raw, dict)
    ]
    meta = {
        "schema": schema,
        "generated_at": payload.get("generated_at", ""),
        "provenance": payload.get("provenance") or {},
        "case_count": len(cases),
    }
    return meta, cases


def load_eval_cases(
    path: str | Path,
    *,
    root: Optional[Path] = None,
) -> List[RepairCase]:
    """读评测集索引（JSONL）→ ``RepairCase`` 列表。

    索引里每行的 ``vul_file`` 是**仓库相对路径**，这里按需读盘。切片文件本身就是
    「切片重编号」的片段（第 1 行 = 原文件 ``slice[0]`` 行），因此一律记
    ``line_base="function"``、``body_line_start=1``，并把 ``vuln.line`` 换成
    **切片内行号** ``vuln_line_local``——这是与检测端 ``file`` 口径的明确区别。

    两处口径来源（不是猜的）：

    * ``verdict="accept"``：这两个集是 APPATCH 的**评测集**，每条都是已确认的漏洞样本，
      数据集标签本身即判定；
    * ``confidence=1.0``：同上，作为 ground truth 记账；它只影响报告排序，不参与门禁。

    ``evidence`` 留空——事实要从检测端的 ``check_assumptions`` / ``check_trigger_path``
    现算（S4 的 ``reverify`` 走这条），入口层不伪造事实。
    """
    base = Path(root) if root is not None else ROOT
    cases: List[RepairCase] = []
    for line_no, line in enumerate(
        Path(path).read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        row = json.loads(line)
        try:
            cases.append(_eval_row_to_case(row, base))
        except OSError as exc:
            raise FileNotFoundError(f"{path}:{line_no} 读不到切片：{exc}") from exc
    return cases


def _eval_row_to_case(row: Dict[str, Any], root: Path) -> RepairCase:
    vul_path = root / str(row["vul_file"])
    func_src = vul_path.read_bytes().decode("utf-8", "replace")
    lines = func_src.splitlines()
    local_line = int(row["vuln_line_local"])

    raw = {
        "case_id": str(row["case_id"]),
        "source": {
            "repo": str(row.get("target") or ""),
            "commit": "",
            "file": str(row.get("file") or f"eval/{row['case_id']}.c"),
        },
        "vuln": {
            "cwe": str(row["cwe"]),
            "line": local_line,
            "line_end": local_line,
            "func": "",
            "confidence": 1.0,
            "verdict": "accept",
        },
        "code": {
            "func_src": func_src,
            "body_line_start": 1,
            "body_line_end": len(lines),
            "line_base": "function",
            "line_source": "dataset",
            "function_resolved_by": "dataset",
        },
        "evidence": {"path_status": "", "path": [], "conditions": [], "blockers": []},
    }
    case = RepairCase.from_dict(raw, origin=str(row.get("eval_set") or "eval"))
    case.eval_meta = {
        "eval_set": row.get("eval_set"),
        "slice": row.get("slice"),
        "vuln_line_abs": row.get("vuln_line_abs"),
        "fixed_file": row.get("fixed_file"),
        "anchor_ok": row.get("anchor_ok"),
    }
    return case


def resolve_line_base(case: RepairCase, *, default: str = DEFAULT_LINE_BASE) -> RepairCase:
    """补齐 ``line_base``：输入带就用输入的，缺了就推断并记账。"""
    if not case.code.line_base:
        case.code.line_base = default
        case.code.line_base_source = "inferred"
    return case


# ---------------------------------------------------------------- 入口判定


def evaluate_entry(
    case: RepairCase,
    *,
    accept_verdicts: Sequence[str] = DEFAULT_ACCEPT_VERDICTS,
) -> Intake:
    """判定单 case 能否进入修复流程；结果同时写回 ``case.intake``。"""
    intake = _evaluate_entry(case, accept_verdicts=accept_verdicts)
    case.intake = intake
    return intake


def _evaluate_entry(case: RepairCase, *, accept_verdicts: Sequence[str]) -> Intake:
    # 1) 检测端自检：优先用透传的 validation，缺了就自己跑一遍
    declared = case.validation or {}
    if declared and declared.get("ok") is False:
        return Intake(False, ENTRY_INVALID, "detection_validation: " + _join(declared.get("errors")))
    detection = case.detection_errors()
    if detection:
        return Intake(False, ENTRY_INVALID, "detection_validation: " + _join(detection))

    # 2) line_base（D5 / §9）
    lb_errors = case.line_base_errors()
    if lb_errors:
        return Intake(False, ENTRY_INVALID, "line_base: " + _join(lb_errors))

    # 3) CWE 必须是规范串（C3 的第一道操作是 CWE 硬过滤，写歪 = 恒空集）
    #    注：``validate_repair_case`` 的第 1 条已经检查了 canonical 形式，所以这一道
    #    在正常路径上是**走不到的**（上面的检测端自检先拦）。保留它是防御性的：入口
    #    将来若改为不跑检测端校验（例如只吃评测集），这一道仍然生效。
    if not is_canonical_cwe(case.vuln.cwe):
        return Intake(False, ENTRY_INVALID, f"cwe_not_canonical: {case.vuln.cwe!r}")

    # 4) verdict 放行
    if case.vuln.verdict not in accept_verdicts:
        return Intake(False, ENTRY_SKIPPED, f"verdict={case.vuln.verdict!r}")

    return Intake(True, ENTRY_ACCEPTED, "")


def gate(
    cases: Iterable[RepairCase],
    *,
    accept_verdicts: Sequence[str] = DEFAULT_ACCEPT_VERDICTS,
    default_line_base: str = DEFAULT_LINE_BASE,
) -> List[RepairCase]:
    """逐个判定入口，返回**全部** case（含未通过的，``intake.kind`` 区分）。"""
    out: List[RepairCase] = []
    for case in cases:
        resolve_line_base(case, default=default_line_base)
        evaluate_entry(case, accept_verdicts=accept_verdicts)
        out.append(case)
    return out


def accepted(cases: Iterable[RepairCase]) -> List[RepairCase]:
    return [c for c in cases if c.intake.accepted]


def summary(cases: Iterable[RepairCase]) -> Dict[str, Any]:
    """入口分档汇总（报告与测试都用它，避免两处各算一套口径）。"""
    cases = list(cases)
    by_kind: Dict[str, int] = {}
    reasons: Dict[str, int] = {}
    by_cwe: Dict[str, int] = {}
    by_origin: Dict[str, int] = {}
    line_bases: Dict[str, int] = {}
    for case in cases:
        by_kind[case.intake.kind] = by_kind.get(case.intake.kind, 0) + 1
        if case.intake.reason:
            key = case.intake.reason.split(":", 1)[0]
            reasons[key] = reasons.get(key, 0) + 1
        by_cwe[case.vuln.cwe or "?"] = by_cwe.get(case.vuln.cwe or "?", 0) + 1
        by_origin[case.origin] = by_origin.get(case.origin, 0) + 1
        key_lb = f"{case.code.line_base}/{case.code.line_base_source or '?'}"
        line_bases[key_lb] = line_bases.get(key_lb, 0) + 1
    return {
        "cases": len(cases),
        "by_kind": dict(sorted(by_kind.items())),
        "by_reason": dict(sorted(reasons.items())),
        "by_cwe": dict(sorted(by_cwe.items())),
        "by_origin": dict(sorted(by_origin.items())),
        "line_base": dict(sorted(line_bases.items())),
        "accepted": sum(1 for c in cases if c.intake.accepted),
    }


def _join(items: Any) -> str:
    if not items:
        return "(未给出明细)"
    if isinstance(items, str):
        return items
    return "; ".join(str(x) for x in items)


__all__ = [
    "REPAIR_SCHEMA",
    "DEFAULT_ACCEPT_VERDICTS",
    "DEFAULT_LINE_BASE",
    "load_repair_input",
    "load_eval_cases",
    "resolve_line_base",
    "evaluate_entry",
    "gate",
    "accepted",
    "summary",
]
