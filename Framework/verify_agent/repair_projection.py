"""修复端输入投影（``repair-input/1``）的构建、落盘与自检。

从 ``verify_agent/d.py`` 拆出（20 文档 §5.1-2）。依据
``change_process/summery/修复端_输入需求与用途_2026-10-23_现状.md`` §4：

修复端 C1/C4 的唯一代码输入是「目标函数全文」，它没有文件系统访问权，
所以这一段必须在检测端切好、切准、切得和工程里那份文件一致。
另写一份文件而不改 ``final_report.json``：后者是「检测结论」的稳定产物，
已有下游（ledger / view / 报告统计），两边演进互不阻塞。
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from observability import log_event
from tools.call_context import function_body_source
from verify_agent.location import as_int

REPAIR_SCHEMA = "repair-input/1"
REPAIR_VERDICTS = ("accept", "uncertain", "challenge", "reject")
_CWE_PATTERN = re.compile(r"CWE[-_ ]?\s*(\d+)", re.IGNORECASE)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_cwe(raw: Any) -> str:
    """归一为 ``^CWE-\\d+$`` 规范串；抽不出来返回空串。

    修复端 C3 的第一道操作是 CWE 硬过滤（``cwe_key(d.cwe) == cwe_key(target)``），
    CWE 写歪 = 检索结果恒为空集。A/B/C 实测会给 ``"CWE-787 越界写"`` 这类变体，
    所以必须收窄到规范串；抽不出来就置空，让校验把该 case 挡在 accept 档外。
    """
    match = _CWE_PATTERN.search(str(raw or ""))
    return f"CWE-{int(match.group(1))}" if match else ""


def is_absolute_path(value: str) -> bool:
    text = str(value or "")
    return bool(text) and (os.path.isabs(text) or re.match(r"^[A-Za-z]:[\\/]", text) is not None)


def safe_id(text: Any) -> str:
    """把任意文本压成可用作目录名的片段。"""
    cleaned = re.sub(r"[^0-9A-Za-z._-]+", "_", str(text or "")).strip("._-")
    return cleaned or "case"


def source_meta(state: Dict[str, Any], file_path: str) -> Dict[str, Any]:
    """组装 ``source``：仓库相对路径优先（跨机器可复现），绝对路径降级但会被校验拦下。"""
    rel = str(state.get("rel_file") or "").strip().replace("\\", "/")
    scan = str(file_path or "")
    return {
        "repo": str(state.get("repo") or ""),
        "commit": str(state.get("commit") or ""),
        "file": rel or scan.replace("\\", "/"),
        "scan_file": scan,
    }


def unique_case_id(
    case_id: str,
    finding: Dict[str, Any],
    source: Dict[str, Any],
    line: int,
    used: set,
) -> str:
    """确定 case 目录名：优先用调用方给的 ``case_id``，否则按「文件名__函数__行号」生成。"""
    base = safe_id(case_id) if str(case_id or "").strip() else ""
    if not base:
        loc = finding.get("location") or {}
        func = str(loc.get("function") or "unknown")
        stem = os.path.splitext(os.path.basename(str(source.get("file") or "")))[0]
        base = "__".join([safe_id(stem or "case"), safe_id(func), f"L{line or 0}"])
    candidate = base
    seq = 2
    while candidate in used:
        candidate = f"{base}__{seq}"
        seq += 1
    used.add(candidate)
    return candidate


def build_repair_input(
    verified: List[Dict[str, Any]],
    file_path: str,
    state: Dict[str, Any],
    report_file: str = "output/final_report.json",
) -> Dict[str, Any]:
    """构建面向修复端的输入投影（``repair-input/1``）。

    每个 case 按设计稿 §4 的形状给出 ``case_id / source / vuln / code / evidence``，
    并额外附两个**增量**字段（下游可忽略、检测端自检用）：

    * ``code.line_source`` / ``code.function_resolved_by``：这行 / 这个函数名是
      语法树给的（``ast``）还是照抄 LLM 的（``llm``）；
    * ``validation``：检测端先跑一遍 §4 的六条校验。``ok=False`` 的 case 修复端
      应记 ``invalid_baseline``、不进 Repair Rate 分母（不是"没修好"）。

    ``code.func_src`` 按原文件字节整段切出（含签名与花括号），因此
    ``body_line_start/end`` 与它的行数天然自洽；断不截，超长函数由修复端自己切窗口。
    """
    code = str(state.get("code") or "")
    source = source_meta(state, file_path)
    default_case_id = str(state.get("case_id") or "")
    generated_at = now_iso()
    used_ids: set = set()
    cases: List[Dict[str, Any]] = []

    for index, finding in enumerate(verified):
        loc = finding.get("location") or {}
        line = as_int(loc.get("line_start"))
        line_end = as_int(loc.get("line_end")) or line
        fn_start = as_int(loc.get("function_line_start"))
        fn_end = as_int(loc.get("function_line_end"))
        evidence = finding.get("evidence") or {}

        case_id = default_case_id
        if default_case_id and len(verified) > 1:
            case_id = f"{default_case_id}__f{index + 1}"

        cases.append(
            {
                "case_id": unique_case_id(case_id, finding, source, line, used_ids),
                "source": dict(source),
                "vuln": {
                    "cwe": normalize_cwe(finding.get("cwe")),
                    "line": line,
                    "line_end": line_end,
                    "func": str(loc.get("function") or ""),
                    "confidence": round(float(finding.get("confidence", 0.0) or 0.0), 4),
                    "verdict": str(finding.get("verdict") or "uncertain"),
                },
                "code": {
                    "func_src": function_body_source(code, fn_start, fn_end),
                    "body_line_start": fn_start,
                    "body_line_end": fn_end,
                    "truncated": False,
                    # D5：行号基准必须显式声明，否则修复端只能猜。
                    # ``function`` = 传入的代码是切片、行号从 1 起（``--slice-start`` 生效时）；
                    # ``file``     = 传入的是真实文件、行号是文件绝对行号。
                    "line_base": str(state.get("line_base") or "file"),
                    "line_source": str(loc.get("line_source") or "llm"),
                    "function_resolved_by": str(loc.get("function_resolved_by") or "llm"),
                },
                "evidence": {
                    "path_status": str(evidence.get("path_status") or ""),
                    "path": evidence.get("path") or [],
                    "conditions": evidence.get("conditions") or [],
                    "blockers": evidence.get("blockers") or [],
                },
                "provenance": {
                    "detector": "A/B/C+D",
                    "report_file": report_file,
                    "generated_at": generated_at,
                },
            }
        )

    for case in cases:
        errors = validate_repair_case(case)
        case["validation"] = {"ok": not errors, "errors": errors}

    return {
        "schema": REPAIR_SCHEMA,
        "generated_at": generated_at,
        "provenance": {
            "detector": "A/B/C+D",
            "report_file": report_file,
            "case_count": len(cases),
            "invalid_count": sum(1 for c in cases if not c["validation"]["ok"]),
        },
        "cases": cases,
    }


def validate_repair_case(case: Dict[str, Any]) -> List[str]:
    """设计稿 §4 的六条校验（第 5 条的「case_id 批次内唯一」在构建时已保证）。

    返回错误列表；空列表 = 这条可以直接交给修复端。
    """
    errors: List[str] = []
    vuln = case.get("vuln") or {}
    code = case.get("code") or {}
    source = case.get("source") or {}

    cwe = str(vuln.get("cwe") or "")
    if re.fullmatch(r"CWE-\d+", cwe) is None:
        errors.append(f"vuln.cwe 不是规范串: {cwe!r}")

    if str(vuln.get("verdict") or "") not in REPAIR_VERDICTS:
        errors.append(f"vuln.verdict 非法: {vuln.get('verdict')!r}")

    if not str(case.get("case_id") or ""):
        errors.append("case_id 为空")
    if is_absolute_path(str(source.get("file") or "")):
        errors.append("source.file 是绝对路径（应为仓库相对路径，否则跨机器无法复现）")

    src = str(code.get("func_src") or "")
    start = as_int(code.get("body_line_start"))
    end = as_int(code.get("body_line_end"))
    if not src:
        # 后续四条都建立在 func_src 之上，缺了就没有继续核的必要
        errors.append("code.func_src 为空（未能按行号定位函数）")
        return errors

    lines = src.splitlines()
    if end < start or len(lines) != end - start + 1:
        errors.append(
            f"func_src 行数 {len(lines)} != body_line_end-body_line_start+1 ({end - start + 1})"
        )

    line = as_int(vuln.get("line"))
    if not (start <= line <= end):
        errors.append(f"vuln.line {line} 落在函数范围 [{start}, {end}] 之外")
    elif not (0 <= line - start < len(lines)):
        # func_src 行数与行范围不一致时，偏移量可能越界（上面的行数检查已记过）
        errors.append("vuln.line 在 func_src 内取不到对应行")
    else:
        text = lines[line - start].strip()
        if not text:
            errors.append("vuln.line 指向空行")
        elif text in ("{", "}", "};"):
            errors.append("vuln.line 指向花括号行，不是语句")

    return errors


def write_repair_input(payload: Dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    cases = payload.get("cases") or []
    log_event(
        "repair_input.written",
        path=str(path),
        cases=len(cases),
        invalid=sum(1 for c in cases if not (c.get("validation") or {}).get("ok")),
    )
