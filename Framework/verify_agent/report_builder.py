"""最终报告组装与落盘（output/final_report.json）。

从 ``verify_agent/d.py`` 拆出（20 文档 §5.1-2）。逐字段白名单重建的约定保持不变：
``location`` 里那些检测端内部字段（``function_line_start`` / ``line_source`` 等）
不会漏进对外报告，数据结构由 ``schema.FINAL_REPORT_TEMPLATE`` 单点定义。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from observability import log_event
from verify_agent.schema import FINAL_REPORT_TEMPLATE


def build_final_report(file_path: str, verified: List[Dict[str, Any]]) -> Dict[str, Any]:
    """按模板逐字段重建最终报告（丢弃检测端内部字段）。"""
    report: Dict[str, Any] = json.loads(json.dumps(FINAL_REPORT_TEMPLATE))
    report["file"] = file_path
    report["findings"] = []
    for f in verified:
        loc = f.get("location") or {}
        item: Dict[str, Any] = json.loads(json.dumps(FINAL_REPORT_TEMPLATE["findings"][0]))
        item["location"] = {
            "file": loc.get("file", file_path) or file_path,
            "line_start": loc.get("line_start", 0),
            "line_end": loc.get("line_end", 0),
            "function": loc.get("function", ""),
        }
        item["taint_chain"] = f.get("taint_chain") or f.get("propagation_path") or []
        item["verification_status"] = f.get("verification_status", "uncertain")
        item["verdict"] = f.get("verdict") or "uncertain"
        item["confidence"] = round(float(f.get("confidence", 0.0) or 0.0), 4)
        item["fix_suggestion"] = f.get("fix_suggestion") or f.get("suggestion", "")
        # 核验证据：缺失时（旧数据 / 未经核验）也保持结构完整，不输出 null
        ev = f.get("evidence") or {}
        item["evidence"] = {
            "path_status": ev.get("path_status", "") or "",
            "path": ev.get("path") or [],
            "conditions": ev.get("conditions") or [],
            "blockers": ev.get("blockers") or [],
            "used_tools": ev.get("used_tools") or [],
        }
        report["findings"].append(item)
    return report


def write_output(final: Dict[str, Any], path: Path) -> None:
    """落盘最终报告（纯 JSON，不输出 markdown / SARIF / 可读摘要）。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(final, fh, ensure_ascii=False, indent=2)
    log_event("output.written", path=str(path))
