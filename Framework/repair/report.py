"""报告层：把一次 R1 批跑的记录渲染成**人工可判分**的产物。

设计依据：``change_process/summery/修复端_结构重构_2026-10-24_设计.md`` §10 阶段 A。

只产出三种东西，不做任何重算：

* ``cases.jsonl`` —— 每 case 一行，机器可读（含 query、Top-K、终局、失败原因）；
* ``judging.md`` —— 人工判分表，一行一个 **case×命中**，留一列 ``判为同类?`` 给人填；
* ``summary.json`` —— 分项计数，报告与论文表格直接取这里的数。

**刻意不在这里重算指标**：Repair Rate / AvgIter 等都要从 ``cases.jsonl`` 现算，
避免"报告里算一遍、脚本里再算一遍"两套口径。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List


def summarize(records: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """分项计数。空集合也要给出结构（下游表格不该因为 0 条就崩）。"""
    records = list(records)
    finals: Dict[str, int] = {}
    entries: Dict[str, int] = {}
    suff: Dict[str, int] = {}
    by_cwe: Dict[str, int] = {}
    degraded = 0
    reverified = 0
    reverify_improved = 0
    pool_sizes: List[int] = []
    hits_total = 0
    cases_with_hits = 0

    for record in records:
        outcome = record.get("outcome") or {}
        final = str(outcome.get("final") or "")
        finals[final] = finals.get(final, 0) + 1
        kind = str(outcome.get("entry_kind") or "")
        entries[kind] = entries.get(kind, 0) + 1
        key = "ok" if outcome.get("facts_sufficiency") == "ok" else "insufficient"
        suff[key] = suff.get(key, 0) + 1
        cwe = str((record.get("case") or {}).get("vuln", {}).get("cwe") or "?")
        by_cwe[cwe] = by_cwe.get(cwe, 0) + 1
        if outcome.get("query_degraded"):
            degraded += 1
        reverify = outcome.get("reverify") or {}
        if reverify.get("requested"):
            reverified += 1
            if reverify.get("improved"):
                reverify_improved += 1

        n_hits = 0
        for view_result in (record.get("retrieval") or {}).values():
            pool_sizes.append(int(view_result.get("pool_size") or 0))
            n_hits += len(view_result.get("hits") or [])
        hits_total += n_hits
        if n_hits:
            cases_with_hits += 1

    return {
        "cases": len(records),
        "by_final": dict(sorted(finals.items())),
        "by_entry": dict(sorted(entries.items())),
        "sufficiency": dict(sorted(suff.items())),
        "by_cwe": dict(sorted(by_cwe.items())),
        "query_degraded": degraded,
        "reverify_requested": reverified,
        "reverify_improved": reverify_improved,
        "pool_size_avg": round(sum(pool_sizes) / len(pool_sizes), 2) if pool_sizes else 0.0,
        "pool_size_min": min(pool_sizes) if pool_sizes else 0,
        "pool_size_max": max(pool_sizes) if pool_sizes else 0,
        "hits_total": hits_total,
        "cases_with_hits": cases_with_hits,
    }


def render_judging_table(records: Iterable[Dict[str, Any]], *, top_k: int = 4) -> str:
    """人工判分表（Markdown）。一行一个 case×命中，``判为同类?`` 留空给人填。"""
    lines: List[str] = [
        "# R1 检索判分表",
        "",
        "判分口径：**候选的根因是否与目标 case 属于同一类缺陷**（同类 = 修法可迁移）。",
        "``判为同类?`` 列填 ``Y`` / ``N``；每 case 至少 3/4 为 Y 视为该 case 通过。",
        "",
    ]
    for record in records:
        case = record.get("case") or {}
        vuln = case.get("vuln") or {}
        outcome = record.get("outcome") or {}
        query = record.get("query") or {}
        lines.append(f"## {case.get('case_id', '?')}")
        lines.append("")
        lines.append(
            f"- CWE：`{vuln.get('cwe', '')}` ｜ verdict：`{vuln.get('verdict', '')}` ｜ "
            f"line_base：`{(case.get('code') or {}).get('line_base', '')}` ｜ "
            f"终局：`{outcome.get('final', '')}`"
        )
        lines.append(f"- 锚点：`{(case.get('anchor_text') or '')[:110]}`")
        if outcome.get("entry_kind") != "accepted":
            lines.append(f"- 未进入检索：{outcome.get('entry_reason') or outcome.get('entry_kind')}")
            lines.append("")
            continue
        suff = outcome.get("facts_sufficiency_why") or ""
        lines.append(f"- 事实充足性：{suff}")
        reverify = outcome.get("reverify") or {}
        if reverify.get("requested"):
            lines.append(
                f"- 复核：rounds={reverify.get('rounds')} improved={reverify.get('improved')}"
            )
        for view_type, view in (query.get("views") or {}).items():
            root = str(view.get("root_cause") or "").replace("\n", " ")[:160]
            refs = ", ".join(view.get("evidence_refs") or []) or "(无)"
            lines.append(f"- **{view_type}** 查询根因：{root}")
            lines.append(f"  - evidence_refs：`{refs}`")
            if view.get("degraded_reason"):
                lines.append(f"  - ⚠ 降级：{view['degraded_reason']}")
        lines.append("")

        for view_type, view_result in (record.get("retrieval") or {}).items():
            hits = view_result.get("hits") or []
            lines.append(f"### {view_type}（池 {view_result.get('pool_size')} 条）")
            lines.append("")
            if not hits:
                lines.append("_无命中_")
                lines.append("")
                continue
            lines.append("| rank | pair_id | CWE | cos | bm25 | bm25_raw | score | 判为同类? |")
            lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
            for hit in hits[:top_k]:
                lines.append(
                    "| {rank} | `{pair}` | {cwe} | {cos} | {bm25} | {raw} | {score} |  |".format(
                        rank=hit.get("rank"),
                        pair=hit.get("pair_id"),
                        cwe=hit.get("cwe"),
                        cos=hit.get("cos"),
                        bm25=hit.get("bm25"),
                        raw=hit.get("bm25_raw"),
                        score=hit.get("score"),
                    )
                )
            lines.append("")
        lines.append("---")
        lines.append("")
    return "\n".join(lines)


def compare_arms(
    main_records: Iterable[Dict[str, Any]],
    control_records: Iterable[Dict[str, Any]],
    *,
    top_k: int = 4,
) -> Dict[str, Any]:
    """两臂对比：**只度量"变了多少"，不度量"变准了多少"**。

    这一点必须说清：``变准`` 需要人工判同一批候选是否同类，而对照臂的数据是按约定
    **用完即弃**的，没有留下可判分的表。所以这里给的是检索结果集合的差异
    （top-1 是否相同、top-K 交集大小），用来回答"事实注入到底有没有改动检索行为"。
    若交集接近满值，说明事实注入对检索没有影响，后面的判分不必做；若差异明显，
    才值得为对照臂单独跑一次人工判分。

    :param main_records: 主臂（``source=evidence``）记录
    :param control_records: 对照臂（``source=none``）记录，主键对齐用 ``case_id``
    """
    control_by_id = {str(r.get("case", {}).get("case_id")): r for r in control_records}
    rows: List[Dict[str, Any]] = []
    same_top1 = 0
    compared_views = 0
    overlap_total = 0
    main_only = 0
    control_only = 0

    for record in main_records:
        case_id = str(record.get("case", {}).get("case_id"))
        other = control_by_id.get(case_id)
        for view_type in ("data_flow", "control_flow"):
            main_view = (record.get("retrieval") or {}).get(view_type) or {}
            ctrl_view = ((other or {}).get("retrieval") or {}).get(view_type) or {}
            main_hits = [h.get("pair_id") for h in (main_view.get("hits") or [])][:top_k]
            ctrl_hits = [h.get("pair_id") for h in (ctrl_view.get("hits") or [])][:top_k]
            compared_views += 1
            overlap = len(set(main_hits) & set(ctrl_hits))
            overlap_total += overlap
            both_have = bool(main_hits) and bool(ctrl_hits)
            if both_have and main_hits[0] == ctrl_hits[0]:
                same_top1 += 1
            if main_hits and not ctrl_hits:
                main_only += 1
            if ctrl_hits and not main_hits:
                control_only += 1
            rows.append(
                {
                    "case_id": case_id,
                    "view_type": view_type,
                    "main_top1": main_hits[0] if main_hits else "",
                    "control_top1": ctrl_hits[0] if ctrl_hits else "",
                    "same_top1": bool(both_have and main_hits[0] == ctrl_hits[0]),
                    "overlap": overlap,
                    "main_pool": int(main_view.get("pool_size") or 0),
                    "control_pool": int(ctrl_view.get("pool_size") or 0),
                }
            )

    changed = sum(1 for row in rows if not row["same_top1"])
    return {
        "views_compared": compared_views,
        "same_top1": same_top1,
        "changed_top1": changed,
        "overlap_total": overlap_total,
        "overlap_avg": round(overlap_total / compared_views, 2) if compared_views else 0.0,
        "main_only_views": main_only,
        "control_only_views": control_only,
        "pool_identical": all(row["main_pool"] == row["control_pool"] for row in rows),
        "rows": rows,
    }


def render_control_comparison(comparison: Dict[str, Any], *, top_k: int = 4) -> str:
    """对照臂对比报告（Markdown）。

    对照臂的逐条记录按约定**不落盘**，本文件只留聚合数字与 top-1 对照，
    可以在不保留对照数据的前提下复述结论。
    """
    lines: List[str] = [
        "# 对照臂对比（事实注入 vs 无诊断）",
        "",
        "> 对照臂（`query.source=none`）的逐条记录**用完即弃**，未落盘。",
        "> 本表只保留聚合数字与 top-1 对照，因此能回答「检索行为有没有被事实注入改变」，",
        "> **不能**回答「准了多少」——那需要人工判同一批候选，而对照数据已按约定丢弃。",
        "",
        "| 指标 | 值 |",
        "| --- | --- |",
        f"| 对比视图数 | {comparison['views_compared']} |",
        f"| top-1 相同 | {comparison['same_top1']} |",
        f"| top-1 不同 | {comparison['changed_top1']} |",
        f"| top-{top_k} 交集均值 | {comparison['overlap_avg']} |",
        f"| 仅主臂有命中 | {comparison['main_only_views']} |",
        f"| 仅对照臂有命中 | {comparison['control_only_views']} |",
        f"| 两臂候选池一致 | {'是' if comparison['pool_identical'] else '**否**（异常：CWE 过滤应两臂相同）'} |",
        "",
        "## 逐 case top-1 对照",
        "",
        "| case | view | 主臂 top-1 | 对照臂 top-1 | 同? | 交集 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in comparison["rows"]:
        lines.append(
            "| {case} | {view} | `{main}` | `{ctrl}` | {same} | {overlap} |".format(
                case=row["case_id"],
                view=row["view_type"],
                main=(row["main_top1"] or "—"),
                ctrl=(row["control_top1"] or "—"),
                same="Y" if row["same_top1"] else "N",
                overlap=row["overlap"],
            )
        )
    lines.append("")
    return "\n".join(lines)


def write_all(
    out_dir: str | Path,
    records: List[Dict[str, Any]],
    *,
    top_k: int = 4,
) -> Dict[str, Path]:
    """落盘三件产物，返回路径表。"""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    cases_path = out / "cases.jsonl"
    cases_path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in records) + ("\n" if records else ""),
        encoding="utf-8",
    )

    judging_path = out / "judging.md"
    judging_path.write_text(render_judging_table(records, top_k=top_k), encoding="utf-8")

    summary_path = out / "summary.json"
    summary_path.write_text(
        json.dumps(summarize(records), ensure_ascii=False, indent=2), encoding="utf-8"
    )

    return {"cases": cases_path, "judging": judging_path, "summary": summary_path}


__all__ = ["summarize", "render_judging_table", "compare_arms", "render_control_comparison", "write_all"]
