"""人工审阅视图：把 ``meta.jsonl`` 渲染成一份可读的 Markdown。

K2 的验收动作就是"人逐条判五类知识项是否合格"，但 ``meta.jsonl`` 一行几百字符，
直接在终端里看很痛苦。本模块把它按 pair 分组、按视图并排，输出：

* 每条记录：root_cause / risky_calls / 行为项 / fixing_strategy；
* 附上 anchor 行号与证据 scope，方便回到源码核对；
* 末尾给一张统计表（长度中位数、是否撞到截断上限、DF/CF 是否雷同）。

用法：
    python -m kbcore.cli --out-dir artifacts/kb-spread review
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

VIEW_ORDER = ("data_flow", "control_flow")
BEHAVIOR_FIELD = {"data_flow": "taint_flow", "control_flow": "control_branch"}


def _cell(text: str, limit: int = 220) -> str:
    body = " ".join((text or "").split())
    return body if len(body) <= limit else body[: limit - 1] + "…"


def build_markdown(records: Iterable[dict], *, title: str = "知识库记录审阅") -> str:
    rows = list(records)
    by_pair: dict[str, dict[str, dict]] = {}
    for record in rows:
        by_pair.setdefault(record["pair_id"], {})[record["view_type"]] = record

    lines: list[str] = [f"# {title}", ""]
    lines.append(f"共 {len(rows)} 条记录 / {len(by_pair)} 对。每条记录三问：")
    lines.append("")
    lines.append("1. `root_cause` 是否只描述缺陷类别（不含本函数内的具体变量名/函数名）？")
    lines.append("2. `risky_calls` 是否真的是这次修复涉及的调用？")
    lines.append("3. `fixing_strategy` 照着做能不能修好？")
    lines.append("")

    for pair_id, views in by_pair.items():
        any_record = next(iter(views.values()))
        anchors = any_record.get("anchors") or {}
        lines.append("---")
        lines.append("")
        lines.append(f"## {pair_id}")
        lines.append("")
        lines.append(
            f"`{any_record['cwe']}` · cve={any_record.get('cve') or '—'} · func=`{any_record.get('func')}`"
            f" · anchor vul L{anchors.get('vul_lines')} → fixed L{anchors.get('new_lines')}"
            f" · {anchors.get('kind')} ({anchors.get('confidence')})"
            f" · evidence={any_record.get('evidence')}"
        )
        lines.append("")
        lines.append("| 视图 | root_cause | risky_calls | 行为项 | fixing_strategy |")
        lines.append("| --- | --- | --- | --- | --- |")
        for view in VIEW_ORDER:
            record = views.get(view)
            if not record:
                lines.append(f"| {view} | _(缺失)_ | | | |")
                continue
            behavior = record.get(BEHAVIOR_FIELD[view]) or ""
            lines.append(
                "| {} | {} | {} | {} | {} |".format(
                    view,
                    _cell(record.get("root_cause", "")),
                    ", ".join(record.get("risky_calls") or []) or "—",
                    _cell(behavior),
                    _cell(record.get("fixing_strategy", "")),
                )
            )
        lines.append("")

    lines.extend(_stats(rows, by_pair))
    return "\n".join(lines) + "\n"


def _stats(rows: list[dict], by_pair: dict[str, dict[str, dict]]) -> list[str]:
    def median(values: list[int]) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        mid = len(ordered) // 2
        return float(ordered[mid]) if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2

    roots = [len(r.get("root_cause", "")) for r in rows]
    behaviors = [
        len(r.get(BEHAVIOR_FIELD[r["view_type"]]) or "") for r in rows if r.get("view_type") in BEHAVIOR_FIELD
    ]
    strategies = [len(r.get("fixing_strategy", "")) for r in rows]
    same = sum(
        1
        for views in by_pair.values()
        if len(views) == 2 and views["data_flow"].get("root_cause") == views["control_flow"].get("root_cause")
    )
    capped_behavior = sum(1 for r in rows if r.get("view_type") in BEHAVIOR_FIELD
                          and len(r.get(BEHAVIOR_FIELD[r["view_type"]]) or "") >= 300)
    out = [
        "---",
        "",
        "## 统计",
        "",
        "| 指标 | 值 |",
        "| --- | --- |",
        f"| 记录数 / 对数 | {len(rows)} / {len(by_pair)} |",
        f"| root_cause 长度（中位） | {median(roots):.0f} |",
        f"| 行为项长度（中位） | {median(behaviors):.0f} |",
        f"| fixing_strategy 长度（中位） | {median(strategies):.0f} |",
        f"| 行为项顶到 300 上限（被截断） | {capped_behavior} |",
        f"| DF/CF root_cause 完全相同 | {same} / {len(by_pair)} |",
        f"| 带 risky_calls 的记录 | {sum(1 for r in rows if r.get('risky_calls'))} / {len(rows)} |",
    ]
    return out


def write_review(out_dir: Path, path: Path | None = None, *, title: str = "知识库记录审阅") -> Path:
    """读 ``out_dir/meta.jsonl``，写 ``review.md``（默认落在同目录）。"""
    out_dir = Path(out_dir)
    meta_path = out_dir / "meta.jsonl"
    if not meta_path.exists():
        raise FileNotFoundError(f"缺 meta.jsonl：{meta_path}")
    records = [json.loads(line) for line in meta_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    target = Path(path) if path else out_dir / "review.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(build_markdown(records, title=title), encoding="utf-8")
    return target


__all__ = ["build_markdown", "write_review", "VIEW_ORDER", "BEHAVIOR_FIELD"]
