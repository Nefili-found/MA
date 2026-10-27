#!/usr/bin/env python3
"""把机器粗判结果整理成可复核的 Markdown（一次性工具，产物在 output/repair_r1/）。

粗判依据是**读文本**：比较 case 的 query.root_cause 与候选的 root_cause 是否描述
同一类「缺/错的前提」，不是跑模型、也不是打分。所以：

* 结论只是**初筛**，``Y``/``N`` 都需要人工复核；``?`` 表示我判不了（降级查询或边界情况）；
* 每个判定附一句理由，理由比结论更重要——不同意结论时直接看理由。

按 **case_id 特征串**对齐（不按序号：``no_match`` 的 case 也带 ``retrieval`` 字段，
用序号极易错位，第一版就错了一次）。
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES = ROOT / "output" / "repair_r1" / "cases.jsonl"
META = ROOT / "artifacts" / "kb-v2" / "meta.jsonl"
OUT = ROOT / "output" / "repair_r1" / "judging_rough.md"

#: 机器粗判：case_id 特征串 → 两视图各 4 个 Y/N/?
VERDICTS = {
    "binutils_dwarf.c__L9290": {"data_flow": ["?", "?", "?", "?"],
                                "control_flow": ["N", "N", "N", "?"]},
    "src_pr.c__L1236__f2": {"data_flow": ["N", "N", "N", "N"],
                            "control_flow": ["N", "N", "N", "N"]},
    "src_pr.c__L1236__f3": {"data_flow": ["Y", "Y", "Y", "Y"],
                            "control_flow": ["Y", "Y", "Y", "Y"]},
    "bfd_dwarf2.c__L2441__f1": {"data_flow": ["Y", "Y", "Y", "Y"],
                                "control_flow": ["?", "?", "?", "?"]},
    "bfd_dwarf2.c__L2441__f2": {"data_flow": ["Y", "?", "N", "?"],
                                "control_flow": ["Y", "N", "N", "N"]},
    "jpc_dec.c__L1234": {"data_flow": ["Y", "Y", "Y", "Y"],
                         "control_flow": ["Y", "Y", "Y", "Y"]},
    "jquant1.c__L536__f1": {"data_flow": ["Y", "Y", "Y", "Y"],
                            "control_flow": ["Y", "Y", "Y", "Y"]},
    "jquant1.c__L536__f2": {"data_flow": ["Y", "Y", "Y", "Y"],
                            "control_flow": ["Y", "Y", "Y", "Y"]},
    "jquant1.c__L536__f3": {"data_flow": ["Y", "Y", "Y", "Y"],
                            "control_flow": ["Y", "Y", "Y", "Y"]},
    "valid.c__L1181": {"data_flow": ["?", "?", "?", "?"],
                       "control_flow": ["?", "Y", "Y", "Y"]},
    "dfa.c__L184__f1": {"data_flow": ["Y", "?", "N", "?"],
                        "control_flow": ["Y", "Y", "?", "N"]},
    "shred.c__L293__f1": {"data_flow": ["Y", "Y", "Y", "N"],
                          "control_flow": ["Y", "Y", "Y", "Y"]},
    "shred.c__L293__f2": {"data_flow": ["Y", "Y", "Y", "Y"],
                          "control_flow": ["Y", "Y", "Y", "Y"]},
    "CVE-2024-36030.c__L8__f1": {"data_flow": ["N", "N", "N", "N"],
                                 "control_flow": ["N", "N", "N", "N"]},
    "CVE-2024-36909.c__L7": {"data_flow": ["Y", "Y", "Y", "Y"],
                             "control_flow": ["?", "Y", "Y", "Y"]},
    "CVE-2024-31744.c__L28": {"data_flow": ["Y", "N", "Y", "Y"],
                              "control_flow": ["Y", "Y", "Y", "Y"]},
    "CVE-2024-36012.c__L19__f1": {"data_flow": ["Y", "Y", "Y", "Y"],
                                  "control_flow": ["Y", "Y", "Y", "Y"]},
}

#: 逐 case 粗判说明
NOTES = {
    "binutils_dwarf.c__L9290": (
        "data_flow 查询已降级（退化成函数体原文），无法判；control_flow 问「源数据不足 8 字节」，"
        "候选都在讲 dest 容量与可达性，不同类。"
    ),
    "src_pr.c__L1236__f2": "问「分隔符换成短串后长度没同步」，候选全是容量/越界类，检索打偏。",
    "src_pr.c__L1236__f3": "问「分隔符指针可能为空」，候选全是空指针解引用，同类且贴合。",
    "bfd_dwarf2.c__L2441__f1": (
        "data_flow 问整数溢出（乘法+累加超表示范围），4 条候选全是收窄/溢出类，同类；"
        "control_flow 查询已降级，无法判。"
    ),
    "bfd_dwarf2.c__L2441__f2": (
        "问「section offset 未校验即用于读」；只有 #1 同类，#2–#4 中 3 条**根因写着没有缺陷**"
        "（见文末 KB 质量问题），污染了 CF 池。"
    ),
    "jpc_dec.c__L1234": "问 hsub/vsub 乘积溢出，4 条候选全是整数收窄/溢出类，贴合。",
    "jquant1.c__L536__f1": "问 context 与 quantization state 未判空即解引用，候选全为空指针流，贴合。",
    "jquant1.c__L536__f2": "同上（output row pointer 未判空），候选全为空指针类。",
    "jquant1.c__L536__f3": "同上（per-component LUT 指针未判空），贴合。",
    "valid.c__L1181": (
        "data_flow 降级无法判；control_flow 问「父节点判空但子节点没判」，#2–#4 同类，"
        "#1 讲 lock 失败，判不了。"
    ),
    "dfa.c__L184__f1": (
        "问「现有 bounds guard 少一个字节」；#1 同类（off-by-one 容量），#2/#3 是负索引/取整偏移，"
        "勉强，#4 讲未初始化。边界 case。"
    ),
    "shred.c__L293__f1": (
        "问「length<3 却在固定偏移写 3 字节」；#1–#3 都是长度/容量不足类，#4 讲未初始化，不同类。"
    ),
    "shred.c__L293__f2": "同 f1（固定模式写入），4 条基本都在讲容量/长度不足。",
    "CVE-2024-36030.c__L8__f1": (
        "**查询本身是否定式的**：模型写的是「不支持存在内存泄漏」。候选全是真泄漏范例，"
        "因此全部不同类——这类查询本身就不该拿去检索（见文末改进项）。"
    ),
    "CVE-2024-36909.c__L7": (
        "问外部指针未判空即解引用，但该 case 的 CWE 是 401（泄漏）→ 池子是 CWE-401 池，"
        "返回的却是空指针类描述，说明记录里的 CWE 与 root_cause 主题不一致。"
    ),
    "CVE-2024-31744.c__L28": "问报文头 stream 未初始化即读，候选多为未初始化值流，同类。",
    "CVE-2024-36012.c__L19__f1": "问没判空就读 name/bus，候选全为空指针类，贴合。",
}


def key_of(case_id: str) -> str:
    """从完整 case_id 里取特征串（``extractfix__CWE-125__x__L1__f2`` → ``x__L1__f2``）。"""
    for token in VERDICTS:
        if case_id.endswith(token) or token in case_id:
            return token
    return ""


def main() -> int:
    meta = {}
    for line in META.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        meta[(row["pair_id"], row["view_type"])] = row

    records = [
        json.loads(line)
        for line in CASES.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    with_hits = [
        r
        for r in records
        if any(((v or {}).get("hits") or []) for v in (r.get("retrieval") or {}).values())
    ]

    lines = [
        "# R1 判分表 —— 机器粗判（待人工复核）",
        "",
        "> **这不是人工判分结论。** 粗判方式是读文本：比较 query 根因与候选根因是否描述",
        "> 同一类「缺/错的前提」，没有跑模型、没有打分。",
        "> `Y` = 我判同类，`N` = 我判不同类，`?` = 判不了（查询降级或边界情况）。",
        "> 明天按 `粗判` 列改成你的结论即可；不同意时优先看 `粗判说明`。",
        "",
    ]

    passed, failed, unjudged = [], [], []
    degraded_views = 0
    for record in with_hits:
        case_id = record["case"]["case_id"]
        token = key_of(case_id)
        vuln = record["case"]["vuln"]
        anchor = record["case"].get("anchor_text") or ""
        marks = VERDICTS.get(token, {})
        lines.append(f"## {case_id}")
        lines.append("")
        lines.append(
            f"- CWE：`{vuln.get('cwe')}` ｜ verdict：`{vuln.get('verdict')}` ｜ "
            f"锚点：`{anchor[:90]}`"
        )
        if token not in VERDICTS:
            lines.append("- ⚠ 本 case 没有粗判记录（脚本索引缺失）")
        lines.append(f"- 粗判说明：{NOTES.get(token, '')}")
        lines.append("")

        per_view = {}
        for view_type in ("data_flow", "control_flow"):
            view = (record.get("query") or {}).get("views", {}).get(view_type) or {}
            group = (record.get("retrieval") or {}).get(view_type) or {}
            hits = group.get("hits") or []
            if not hits:
                lines.append(f"### {view_type} —— 无命中（pool={group.get('pool_size')}）")
                lines.append("")
                continue
            if view.get("degraded_reason"):
                degraded_views += 1
                lines.append(f"### {view_type} ⚠ 查询降级：{view['degraded_reason']}")
                lines.append("")
                continue
            root = (view.get("root_cause") or "").replace("\n", " ")
            lines.append(f"### {view_type}（pool={group.get('pool_size')}）")
            lines.append("")
            lines.append(f"查询根因：{root[:240]}")
            lines.append("")
            lines.append("| rank | score | 候选根因（截断） | 粗判 |")
            lines.append("| --- | --- | --- | --- |")
            marks_view = marks.get(view_type) or []
            yes = 0
            for rank, hit in enumerate(hits, start=1):
                candidate = meta.get((hit["pair_id"], view_type)) or {}
                text = (candidate.get("root_cause") or "(KB 里找不到该记录)").replace("\n", " ")
                mark = marks_view[rank - 1] if rank - 1 < len(marks_view) else "?"
                if mark == "Y":
                    yes += 1
                lines.append(f"| {rank} | {hit.get('score')} | {text[:150]} | **{mark}** |")
            lines.append("")
            per_view[view_type] = (yes, len(hits))

        summary = "；".join(f"{k} {v[0]}/{v[1]}" for k, v in per_view.items()) or "无可判视图"
        ok_views = [v for v in per_view.values() if v[0] >= 3]
        if ok_views:
            passed.append(case_id)
            verdict = "通过"
        elif per_view:
            failed.append(case_id)
            verdict = "未通过"
        else:
            unjudged.append(case_id)
            verdict = "不可判（查询降级）"
        lines.append(f"**粗判合计：{summary}** → {verdict}")
        lines.append("")
        lines.append("---")
        lines.append("")

    lines += [
        "# 汇总",
        "",
        f"- 有命中的 case：{len(with_hits)}",
        f"- 粗判通过（任一视图 ≥3/4）：**{len(passed)}**",
        *[f"  - {c}" for c in passed],
        f"- 粗判未通过：**{len(failed)}**",
        *[f"  - {c}" for c in failed],
        f"- 不可判（查询降级）：**{len(unjudged)}**",
        *[f"  - {c}" for c in unjudged],
        f"- 因降级而跳过的视图数：{degraded_views}",
        "",
        "# 粗判发现的三个问题",
        "",
        "1. **知识库里有「根因写着没有缺陷」的记录**：`kb-v2` 578 条里 6 条属此类"
        "（全为 `control_flow`，CWE-125 ×3 / CWE-190 ×3），集中在 2–3 个 pair 上。"
        "它们作为修补范例毫无价值，却占住了对应 CWE 的 CF 池"
        "（`bfd_dwarf2.c__L2441__f2` 的 control_flow top-4 里有 3 条就是这种）。",
        "2. **降级查询的根因不可用**：3 个视图的 root_cause 退化成函数体原文"
        "（LLM 两次都写出实现标识符），拿代码当根因去检索，结果没有解释力。",
        "3. **CWE 与根因主题不一致**：`CVE-2024-36909` 的 CWE 是 401（泄漏），"
        "但查询问的是空指针；检索被 CWE 硬过滤锁在 401 池里 —— 池子对，问的东西不对。"
        "根源是检测端判的 CWE 与 A/B/C 写的根因描述各说各话。",
        "",
    ]
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"written: {OUT}")
    print(f"passed={len(passed)} failed={len(failed)} unjudged={len(unjudged)} "
          f"degraded_views={degraded_views}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
