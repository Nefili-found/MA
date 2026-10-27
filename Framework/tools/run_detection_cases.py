#!/usr/bin/env python3
"""批量跑检测端，为修复端评测集产出真实的 ``repair_input/1``。

为什么需要它
------------
``main.py`` 一次只扫一个文件，且 ``repair_input.json`` 固定写到
``output/repair_input.json``（每次覆盖）。要拿一批 case，就得：
逐条调用 ``main.py`` → 用环境变量把每条产物重定向到 ``output/detection/<case_id>/``
→ 最后合并成 ``output/repair_input_batch.json``。

切片行号
--------
评测集里的文件都是**切片**（文件第 1 行 = 原文件 ``slice[0]`` 行），而 A/B/C 常把
漏洞行写成原文件坐标。所以每条都要把 ``slice[0]`` 作为 ``--slice-start`` 传进去，
否则 ``function_at`` 取不到函数、``func_src`` 为空、case 全被判 ``invalid_baseline``。

用法::

    .venv\\Scripts\\python.exe tools/run_detection_cases.py --per-cwe 2
    .venv\\Scripts\\python.exe tools/run_detection_cases.py --per-cwe 2 --dry-run

已存在的单条产物会被跳过，可重复运行（断点续跑）。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
EVAL_CASES = ROOT / "test_data" / "repair_eval_cases.jsonl"
OUT_ROOT = ROOT / "output" / "detection"
BATCH_OUT = ROOT / "output" / "repair_input_batch.json"


def select_cases(path: Path, per_cwe: int) -> List[Dict[str, Any]]:
    """每个 CWE 取前 ``per_cwe`` 条**锚点有效**的 case（跨 CWE，不按目录序截断）。"""
    picked: List[Dict[str, Any]] = []
    counts: Dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if not row.get("anchor_ok"):
            continue
        cwe = str(row.get("cwe") or "")
        if counts.get(cwe, 0) >= per_cwe:
            continue
        counts[cwe] = counts.get(cwe, 0) + 1
        picked.append(row)
    return picked


def run_one(row: Dict[str, Any], *, dry_run: bool = False, timeout: float = 900.0) -> Dict[str, Any]:
    case_id = str(row["case_id"])
    out_dir = OUT_ROOT / case_id
    out_dir.mkdir(parents=True, exist_ok=True)
    repair_path = out_dir / "repair_input.json"
    report_path = out_dir / "final_report.json"

    if repair_path.exists():
        return {"case_id": case_id, "skipped": True, "repair_input": str(repair_path)}

    vul_file = str(row["vul_file"])
    slice_start = int((row.get("slice") or [1])[0])
    cmd = [
        sys.executable,
        str(ROOT / "main.py"),
        "--file",
        vul_file,
        "--repo-root",
        str(ROOT),
        "--case-id",
        case_id,
        "--repo",
        str(row.get("target") or ""),
        "--commit",
        "",
        "--slice-start",
        str(slice_start),
    ]
    env = dict(os.environ)
    env["REPAIR_INPUT_PATH"] = str(repair_path)
    env["OUTPUT_PATH"] = str(report_path)

    if dry_run:
        return {"case_id": case_id, "skipped": False, "dry_run": True, "cmd": cmd}

    started = time.time()
    # 单条超时：一条 case 卡在 LLM 重试上会把整批拖死（实测有一条跑了 11 分钟仍无产物，
    # CPU 只用了 4.6s —— 纯粹在等网络）。超时就记为失败，继续下一条。
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "case_id": case_id,
            "skipped": False,
            "ok": False,
            "timeout": True,
            "secs": round(time.time() - started, 1),
            "cases": 0,
            "invalid": 0,
            "tail": [f"TIMEOUT after {timeout}s"],
        }
    secs = round(time.time() - started, 1)
    ok = proc.returncode == 0 and repair_path.exists()
    cases = 0
    invalid = 0
    if ok:
        payload = json.loads(repair_path.read_text(encoding="utf-8"))
        cases = len(payload.get("cases") or [])
        invalid = sum(1 for c in payload.get("cases") or [] if not (c.get("validation") or {}).get("ok"))
    tail = (proc.stdout or "").strip().splitlines()[-3:]
    return {
        "case_id": case_id,
        "skipped": False,
        "returncode": proc.returncode,
        "secs": secs,
        "cases": cases,
        "invalid": invalid,
        "ok": ok,
        "tail": tail,
    }


def merge_batch(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """把逐条产物合并成一个 ``repair-input/1``（case_id 已由 main.py 保证批次内唯一）。"""
    cases: List[Dict[str, Any]] = []
    for row in rows:
        path = OUT_ROOT / str(row["case_id"]) / "repair_input.json"
        if not path.exists():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        cases.extend(payload.get("cases") or [])
    return {
        "schema": "repair-input/1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "provenance": {
            "detector": "A/B/C+D (tools/run_detection_cases.py)",
            "case_count": len(cases),
            "invalid_count": sum(1 for c in cases if not (c.get("validation") or {}).get("ok")),
            "sources": [str(r["case_id"]) for r in rows],
        },
        "cases": cases,
    }


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cases", default=str(EVAL_CASES))
    parser.add_argument("--per-cwe", type=int, default=2)
    parser.add_argument("--out", default=str(BATCH_OUT))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int, default=0, help="只跑前 N 条（调试用）")
    parser.add_argument("--timeout", type=float, default=900.0, help="单条 case 超时秒数（默认 900）")
    args = parser.parse_args(argv)

    cases_path = Path(args.cases)
    if not cases_path.exists():
        raise SystemExit(f"缺评测集索引：{cases_path}（先跑 test_data/build_repair_eval_cases.py）")

    picked = select_cases(cases_path, args.per_cwe)
    if args.limit:
        picked = picked[: args.limit]
    print(f"selected : {len(picked)} cases（每 CWE {args.per_cwe} 条，锚点有效的）")
    hist: Dict[str, int] = {}
    for row in picked:
        hist[str(row["cwe"])] = hist.get(str(row["cwe"]), 0) + 1
    print(f"cwe      : {dict(sorted(hist.items()))}")

    results: List[Dict[str, Any]] = []
    for index, row in enumerate(picked, start=1):
        print(f"[{index}/{len(picked)}] {row['case_id']} (slice_start={(row.get('slice') or [1])[0]})", flush=True)
        result = run_one(row, dry_run=args.dry_run, timeout=args.timeout)
        results.append(result)
        if result.get("dry_run"):
            print("    " + " ".join(result["cmd"]))
        elif result.get("skipped"):
            print("    skipped（已有产物）")
        else:
            flag = "ok" if result.get("ok") else f"FAIL rc={result.get('returncode')}"
            print(
                f"    {flag} | {result.get('secs')}s | cases={result.get('cases')}"
                f" invalid={result.get('invalid')}",
                flush=True,
            )

    if args.dry_run:
        return 0

    batch = merge_batch(results)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(batch, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n=== batch ===")
    print(f"cases    : {batch['provenance']['case_count']}")
    print(f"invalid  : {batch['provenance']['invalid_count']}")
    print(f"written  : {out}")
    failed = [r["case_id"] for r in results if not r.get("skipped") and not r.get("ok")]
    if failed:
        print(f"failed   : {failed}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
