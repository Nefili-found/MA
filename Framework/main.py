"""入口：运行多 Agent 代码漏洞扫描流程。

用法::

    python main.py --file examples/input/sample.c

说明：
* 仅读取 ``--file`` 指定的单个 C 源码文件，不读取其他文件；
* 污点分析严格限制在该文件内（由各 Agent 的 Prompt / 工具负责约束）；
* 最终报告写入 output/final_report.json。
"""
from __future__ import annotations

import argparse
import os
import sys
import uuid
from pathlib import Path
from typing import Optional, Sequence

from config import load_settings, resolve
from errors import FatalError
from graph import build_graph
from observability import configure_logging, log_event


def read_code(file_path: Path) -> str:
    """只读取指定文件。"""
    with file_path.open("r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="多 Agent 代码漏洞扫描系统")
    parser.add_argument(
        "--file",
        dest="file",
        default=None,
        help="待扫描的单个 C 源码文件（默认取配置中的 input.file）",
    )
    parser.add_argument(
        "--config",
        dest="config",
        default=None,
        help="配置文件路径（默认 config/config.yaml，回退 config/config.example.yaml）",
    )
    # 【修复端输入 P0】repair_input.json 需要的元数据；不传则降级（case 会被校验拦下）
    parser.add_argument(
        "--case-id",
        dest="case_id",
        default=None,
        help="用例目录名（批次内唯一），写入 repair_input.json 的 case_id",
    )
    parser.add_argument(
        "--repo",
        dest="repo",
        default=None,
        help="上游仓库名（如 OpenSC），写入 repair_input.json 的 source.repo",
    )
    parser.add_argument(
        "--commit",
        dest="commit",
        default=None,
        help="被扫描文件对应的上游 commit，写入 source.commit",
    )
    parser.add_argument(
        "--repo-root",
        dest="repo_root",
        default=None,
        help="真实仓库根目录；给了才能把 --file 转成仓库相对路径（跨机器可复现）",
    )
    parser.add_argument(
        "--slice-start",
        dest="slice_start",
        type=int,
        default=0,
        help=(
            "被扫描文件是**切片**时，它在原文件里的起始行号（1-based）；"
            "0 = 传入的是完整文件。给了它，A/B/C 报出的原文件绝对行号会被归一成切片内行号，"
            "否则 function_at 取不到函数、func_src 为空、case 直接被判 invalid_baseline。"
        ),
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    settings = load_settings(args.config)
    configure_logging(settings.log_enabled, settings.log_format, settings.log_level)

    target = resolve(args.file or settings.input_file)
    if not target.exists():
        print(f"[error] 输入文件不存在: {target}", file=sys.stderr)
        return 2

    code = read_code(target)
    session_id = uuid.uuid4().hex

    # 仓库相对路径：只有给了 --repo-root 才能算出来，否则 repair_input 的校验会因
    # source.file 是绝对路径而判 invalid_baseline（这是故意的，见设计稿 §4 校验 5）
    rel_file = ""
    if args.repo_root:
        try:
            rel_file = os.path.relpath(str(target), args.repo_root).replace(os.sep, "/")
            if rel_file.startswith("../"):
                rel_file = ""
        except ValueError:  # 跨盘符
            rel_file = ""

    state = {
        "file_path": str(target),
        "code": code,
        "case_id": args.case_id or "",
        "repo": args.repo or "",
        "commit": args.commit or "",
        "rel_file": rel_file,
        # 【D5 行号基准】切片扫描：行号从切片起算；完整文件：行号即文件绝对行号。
        # 这两个键一路传到 verify_agent/repair_projection.py 的 code.line_base。
        "slice_start": max(0, int(args.slice_start or 0)),
        "line_base": "function" if int(args.slice_start or 0) > 0 else "file",
        "reports": {},
        "merged_findings": [],
        "verified_findings": [],
        "final_report": {},
        "repair_input": {},
        "session_id": session_id,
        "errors": [],
    }

    log_event("run.start", file=str(target), session=session_id)
    app = build_graph()
    try:
        result = app.invoke(state, config={"recursion_limit": 50})
    except FatalError as exc:
        # 【健壮性包 B-2】不可恢复错误：给清楚的一句话 + 非零退出码，不喷 traceback
        log_event("run.fatal", level="error", session=session_id, error=str(exc))
        print(f"[error] {exc}", file=sys.stderr)
        return int(getattr(exc, "exit_code", 2))
    log_event(
        "run.done",
        session=session_id,
        findings=len((result.get("final_report") or {}).get("findings", [])),
    )

    print(f"[ok] 最终报告已写入: {resolve(settings.output_path)}")
    repair_input = result.get("repair_input") or {}
    repair_cases = repair_input.get("cases") or []
    if repair_cases:
        invalid = sum(1 for c in repair_cases if not (c.get("validation") or {}).get("ok"))
        print(f"[ok] 修复端输入已写入: {resolve(settings.repair_input_path)}")
        print(f"[ok] 可交给修复端的 case: {len(repair_cases) - invalid}/{len(repair_cases)}")
        for case in repair_cases:
            if (case.get("validation") or {}).get("ok"):
                continue
            print(f"[warn] {case.get('case_id')}: {'; '.join(case['validation']['errors'])}")
    # 【健壮性包 B-2】把降级/失败事件汇总给用户看：静默降级 = 静默丢能力
    errors = result.get("errors") or []
    if errors:
        print(f"[warn] 本次运行记录了 {len(errors)} 条降级/失败事件：")
        for item in errors:
            print(f"[warn] {item}")

    print(f"[ok] 记忆库: {resolve(settings.db_path)}")
    print(f"[ok] session_id: {session_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
