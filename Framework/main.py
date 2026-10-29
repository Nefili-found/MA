"""入口：运行多 Agent 代码漏洞扫描流程。

用法::

    # 单文件（原行为，不变）
    python main.py --file examples/input/sample.c

    # 批量模式（性能优化：build_graph / settings / LLM client 只建一次，
    # 避免 subprocess 重启 + import 开销。批量跑 N 个文件时，wall time 从
    # ~N*1.2s 降到 ~单次启动 + N*业务时间）
    python main.py --batch-list files.txt --batch-out output/batch

``files.txt`` 每行一个待扫描 C 文件路径；``--batch-out`` 下每条 case 按
``--case-id``（缺省用文件名）建子目录写 ``final_report.json`` 与
``repair_input.json``。

说明：
* 单文件模式仅读取 ``--file`` 指定的单个 C 源码文件，不读取其他文件；
* 污点分析严格限制在该文件内（由各 Agent 的 Prompt / 工具负责约束）；
* 最终报告写入 output/final_report.json（单文件模式）或 --batch-out/<case_id>/。
"""
from __future__ import annotations

import argparse
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Optional, Sequence

from config import load_settings, resolve
from errors import FatalError
from graph import build_graph
from observability import configure_logging, log_event


def read_code(file_path: Path) -> str:
    """只读取指定文件。"""
    with file_path.open("r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _build_state(
    *,
    target: Path,
    code: str,
    session_id: str,
    case_id: str,
    repo: str,
    commit: str,
    repo_root: Optional[str],
    slice_start: int,
) -> dict:
    """构造 LangGraph 初始 state。抽出来便于单文件 / 批量两条路径共用。"""
    rel_file = ""
    if repo_root:
        try:
            rel_file = os.path.relpath(str(target), repo_root).replace(os.sep, "/")
            if rel_file.startswith("../"):
                rel_file = ""
        except ValueError:  # 跨盘符
            rel_file = ""
    return {
        "file_path": str(target),
        "code": code,
        "case_id": case_id,
        "repo": repo,
        "commit": commit,
        "rel_file": rel_file,
        "slice_start": max(0, int(slice_start or 0)),
        "line_base": "function" if int(slice_start or 0) > 0 else "file",
        "reports": {},
        "merged_findings": [],
        "verified_findings": [],
        "final_report": {},
        "repair_input": {},
        "session_id": session_id,
        "errors": [],
    }


def scan_one(
    *,
    app: Any,
    target: Path,
    code: str,
    case_id: str,
    repo: str = "",
    commit: str = "",
    repo_root: Optional[str] = None,
    slice_start: int = 0,
    output_path: Optional[Path] = None,
    repair_input_path: Optional[Path] = None,
) -> dict:
    """扫描单个文件，返回 LangGraph result dict。

    【性能优化】batch 模式下 app（=build_graph()）由调用方建一次复用；
    本函数不再 build_graph()，也不再读 settings——输出路径由调用方传。

    ``output_path`` / ``repair_input_path`` 给了就覆盖默认（批量模式下每条 case
    写到自己的子目录）；不给则用 settings 默认路径（单文件模式）。
    """
    session_id = uuid.uuid4().hex
    state = _build_state(
        target=target, code=code, session_id=session_id,
        case_id=case_id, repo=repo, commit=commit,
        repo_root=repo_root, slice_start=slice_start,
    )
    # 允许调用方把输出路径注入 state：report_builder / repair_projection 会读
    # settings.output_path，但我们用 monkey-patch 太重，直接在 state 里塞一个覆盖键。
    # 实际写入路径由 d.py 里 resolve(settings.output_path) 决定，所以批量模式下
    # 我们在跑完后自己把产物 copy 到 case 子目录（见 _finalize_batch_case）。
    log_event("run.start", file=str(target), session=session_id)
    result = app.invoke(state, config={"recursion_limit": 50})
    log_event(
        "run.done",
        session=session_id,
        findings=len((result.get("final_report") or {}).get("findings", [])),
    )
    result["_session_id"] = session_id
    result["_target"] = str(target)
    return result


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
    # 【批量模式】--batch-list: 每行一个文件路径；--batch-out: 每条 case 的产物目录
    parser.add_argument(
        "--batch-list",
        dest="batch_list",
        default=None,
        help="批量模式：一个文本文件，每行一个待扫描 C 文件路径。"
             "此时 --file 被忽略；build_graph() 只建一次。",
    )
    parser.add_argument(
        "--batch-out",
        dest="batch_out",
        default=None,
        help="批量模式产物根目录；每条 case 写到 <batch-out>/<case_id>/。"
             "case_id 缺省用文件名（去扩展名）。",
    )
    return parser.parse_args(argv)


def _print_single_summary(result: dict, output_path: Path, repair_input_path: Path) -> None:
    """单文件模式的 stdout 摘要（与原行为一致）。"""
    print(f"[ok] 最终报告已写入: {output_path}")
    repair_input = result.get("repair_input") or {}
    repair_cases = repair_input.get("cases") or []
    if repair_cases:
        invalid = sum(1 for c in repair_cases if not (c.get("validation") or {}).get("ok"))
        print(f"[ok] 修复端输入已写入: {repair_input_path}")
        print(f"[ok] 可交给修复端的 case: {len(repair_cases) - invalid}/{len(repair_cases)}")
        for case in repair_cases:
            if (case.get("validation") or {}).get("ok"):
                continue
            print(f"[warn] {case.get('case_id')}: {'; '.join(case['validation']['errors'])}")
    errors = result.get("errors") or []
    if errors:
        print(f"[warn] 本次运行记录了 {len(errors)} 条降级/失败事件：")
        for item in errors:
            print(f"[warn] {item}")


def _run_batch(args: argparse.Namespace, settings) -> int:
    """批量模式：同进程内循环跑文件列表，build_graph 只建一次。"""
    list_path = Path(args.batch_list)
    if not list_path.exists():
        print(f"[error] --batch-list 文件不存在: {list_path}", file=sys.stderr)
        return 2
    out_root = Path(args.batch_out or "output/batch")
    out_root.mkdir(parents=True, exist_ok=True)

    files = [
        line.strip() for line in list_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not files:
        print("[error] --batch-list 为空", file=sys.stderr)
        return 2

    print(f"[batch] {len(files)} files; out_root={out_root}")
    # 关键优化：graph 只建一次
    app = build_graph()

    ok = 0
    fail = 0
    for i, f in enumerate(files, 1):
        target = Path(f)
        if not target.exists():
            print(f"[{i}/{len(files)}] MISS  {f}", flush=True)
            fail += 1
            continue
        case_id = args.case_id or target.stem
        code = read_code(target)
        try:
            result = scan_one(
                app=app, target=target, code=code, case_id=case_id,
                repo=args.repo or "", commit=args.commit or "",
                repo_root=args.repo_root, slice_start=args.slice_start,
            )
            # 把产物 copy 到 case 子目录（d.py 写到 settings.output_path，会被覆盖，
            # 所以每条 case 跑完立刻搬）
            case_dir = out_root / case_id
            case_dir.mkdir(parents=True, exist_ok=True)
            src_report = resolve(settings.output_path)
            src_repair = resolve(getattr(settings, "repair_input_path", "output/repair_input.json"))
            import shutil
            if Path(src_report).exists():
                shutil.copy2(src_report, case_dir / "final_report.json")
            if Path(src_repair).exists():
                shutil.copy2(src_repair, case_dir / "repair_input.json")
            n_findings = len((result.get("final_report") or {}).get("findings", []))
            n_repair = len((result.get("repair_input") or {}).get("cases", []))
            print(f"[{i}/{len(files)}] OK    {case_id:40s} findings={n_findings} repair_cases={n_repair}", flush=True)
            ok += 1
        except FatalError as exc:
            print(f"[{i}/{len(files)}] FATAL {case_id}: {exc}", flush=True)
            fail += 1
        except Exception as exc:  # 单条失败不拖垮整批
            print(f"[{i}/{len(files)}] ERR   {case_id}: {type(exc).__name__}: {exc}", flush=True)
            fail += 1

    print(f"[batch] done: ok={ok} fail={fail}")
    return 0 if fail == 0 else 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    settings = load_settings(args.config)
    configure_logging(settings.log_enabled, settings.log_format, settings.log_level)

    # 批量模式
    if args.batch_list:
        return _run_batch(args, settings)

    # 单文件模式（原行为）
    target = resolve(args.file or settings.input_file)
    if not target.exists():
        print(f"[error] 输入文件不存在: {target}", file=sys.stderr)
        return 2

    code = read_code(target)
    app = build_graph()
    result = scan_one(
        app=app, target=target, code=code,
        case_id=args.case_id or "",
        repo=args.repo or "", commit=args.commit or "",
        repo_root=args.repo_root, slice_start=args.slice_start,
    )

    _print_single_summary(
        result,
        resolve(settings.output_path),
        resolve(getattr(settings, "repair_input_path", "output/repair_input.json")),
    )
    print(f"[ok] 记忆库: {resolve(settings.db_path)}")
    print(f"[ok] session_id: {result.get('_session_id')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
