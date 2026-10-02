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
import sys
import uuid
from pathlib import Path
from typing import Optional, Sequence

from config import load_settings, resolve
from graph import build_graph
from observability import log_event, set_log_enabled


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
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    settings = load_settings(args.config)
    set_log_enabled(settings.log_enabled)

    target = resolve(args.file or settings.input_file)
    if not target.exists():
        print(f"[error] 输入文件不存在: {target}", file=sys.stderr)
        return 2

    code = read_code(target)
    session_id = uuid.uuid4().hex

    state = {
        "file_path": str(target),
        "code": code,
        "reports": {},
        "merged_findings": [],
        "verified_findings": [],
        "final_report": {},
        "session_id": session_id,
        "errors": [],
    }

    log_event("run.start", file=str(target), session=session_id)
    app = build_graph()
    result = app.invoke(state, config={"recursion_limit": 50})
    log_event(
        "run.done",
        session=session_id,
        findings=len((result.get("final_report") or {}).get("findings", [])),
    )

    print(f"[ok] 最终报告已写入: {resolve(settings.output_path)}")
    print(f"[ok] 记忆库: {resolve(settings.db_path)}")
    print(f"[ok] session_id: {session_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
