"""修复端命令行：阶段 A（R1 检索可验）的批量入口。

用法::

    .venv\\Scripts\\python.exe -m repair.cli batch --input output/repair_input_batch.json \\
        --kb artifacts/kb-v2 --out output/repair_r1 --accept-verdicts accept,uncertain

    # 不花钱：跳过 LLM，全部视图走降级 root_cause，只验证链路
    .venv\\Scripts\\python.exe -m repair.cli batch --input ... --kb ... --out ... --no-llm

一条 case 的处理顺序（与设计稿 §3 的链路图一致）::

    intake → facts ─(不足)→ reverify → facts' ─(仍不足)→ insufficient_facts
                │
                └→ query → retrieve(DF/CF) → retrieved / no_match

``--no-llm`` 只影响 ``query`` 的 Step 4；其余每一步都是确定性的。
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.call_context import build_context
from verify_agent.reverify import reverify_case

from .facts import build_facts, build_reverify_request
from .intake import load_eval_cases, load_repair_input, gate
from .query import build_query
from .report import write_all
from .retrieve import load_kb, retrieve_for_case
from .schema import CaseOutcome, RepairCase

ROOT = Path(__file__).resolve().parent.parent


def load_cases(
    input_path: Path,
    *,
    accept_verdicts: List[str],
    default_line_base: str = "file",
) -> List[RepairCase]:
    """按扩展名分派：``.jsonl`` 走评测集索引，``.json`` 走 ``repair-input/1``。"""
    if input_path.suffix == ".jsonl":
        cases = load_eval_cases(input_path)
    else:
        _meta, cases = load_repair_input(input_path, default_line_base=default_line_base)
    return gate(cases, accept_verdicts=accept_verdicts, default_line_base=default_line_base)


def _make_llm() -> Any:
    """复用知识库侧的 provider 配置（同一份 config/.env，同一套凭证）。"""
    from kbcore.config import load_config
    from kbcore.llm import OpenAICompatClient

    cfg = load_config()
    if not cfg.model or not cfg.api_key:
        raise RuntimeError(
            "缺 LLM 凭证（config/.env 的 MODEL_NAME / OPENAI_API_KEY）；"
            "离线跑请加 --no-llm"
        )
    return OpenAICompatClient(
        cfg.model,
        cfg.api_key,
        cfg.base_url,
        temperature=0.0,
        max_tokens=512,
        timeout_s=cfg.llm_timeout_s,
        retries=cfg.llm_retries,
    )


def run_case(
    case: RepairCase,
    kb: Any,
    llm: Optional[Any],
    *,
    top_k: int,
    accept_verdicts: List[str],
    cos_weight: float,
    cwe_merge: bool,
    enable_reverify: bool,
    query_source: str = "evidence",
) -> Dict[str, Any]:
    """跑一条 case，返回可直接落盘的记录。异常收敛成 ``infra_error``，不拖垮整批。"""
    started = time.time()
    outcome = CaseOutcome(
        case_id=case.case_id,
        origin=case.origin,
        entry_kind=case.intake.kind,
        entry_reason=case.intake.reason,
        entry_verdict=case.vuln.verdict,
        line_base=case.code.line_base,
    )
    record: Dict[str, Any] = {
        "case": case.to_dict(),
        "outcome": {},
        "query": {},
        "retrieval": {},
        "facts": {},
    }

    try:
        if not case.intake.accepted:
            outcome.final = "invalid_baseline" if case.intake.kind == "invalid_baseline" else "no_match"
            outcome.iters = 0
            outcome.secs = time.time() - started
            record["outcome"] = outcome.to_dict()
            return record

        facts = build_facts(case)
        record["facts"] = facts.to_dict()

        if not facts.sufficiency.ok and enable_reverify:
            request = build_reverify_request(case, facts)
            if request:
                outcome.reverify_requested = True
                rebased = _apply_reverify(case, request)
                if rebased is not None:
                    case = rebased
                    facts = build_facts(case)
                    outcome.reverify_rounds = 1
                    outcome.reverify_improved = bool(
                        (case.raw.get("reverify") or {}).get("improved")
                    )
                    record["facts"] = facts.to_dict()
                    record["case"] = case.to_dict()

        outcome.facts_sufficiency = "ok" if facts.sufficiency.ok else "insufficient"
        outcome.facts_sufficiency_why = facts.sufficiency.why
        outcome.facts_dropped = len(facts.dropped)

        if not facts.sufficiency.ok:
            outcome.final = "insufficient_facts"
            outcome.secs = time.time() - started
            record["outcome"] = outcome.to_dict()
            return record

        query = build_query(case, facts, llm, source=query_source)
        outcome.query_degraded = query.degraded
        record["query"] = query.to_dict()

        hits_any = False
        for view_type in ("data_flow", "control_flow"):
            view = query.views.get(view_type)
            if view is None:
                continue
            result = retrieve_for_case(
                kb,
                view,
                case.vuln.cwe,
                top_k=top_k,
                cos_weight=cos_weight,
                cwe_merge=cwe_merge,
            )
            record["retrieval"][view_type] = result.to_dict()
            if result.hits:
                hits_any = True
                outcome.exemplar_pair_ids.extend(result.pair_ids)

        outcome.final = "retrieved" if hits_any else "no_match"
        outcome.iters = 1
    except Exception as exc:  # noqa: BLE001 - 单条失败不影响批次
        outcome.final = "infra_error"
        record["error"] = f"{type(exc).__name__}: {exc}"
    outcome.secs = time.time() - started
    record["outcome"] = outcome.to_dict()
    return record


def _apply_reverify(case: RepairCase, request: Dict[str, Any]) -> Optional[RepairCase]:
    """走一轮检测端复核并把结果变回 ``RepairCase``。失败就保持原 case。"""
    try:
        ctx = build_context(case.code.func_src)
        new_raw = reverify_case(case.raw, request, code=case.code.func_src, ctx=ctx)
    except Exception:  # noqa: BLE001 - 复核失败不该让 case 变成 infra_error
        return None
    rebased = RepairCase.from_dict(new_raw, origin=case.origin)
    rebased.eval_meta = dict(case.eval_meta)
    return rebased


def cmd_batch(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[error] 输入不存在：{input_path}", file=sys.stderr)
        return 2

    accept_verdicts = [v.strip() for v in str(args.accept_verdicts).split(",") if v.strip()]
    cases = load_cases(
        input_path, accept_verdicts=accept_verdicts, default_line_base=args.default_line_base
    )
    if args.limit:
        cases = cases[: args.limit]
    print(f"cases    : {len(cases)}（accept_verdicts={accept_verdicts}）")

    kb = load_kb(args.kb)
    print(f"kb       : {kb.kb_ver} backend={kb.backend} embed={kb.embed_model}")

    llm = None if args.no_llm else _make_llm()
    print(f"llm      : {'(no-llm)' if llm is None else 'enabled'}")

    records: List[Dict[str, Any]] = []
    control_records: List[Dict[str, Any]] = []
    for index, case in enumerate(cases, start=1):
        record = run_case(
            case,
            kb,
            llm,
            top_k=args.top_k,
            accept_verdicts=accept_verdicts,
            cos_weight=args.cos_weight,
            cwe_merge=args.cwe_merge,
            enable_reverify=not args.no_reverify,
        )
        records.append(record)
        # 对照臂：只跑、不落盘。设计稿 §12 的 E1——同一套 retrieve，只把 query 换成
        # "无诊断"（不吃 facts）。复核对它无意义（它本来就不用事实），所以关掉。
        if args.with_control:
            control_records.append(
                run_case(
                    case,
                    kb,
                    llm,
                    top_k=args.top_k,
                    accept_verdicts=accept_verdicts,
                    cos_weight=args.cos_weight,
                    cwe_merge=args.cwe_merge,
                    enable_reverify=False,
                    query_source="none",
                )
            )
        outcome = record["outcome"]
        print(
            f"[{index}/{len(cases)}] {case.case_id[:58]:58} {outcome['final']:18} "
            f"hits={sum(len(v.get('hits') or []) for v in record['retrieval'].values())}",
            flush=True,
        )

    paths = write_all(args.out, records, top_k=args.top_k)
    from .report import summarize

    print("\n=== summary ===")
    print(json.dumps(summarize(records), ensure_ascii=False, indent=2))
    for name, path in paths.items():
        print(f"{name:9}: {path}")

    if args.with_control:
        from .report import compare_arms, render_control_comparison

        comparison = compare_arms(records, control_records, top_k=args.top_k)
        control_path = Path(args.out) / "control_comparison.md"
        control_path.write_text(
            render_control_comparison(comparison, top_k=args.top_k), encoding="utf-8"
        )
        print("\n=== control arm (不落盘逐条记录，只留对比) ===")
        print(
            json.dumps(
                {k: v for k, v in comparison.items() if k != "rows"},
                ensure_ascii=False,
                indent=2,
            )
        )
        print(f"control  : {control_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="repair", description="修复端（阶段 A：R1 检索可验）")
    sub = parser.add_subparsers(dest="cmd", required=True)

    batch = sub.add_parser("batch", help="批量跑：intake→facts→(reverify)→query→retrieve→报告")
    batch.add_argument("--input", required=True, help="repair_input.json 或评测集 .jsonl")
    batch.add_argument("--kb", required=True, help="知识库目录（artifacts/<kb_ver>）")
    batch.add_argument("--out", required=True, help="产物目录")
    batch.add_argument("--top-k", dest="top_k", type=int, default=4)
    batch.add_argument(
        "--accept-verdicts",
        dest="accept_verdicts",
        default="accept",
        help="入口放行的 verdict 档位，逗号分隔（默认 accept；加 uncertain 会纳入更多 case）",
    )
    batch.add_argument(
        "--default-line-base",
        dest="default_line_base",
        default="file",
        help="输入缺 line_base 时的推断值（file | function）",
    )
    batch.add_argument("--cos-weight", dest="cos_weight", type=float, default=0.3)
    batch.add_argument("--cwe-merge", dest="cwe_merge", action="store_true")
    batch.add_argument("--no-llm", dest="no_llm", action="store_true", help="跳过 LLM（全部降级）")
    batch.add_argument(
        "--no-reverify", dest="no_reverify", action="store_true", help="不触发检测端复核"
    )
    batch.add_argument("--limit", type=int, default=0)
    batch.add_argument(
        "--with-control",
        dest="with_control",
        action="store_true",
        help=(
            "同时跑对照臂（query.source=none，不吃事实）。对照臂的逐条记录**不落盘**，"
            "只产出 <out>/control_comparison.md 的聚合对比（用完即弃，见设计稿 §12）"
        ),
    )
    batch.set_defaults(func=cmd_batch)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
