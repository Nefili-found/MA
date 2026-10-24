"""命令行入口：把建库各阶段拆成可单独跑、可单独验收的子命令。

    python -m kbcore.cli pairs                 # K0：数据集盘点（无 LLM）
    python -m kbcore.cli evidence --limit 12   # K1：anchor + 证据样例（无 LLM）
    python -m kbcore.cli extract --limit 10    # K2：真跑抽取/抽象/门禁（花钱）
    python -m kbcore.cli build                 # K3/K4：全量 + 建索引
    python -m kbcore.cli audit --out artifacts/kb-v1

设计约束：``extract`` 与 ``build`` 会真花钱，所以都必须显式 ``--limit`` 或
``--yes`` 才会跑全量；``--dry-run`` 用假模型走通链路但不联网。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from .anchor import locate
from .cache import Cache
from .config import KBConfig, load_config, require_llm
from .pairs import KNOWN_CWES, cwe_histogram, load_pairs, select_spread
from .pipeline import build_records, process_pair, write_run_files
from .views import extract_evidence


def _load(args: argparse.Namespace) -> tuple[KBConfig, list]:
    cfg = load_config(args.config, provider=getattr(args, "provider", None))
    if getattr(args, "out_dir", None):
        cfg.out_dir = Path(args.out_dir)
    if getattr(args, "evidence_mode", None):
        cfg.evidence_mode = args.evidence_mode
    if getattr(args, "kb_ver", None):
        cfg.kb_ver = args.kb_ver
    if getattr(args, "model", None):
        cfg.model = args.model
    cwes = [c.strip() for c in args.cwe.split(",") if c.strip()] if getattr(args, "cwe", None) else None
    pairs = load_pairs(cfg.pairs_root, cwes=cwes)
    if getattr(args, "per_cwe", None):
        pairs = select_spread(pairs, int(args.per_cwe))
    if args.limit:
        pairs = pairs[: args.limit]
    return cfg, pairs


def cmd_pairs(args: argparse.Namespace) -> int:
    cfg, pairs = _load(args)
    print(f"pairs_root : {cfg.pairs_root}")
    print(f"pairs      : {len(pairs)}")
    print(f"cwe        : {cwe_histogram(pairs)}")
    with_ast = sum(1 for p in pairs if p.has_ast_artifacts)
    print(f"with ast artifacts : {with_ast}")
    print(f"known cwes : {sorted(KNOWN_CWES)}")
    return 0


def cmd_evidence(args: argparse.Namespace) -> int:
    cfg, pairs = _load(args)
    limit = args.limit or 5
    for pair in pairs[:limit]:
        anchor = locate(pair)
        ev = extract_evidence(pair, anchor, max_df_items=cfg.max_df_items, max_cf_items=cfg.max_cf_items)
        print("=" * 78)
        print(f"{pair.pair_id}\ncwe={pair.cwe} func={pair.func}")
        print(f"anchor={anchor.as_dict()}  evidence_scope={ev.scope if ev else 'none'}")
        if ev is not None:
            print("--- DF ---")
            print(ev.df.render() or "(empty)")
            print("--- CF ---")
            print(ev.cf.render() or "(empty)")
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    cfg, pairs = _load(args)
    if args.dry_run:
        from .testing import FakeLLM

        llm = FakeLLM()
        # 关键：把 model 打上 fake 标记，否则假结果会以真实模型名写进缓存，
        # 之后真跑会静默复用假数据（缓存键含 model）。
        cfg.model = f"fake::{cfg.model}"
        print("!! dry-run：使用 FakeLLM，不联网、不产生费用")
    else:
        require_llm(cfg)
        from .llm import OpenAICompatClient

        llm = OpenAICompatClient(
            cfg.model,
            cfg.api_key,
            cfg.base_url,
            temperature=cfg.temperature,
            max_tokens=cfg.max_tokens,
            timeout_s=cfg.llm_timeout_s,
            retries=cfg.llm_retries,
        )
        print(f"model={cfg.model} base_url={cfg.base_url or '(default)'}")

    cache = Cache(cfg.cache_dir, enabled=cfg.cache)
    records, rejects, stats = build_records(cfg, pairs, llm, cache=cache)
    tag = args.tag or "extract"
    rec_path, rej_path = write_run_files(cfg, records, rejects, stats, tag=tag)

    print(f"\nrecords   : {len(records)}  -> {rec_path}")
    print(f"rejects   : {len(rejects)}  -> {rej_path}")
    print(f"cache     : hits={cache.hits} misses={cache.misses}")
    print(f"stats     : {json.dumps(stats.as_dict(), ensure_ascii=False)}")
    if records:
        print("\nsample record:")
        print(json.dumps(records[0], ensure_ascii=False, indent=2)[:1600])
    if rejects:
        print("\nreject reasons:")
        for item in rejects[:5]:
            print(f"  - {item['pair_id'][:60]}: {item['reason'][:160]}")
    return 0 if records else 1


def cmd_build(args: argparse.Namespace) -> int:
    cfg, pairs = _load(args)
    if not args.yes and not args.dry_run and args.limit is None and not getattr(args, "per_cwe", None):
        print("全量建库会真实计费；加 --yes 确认，或用 --limit 先试跑。", file=sys.stderr)
        return 2

    if args.dry_run:
        from .testing import FakeLLM

        llm = FakeLLM()
    else:
        require_llm(cfg)
        from .llm import OpenAICompatClient

        llm = OpenAICompatClient(
            cfg.model,
            cfg.api_key,
            cfg.base_url,
            temperature=cfg.temperature,
            max_tokens=cfg.max_tokens,
            timeout_s=cfg.llm_timeout_s,
            retries=cfg.llm_retries,
        )

    from .embed import get_embedder
    from .store import build

    cache = Cache(cfg.cache_dir, enabled=cfg.cache)
    records, rejects, stats = build_records(cfg, pairs, llm, cache=cache)
    write_run_files(cfg, records, rejects, stats, tag=args.tag or "build")
    embedder = get_embedder(cfg, allow_fallback=args.allow_hash_embed)
    result = build(cfg, records, embedder, stats=stats)
    print(f"out_dir   : {result.out_dir}")
    print(f"backend   : {result.backend}  n_df={result.n_df} n_cf={result.n_cf}")
    print(f"manifest  : {result.manifest_path}")
    print(f"rejects   : {len(rejects)}")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    from .store import load_meta

    out_dir = Path(args.out_dir or load_config(args.config).out_dir)
    meta = load_meta(out_dir)
    manifest_path = out_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    print(f"out_dir  : {out_dir}")
    print(f"manifest : {json.dumps(manifest, ensure_ascii=False, indent=2)[:800]}")
    print(f"records  : {len(meta)}")
    views: dict[str, int] = {}
    for record in meta:
        views[record["view_type"]] = views.get(record["view_type"], 0) + 1
    print(f"views    : {views}")
    pairs = {(r["pair_id"], r["view_type"]) for r in meta}
    pair_ids = {p for p, _ in pairs}
    print(f"pairs    : {len(pair_ids)}")
    # 视图可分性粗看：同 pair 两条 root_cause 是否一字不差（真实指标见 §8-G3）
    by_pair: dict[str, dict[str, str]] = {}
    for record in meta:
        by_pair.setdefault(record["pair_id"], {})[record["view_type"]] = record["root_cause"]
    identical = sum(
        1 for d in by_pair.values() if len(d) == 2 and d["data_flow"] == d["control_flow"]
    )
    print(f"identical df/cf root_cause : {identical}/{len(by_pair)}")
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    from .review import write_review

    out_dir = Path(args.out_dir or load_config(args.config).out_dir)
    path = write_review(out_dir, Path(args.md) if args.md else None)
    print(f"review -> {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="kbcore", description="双视图知识库建库工具")
    parser.add_argument("--config", default=None, help="YAML 路径（默认 configs/kb.yaml）")
    parser.add_argument("--limit", type=int, default=None, help="只处理前 N 对")
    parser.add_argument("--cwe", default=None, help="只跑这些 CWE，逗号分隔，如 CWE-190,CWE-416")
    parser.add_argument("--per-cwe", type=int, default=None, help="每个 CWE 取前 N 对（跨 CWE 小样本试跑）")
    parser.add_argument("--out-dir", default=None, help="产物目录（默认 artifacts/kb-v1）")
    parser.add_argument("--evidence-mode", choices=["tree_sitter", "none"], default=None)
    parser.add_argument("--provider", choices=["openai", "deepseek"], default=None,
                        help="LLM 凭证组（openai | deepseek），覆盖 kb.yaml 的 provider")
    parser.add_argument("--model", default=None, help="覆盖模型名，如 deepseek-reasoner")
    parser.add_argument("--kb-ver", default=None)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_pairs = sub.add_parser("pairs", help="K0：数据集盘点")
    p_pairs.set_defaults(func=cmd_pairs)

    p_ev = sub.add_parser("evidence", help="K1：anchor + DF/CF 证据")
    p_ev.set_defaults(func=cmd_evidence)

    p_ex = sub.add_parser("extract", help="K2：抽取 + 抽象 + 门禁（不建索引）")
    p_ex.add_argument("--dry-run", action="store_true")
    p_ex.add_argument("--tag", default=None)
    p_ex.set_defaults(func=cmd_extract)

    p_build = sub.add_parser("build", help="K3/K4：全量建库并落索引")
    p_build.add_argument("--dry-run", action="store_true")
    p_build.add_argument("--yes", action="store_true", help="确认全量计费")
    p_build.add_argument("--allow-hash-embed", action="store_true", help="缺 sentence-transformers 时允许降级嵌入")
    p_build.add_argument("--tag", default=None)
    p_build.set_defaults(func=cmd_build)

    p_audit = sub.add_parser("audit", help="检查产物（meta/manifest/视图可分性粗看）")
    p_audit.set_defaults(func=cmd_audit)

    p_review = sub.add_parser("review", help="把 meta.jsonl 渲染成可人工审阅的 Markdown")
    p_review.add_argument("--md", default=None, help="输出路径（默认 <out_dir>/review.md）")
    p_review.set_defaults(func=cmd_review)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
