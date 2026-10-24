"""建库流水线：pairs → anchor → views → extract → abstract → gate → records。

对应设计文档 §4。这里只做编排与记账，所有判断都在各模块里：

* 唯一写盘的地方是 ``rejects.jsonl`` / ``records.jsonl``（落 ``runs/``）；
* 一个 pair 失败不影响其它 pair，但**会整对剔除**（成对判定，§7.3）；
* 每对的耗时/计量即时写日志，便于中断后判断"钱花到哪了"。
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

from .abstract import abstract_pair
from .anchor import Anchor, locate
from .cache import Cache
from .config import KBConfig, require_llm
from .extract import BEHAVIOR_FIELD, VIEWS, extract_pair
from .gate import gate_pair
from .interfaces import LLMClient, RunStats, TokenUsage
from .pairs import PairRecord
from .views import Evidence, extract_evidence


@dataclass
class PairOutcome:
    """一对的产物：要么两条视图记录，要么一条拒绝原因。"""

    pair_id: str
    records: list[dict] = field(default_factory=list)
    reject_reason: str = ""
    dropped_calls: dict[str, list[str]] = field(default_factory=dict)
    violations: dict[str, list[str]] = field(default_factory=dict)
    tokens: TokenUsage = field(default_factory=TokenUsage)
    cache_hits: int = 0
    secs: float = 0.0
    evidence_scope: str = "none"

    @property
    def ok(self) -> bool:
        return bool(self.records)


def _base_record(cfg: KBConfig, pair: PairRecord, anchor: Anchor, view: str, knowledge: dict) -> dict:
    """按设计文档 §3 组装一条记录（字段顺序即契约，新增只能追加在末尾）。"""
    record = {
        "pair_id": pair.pair_id,
        "view_type": view,
        "cwe": pair.cwe,
        "cve": pair.cve,
        "repo": pair.repo,
        "func": pair.func,
        "root_cause": knowledge.get("root_cause", ""),
        "risky_calls": list(knowledge.get("risky_calls") or []),
        "taint_flow": None,
        "control_branch": None,
        "fixing_strategy": knowledge.get("fixing_strategy", ""),
        "vuln_code": pair.vul_src,
        "fixed_code": pair.non_src,
        "anchors": anchor.as_dict(),
        "evidence": "none",
        "gen": {
            "prompt_ver": cfg.prompt_ver,
            "abstract_prompt_ver": cfg.abstract_prompt_ver,
            "model": cfg.model,
            "temperature": cfg.temperature,
        },
        "abstracted": True,
        "index_row": -1,
    }
    record[BEHAVIOR_FIELD[view]] = knowledge.get(BEHAVIOR_FIELD[view], "")
    return record


def process_pair(
    cfg: KBConfig,
    pair: PairRecord,
    llm: LLMClient,
    cache: Optional[Cache] = None,
) -> PairOutcome:
    """跑一对的全流程。异常一律收敛成 ``reject_reason``，不让单对拖垮整批。"""
    started = time.time()
    outcome = PairOutcome(pair_id=pair.pair_id)

    try:
        anchor = locate(pair)
    except Exception as exc:  # noqa: BLE001
        outcome.reject_reason = f"anchor: {exc}"
        outcome.secs = time.time() - started
        return outcome

    ev: Optional[Evidence] = None
    if cfg.evidence_mode == "tree_sitter":
        try:
            ev = extract_evidence(pair, anchor, max_df_items=cfg.max_df_items, max_cf_items=cfg.max_cf_items)
        except Exception:  # noqa: BLE001 - 证据是可选的，失败就当没有
            ev = None
    outcome.evidence_scope = ev.scope if ev is not None else "none"

    try:
        raw = extract_pair(cfg, pair, anchor, ev, llm, cache)
    except Exception as exc:  # noqa: BLE001
        outcome.reject_reason = f"extract: {exc}"
        outcome.secs = time.time() - started
        return outcome
    outcome.tokens = outcome.tokens + raw.tokens
    outcome.cache_hits += 1 if raw.cache_hit else 0

    try:
        df_abs, cf_abs, abstract_ok, abs_usage, violations = abstract_pair(
            cfg, pair, raw.df, raw.cf, llm, cache
        )
    except Exception as exc:  # noqa: BLE001
        outcome.reject_reason = f"abstract: {exc}"
        outcome.secs = time.time() - started
        return outcome
    outcome.tokens = outcome.tokens + abs_usage
    outcome.violations = violations

    if not abstract_ok:
        outcome.reject_reason = "abstract_violation: " + json.dumps(
            {k: v for k, v in violations.items() if v}, ensure_ascii=False
        )
        outcome.secs = time.time() - started
        return outcome

    ok, cleaned, problems, dropped = gate_pair(cfg, pair, {"data_flow": df_abs, "control_flow": cf_abs})
    outcome.dropped_calls = dropped
    if not ok:
        outcome.reject_reason = "gate: " + json.dumps(
            {k: v for k, v in problems.items() if v}, ensure_ascii=False
        )
        outcome.secs = time.time() - started
        return outcome

    for view in VIEWS:
        record = _base_record(cfg, pair, anchor, view, cleaned[view])
        record["evidence"] = (
            "tree_sitter" if (ev is not None and cfg.evidence_mode == "tree_sitter") else "none"
        )
        record["gen"]["tokens"] = outcome.tokens.as_dict()
        record["gen"]["dropped_calls"] = dropped.get(view) or []
        record["gen"]["evidence_scope"] = outcome.evidence_scope
        outcome.records.append(record)

    outcome.secs = time.time() - started
    return outcome


def build_records(
    cfg: KBConfig,
    pairs: Iterable[PairRecord],
    llm: LLMClient,
    *,
    cache: Optional[Cache] = None,
    on_done: Optional[Callable[[PairOutcome], None]] = None,
    stats: Optional[RunStats] = None,
) -> tuple[list[dict], list[dict], RunStats]:
    """并发跑完整批，返回 ``(records, rejects, stats)``。"""
    cache = cache if cache is not None else Cache(cfg.cache_dir, enabled=cfg.cache)
    stats = stats or RunStats()
    pairs = list(pairs)
    stats.pairs_total = len(pairs)

    records: list[dict] = []
    rejects: list[dict] = []

    with ThreadPoolExecutor(max_workers=max(1, int(cfg.concurrency))) as pool:
        futures = {pool.submit(process_pair, cfg, pair, llm, cache): pair for pair in pairs}
        for fut in as_completed(futures):
            pair = futures[fut]
            try:
                outcome = fut.result()
            except Exception as exc:  # noqa: BLE001 - 线程内异常兜底
                outcome = PairOutcome(pair_id=pair.pair_id, reject_reason=f"worker: {exc}")

            stats.llm = stats.llm + outcome.tokens
            stats.cache_hits += outcome.cache_hits
            if outcome.evidence_scope == "function":
                stats.evidence_func += 1
            elif outcome.evidence_scope == "file":
                stats.evidence_file += 1
            else:
                stats.evidence_none += 1

            if outcome.ok:
                stats.pairs_ok += 1
                records.extend(outcome.records)
            else:
                stats.pairs_rejected += 1
                rejects.append(
                    {
                        "pair_id": outcome.pair_id,
                        "cwe": pair.cwe,
                        "reason": outcome.reject_reason,
                        "violations": outcome.violations,
                        "dropped_calls": outcome.dropped_calls,
                        "secs": round(outcome.secs, 2),
                    }
                )
            if on_done is not None:
                on_done(outcome)

    records.sort(key=lambda r: (r["pair_id"], r["view_type"]))
    rejects.sort(key=lambda r: r["pair_id"])
    return records, rejects, stats


def assign_index_rows(records: list[dict]) -> dict[str, list[int]]:
    """分配 ``index_row``（两库同序，§3 决策 2），返回 ``view -> 行号列表``。"""
    rows: dict[str, list[int]] = {view: [] for view in VIEWS}
    for idx, record in enumerate(records):
        record["index_row"] = idx
        rows[record["view_type"]].append(idx)
    return rows


def write_run_files(
    cfg: KBConfig,
    records: list[dict],
    rejects: list[dict],
    stats: RunStats,
    *,
    tag: str = "kb",
) -> tuple[Path, Path]:
    """把 records / rejects 落到 ``runs/``（唯一写盘处）。"""
    run_dir = Path(cfg.runs_dir) / f"{tag}_{cfg.kb_ver}"
    run_dir.mkdir(parents=True, exist_ok=True)
    rec_path = run_dir / "records.jsonl"
    rej_path = run_dir / "rejects.jsonl"
    rec_path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in records) + ("\n" if records else ""),
        encoding="utf-8",
    )
    rej_path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in rejects) + ("\n" if rejects else ""),
        encoding="utf-8",
    )
    (run_dir / "stats.json").write_text(
        json.dumps(stats.as_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return rec_path, rej_path


__all__ = [
    "BEHAVIOR_FIELD",
    "PairOutcome",
    "process_pair",
    "build_records",
    "assign_index_rows",
    "write_run_files",
]
