"""抽象化：把 ``root_cause`` 改写成实现无关表述（LLM 改写 + 确定性判定）。

对应设计文档 §5.5。只处理 ``root_cause``：

* ``risky_calls``（API 名天然通用）、``taint_flow`` / ``control_branch``（修复端 BM25
  要拿它分词）**原样透传** —— 全抽象掉会让 IDF 归零、区分度消失；
* ``fixing_strategy`` 只进生成阶段 prompt，原文越具体越有用，也不抽象。

判定是确定性的（``common.abstraction.abstraction_violations``），
两次不过 → 该对**不入索引**：查询侧被强制抽象，一条未抽象的库记录在向量空间里
永远检索不到，入库只会抬高池噪声。
"""

from __future__ import annotations

from typing import Optional

from common.abstraction import abstraction_violations

from .cache import Cache, cache_key
from .config import KBConfig
from .extract import BEHAVIOR_FIELD, load_prompt, render
from .interfaces import LLMClient, TokenUsage
from .llm import parse_json_object
from .pairs import PairRecord

ABSTRACT_SYSTEM = (
    "You rewrite root-cause statements so that they are implementation independent. "
    "You output exactly one JSON object and nothing else."
)

ABSTRACT_PROMPT_FILE = "kb_abstract.md"


def rewrite(
    cfg: KBConfig,
    pair: PairRecord,
    root_cause: str,
    llm: LLMClient,
    cache: Optional[Cache] = None,
) -> tuple[str, TokenUsage]:
    """让模型改写一次；网络/格式失败时**返回原句**（不因格式问题丢样本）。"""
    key = cache_key("abstract", pair.cwe, root_cause, cfg.abstract_prompt_ver, cfg.model)
    if cache is not None:
        hit = cache.get(key)
        if hit is not None:
            return hit["root_cause"], TokenUsage()

    user = render(load_prompt(cfg, ABSTRACT_PROMPT_FILE), {"cwe": pair.cwe, "root_cause": root_cause})
    try:
        text, usage = llm.complete(
            ABSTRACT_SYSTEM,
            user,
            tag="abstract",
            temperature=cfg.temperature,
            max_tokens=256,
        )
        data = parse_json_object(text)
        new_root = str(data.get("root_cause", "")).strip()
    except Exception:
        return root_cause, TokenUsage()

    if not new_root:
        return root_cause, usage
    if cache is not None:
        cache.put(key, {"root_cause": new_root})
    return new_root, usage


def abstract_record(
    cfg: KBConfig,
    pair: PairRecord,
    record: dict,
    view: str,
    llm: LLMClient,
    cache: Optional[Cache] = None,
) -> tuple[dict, bool, TokenUsage, list[str]]:
    """对一个视图的记录做抽象化。

    :return: ``(新记录, 是否合格, 计量, 剩余违例)``
    """
    out = dict(record)
    usage = TokenUsage()
    if not cfg.abstract_enabled:
        violations = abstraction_violations(out.get("root_cause", ""), pair.vul_src)
        return out, not violations, usage, violations

    violations = abstraction_violations(out.get("root_cause", ""), pair.vul_src)
    attempts = 0
    while violations and attempts <= max(0, cfg.abstract_max_retry):
        new_root, used = rewrite(cfg, pair, out.get("root_cause", ""), llm, cache)
        usage = usage + used
        out["root_cause"] = new_root
        violations = abstraction_violations(new_root, pair.vul_src)
        attempts += 1

    # 独占字段名兜底：确保视图互斥（DF 只有 taint_flow，CF 只有 control_branch）
    other = "control_flow" if view == "data_flow" else "data_flow"
    out.pop(BEHAVIOR_FIELD[other], None)
    return out, not violations, usage, violations


def abstract_pair(
    cfg: KBConfig,
    pair: PairRecord,
    df: dict,
    cf: dict,
    llm: LLMClient,
    cache: Optional[Cache] = None,
) -> tuple[dict, dict, bool, TokenUsage, dict[str, list[str]]]:
    """成对抽象（§7.3：任一视图不合格 → 整对剔除）。"""
    usage = TokenUsage()
    out_df, ok_df, u1, v1 = abstract_record(cfg, pair, df, "data_flow", llm, cache)
    out_cf, ok_cf, u2, v2 = abstract_record(cfg, pair, cf, "control_flow", llm, cache)
    usage = usage + u1 + u2
    violations = {"data_flow": v1, "control_flow": v2}
    return out_df, out_cf, (ok_df and ok_cf), usage, violations


__all__ = ["rewrite", "abstract_record", "abstract_pair", "ABSTRACT_SYSTEM"]
