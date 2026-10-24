"""双视图知识项抽取（LLM，每对 2 次调用）。

对应设计文档 §5.4。三条关键决策：

1. 两视图**共享同一份输入**，但 prompt 的任务段不同 —— 这是让两棵 ``root_cause``
   真正分开的唯一来源（否则两个库同构，级联检索退化成单库）。
2. 证据缺失时删掉证据段，退化为论文原样的"纯 LLM 抽取"，保证没有 pair 因为
   解析失败被剔除（实测 30/306 段不是合法 C，触发该路径）。
3. 缓存键必须含 ``prompt_ver + model + temperature + evidence 摘要``，
   少带一个就会静默复用旧结论（§8-G6 要求重跑 0 次调用）。
"""

from __future__ import annotations

import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .anchor import Anchor
from .cache import Cache, cache_key
from .config import KBConfig
from .interfaces import LLMClient, TokenUsage
from .llm import parse_json_object
from .pairs import PairRecord
from .views import Evidence

VIEWS: tuple[str, ...] = ("data_flow", "control_flow")

# 视图 → 该视图独占的行为字段
BEHAVIOR_FIELD: dict[str, str] = {"data_flow": "taint_flow", "control_flow": "control_branch"}

# 视图 → prompt 文件
PROMPT_FILE: dict[str, str] = {
    "data_flow": "kb_extract_df.md",
    "control_flow": "kb_extract_cf.md",
}


@dataclass
class RawKnowledge:
    """一对 pair 的双视图原始抽取结果（尚未抽象、未过门禁）。"""

    df: dict
    cf: dict
    tokens: TokenUsage = field(default_factory=TokenUsage)
    degraded: bool = False  # True = 无证据注入（纯 LLM 抽取）
    cache_hit: bool = False
    raw_texts: dict[str, str] = field(default_factory=dict)


def load_prompt(cfg: KBConfig, name: str) -> str:
    path = Path(cfg.prompts_dir) / name
    if not path.exists():
        raise FileNotFoundError(f"prompt 模板缺失：{path}")
    return path.read_text(encoding="utf-8")


def render(template: str, mapping: dict) -> str:
    """``string.Template`` 填充：用 ``$var`` 而不是 ``{}``，避免 JSON 花括号被当成占位符。"""
    return string.Template(template).safe_substitute(mapping)


def number_lines(src: str, start_line: int = 1) -> str:
    """给每行加原文件行号前缀（压低行号幻觉，§5.3 决策）。"""
    out = []
    for offset, line in enumerate(src.splitlines()):
        out.append(f"{start_line + offset:4d} | {line}")
    return "\n".join(out)


def diff_block(pair: PairRecord, anchor: Anchor) -> str:
    """把 anchor 区间切成 ``-`` / ``+`` 块（vul 侧 → 修复侧）。"""
    vul = pair.vul_lines[anchor.vul_start - 1 : anchor.vul_end]
    new = pair.non_lines[anchor.new_start - 1 : anchor.new_end]
    lines = [f"- {text}" for text in vul] + [f"+ {text}" for text in new]
    if not lines:
        return "(no textual difference recovered)"
    return "\n".join(lines)


def evidence_block(ev: Optional[Evidence], view: str, mode: str) -> str:
    """视图证据段：**整段不渲染**而不是渲染成空段（空段会被模型读成"没有证据"的反向提示）。"""
    if mode != "tree_sitter" or ev is None:
        return ""
    body = ev.render(view)
    if not body.strip():
        return ""
    return "\n4) Structural evidence extracted by a static analyzer (facts only, no interpretation):\n" + body + "\n"


def build_prompt(
    cfg: KBConfig,
    pair: PairRecord,
    anchor: Anchor,
    ev: Optional[Evidence],
    view: str,
) -> str:
    template = load_prompt(cfg, PROMPT_FILE[view])
    return render(
        template,
        {
            "cwe": pair.cwe,
            "vul_start": anchor.vul_start,
            "vul_end": anchor.vul_end,
            "new_start": anchor.new_start,
            "new_end": anchor.new_end,
            "code_block": number_lines(pair.vul_src),
            "diff_block": diff_block(pair, anchor),
            "evidence_block": evidence_block(ev, view, cfg.evidence_mode),
        },
    )


SYSTEM_PROMPT = (
    "You are a senior C/C++ security analyst. "
    "You output exactly one JSON object and nothing else — no markdown, no code fences, no commentary."
)


def _check_shape(data: dict, view: str) -> list[str]:
    problems: list[str] = []
    if not isinstance(data.get("root_cause"), str) or not data["root_cause"].strip():
        problems.append("root_cause 缺失或为空")
    calls = data.get("risky_calls")
    if not isinstance(calls, list):
        problems.append("risky_calls 不是数组")
    behavior = BEHAVIOR_FIELD[view]
    if not isinstance(data.get(behavior), str):
        problems.append(f"{behavior} 缺失")
    if not isinstance(data.get("fixing_strategy"), str) or not data["fixing_strategy"].strip():
        problems.append("fixing_strategy 缺失或为空")
    return problems


def extract_view(
    cfg: KBConfig,
    pair: PairRecord,
    anchor: Anchor,
    ev: Optional[Evidence],
    view: str,
    llm: LLMClient,
    cache: Optional[Cache] = None,
) -> tuple[dict, TokenUsage, bool, bool, str]:
    """抽一个视图。

    :return: ``(记录 dict, 计量, 是否缓存命中, 是否退化, 原始输出)``
    """
    ev_part = ev.cache_key_part() if (ev is not None and cfg.evidence_mode == "tree_sitter") else "none"
    key = cache_key(
        "extract",
        pair.pair_id,
        view,
        cfg.prompt_ver,
        cfg.model,
        cfg.temperature,
        cfg.max_tokens,
        cfg.evidence_mode,
        ev_part,
    )
    if cache is not None:
        hit = cache.get(key)
        if hit is not None:
            return hit["record"], TokenUsage(), True, bool(hit.get("degraded")), hit.get("raw", "")

    user = build_prompt(cfg, pair, anchor, ev, view)
    degraded = cfg.evidence_mode != "tree_sitter" or ev is None or not evidence_block(
        ev, view, cfg.evidence_mode
    ).strip()
    problems: list[str] = []
    last_text = ""
    usage_total = TokenUsage()

    for attempt in range(max(0, cfg.extract_retries) + 1):
        prompt = user
        if problems:
            prompt += (
                "\n\nYour previous answer was rejected: "
                + "; ".join(problems)
                + "\nReturn the JSON object again, with every key present and non-empty."
            )
        # 重试时放大输出预算：实测截断（out == max_tokens）是"输出不是 JSON"的首要成因，
        # 原样重发往往还是撞同一个上限。
        budget = cfg.max_tokens if attempt == 0 else min(cfg.max_tokens * 2, 8192)
        text, usage = llm.complete(
            SYSTEM_PROMPT,
            prompt,
            tag=f"extract:{view}",
            temperature=cfg.temperature,
            max_tokens=budget,
        )
        usage_total = usage_total + usage
        last_text = text
        try:
            data = parse_json_object(text)
        except ValueError as exc:
            problems = [str(exc)]
            continue
        problems = _check_shape(data, view)
        if not problems:
            record = {
                "root_cause": data["root_cause"].strip(),
                "risky_calls": [str(x) for x in (data.get("risky_calls") or [])][: cfg.max_calls],
                BEHAVIOR_FIELD[view]: str(data[BEHAVIOR_FIELD[view]]).strip(),
                "fixing_strategy": str(data["fixing_strategy"]).strip(),
            }
            if cache is not None:
                cache.put(key, {"record": record, "degraded": degraded, "raw": text})
            return record, usage_total, False, degraded, text

    raise ValueError(f"{pair.pair_id}/{view}: 抽取失败（{'; '.join(problems)}）")


def extract_pair(
    cfg: KBConfig,
    pair: PairRecord,
    anchor: Anchor,
    ev: Optional[Evidence],
    llm: LLMClient,
    cache: Optional[Cache] = None,
) -> RawKnowledge:
    """一次抽两个视图。任一视图失败整对失败（门禁按对成对判定，§7.3）。"""
    out = RawKnowledge(df={}, cf={})
    degraded_any = False
    for view in VIEWS:
        record, usage, hit, degraded, raw = extract_view(cfg, pair, anchor, ev, view, llm, cache)
        out.tokens = out.tokens + usage
        out.cache_hit = out.cache_hit or hit
        degraded_any = degraded_any or degraded
        out.raw_texts[view] = raw
        if view == "data_flow":
            out.df = record
        else:
            out.cf = record
    out.degraded = degraded_any
    return out


__all__ = [
    "VIEWS",
    "BEHAVIOR_FIELD",
    "SYSTEM_PROMPT",
    "RawKnowledge",
    "load_prompt",
    "render",
    "number_lines",
    "diff_block",
    "evidence_block",
    "build_prompt",
    "extract_view",
    "extract_pair",
]
